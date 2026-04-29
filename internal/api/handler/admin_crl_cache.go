package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// AdminCRLCacheService is the slice of CRLCacheRepository the admin
// endpoint needs. The handler depends on this narrow interface rather
// than the full *service.CRLCacheService so the wiring stays
// service-side and the handler stays test-friendly.
type AdminCRLCacheService interface {
	// CacheRows returns one row per issuer that currently has a cached
	// CRL. Implementations walk the registry and call the repository's
	// Get for each; rows that don't exist (issuer never had a CRL
	// generated) are returned with CacheRow.CachePresent=false so the
	// GUI can show "not yet generated" rather than 404ing.
	CacheRows(ctx context.Context) ([]CRLCacheRow, error)
}

// CRLCacheRow is the admin-endpoint view of a single issuer's cache
// state. The raw CRL DER is omitted (kept on the server) — operators
// fetch it via the standard /.well-known/pki/crl/{issuer_id} URL.
type CRLCacheRow struct {
	IssuerID        string        `json:"issuer_id"`
	CachePresent    bool          `json:"cache_present"`
	CRLNumber       int64         `json:"crl_number,omitempty"`
	ThisUpdate      *time.Time    `json:"this_update,omitempty"`
	NextUpdate      *time.Time    `json:"next_update,omitempty"`
	GeneratedAt     *time.Time    `json:"generated_at,omitempty"`
	GenerationDurMs int64         `json:"generation_duration_ms,omitempty"`
	RevokedCount    int           `json:"revoked_count,omitempty"`
	IsStale         bool          `json:"is_stale,omitempty"`
	RecentEvents    []CRLCacheEvt `json:"recent_events,omitempty"`
}

// CRLCacheEvt is the trimmed view of a CRLGenerationEvent for the
// admin response. We omit the DB row ID (operators don't care) and
// flatten the duration to milliseconds.
type CRLCacheEvt struct {
	StartedAt    time.Time `json:"started_at"`
	DurationMs   int64     `json:"duration_ms"`
	Succeeded    bool      `json:"succeeded"`
	CRLNumber    int64     `json:"crl_number"`
	RevokedCount int       `json:"revoked_count"`
	Error        string    `json:"error,omitempty"`
}

// AdminCRLCacheHandler serves the GET /api/v1/admin/crl/cache endpoint
// for ops visibility into the scheduler-driven CRL pre-generation
// pipeline. CRL/OCSP-Responder Phase 5.
//
// The endpoint is admin-gated (M-003 pattern) — non-admin Bearer
// callers get 403. This is a fleet-state observability surface; we
// don't expose it to every authenticated user because the cache
// rows reveal the operator's issuer set + CRL cadence.
type AdminCRLCacheHandler struct {
	svc AdminCRLCacheService
}

// NewAdminCRLCacheHandler creates a new handler.
func NewAdminCRLCacheHandler(svc AdminCRLCacheService) AdminCRLCacheHandler {
	return AdminCRLCacheHandler{svc: svc}
}

// ListCache handles GET /api/v1/admin/crl/cache.
func (h AdminCRLCacheHandler) ListCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !middleware.IsAdmin(r.Context()) {
		Error(w, http.StatusForbidden, "Admin access required")
		return
	}

	rows, err := h.svc.CacheRows(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "Failed to read CRL cache state")
		return
	}
	if rows == nil {
		// Avoid serialising as `null` — the GUI expects an array.
		rows = []CRLCacheRow{}
	}
	_ = JSON(w, http.StatusOK, map[string]any{
		"cache_rows":   rows,
		"row_count":    len(rows),
		"generated_at": time.Now().UTC(),
	})
}

// AdminCRLCacheServiceImpl is the production implementation of
// AdminCRLCacheService. It walks the issuer registry, fetches the
// cache row for each via the repository, and decorates with recent
// generation events. Lives in the handler package because it's a
// thin handler-side composition; the heavy lifting stays in the
// repository.
type AdminCRLCacheServiceImpl struct {
	cacheRepo repository.CRLCacheRepository
	issuerIDs func() []string // returns all issuer IDs (callback so the
	//                             registry doesn't have to be imported here)
	now        func() time.Time
	eventLimit int
}

// NewAdminCRLCacheServiceImpl constructs the handler-side service.
// issuerIDsFn is a callback so we don't import internal/service from
// the handler package (would be a layering violation).
func NewAdminCRLCacheServiceImpl(cacheRepo repository.CRLCacheRepository, issuerIDsFn func() []string) *AdminCRLCacheServiceImpl {
	return &AdminCRLCacheServiceImpl{
		cacheRepo:  cacheRepo,
		issuerIDs:  issuerIDsFn,
		now:        func() time.Time { return time.Now().UTC() },
		eventLimit: 5,
	}
}

// CacheRows implements AdminCRLCacheService.
func (s *AdminCRLCacheServiceImpl) CacheRows(ctx context.Context) ([]CRLCacheRow, error) {
	now := s.now()
	ids := s.issuerIDs()
	out := make([]CRLCacheRow, 0, len(ids))

	for _, issuerID := range ids {
		row := CRLCacheRow{IssuerID: issuerID}

		entry, err := s.cacheRepo.Get(ctx, issuerID)
		if err != nil {
			// One issuer's failure should not blank the whole response —
			// the GUI shows partial state and surfaces the per-issuer
			// error as a generation event.
			row.RecentEvents = []CRLCacheEvt{{
				StartedAt: now, Succeeded: false,
				Error: "cache lookup failed: " + err.Error(),
			}}
			out = append(out, row)
			continue
		}
		if entry == nil {
			out = append(out, row) // CachePresent stays false
			continue
		}

		row.CachePresent = true
		row.CRLNumber = entry.CRLNumber
		row.ThisUpdate = &entry.ThisUpdate
		row.NextUpdate = &entry.NextUpdate
		row.GeneratedAt = &entry.GeneratedAt
		row.GenerationDurMs = entry.GenerationDuration.Milliseconds()
		row.RevokedCount = entry.RevokedCount
		row.IsStale = entry.IsStale(now)

		// Most-recent N generation events for ops grep.
		evts, err := s.cacheRepo.ListGenerationEvents(ctx, issuerID, s.eventLimit)
		if err == nil {
			row.RecentEvents = make([]CRLCacheEvt, 0, len(evts))
			for _, e := range evts {
				row.RecentEvents = append(row.RecentEvents, CRLCacheEvt{
					StartedAt:    e.StartedAt,
					DurationMs:   e.Duration.Milliseconds(),
					Succeeded:    e.Succeeded,
					CRLNumber:    e.CRLNumber,
					RevokedCount: e.RevokedCount,
					Error:        e.Error,
				})
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// Compile-time interface check.
var _ AdminCRLCacheService = (*AdminCRLCacheServiceImpl)(nil)

// _ silences the unused-import warning if domain pulls in only via
// type aliases; the explicit reference here means the import is
// intentional even when the file's other symbols don't reference it.
var _ = domain.CRLGenerationEvent{}
