package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/service"
)

// EST RFC 7030 hardening master bundle Phase 7.2 — admin observability
// endpoints for the EST Administration GUI.
//
// Endpoints:
//
//	GET  /api/v1/admin/est/profiles         — Phase 7.2 (per-profile snapshot)
//	POST /api/v1/admin/est/reload-trust     — Phase 7.2 (JSON body: {"path_id":"corp"})
//
// All endpoints are admin-gated (M-008 pattern). Non-admin Bearer
// callers get 403 — the profiles endpoint reveals the operator's
// profile set + trust-anchor expiries (sensitive operational metadata),
// the reload endpoint is a privileged action that swaps the in-memory
// trust pool.

// AdminESTService is the slice of the per-profile ESTService set the
// admin handler needs. The handler depends on this narrow interface
// rather than the concrete *service.ESTService set so wiring stays
// service-side and the handler stays test-friendly.
type AdminESTService interface {
	// Profiles returns one snapshot per configured EST profile. Walks
	// the per-PathID service map under the hood.
	Profiles(ctx context.Context, now time.Time) ([]service.ESTStatsSnapshot, error)

	// ReloadTrust triggers the SIGHUP-equivalent Reload on the named
	// profile's trust holder. Returns ErrAdminESTProfileNotFound if the
	// PathID isn't known, or service.ErrESTMTLSDisabled if the profile
	// exists but mTLS isn't configured, or the underlying parse error
	// from trustanchor.LoadBundle on a bad reload (the holder retains
	// the OLD pool either way — fail-safe enforced one layer down).
	ReloadTrust(ctx context.Context, pathID string) error
}

// ErrAdminESTProfileNotFound is returned by AdminESTService implementations
// when the operator targets a PathID that doesn't map to any configured
// EST profile. The handler maps this to HTTP 404.
var ErrAdminESTProfileNotFound = errors.New("admin est: profile not found for the given path_id")

// AdminESTHandler serves the per-profile EST observability endpoints.
type AdminESTHandler struct {
	svc AdminESTService
}

// NewAdminESTHandler creates a new admin handler.
func NewAdminESTHandler(svc AdminESTService) AdminESTHandler {
	return AdminESTHandler{svc: svc}
}

// adminESTReloadRequest is the POST body shape for the reload-trust
// endpoint. PathID="" targets the legacy /.well-known/est root profile
// (the one with empty PathID), matching the convention used elsewhere
// in the per-profile dispatch.
type adminESTReloadRequest struct {
	PathID string `json:"path_id"`
}

// Profiles handles GET /api/v1/admin/est/profiles.
//
// Mirrors AdminSCEPIntuneHandler.Profiles. Returns one snapshot per
// configured EST profile in ESTStatsSnapshot shape (always-present
// per-profile fields + optional trust-anchor sub-block).
func (h AdminESTHandler) Profiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !middleware.IsAdmin(r.Context()) {
		Error(w, http.StatusForbidden, "Admin access required")
		return
	}

	now := time.Now()
	rows, err := h.svc.Profiles(r.Context(), now)
	if err != nil {
		Error(w, http.StatusInternalServerError, "Failed to read EST profiles")
		return
	}
	if rows == nil {
		// Avoid serialising as `null` — the GUI expects an array.
		rows = []service.ESTStatsSnapshot{}
	}
	_ = JSON(w, http.StatusOK, map[string]any{
		"profiles":      rows,
		"profile_count": len(rows),
		"generated_at":  now.UTC(),
	})
}

// ReloadTrust handles POST /api/v1/admin/est/reload-trust.
func (h AdminESTHandler) ReloadTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !middleware.IsAdmin(r.Context()) {
		Error(w, http.StatusForbidden, "Admin access required")
		return
	}

	var body adminESTReloadRequest
	// An empty body is permitted: it implicitly targets the legacy
	// /.well-known/est root profile (PathID=""). Operators with multi-
	// profile deploys MUST supply a path_id JSON field.
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			Error(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
			return
		}
	}

	err := h.svc.ReloadTrust(r.Context(), body.PathID)
	switch {
	case err == nil:
		_ = JSON(w, http.StatusOK, map[string]any{
			"reloaded":    true,
			"path_id":     body.PathID,
			"reloaded_at": time.Now().UTC(),
		})
	case errors.Is(err, ErrAdminESTProfileNotFound):
		Error(w, http.StatusNotFound, "EST profile not found for path_id="+body.PathID)
	case errors.Is(err, service.ErrESTMTLSDisabled):
		// 409 Conflict: profile exists but mTLS isn't enabled, so
		// there's no trust anchor to reload. Distinct from 404 so the
		// operator can correct the request without re-checking the
		// profile list.
		Error(w, http.StatusConflict, "EST profile path_id="+body.PathID+" does not have mTLS enabled")
	default:
		// Underlying trustanchor.LoadBundle errors (parse failure,
		// expired cert, missing file). The holder retains its previous
		// pool — the operator's enrollments keep working off the old
		// trust anchor while the operator fixes the file.
		Error(w, http.StatusInternalServerError, "Trust anchor reload failed: "+err.Error())
	}
}

// AdminESTServiceImpl is the production implementation of AdminESTService.
// Walks the per-profile ESTService set built by cmd/server/main.go.
type AdminESTServiceImpl struct {
	services map[string]*service.ESTService
}

// NewAdminESTServiceImpl constructs the handler-side service from the
// per-profile ESTService map built at startup.
func NewAdminESTServiceImpl(services map[string]*service.ESTService) *AdminESTServiceImpl {
	if services == nil {
		services = map[string]*service.ESTService{}
	}
	return &AdminESTServiceImpl{services: services}
}

// Profiles implements AdminESTService.
func (s *AdminESTServiceImpl) Profiles(_ context.Context, now time.Time) ([]service.ESTStatsSnapshot, error) {
	out := make([]service.ESTStatsSnapshot, 0, len(s.services))
	for _, svc := range s.services {
		out = append(out, svc.Stats(now))
	}
	return out, nil
}

// ReloadTrust implements AdminESTService.
func (s *AdminESTServiceImpl) ReloadTrust(ctx context.Context, pathID string) error {
	svc, ok := s.services[pathID]
	if !ok {
		return ErrAdminESTProfileNotFound
	}
	return svc.ReloadTrust(ctx)
}

// Compile-time interface check.
var _ AdminESTService = (*AdminESTServiceImpl)(nil)
