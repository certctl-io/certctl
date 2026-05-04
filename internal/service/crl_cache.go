package service

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// CRLCacheService is the read-through + scheduler-driven cache layer
// for pre-generated CRLs. The HTTP handler at
// /.well-known/pki/crl/{issuer_id} reads via Get; the
// scheduler.crlGenerationLoop drives RegenerateAll on a tick.
//
// Bundle CRL/OCSP-Responder Phase 3.
//
// Concurrency model:
//
//   - The cache row is the source of truth (one row per issuer).
//   - Get returns the cached row when fresh; on miss / staleness it
//     calls regenerateOne behind a singleflight gate keyed by issuer
//     ID so concurrent miss requests for the same issuer collapse to
//     a single underlying generation call.
//   - RegenerateAll iterates every issuer in the registry, calling
//     regenerateOne for each. Per-issuer failures are logged + audited
//     via crl_generation_events; one bad issuer does not stop the
//     others.
//   - The CA-side CRL generation (caSvc.GenerateDERCRL → issuer
//     connector.GenerateCRL) is unchanged. This service is additive:
//     it persists results, surfaces them via Get, and tracks events.
type CRLCacheService struct {
	cacheRepo repository.CRLCacheRepository
	caSvc     *CAOperationsSvc
	registry  *IssuerRegistry
	logger    *slog.Logger

	// singleflight collapses concurrent regeneration requests for the
	// same issuer ID. A simpler alternative to vendoring
	// golang.org/x/sync/singleflight; this in-tree version is ~30 LoC
	// and matches the project's "no new deps unless necessary" rule.
	flight sync.Map // issuerID → *flightEntry
}

// flightEntry coordinates a single in-flight generation across
// concurrent callers. The first arrival kicks off the work; later
// arrivals wait on done and read the shared result. Pattern matches
// golang.org/x/sync/singleflight semantics for the single-call case
// (we don't need the multi-result Forget capability here).
type flightEntry struct {
	done   chan struct{}
	result *domain.CRLCacheEntry
	err    error
}

// NewCRLCacheService constructs a cache service. caSvc must already
// have its issuer registry wired (CAOperationsSvc.SetIssuerRegistry).
func NewCRLCacheService(
	cacheRepo repository.CRLCacheRepository,
	caSvc *CAOperationsSvc,
	registry *IssuerRegistry,
	logger *slog.Logger,
) *CRLCacheService {
	return &CRLCacheService{
		cacheRepo: cacheRepo,
		caSvc:     caSvc,
		registry:  registry,
		logger:    logger,
	}
}

// Get returns the cached CRL DER + thisUpdate timestamp for an issuer.
// On cache hit the path is purely a DB read (~ms). On miss or
// staleness (next_update in the past), Get triggers an immediate
// regeneration via the singleflight gate so concurrent requests
// collapse to one underlying call.
func (s *CRLCacheService) Get(ctx context.Context, issuerID string) ([]byte, time.Time, error) {
	if s.cacheRepo == nil {
		return nil, time.Time{}, errors.New("crl_cache service: cache repo not configured")
	}

	now := time.Now().UTC()
	entry, err := s.cacheRepo.Get(ctx, issuerID)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("crl_cache service get %q: %w", issuerID, err)
	}
	if entry != nil && !entry.IsStale(now) {
		return entry.CRLDER, entry.ThisUpdate, nil
	}

	// Miss or stale → regenerate behind the singleflight gate.
	fresh, err := s.regenerateOne(ctx, issuerID)
	if err != nil {
		return nil, time.Time{}, err
	}
	return fresh.CRLDER, fresh.ThisUpdate, nil
}

// RegenerateAll walks every issuer in the registry, calling
// regenerateOne for each. Per-issuer failures are logged + audited
// (via crl_generation_events); a single bad issuer does not stop
// the others. Called by scheduler.crlGenerationLoop on each tick.
//
// Issuers whose connector returns nil from GenerateCRL (e.g., ACME,
// Vault PKI, DigiCert — they manage their own CRL distribution) are
// skipped silently; the regenerateOne path detects nil and treats it
// as "no CRL to cache" rather than an error.
func (s *CRLCacheService) RegenerateAll(ctx context.Context) {
	if s.registry == nil {
		s.logger.Warn("CRL cache RegenerateAll: registry not configured; nothing to do")
		return
	}

	issuers := s.registry.List()
	for issuerID := range issuers {
		select {
		case <-ctx.Done():
			s.logger.Warn("CRL cache RegenerateAll: ctx cancelled mid-cycle",
				"completed", issuerID)
			return
		default:
		}

		if _, err := s.regenerateOne(ctx, issuerID); err != nil {
			// regenerateOne already logs + audits the failure; log here
			// only at debug level to avoid double-noise.
			s.logger.Debug("CRL cache RegenerateAll: per-issuer failure",
				"issuer_id", issuerID, "error", err)
		}
	}
}

// regenerateOne is the singleflight-gated worker. The first concurrent
// call for an issuer ID executes the generation; later calls block on
// the in-flight entry's done channel and return the same result.
//
// The gate is released in a defer so callers can rely on subsequent
// calls (after the result is observed) starting a fresh generation.
func (s *CRLCacheService) regenerateOne(ctx context.Context, issuerID string) (*domain.CRLCacheEntry, error) {
	// Check for an in-flight generation. LoadOrStore atomically:
	//   - If absent: stores our entry as the in-flight one and returns
	//     it; we kick off the work.
	//   - If present: returns the existing entry; we wait on it.
	mine := &flightEntry{done: make(chan struct{})}
	actual, loaded := s.flight.LoadOrStore(issuerID, mine)
	entry := actual.(*flightEntry)

	if loaded {
		// Another goroutine is already generating. Wait for them.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-entry.done:
		}
		if entry.err != nil {
			return nil, entry.err
		}
		return entry.result, nil
	}

	// We are the leader; do the work and signal others on done.
	defer func() {
		s.flight.Delete(issuerID)
		close(mine.done)
	}()

	mine.result, mine.err = s.doRegenerate(ctx, issuerID)
	return mine.result, mine.err
}

// doRegenerate is the actual work: ask CAOperationsSvc to build the
// CRL DER, parse it to recover thisUpdate/nextUpdate, persist into
// crl_cache, and record an audit event in crl_generation_events.
func (s *CRLCacheService) doRegenerate(ctx context.Context, issuerID string) (*domain.CRLCacheEntry, error) {
	if s.caSvc == nil {
		return nil, errors.New("crl_cache service: caSvc not configured")
	}

	startedAt := time.Now().UTC()

	// Build the CRL via the existing on-demand path.
	derBytes, err := s.caSvc.GenerateDERCRL(ctx, issuerID)
	if err != nil {
		s.recordEvent(ctx, &domain.CRLGenerationEvent{
			IssuerID:  issuerID,
			StartedAt: startedAt,
			Duration:  time.Since(startedAt),
			Succeeded: false,
			Error:     err.Error(),
		})
		return nil, fmt.Errorf("crl_cache service generate %q: %w", issuerID, err)
	}

	// Parse to extract thisUpdate / nextUpdate / number / count.
	parsed, perr := x509.ParseRevocationList(derBytes)
	if perr != nil {
		s.recordEvent(ctx, &domain.CRLGenerationEvent{
			IssuerID:  issuerID,
			StartedAt: startedAt,
			Duration:  time.Since(startedAt),
			Succeeded: false,
			Error:     "parse generated CRL: " + perr.Error(),
		})
		return nil, fmt.Errorf("crl_cache service parse %q: %w", issuerID, perr)
	}

	crlNumber := int64(0)
	if parsed.Number != nil {
		crlNumber = parsed.Number.Int64()
	}

	entry := &domain.CRLCacheEntry{
		IssuerID:           issuerID,
		CRLDER:             derBytes,
		CRLNumber:          crlNumber,
		ThisUpdate:         parsed.ThisUpdate,
		NextUpdate:         parsed.NextUpdate,
		GeneratedAt:        startedAt,
		GenerationDuration: time.Since(startedAt),
		RevokedCount:       len(parsed.RevokedCertificateEntries),
	}
	if err := s.cacheRepo.Put(ctx, entry); err != nil {
		s.recordEvent(ctx, &domain.CRLGenerationEvent{
			IssuerID:  issuerID,
			CRLNumber: crlNumber,
			StartedAt: startedAt,
			Duration:  time.Since(startedAt),
			Succeeded: false,
			Error:     "persist cache row: " + err.Error(),
		})
		return nil, fmt.Errorf("crl_cache service persist %q: %w", issuerID, err)
	}

	s.recordEvent(ctx, &domain.CRLGenerationEvent{
		IssuerID:     issuerID,
		CRLNumber:    crlNumber,
		Duration:     entry.GenerationDuration,
		RevokedCount: entry.RevokedCount,
		StartedAt:    startedAt,
		Succeeded:    true,
	})

	s.logger.Info("CRL pre-generated and cached",
		"issuer_id", issuerID,
		"crl_number", crlNumber,
		"revoked_count", entry.RevokedCount,
		"this_update", entry.ThisUpdate,
		"next_update", entry.NextUpdate,
		"duration_ms", entry.GenerationDuration.Milliseconds())
	return entry, nil
}

// recordEvent persists a generation event but does NOT propagate
// failure-to-record back to the caller — the event log is a
// best-effort audit trail; missing it should not turn a successful
// CRL generation into an error.
func (s *CRLCacheService) recordEvent(ctx context.Context, evt *domain.CRLGenerationEvent) {
	if s.cacheRepo == nil {
		return
	}
	if err := s.cacheRepo.RecordGenerationEvent(ctx, evt); err != nil {
		s.logger.Warn("crl_cache service: failed to record generation event",
			"issuer_id", evt.IssuerID, "error", err)
	}
}
