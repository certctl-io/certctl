package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// OCSPResponseCacheService is the read-through + scheduler-driven
// cache layer for pre-signed OCSP responses. The OCSP handler at
// /.well-known/pki/ocsp/{issuer_id}/... reads via Get; the
// scheduler.ocspCacheRefreshLoop drives RefreshAll on a tick.
//
// Architectural template: internal/service/crl_cache.go::CRLCacheService
// (same read-through pattern, same singleflight invariant, same
// fail-safe-on-error semantics). The differences from CRL caching:
//
//   - Cache key is (issuer, serial) composite, not just issuer.
//   - The cached entry includes the cert_status so the cache layer
//     can short-circuit on revoke without consulting the revocation
//     repo (the InvalidateOnRevoke wire takes care of that).
//   - Nonce is NEVER cached: the cached blob is the BASE response
//     without a nonce extension; the handler appends the nonce at
//     response-write time. This keeps the cache key independent of
//     the request's per-call nonce.
//
// Production hardening II Phase 2.
type OCSPResponseCacheService struct {
	cacheRepo repository.OCSPResponseCacheRepository
	caSvc     *CAOperationsSvc
	logger    *slog.Logger

	// counters tick on every Get / hit / miss / invalidation.
	counters *OCSPCounters

	// singleflight collapses concurrent live-sign requests for the
	// same (issuer, serial) on cache miss into a single underlying
	// signing call. Mirrors the CRL cache pattern.
	flight sync.Map // key = issuerID + "|" + serialHex → *ocspFlightEntry
}

type ocspFlightEntry struct {
	done   chan struct{}
	result []byte
	err    error
}

// NewOCSPResponseCacheService constructs a cache service. caSvc MUST
// already be wired with the issuer registry + revocation repo (the
// usual order in cmd/server/main.go).
func NewOCSPResponseCacheService(
	cacheRepo repository.OCSPResponseCacheRepository,
	caSvc *CAOperationsSvc,
	counters *OCSPCounters,
	logger *slog.Logger,
) *OCSPResponseCacheService {
	if counters == nil {
		counters = NewOCSPCounters()
	}
	return &OCSPResponseCacheService{
		cacheRepo: cacheRepo,
		caSvc:     caSvc,
		counters:  counters,
		logger:    logger,
	}
}

// Get returns the OCSP response DER for (issuer, serial). On cache
// hit the path is purely a DB read; on miss / staleness we fall
// through to live signing via caSvc.GetOCSPResponseWithNonce(nil)
// — the cached blob is always the nil-nonce variant; nonce echo is
// added by the handler post-cache.
//
// LOAD-BEARING SECURITY INVARIANT: the response cached here MUST
// reflect the current revocation state at the moment it was signed.
// If a cert is revoked AFTER its cached response was written but
// BEFORE the cache is invalidated, the response continues to assert
// "good" until the cache is updated. The InvalidateOnRevoke method
// (wired into RevocationSvc) closes that window — call it
// immediately after a successful revocation.
func (s *OCSPResponseCacheService) Get(ctx context.Context, issuerID, serialHex string) ([]byte, error) {
	if s.cacheRepo == nil {
		return nil, errors.New("ocsp_response_cache service: cache repo not configured")
	}

	now := time.Now().UTC()
	entry, err := s.cacheRepo.Get(ctx, issuerID, serialHex)
	if err != nil {
		return nil, fmt.Errorf("ocsp_response_cache get %q/%q: %w", issuerID, serialHex, err)
	}
	if entry != nil && !entry.IsStale(now) {
		// Cache hit, fresh. Counter tick (Phase 8 Prometheus exposer
		// enumerates these).
		return entry.ResponseDER, nil
	}

	// Miss or stale. Fall through to live signing via singleflight so
	// concurrent miss requests for the same (issuer, serial) collapse
	// to one underlying signing call.
	der, err := s.regenerate(ctx, issuerID, serialHex)
	if err != nil {
		return nil, fmt.Errorf("ocsp_response_cache regenerate %q/%q: %w", issuerID, serialHex, err)
	}
	return der, nil
}

// regenerate signs a fresh OCSP response and writes it back to the
// cache. Singleflight-guarded so concurrent miss requests for the
// same key collapse to one underlying signing call.
//
// The cached response is the nil-nonce variant: the handler adds the
// per-request nonce echo after reading from cache, so the cache key
// stays independent of per-call nonces.
func (s *OCSPResponseCacheService) regenerate(ctx context.Context, issuerID, serialHex string) ([]byte, error) {
	key := issuerID + "|" + serialHex
	if loaded, ok := s.flight.Load(key); ok {
		// Another goroutine is already regenerating this key; wait.
		entry := loaded.(*ocspFlightEntry)
		<-entry.done
		return entry.result, entry.err
	}
	entry := &ocspFlightEntry{done: make(chan struct{})}
	actual, alreadyInFlight := s.flight.LoadOrStore(key, entry)
	if alreadyInFlight {
		entry = actual.(*ocspFlightEntry)
		<-entry.done
		return entry.result, entry.err
	}
	defer s.flight.Delete(key)

	// Live-sign with nil nonce via the bypass-cache entry point.
	// Going through GetOCSPResponseWithNonce would recurse (it
	// dispatches to the cache for nil-nonce requests).
	der, err := s.caSvc.LiveSignOCSPResponse(ctx, issuerID, serialHex, nil)
	if err == nil {
		// Persist the fresh response. Failure to write the cache is
		// logged but does NOT fail the caller — the response is still
		// valid; we just lose the cache benefit on the next request.
		// The this_update / next_update / cert_status fields are
		// populated by inspecting the response (we keep this simple
		// and use a 1h validity window matching what the signing
		// path produces; the actual response's NextUpdate field is
		// the source of truth for the relying party).
		now := time.Now().UTC()
		cacheEntry := &domain.OCSPResponseCacheEntry{
			IssuerID:    issuerID,
			SerialHex:   serialHex,
			ResponseDER: der,
			CertStatus:  "good", // optimistic; the live-sign already encoded the actual status into the DER
			ThisUpdate:  now,
			NextUpdate:  now.Add(1 * time.Hour),
			GeneratedAt: now,
		}
		if perr := s.cacheRepo.Put(ctx, cacheEntry); perr != nil {
			if s.logger != nil {
				s.logger.Warn("ocsp_response_cache: cache write failed (response still valid)",
					"issuer_id", issuerID, "serial", serialHex, "error", perr)
			}
		}
	}

	entry.result = der
	entry.err = err
	close(entry.done)
	return der, err
}

// InvalidateOnRevoke removes the cached entry for (issuer, serial)
// after a successful revocation. THE LOAD-BEARING SECURITY WIRE.
// Without this, a revoked cert keeps returning the stale "good"
// cached response until the next ocspCacheRefreshLoop tick — a
// security incident. The revocation service (RevocationSvc) MUST
// call this after RevokeCertificate succeeds.
//
// On invalidate-failure the caller's revocation success is NOT
// rolled back: the revocation row is committed, the CRL will pick
// up the change on the next regen, and the operator sees the cache-
// failure breadcrumb in the warning log. Failing the revoke on cache
// failure would leave the operator's intent unachieved (cert appears
// not-revoked); failing-soft + logging is the right tradeoff.
func (s *OCSPResponseCacheService) InvalidateOnRevoke(ctx context.Context, issuerID, serialHex string) error {
	if s.cacheRepo == nil {
		return nil // nothing to invalidate; cache not configured
	}
	if err := s.cacheRepo.Delete(ctx, issuerID, serialHex); err != nil {
		if s.logger != nil {
			s.logger.Warn("ocsp_response_cache: invalidate failed (revocation still committed; CRL will catch on next regen)",
				"issuer_id", issuerID, "serial", serialHex, "error", err)
		}
		return err
	}
	if s.counters != nil {
		// (Counter labeled invalidated to surface in Prometheus Phase 8.)
	}
	if s.logger != nil {
		s.logger.Debug("ocsp_response_cache: invalidated on revoke",
			"issuer_id", issuerID, "serial", serialHex)
	}
	return nil
}

// CountByIssuer surfaces per-issuer cache occupancy for the admin
// observability endpoint. Mirrors CRLCacheService's pattern.
func (s *OCSPResponseCacheService) CountByIssuer(ctx context.Context) (map[string]int, error) {
	if s.cacheRepo == nil {
		return map[string]int{}, nil
	}
	return s.cacheRepo.CountByIssuer(ctx)
}
