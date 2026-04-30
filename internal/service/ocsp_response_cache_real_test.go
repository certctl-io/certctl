package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// Production hardening II Phase 2 — exercise the REAL OCSPResponseCacheService
// (not the test-harness mirror in ocsp_response_cache_test.go) wired against
// a real CAOperationsSvc + mockIssuerConnector. Closes the coverage gap on:
//
//   - OCSPResponseCacheService.Get (cache miss → live-sign → write-back)
//   - OCSPResponseCacheService.regenerate (singleflight + cache.Put + the
//     cache-write-failure log branch)
//   - OCSPResponseCacheService.InvalidateOnRevoke (the load-bearing wire
//     into the real revocation flow)
//   - OCSPResponseCacheService.CountByIssuer
//   - CAOperationsSvc.GetOCSPResponseWithNonce dispatch when cache wired
//   - CAOperationsSvc.SetOCSPCacheSvc setter
//   - RevocationSvc.SetOCSPCacheInvalidator setter + invalidator wire

// silentLogger returns a slog.Logger that discards everything.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10}))
}

// putErrorRepo wraps the in-memory cache repo and forces Put to fail.
// Used to exercise the "cache write failed (response still valid)"
// log branch in regenerate.
type putErrorRepo struct {
	*fakeOCSPCacheRepo
	putErr error
}

func (r *putErrorRepo) Put(ctx context.Context, e *domain.OCSPResponseCacheEntry) error {
	if r.putErr != nil {
		return r.putErr
	}
	return r.fakeOCSPCacheRepo.Put(ctx, e)
}

// deleteErrorRepo forces Delete to fail; exercises the invalidate-failure
// log branch in InvalidateOnRevoke.
type deleteErrorRepo struct {
	*fakeOCSPCacheRepo
	deleteErr error
}

func (r *deleteErrorRepo) Delete(ctx context.Context, issuer, serial string) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	return r.fakeOCSPCacheRepo.Delete(ctx, issuer, serial)
}

func TestOCSPResponseCacheService_RealGet_HappyPath_CachesAfterMiss(t *testing.T) {
	caSvc, _, _, _ := newCAOperationsSvcTestWithIssuer()
	cacheRepo := newFakeOCSPCacheRepo()
	cache := NewOCSPResponseCacheService(cacheRepo, caSvc, NewOCSPCounters(), silentLogger())

	// First fetch: cache miss → live-sign via mockIssuerConnector → cache write-back.
	der1, err := cache.Get(context.Background(), "iss-local", "deadbeef")
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if len(der1) == 0 {
		t.Fatal("expected non-empty DER from live sign")
	}

	// Cache row now present.
	got, _ := cacheRepo.Get(context.Background(), "iss-local", "deadbeef")
	if got == nil {
		t.Fatal("expected cache row written after miss")
	}

	// Second fetch: cache hit (returns the same cached bytes).
	der2, err := cache.Get(context.Background(), "iss-local", "deadbeef")
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if string(der1) != string(der2) {
		t.Errorf("cache returned different bytes than original sign")
	}
}

func TestOCSPResponseCacheService_RealGet_CacheWriteFailureIsNonFatal(t *testing.T) {
	caSvc, _, _, _ := newCAOperationsSvcTestWithIssuer()
	cacheRepo := &putErrorRepo{
		fakeOCSPCacheRepo: newFakeOCSPCacheRepo(),
		putErr:            errors.New("disk full simulation"),
	}
	cache := NewOCSPResponseCacheService(cacheRepo, caSvc, nil, silentLogger())

	// Get: live-sign succeeds, cache.Put fails — the response is still
	// valid; we just lose the cache benefit on the next request. The
	// caller MUST get a successful response.
	der, err := cache.Get(context.Background(), "iss-local", "deadbeef")
	if err != nil {
		t.Fatalf("expected fail-soft on cache write failure, got %v", err)
	}
	if len(der) == 0 {
		t.Fatal("expected non-empty DER even when cache.Put failed")
	}
}

func TestOCSPResponseCacheService_RealGet_StaleEntryRegenerates(t *testing.T) {
	caSvc, _, _, _ := newCAOperationsSvcTestWithIssuer()
	cacheRepo := newFakeOCSPCacheRepo()
	// Pre-populate with a stale entry.
	stale := &domain.OCSPResponseCacheEntry{
		IssuerID:    "iss-local",
		SerialHex:   "abcd",
		ResponseDER: []byte{0x11},
		CertStatus:  "good",
		ThisUpdate:  time.Now().Add(-2 * time.Hour),
		NextUpdate:  time.Now().Add(-1 * time.Hour),
		GeneratedAt: time.Now().Add(-2 * time.Hour),
	}
	_ = cacheRepo.Put(context.Background(), stale)

	cache := NewOCSPResponseCacheService(cacheRepo, caSvc, nil, silentLogger())
	der, err := cache.Get(context.Background(), "iss-local", "abcd")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// Stale entry → re-sign produces fresh bytes (different from the
	// pre-populated 0x11 placeholder).
	if len(der) == 1 && der[0] == 0x11 {
		t.Errorf("stale entry should have triggered re-sign; got pre-populated bytes")
	}
}

func TestOCSPResponseCacheService_RealInvalidateOnRevoke(t *testing.T) {
	caSvc, _, _, _ := newCAOperationsSvcTestWithIssuer()
	cacheRepo := newFakeOCSPCacheRepo()
	cache := NewOCSPResponseCacheService(cacheRepo, caSvc, nil, silentLogger())

	// Pre-populate one row.
	_ = cacheRepo.Put(context.Background(), &domain.OCSPResponseCacheEntry{
		IssuerID:    "iss-local",
		SerialHex:   "deadbeef",
		ResponseDER: []byte{0x42},
		CertStatus:  "good",
		ThisUpdate:  time.Now(),
		NextUpdate:  time.Now().Add(1 * time.Hour),
		GeneratedAt: time.Now(),
	})

	if err := cache.InvalidateOnRevoke(context.Background(), "iss-local", "deadbeef"); err != nil {
		t.Fatalf("invalidate: %v", err)
	}

	got, _ := cacheRepo.Get(context.Background(), "iss-local", "deadbeef")
	if got != nil {
		t.Errorf("expected cache row deleted after invalidate")
	}
}

func TestOCSPResponseCacheService_InvalidateOnRevoke_DeleteFailureSurfacesError(t *testing.T) {
	caSvc, _, _, _ := newCAOperationsSvcTestWithIssuer()
	cacheRepo := &deleteErrorRepo{
		fakeOCSPCacheRepo: newFakeOCSPCacheRepo(),
		deleteErr:         errors.New("delete failed"),
	}
	cache := NewOCSPResponseCacheService(cacheRepo, caSvc, nil, silentLogger())
	err := cache.InvalidateOnRevoke(context.Background(), "iss-local", "deadbeef")
	if err == nil {
		t.Errorf("expected error when delete fails, got nil")
	}
}

func TestOCSPResponseCacheService_RealCountByIssuer(t *testing.T) {
	caSvc, _, _, _ := newCAOperationsSvcTestWithIssuer()
	cacheRepo := newFakeOCSPCacheRepo()
	cache := NewOCSPResponseCacheService(cacheRepo, caSvc, nil, silentLogger())

	for i, e := range []struct{ iss, ser string }{
		{"iss-local", "ser1"},
		{"iss-local", "ser2"},
		{"iss-other", "ser1"},
	} {
		_ = i
		_ = cacheRepo.Put(context.Background(), &domain.OCSPResponseCacheEntry{
			IssuerID:    e.iss,
			SerialHex:   e.ser,
			ResponseDER: []byte{0x42},
			CertStatus:  "good",
			ThisUpdate:  time.Now(),
			NextUpdate:  time.Now().Add(1 * time.Hour),
			GeneratedAt: time.Now(),
		})
	}
	got, err := cache.CountByIssuer(context.Background())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if got["iss-local"] != 2 || got["iss-other"] != 1 {
		t.Errorf("CountByIssuer = %#v, want iss-local=2 iss-other=1", got)
	}
}

func TestOCSPResponseCacheService_NilRepoReturnsEmptyCountByIssuer(t *testing.T) {
	cache := NewOCSPResponseCacheService(nil, nil, nil, silentLogger())
	got, err := cache.CountByIssuer(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestCAOperationsSvc_GetOCSPResponseWithNonce_CacheDispatchHit(t *testing.T) {
	caSvc, _, _, _ := newCAOperationsSvcTestWithIssuer()
	cacheRepo := newFakeOCSPCacheRepo()
	cache := NewOCSPResponseCacheService(cacheRepo, caSvc, nil, silentLogger())
	caSvc.SetOCSPCacheSvc(cache)

	// Nil-nonce request: dispatches through the cache. First call is
	// a miss (live-sign + write-back); cache row should appear.
	_, err := caSvc.GetOCSPResponseWithNonce(context.Background(), "iss-local", "deadbeef", nil)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if got, _ := cacheRepo.Get(context.Background(), "iss-local", "deadbeef"); got == nil {
		t.Errorf("expected cache row populated after first nil-nonce request")
	}
	// Second call returns the cached bytes (same content).
	der1, _ := caSvc.GetOCSPResponseWithNonce(context.Background(), "iss-local", "deadbeef", nil)
	der2, _ := caSvc.GetOCSPResponseWithNonce(context.Background(), "iss-local", "deadbeef", nil)
	if string(der1) != string(der2) {
		t.Errorf("repeated cached fetches returned different bytes")
	}
}

func TestCAOperationsSvc_GetOCSPResponseWithNonce_NonceBypassesCache(t *testing.T) {
	caSvc, _, _, _ := newCAOperationsSvcTestWithIssuer()
	cacheRepo := newFakeOCSPCacheRepo()
	cache := NewOCSPResponseCacheService(cacheRepo, caSvc, nil, silentLogger())
	caSvc.SetOCSPCacheSvc(cache)

	// Nonce-bearing request: bypasses the cache entirely. After the
	// call, the cache row should still NOT be populated.
	nonce := []byte{0xaa, 0xbb}
	_, err := caSvc.GetOCSPResponseWithNonce(context.Background(), "iss-local", "deadbeef", nonce)
	if err != nil {
		t.Fatalf("nonce request: %v", err)
	}
	if got, _ := cacheRepo.Get(context.Background(), "iss-local", "deadbeef"); got != nil {
		t.Errorf("nonce-bearing live-sign should NOT write to cache; found row %#v", got)
	}
}

func TestRevocationSvc_SetOCSPCacheInvalidator_WireConnects(t *testing.T) {
	// The wire under test: SetOCSPCacheInvalidator stores the invalidator
	// on the service such that subsequent revoke flows can call it.
	// We verify the wire is connected by directly invoking the stored
	// invalidator (the full revoke flow needs a live cert + repo
	// pipeline that's covered elsewhere).
	fake := &fakeInvalidator{}
	svc := NewRevocationSvc(nil, nil, nil)
	svc.SetOCSPCacheInvalidator(fake)

	if err := svc.ocspCacheInvalidator.InvalidateOnRevoke(context.Background(), "iss-local", "ff"); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	if fake.calls != 1 {
		t.Errorf("expected 1 InvalidateOnRevoke call, got %d", fake.calls)
	}
	if fake.lastIssuer != "iss-local" || fake.lastSerial != "ff" {
		t.Errorf("invalidator received wrong args: issuer=%q serial=%q",
			fake.lastIssuer, fake.lastSerial)
	}
}

type fakeInvalidator struct {
	mu         sync.Mutex
	calls      int
	lastIssuer string
	lastSerial string
}

func (f *fakeInvalidator) InvalidateOnRevoke(_ context.Context, issuerID, serialHex string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastIssuer = issuerID
	f.lastSerial = serialHex
	return nil
}
