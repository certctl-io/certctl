package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/auth"
)

// Bundle B / Audit M-025 (OWASP ASVS L2 §11.2.1): per-key rate-limiter
// regression suite. Pre-bundle the limiter was global — a single noisy
// caller could exhaust everyone's budget. Post-bundle each authenticated
// user and each distinct IP gets an independent token bucket.

func newKeyedTestHandler(t *testing.T, cfg RateLimitConfig) http.Handler {
	t.Helper()
	return NewRateLimiter(cfg)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
}

// TestRateLimiter_M025_TwoIPsHaveIndependentBuckets ensures one IP
// exhausting its bucket does not affect another IP.
func TestRateLimiter_M025_TwoIPsHaveIndependentBuckets(t *testing.T) {
	h := newKeyedTestHandler(t, RateLimitConfig{RPS: 0.0001, BurstSize: 1})

	// IP A burns its single token.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("IP A first request should pass; got %d", rr.Code)
	}

	// IP A's second request must 429.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("IP A second request should 429; got %d", rr.Code)
	}

	// IP B's first request must still pass — independent bucket.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.2:54321"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("IP B first request must pass (independent bucket); got %d", rr2.Code)
	}
}

// TestRateLimiter_M025_SameUserDifferentIPsShareBucket pins the keying
// rule that authenticated callers are bucketed by user identity, not by
// IP — so a user rotating between devices still shares one budget.
func TestRateLimiter_M025_SameUserDifferentIPsShareBucket(t *testing.T) {
	h := newKeyedTestHandler(t, RateLimitConfig{RPS: 0.0001, BurstSize: 1})

	mkReq := func(remote string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		ctx := context.WithValue(req.Context(), auth.UserKey{}, "alice")
		return req.WithContext(ctx)
	}

	// Alice from IP X exhausts her bucket.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, mkReq("10.0.0.1:54321"))
	if rr.Code != http.StatusOK {
		t.Fatalf("alice first request should pass; got %d", rr.Code)
	}

	// Alice from IP Y must 429 — same user-scoped bucket.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, mkReq("10.0.0.2:54321"))
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("alice second request from different IP should still 429; got %d", rr.Code)
	}
}

// TestRateLimiter_M025_TwoUsersHaveIndependentBuckets pins the keying rule
// that two authenticated users share neither buckets nor side effects.
func TestRateLimiter_M025_TwoUsersHaveIndependentBuckets(t *testing.T) {
	h := newKeyedTestHandler(t, RateLimitConfig{RPS: 0.0001, BurstSize: 1})

	mkReq := func(user string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:54321"
		ctx := context.WithValue(req.Context(), auth.UserKey{}, user)
		return req.WithContext(ctx)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, mkReq("alice"))
	if rr.Code != http.StatusOK {
		t.Fatalf("alice first request should pass; got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, mkReq("alice"))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("alice second request should 429; got %d", rr.Code)
	}

	// Bob shares the same RemoteAddr but his bucket is independent.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, mkReq("bob"))
	if rr.Code != http.StatusOK {
		t.Errorf("bob's first request must pass despite alice exhausting hers; got %d", rr.Code)
	}
}

// TestRateLimiter_M025_PerUserBudgetOverride exercises the optional
// PerUserRPS / PerUserBurstSize knobs. Authenticated callers get the
// generous budget; unauthenticated callers stay on the strict default.
func TestRateLimiter_M025_PerUserBudgetOverride(t *testing.T) {
	cfg := RateLimitConfig{
		RPS:              0.0001,
		BurstSize:        1, // strict for unauthenticated
		PerUserRPS:       0.0001,
		PerUserBurstSize: 5, // generous for authenticated
	}
	h := newKeyedTestHandler(t, cfg)

	// IP-keyed: 1 token, second request 429.
	ipReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.99:54321"
		return req
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, ipReq())
	if rr.Code != http.StatusOK {
		t.Fatalf("ip request 1 should pass; got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, ipReq())
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("ip request 2 should 429; got %d", rr.Code)
	}

	// User-keyed: 5 tokens, sixth request 429.
	userReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.42:54321"
		ctx := context.WithValue(req.Context(), auth.UserKey{}, "carol")
		return req.WithContext(ctx)
	}
	for i := 1; i <= 5; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, userReq())
		if rr.Code != http.StatusOK {
			t.Errorf("user request %d should pass; got %d", i, rr.Code)
		}
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, userReq())
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("user request 6 should 429 (over PerUserBurstSize); got %d", rr.Code)
	}
}

// TestRateLimiter_M025_EmptyUserKeyTreatedAsAnonymous ensures a
// misconfigured auth middleware that puts an empty string under UserKey
// does NOT collapse every anonymous request onto a single bucket.
func TestRateLimiter_M025_EmptyUserKeyTreatedAsAnonymous(t *testing.T) {
	h := newKeyedTestHandler(t, RateLimitConfig{RPS: 0.0001, BurstSize: 1})

	mkReq := func(remote string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		ctx := context.WithValue(req.Context(), auth.UserKey{}, "")
		return req.WithContext(ctx)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, mkReq("10.0.1.1:54321"))
	if rr.Code != http.StatusOK {
		t.Fatalf("first anonymous request should pass; got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, mkReq("10.0.1.2:54321"))
	if rr.Code != http.StatusOK {
		t.Errorf("second anonymous request from different IP should still pass (independent IP buckets); got %d", rr.Code)
	}
}

// =============================================================================
// SEC-006 closure (Sprint 2, 2026-05-16). The token-bucket map now has
// a background sweeper that evicts buckets whose last allow() call is
// older than the configured BucketTTL. This test pins the eviction
// path against a synthetic 1000-key load and asserts:
//
//   1. Buckets created by N distinct keys land in the map.
//   2. After the simulated TTL elapses and the sweeper runs, the map
//      is reclaimed and evictedTotal reflects the count.
//   3. A subsequent request from a fresh key creates a new bucket
//      (i.e. the map isn't poisoned by the eviction).
//
// The test calls sweep() directly rather than relying on the goroutine
// + time.Ticker so it stays deterministic and fast. The sweeper
// goroutine itself is exercised in production; this test pins the
// eviction predicate.
// =============================================================================

func TestKeyedRateLimiter_SweepEvictsIdleBuckets(t *testing.T) {
	limiter := &keyedRateLimiter{
		ipRate:    1000,
		ipBurst:   1000,
		userRate:  1000,
		userBurst: 1000,
		buckets:   make(map[string]*tokenBucket),
		bucketTTL: 100 * time.Millisecond,
	}

	// Populate 1000 buckets from a synthetic IP-key churn.
	for i := 0; i < 1000; i++ {
		key := "ip:198.51.100." + fmt.Sprintf("%d", i%256) + "/" + fmt.Sprintf("%d", i)
		if !limiter.allow(key, false) {
			t.Fatalf("synthetic IP-key %d: allow returned false on first call", i)
		}
	}
	limiter.mu.RLock()
	if got := len(limiter.buckets); got != 1000 {
		limiter.mu.RUnlock()
		t.Fatalf("post-populate bucket count = %d; want 1000", got)
	}
	limiter.mu.RUnlock()

	// Advance past the TTL boundary, then sweep.
	time.Sleep(110 * time.Millisecond)
	limiter.sweep()

	limiter.mu.RLock()
	remaining := len(limiter.buckets)
	limiter.mu.RUnlock()
	if remaining != 0 {
		t.Errorf("post-sweep bucket count = %d; want 0 (all should have been evicted)", remaining)
	}
	if got := limiter.evictedTotal.Load(); got != 1000 {
		t.Errorf("evictedTotal = %d; want 1000", got)
	}

	// A fresh request creates a new bucket — map isn't poisoned.
	if !limiter.allow("ip:203.0.113.7", false) {
		t.Errorf("fresh key: allow returned false on first call after sweep")
	}
	limiter.mu.RLock()
	defer limiter.mu.RUnlock()
	if got := len(limiter.buckets); got != 1 {
		t.Errorf("post-sweep-plus-one bucket count = %d; want 1", got)
	}
}

// TestKeyedRateLimiter_SweepKeepsActiveBuckets pins the inverse — a
// bucket touched within the TTL window survives the sweep. Catches a
// future regression that inverts the cutoff comparison.
func TestKeyedRateLimiter_SweepKeepsActiveBuckets(t *testing.T) {
	limiter := &keyedRateLimiter{
		ipRate:    1000,
		ipBurst:   1000,
		userRate:  1000,
		userBurst: 1000,
		buckets:   make(map[string]*tokenBucket),
		bucketTTL: 1 * time.Hour, // generous so test timing doesn't flake
	}
	limiter.allow("ip:198.51.100.42", false)
	limiter.sweep()
	limiter.mu.RLock()
	defer limiter.mu.RUnlock()
	if got := len(limiter.buckets); got != 1 {
		t.Errorf("active-bucket count = %d; want 1 (sweep should not evict within TTL)", got)
	}
	if got := limiter.evictedTotal.Load(); got != 0 {
		t.Errorf("evictedTotal = %d; want 0 (no evictions expected)", got)
	}
}
