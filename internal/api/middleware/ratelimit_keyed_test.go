package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
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
		ctx := context.WithValue(req.Context(), UserKey{}, "alice")
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
		ctx := context.WithValue(req.Context(), UserKey{}, user)
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
		ctx := context.WithValue(req.Context(), UserKey{}, "carol")
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
		ctx := context.WithValue(req.Context(), UserKey{}, "")
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
