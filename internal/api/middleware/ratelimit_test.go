package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestRateLimiter_AllowedWithinLimit verifies that requests within the rate limit are allowed.
func TestRateLimiter_AllowedWithinLimit(t *testing.T) {
	handler := NewRateLimiter(RateLimitConfig{RPS: 10, BurstSize: 10})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// TestRateLimiter_ExceededReturns429 verifies that requests exceeding the rate limit get 429.
func TestRateLimiter_ExceededReturns429(t *testing.T) {
	// Create a limiter with very strict limits
	handler := NewRateLimiter(RateLimitConfig{RPS: 0.1, BurstSize: 1})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	// First request should succeed (within burst)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("first request: expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Second request should fail (burst exhausted, no tokens refilled)
	req2 := httptest.NewRequest("GET", "/test", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected status %d, got %d", http.StatusTooManyRequests, w2.Code)
	}
}

// TestRateLimiter_BurstCapacity verifies that burst allows spike in traffic.
func TestRateLimiter_BurstCapacity(t *testing.T) {
	handler := NewRateLimiter(RateLimitConfig{RPS: 1, BurstSize: 5})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	// Fire 5 requests in rapid succession (burst size)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("burst request %d: expected status %d, got %d", i, http.StatusOK, w.Code)
		}
	}

	// 6th request should be rejected (burst exhausted)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("request after burst: expected status %d, got %d", http.StatusTooManyRequests, w.Code)
	}
}

// TestRateLimiter_TokenRefill verifies that tokens refill over time.
func TestRateLimiter_TokenRefill(t *testing.T) {
	handler := NewRateLimiter(RateLimitConfig{RPS: 10, BurstSize: 1})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	// First request succeeds (within burst)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("first request: expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Second request fails (burst exhausted)
	req2 := httptest.NewRequest("GET", "/test", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected status %d, got %d", http.StatusTooManyRequests, w2.Code)
	}

	// Wait for tokens to refill at RPS=10 (100ms per token)
	time.Sleep(150 * time.Millisecond)

	// Third request should succeed (token refilled)
	req3 := httptest.NewRequest("GET", "/test", nil)
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("third request after refill: expected status %d, got %d", http.StatusOK, w3.Code)
	}
}

// TestRateLimiter_ConcurrentRequests verifies behavior under concurrent load.
func TestRateLimiter_ConcurrentRequests(t *testing.T) {
	// Rate limit: 5 RPS, burst of 2
	handler := NewRateLimiter(RateLimitConfig{RPS: 5, BurstSize: 2})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	numGoroutines := 10
	results := make([]int, numGoroutines)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Fire concurrent requests
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			mu.Lock()
			results[idx] = w.Code
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// Count successful vs rate-limited responses
	successCount := 0
	rateLimitedCount := 0
	for _, code := range results {
		if code == http.StatusOK {
			successCount++
		} else if code == http.StatusTooManyRequests {
			rateLimitedCount++
		} else {
			t.Errorf("unexpected status code: %d", code)
		}
	}

	// With burst size 2, at most 2 should succeed immediately
	if successCount > 2 {
		t.Errorf("expected at most 2 concurrent requests to succeed, got %d", successCount)
	}

	// Some should be rate limited
	if rateLimitedCount == 0 {
		t.Error("expected at least some requests to be rate limited")
	}

	if successCount+rateLimitedCount != numGoroutines {
		t.Errorf("request count mismatch: %d + %d != %d", successCount, rateLimitedCount, numGoroutines)
	}
}

// TestRateLimiter_RetryAfterHeader verifies that rate-limited responses include Retry-After.
func TestRateLimiter_RetryAfterHeader(t *testing.T) {
	handler := NewRateLimiter(RateLimitConfig{RPS: 0.1, BurstSize: 1})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	// Exhaust burst
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Trigger rate limit
	req2 := httptest.NewRequest("GET", "/test", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w2.Code)
	}

	// Check for Retry-After header
	retryAfter := w2.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("expected Retry-After header in rate-limited response")
	}
}

// TestRateLimiter_ZeroRPS verifies behavior with RPS=0 (all requests blocked).
func TestRateLimiter_ZeroRPS(t *testing.T) {
	handler := NewRateLimiter(RateLimitConfig{RPS: 0, BurstSize: 1})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	// First request succeeds (burst)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("burst request: expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Second request blocked (no refill with RPS=0)
	req2 := httptest.NewRequest("GET", "/test", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected status %d, got %d", http.StatusTooManyRequests, w2.Code)
	}
}

// TestRateLimiter_VeryHighRPS verifies behavior with very high RPS (unlimited-like).
func TestRateLimiter_VeryHighRPS(t *testing.T) {
	// 1000 RPS should allow most requests through
	handler := NewRateLimiter(RateLimitConfig{RPS: 1000, BurstSize: 100})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	// Fire 50 requests — most should succeed given the high rate
	successCount := 0
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			successCount++
		}
	}

	// With 1000 RPS and 100 burst, most should pass
	if successCount < 40 {
		t.Errorf("expected at least 40 of 50 requests to succeed at 1000 RPS, got %d", successCount)
	}
}
