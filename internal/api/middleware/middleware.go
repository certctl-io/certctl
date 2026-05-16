// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/certctl-io/certctl/internal/auth"
)

// Bundle 1 / Phase 0: the auth surface (NamedAPIKey, HashAPIKey, AuthConfig,
// NewAuthWithNamedKeys, NewAuth, UserKey, AdminKey, GetUser, IsAdmin) moved
// to internal/auth/. The rate limiter below still keys per-user via
// auth.GetUser(ctx); other middlewares in this package are auth-agnostic.
//
// Existing callers continue to import internal/auth/middleware "as
// middleware" only for the non-auth helpers below; auth-related references
// have been migrated to the new package.

// RequestIDKey is the context key for storing request IDs.
type RequestIDKey struct{}

// RequestID middleware generates a unique request ID and adds it to the request context and response headers.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), RequestIDKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logging middleware logs request details including method, path, status, and duration.
// Deprecated: Use NewLogging for structured logging with slog.
//
// CWE-117 log-injection defense: r.Method and r.URL.Path are
// attacker-controllable (request-line bytes; Go's net/http leaves
// percent-decoded path segments in r.URL.Path, which can include CR/LF
// in the decoded form even though the raw HTTP request line cannot).
// strings.ReplaceAll on CR/LF/NUL strips the forgery vector before the
// log line is emitted. Closes CodeQL #17 + #32 (go/log-injection).
//
// The replacement is intentionally inlined at the call site (literal
// strings.ReplaceAll chains) because CodeQL's go/log-injection
// taint tracker only recognizes that exact pattern as a sanitizer;
// strings.NewReplacer / wrapper helpers don't trigger the recognition,
// reopening the alert. The OWASP example in the CodeQL rule docs uses
// the same pattern.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		requestID := getRequestID(r.Context())

		// Strip CR/LF/NUL from attacker-controllable request fields
		// before logging. Inlined per CodeQL #32; the ReplaceAll
		// chain is the pattern the analyzer pattern-matches as a
		// sanitizer.
		method := strings.ReplaceAll(r.Method, "\n", "")
		method = strings.ReplaceAll(method, "\r", "")
		method = strings.ReplaceAll(method, "\x00", "")
		urlPath := strings.ReplaceAll(r.URL.Path, "\n", "")
		urlPath = strings.ReplaceAll(urlPath, "\r", "")
		urlPath = strings.ReplaceAll(urlPath, "\x00", "")

		log.Printf("[%s] %s %s %d %v", requestID, method, urlPath, wrapped.statusCode, duration)
	})
}

// NewLogging creates a structured logging middleware using slog.
// Logs request_id, method, path, status, duration_ms, and remote_addr.
func NewLogging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
			requestID := getRequestID(r.Context())

			logger.InfoContext(r.Context(), "request completed",
				"request_id", requestID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration_ms", duration.Milliseconds(),
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}

// Recovery middleware recovers from panics and returns a 500 error.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		defer func() {
			if err := recover(); err != nil {
				requestID := getRequestID(ctx)
				// Use slog.ErrorContext so the panic log carries the same
				// request-scoped trace/auth metadata as normal request logs
				// (M-2 / D-3 — preserve ctx propagation on the panic path).
				slog.ErrorContext(ctx, "panic recovered in HTTP handler",
					"request_id", requestID,
					"panic", fmt.Sprintf("%v", err),
				)
				http.Error(w, `{"error":"Internal Server Error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// RateLimitConfig holds configuration for the rate limiter.
//
// Bundle B / Audit M-025 (OWASP ASVS L2 §11.2.1) extends this with per-user
// and per-IP keying. The historic RPS / BurstSize fields are preserved for
// source compatibility; they now describe the per-key budget rather than
// the global budget. PerUserRPS / PerUserBurstSize, when non-zero, override
// RPS / BurstSize for authenticated callers; the IP-keyed fallback
// continues to use RPS / BurstSize so unauthenticated callers don't get
// a more generous bucket than authenticated ones by default.
type RateLimitConfig struct {
	RPS       float64 // Tokens per second per key (default applies to IP-keyed buckets)
	BurstSize int     // Max tokens per key (default applies to IP-keyed buckets)

	// PerUserRPS overrides RPS for authenticated callers (keyed by
	// auth.UserKey in context). Zero means "use RPS as the authenticated
	// budget too".
	PerUserRPS float64

	// PerUserBurstSize overrides BurstSize for authenticated callers.
	// Zero means "use BurstSize".
	PerUserBurstSize int

	// BucketTTL bounds the lifetime of an unused token bucket in the
	// per-key map. The background sweeper runs every (BucketTTL/4) and
	// removes entries whose last allow() call is older than BucketTTL.
	// Zero or negative values fall through to a 1-hour default; values
	// below 1 minute are clamped up to 1 minute (sweeper sanity).
	// SEC-006 closure (Sprint 2, 2026-05-16).
	BucketTTL time.Duration
}

// NewRateLimiter creates a per-key token bucket rate limiting middleware.
//
// Bundle B / Audit M-025: pre-bundle this returned a single global bucket
// shared across every request, so a single noisy caller could exhaust the
// budget for everyone else (effectively a self-DoS). Post-bundle each
// authenticated user and each unauthenticated IP gets its own bucket. Keys
// are computed per request:
//
//   - Authenticated: "user:" + auth.GetUser(ctx)
//   - Unauthenticated: "ip:" + r.RemoteAddr's host portion
//
// The bucket map is sync.RWMutex-guarded; create-on-demand for new keys.
//
// SEC-006 closure (Sprint 2, 2026-05-16). Pre-fix the bucket map had no
// eviction, so high-cardinality unauthenticated traffic (CGNAT churn,
// Tor exit lists, botnets, infinite-cardinality scanners) grew process
// memory unboundedly. Each bucket now carries `lastAccess`; a background
// sweeper goroutine (one per limiter) wakes every (bucketTTL / 4) and
// removes entries whose lastAccess is older than `bucketTTL`. Default
// TTL is 1 hour — well above realistic operator IP churn windows so a
// returning client gets the same bucket, but bounded enough that a
// scanner's churn is reclaimed within an hour. Operators can override
// via cfg.BucketTTL (or the CERTCTL_RATE_LIMIT_BUCKET_TTL env var that
// cmd/server/main.go threads through).
func NewRateLimiter(cfg RateLimitConfig) func(http.Handler) http.Handler {
	// Default per-user budgets to the IP-keyed budget when not overridden.
	perUserRPS := cfg.PerUserRPS
	if perUserRPS == 0 {
		perUserRPS = cfg.RPS
	}
	perUserBurst := float64(cfg.PerUserBurstSize)
	if perUserBurst == 0 {
		perUserBurst = float64(cfg.BurstSize)
	}

	// SEC-006: bucket TTL eviction. Default 1h; minimum 1m to keep
	// the sweeper from running pathologically often if an operator
	// sets a tiny value.
	bucketTTL := cfg.BucketTTL
	if bucketTTL <= 0 {
		bucketTTL = time.Hour
	}
	if bucketTTL < time.Minute {
		bucketTTL = time.Minute
	}

	limiter := &keyedRateLimiter{
		ipRate:    cfg.RPS,
		ipBurst:   float64(cfg.BurstSize),
		userRate:  perUserRPS,
		userBurst: perUserBurst,
		buckets:   make(map[string]*tokenBucket),
		bucketTTL: bucketTTL,
	}

	// Sweeper goroutine. Single goroutine per limiter; production wires
	// 2 limiters (default + no-auth-fallback) so the cost is 2 idle
	// goroutines per server. Lives for the process lifetime; no
	// shutdown handle is exposed because main.go owns both limiters
	// for the entire run.
	go limiter.sweepLoop()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, isUser := rateLimitKey(r)
			if !limiter.allow(key, isUser) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Retry-After", "1")
				http.Error(w, `{"error":"Rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// rateLimitKey computes the per-request bucket key. Authenticated callers
// get a "user:<name>" key derived from the UserKey context value populated
// by auth.NewAuthWithNamedKeys; everyone else falls back to "ip:<host>"
// parsed from r.RemoteAddr (X-Forwarded-For is intentionally NOT consulted
// here; operators behind a trusted proxy must configure that proxy to set
// RemoteAddr correctly, or the rate limiter would be trivially bypassable
// by spoofing the header).
//
// Returns (key, isAuthenticated). Empty UserKey strings are treated as
// unauthenticated so a misconfigured auth middleware doesn't grant the
// same bucket to every anonymous request.
func rateLimitKey(r *http.Request) (string, bool) {
	if user := auth.GetUser(r.Context()); user != "" {
		return "user:" + user, true
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	if host == "" {
		host = "unknown"
	}
	return "ip:" + host, false
}

// keyedRateLimiter holds a token bucket per (user-or-ip) key with separate
// rate / burst defaults for the user-keyed and ip-keyed dimensions.
//
// SEC-006: bucketTTL bounds the unused-bucket lifetime; sweepLoop runs
// in a goroutine spawned by NewRateLimiter and evicts entries whose
// lastAccess is older than bucketTTL on every (bucketTTL/4) tick.
// evictedTotal exposes the lifetime eviction count (atomic-loaded by
// tests and the operator stats endpoint).
type keyedRateLimiter struct {
	mu        sync.RWMutex
	buckets   map[string]*tokenBucket
	ipRate    float64
	ipBurst   float64
	userRate  float64
	userBurst float64

	bucketTTL    time.Duration
	evictedTotal atomic.Uint64
	// sweepTick is the channel sweepLoop ticks on. Default time.Ticker;
	// tests swap to a manual chan time.Time for deterministic eviction.
	// Set via the (test-only) seam noted below; production never
	// reassigns this field.
	sweepTickCh <-chan time.Time
}

func (k *keyedRateLimiter) allow(key string, isUser bool) bool {
	// Fast path: bucket already exists.
	k.mu.RLock()
	tb, ok := k.buckets[key]
	k.mu.RUnlock()

	if !ok {
		// Slow path: create-on-demand under write lock with double-check.
		k.mu.Lock()
		tb, ok = k.buckets[key]
		if !ok {
			rate, burst := k.ipRate, k.ipBurst
			if isUser {
				rate, burst = k.userRate, k.userBurst
			}
			tb = &tokenBucket{
				rate:       rate,
				burstSize:  burst,
				tokens:     burst,
				lastRefill: time.Now(),
				lastAccess: time.Now(),
			}
			k.buckets[key] = tb
		}
		k.mu.Unlock()
	}
	allowed := tb.allow()
	// SEC-006: update lastAccess on every call (cheap; same mutex
	// the bucket already holds via tb.allow's mu). Sweeper reads
	// this to decide eviction.
	tb.touch()
	return allowed
}

// sweepLoop is the background eviction goroutine spawned by
// NewRateLimiter. It wakes every bucketTTL/4 and removes any bucket
// whose lastAccess is older than bucketTTL. The (bucketTTL/4) cadence
// is a compromise — fast enough to keep the map ceiling tight,
// slow enough that the sweep cost amortises across many requests.
// SEC-006 closure.
func (k *keyedRateLimiter) sweepLoop() {
	// Test seam: if a manual tick channel is wired, use it. Production
	// always uses time.NewTicker which time.Time-types the channel
	// identically.
	if k.sweepTickCh != nil {
		for range k.sweepTickCh {
			k.sweep()
		}
		return
	}
	period := k.bucketTTL / 4
	if period < time.Second {
		period = time.Second
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for range t.C {
		k.sweep()
	}
}

// sweep removes every bucket whose lastAccess is older than bucketTTL
// and bumps evictedTotal. Exported for tests via a same-package alias.
func (k *keyedRateLimiter) sweep() {
	cutoff := time.Now().Add(-k.bucketTTL)
	k.mu.Lock()
	defer k.mu.Unlock()
	for key, tb := range k.buckets {
		if tb.lastAccessTime().Before(cutoff) {
			delete(k.buckets, key)
			k.evictedTotal.Add(1)
		}
	}
}

// tokenBucket implements a simple thread-safe token bucket rate limiter.
// This avoids importing golang.org/x/time/rate to keep dependencies minimal.
//
// SEC-006: lastAccess is updated on every allow() call (via touch()) so
// the keyedRateLimiter sweeper can evict idle buckets without a second
// per-key map. Guarded by the same mu as rate-limiting state.
type tokenBucket struct {
	mu         sync.Mutex
	rate       float64   // tokens per second
	burstSize  float64   // max tokens
	tokens     float64   // current tokens
	lastRefill time.Time // last refill time
	lastAccess time.Time // last allow() call — for SEC-006 sweeper
}

// touch updates the bucket's lastAccess timestamp under its own mutex.
// Called from keyedRateLimiter.allow after the rate-limit decision.
func (tb *tokenBucket) touch() {
	tb.mu.Lock()
	tb.lastAccess = time.Now()
	tb.mu.Unlock()
}

// lastAccessTime is the sweeper's read accessor. Uses the bucket's
// own mutex so the read is consistent with concurrent touch() calls.
func (tb *tokenBucket) lastAccessTime() time.Time {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.lastAccess
}

func (tb *tokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Bundle E / Audit L-013 (monotonic clock): both `now` and
	// `tb.lastRefill` come from `time.Now()`, which carries a
	// monotonic-clock reading per the time package contract. `t1.Sub(t2)`
	// uses the monotonic component when both ts have it, so this elapsed
	// computation is NOT affected by wall-clock drift, NTP slew, DST, or
	// `clock_settime` adjustments. The audit's general concern about
	// `time.Now().Sub` was about wall-clock-only deltas across process
	// boundaries; this is intra-process and monotonic-safe.
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.burstSize {
		tb.tokens = tb.burstSize
	}
	tb.lastRefill = now

	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// CORSConfig holds configuration for the CORS middleware.
type CORSConfig struct {
	AllowedOrigins []string // Allowed origins; empty = same-origin only
}

// NewCORS creates a CORS middleware with configurable allowed origins.
// Security default: If no origins are configured, CORS headers are NOT set,
// denying all cross-origin requests (same-origin only).
// If ["*"] is configured, all origins are allowed (development/demo mode only).
// If specific origins are configured, only requests matching those origins receive CORS headers.
func NewCORS(cfg CORSConfig) func(http.Handler) http.Handler {
	allowAll := false
	originSet := make(map[string]bool)
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			allowAll = true
		}
		originSet[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security default: deny CORS when no origins are configured.
			// This prevents CSRF attacks from arbitrary origins.
			if len(cfg.AllowedOrigins) == 0 {
				// No CORS headers set; only same-origin requests can read response
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")

			if allowAll {
				// Wildcard allows all origins (development/demo only)
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else if origin != "" && originSet[origin] {
				// Exact match found in allowed origins list
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			// If origin is empty or not in allowlist, no CORS headers are set

			// CORS preflight response headers (only meaningful if Access-Control-Allow-Origin was set)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ContentType middleware sets the Content-Type header to application/json.
func ContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

// CORSWildcard emits Access-Control-Allow-Origin: * unconditionally. ONLY use
// for endpoints that (a) carry no credentials and (b) must be reachable from
// any origin (e.g. K8s/Docker health probes, Prometheus scrapers, the GUI's
// pre-login auth-info probe). Every call site MUST appear in
// scripts/ci-guards/cors-wildcard-allowlist.sh — adding a new call site
// without listing it in the allowlist fails CI.
//
// For credentialed endpoints (sessions, OIDC handshake, BCL, bootstrap,
// breakglass-login, every /api/v1/* mutation route) use
// middleware.NewCORS(corsCfg) which honors CERTCTL_CORS_ORIGINS and emits
// per-origin headers (with Vary: Origin for cache correctness).
//
// History: this function was named `CORS` pre-2026-05-10 and was applied as
// the default CORS middleware on the OIDC handshake, BCL, logout, bootstrap,
// and breakglass-login routes — CRIT-3 of the 2026-05-10 audit
// (cowork/auth-bundles-audit-2026-05-10.md). The fix narrowed those call
// sites to NewCORS(corsCfg) and renamed the wildcard form to make the
// security tradeoff explicit at every remaining call site.
func CORSWildcard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetRequestID extracts the request ID from context.
func GetRequestID(ctx context.Context) string {
	return getRequestID(ctx)
}

// getRequestID is an internal helper to extract request ID from context.
func getRequestID(ctx context.Context) string {
	id, ok := ctx.Value(RequestIDKey{}).(string)
	if !ok {
		return "unknown"
	}
	return id
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Chain chains multiple middleware functions.
func Chain(h http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}
