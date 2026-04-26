package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RequestIDKey is the context key for storing request IDs.
type RequestIDKey struct{}

// UserKey is the context key for storing authenticated user information.
type UserKey struct{}

// AdminKey is the context key for storing admin flag information.
type AdminKey struct{}

// NamedAPIKey represents a named API key with optional admin flag.
type NamedAPIKey struct {
	Name  string
	Key   string
	Admin bool
}

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
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		requestID := getRequestID(r.Context())
		log.Printf("[%s] %s %s %d %v", requestID, r.Method, r.URL.Path, wrapped.statusCode, duration)
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

// HashAPIKey computes the SHA-256 hash of an API key for secure storage.
// We use SHA-256 rather than bcrypt because API keys are high-entropy
// random strings (not user-chosen passwords), so rainbow tables and
// brute-force attacks are not a practical concern.
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// AuthConfig holds configuration for the Auth middleware.
//
// G-1 (P1): valid Type values are "api-key" or "none" only. "jwt" was
// removed because no JWT middleware ships with certctl (silent auth
// downgrade pre-G-1). The single source of truth for the allowed set
// lives at internal/config.AuthType / config.ValidAuthTypes() — prefer
// those constants over string literals when comparing.
type AuthConfig struct {
	Type   string // "api-key" or "none" (see config.AuthType constants)
	Secret string // The raw API key or comma-separated list of valid API keys
}

// NewAuthWithNamedKeys creates an authentication middleware that validates
// Bearer tokens against a set of named API keys. Each key carries a name
// (propagated as the actor via context) and an admin flag (consulted by
// authorization gates such as bulk revocation).
//
// When namedKeys is empty the returned middleware is a no-op pass-through,
// which is used in demo/development mode (CERTCTL_AUTH_TYPE=none). When one
// or more keys are provided, requests must include a matching Bearer token
// or they are rejected with 401.
func NewAuthWithNamedKeys(namedKeys []NamedAPIKey) func(http.Handler) http.Handler {
	if len(namedKeys) == 0 {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	// Pre-compute hashes of all valid keys for constant-time comparison.
	type keyEntry struct {
		hash  string
		name  string
		admin bool
	}
	var entries []keyEntry
	for _, nk := range namedKeys {
		entries = append(entries, keyEntry{
			hash:  HashAPIKey(nk.Key),
			name:  nk.Name,
			admin: nk.Admin,
		})
	}

	// Warn if only one key is configured in production mode
	if len(entries) == 1 {
		slog.Warn("only one API key configured — consider adding a rotation key for zero-downtime rotation")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("WWW-Authenticate", `Bearer realm="certctl"`)
				http.Error(w, `{"error":"Authorization header required"}`, http.StatusUnauthorized)
				return
			}

			// Extract Bearer token
			if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				http.Error(w, `{"error":"Invalid Authorization header format, expected: Bearer <token>"}`, http.StatusUnauthorized)
				return
			}

			token := authHeader[7:]
			tokenHash := HashAPIKey(token)

			// Check against all valid keys using constant-time comparison
			var matched *keyEntry
			for i := range entries {
				if subtle.ConstantTimeCompare([]byte(tokenHash), []byte(entries[i].hash)) == 1 {
					matched = &entries[i]
					break
				}
			}

			if matched == nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				http.Error(w, `{"error":"Invalid API key"}`, http.StatusUnauthorized)
				return
			}

			// Store the authenticated identity and admin flag in context
			ctx := context.WithValue(r.Context(), UserKey{}, matched.name)
			ctx = context.WithValue(ctx, AdminKey{}, matched.admin)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// NewAuth is a legacy shim that converts a comma-separated Secret list into
// synthesized legacy-key-N named entries and delegates to NewAuthWithNamedKeys.
// It preserves the pre-M-002 behavior for callers that still pass raw AuthConfig
// (primarily cmd/server/main_test.go). The synthesized actor is "legacy-key-N"
// rather than the old hardcoded "api-key-user" so audit events carry
// meaningful identity even on the legacy path.
//
// Deprecated: Use NewAuthWithNamedKeys with explicit NamedAPIKey entries.
func NewAuth(cfg AuthConfig) func(http.Handler) http.Handler {
	if cfg.Type == "none" {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	var namedKeys []NamedAPIKey
	idx := 0
	for _, k := range strings.Split(cfg.Secret, ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		namedKeys = append(namedKeys, NamedAPIKey{
			Name:  fmt.Sprintf("legacy-key-%d", idx),
			Key:   k,
			Admin: false,
		})
		idx++
	}
	return NewAuthWithNamedKeys(namedKeys)
}

// RateLimitConfig holds configuration for the rate limiter.
//
// Bundle B / Audit M-025 (OWASP ASVS L2 §11.2.1) extends this with per-user
// and per-IP keying. The historic RPS / BurstSize fields are preserved for
// source compatibility — they now describe the per-key budget rather than
// the global budget. PerUserRPS / PerUserBurstSize, when non-zero, override
// RPS / BurstSize for authenticated callers; the IP-keyed fallback
// continues to use RPS / BurstSize so unauthenticated callers don't get
// a more generous bucket than authenticated ones by default.
type RateLimitConfig struct {
	RPS       float64 // Tokens per second per key (default applies to IP-keyed buckets)
	BurstSize int     // Max tokens per key (default applies to IP-keyed buckets)

	// PerUserRPS overrides RPS for authenticated callers (keyed by UserKey
	// in context). Zero means "use RPS as the authenticated budget too".
	PerUserRPS float64

	// PerUserBurstSize overrides BurstSize for authenticated callers.
	// Zero means "use BurstSize".
	PerUserBurstSize int
}

// NewRateLimiter creates a per-key token bucket rate limiting middleware.
//
// Bundle B / Audit M-025: pre-bundle this returned a single global bucket
// shared across every request, so a single noisy caller could exhaust the
// budget for everyone else (effectively a self-DoS). Post-bundle each
// authenticated user and each unauthenticated IP gets its own bucket. Keys
// are computed per request:
//
//   - Authenticated: "user:" + middleware.GetUser(ctx)
//   - Unauthenticated: "ip:" + r.RemoteAddr's host portion
//
// The bucket map is sync.RWMutex-guarded; create-on-demand for new keys.
// There is no eviction — for a long-running server with millions of unique
// IPs this can leak memory. A future enhancement is per-key TTL via a
// lazy sweeper. For now the leak is bounded by realistic operator IP
// fan-out and is acceptable per OWASP ASVS L2 (the threat model is abuse
// by a known set of clients, not infinite-cardinality scanners).
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

	limiter := &keyedRateLimiter{
		ipRate:       cfg.RPS,
		ipBurst:      float64(cfg.BurstSize),
		userRate:     perUserRPS,
		userBurst:    perUserBurst,
		buckets:      make(map[string]*tokenBucket),
	}

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
// by NewAuthWithNamedKeys; everyone else falls back to "ip:<host>" parsed
// from r.RemoteAddr (X-Forwarded-For is intentionally NOT consulted here
// — operators behind a trusted proxy must configure that proxy to set
// RemoteAddr correctly, or the rate limiter would be trivially bypassable
// by spoofing the header).
//
// Returns (key, isAuthenticated). Empty UserKey strings are treated as
// unauthenticated so a misconfigured auth middleware doesn't grant the
// same bucket to every anonymous request.
func rateLimitKey(r *http.Request) (string, bool) {
	if user := GetUser(r.Context()); user != "" {
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
type keyedRateLimiter struct {
	mu        sync.RWMutex
	buckets   map[string]*tokenBucket
	ipRate    float64
	ipBurst   float64
	userRate  float64
	userBurst float64
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
			}
			k.buckets[key] = tb
		}
		k.mu.Unlock()
	}
	return tb.allow()
}

// tokenBucket implements a simple thread-safe token bucket rate limiter.
// This avoids importing golang.org/x/time/rate to keep dependencies minimal.
type tokenBucket struct {
	mu         sync.Mutex
	rate       float64   // tokens per second
	burstSize  float64   // max tokens
	tokens     float64   // current tokens
	lastRefill time.Time // last refill time
}

func (tb *tokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

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
				// No CORS headers set — only same-origin requests can read response
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

// CORS middleware adds CORS headers to allow cross-origin requests.
// Deprecated: Use NewCORS for configurable origins. Kept for health endpoints.
func CORS(next http.Handler) http.Handler {
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

// GetUser extracts the authenticated user from context.
// Returns the name of the matched API key and whether it was found.
func GetUser(ctx context.Context) string {
	user, ok := ctx.Value(UserKey{}).(string)
	if !ok {
		return ""
	}
	return user
}

// IsAdmin extracts the admin flag from context.
// Returns true if the authenticated user has admin privileges.
func IsAdmin(ctx context.Context) bool {
	admin, ok := ctx.Value(AdminKey{}).(bool)
	return ok && admin
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
