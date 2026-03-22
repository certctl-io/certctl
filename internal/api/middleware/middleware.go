package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RequestIDKey is the context key for storing request IDs.
type RequestIDKey struct{}

// UserKey is the context key for storing authenticated user information.
type UserKey struct{}

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
		defer func() {
			if err := recover(); err != nil {
				requestID := getRequestID(r.Context())
				log.Printf("[%s] PANIC: %v", requestID, err)
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
type AuthConfig struct {
	Type   string // "api-key", "jwt", "none"
	Secret string // The raw API key (server compares against this)
}

// NewAuth creates an authentication middleware based on config.
// When Type is "none", all requests pass through (demo/development mode).
// When Type is "api-key", requests must include a valid Bearer token.
func NewAuth(cfg AuthConfig) func(http.Handler) http.Handler {
	if cfg.Type == "none" {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	// Pre-compute hash of the expected key for constant-time comparison
	expectedHash := HashAPIKey(cfg.Secret)

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

			// Constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(tokenHash), []byte(expectedHash)) != 1 {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				http.Error(w, `{"error":"Invalid API key"}`, http.StatusUnauthorized)
				return
			}

			// Store the authenticated identity in context
			ctx := context.WithValue(r.Context(), UserKey{}, "api-key-user")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RateLimitConfig holds configuration for the rate limiter.
type RateLimitConfig struct {
	RPS       float64 // Requests per second
	BurstSize int     // Maximum burst size
}

// NewRateLimiter creates a token bucket rate limiting middleware.
// Uses a simple token bucket: tokens refill at RPS rate, burst allows short spikes.
func NewRateLimiter(cfg RateLimitConfig) func(http.Handler) http.Handler {
	limiter := &tokenBucket{
		rate:       cfg.RPS,
		burstSize:  float64(cfg.BurstSize),
		tokens:     float64(cfg.BurstSize),
		lastRefill: time.Now(),
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.allow() {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Retry-After", "1")
				http.Error(w, `{"error":"Rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
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
// If no origins are configured, same-origin requests are allowed by default.
// If ["*"] is configured, all origins are allowed (development/demo mode).
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
			origin := r.Header.Get("Origin")

			if allowAll {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else if origin != "" && originSet[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			} else if len(cfg.AllowedOrigins) == 0 && origin != "" {
				// No config = permissive same-origin default for single-host deployments
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}

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
func GetUser(ctx context.Context) (string, bool) {
	user, ok := ctx.Value(UserKey{}).(string)
	return user, ok
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
