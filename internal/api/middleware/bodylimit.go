package middleware

import (
	"net/http"
)

// BodyLimitConfig holds configuration for the body size limit middleware.
type BodyLimitConfig struct {
	MaxBytes int64 // Maximum request body size in bytes; 0 = use default (1MB)
}

// DefaultMaxBodySize is the default maximum request body size (1MB).
const DefaultMaxBodySize int64 = 1 * 1024 * 1024

// NewBodyLimit creates a middleware that limits request body size.
// If the body exceeds the configured limit, the server returns 413 Request Entity Too Large.
// This prevents clients from sending excessively large payloads that could cause
// memory exhaustion or denial of service (CWE-400).
func NewBodyLimit(cfg BodyLimitConfig) func(http.Handler) http.Handler {
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodySize
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip body limit for requests without bodies
			if r.Body == nil || r.ContentLength == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Wrap the body with MaxBytesReader
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}
