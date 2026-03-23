package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// AuditRecorder is the interface that the audit middleware uses to record API calls.
// This avoids importing the service package directly, maintaining dependency inversion.
type AuditRecorder interface {
	RecordAPICall(ctx context.Context, method, path, actor string, bodyHash string, status int, latencyMs int64) error
}

// AuditConfig holds configuration for the API audit logging middleware.
type AuditConfig struct {
	// ExcludePaths are path prefixes to skip audit logging (e.g., "/health", "/ready").
	ExcludePaths []string
	// Logger for audit middleware errors (audit recording failures shouldn't break requests).
	Logger *slog.Logger
}

// NewAuditLog creates a middleware that records every API call to the audit trail.
// It captures method, path, authenticated actor, request body hash, response status, and latency.
// Audit recording is best-effort — failures are logged but don't affect the HTTP response.
func NewAuditLog(recorder AuditRecorder, cfg AuditConfig) func(http.Handler) http.Handler {
	excludeSet := make(map[string]bool, len(cfg.ExcludePaths))
	for _, p := range cfg.ExcludePaths {
		excludeSet[p] = true
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip excluded paths (health, readiness probes)
			for prefix := range excludeSet {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}

			start := time.Now()

			// Hash request body for audit (don't store raw bodies — security + size concerns)
			bodyHash := ""
			if r.Body != nil && r.Body != http.NoBody {
				hasher := sha256.New()
				body, err := io.ReadAll(r.Body)
				if err == nil && len(body) > 0 {
					hasher.Write(body)
					bodyHash = hex.EncodeToString(hasher.Sum(nil))[:16] // truncated hash
					// Restore the body for downstream handlers
					r.Body = io.NopCloser(strings.NewReader(string(body)))
				}
			}

			// Extract actor from auth context
			actor := "anonymous"
			if user, ok := GetUser(r.Context()); ok && user != "" {
				actor = user
			}

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			latency := time.Since(start).Milliseconds()

			// Record audit event asynchronously (best-effort, don't block response)
			go func() {
				if err := recorder.RecordAPICall(
					context.Background(),
					r.Method,
					r.URL.Path,
					actor,
					bodyHash,
					wrapped.statusCode,
					latency,
				); err != nil {
					logger.Error("failed to record API audit event",
						"error", err,
						"method", r.Method,
						"path", r.URL.Path,
					)
				}
			}()
		})
	}
}

// AuditServiceAdapter adapts the AuditService to the AuditRecorder interface.
// This keeps the middleware decoupled from the service package.
type AuditServiceAdapter struct {
	recordFn func(ctx context.Context, actor string, actorType string, action string, resourceType string, resourceID string, details map[string]interface{}) error
}

// NewAuditServiceAdapter creates an adapter that bridges the middleware AuditRecorder
// interface to the service layer's RecordEvent method.
func NewAuditServiceAdapter(recordFn func(ctx context.Context, actor string, actorType string, action string, resourceType string, resourceID string, details map[string]interface{}) error) *AuditServiceAdapter {
	return &AuditServiceAdapter{recordFn: recordFn}
}

// RecordAPICall implements AuditRecorder by translating API call data into an audit event.
func (a *AuditServiceAdapter) RecordAPICall(ctx context.Context, method, path, actor string, bodyHash string, status int, latencyMs int64) error {
	details := map[string]interface{}{
		"method":      method,
		"path":        path,
		"body_hash":   bodyHash,
		"status":      status,
		"latency_ms":  latencyMs,
	}

	action := fmt.Sprintf("api_%s", strings.ToLower(method))
	return a.recordFn(ctx, actor, "User", action, "api", path, details)
}
