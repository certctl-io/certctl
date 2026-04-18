package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuditRecorder is the interface that the audit middleware uses to record API calls.
// This avoids importing the service package directly, maintaining dependency inversion.
//
// Implementations may perform I/O (e.g., database writes). The middleware invokes
// RecordAPICall from a tracked goroutine so that callers can drain in-flight
// recordings during graceful shutdown via AuditMiddleware.Flush.
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

// ErrAuditFlushTimeout is returned by AuditMiddleware.Flush when in-flight audit
// recordings do not complete before the provided context is cancelled or its
// deadline elapses. It mirrors scheduler.ErrSchedulerShutdownTimeout so callers
// can branch on graceful-shutdown timeouts consistently across subsystems.
var ErrAuditFlushTimeout = errors.New("audit middleware flush timeout")

// AuditMiddleware is the handle returned by NewAuditLog. It wraps the audit
// logging HTTP middleware and tracks the goroutines spawned to record each API
// call, so that callers can drain them during graceful shutdown (M-1, CWE-662
// / CWE-400). The goroutines themselves still run detached from the request
// context — the shutdown-drain signal flows through this struct's WaitGroup
// instead of the per-request context.
type AuditMiddleware struct {
	recorder   AuditRecorder
	logger     *slog.Logger
	excludeSet map[string]bool

	// wg tracks every audit-recording goroutine spawned by Middleware so Flush
	// can block until they complete before the DB pool is torn down.
	wg sync.WaitGroup
}

// NewAuditLog constructs the API audit logging middleware. The returned
// *AuditMiddleware exposes the HTTP middleware via the Middleware method value
// (same func(http.Handler) http.Handler shape) and a Flush method that the
// process shutdown path must call after the HTTP server has stopped accepting
// new requests but before the audit recorder's backing store (e.g., the
// database connection pool) is closed.
//
// The middleware records method, path, authenticated actor, request body hash,
// response status, and latency. Recording is best-effort — individual failures
// are logged and do not affect the HTTP response. Shutdown is NOT best-effort:
// Flush must succeed (or time out, returning ErrAuditFlushTimeout) so that
// in-flight events are not lost when the audit recorder's connection pool is
// closed out from under the goroutines.
func NewAuditLog(recorder AuditRecorder, cfg AuditConfig) *AuditMiddleware {
	excludeSet := make(map[string]bool, len(cfg.ExcludePaths))
	for _, p := range cfg.ExcludePaths {
		excludeSet[p] = true
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &AuditMiddleware{
		recorder:   recorder,
		logger:     logger,
		excludeSet: excludeSet,
	}
}

// Middleware is the http.Handler wrapper. It has the standard
// func(http.Handler) http.Handler middleware signature so it can be composed
// into an existing middleware chain via a method value (auditMiddleware.Middleware).
func (a *AuditMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip excluded paths (health, readiness probes)
		for prefix := range a.excludeSet {
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

		// Snapshot request-derived inputs so the goroutine does not race with
		// the http.Server reusing r after this handler returns.
		method := r.Method
		path := r.URL.Path
		status := wrapped.statusCode

		// Derive a detached context that preserves request-scoped values
		// (trace IDs, auth info carried via context keys) but is not cancelled
		// when the HTTP server finalizes the request. Using r.Context()
		// directly would cause the async audit write to observe ctx.Done()
		// as soon as the response completes; using context.Background() would
		// discard useful observability metadata. WithoutCancel gives us both
		// (M-2 / D-3).
		auditCtx := context.WithoutCancel(r.Context())

		// Record audit event asynchronously (best-effort, don't block response).
		// SECURITY: We intentionally use r.URL.Path (not r.URL.String() or r.RequestURI)
		// to prevent query parameters from being recorded in the immutable audit trail.
		// Query strings may contain cursor tokens, API keys passed as params, or other
		// sensitive filter values. Since the audit trail is append-only with no deletion
		// capability, any sensitive data recorded would persist permanently.
		//
		// The goroutine is tracked in a.wg so AuditMiddleware.Flush can drain
		// in-flight recordings during graceful shutdown. Without this (M-1,
		// CWE-662 / CWE-400), SIGTERM would close the DB pool while recordings
		// were still mid-flight, silently dropping audit events.
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			if err := a.recorder.RecordAPICall(
				auditCtx,
				method,
				path,
				actor,
				bodyHash,
				status,
				latency,
			); err != nil {
				a.logger.Error("failed to record API audit event",
					"error", err,
					"method", method,
					"path", path,
				)
			}
		}()
	})
}

// Flush blocks until every audit-recording goroutine spawned by Middleware has
// completed, or until ctx is cancelled / its deadline elapses. It must be
// called from the process shutdown path after http.Server.Shutdown has
// returned (so no new requests are being accepted) but before the backing
// audit recorder's resources (DB pool, etc.) are torn down.
//
// On timeout or cancellation Flush returns ErrAuditFlushTimeout wrapped with
// any context error; in-flight goroutines continue to run and may still write
// to the recorder once they unblock — the caller is responsible for deciding
// whether to proceed with teardown anyway or surface the error.
//
// Flush mirrors the idiom used by scheduler.Scheduler.WaitForCompletion so
// that the two subsystems drain identically at shutdown.
func (a *AuditMiddleware) Flush(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		a.logger.Info("audit middleware flush complete")
		return nil
	case <-ctx.Done():
		a.logger.Warn("audit middleware flush did not complete before context cancellation",
			"error", ctx.Err(),
		)
		return fmt.Errorf("%w: %w", ErrAuditFlushTimeout, ctx.Err())
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
