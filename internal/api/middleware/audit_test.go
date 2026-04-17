package middleware

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockAuditRecorder captures RecordAPICall invocations for testing.
type mockAuditRecorder struct {
	mu      sync.Mutex
	calls   []auditCall
	err     error         // if non-nil, RecordAPICall returns this
	block   chan struct{} // if non-nil, RecordAPICall blocks on receive before returning
}

type auditCall struct {
	Method    string
	Path      string
	Actor     string
	BodyHash  string
	Status    int
	LatencyMs int64
}

func (m *mockAuditRecorder) RecordAPICall(ctx context.Context, method, path, actor, bodyHash string, status int, latencyMs int64) error {
	// Optional: block the recorder until a signal is received so tests can
	// exercise the shutdown-drain path deterministically. The block happens
	// before any state mutation so Flush-timeout tests see the call
	// "in-flight" (wg counter > 0) with no recorded entries yet.
	if m.block != nil {
		<-m.block
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, auditCall{
		Method:    method,
		Path:      path,
		Actor:     actor,
		BodyHash:  bodyHash,
		Status:    status,
		LatencyMs: latencyMs,
	})
	return m.err
}

func (m *mockAuditRecorder) getCalls() []auditCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]auditCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// waitableAuditRecorder wraps a mockAuditRecorder and signals when a recording completes.
// This allows tests to synchronously wait for async audit records without using time.Sleep.
type waitableAuditRecorder struct {
	inner    *mockAuditRecorder
	recorded chan struct{}
}

func newWaitableAuditRecorder() *waitableAuditRecorder {
	return &waitableAuditRecorder{
		inner:    &mockAuditRecorder{},
		recorded: make(chan struct{}, 100), // buffered to avoid blocking
	}
}

func (w *waitableAuditRecorder) RecordAPICall(ctx context.Context, method, path, actor, bodyHash string, status int, latencyMs int64) error {
	err := w.inner.RecordAPICall(ctx, method, path, actor, bodyHash, status, latencyMs)
	// Signal that a recording was completed
	select {
	case w.recorded <- struct{}{}:
	default:
	}
	return err
}

func (w *waitableAuditRecorder) getCalls() []auditCall {
	return w.inner.getCalls()
}

// Wait blocks until a recording is signaled or timeout expires. Returns true if recording completed, false on timeout.
func (w *waitableAuditRecorder) Wait(timeout time.Duration) bool {
	select {
	case <-w.recorded:
		return true
	case <-time.After(timeout):
		return false
	}
}

func TestAuditLog_RecordsAPICall(t *testing.T) {
	recorder := newWaitableAuditRecorder()
	mw := NewAuditLog(recorder, AuditConfig{}).Middleware

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Audit recording is async — wait for goroutine to complete
	if !recorder.Wait(1 * time.Second) {
		t.Fatal("timeout waiting for audit record")
	}

	calls := recorder.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 audit call, got %d", len(calls))
	}
	if calls[0].Method != "GET" {
		t.Errorf("expected method GET, got %s", calls[0].Method)
	}
	if calls[0].Path != "/api/v1/certificates" {
		t.Errorf("expected path /api/v1/certificates, got %s", calls[0].Path)
	}
	if calls[0].Actor != "anonymous" {
		t.Errorf("expected actor anonymous, got %s", calls[0].Actor)
	}
	if calls[0].Status != 200 {
		t.Errorf("expected status 200, got %d", calls[0].Status)
	}
}

func TestAuditLog_CapturesStatusCode(t *testing.T) {
	recorder := newWaitableAuditRecorder()
	mw := NewAuditLog(recorder, AuditConfig{}).Middleware

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/mc-nonexistent", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !recorder.Wait(1 * time.Second) {
		t.Fatal("timeout waiting for audit record")
	}

	calls := recorder.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 audit call, got %d", len(calls))
	}
	if calls[0].Status != 404 {
		t.Errorf("expected status 404, got %d", calls[0].Status)
	}
}

func TestAuditLog_ExcludesHealth(t *testing.T) {
	recorder := newWaitableAuditRecorder()
	mw := NewAuditLog(recorder, AuditConfig{
		ExcludePaths: []string{"/health", "/ready"},
	}).Middleware

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Health endpoint — should be excluded
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Ready endpoint — should be excluded
	req2 := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	// API endpoint — should be recorded
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)

	if !recorder.Wait(1 * time.Second) {
		t.Fatal("timeout waiting for audit record")
	}

	calls := recorder.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 audit call (health/ready excluded), got %d", len(calls))
	}
	if calls[0].Path != "/api/v1/certificates" {
		t.Errorf("expected path /api/v1/certificates, got %s", calls[0].Path)
	}
}

func TestAuditLog_HashesRequestBody(t *testing.T) {
	recorder := newWaitableAuditRecorder()
	mw := NewAuditLog(recorder, AuditConfig{}).Middleware

	// Handler verifies body was restored
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"name":"test"}` {
			t.Errorf("body was not restored: got %q", string(body))
		}
		w.WriteHeader(http.StatusCreated)
	}))

	body := strings.NewReader(`{"name":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", body)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !recorder.Wait(1 * time.Second) {
		t.Fatal("timeout waiting for audit record")
	}

	calls := recorder.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 audit call, got %d", len(calls))
	}
	// Body hash should be a 16-char hex string (truncated SHA-256)
	if len(calls[0].BodyHash) != 16 {
		t.Errorf("expected 16-char body hash, got %q (len=%d)", calls[0].BodyHash, len(calls[0].BodyHash))
	}
	if calls[0].Status != 201 {
		t.Errorf("expected status 201, got %d", calls[0].Status)
	}
}

func TestAuditLog_EmptyBodyNoHash(t *testing.T) {
	recorder := newWaitableAuditRecorder()
	mw := NewAuditLog(recorder, AuditConfig{}).Middleware

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !recorder.Wait(1 * time.Second) {
		t.Fatal("timeout waiting for audit record")
	}

	calls := recorder.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 audit call, got %d", len(calls))
	}
	if calls[0].BodyHash != "" {
		t.Errorf("expected empty body hash for GET, got %q", calls[0].BodyHash)
	}
}

func TestAuditLog_ExtractsAuthenticatedActor(t *testing.T) {
	recorder := newWaitableAuditRecorder()
	mw := NewAuditLog(recorder, AuditConfig{}).Middleware

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/mc-1", nil)
	// Simulate auth middleware having set the user in context
	ctx := context.WithValue(req.Context(), UserKey{}, "api-key-user")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !recorder.Wait(1 * time.Second) {
		t.Fatal("timeout waiting for audit record")
	}

	calls := recorder.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 audit call, got %d", len(calls))
	}
	if calls[0].Actor != "api-key-user" {
		t.Errorf("expected actor api-key-user, got %s", calls[0].Actor)
	}
	if calls[0].Method != "DELETE" {
		t.Errorf("expected method DELETE, got %s", calls[0].Method)
	}
}

func TestAuditLog_RecorderErrorDoesNotBreakResponse(t *testing.T) {
	recorder := &mockAuditRecorder{err: fmt.Errorf("db connection lost")}
	mw := NewAuditLog(recorder, AuditConfig{}).Middleware

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/summary", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Response should still be 200 even though audit recording fails
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 despite recorder error, got %d", rr.Code)
	}
}

func TestAuditLog_CapturesLatency(t *testing.T) {
	recorder := newWaitableAuditRecorder()
	mw := NewAuditLog(recorder, AuditConfig{}).Middleware

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !recorder.Wait(1 * time.Second) {
		t.Fatal("timeout waiting for audit record")
	}

	calls := recorder.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 audit call, got %d", len(calls))
	}
	if calls[0].LatencyMs < 10 {
		t.Errorf("expected latency >= 10ms, got %dms", calls[0].LatencyMs)
	}
}

func TestAuditLog_ExcludesQueryParamsFromPath(t *testing.T) {
	recorder := newWaitableAuditRecorder()
	mw := NewAuditLog(recorder, AuditConfig{}).Middleware

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Send a request with sensitive query parameters
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?api_key=secret123&cursor=abc&status=active", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !recorder.Wait(1 * time.Second) {
		t.Fatal("timeout waiting for audit record")
	}

	calls := recorder.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 audit call, got %d", len(calls))
	}

	// Path should contain ONLY the path, no query parameters
	if calls[0].Path != "/api/v1/certificates" {
		t.Errorf("expected path /api/v1/certificates (no query params), got %s", calls[0].Path)
	}
	if strings.Contains(calls[0].Path, "api_key") {
		t.Error("audit path contains 'api_key' — query parameters leaked into audit trail")
	}
	if strings.Contains(calls[0].Path, "secret123") {
		t.Error("audit path contains sensitive value 'secret123' — query parameters leaked into audit trail")
	}
	if strings.Contains(calls[0].Path, "cursor") {
		t.Error("audit path contains 'cursor' — query parameters leaked into audit trail")
	}
	if strings.Contains(calls[0].Path, "?") {
		t.Error("audit path contains '?' — query string leaked into audit trail")
	}
}

func TestAuditServiceAdapter_TranslatesCallToEvent(t *testing.T) {
	var capturedActor, capturedActorType, capturedAction, capturedResourceType, capturedResourceID string
	var capturedDetails map[string]interface{}

	adapter := NewAuditServiceAdapter(func(ctx context.Context, actor, actorType, action, resourceType, resourceID string, details map[string]interface{}) error {
		capturedActor = actor
		capturedActorType = actorType
		capturedAction = action
		capturedResourceType = resourceType
		capturedResourceID = resourceID
		capturedDetails = details
		return nil
	})

	err := adapter.RecordAPICall(context.Background(), "POST", "/api/v1/certificates", "admin", "abc123", 201, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedActor != "admin" {
		t.Errorf("expected actor admin, got %s", capturedActor)
	}
	if capturedActorType != "User" {
		t.Errorf("expected actorType User, got %s", capturedActorType)
	}
	if capturedAction != "api_post" {
		t.Errorf("expected action api_post, got %s", capturedAction)
	}
	if capturedResourceType != "api" {
		t.Errorf("expected resourceType api, got %s", capturedResourceType)
	}
	if capturedResourceID != "/api/v1/certificates" {
		t.Errorf("expected resourceID /api/v1/certificates, got %s", capturedResourceID)
	}
	if capturedDetails["method"] != "POST" {
		t.Errorf("expected details.method POST, got %v", capturedDetails["method"])
	}
	if capturedDetails["status"] != 201 {
		t.Errorf("expected details.status 201, got %v", capturedDetails["status"])
	}
	if capturedDetails["latency_ms"] != int64(42) {
		t.Errorf("expected details.latency_ms 42, got %v", capturedDetails["latency_ms"])
	}
	if capturedDetails["body_hash"] != "abc123" {
		t.Errorf("expected details.body_hash abc123, got %v", capturedDetails["body_hash"])
	}
}

func TestAuditServiceAdapter_PropagatesError(t *testing.T) {
	adapter := NewAuditServiceAdapter(func(ctx context.Context, actor, actorType, action, resourceType, resourceID string, details map[string]interface{}) error {
		return fmt.Errorf("database error")
	})

	err := adapter.RecordAPICall(context.Background(), "GET", "/api/v1/agents", "user", "", 200, 5)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "database error") {
		t.Errorf("expected database error, got %v", err)
	}
}

// TestAuditLog_FlushDrainsInFlightGoroutines verifies the M-1 shutdown-drain
// contract: Flush blocks until every audit-recording goroutine spawned by the
// middleware completes, then returns nil. Without the drain (pre-M-1 code),
// the DB pool would be closed while in-flight goroutines were still calling
// RecordAPICall, silently dropping audit events (CWE-662 / CWE-400).
func TestAuditLog_FlushDrainsInFlightGoroutines(t *testing.T) {
	// Recorder blocks on `unblock` until the test releases it. This simulates
	// a slow DB write still in flight when shutdown begins.
	unblock := make(chan struct{})
	recorder := &mockAuditRecorder{block: unblock}
	auditMW := NewAuditLog(recorder, AuditConfig{})

	handler := auditMW.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Fire a request. Handler returns immediately; recorder goroutine is
	// parked on the `unblock` channel inside RecordAPICall.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Start Flush in a goroutine — it must block on the WaitGroup until we
	// release the recorder.
	flushDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		flushDone <- auditMW.Flush(ctx)
	}()

	// Confirm Flush is actually blocked (not returning immediately).
	select {
	case err := <-flushDone:
		t.Fatalf("Flush returned before recorder unblocked: err=%v", err)
	case <-time.After(50 * time.Millisecond):
		// expected: Flush is blocked on wg.Wait
	}

	// Release the recorder. Flush should now observe wg counter drop to 0
	// and return nil.
	close(unblock)

	select {
	case err := <-flushDone:
		if err != nil {
			t.Fatalf("expected nil from Flush after drain, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Flush did not return after recorder unblocked")
	}

	// Verify the audit event was actually recorded (i.e., the goroutine
	// completed its write — not just that Flush unblocked).
	calls := recorder.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 recorded audit call, got %d", len(calls))
	}
	if calls[0].Path != "/api/v1/certificates" {
		t.Errorf("expected path /api/v1/certificates, got %s", calls[0].Path)
	}
}

// TestAuditLog_FlushTimeoutReturnsErrAuditFlushTimeout verifies that Flush
// respects its context: when in-flight goroutines exceed the shutdown budget,
// Flush returns an error wrapping ErrAuditFlushTimeout plus ctx.Err(). The
// caller can then decide whether to proceed with teardown anyway.
func TestAuditLog_FlushTimeoutReturnsErrAuditFlushTimeout(t *testing.T) {
	// Recorder will never unblock on its own — we unblock at end of test for
	// a clean race-safe teardown.
	unblock := make(chan struct{})
	recorder := &mockAuditRecorder{block: unblock}
	auditMW := NewAuditLog(recorder, AuditConfig{})

	handler := auditMW.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Flush with a tiny deadline — must time out.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := auditMW.Flush(ctx)

	if err == nil {
		// Release the blocked goroutine before failing so the race detector
		// doesn't trip on teardown.
		close(unblock)
		t.Fatal("expected Flush to return an error on timeout, got nil")
	}
	if !errors.Is(err, ErrAuditFlushTimeout) {
		close(unblock)
		t.Fatalf("expected error to wrap ErrAuditFlushTimeout, got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		close(unblock)
		t.Fatalf("expected error to wrap context.DeadlineExceeded, got %v", err)
	}

	// Race-safe teardown: unblock the recorder goroutine so it exits cleanly
	// before the test returns. The goroutine itself is still detached and
	// will record to the mock even after Flush timed out — that's the
	// documented behavior (Flush surfaces the timeout; caller decides).
	close(unblock)
}
