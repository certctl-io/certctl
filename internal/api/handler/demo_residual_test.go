package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/certctl-io/certctl/internal/auth"
	"github.com/certctl-io/certctl/internal/domain"
)

// Audit 2026-05-11 A-8 — DemoResidualHandler regression coverage.
// Uses fake closures for the cleanup + authType deps so the test
// stays stdlib + httptest only (no DB needed). DB-shape coverage
// lives in cmd/server/preflight_demo_residual_test.go.

func fakeAuthType(s string) func() string { return func() string { return s } }

// fakeAuditWriter captures the last RecordEventWithCategory invocation.
type fakeAuditWriter struct {
	called   atomic.Bool
	lastCall struct {
		actor, action, category, resourceType, resourceID string
		details                                           map[string]interface{}
	}
}

func (f *fakeAuditWriter) RecordEventWithCategory(
	ctx context.Context, actor string, actorType domain.ActorType,
	action, eventCategory, resourceType, resourceID string,
	details map[string]interface{},
) error {
	f.called.Store(true)
	f.lastCall.actor = actor
	f.lastCall.action = action
	f.lastCall.category = eventCategory
	f.lastCall.resourceType = resourceType
	f.lastCall.resourceID = resourceID
	f.lastCall.details = details
	return nil
}

func authCtxReq(method, path string, actor string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(req.Context(), auth.ActorIDKey{}, actor)
	ctx = context.WithValue(ctx, auth.ActorTypeKey{}, string(domain.ActorTypeAPIKey))
	return req.WithContext(ctx)
}

// TestDemoResidualCleanup_HappyPath — fake cleanup returns 3 rows
// removed; handler emits 200 + JSON body {removed:3} + audit row.
func TestDemoResidualCleanup_HappyPath(t *testing.T) {
	audit := &fakeAuditWriter{}
	h := NewDemoResidualHandler(
		func(ctx context.Context) (int64, error) { return 3, nil },
		fakeAuthType("api-key"),
		audit,
	)
	rec := httptest.NewRecorder()
	h.Cleanup(rec, authCtxReq(http.MethodPost, "/api/v1/auth/demo-residual/cleanup", "k-admin"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body demoResidualCleanupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Removed != 3 {
		t.Errorf("removed = %d, want 3", body.Removed)
	}

	// Audit row must be emitted with the right category + caller actor.
	if !audit.called.Load() {
		t.Fatal("expected audit RecordEventWithCategory to be called")
	}
	if audit.lastCall.action != "auth.demo_residual_grants_cleaned" {
		t.Errorf("audit action = %q, want auth.demo_residual_grants_cleaned", audit.lastCall.action)
	}
	if audit.lastCall.category != domain.EventCategoryAuth {
		t.Errorf("audit category = %q, want %q", audit.lastCall.category, domain.EventCategoryAuth)
	}
	if audit.lastCall.actor != "k-admin" {
		t.Errorf("audit actor = %q, want k-admin", audit.lastCall.actor)
	}
	if audit.lastCall.resourceID != "actor-demo-anon" {
		t.Errorf("audit resource_id = %q, want actor-demo-anon", audit.lastCall.resourceID)
	}
	if got, ok := audit.lastCall.details["removed"].(int64); !ok || got != 3 {
		t.Errorf("audit details.removed = %v, want 3", audit.lastCall.details["removed"])
	}
}

// TestDemoResidualCleanup_Idempotent_ReturnsZero — fake cleanup returns
// (0, nil); the handler still emits 200 + body {removed:0} + audit.
func TestDemoResidualCleanup_Idempotent_ReturnsZero(t *testing.T) {
	audit := &fakeAuditWriter{}
	h := NewDemoResidualHandler(
		func(ctx context.Context) (int64, error) { return 0, nil },
		fakeAuthType("api-key"),
		audit,
	)
	rec := httptest.NewRecorder()
	h.Cleanup(rec, authCtxReq(http.MethodPost, "/api/v1/auth/demo-residual/cleanup", "k-admin"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body demoResidualCleanupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Removed != 0 {
		t.Errorf("removed = %d, want 0", body.Removed)
	}
	// Audit row should STILL fire on a no-op cleanup so the operator's
	// action is recorded. This is intentional — the cleanup endpoint is
	// admin-class and every invocation should leave a trail.
	if !audit.called.Load() {
		t.Error("audit row must fire even on no-op cleanup")
	}
}

// TestDemoResidualCleanup_RejectsInDemoMode — Auth.Type=none returns 503.
func TestDemoResidualCleanup_RejectsInDemoMode(t *testing.T) {
	audit := &fakeAuditWriter{}
	var cleanupCalled atomic.Bool
	h := NewDemoResidualHandler(
		func(ctx context.Context) (int64, error) {
			cleanupCalled.Store(true)
			return 0, nil
		},
		fakeAuthType("none"),
		audit,
	)
	rec := httptest.NewRecorder()
	h.Cleanup(rec, authCtxReq(http.MethodPost, "/api/v1/auth/demo-residual/cleanup", "k-admin"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "demo mode") {
		t.Errorf("body = %q, want mention of demo mode", rec.Body.String())
	}
	// The cleanup closure must NOT have been called.
	if cleanupCalled.Load() {
		t.Error("cleanup closure called despite demo-mode reject")
	}
	// No audit row should fire on rejection — the action didn't happen.
	if audit.called.Load() {
		t.Error("audit row fired on rejected cleanup; should not")
	}
}

// TestDemoResidualCleanup_CleanupError_Surfaces500 — cleanup func
// returns an error; handler emits 500.
func TestDemoResidualCleanup_CleanupError_Surfaces500(t *testing.T) {
	audit := &fakeAuditWriter{}
	h := NewDemoResidualHandler(
		func(ctx context.Context) (int64, error) { return 0, errors.New("boom") },
		fakeAuthType("api-key"),
		audit,
	)
	rec := httptest.NewRecorder()
	h.Cleanup(rec, authCtxReq(http.MethodPost, "/api/v1/auth/demo-residual/cleanup", "k-admin"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if audit.called.Load() {
		t.Error("audit row fired on cleanup error; should not")
	}
}

// TestDemoResidualCleanup_NilCleanupFn — handler with no wired
// cleanup returns 500 (defensive — should never happen in prod, but
// the contract should be observable).
func TestDemoResidualCleanup_NilCleanupFn(t *testing.T) {
	h := DemoResidualHandler{cleanup: nil, authType: fakeAuthType("api-key")}
	rec := httptest.NewRecorder()
	h.Cleanup(rec, authCtxReq(http.MethodPost, "/api/v1/auth/demo-residual/cleanup", "k-admin"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestDemoResidualCleanup_NilAuditWriter_DoesNotPanic — audit is
// optional (Bundle-2 wiring may set it nil in tests / minimal configs).
// Handler must still succeed with valid cleanup.
func TestDemoResidualCleanup_NilAuditWriter_DoesNotPanic(t *testing.T) {
	h := NewDemoResidualHandler(
		func(ctx context.Context) (int64, error) { return 1, nil },
		fakeAuthType("api-key"),
		nil,
	)
	rec := httptest.NewRecorder()
	h.Cleanup(rec, authCtxReq(http.MethodPost, "/api/v1/auth/demo-residual/cleanup", "k-admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestDemoResidualCleanup_MissingActorContext — caller without
// ActorIDKey gets "unknown" recorded; the cleanup still runs. The
// rbacGate at the router enforces that authenticated callers reach
// this point, so missing actor context is purely a test-shape thing.
func TestDemoResidualCleanup_MissingActorContext(t *testing.T) {
	audit := &fakeAuditWriter{}
	h := NewDemoResidualHandler(
		func(ctx context.Context) (int64, error) { return 1, nil },
		fakeAuthType("api-key"),
		audit,
	)
	rec := httptest.NewRecorder()
	// No auth context — bare httptest.NewRequest.
	h.Cleanup(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/demo-residual/cleanup", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if audit.lastCall.actor != "unknown" {
		t.Errorf("audit actor = %q, want unknown for missing actor context", audit.lastCall.actor)
	}
}
