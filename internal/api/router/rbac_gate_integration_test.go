package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/certctl-io/certctl/internal/auth"
)

// =============================================================================
// Bundle 1 Phase 3.5 integration tests for the rbacGate wraps. The
// pre-Phase-3.5 in-handler auth.IsAdmin checks moved to the router via
// auth.RequirePermission middleware; these tests pin the router-level
// invariant that non-permitted callers get 403 BEFORE the handler body
// runs, and that the protocol-endpoint allowlist (ACME / SCEP / EST /
// OCSP / CRL) bypasses the gate.
// =============================================================================

// fakeChecker satisfies auth.PermissionChecker. permFn returns the
// canned (allowed, error) tuple per call.
type fakeChecker struct {
	permFn func(ctx context.Context, actorID, actorType, tenantID, perm, scopeType string, scopeID *string) (bool, error)
}

func (f *fakeChecker) CheckPermission(ctx context.Context, actorID, actorType, tenantID, perm, scopeType string, scopeID *string) (bool, error) {
	if f.permFn == nil {
		return true, nil
	}
	return f.permFn(ctx, actorID, actorType, tenantID, perm, scopeType, scopeID)
}

// reachedHandler is a sentinel to confirm the gated handler body
// actually ran.
type reachedHandler struct{ called bool }

func (rh *reachedHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	rh.called = true
	w.WriteHeader(http.StatusOK)
}

// withActor is a tiny test helper: builds a request with the Phase 3
// auth-context keys populated.
func withActor(req *http.Request, actorID, actorType string) *http.Request {
	ctx := req.Context()
	ctx = context.WithValue(ctx, auth.ActorIDKey{}, actorID)
	ctx = context.WithValue(ctx, auth.ActorTypeKey{}, actorType)
	return req.WithContext(ctx)
}

func TestRBACGate_DeniedActorReturns403_HandlerNotReached(t *testing.T) {
	rh := &reachedHandler{}
	checker := &fakeChecker{permFn: func(_ context.Context, _, _, _, perm, _ string, _ *string) (bool, error) {
		if perm != "cert.bulk_revoke" {
			t.Errorf("perm = %q, want cert.bulk_revoke", perm)
		}
		return false, nil
	}}
	gated := rbacGate(checker, "cert.bulk_revoke", rh.ServeHTTP)

	req := withActor(httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", nil), "bob", auth.ActorTypeAPIKey)
	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("non-permitted caller should get 403; got %d", rec.Code)
	}
	if rh.called {
		t.Errorf("handler body must NOT run when middleware denies the request")
	}
}

func TestRBACGate_PermittedActorReachesHandler(t *testing.T) {
	rh := &reachedHandler{}
	checker := &fakeChecker{permFn: func(_ context.Context, _, _, _, _, _ string, _ *string) (bool, error) {
		return true, nil
	}}
	gated := rbacGate(checker, "cert.bulk_revoke", rh.ServeHTTP)

	req := withActor(httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", nil), "alice", auth.ActorTypeAPIKey)
	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("permitted caller should reach handler 200; got %d", rec.Code)
	}
	if !rh.called {
		t.Errorf("handler body must run when middleware allows the request")
	}
}

func TestRBACGate_NoCheckerNoOps(t *testing.T) {
	// Test deployments / demo configs may construct HandlerRegistry
	// without a Checker. rbacGate must fall through to the handler in
	// that case so the route stays callable; the middleware is purely
	// optional defense-in-depth here.
	rh := &reachedHandler{}
	gated := rbacGate(nil, "cert.bulk_revoke", rh.ServeHTTP)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", nil)
	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("nil-checker rbacGate should fall through; got %d", rec.Code)
	}
	if !rh.called {
		t.Errorf("nil-checker rbacGate should reach handler unconditionally")
	}
}

func TestRBACGate_NoActorReturns401(t *testing.T) {
	rh := &reachedHandler{}
	checker := &fakeChecker{} // permFn nil -> always allow; never called
	gated := rbacGate(checker, "cert.bulk_revoke", rh.ServeHTTP)

	// No ActorIDKey in context.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", nil)
	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing actor should yield 401; got %d", rec.Code)
	}
	if rh.called {
		t.Errorf("handler body must NOT run when no actor in context")
	}
}

// TestRBACGate_DemoModeChainReachesHandler is the end-to-end Bundle 1
// Phase 3 closure (C1) regression: when CERTCTL_AUTH_TYPE=none, the
// auth.NewDemoModeAuth middleware injects the synthetic actor-demo-anon
// actor into context. The rbacGate downstream sees a populated actor +
// the fake checker (standing in for the seeded admin grant on the
// demo actor) and forwards the request. Without the C1 fix, the
// pre-closure NewAuthWithNamedKeys no-op pass-through would have left
// context unpopulated and the rbacGate would 401 every demo request.
func TestRBACGate_DemoModeChainReachesHandler(t *testing.T) {
	rh := &reachedHandler{}
	// Mirror the seeded admin grant on actor-demo-anon: the checker
	// allows every permission for the demo actor (matches the data
	// migration seeds in 000029_rbac.up.sql).
	checker := &fakeChecker{permFn: func(_ context.Context, actorID, _, _, _, _ string, _ *string) (bool, error) {
		if actorID != auth.DemoAnonActorID {
			t.Errorf("checker called for unexpected actor %q (want demo-anon)", actorID)
		}
		return true, nil
	}}
	gated := rbacGate(checker, "cert.bulk_revoke", rh.ServeHTTP)
	chain := auth.NewDemoModeAuth()(gated)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-revoke", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("demo-mode caller against admin route should reach handler 200; got %d", rec.Code)
	}
	if !rh.called {
		t.Errorf("handler body must run for demo-mode caller (C1 closure regression)")
	}
}
