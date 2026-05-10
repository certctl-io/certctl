package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeChecker implements PermissionChecker for unit tests. The check
// function controls the result; tests pin specific behaviour via
// closures.
type fakeChecker struct {
	check func(ctx context.Context, actorID, actorType, tenantID, perm, scopeType string, scopeID *string) (bool, error)
}

func (f *fakeChecker) CheckPermission(ctx context.Context, actorID, actorType, tenantID, perm, scopeType string, scopeID *string) (bool, error) {
	return f.check(ctx, actorID, actorType, tenantID, perm, scopeType, scopeID)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRequirePermission_NoActorReturns401(t *testing.T) {
	checker := &fakeChecker{check: func(_ context.Context, _, _, _, _, _ string, _ *string) (bool, error) {
		t.Fatalf("checker should not be called when no actor in context")
		return false, nil
	}}
	mw := RequirePermission(checker, "cert.read", nil)
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no actor should yield 401; got %d", rec.Code)
	}
}

func TestRequirePermission_GrantedActorReaches200(t *testing.T) {
	checker := &fakeChecker{check: func(_ context.Context, actorID, actorType, _, perm, _ string, _ *string) (bool, error) {
		if actorID != "alice" {
			t.Errorf("actor id = %q, want alice", actorID)
		}
		if actorType != ActorTypeAPIKey {
			t.Errorf("actor type = %q, want %q", actorType, ActorTypeAPIKey)
		}
		if perm != "cert.read" {
			t.Errorf("perm = %q, want cert.read", perm)
		}
		return true, nil
	}}
	mw := RequirePermission(checker, "cert.read", nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req = req.WithContext(WithActor(req.Context(), "alice"))
	req = req.WithContext(context.WithValue(req.Context(), ActorIDKey{}, "alice"))
	req = req.WithContext(context.WithValue(req.Context(), ActorTypeKey{}, ActorTypeAPIKey))
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("granted actor should reach handler 200; got %d", rec.Code)
	}
}

func TestRequirePermission_DeniedActorReturns403(t *testing.T) {
	checker := &fakeChecker{check: func(_ context.Context, _, _, _, _, _ string, _ *string) (bool, error) {
		return false, nil
	}}
	mw := RequirePermission(checker, "cert.delete", nil)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/mc-1", nil)
	req = req.WithContext(context.WithValue(req.Context(), ActorIDKey{}, "bob"))
	req = req.WithContext(context.WithValue(req.Context(), ActorTypeKey{}, ActorTypeAPIKey))
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("denied actor should yield 403; got %d", rec.Code)
	}
}

func TestRequirePermission_CheckerErrorReturns500(t *testing.T) {
	checker := &fakeChecker{check: func(_ context.Context, _, _, _, _, _ string, _ *string) (bool, error) {
		return false, errors.New("database fell over")
	}}
	mw := RequirePermission(checker, "cert.read", nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req = req.WithContext(context.WithValue(req.Context(), ActorIDKey{}, "alice"))
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("checker error should yield 500; got %d", rec.Code)
	}
}

func TestRequirePermission_ProtocolEndpointBypassesGate(t *testing.T) {
	gateChecks := 0
	checker := &fakeChecker{check: func(_ context.Context, _, _, _, _, _ string, _ *string) (bool, error) {
		gateChecks++
		return false, nil
	}}
	mw := RequirePermission(checker, "cert.read", nil)
	for _, p := range []string{
		"/acme/profile/corp/new-order",
		"/scep",
		"/.well-known/est/cacerts",
		"/.well-known/pki/ocsp",
		"/.well-known/pki/crl/ca.crl",
	} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		// Deliberately no actor: protocol endpoints must reach the
		// handler regardless of context state.
		rec := httptest.NewRecorder()
		mw(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("protocol endpoint %s should bypass gate; got %d", p, rec.Code)
		}
	}
	if gateChecks != 0 {
		t.Errorf("checker should be called zero times for protocol endpoints; got %d", gateChecks)
	}
}

func TestRequirePermission_ScopeFnExtractsResourceID(t *testing.T) {
	captured := struct {
		scopeType string
		scopeID   *string
	}{}
	checker := &fakeChecker{check: func(_ context.Context, _, _, _, _, st string, sid *string) (bool, error) {
		captured.scopeType = st
		captured.scopeID = sid
		return true, nil
	}}
	scope := func(r *http.Request) (string, *string) {
		id := r.URL.Query().Get("profile")
		return "profile", &id
	}
	mw := RequirePermission(checker, "profile.edit", scope)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/profiles/p-corp?profile=p-corp", nil)
	req = req.WithContext(context.WithValue(req.Context(), ActorIDKey{}, "alice"))
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scoped grant should pass; got %d", rec.Code)
	}
	if captured.scopeType != "profile" {
		t.Errorf("scope type = %q, want profile", captured.scopeType)
	}
	if captured.scopeID == nil || *captured.scopeID != "p-corp" {
		t.Errorf("scope id = %v, want p-corp", captured.scopeID)
	}
}

func TestIsProtocolEndpoint_PrefixesOnly(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/acme", true},
		{"/acme/profile/corp/new-order", true},
		{"/scep", true},
		// Query strings live in r.URL.RawQuery; r.URL.Path stays
		// just `/scep`, so callers always pass the path-only form.
		{"/.well-known/est/cacerts", true},
		{"/.well-known/pki/ocsp", true},
		{"/.well-known/pki/crl/ca.crl", true},
		{"/api/v1/certificates", false},
		{"/api/v1/auth/me", false},
		{"/health", false}, // bypassed at the router level, NOT by RBAC.
		{"/acmedotcom", false},
		{"/scepfake", false},
	}
	for _, tc := range cases {
		if got := IsProtocolEndpoint(tc.path); got != tc.want {
			t.Errorf("IsProtocolEndpoint(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestNewDemoModeAuth_InjectsSyntheticActor(t *testing.T) {
	mw := NewDemoModeAuth()
	var captured struct {
		actorID, actorType, user string
		isAdmin                  bool
	}
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured.actorID = GetActorID(r.Context())
		captured.actorType = GetActorType(r.Context())
		captured.user = GetUser(r.Context())
		captured.isAdmin = IsAdmin(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if captured.actorID != DemoAnonActorID {
		t.Errorf("actor id = %q, want %q", captured.actorID, DemoAnonActorID)
	}
	if captured.actorType != ActorTypeAnonymous {
		t.Errorf("actor type = %q, want %q", captured.actorType, ActorTypeAnonymous)
	}
	if captured.user != DemoAnonActorID {
		t.Errorf("legacy UserKey = %q, want %q (back-compat)", captured.user, DemoAnonActorID)
	}
	if !captured.isAdmin {
		t.Errorf("legacy AdminKey should be true in demo mode (back-compat for IsAdmin handlers)")
	}
}

func TestNewAuthWithNamedKeys_PopulatesPhase3ContextKeys(t *testing.T) {
	mw := NewAuthWithNamedKeys([]NamedAPIKey{
		{Name: "alice", Key: "ALICE_KEY", Admin: true},
	})
	var captured struct {
		actorID, actorType, tenantID string
	}
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured.actorID = GetActorID(r.Context())
		captured.actorType = GetActorType(r.Context())
		captured.tenantID = GetTenantID(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Authorization", "Bearer ALICE_KEY")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if captured.actorID != "alice" {
		t.Errorf("Phase 3 actor id = %q, want alice", captured.actorID)
	}
	if captured.actorType != ActorTypeAPIKey {
		t.Errorf("Phase 3 actor type = %q, want %q", captured.actorType, ActorTypeAPIKey)
	}
	if captured.tenantID != DefaultTenantID {
		t.Errorf("Phase 3 tenant id = %q, want %q", captured.tenantID, DefaultTenantID)
	}
}
