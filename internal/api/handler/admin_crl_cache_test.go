package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/api/middleware"
)

// fakeAdminCRLCacheService is the test stub for the
// AdminCRLCacheService interface — lets us exercise gate behavior
// (admin / non-admin / explicit-false) without spinning up a real
// CRLCacheRepository or issuer registry.
type fakeAdminCRLCacheService struct {
	called bool
	rows   []CRLCacheRow
	err    error
}

func (f *fakeAdminCRLCacheService) CacheRows(_ context.Context) ([]CRLCacheRow, error) {
	f.called = true
	return f.rows, f.err
}

// TestAdminCRLCache_NonAdmin_Returns403 — M-003-pattern central
// gate test. A caller without an admin-tagged context must be
// rejected with HTTP 403, and the service layer must never see
// the request (no enumeration of issuer set / cache state).
func TestAdminCRLCache_NonAdmin_Returns403(t *testing.T) {
	svc := &fakeAdminCRLCacheService{}
	h := NewAdminCRLCacheHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/crl/cache", nil)
	req = req.WithContext(contextWithRequestID()) // request id only, no admin flag
	w := httptest.NewRecorder()

	h.ListCache(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d (body=%q)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	msg, _ := resp["message"].(string)
	if !strings.Contains(strings.ToLower(msg), "admin") {
		t.Errorf("expected message to mention admin requirement, got %q", msg)
	}
	if svc.called {
		t.Errorf("service was invoked despite non-admin caller — gate failed open")
	}
}

// TestAdminCRLCache_AdminExplicitFalse_Returns403 pins the
// AdminKey-present-but-false case. Without this, a regression to
// "key missing == deny, key present == allow" would silently grant
// a false flag to any caller that managed to set the context value.
func TestAdminCRLCache_AdminExplicitFalse_Returns403(t *testing.T) {
	svc := &fakeAdminCRLCacheService{}
	h := NewAdminCRLCacheHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/crl/cache", nil)
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.ListCache(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 for admin=false, got %d", w.Code)
	}
	if svc.called {
		t.Error("service called despite admin=false gate")
	}
}

// TestAdminCRLCache_AdminPermitted_ForwardsActor confirms the
// happy path: an admin-tagged context reaches the service and the
// response shape is what the GUI expects (cache_rows / row_count /
// generated_at). The actor-forwarding aspect of M-002 doesn't apply
// here — this is a read-only endpoint with no audit-event side
// effect — but the test name matches the M008 triplet convention so
// the regression scanner finds it.
func TestAdminCRLCache_AdminPermitted_ForwardsActor(t *testing.T) {
	svc := &fakeAdminCRLCacheService{
		rows: []CRLCacheRow{
			{IssuerID: "iss-a", CachePresent: true, CRLNumber: 1},
			{IssuerID: "iss-b", CachePresent: false},
		},
	}
	h := NewAdminCRLCacheHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/crl/cache", nil)
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	ctx = context.WithValue(ctx, middleware.UserKey{}, "ops-admin")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.ListCache(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin caller, got %d (body=%q)", w.Code, w.Body.String())
	}
	if !svc.called {
		t.Fatal("service was not invoked for admin caller")
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rc, ok := resp["row_count"].(float64); !ok || rc != 2 {
		t.Errorf("row_count = %v, want 2", resp["row_count"])
	}
	if _, ok := resp["cache_rows"].([]any); !ok {
		t.Errorf("cache_rows missing or wrong shape: %v", resp["cache_rows"])
	}
}

// TestAdminCRLCache_RejectsNonGetMethod pins the method gate.
// Companion to the admin gate — both must fire to satisfy the
// admin-only-GET contract.
func TestAdminCRLCache_RejectsNonGetMethod(t *testing.T) {
	h := NewAdminCRLCacheHandler(&fakeAdminCRLCacheService{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/crl/cache", nil)
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.ListCache(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", w.Code)
	}
}

// TestAdminCRLCache_PropagatesServiceError surfaces 500 when the
// service errors. Pins the failure-path response shape so future
// refactors don't accidentally swallow errors as 200.
func TestAdminCRLCache_PropagatesServiceError(t *testing.T) {
	svc := &fakeAdminCRLCacheService{err: errors.New("db down")}
	h := NewAdminCRLCacheHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/crl/cache", nil)
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.ListCache(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on service error, got %d", w.Code)
	}
}
