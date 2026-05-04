package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/service"
)

// EST RFC 7030 hardening master bundle Phase 7.4 — admin handler tests.
// Mirrors admin_scep_intune_test.go's structure verbatim:
//   - M-008 admin-gate triplet for both endpoints (non-admin / admin=false / admin=true).
//   - Method-not-allowed gates.
//   - Error mapping (404 unknown PathID / 409 mTLS-disabled / 500 underlying parse error).

// fakeAdminESTService is the test stub. Records call observations so the
// M-008 admin-gate triplet can pin "service was never invoked" when the
// gate rejects the caller.
type fakeAdminESTService struct {
	profilesCalled bool
	reloadCalled   bool
	rows           []service.ESTStatsSnapshot
	profilesErr    error
	reloadPathID   string
	reloadErr      error
}

func (f *fakeAdminESTService) Profiles(_ context.Context, _ time.Time) ([]service.ESTStatsSnapshot, error) {
	f.profilesCalled = true
	return f.rows, f.profilesErr
}

func (f *fakeAdminESTService) ReloadTrust(_ context.Context, pathID string) error {
	f.reloadCalled = true
	f.reloadPathID = pathID
	return f.reloadErr
}

// ----- M-008 admin-gate triplet for Profiles (GET) -----

func TestAdminEST_Profiles_NonAdmin_Returns403(t *testing.T) {
	svc := &fakeAdminESTService{}
	h := NewAdminESTHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/est/profiles", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()
	h.Profiles(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403", w.Code)
	}
	if svc.profilesCalled {
		t.Errorf("service was invoked despite non-admin caller — gate failed open")
	}
}

func TestAdminEST_Profiles_AdminExplicitFalse_Returns403(t *testing.T) {
	svc := &fakeAdminESTService{}
	h := NewAdminESTHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/est/profiles", nil)
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Profiles(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("admin=false status = %d, want 403", w.Code)
	}
	if svc.profilesCalled {
		t.Errorf("service was invoked despite admin=false — gate failed open")
	}
}

func TestAdminEST_Profiles_AdminTrue_Returns200(t *testing.T) {
	svc := &fakeAdminESTService{
		rows: []service.ESTStatsSnapshot{
			{PathID: "corp", IssuerID: "iss-corp"},
		},
	}
	h := NewAdminESTHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/est/profiles", nil)
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Profiles(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want 200; body = %q", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if pc, _ := resp["profile_count"].(float64); int(pc) != 1 {
		t.Errorf("profile_count = %v, want 1", resp["profile_count"])
	}
	if !svc.profilesCalled {
		t.Error("service should have been called")
	}
}

func TestAdminEST_Profiles_MethodNotAllowed(t *testing.T) {
	svc := &fakeAdminESTService{}
	h := NewAdminESTHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/est/profiles", nil)
	w := httptest.NewRecorder()
	h.Profiles(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST against GET-only endpoint status = %d, want 405", w.Code)
	}
}

func TestAdminEST_Profiles_NilRowsSerializedAsEmptyArray(t *testing.T) {
	svc := &fakeAdminESTService{rows: nil}
	h := NewAdminESTHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/est/profiles", nil)
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Profiles(w, req)
	body := w.Body.String()
	if strings.Contains(body, `"profiles":null`) {
		t.Errorf("profiles serialised as null; want []. body=%q", body)
	}
}

// ----- M-008 admin-gate triplet for ReloadTrust (POST) -----

func TestAdminEST_ReloadTrust_NonAdmin_Returns403(t *testing.T) {
	svc := &fakeAdminESTService{}
	h := NewAdminESTHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/est/reload-trust",
		strings.NewReader(`{"path_id":"corp"}`))
	req.ContentLength = int64(len(`{"path_id":"corp"}`))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403", w.Code)
	}
	if svc.reloadCalled {
		t.Errorf("service was invoked despite non-admin caller — gate failed open")
	}
}

func TestAdminEST_ReloadTrust_AdminExplicitFalse_Returns403(t *testing.T) {
	svc := &fakeAdminESTService{}
	h := NewAdminESTHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/est/reload-trust",
		strings.NewReader(`{"path_id":"corp"}`))
	req.ContentLength = int64(len(`{"path_id":"corp"}`))
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("admin=false status = %d, want 403", w.Code)
	}
	if svc.reloadCalled {
		t.Errorf("service was invoked despite admin=false — gate failed open")
	}
}

func TestAdminEST_ReloadTrust_HappyPath(t *testing.T) {
	svc := &fakeAdminESTService{}
	h := NewAdminESTHandler(svc)
	body := `{"path_id":"corp"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/est/reload-trust",
		strings.NewReader(body))
	req.ContentLength = int64(len(body))
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", w.Code, w.Body.String())
	}
	if svc.reloadPathID != "corp" {
		t.Errorf("reloadPathID = %q, want %q", svc.reloadPathID, "corp")
	}
}

func TestAdminEST_ReloadTrust_UnknownPathID_Returns404(t *testing.T) {
	svc := &fakeAdminESTService{reloadErr: ErrAdminESTProfileNotFound}
	h := NewAdminESTHandler(svc)
	body := `{"path_id":"nope"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/est/reload-trust",
		strings.NewReader(body))
	req.ContentLength = int64(len(body))
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown path_id status = %d, want 404", w.Code)
	}
}

func TestAdminEST_ReloadTrust_MTLSDisabled_Returns409(t *testing.T) {
	svc := &fakeAdminESTService{reloadErr: service.ErrESTMTLSDisabled}
	h := NewAdminESTHandler(svc)
	body := `{"path_id":"static-only"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/est/reload-trust",
		strings.NewReader(body))
	req.ContentLength = int64(len(body))
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("mTLS-disabled status = %d, want 409", w.Code)
	}
}

func TestAdminEST_ReloadTrust_ParseError_Returns500(t *testing.T) {
	svc := &fakeAdminESTService{reloadErr: errors.New("trustanchor: cert in /etc/est-corp.pem expired at 2020-01-01")}
	h := NewAdminESTHandler(svc)
	body := `{"path_id":"corp"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/est/reload-trust",
		strings.NewReader(body))
	req.ContentLength = int64(len(body))
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("parse-error status = %d, want 500", w.Code)
	}
}

func TestAdminEST_ReloadTrust_MalformedJSON_Returns400(t *testing.T) {
	svc := &fakeAdminESTService{}
	h := NewAdminESTHandler(svc)
	body := `not-json`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/est/reload-trust",
		strings.NewReader(body))
	req.ContentLength = int64(len(body))
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed-JSON status = %d, want 400", w.Code)
	}
	if svc.reloadCalled {
		t.Errorf("service called despite malformed body")
	}
}

func TestAdminEST_ReloadTrust_MethodNotAllowed(t *testing.T) {
	svc := &fakeAdminESTService{}
	h := NewAdminESTHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/est/reload-trust", nil)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET against POST-only endpoint status = %d, want 405", w.Code)
	}
}

// ----- AdminESTServiceImpl plumbing -----

func TestAdminESTServiceImpl_NilMapAccepted(t *testing.T) {
	svc := NewAdminESTServiceImpl(nil)
	rows, err := svc.Profiles(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("nil-map should produce empty profile list; got %d", len(rows))
	}
}

func TestAdminESTServiceImpl_ReloadTrust_UnknownPath_NotFound(t *testing.T) {
	svc := NewAdminESTServiceImpl(map[string]*service.ESTService{})
	if err := svc.ReloadTrust(context.Background(), "nonexistent"); !errors.Is(err, ErrAdminESTProfileNotFound) {
		t.Errorf("unknown path_id err = %v, want ErrAdminESTProfileNotFound", err)
	}
}
