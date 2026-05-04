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

// fakeAdminSCEPIntuneService is the test stub for AdminSCEPIntuneService.
// Records call observations so the M-008 admin-gate triplet can pin
// "service was never invoked" when the gate rejects the caller.
type fakeAdminSCEPIntuneService struct {
	statsCalled    bool
	profilesCalled bool
	reloadCalled   bool
	rows           []service.IntuneStatsSnapshot
	profileRows    []service.SCEPProfileStatsSnapshot
	statsErr       error
	profilesErr    error
	reloadPathID   string
	reloadErr      error
}

func (f *fakeAdminSCEPIntuneService) Stats(_ context.Context, _ time.Time) ([]service.IntuneStatsSnapshot, error) {
	f.statsCalled = true
	return f.rows, f.statsErr
}

func (f *fakeAdminSCEPIntuneService) Profiles(_ context.Context, _ time.Time) ([]service.SCEPProfileStatsSnapshot, error) {
	f.profilesCalled = true
	return f.profileRows, f.profilesErr
}

func (f *fakeAdminSCEPIntuneService) ReloadTrust(_ context.Context, pathID string) error {
	f.reloadCalled = true
	f.reloadPathID = pathID
	return f.reloadErr
}

// =============================================================================
// M-008 admin-gate triplet for Stats (GET).
// =============================================================================

func TestAdminSCEPIntune_NonAdmin_Returns403(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{}
	h := NewAdminSCEPIntuneHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/scep/intune/stats", nil)
	req = req.WithContext(contextWithRequestID()) // request id only, no admin flag
	w := httptest.NewRecorder()

	h.Stats(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d (body=%q)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	msg, _ := resp["message"].(string)
	if !strings.Contains(strings.ToLower(msg), "admin") {
		t.Errorf("expected message to mention admin requirement, got %q", msg)
	}
	if svc.statsCalled {
		t.Errorf("service was invoked despite non-admin caller — gate failed open")
	}
}

func TestAdminSCEPIntune_AdminExplicitFalse_Returns403(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{}
	h := NewAdminSCEPIntuneHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/scep/intune/stats", nil)
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Stats(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for admin=false, got %d", w.Code)
	}
	if svc.statsCalled {
		t.Error("service called despite admin=false gate")
	}
}

func TestAdminSCEPIntune_AdminPermitted_ForwardsActor(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{
		rows: []service.IntuneStatsSnapshot{
			{PathID: "corp", IssuerID: "iss-corp", Enabled: true},
			{PathID: "iot", IssuerID: "iss-iot", Enabled: false},
		},
	}
	h := NewAdminSCEPIntuneHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/scep/intune/stats", nil)
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	ctx = context.WithValue(ctx, middleware.UserKey{}, "ops-admin")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Stats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin caller, got %d (body=%q)", w.Code, w.Body.String())
	}
	if !svc.statsCalled {
		t.Fatal("service was not invoked for admin caller")
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if pc, ok := resp["profile_count"].(float64); !ok || pc != 2 {
		t.Errorf("profile_count = %v, want 2", resp["profile_count"])
	}
	if _, ok := resp["profiles"].([]any); !ok {
		t.Errorf("profiles missing or wrong shape: %v", resp["profiles"])
	}
}

// =============================================================================
// M-008 triplet for ReloadTrust (POST).
// =============================================================================

func TestAdminSCEPIntuneReload_NonAdmin_Returns403(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{}
	h := NewAdminSCEPIntuneHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/scep/intune/reload-trust",
		strings.NewReader(`{"path_id":"corp"}`))
	req.ContentLength = int64(len(`{"path_id":"corp"}`))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.ReloadTrust(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 non-admin, got %d", w.Code)
	}
	if svc.reloadCalled {
		t.Error("service called despite non-admin gate")
	}
}

func TestAdminSCEPIntuneReload_AdminExplicitFalse_Returns403(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{}
	h := NewAdminSCEPIntuneHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/scep/intune/reload-trust",
		strings.NewReader(`{"path_id":"corp"}`))
	req.ContentLength = int64(len(`{"path_id":"corp"}`))
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.ReloadTrust(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 admin=false, got %d", w.Code)
	}
	if svc.reloadCalled {
		t.Error("service called despite admin=false gate")
	}
}

func TestAdminSCEPIntuneReload_AdminPermitted_ForwardsActor(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{}
	h := NewAdminSCEPIntuneHandler(svc)
	body := `{"path_id":"corp"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/scep/intune/reload-trust",
		strings.NewReader(body))
	req.ContentLength = int64(len(body))
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	ctx = context.WithValue(ctx, middleware.UserKey{}, "ops-admin")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.ReloadTrust(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", w.Code, w.Body.String())
	}
	if !svc.reloadCalled {
		t.Fatal("reload was not invoked")
	}
	if svc.reloadPathID != "corp" {
		t.Errorf("path_id forwarded = %q, want corp", svc.reloadPathID)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if reloaded, _ := resp["reloaded"].(bool); !reloaded {
		t.Errorf("response.reloaded = %v, want true", resp["reloaded"])
	}
}

// =============================================================================
// Endpoint behavior — method gates, error mapping, body parsing.
// =============================================================================

func TestAdminSCEPIntuneStats_RejectsNonGetMethod(t *testing.T) {
	h := NewAdminSCEPIntuneHandler(&fakeAdminSCEPIntuneService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/scep/intune/stats", nil)
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Stats(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", w.Code)
	}
}

func TestAdminSCEPIntuneReload_RejectsNonPostMethod(t *testing.T) {
	h := NewAdminSCEPIntuneHandler(&fakeAdminSCEPIntuneService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/scep/intune/reload-trust", nil)
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestAdminSCEPIntuneStats_PropagatesServiceError(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{statsErr: errors.New("registry walk failed")}
	h := NewAdminSCEPIntuneHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/scep/intune/stats", nil)
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Stats(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on service error, got %d", w.Code)
	}
}

func TestAdminSCEPIntuneReload_ProfileNotFound_Returns404(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{reloadErr: ErrAdminSCEPProfileNotFound}
	h := NewAdminSCEPIntuneHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/scep/intune/reload-trust",
		strings.NewReader(`{"path_id":"nonexistent"}`))
	req.ContentLength = int64(len(`{"path_id":"nonexistent"}`))
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown profile, got %d", w.Code)
	}
}

func TestAdminSCEPIntuneReload_IntuneDisabled_Returns409(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{reloadErr: service.ErrSCEPProfileIntuneDisabled}
	h := NewAdminSCEPIntuneHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/scep/intune/reload-trust",
		strings.NewReader(`{"path_id":"iot"}`))
	req.ContentLength = int64(len(`{"path_id":"iot"}`))
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for Intune-disabled profile, got %d", w.Code)
	}
}

func TestAdminSCEPIntuneReload_BadReloadPropagates500(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{reloadErr: errors.New("trust anchor cert expired")}
	h := NewAdminSCEPIntuneHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/scep/intune/reload-trust",
		strings.NewReader(`{"path_id":"corp"}`))
	req.ContentLength = int64(len(`{"path_id":"corp"}`))
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on bad reload, got %d", w.Code)
	}
}

func TestAdminSCEPIntuneReload_EmptyBodyTargetsLegacyRoot(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{}
	h := NewAdminSCEPIntuneHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/scep/intune/reload-trust", nil)
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with empty body (legacy root path), got %d", w.Code)
	}
	if svc.reloadPathID != "" {
		t.Errorf("empty body should target empty PathID; got %q", svc.reloadPathID)
	}
}

func TestAdminSCEPIntuneReload_RejectsMalformedJSON(t *testing.T) {
	h := NewAdminSCEPIntuneHandler(&fakeAdminSCEPIntuneService{})
	bad := `{not valid json`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/scep/intune/reload-trust",
		strings.NewReader(bad))
	req.ContentLength = int64(len(bad))
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReloadTrust(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on malformed JSON, got %d", w.Code)
	}
}

// =============================================================================
// AdminSCEPIntuneServiceImpl — narrow integration with the per-profile map.
// =============================================================================

func TestAdminSCEPIntuneServiceImpl_NilMapReturnsEmpty(t *testing.T) {
	impl := NewAdminSCEPIntuneServiceImpl(nil)
	rows, err := impl.Stats(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("nil-map Stats: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("nil-map Stats len=%d, want 0", len(rows))
	}
}

func TestAdminSCEPIntuneServiceImpl_ReloadUnknownPathReturnsNotFound(t *testing.T) {
	impl := NewAdminSCEPIntuneServiceImpl(map[string]*service.SCEPService{})
	if err := impl.ReloadTrust(context.Background(), "nope"); !errors.Is(err, ErrAdminSCEPProfileNotFound) {
		t.Errorf("ReloadTrust unknown = %v, want ErrAdminSCEPProfileNotFound", err)
	}
}

// =============================================================================
// M-008 admin-gate triplet for Profiles (GET) — Phase 9 follow-up endpoint.
// =============================================================================

func TestAdminSCEPProfiles_NonAdmin_Returns403(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{}
	h := NewAdminSCEPIntuneHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/scep/profiles", nil)
	req = req.WithContext(contextWithRequestID()) // request id only, no admin flag
	w := httptest.NewRecorder()

	h.Profiles(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d (body=%q)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	msg, _ := resp["message"].(string)
	if !strings.Contains(strings.ToLower(msg), "admin") {
		t.Errorf("expected message to mention admin requirement, got %q", msg)
	}
	if svc.profilesCalled {
		t.Errorf("service was invoked despite non-admin caller — gate failed open")
	}
}

func TestAdminSCEPProfiles_AdminExplicitFalse_Returns403(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{}
	h := NewAdminSCEPIntuneHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/scep/profiles", nil)
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Profiles(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for admin=false, got %d", w.Code)
	}
	if svc.profilesCalled {
		t.Error("service called despite admin=false gate")
	}
}

func TestAdminSCEPProfiles_AdminPermitted_ForwardsActor(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{
		profileRows: []service.SCEPProfileStatsSnapshot{
			{
				PathID:               "corp",
				IssuerID:             "iss-corp",
				ChallengePasswordSet: true,
				MTLSEnabled:          true,
				Intune: &service.IntuneSection{
					Audience: "https://certctl.example.com/scep/corp",
				},
			},
			{
				PathID:               "iot",
				IssuerID:             "iss-iot",
				ChallengePasswordSet: true,
				// Intune nil — disabled
			},
		},
	}
	h := NewAdminSCEPIntuneHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/scep/profiles", nil)
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey{}, "test-request-id")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, true)
	ctx = context.WithValue(ctx, middleware.UserKey{}, "ops-admin")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Profiles(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin caller, got %d (body=%q)", w.Code, w.Body.String())
	}
	if !svc.profilesCalled {
		t.Fatal("service was not invoked for admin caller")
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if pc, ok := resp["profile_count"].(float64); !ok || pc != 2 {
		t.Errorf("profile_count = %v, want 2", resp["profile_count"])
	}
	rows, ok := resp["profiles"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("profiles missing or wrong shape: %v", resp["profiles"])
	}
	// Find the Intune-enabled vs Intune-disabled row by path_id and
	// assert the Intune sub-block is present/absent accordingly.
	for _, raw := range rows {
		row := raw.(map[string]any)
		switch row["path_id"] {
		case "corp":
			if _, has := row["intune"]; !has {
				t.Errorf("expected corp profile to carry an intune sub-block")
			}
		case "iot":
			if _, has := row["intune"]; has {
				t.Errorf("expected iot profile to OMIT the intune sub-block (Intune disabled)")
			}
		}
	}
}

func TestAdminSCEPProfiles_RejectsNonGetMethod(t *testing.T) {
	h := NewAdminSCEPIntuneHandler(&fakeAdminSCEPIntuneService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/scep/profiles", nil)
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Profiles(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", w.Code)
	}
}

func TestAdminSCEPProfiles_PropagatesServiceError(t *testing.T) {
	svc := &fakeAdminSCEPIntuneService{profilesErr: errors.New("registry walk failed")}
	h := NewAdminSCEPIntuneHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/scep/profiles", nil)
	ctx := context.WithValue(context.Background(), middleware.AdminKey{}, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Profiles(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on service error, got %d", w.Code)
	}
}

func TestAdminSCEPProfilesServiceImpl_NilMapReturnsEmpty(t *testing.T) {
	impl := NewAdminSCEPIntuneServiceImpl(nil)
	rows, err := impl.Profiles(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("nil-map Profiles: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("nil-map Profiles len=%d, want 0", len(rows))
	}
}
