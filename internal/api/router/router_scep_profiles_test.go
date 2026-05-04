package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/certctl-io/certctl/internal/api/handler"
	"github.com/certctl-io/certctl/internal/domain"
)

// SCEP RFC 8894 + Intune master bundle Phase 1.5: per-issuer profiles router
// registration. Pins:
//
//   1. Empty PathID maps to /scep root (legacy backward-compat).
//   2. Non-empty PathID maps to /scep/<pathID>.
//   3. Multi-profile registration produces 2N routes (GET + POST per profile).
//   4. Each registered route reaches the right handler instance — no
//      cross-profile bleed-through (proven by the per-profile mock counters).
//
// The mock service is a minimal SCEPService implementation that records
// which profile served the request via the GetCACaps capability string —
// the test asserts it sees the right per-profile string echoed back, which
// would only happen if the right handler was wired to the right path.

// scepProfileMockService is a per-profile-tagged mock SCEPService for
// router-level tests. The CACaps string carries the profile tag so the
// caller can verify which profile's handler served a given request.
type scepProfileMockService struct {
	tag string
}

func (s *scepProfileMockService) GetCACaps(_ context.Context) string {
	return "POSTPKIOperation\nSHA-256\nPROFILE=" + s.tag + "\n"
}

func (s *scepProfileMockService) GetCACert(_ context.Context) (string, error) {
	return "", nil
}

func (s *scepProfileMockService) PKCSReq(_ context.Context, _, _, _ string) (*domain.SCEPEnrollResult, error) {
	return nil, nil
}

// PKCSReqWithEnvelope / RenewalReqWithEnvelope / GetCertInitialWithEnvelope
// were added to the SCEPService interface in SCEP RFC 8894 + Intune master
// bundle Phase 2.4 + Phase 4. The router-level tests don't drive the
// RFC 8894 path; these stubs satisfy the interface so the per-profile
// dispatch tests still compile.
func (s *scepProfileMockService) PKCSReqWithEnvelope(_ context.Context, _, _ string, env *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	return &domain.SCEPResponseEnvelope{Status: domain.SCEPStatusSuccess, TransactionID: env.TransactionID}
}

func (s *scepProfileMockService) RenewalReqWithEnvelope(_ context.Context, _, _ string, env *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	return &domain.SCEPResponseEnvelope{Status: domain.SCEPStatusSuccess, TransactionID: env.TransactionID}
}

func (s *scepProfileMockService) GetCertInitialWithEnvelope(_ context.Context, env *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	return &domain.SCEPResponseEnvelope{Status: domain.SCEPStatusFailure, FailInfo: domain.SCEPFailBadCertID, TransactionID: env.TransactionID}
}

func TestRouter_RegisterSCEPHandlers_LegacyEmptyPathIDMapsToRoot(t *testing.T) {
	r := New()
	svc := &scepProfileMockService{tag: "legacy"}
	r.RegisterSCEPHandlers(map[string]handler.SCEPHandler{
		"": handler.NewSCEPHandler(svc),
	})

	// GetCACaps is GET-only per RFC 8894 §3.5.2. The router registers BOTH
	// GET and POST; the handler decides what each operation accepts. We
	// exercise GET here (POST PKIOperation is exercised by the existing
	// internal/api/handler tests and by the e2e suite).
	req := httptest.NewRequest(http.MethodGet, "/scep?operation=GetCACaps", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /scep — code %d, want 200 (body=%q)", w.Code, w.Body.String())
	}
	if got := w.Body.String(); !contains(got, "PROFILE=legacy") {
		t.Errorf("GET /scep body = %q, want contains PROFILE=legacy", got)
	}
	// Confirm POST /scep IS registered at the router level (the handler
	// will respond 405 for GetCACaps because it's GET-only, but the route
	// has to exist or we'd get a 404 from the mux instead).
	req = httptest.NewRequest(http.MethodPost, "/scep?operation=GetCACaps", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /scep?operation=GetCACaps — code %d, want 405 (route registered, handler rejects POST for GetCACaps)", w.Code)
	}
}

func TestRouter_RegisterSCEPHandlers_NonEmptyPathIDMapsToSubpath(t *testing.T) {
	r := New()
	svc := &scepProfileMockService{tag: "corp"}
	r.RegisterSCEPHandlers(map[string]handler.SCEPHandler{
		"corp": handler.NewSCEPHandler(svc),
	})

	// GET /scep/corp?operation=GetCACaps reaches the corp handler.
	req := httptest.NewRequest(http.MethodGet, "/scep/corp?operation=GetCACaps", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /scep/corp — code %d, want 200 (body=%q)", w.Code, w.Body.String())
	}
	if got := w.Body.String(); !contains(got, "PROFILE=corp") {
		t.Errorf("GET /scep/corp body = %q, want contains PROFILE=corp", got)
	}
	// POST /scep/corp must also be registered (the handler will reject
	// GetCACaps as 405; we just confirm the route exists).
	req = httptest.NewRequest(http.MethodPost, "/scep/corp?operation=GetCACaps", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /scep/corp?operation=GetCACaps — code %d, want 405 (route registered, handler rejects POST for GetCACaps)", w.Code)
	}
	// /scep root must NOT be registered when only non-empty PathIDs exist.
	req = httptest.NewRequest(http.MethodGet, "/scep?operation=GetCACaps", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("/scep without legacy profile — code %d, want 404 or 405 (no handler should be registered)", w.Code)
	}
}

func TestRouter_RegisterSCEPHandlers_MultipleProfilesNoCrossBleed(t *testing.T) {
	r := New()
	r.RegisterSCEPHandlers(map[string]handler.SCEPHandler{
		"":     handler.NewSCEPHandler(&scepProfileMockService{tag: "default"}),
		"corp": handler.NewSCEPHandler(&scepProfileMockService{tag: "corp"}),
		"iot":  handler.NewSCEPHandler(&scepProfileMockService{tag: "iot"}),
	})

	cases := []struct {
		path    string
		wantTag string
	}{
		{"/scep?operation=GetCACaps", "default"},
		{"/scep/corp?operation=GetCACaps", "corp"},
		{"/scep/iot?operation=GetCACaps", "iot"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("code %d, want 200", w.Code)
			}
			if got := w.Body.String(); !contains(got, "PROFILE="+tc.wantTag) {
				t.Errorf("body = %q, want contains PROFILE=%s", got, tc.wantTag)
			}
		})
	}
}

func TestRouter_RegisterSCEPHandlers_EmptyMapRegistersNoRoutes(t *testing.T) {
	r := New()
	r.RegisterSCEPHandlers(map[string]handler.SCEPHandler{})

	req := httptest.NewRequest(http.MethodGet, "/scep?operation=GetCACaps", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("/scep with no profiles registered — code %d, want 404 or 405", w.Code)
	}
}

// Tiny helper local to this file to avoid importing strings just for one
// substring check; keeps the test file's import surface minimal.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
