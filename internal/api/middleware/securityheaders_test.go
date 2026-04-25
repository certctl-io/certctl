package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSecurityHeaders_DefaultsAllPresent asserts every default header
// arrives on a 200 response. H-1 closure (cat-s11-missing_security_headers).
func TestSecurityHeaders_DefaultsAllPresent(t *testing.T) {
	mw := SecurityHeaders(SecurityHeadersDefaults())
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)

	for _, h := range []string{
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Content-Security-Policy",
	} {
		if got := rec.Header().Get(h); got == "" {
			t.Errorf("expected header %q to be set, got empty", h)
		}
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options: got %q, want %q", got, "nosniff")
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options: got %q, want %q", got, "DENY")
	}
}

// TestSecurityHeaders_EmptyValueDisablesHeader asserts an operator can
// disable a single header by setting its config field to empty without
// affecting the others.
func TestSecurityHeaders_EmptyValueDisablesHeader(t *testing.T) {
	cfg := SecurityHeadersDefaults()
	cfg.HSTS = "" // simulate operator override
	mw := SecurityHeaders(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS should be omitted when config value is empty; got %q", got)
	}
	// Other headers still present
	if got := rec.Header().Get("X-Frame-Options"); got == "" {
		t.Errorf("X-Frame-Options should still be present (empty HSTS only disables HSTS)")
	}
}

// TestSecurityHeaders_OverrideValueApplied asserts a non-default value
// makes it through.
func TestSecurityHeaders_OverrideValueApplied(t *testing.T) {
	cfg := SecurityHeadersDefaults()
	cfg.FrameOptions = "SAMEORIGIN"
	mw := SecurityHeaders(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options: got %q, want %q", got, "SAMEORIGIN")
	}
}

// TestSecurityHeaders_AppliedOnErrorResponses asserts headers are
// present on 4xx/5xx as well as 2xx — this is critical for the
// security posture (an attacker probing for misconfiguration sees
// the same headers on a 401 as on a 200).
func TestSecurityHeaders_AppliedOnErrorResponses(t *testing.T) {
	mw := SecurityHeaders(SecurityHeadersDefaults())
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("Strict-Transport-Security"); got == "" {
		t.Errorf("HSTS missing on 401 response (must be on every response)")
	}
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Errorf("CSP missing on 401 response")
	}
}
