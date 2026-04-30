package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Bundle B / Audit M-013 (CWE-942) regression pins.
//
// The audit-finding text reads: "CORS configuration default allows all
// origins if env-var unset". Phase 0 recon proves that claim is WRONG —
// internal/api/middleware/middleware.go::NewCORS already denies when
// len(cfg.AllowedOrigins) == 0 (no Access-Control-Allow-Origin header is
// emitted, so same-origin policy applies). Bundle B's M-013 closure is
// "verified-already-clean": these tests pin the deny-by-default contract
// in BOTH shapes (nil slice and empty slice) so a future refactor that
// inverts the default fails CI.

// TestNewCORS_NilOriginsDeniesAll pins the deny-by-default contract for
// the nil-slice shape (which is what propagates from a missing
// CERTCTL_CORS_ORIGINS env var via internal/config/config.go::getEnvList).
func TestNewCORS_NilOriginsDeniesAll(t *testing.T) {
	mw := NewCORS(CORSConfig{AllowedOrigins: nil})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Origin", "https://attacker.example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("nil AllowedOrigins must NOT emit Access-Control-Allow-Origin, got %q", got)
	}
	if got := rr.Header().Get("Vary"); got != "" {
		t.Errorf("nil AllowedOrigins must NOT emit Vary, got %q", got)
	}
}

// TestNewCORS_M013_ContractDocumentedInOrder pins the documented dispatch
// order so a refactor cannot silently invert the cases:
//
//  1. len(AllowedOrigins) == 0  → deny (no CORS headers)
//  2. AllowedOrigins == ["*"]   → allow all (Access-Control-Allow-Origin: *)
//  3. else                      → exact-match allowlist with Vary: Origin
//
// If a refactor accidentally falls through to the allow-all branch when
// AllowedOrigins is empty, this test fails on case 1.
func TestNewCORS_M013_ContractDocumentedInOrder(t *testing.T) {
	cases := []struct {
		name           string
		origins        []string
		incomingOrigin string
		wantHeader     string // "" means no header expected
	}{
		{"deny_empty_slice", []string{}, "https://app.example.com", ""},
		{"deny_nil", nil, "https://app.example.com", ""},
		{"allow_all_with_star", []string{"*"}, "https://app.example.com", "*"},
		{"exact_allow_match", []string{"https://app.example.com"}, "https://app.example.com", "https://app.example.com"},
		{"exact_deny_mismatch", []string{"https://app.example.com"}, "https://attacker.example.com", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw := NewCORS(CORSConfig{AllowedOrigins: tc.origins})
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Origin", tc.incomingOrigin)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if got := rr.Header().Get("Access-Control-Allow-Origin"); got != tc.wantHeader {
				t.Errorf("got Access-Control-Allow-Origin=%q, want %q (incoming origin=%q)", got, tc.wantHeader, tc.incomingOrigin)
			}
		})
	}
}

// TestNewCORS_EmptyOriginList denies CORS by default (secure default).
func TestNewCORS_EmptyOriginList(t *testing.T) {
	mw := NewCORS(CORSConfig{AllowedOrigins: []string{}})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Response should be OK, but no CORS headers should be set
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Verify no CORS headers are present
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no Access-Control-Allow-Origin header, got %q", rr.Header().Get("Access-Control-Allow-Origin"))
	}
	if rr.Header().Get("Vary") != "" {
		t.Errorf("expected no Vary header, got %q", rr.Header().Get("Vary"))
	}
}

// TestNewCORS_EmptyOriginList_Preflight denies preflight when empty allowlist.
func TestNewCORS_EmptyOriginList_Preflight(t *testing.T) {
	mw := NewCORS(CORSConfig{AllowedOrigins: []string{}})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/certificates", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Preflight should return 204, but no CORS headers
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}

	// No CORS headers should be set
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no Access-Control-Allow-Origin header, got %q", rr.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestNewCORS_WildcardAllowsAll allows all origins with wildcard.
func TestNewCORS_WildcardAllowsAll(t *testing.T) {
	mw := NewCORS(CORSConfig{AllowedOrigins: []string{"*"}})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Origin", "https://any-origin.example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Wildcard should set Access-Control-Allow-Origin: *
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected Access-Control-Allow-Origin: *, got %q", rr.Header().Get("Access-Control-Allow-Origin"))
	}

	// Verify other CORS headers are present
	if rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Errorf("expected Access-Control-Allow-Methods header")
	}
}

// TestNewCORS_ExactMatchAllows allows only exact matches from allowlist.
func TestNewCORS_ExactMatchAllows(t *testing.T) {
	mw := NewCORS(CORSConfig{AllowedOrigins: []string{"https://app.example.com", "https://admin.example.com"}})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test 1: Origin in allowlist
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req1.Header.Set("Origin", "https://app.example.com")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	if rr1.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("expected https://app.example.com, got %q", rr1.Header().Get("Access-Control-Allow-Origin"))
	}
	if rr1.Header().Get("Vary") != "Origin" {
		t.Errorf("expected Vary: Origin, got %q", rr1.Header().Get("Vary"))
	}

	// Test 2: Different origin in allowlist
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req2.Header.Set("Origin", "https://admin.example.com")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Header().Get("Access-Control-Allow-Origin") != "https://admin.example.com" {
		t.Errorf("expected https://admin.example.com, got %q", rr2.Header().Get("Access-Control-Allow-Origin"))
	}

	// Test 3: Origin NOT in allowlist
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req3.Header.Set("Origin", "https://evil.example.com")
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)

	if rr3.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no Access-Control-Allow-Origin for non-allowlisted origin, got %q", rr3.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestNewCORS_NoOriginHeader denies CORS without Origin header.
func TestNewCORS_NoOriginHeader(t *testing.T) {
	mw := NewCORS(CORSConfig{AllowedOrigins: []string{"https://app.example.com"}})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request without Origin header
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	// Don't set Origin header
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// No CORS headers should be set (Origin header was missing)
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no Access-Control-Allow-Origin without Origin header, got %q", rr.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestNewCORS_PreflightRequestMatches tests OPTIONS preflight with matching origin.
func TestNewCORS_PreflightRequestMatches(t *testing.T) {
	mw := NewCORS(CORSConfig{AllowedOrigins: []string{"https://app.example.com"}})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/certificates", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}

	if rr.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("expected https://app.example.com, got %q", rr.Header().Get("Access-Control-Allow-Origin"))
	}

	// Verify preflight response headers
	if rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Errorf("expected Access-Control-Allow-Methods header")
	}
	if rr.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Errorf("expected Access-Control-Allow-Headers header")
	}
	if rr.Header().Get("Access-Control-Max-Age") == "" {
		t.Errorf("expected Access-Control-Max-Age header")
	}
}

// TestNewCORS_PreflightRequestMismatch tests OPTIONS preflight with non-matching origin.
func TestNewCORS_PreflightRequestMismatch(t *testing.T) {
	mw := NewCORS(CORSConfig{AllowedOrigins: []string{"https://app.example.com"}})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/certificates", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}

	// No CORS headers should be set (origin not in allowlist)
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no Access-Control-Allow-Origin for mismatched origin, got %q", rr.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestNewCORS_MultipleOrigins tests with multiple configured origins.
func TestNewCORS_MultipleOrigins(t *testing.T) {
	mw := NewCORS(CORSConfig{AllowedOrigins: []string{
		"https://app.example.com",
		"https://admin.example.com",
		"http://localhost:3000",
	}})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		origin      string
		shouldAllow bool
		description string
	}{
		{"https://app.example.com", true, "first origin in list"},
		{"https://admin.example.com", true, "second origin in list"},
		{"http://localhost:3000", true, "third origin in list"},
		{"https://evil.example.com", false, "origin not in list"},
		{"http://localhost:8080", false, "different port than configured"},
		{"", false, "no origin header"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
		if tt.origin != "" {
			req.Header.Set("Origin", tt.origin)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		headerValue := rr.Header().Get("Access-Control-Allow-Origin")
		if tt.shouldAllow {
			if headerValue != tt.origin {
				t.Errorf("test %q: expected %q, got %q", tt.description, tt.origin, headerValue)
			}
		} else {
			if headerValue != "" {
				t.Errorf("test %q: expected no header, got %q", tt.description, headerValue)
			}
		}
	}
}

// TestNewCORS_NoOriginHeaderWithWildcard tests wildcard doesn't set origin without Origin header.
func TestNewCORS_NoOriginHeaderWithWildcard(t *testing.T) {
	mw := NewCORS(CORSConfig{AllowedOrigins: []string{"*"}})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	// Don't set Origin header
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Wildcard should still set * even without Origin header
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected *, got %q", rr.Header().Get("Access-Control-Allow-Origin"))
	}
}
