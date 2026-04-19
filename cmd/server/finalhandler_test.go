package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildFinalHandler_Dispatch is the M-001 regression harness for the outer
// HTTP dispatch layer. It pins which path prefixes ride the no-auth middleware
// chain (EST, SCEP, /.well-known/pki, health/ready, /api/v1/auth/info) versus
// the authenticated chain (/api/v1/*).
//
// The concern under test is ONLY the dispatch in buildFinalHandler — the
// handlers themselves are mocked as marker handlers that stamp "AUTH" or
// "NOAUTH" into the response body. Service-layer concerns (SCEP password
// validation, EST CSR validation, API auth enforcement) are covered by their
// respective test suites.
//
// Case (i) is the central guard: EST with NO client cert / NO Bearer token
// MUST reach the no-auth handler (pre-M-001 it was 401'd by the Auth
// middleware, blocking enrollment for every real-world EST client).
func TestBuildFinalHandler_Dispatch(t *testing.T) {
	// Marker handlers — each stamps a unique body so tests can verify which
	// chain the request traversed.
	authHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Chain", "auth")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("AUTH"))
	})
	noAuthHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Chain", "noauth")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("NOAUTH"))
	})

	// Dashboard directory with index.html + assets/ for SPA fallback and
	// static-asset tests. Cleaned up by t.TempDir.
	webDir := t.TempDir()
	indexHTML := []byte("<!doctype html><html><body>certctl dashboard</body></html>")
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), indexHTML, 0o644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}
	assetsDir := filepath.Join(webDir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		t.Fatalf("mkdir assets: %v", err)
	}
	assetJS := []byte("console.log('certctl');")
	if err := os.WriteFile(filepath.Join(assetsDir, "app.js"), assetJS, 0o644); err != nil {
		t.Fatalf("write app.js: %v", err)
	}

	handler := buildFinalHandler(authHandler, noAuthHandler, webDir, true /* dashboardEnabled */)

	tests := []struct {
		name           string
		method         string
		path           string
		wantBody       string // "AUTH" | "NOAUTH" | "" (== substring match against response body)
		wantBodyPrefix string
		wantStatus     int
		description    string
	}{
		// ---- Case (i): M-001 central regression guard ----
		{
			name:        "est_cacerts_no_auth_reaches_noauth_handler",
			method:      http.MethodGet,
			path:        "/.well-known/est/cacerts",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "EST clients cannot present Bearer tokens — must NOT be 401'd before reaching the handler (RFC 7030 §4.1.1)",
		},
		{
			name:        "est_simpleenroll_no_auth_reaches_noauth_handler",
			method:      http.MethodPost,
			path:        "/.well-known/est/simpleenroll",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "RFC 7030 §4.2 simpleenroll served from no-auth chain (option D)",
		},
		{
			name:        "est_simplereenroll_no_auth_reaches_noauth_handler",
			method:      http.MethodPost,
			path:        "/.well-known/est/simplereenroll",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "RFC 7030 §4.2.2 simplereenroll also on no-auth chain",
		},
		{
			name:        "est_csrattrs_no_auth_reaches_noauth_handler",
			method:      http.MethodGet,
			path:        "/.well-known/est/csrattrs",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "RFC 7030 §4.5 csrattrs also on no-auth chain",
		},

		// ---- Cases (ii) + (iii): SCEP dispatch ----
		// The actual challengePassword validation lives in the service layer
		// (internal/service/scep.go). This test pins that ALL /scep* requests
		// reach the no-auth chain — the service layer is then responsible for
		// rejecting or accepting based on password contents.
		{
			name:        "scep_exact_path_reaches_noauth_handler",
			method:      http.MethodGet,
			path:        "/scep",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "SCEP clients authenticate via CSR challengePassword, not Bearer (RFC 8894 §3.2)",
		},
		{
			name:        "scep_subpath_reaches_noauth_handler",
			method:      http.MethodPost,
			path:        "/scep/",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "Trailing-slash variant must also ride no-auth chain",
		},
		{
			name:        "scep_query_string_reaches_noauth_handler",
			method:      http.MethodGet,
			path:        "/scep?operation=GetCACaps",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "Query string does not affect dispatch — operation dispatch is handler-internal",
		},
		// Defensive: /scepxyz MUST NOT match the SCEP prefix (guards against
		// over-broad matching that would leak non-SCEP paths into no-auth).
		{
			name:        "scepxyz_does_not_match_scep_prefix",
			method:      http.MethodGet,
			path:        "/scepxyz",
			wantStatus:  http.StatusOK,
			wantBody:    "certctl dashboard",
			description: "SPA fallback — /scepxyz must not be confused with /scep or /scep/",
		},

		// ---- Case (iv): RFC 5280 CRL + RFC 6960 OCSP ----
		{
			name:        "pki_crl_no_auth_reaches_noauth_handler",
			method:      http.MethodGet,
			path:        "/.well-known/pki/crl/abc123",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "RFC 5280 CRL distribution point must be served without auth",
		},
		{
			name:        "pki_ocsp_no_auth_reaches_noauth_handler",
			method:      http.MethodGet,
			path:        "/.well-known/pki/ocsp/abc123/serial",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "RFC 6960 OCSP responder must be served without auth",
		},

		// ---- Case (v): Authenticated API routes ----
		{
			name:        "api_v1_certificates_goes_through_auth",
			method:      http.MethodGet,
			path:        "/api/v1/certificates",
			wantBody:    "AUTH",
			wantStatus:  http.StatusOK,
			description: "Primary API surface must still require Bearer token",
		},
		{
			name:        "api_v1_auth_check_goes_through_auth",
			method:      http.MethodGet,
			path:        "/api/v1/auth/check",
			wantBody:    "AUTH",
			wantStatus:  http.StatusOK,
			description: "auth/check validates the caller's Bearer — auth chain required",
		},
		{
			name:        "api_v1_jobs_goes_through_auth",
			method:      http.MethodGet,
			path:        "/api/v1/jobs",
			wantBody:    "AUTH",
			wantStatus:  http.StatusOK,
			description: "Jobs API is part of the privileged surface",
		},

		// ---- Health probes bypass auth ----
		{
			name:        "health_bypasses_auth",
			method:      http.MethodGet,
			path:        "/health",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "Docker/K8s health probes cannot carry Bearer tokens",
		},
		{
			name:        "ready_bypasses_auth",
			method:      http.MethodGet,
			path:        "/ready",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "Readiness probe also unauthenticated",
		},
		{
			name:        "auth_info_bypasses_auth",
			method:      http.MethodGet,
			path:        "/api/v1/auth/info",
			wantBody:    "NOAUTH",
			wantStatus:  http.StatusOK,
			description: "React app calls auth/info BEFORE login to discover auth mode",
		},

		// ---- Static assets served by file server ----
		{
			name:        "static_asset_served_by_file_server",
			method:      http.MethodGet,
			path:        "/assets/app.js",
			wantStatus:  http.StatusOK,
			wantBody:    "console.log('certctl');",
			description: "Built Vite assets served directly without auth",
		},

		// ---- SPA fallback ----
		{
			name:        "spa_fallback_serves_index_html",
			method:      http.MethodGet,
			path:        "/",
			wantStatus:  http.StatusOK,
			wantBody:    "certctl dashboard",
			description: "Root path serves SPA entry point",
		},
		{
			name:        "spa_fallback_for_unknown_route",
			method:      http.MethodGet,
			path:        "/certificates",
			wantStatus:  http.StatusOK,
			wantBody:    "certctl dashboard",
			description: "React Router routes fall through to index.html",
		},
		{
			name:        "spa_fallback_deep_route",
			method:      http.MethodGet,
			path:        "/certificates/mc-api-prod/detail",
			wantStatus:  http.StatusOK,
			wantBody:    "certctl dashboard",
			description: "Deep React Router routes also fall through to SPA",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (%s)", w.Code, tc.wantStatus, tc.description)
			}
			body := w.Body.String()
			if tc.wantBody != "" && !strings.Contains(body, tc.wantBody) {
				t.Errorf("body %q does not contain %q (%s)", body, tc.wantBody, tc.description)
			}
			if tc.wantBodyPrefix != "" && !strings.HasPrefix(body, tc.wantBodyPrefix) {
				t.Errorf("body %q does not start with %q (%s)", body, tc.wantBodyPrefix, tc.description)
			}
		})
	}
}

// TestBuildFinalHandler_NoDashboard pins the API-only (dashboard-absent)
// dispatch behavior. When web/dist/index.html is missing, everything that's
// not a no-auth bypass route falls through to the authenticated apiHandler
// (pre-M-001 behavior for headless deployments). EST/SCEP/PKI still ride the
// no-auth chain.
func TestBuildFinalHandler_NoDashboard(t *testing.T) {
	authHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("AUTH"))
	})
	noAuthHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("NOAUTH"))
	})

	handler := buildFinalHandler(authHandler, noAuthHandler, "/nonexistent", false /* dashboardEnabled */)

	tests := []struct {
		name     string
		path     string
		wantBody string
	}{
		{"est_still_no_auth", "/.well-known/est/cacerts", "NOAUTH"},
		{"scep_still_no_auth", "/scep", "NOAUTH"},
		{"pki_still_no_auth", "/.well-known/pki/crl/x", "NOAUTH"},
		{"health_still_no_auth", "/health", "NOAUTH"},
		{"api_still_auth", "/api/v1/certificates", "AUTH"},
		// The difference: non-API, non-special paths go through auth chain when
		// there's no dashboard to serve (preserves legacy headless behavior).
		{"unknown_path_falls_through_to_auth", "/", "AUTH"},
		{"unknown_deep_path_falls_through_to_auth", "/random/path", "AUTH"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", w.Code)
			}
			if got := w.Body.String(); !strings.Contains(got, tc.wantBody) {
				t.Errorf("body = %q, want to contain %q", got, tc.wantBody)
			}
		})
	}
}
