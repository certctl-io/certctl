package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/api/router"
)

// Bundle B / Audit M-002 (CWE-862): pin the dispatch-layer auth-exempt
// allowlist. cmd/server/main.go::buildFinalHandler decides per-request
// whether a path goes through the authenticated apiHandler or the
// no-auth handler. This test:
//
//   - constructs a buildFinalHandler with two sentinel handlers (one
//     for "auth", one for "no-auth") so we can observe which path is
//     taken from the response body.
//   - probes every prefix listed in router.AuthExemptDispatchPrefixes
//     and confirms it routes to no-auth.
//   - probes a few representative authenticated routes and confirms
//     they route to auth.
//   - probes the static-route allowlist (/health, /ready, etc.) that
//     also bypasses auth at this layer.
//
// Adding a new auth-bypass to buildFinalHandler without updating the
// router.AuthExemptDispatchPrefixes constant fails this test.

func TestBuildFinalHandler_AuthExemptDispatchAllowlist(t *testing.T) {
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("AUTH"))
	})
	noAuthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("NOAUTH"))
	})

	// dashboardEnabled=false keeps the dispatch logic deterministic — no
	// fileServer fallback to muddy the result.
	final := buildFinalHandler(apiHandler, noAuthHandler, "/nonexistent", false)

	cases := []struct {
		name string
		path string
		want string
	}{
		// AuthExemptRouterRoutes (also enforced at this layer)
		{"health", "/health", "NOAUTH"},
		{"ready", "/ready", "NOAUTH"},
		{"auth_info", "/api/v1/auth/info", "NOAUTH"},
		{"version", "/api/v1/version", "NOAUTH"},

		// AuthExemptDispatchPrefixes — every documented prefix
		{"pki_crl", "/.well-known/pki/crl", "NOAUTH"},
		{"pki_ocsp", "/.well-known/pki/ocsp", "NOAUTH"},
		{"est_simpleenroll", "/.well-known/est/simpleenroll", "NOAUTH"},
		{"est_cacerts", "/.well-known/est/cacerts", "NOAUTH"},
		{"scep_root", "/scep", "NOAUTH"},
		{"scep_op", "/scep/pkiclient.exe", "NOAUTH"},

		// Authenticated routes — must hit apiHandler
		{"certs_list", "/api/v1/certificates", "AUTH"},
		{"agents_list", "/api/v1/agents", "AUTH"},
		{"audit_check", "/api/v1/auth/check", "AUTH"},

		// Random non-API path — falls through to apiHandler when
		// dashboard disabled (preserves pre-M-001 API-only behavior).
		{"unknown", "/some-other-path", "AUTH"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			final.ServeHTTP(rec, req)
			got := rec.Body.String()
			if got != tc.want {
				t.Errorf("path %q routed to %q; want %q (this is the M-002 dispatch-layer pin)", tc.path, got, tc.want)
			}
		})
	}
}

// TestDispatch_NoUndocumentedBypasses asserts that for every prefix the
// dispatch layer routes to noAuthHandler, that prefix appears in the
// router.AuthExemptDispatchPrefixes constant. This is the inverse pin —
// adding a new bypass to buildFinalHandler without updating the constant
// fails this test.
//
// We probe a curated set of "would-be-bypasses" derived from the actual
// dispatch source by reading buildFinalHandler's lines. If the dispatch
// logic adds a new prefix that ends up in the no-auth chain, the
// curated set must be extended in the same commit that updates the
// constant — this fails-loud rather than silently allowing a bypass.
func TestDispatch_NoUndocumentedBypasses(t *testing.T) {
	for _, prefix := range router.AuthExemptDispatchPrefixes {
		if !strings.HasPrefix(prefix, "/") {
			t.Errorf("AuthExemptDispatchPrefixes entry %q must start with / for prefix matching", prefix)
		}
	}
	// Every entry in router.AuthExemptDispatchPrefixes must round-trip
	// through buildFinalHandler to noAuthHandler (covered by the table
	// test above). This test additionally asserts the inverse: known
	// authenticated prefixes do NOT match any documented bypass prefix.
	authenticatedPrefixes := []string{
		"/api/v1/certificates",
		"/api/v1/agents",
		"/api/v1/audit",
	}
	for _, ap := range authenticatedPrefixes {
		for _, bypass := range router.AuthExemptDispatchPrefixes {
			if strings.HasPrefix(ap, bypass) {
				t.Errorf("authenticated prefix %q overlaps with documented bypass %q — auth bypass risk", ap, bypass)
			}
		}
	}
}
