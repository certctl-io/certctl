// Test-only setup for the internal/auth/oidc package.
//
// Bundle 5 closure (audit R6) wrapped the package's jwks reachability
// probe in validation.SafeHTTPDialContext so production OIDC config
// dry-runs can't be pivoted into reserved-address ranges via DNS
// rebinding. The test suite uses httptest.NewServer which binds to
// 127.0.0.1 — that's exactly the reserved-address case the production
// guard refuses to dial, so the package-level jwksProbeClient is
// replaced here with an SSRF-guard-bypassed http.Client for the
// duration of every test in this package.
//
// Mirrors the internal/connector/notifier/webhook + slack + teams
// test-seam pattern (newForTest constructor). The production code
// never reassigns jwksProbeClient — only this _test.go file does, so
// the test seam can't leak into a real deployment.

package oidc

import (
	"net/http"
	"time"
)

func init() {
	// Replace the SSRF-safe transport with one that has no
	// DialContext override. http.DefaultTransport handles 127.0.0.1
	// without complaint, which is what httptest.NewServer needs.
	jwksProbeClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: http.DefaultTransport,
	}
}
