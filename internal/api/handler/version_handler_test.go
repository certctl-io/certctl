package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

// TestVersion_ReturnsBuildInfo is the regression for the U-3 ride-along
// cat-u-no_version_endpoint (P2). Three behaviors must hold for the
// endpoint to be useful in operator tooling:
//
//  1. GET /api/v1/version returns 200 with a JSON body that decodes into
//     the documented VersionInfo shape — the wire contract that rollout
//     systems and Prometheus blackbox probes parse.
//  2. The Go runtime version always populates (runtime.Version() can never
//     return empty), so consumers can always answer "which Go did this
//     binary compile with" even when ldflags / VCS info are missing.
//  3. The Version field is never empty — the fallback ladder
//     (ldflags > VCS commit > "dev") guarantees a non-empty string so
//     consumers don't have to special-case absent values.
//
// We don't pin the exact Version value because it depends on whether the
// test binary was built with -ldflags or under `go test`, both of which
// the handler must tolerate. The "no empty string" check is the
// behavioral contract.
func TestVersion_ReturnsBuildInfo(t *testing.T) {
	h := NewVersionHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		t.Errorf("Content-Type = %q, want application/json prefix (operator tooling parses JSON)", contentType)
	}

	var got VersionInfo
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("response body did not decode into VersionInfo: %v\nbody: %s", err, rec.Body.String())
	}

	// Version must never be empty — the fallback ladder in readBuildInfo
	// guarantees this. An empty Version would force every downstream
	// consumer (k8s rollouts, Prometheus blackbox, the support tooling)
	// to special-case the missing value, which defeats the point of
	// /api/v1/version existing.
	if got.Version == "" {
		t.Error("Version is empty — the fallback ladder (ldflags > VCS commit > 'dev') must guarantee a non-empty value")
	}

	// GoVersion must equal runtime.Version() — the handler reads it
	// directly and cannot be subverted by ldflags or BuildInfo. This is
	// the one field that should always be ground-truth.
	if got.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q (must come straight from runtime.Version())",
			got.GoVersion, runtime.Version())
	}
}

// TestVersion_RejectsNonGet pins the GET-only contract. /api/v1/version
// is read-only build identity; POST/PUT/DELETE etc. are nonsensical and
// should return 405 like the HealthHandler does. Operator tooling that
// fat-fingers the verb gets a clear error rather than a confusing 200
// from the wrong code path.
func TestVersion_RejectsNonGet(t *testing.T) {
	h := NewVersionHandler()

	for _, method := range []string{
		http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch,
	} {
		req := httptest.NewRequest(method, "/api/v1/version", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/v1/version → status %d, want 405", method, rec.Code)
		}
	}
}

// TestVersion_LdflagsOverride locks in the priority order: when the
// build-time Version variable is non-empty (e.g. "v2.0.50" injected by
// release.yml), readBuildInfo MUST surface that value verbatim and not
// silently substitute the VCS commit. The release-pipeline contract
// depends on this — a release tagged v2.0.50 should report "v2.0.50",
// not the underlying SHA.
//
// We achieve test isolation by save/restore on the package-level Version
// variable; t.Cleanup ensures parallel/subsequent tests see the original.
func TestVersion_LdflagsOverride(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })

	Version = "v2.0.50-test"
	got := readBuildInfo()
	if got.Version != "v2.0.50-test" {
		t.Errorf("Version = %q, want %q (ldflags-supplied Version must take priority over VCS fallback)",
			got.Version, "v2.0.50-test")
	}
}
