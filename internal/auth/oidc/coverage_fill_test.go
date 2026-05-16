package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/validation"
)

// Coverage fill — v2.1.0 release gate Phase 3.
//
// Targets two service-level functions added by post-merge fixes that
// shipped without unit tests:
//
//   - Service.JWKSStatus — added in audit 2026-05-10 MED-7 closure
//     (per-provider JWKS counters + cache state).
//   - Service.TestDiscovery — added in audit 2026-05-10 MED-5 closure
//     (dry-run /api/v1/auth/oidc/test endpoint).

// TestJWKSStatus_ReturnsLoadError_WhenProviderUnknown asserts that
// JWKSStatus forwards the getOrLoad error verbatim when the requested
// providerID is not in the repo. This is the entry-point fail-closed
// branch.
func TestJWKSStatus_ReturnsLoadError_WhenProviderUnknown(t *testing.T) {
	svc := newServiceForUnitTest(t)
	snap, err := svc.JWKSStatus(context.Background(), "rp-does-not-exist")
	if err == nil {
		t.Fatalf("expected error for unknown provider, got nil")
	}
	if snap != nil {
		t.Errorf("expected nil snapshot on error, got %+v", snap)
	}
}

// TestJWKSStatus_ReturnsSnapshot_AfterAuthRequestPopulatesEntry pre-
// warms the provider cache via HandleAuthRequest (which calls
// getOrLoad → populates s.cache) and then asserts JWKSStatus returns
// a non-nil snapshot reflecting the entry's stats.
func TestJWKSStatus_ReturnsSnapshot_AfterAuthRequestPopulatesEntry(t *testing.T) {
	idp := newMockIdP(t)
	svc, _ := newServiceWithProviderAndPL(t, idp.URL(), "rp-jwks-status")
	// Pre-warm the cache.
	if _, _, _, err := svc.HandleAuthRequest(context.Background(), "rp-jwks-status", "10.0.0.1", "test/1.0"); err != nil {
		t.Fatalf("HandleAuthRequest: %v", err)
	}
	snap, err := svc.JWKSStatus(context.Background(), "rp-jwks-status")
	if err != nil {
		t.Fatalf("JWKSStatus: %v", err)
	}
	if snap == nil {
		t.Fatalf("expected non-nil snapshot")
	}
	// CurrentKIDs is intentionally empty (go-oidc doesn't expose its
	// JWKS cache). Test the shape rather than the kids.
	if snap.CurrentKIDs == nil {
		t.Errorf("CurrentKIDs must be non-nil (empty slice OK)")
	}
}

// TestTestDiscovery_RejectsSSRFIssuer_AtEarlyFailRail pins the
// SEC-001 closure (Sprint 1, 2026-05-16): TestDiscovery refuses
// reserved-address issuers up-front via validateIssuerSSRF, surfacing
// a clean "issuer_url failed SSRF policy" error in the result's
// Errors slice without ever hitting the dial path. The package-wide
// setup_test.go init() swaps validateIssuerSSRF to a no-op so the
// other tests can use httptest loopback servers; this test temporarily
// restores the production gate (validation.ValidateSafeURL) and
// asserts the rejection fires.
func TestTestDiscovery_RejectsSSRFIssuer_AtEarlyFailRail(t *testing.T) {
	prev := validateIssuerSSRF
	validateIssuerSSRF = validation.ValidateSafeURL
	defer func() { validateIssuerSSRF = prev }()

	svc := newServiceForUnitTest(t)
	cases := []struct {
		name   string
		issuer string
	}{
		{"loopback_v4", "https://127.0.0.1/realms/certctl"},
		{"loopback_v6", "https://[::1]/realms/certctl"},
		{"cloud_metadata", "https://169.254.169.254/latest/meta-data/"},
		{"link_local_v4", "https://169.254.10.5/realms/certctl"},
		{"link_local_v6", "https://[fe80::1]/realms/certctl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := svc.TestDiscovery(context.Background(), tc.issuer)
			if err != nil {
				t.Fatalf("TestDiscovery (non-fatal): %v", err)
			}
			if res == nil {
				t.Fatalf("expected non-nil result")
			}
			if res.DiscoverySucceeded {
				t.Errorf("expected DiscoverySucceeded=false for SSRF issuer; got true")
			}
			if len(res.Errors) == 0 {
				t.Fatalf("expected non-empty Errors slice")
			}
			joined := strings.Join(res.Errors, "|")
			if !strings.Contains(joined, "SSRF policy") {
				t.Errorf("expected 'SSRF policy' in errors; got %v", res.Errors)
			}
		})
	}
}

// TestTestDiscovery_DiscoveryFailure_ReturnsErrorsSlice points
// TestDiscovery at a URL that doesn't serve a discovery doc; the
// function MUST return res with DiscoverySucceeded=false and a
// non-empty Errors slice, and a nil err (per the documented "non-
// fatal at this layer; per-leg failure carried in res.Errors"
// contract).
func TestTestDiscovery_DiscoveryFailure_ReturnsErrorsSlice(t *testing.T) {
	svc := newServiceForUnitTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res, err := svc.TestDiscovery(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("TestDiscovery (non-fatal): %v", err)
	}
	if res == nil {
		t.Fatalf("expected non-nil result")
	}
	if res.DiscoverySucceeded {
		t.Errorf("expected DiscoverySucceeded=false when discovery doc is missing")
	}
	if len(res.Errors) == 0 {
		t.Errorf("expected non-empty Errors slice")
	}
	if !strings.Contains(strings.Join(res.Errors, "|"), "discovery fetch failed") {
		t.Errorf("expected 'discovery fetch failed' in errors; got %v", res.Errors)
	}
}

// TestTestDiscovery_HappyPath_AgainstMockIdP exercises the
// success path: discovery doc fetch, claims parse, alg-downgrade
// check (RS256 → not denied), JWKS reachability.
func TestTestDiscovery_HappyPath_AgainstMockIdP(t *testing.T) {
	idp := newMockIdP(t)
	svc := newServiceForUnitTest(t)

	res, err := svc.TestDiscovery(context.Background(), idp.URL())
	if err != nil {
		t.Fatalf("TestDiscovery: %v", err)
	}
	if !res.DiscoverySucceeded {
		t.Errorf("expected DiscoverySucceeded=true")
	}
	if res.IssuerEcho != idp.URL() {
		t.Errorf("expected IssuerEcho=%q, got %q", idp.URL(), res.IssuerEcho)
	}
	if res.AuthorizationURL == "" || res.TokenURL == "" {
		t.Errorf("expected non-empty AuthorizationURL+TokenURL; got %q / %q", res.AuthorizationURL, res.TokenURL)
	}
	if !res.JWKSReachable {
		t.Errorf("expected JWKSReachable=true; got Errors=%v", res.Errors)
	}
	if len(res.SupportedAlgValues) == 0 {
		t.Errorf("expected non-empty SupportedAlgValues")
	}
	// Mock IdP advertises RS256; no downgrade-defense trip.
	for _, e := range res.Errors {
		if strings.Contains(e, "alg-downgrade defense tripped") {
			t.Errorf("unexpected alg-downgrade trip: %s", e)
		}
	}
}

// TestTestDiscovery_AlgDowngrade_HS256AlongsideRS256_BindsWithNote runs
// against a stub IdP that advertises both HS256 + RS256 (Keycloak-shape).
// Under v2.1.0-relaxed semantics this must SUCCEED (DiscoverySucceeded=true,
// JWKSReachable=true) and surface only an informational note about the
// weak-alg advertisement — NOT a hard "alg-downgrade defense tripped" error.
// The per-token alg pin at sig-verify time remains the load-bearing defense.
func TestTestDiscovery_AlgDowngrade_HS256AlongsideRS256_BindsWithNote(t *testing.T) {
	svc := newServiceForUnitTest(t)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"HS256", "RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})

	res, err := svc.TestDiscovery(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("TestDiscovery: %v", err)
	}
	if !res.DiscoverySucceeded {
		t.Errorf("expected DiscoverySucceeded=true; got Errors=%v", res.Errors)
	}
	// The Keycloak-shape advertisement must NOT trip the hard fail.
	for _, e := range res.Errors {
		if strings.Contains(e, "alg-downgrade defense tripped") {
			t.Errorf("v2.1.0-relaxed semantics: HS256+RS256 must NOT trip hard fail; got %q", e)
		}
	}
	// Informational note must be present.
	noteFound := false
	for _, e := range res.Errors {
		if strings.Contains(e, "note:") && strings.Contains(e, "HS256") {
			noteFound = true
		}
	}
	if !noteFound {
		t.Errorf("expected informational note about HS256 in errors; got %v", res.Errors)
	}
}

// TestTestDiscovery_AlgDowngrade_HSOnly_StillTrips_HardFail asserts the
// pathological intersection-empty case still hard-fails.
func TestTestDiscovery_AlgDowngrade_HSOnly_StillTrips_HardFail(t *testing.T) {
	svc := newServiceForUnitTest(t)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"HS256", "HS384"}, // no RS
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})

	res, err := svc.TestDiscovery(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("TestDiscovery: %v", err)
	}
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "alg-downgrade defense tripped") && strings.Contains(e, "only weak algorithms") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected hard-fail for HS-only IdP; got %v", res.Errors)
	}
}

// TestTestDiscovery_MissingJWKSURI surfaces the "discovery doc omits
// jwks_uri" branch.
func TestTestDiscovery_MissingJWKSURI(t *testing.T) {
	svc := newServiceForUnitTest(t)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			// jwks_uri intentionally omitted
		})
	})

	res, err := svc.TestDiscovery(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("TestDiscovery: %v", err)
	}
	if res.JWKSReachable {
		t.Errorf("expected JWKSReachable=false when jwks_uri is missing")
	}
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "omits jwks_uri") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'omits jwks_uri' in errors; got %v", res.Errors)
	}
}

// TestTestDiscovery_JWKSFetchFails covers the jwksReachable error
// branch (non-2xx JWKS response).
func TestTestDiscovery_JWKSFetchFails(t *testing.T) {
	svc := newServiceForUnitTest(t)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal", http.StatusInternalServerError)
	})

	res, err := svc.TestDiscovery(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("TestDiscovery: %v", err)
	}
	if res.JWKSReachable {
		t.Errorf("expected JWKSReachable=false on 500")
	}
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "JWKS endpoint returned non-200") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'JWKS endpoint returned non-200' in errors; got %v", res.Errors)
	}
}
