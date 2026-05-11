//go:build integration

package oidc_test

import (
	"context"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/auth/oidc/testfixtures"
)

// =============================================================================
// Audit 2026-05-10 Nit-5 closure — Keycloak-backed integration test for
// the MED-6 JWKS auto-refresh path.
//
// Distinct from integration_keycloak_test.go's existing
// TestKeycloakIntegration_JWKSRotation_RefreshKeysPicksUpNewKey: that
// test calls `svc.RefreshKeys` explicitly between the rotate event and
// the second login (operator-driven path). This test deliberately does
// NOT call RefreshKeys — it exercises the IMPLICIT auto-refresh that
// MED-6 added inside HandleCallback's verify-error branch.
//
// The unit-test sibling lives in service_test.go::
// TestService_HandleCallback_MED6_AutoRefreshOnKidMiss; it uses an
// in-process mockIdP. Here we run against a real Keycloak realm so
// the test pins behavior against the actual go-oidc error strings
// emitted by a production-grade JWKS endpoint with multiple active
// keys + a key-priority change.
//
// Build-tagged `integration` so it doesn't run under `make test` /
// `go test -short`. Runs via `make keycloak-integration-test` which
// boots the Keycloak testcontainer.
// =============================================================================

// TestKeycloakIntegration_MED6_AutoRefreshOnKidMiss pins the MED-6
// recovery contract: after the realm rotates its signing key, the
// next /auth/oidc/callback request that arrives WITHOUT an explicit
// operator-initiated RefreshKeys must still succeed — HandleCallback
// detects the kid-not-in-cache shape and runs the one-shot refresh +
// retry internally.
//
// Plan:
//  1. Successful baseline login under the realm's original signing key
//     (primes the certctl service's JWKS cache).
//  2. Rotate the realm's RSA key via the Keycloak admin API.
//  3. Run a fresh /auth/oidc/login → /auth/oidc/callback flow.
//     - Keycloak signs the new ID token under the new (higher-priority)
//     key.
//     - certctl's verifier holds the pre-rotate JWKS in cache.
//     - The verify trips kid-not-in-cache → MED-6 auto-refresh fires →
//     second verify succeeds.
//  4. Assert the callback succeeded without the test having called
//     RefreshKeys (which would mask the MED-6 path).
//
// Note: this is the Keycloak-against-real-IdP variant of MED-6's
// unit test. The unit test stays the canonical regression because
// it doesn't require the testcontainer; this test is the
// belt-and-braces check that the auto-refresh works against real
// go-oidc error wording emitted by a production-grade JWKS endpoint.
func TestKeycloakIntegration_MED6_AutoRefreshOnKidMiss(t *testing.T) {
	fx := keycloakFor(t)
	svc, _, _, _ := buildKeycloakService(t, fx, map[string]string{
		testfixtures.EngineerGroup: "r-operator",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Step 1 — baseline login to prime the JWKS cache.
	preAuthURL, preCookie, _, err := svc.HandleAuthRequest(ctx, fx.Provider.ID, "", "")
	if err != nil {
		t.Fatalf("pre-rotate HandleAuthRequest: %v", err)
	}
	preCode, preState := driveAuthCodeFlow(t, preAuthURL, testfixtures.EngineerUser, testfixtures.EngineerPassword)
	if _, err := svc.HandleCallback(ctx, preCookie, preCode, preState, "", "ip", "ua"); err != nil {
		t.Fatalf("pre-rotate HandleCallback (priming): %v", err)
	}

	// Step 2 — rotate Keycloak's realm signing key.
	fx.RotateRealmKeys(t)

	// Step 3 — DELIBERATELY skip svc.RefreshKeys. The whole point of
	// MED-6 is that the implicit auto-refresh inside HandleCallback
	// recovers from kid-not-in-cache without operator intervention.
	// If MED-6 regressed, the callback below would fail with a
	// generic verify error or ErrJWKSUnreachable.

	// Step 4 — post-rotate login through the implicit recovery path.
	postAuthURL, postCookie, _, err := svc.HandleAuthRequest(ctx, fx.Provider.ID, "", "")
	if err != nil {
		t.Fatalf("post-rotate HandleAuthRequest: %v", err)
	}
	postCode, postState := driveAuthCodeFlow(t, postAuthURL, testfixtures.EngineerUser, testfixtures.EngineerPassword)
	res, err := svc.HandleCallback(ctx, postCookie, postCode, postState, "", "ip", "ua")
	if err != nil {
		t.Fatalf("post-rotate HandleCallback (expected MED-6 auto-refresh): %v", err)
	}
	if res == nil || res.User == nil {
		t.Fatalf("CallbackResult missing user after MED-6 recovery")
	}
}
