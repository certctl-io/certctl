//go:build integration && okta_smoke

package oidc_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/auth/oidc"
	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
)

// =============================================================================
// Bundle 2 Phase 10 — optional Okta smoke test.
//
// Gated behind TWO build tags (`integration` AND `okta_smoke`) so it
// NEVER runs in normal CI — Keycloak is the load-bearing free-tier
// fixture; Okta is a paid dev-tenant smoke test the operator runs by
// hand against the operator's own Okta org. Documented for manual
// verification.
//
// Run via:
//
//	export OKTA_ISSUER=https://dev-12345.okta.com/oauth2/default
//	export OKTA_CLIENT_ID=0oa…
//	export OKTA_CLIENT_SECRET=…
//	export OKTA_USERNAME=tester@example.com
//	export OKTA_PASSWORD=…
//	go test -tags 'integration okta_smoke' -count=1 -timeout 2m \
//	  ./internal/auth/oidc/...
//
// Pre-reqs in the operator's Okta org:
//
//   - One Web Application (OAuth/OIDC) with sign-in redirect URI set to
//     http://localhost:8443/auth/oidc/callback (or whatever the test
//     operator binds; matches OIDCProvider.RedirectURI).
//   - One App Group named `certctl-engineers`, assigned to the user
//     above + assigned to the application.
//   - The default "groups" claim emitted as a `string-array` (Okta's
//     default).
//   - "Resource Owner Password" grant ENABLED (Sign-On tab → Grant
//     types) — the smoke test uses ROPC to skip the browser login.
//     This is for SMOKE TESTING ONLY; production certctl uses the
//     auth-code-with-PKCE flow.
//
// What this test exercises:
//
//   - Discovery doc fetched against the live Okta tenant.
//   - JWKS cached.
//   - RefreshKeys returns no error (re-runs the IdP-downgrade-attack
//     defense against Okta's advertised signing algs).
//
// What this test does NOT exercise:
//
//   - The full auth-code flow (Okta requires a browser session +
//     consent screen for the auth-code path; the Keycloak fixture is
//     where that flow lives).
//   - JWKS rotation (requires admin-level access to Okta's signing
//     key admin REST endpoints; out of scope for a smoke test).
//
// If any required env var is missing, the test t.Skip's with a clear
// message so the operator knows what to set.
// =============================================================================

func TestOktaSmoke_DiscoveryAndRefreshKeys(t *testing.T) {
	issuer := strings.TrimRight(os.Getenv("OKTA_ISSUER"), "/")
	clientID := os.Getenv("OKTA_CLIENT_ID")
	clientSecret := os.Getenv("OKTA_CLIENT_SECRET")

	missing := []string{}
	if issuer == "" {
		missing = append(missing, "OKTA_ISSUER")
	}
	if clientID == "" {
		missing = append(missing, "OKTA_CLIENT_ID")
	}
	if clientSecret == "" {
		missing = append(missing, "OKTA_CLIENT_SECRET")
	}
	if len(missing) > 0 {
		t.Skipf("Okta smoke test requires env vars: %s — skipping", strings.Join(missing, ", "))
	}

	prov := &oidcdomain.OIDCProvider{
		ID:                    "op-okta-smoke",
		TenantID:              "t-default",
		Name:                  "Okta (smoke)",
		IssuerURL:             issuer,
		ClientID:              clientID,
		ClientSecretEncrypted: []byte(clientSecret), // plaintext-passthrough; encryption-at-rest covered elsewhere
		RedirectURI:           "http://localhost:8443/auth/oidc/callback",
		GroupsClaimPath:       "groups",
		GroupsClaimFormat:     oidcdomain.GroupsClaimFormatStringArray,
		FetchUserinfo:         false,
		Scopes:                []string{"openid", "profile", "email", "groups"},
		IATWindowSeconds:      300,
		JWKSCacheTTLSeconds:   3600,
		CreatedAt:             time.Now().UTC(),
		UpdatedAt:             time.Now().UTC(),
	}

	provLookup := &itestProviderLookup{provider: prov}
	mappings := &itestMappings{lookup: map[string]string{"certctl-engineers": "r-operator"}}
	users := newItestUsers()
	sessions := newItestSessionMinter()
	pl := newItestPreLogin()
	svc := oidc.NewService(provLookup, mappings, users, sessions, pl, "")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Behavior 1: discovery doc fetched + JWKS loaded.
	if err := svc.RefreshKeys(ctx, prov.ID); err != nil {
		t.Fatalf("RefreshKeys against %s: %v", issuer, err)
	}

	// Behavior 2: HandleAuthRequest produces an authz URL anchored at
	// the configured Okta issuer. We don't drive the browser login
	// here — the Keycloak fixture covers full auth-code; this test
	// only confirms the wire setup against a real Okta tenant.
	authURL, _, _, err := svc.HandleAuthRequest(ctx, prov.ID)
	if err != nil {
		t.Fatalf("HandleAuthRequest: %v", err)
	}
	if !strings.HasPrefix(authURL, issuer) {
		t.Errorf("authURL not anchored at %s; got %s", issuer, authURL)
	}
}
