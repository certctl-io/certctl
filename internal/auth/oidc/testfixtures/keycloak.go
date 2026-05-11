//go:build integration

// Package testfixtures provides Bundle 2 Phase 10 multi-IdP integration
// test harnesses. The package is compiled ONLY under the `integration`
// build tag so the heavy Keycloak (or Okta) container start never lands
// in `go test -short` or the default `go test ./...` developer loop.
//
// Run via:
//
//	go test -tags integration -count=1 -timeout 5m ./internal/auth/oidc/...
//	# or via the Makefile target:
//	make keycloak-integration-test
//
// On a workstation without Docker, `go test -tags integration` will
// fail at container start with a clear error from testcontainers-go.
// The pre-commit `make verify` gate uses `-short` (no `integration`
// tag), so the absence of Docker on a contributor box does not block
// commits.
package testfixtures

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
)

// =============================================================================
// Bundle 2 Phase 10 — Keycloak testcontainers harness.
//
// Boots a single Keycloak container running in dev mode (`start-dev`),
// imports the canned realm at testfixtures/keycloak-realm.json, and
// returns a populated *oidcdomain.OIDCProvider plus a small typed
// helper struct the integration test uses to drive end-to-end flows.
//
// Realm contents (see keycloak-realm.json):
//
//   - Realm `certctl` (enabled).
//   - OIDC client `certctl` (confidential, secret pinned).
//   - Two groups (`certctl-engineers`, `certctl-viewers`).
//   - Two users with credentials:
//     - `alice` / `alice-password-1` in /certctl-engineers
//     - `bob`   / `bob-password-1`   in /certctl-viewers
//   - Group-claim mapper emitting the user's groups under `groups`
//     (id_token + access_token + userinfo).
//
// The harness pins the realm name + client id + secret + user creds as
// exported constants so the integration test can build OIDC requests
// without coupling to the JSON file's internals.
// =============================================================================

const (
	// KeycloakImage is the version-pinned image. Change requires
	// re-validating realm-import compatibility.
	KeycloakImage = "quay.io/keycloak/keycloak:25.0"

	// RealmName matches the `realm` key in keycloak-realm.json.
	RealmName = "certctl"

	// ClientID + ClientSecret match the `clients[0]` entry in the
	// realm-import JSON. Pinned by the integration test when configuring
	// the OIDC provider row that drives the certctl service.
	ClientID     = "certctl"
	ClientSecret = "certctl-keycloak-test-secret"

	// AdminUser + AdminPass are the bootstrap admin credentials Keycloak
	// uses on first start under the `start-dev` command. They are NEVER
	// surfaced by the harness for cert-issuance flows; only used to
	// enable the admin REST API for JWKS-rotation flows.
	AdminUser = "admin"
	AdminPass = "admin"

	// EngineerUser + EngineerPassword identify the alice fixture user
	// (member of the engineers group). The integration test drives
	// /token with these creds via the Resource Owner Password
	// Credentials grant (which Keycloak supports OOTB and which we
	// enable in the realm import — `directAccessGrantsEnabled: true`).
	// In production certctl uses the auth-code-with-PKCE flow; ROPC is
	// used here ONLY because driving a real browser through the IdP UI
	// in CI is brittle. The token-validation path under test is the
	// SAME — Keycloak issues structurally identical ID tokens for both
	// flows.
	EngineerUser     = "alice"
	EngineerPassword = "alice-password-1"
	EngineerGroup    = "certctl-engineers"

	ViewerUser     = "bob"
	ViewerPassword = "bob-password-1"
	ViewerGroup    = "certctl-viewers"
)

// KeycloakFixture wraps the running container + the OIDC provider row
// the integration test feeds into the certctl service. Close() tears the
// container down; deferred from the test to keep the test surface tidy.
type KeycloakFixture struct {
	Container testcontainers.Container

	// IssuerURL is the canonical realm issuer (e.g.
	// http://localhost:53219/realms/certctl). Used as
	// OIDCProvider.IssuerURL.
	IssuerURL string

	// Provider is a fully-populated domain row mirroring what
	// certctl-server would persist after a successful "Configure new
	// OIDC provider" flow in the GUI. The integration test feeds it
	// directly into the OIDC service's provider-lookup port without
	// going through the HTTP API — Phase 10's contract is "drive the
	// service end-to-end against a live IdP", not "drive the entire
	// HTTP stack".
	Provider *oidcdomain.OIDCProvider

	// adminToken is the cached admin REST API bearer (10-min lifetime,
	// re-fetched via getAdminToken when older than 9m).
	adminToken    string
	adminTokenExp time.Time
}

// StartKeycloak boots a Keycloak container with the canned realm
// pre-imported and returns the populated fixture. The container is
// reachable at the IssuerURL on the host network; testcontainers
// allocates a random host port and maps to 8080/tcp inside.
//
// Boot is bounded at 90s — Keycloak's JVM start is the dominant cost
// (warm: ~12s; cold pull: ~60s). On a busy CI runner the wait may
// timeout, in which case the test t.Fatal's with a clear message so the
// operator can rerun.
func StartKeycloak(t *testing.T) *KeycloakFixture {
	t.Helper()
	if testing.Short() {
		t.Skip("Phase 10 Keycloak integration: skipped under -short (heavy container start)")
	}

	ctx := context.Background()

	realmPath, err := realmImportPath()
	if err != nil {
		t.Fatalf("realmImportPath: %v", err)
	}

	req := testcontainers.ContainerRequest{
		Image:        KeycloakImage,
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": AdminUser,
			"KC_BOOTSTRAP_ADMIN_PASSWORD": AdminPass,
			// Disable HTTPS in dev mode; the integration test runs
			// over HTTP because the OIDC service-layer test injects
			// the provider config directly + Keycloak's dev mode
			// doesn't ship a TLS cert without --features=preview
			// flags. Production deploys MUST enable TLS at the IdP
			// (validated at OIDCProvider.Validate() time — issuer URL
			// MUST be https in non-test paths).
			"KC_HOSTNAME_STRICT":       "false",
			"KC_HOSTNAME_STRICT_HTTPS": "false",
			"KC_HEALTH_ENABLED":        "true",
			"KC_HTTP_ENABLED":          "true",
			"KC_PROXY_HEADERS":         "xforwarded",
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      realmPath,
				ContainerFilePath: "/opt/keycloak/data/import/realm.json",
				FileMode:          0o644,
			},
		},
		Cmd: []string{
			"start-dev",
			"--import-realm",
		},
		WaitingFor: wait.ForLog("Listening on:").WithStartupTimeout(90 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("Keycloak container start: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("container.Host: %v", err)
	}
	port, err := container.MappedPort(ctx, "8080")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("container.MappedPort: %v", err)
	}

	issuerURL := fmt.Sprintf("http://%s:%s/realms/%s", host, port.Port(), RealmName)

	// Wait for the realm endpoint to actually answer — the "Listening on"
	// log line fires before realm import completes on cold-pull boots.
	if err := waitForDiscovery(issuerURL, 60*time.Second); err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("waitForDiscovery: %v", err)
	}

	prov := &oidcdomain.OIDCProvider{
		ID:        "op-keycloak-itest",
		TenantID:  "t-default",
		Name:      "Keycloak (integration test)",
		IssuerURL: issuerURL,
		ClientID:  ClientID,
		// Enabled=true is required for HandleAuthRequest to reach the
		// IdP discovery + redirect path. The field was added by Audit
		// 2026-05-11 MED-9 (Bundle 2 Fix 13 Phase B); pre-fix providers
		// had no enable-flag and HandleAuthRequest always proceeded.
		// Default zero-value false would gate all integration tests
		// behind ErrProviderDisabled.
		Enabled: true,
		// ClientSecretEncrypted intentionally left zero-length: the
		// integration test invokes the service with encryptionKey="",
		// which the Phase-3 service treats as plaintext-passthrough.
		// Production MUST set CERTCTL_CONFIG_ENCRYPTION_KEY (validated
		// at server boot) — the integration test exercises the wire +
		// validation paths, not the encryption-at-rest path (that's
		// covered by the Phase-2 repository tests).
		ClientSecretEncrypted: []byte(ClientSecret),
		RedirectURI:           "http://localhost:8443/auth/oidc/callback",
		GroupsClaimPath:       "groups",
		GroupsClaimFormat:     oidcdomain.GroupsClaimFormatStringArray,
		FetchUserinfo:         false,
		Scopes:                []string{"openid", "profile", "email"},
		IATWindowSeconds:      300,
		JWKSCacheTTLSeconds:   3600,
		CreatedAt:             time.Now().UTC(),
		UpdatedAt:             time.Now().UTC(),
	}

	return &KeycloakFixture{
		Container: container,
		IssuerURL: issuerURL,
		Provider:  prov,
	}
}

// Close terminates the container. Idempotent — calling twice is safe.
func (f *KeycloakFixture) Close() {
	if f == nil || f.Container == nil {
		return
	}
	_ = f.Container.Terminate(context.Background())
	f.Container = nil
}

// AdminBaseURL returns the Keycloak admin REST API base for this realm.
// The integration test uses it to drive JWKS-key rotation (the only
// admin op the harness exposes; everything else flows through the
// public OIDC endpoints).
func (f *KeycloakFixture) AdminBaseURL() string {
	// The realm-management API lives under /admin/realms/{realm}.
	// IssuerURL is .../realms/{realm}; chop the realms-prefix and
	// re-append /admin/realms/{realm}.
	idx := strings.LastIndex(f.IssuerURL, "/realms/")
	if idx < 0 {
		return ""
	}
	return f.IssuerURL[:idx] + "/admin/realms/" + RealmName
}

// AdminToken returns a cached admin-realm bearer token, refreshed every
// 9 minutes (Keycloak's default 10-minute admin-token lifetime). The
// integration test passes this token into Keycloak's admin REST API via
// the Authorization header.
func (f *KeycloakFixture) AdminToken(t *testing.T) string {
	t.Helper()
	if f.adminToken != "" && time.Now().Before(f.adminTokenExp) {
		return f.adminToken
	}

	// The admin-cli client lives under the master realm.
	masterTokenURL := strings.Replace(f.IssuerURL, "/realms/"+RealmName, "/realms/master/protocol/openid-connect/token", 1)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "admin-cli")
	form.Set("username", AdminUser)
	form.Set("password", AdminPass)

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := httpClient.PostForm(masterTokenURL, form)
	if err != nil {
		t.Fatalf("admin-cli token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin-cli token: HTTP %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("admin-cli token decode: %v", err)
	}
	if body.AccessToken == "" {
		t.Fatalf("admin-cli token: empty access_token")
	}
	f.adminToken = body.AccessToken
	// Refresh 1 minute before actual expiry so a long-running test
	// doesn't trip on a token-just-expired edge.
	f.adminTokenExp = time.Now().Add(time.Duration(body.ExpiresIn-60) * time.Second)
	return f.adminToken
}

// FetchTokensROPC fetches an ID token + access token via the Resource
// Owner Password Credentials grant. Used by the integration test to
// drive the service-layer token-validation path against a real
// Keycloak-issued ID token without scripting a browser through the
// IdP login UI. The certctl service runs the SAME validation pipeline
// regardless of the grant type that produced the tokens — alg pin,
// iss, aud, azp, at_hash, exp, iat, nonce, JWKS — so the IdP-side
// shape is what's under test.
//
// Note: production certctl uses auth-code-with-PKCE; ROPC is enabled in
// keycloak-realm.json's `directAccessGrantsEnabled: true` for this
// fixture and ONLY this fixture.
func (f *KeycloakFixture) FetchTokensROPC(t *testing.T, username, password string) (idToken, accessToken string) {
	t.Helper()
	tokenURL := f.IssuerURL + "/protocol/openid-connect/token"

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", ClientID)
	form.Set("client_secret", ClientSecret)
	form.Set("username", username)
	form.Set("password", password)
	form.Set("scope", "openid profile email")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.PostForm(tokenURL, form)
	if err != nil {
		t.Fatalf("ROPC token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ROPC token: HTTP %d", resp.StatusCode)
	}
	var body struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("ROPC token decode: %v", err)
	}
	if body.IDToken == "" || body.AccessToken == "" {
		t.Fatalf("ROPC token: missing id_token / access_token")
	}
	return body.IDToken, body.AccessToken
}

// RotateRealmKeys drops + re-adds the active RSA key under the realm,
// forcing every subsequent token to be signed under a new kid. The
// integration test uses this to verify the certctl service's JWKS
// cache + downgrade-attack defense pick up the new key after a
// RefreshKeys() call.
//
// Implementation: Keycloak exposes /admin/realms/{realm}/keys for read,
// and /admin/realms/{realm}/components for rotate. The simplest
// reliable shape is to add a brand-new RSA-2048 key component (which
// becomes active because of the higher priority we set), leaving the
// old one as fallback. Any token signed under the new key must be
// validated against the JWKS doc fetched after the rotation; tokens
// signed under the old key must STILL validate (Keycloak keeps the
// old key as inactive-but-trusted until manually deleted).
func (f *KeycloakFixture) RotateRealmKeys(t *testing.T) {
	t.Helper()
	token := f.AdminToken(t)

	body := map[string]any{
		"name":         fmt.Sprintf("rotated-%d", time.Now().UnixNano()),
		"providerId":   "rsa-generated",
		"providerType": "org.keycloak.keys.KeyProvider",
		"config": map[string][]string{
			"priority":  {"200"},
			"enabled":   {"true"},
			"active":    {"true"},
			"algorithm": {"RS256"},
			"keySize":   {"2048"},
		},
	}
	payload, _ := json.Marshal(body)

	// Realm name on the path is the master endpoint slug; resolve it
	// via the realm's own admin URL, not the master realm's. The
	// rotated key is added to the certctl realm.
	realmAdminURL := f.AdminBaseURL() + "/components"

	req, err := http.NewRequest(http.MethodPost, realmAdminURL, strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("rotate keys: build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("rotate keys: HTTP: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("rotate keys: HTTP %d", resp.StatusCode)
	}
}

// realmImportPath resolves the absolute path to keycloak-realm.json
// next to this source file. Used to mount the realm-import volume into
// the container.
func realmImportPath() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed")
	}
	dir := filepath.Dir(filename)
	candidate := filepath.Join(dir, "keycloak-realm.json")
	return candidate, nil
}

// waitForDiscovery polls the OIDC discovery doc until it returns 200 OR
// the deadline elapses. Keycloak's "Listening on" log line fires before
// the realm-import completes on cold-pull boots, so we layer this poll
// on top of the WaitForLog primitive.
func waitForDiscovery(issuerURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	httpClient := &http.Client{Timeout: 2 * time.Second}
	for {
		resp, err := httpClient.Get(issuerURL + "/.well-known/openid-configuration")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("discovery doc never returned 200 within %s", timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
