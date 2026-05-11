# Keycloak OIDC runbook

> Last reviewed: 2026-05-10

This is the canonical reference runbook for wiring certctl's OIDC SSO surface against [Keycloak](https://www.keycloak.org/). Keycloak is a free / open-source identity provider that runs on-prem or self-hosted; it is also the load-bearing test fixture for certctl's OIDC integration tests (`internal/auth/oidc/testfixtures/keycloak.go`), so the certctl-side validation pipeline is exhaustively exercised against it.

If your IdP is something else (Okta, Auth0, Azure AD, Authentik, Google Workspace), see the per-IdP siblings in [this directory](index.md). The mental model + certctl-side wiring are identical; only the IdP-side console differs.

## Prerequisites

**On the Keycloak side:**

- Keycloak ≥ 25.0 (older versions work but the screen flows differ slightly — the integration test fixture pins 25.0).
- Admin access to a realm — either an existing tenant realm or a fresh one created for certctl. Don't share Keycloak's `master` realm; create a dedicated realm.
- Network reachability from certctl-server to the Keycloak `https://<keycloak-host>/realms/<realm-name>` discovery endpoint. The certctl service fetches `/.well-known/openid-configuration` at provider creation and at every `RefreshKeys` call.
- Keycloak's signing alg set to RS256 (default) or any of: RS512, ES256, ES384, EdDSA. HS256/HS384/HS512 + `none` are rejected by certctl's IdP-downgrade-attack defense at provider creation time.

**On the certctl side:**

- `CERTCTL_CONFIG_ENCRYPTION_KEY` set to a stable secret (production deployments only — the encryption-at-rest layer for the OIDC client_secret depends on it).
- An admin actor holding `auth.oidc.create` + `auth.oidc.edit` (held by `r-admin` by default; granted via `certctl_auth_assign_role_to_key` MCP tool or the GUI's Auth → Keys page).
- Server build ≥ v2.1.0.

## IdP-side configuration

The same configuration you'll do by hand here is what the testcontainers fixture imports from `internal/auth/oidc/testfixtures/keycloak-realm.json` — read that file alongside this runbook to see the exact JSON shape Keycloak persists.

### 1. Create or pick a realm

In the Keycloak admin console (`https://<keycloak-host>/admin/`), drop into the realm you'll use. If creating a new one, the realm name will become part of the issuer URL: `https://<keycloak-host>/realms/<realm-name>`.

### 2. Create the OIDC client

**Clients → Create client**:

- Client type: **OpenID Connect**
- Client ID: `certctl` (or whatever you prefer; it goes into `OIDCProvider.client_id` on the certctl side).
- Always display in console: off.
- Click **Next**.

On the capability config page:

- Client authentication: **On** (this makes the client confidential, which is what certctl requires).
- Authorization: off.
- Standard flow: **on** (auth-code with PKCE — this is the path certctl uses).
- Direct access grants: off (ROPC; the test fixture turns this on for ROPC convenience but production should NOT).
- Implicit flow: off.
- Service accounts roles: off.
- Click **Next**.

Login settings:

- Root URL: leave blank.
- Home URL: blank.
- Valid redirect URIs: `https://<your-certctl-host>:8443/auth/oidc/callback` — ONE entry, exact match. Wildcards (`*`) work for local dev (`http://localhost:*`) but production should pin the exact host.
- Valid post logout redirect URIs: blank or `+` (matches the redirect URI list).
- Web origins: `+` (matches the redirect URI origin) or empty.
- Click **Save**.

On the saved client's **Credentials** tab, copy the **Client secret** — you'll need it for the certctl-side payload.

### 3. Create the groups

**Groups → Create group**:

- Repeat for every certctl role you want to map to a group. A typical setup creates two:
  - `certctl-engineers` (intended target: `r-operator`)
  - `certctl-viewers` (intended target: `r-viewer`)
- Optionally an `certctl-admins` group → `r-admin` for break-glass-free first-admin bootstrap; see the [`auth-threat-model.md`](../auth-threat-model.md) section on bootstrap admins.

### 4. Configure the group-membership claim mapper

This is the load-bearing step — without it, the ID token won't carry a `groups` claim and every login fails closed with `ErrGroupsUnmapped`.

**Clients → certctl → Client scopes → certctl-dedicated → Add mapper → By configuration → Group Membership**:

- Name: `groups`
- Token Claim Name: `groups`
- Full group path: **off** (so the claim emits `engineers`, not `/engineers`; matches the certctl `string-array` group-claim format).
- Add to ID token: **on**.
- Add to access token: **on** (optional but recommended; the userinfo-fallback path uses it).
- Add to userinfo: **on**.
- Click **Save**.

### 5. Create the user(s)

**Users → Add user**:

- Username: `alice` (or however you identify operators).
- Email: required (used as the certctl-side `User.Email`).
- First name + last name: optional but populates `User.DisplayName`.
- Email verified: **on** if you trust the user.
- Click **Create**.

On the saved user's **Credentials** tab:
- Set a password. Mark **Temporary** if you want the user to reset on first login.

On the **Groups** tab:
- Join the user to the group(s) you created in step 3.

## certctl-side configuration

### Via the GUI

1. Sign in as an admin actor.
2. Navigate to **Auth → OIDC Providers** in the sidebar.
3. Click **Configure provider**.
4. Fill in:
   - **Display name**: `Keycloak` (free-text; what end-users see on the login page button).
   - **Issuer URL**: `https://<keycloak-host>/realms/<realm-name>`.
   - **Client ID**: `certctl` (matches step 2 above).
   - **Client secret**: paste the secret from step 2's Credentials tab.
   - **Redirect URI**: `https://<your-certctl-host>:8443/auth/oidc/callback`.
   - **Groups claim path**: `groups` (the default; matches step 4's Token Claim Name).
   - **Groups claim format**: `string-array` (the default).
   - **Fetch userinfo**: off (Keycloak emits groups in the ID token; userinfo fallback is for IdPs that don't).
   - **Scopes**: `openid profile email` (the certctl service prepends `openid` if missing).
   - **IAT window seconds**: 300 (default).
   - **JWKS cache TTL seconds**: 3600 (default).
5. Click **Save**.

If the discovery doc fetch fails, the modal surfaces the error inline. The most common cause is a typo in the issuer URL — Keycloak emits 404 for any path under `/realms/` that doesn't match an actual realm.

### Via the API

```bash
curl -X POST https://<your-certctl-host>:8443/api/v1/auth/oidc/providers \
  -H "Authorization: Bearer ${CERTCTL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Keycloak",
    "issuer_url": "https://keycloak.example.com/realms/certctl",
    "client_id": "certctl",
    "client_secret": "<paste-the-secret>",
    "redirect_uri": "https://certctl.example.com:8443/auth/oidc/callback",
    "groups_claim_path": "groups",
    "groups_claim_format": "string-array",
    "fetch_userinfo": false,
    "scopes": ["openid", "profile", "email"],
    "iat_window_seconds": 300,
    "jwks_cache_ttl_seconds": 3600
  }'
```

### Via MCP

```
certctl_auth_create_oidc_provider {
  "name": "Keycloak",
  "issuer_url": "https://keycloak.example.com/realms/certctl",
  "client_id": "certctl",
  "client_secret": "<paste-the-secret>",
  "redirect_uri": "https://certctl.example.com:8443/auth/oidc/callback",
  "groups_claim_path": "groups",
  "groups_claim_format": "string-array",
  "scopes": ["openid", "profile", "email"]
}
```

### Add the group→role mappings

GUI: **Auth → OIDC Providers → Keycloak → Group → role mappings → Add**.

- IdP group: `certctl-engineers` → certctl role: `r-operator`.
- IdP group: `certctl-viewers` → certctl role: `r-viewer`.

API equivalent: `POST /api/v1/auth/oidc/group-mappings` with `{"provider_id": "<id>", "group_name": "certctl-engineers", "role_id": "r-operator"}`. MCP equivalent: `certctl_auth_add_group_mapping`.

Empty mapping list = nobody can log in via Keycloak (the fail-closed contract). Add at least one before announcing the SSO endpoint to users.

## Verification

### End-to-end login

1. Open `https://<your-certctl-host>:8443/login` in a fresh incognito window.
2. The page renders an OIDC button block with `Sign in with Keycloak` (the display name from the create-provider step).
3. Click it. The browser redirects to Keycloak, you authenticate as `alice`, Keycloak redirects back to certctl, and you land on the dashboard.
4. Navigate to **Auth → Sessions**. You should see a row with your own actor ID, the IP you logged in from, and the current timestamp under "last seen".

### Audit trail

```bash
curl https://<your-certctl-host>:8443/api/v1/audit?category=auth \
  -H "Authorization: Bearer ${CERTCTL_API_KEY}" | jq '.events[] | select(.action == "auth.oidc_login_succeeded")'
```

You should see a row for the login above, with `details.provider_id` matching the Keycloak provider's id and `details.subject` set to the Keycloak user's `sub` claim (typically a UUID).

### JWKS-rotation drill

Operator action when Keycloak rotates its realm signing key:

1. In Keycloak: **Realm settings → Keys → Providers → Add provider → rsa-generated**, set priority higher than the current key (e.g. 200), enabled = on, active = on.
2. In certctl: GUI → **Auth → OIDC Providers → Keycloak → Refresh discovery cache** button. Or the CLI / MCP equivalent: `POST /api/v1/auth/oidc/providers/<id>/refresh`.
3. Run another login. The new ID token is signed under the new key; the certctl service validates it against the freshly-fetched JWKS doc.

The Keycloak integration test `TestKeycloakIntegration_JWKSRotation_RefreshKeysPicksUpNewKey` exercises this exact flow end to end.

## Troubleshooting

**"Discovery doc fetch failed" at provider creation.**
The most common cause is a wrong issuer URL — typo in realm name, missing `/realms/` segment, or HTTP→HTTPS redirect that the Go client doesn't follow without explicit headers. Curl the URL manually:
```
curl -v https://<keycloak-host>/realms/<realm-name>/.well-known/openid-configuration
```
If that returns 404, fix the realm name. If it returns 200 but certctl still fails, check `cmd/server` logs for the wrapped error.

**"IdP downgrade-attack defense" rejected provider creation.**
Keycloak's realm has a signing key advertised in `id_token_signing_alg_values_supported` that's in certctl's deny-list (HS256/HS384/HS512/`none`). Check **Realm settings → Keys → Providers** — disable any HMAC key providers and re-create the provider in certctl.

**Login redirects to Keycloak, the user authenticates, but the callback redirects back to `/login` with "no roles assigned".**
The user authenticated successfully but their groups didn't match any configured mapping (`ErrGroupsUnmapped`). Check:
- The user is actually a member of the group you mapped (Users → user → Groups tab in Keycloak).
- The group-membership mapper is configured correctly (Clients → certctl → Client scopes → certctl-dedicated → mappers → groups → "Full group path: off" matters).
- The group name in your certctl mapping exactly matches what Keycloak emits — case-sensitive, no leading slash if "Full group path: off".

You can confirm what Keycloak is actually emitting by decoding the ID token at jwt.io against the Keycloak public key, or by enabling certctl's debug logging on the OIDC service for one login (logs are scrubbed of token contents per the OIDC service's token-leak hygiene contract; debug logs surface only the resolved group list and the mapping decision).

**"id_token verify failed: token used before issued"**
Clock skew between Keycloak and certctl-server. Either align both to NTP, or bump `iat_window_seconds` on the OIDC provider config (default 300 = 5 minutes). The certctl service caps `iat_window_seconds` at 600.

**"oidc: pre-login session not found or already consumed"**
The user clicked the OIDC login button, then the browser tab idled past the 10-minute pre-login TTL OR the user opened the IdP login in a new tab and consumed the row from the first one. Have them retry.

**"oidc: state parameter mismatch (replay or forgery)"**
Either the user double-submitted a callback URL (clicked it twice from email or browser history), or a CSRF attempt. The pre-login row is single-use; second consumption returns `ErrPreLoginNotFound`. Have them retry from the login page.

**Sessions revoked but the user can still hit the API.**
Check the session contract: the cookie is HMAC-validated on every request, but the actual database row is what `Revoke` deletes. If your reverse proxy is caching the response or the `__Host-certctl_session` cookie wasn't actually cleared on the client, the cookie will hit the server's session middleware which will return 401 on the missing-row lookup. The middleware never serves stale data; the issue is upstream of certctl in this case.

## Validation checklist

Before signing off this runbook for production rollout, validate these end-to-end:

- [ ] `auth.oidc_provider_created` audit row appears after the create-provider POST.
- [ ] `Sign in with Keycloak` button renders on the login page after `getAuthInfo` returns the configured provider.
- [ ] A user with mapped groups completes the auth-code flow and lands on the dashboard.
- [ ] A user WITHOUT mapped groups gets the "no roles assigned" landing (not the dashboard).
- [ ] The `auth.oidc_login_succeeded` and `auth.oidc_login_failed` audit rows correctly distinguish the two cases.
- [ ] The Sessions page shows the new session, with self-pill on the caller's row.
- [ ] Revoking the session via the GUI causes the next API request from that browser to 401 + redirect to login.
- [ ] Running the JWKS-rotation drill (steps above) does not break in-flight logins; rotated tokens validate against the refreshed JWKS.
- [ ] Editing the provider with `client_secret` blank preserves the existing ciphertext (operator confirms by reading the `oidc_providers.client_secret_encrypted` column before + after the PUT — bytes unchanged).

Sign-off: _______________ (operator) on _______________ (date).
