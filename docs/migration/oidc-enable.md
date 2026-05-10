# Enable OIDC SSO on a Bundle-1-merged deployment

> Last reviewed: 2026-05-10

This guide walks an operator already running certctl with Bundle 1 (RBAC primitive on top of API-key auth) through enabling OIDC SSO from Bundle 2. The path is additive: API-key auth keeps working unchanged; OIDC sits alongside as a second authentication surface for human users.

If you are upgrading from a pre-Bundle-1 deployment, finish [`api-keys-to-rbac.md`](api-keys-to-rbac.md) first. If you have not deployed certctl at all, start with [`getting-started/quickstart.md`](../getting-started/quickstart.md). For the canonical mental model + per-flow threat coverage, see [`security.md`](../operator/security.md) and [`auth-threat-model.md`](../operator/auth-threat-model.md).

## What "enable OIDC" gives you

After this migration:

- Human operators can log in via the OIDC button on the certctl login page (one button per configured IdP).
- The IdP authenticates the user; certctl validates the returned ID token, mints a session cookie, and redirects to the dashboard.
- IdP groups → certctl roles are operator-configured (e.g. `engineering@example.com` → `r-operator`).
- Every login emits an audit row (`auth.oidc_login_succeeded`) attributing the action to the federated user, NOT to a shared API key.
- The first user from a configured admin group (when `CERTCTL_BOOTSTRAP_ADMIN_GROUPS` is set) becomes admin per tenant; one-shot per the admin-existence probe.

What does NOT change:

- API keys keep working. Existing automation continues to authenticate via `Authorization: Bearer` exactly as before.
- The break-glass admin path (Phase 7.5) stays default-OFF.
- The auditor split + approval workflow + RBAC primitive are unchanged.

## Pre-requisites

**On certctl side:**

- Server build ≥ v2.1.0 (the post-Bundle-2 master). Confirm via `curl https://<your-host>:8443/api/v1/version`.
- `CERTCTL_CONFIG_ENCRYPTION_KEY` set in the server environment. This is the passphrase that encrypts the OIDC `client_secret` at rest. Use a stable, secrets-manager-stored value at least 32 random bytes long. **The server refuses to start if the key is missing AND any source='database' rows already exist** (per Bundle B / M-001 / CWE-311 closure). Set this before doing anything else.
- An admin actor available to drive the configuration. The actor needs the `auth.oidc.create` + `auth.oidc.edit` permissions; `r-admin` carries both by default. Get one via the day-0 bootstrap path if you don't have one yet.
- HTTPS-only control plane (post-v2.2 milestone — this is the default). The OIDC redirect URI MUST be `https://`.

**On IdP side:**

- A Keycloak / Authentik / Okta / Auth0 / Entra ID / Google Workspace tenant where you can register an OIDC application. Free dev tiers work for evaluation. See the per-IdP runbook at [`oidc-runbooks/index.md`](../operator/oidc-runbooks/index.md).
- Network reachability from certctl-server to the IdP's `/.well-known/openid-configuration` discovery endpoint. The certctl service fetches discovery + JWKS at provider creation and at every `RefreshKeys` call.

## Step-by-step

### 1. Pin `CERTCTL_CONFIG_ENCRYPTION_KEY`

If your deployment already has it set (the Bundle B M-001 fail-closed gate enforces this for any source='database' issuer/target row), skip this step. If you don't:

```bash
# Generate a 32-byte random key + base64-encode it.
openssl rand -base64 32 > /etc/certctl/config-encryption-key
chmod 600 /etc/certctl/config-encryption-key
```

Then make the server consume it at boot:

```bash
# In your environment, systemd unit, k8s Secret, etc.
export CERTCTL_CONFIG_ENCRYPTION_KEY="$(cat /etc/certctl/config-encryption-key)"
```

Restart the server. Confirm the boot log does NOT show the `ErrEncryptionKeyRequired` warning. If it does, the server refuses to start because there's pre-existing source='database' material that needs to be re-sealed; see the pre-Bundle-B migration notes for re-encryption flow.

### 2. Pick an IdP runbook + complete the IdP-side configuration

Pick the runbook for your IdP and do EVERYTHING in its IdP-side section. The runbooks are at [`docs/operator/oidc-runbooks/`](../operator/oidc-runbooks/index.md). What you need from the runbook before continuing here:

- The IdP's discovery URL (the `iss` value certctl will validate against).
- An OIDC client ID + client secret. Save the secret; you'll paste it into certctl in step 3.
- At least one IdP group with the users who should be allowed to log in. The runbook walks the group-claim mapper config.
- The IdP-side group claim shape — most IdPs emit `string-array` under a `groups` key, but Auth0 uses namespaced URL keys (`https://your-namespace/groups`) and Entra ID emits group OBJECT IDs (GUIDs) instead of names. The runbook calls out the per-IdP shape.

### 3. Configure the certctl-side OIDC provider

Via the GUI (recommended for first-time setup):

1. Sign in as an admin actor.
2. Navigate to **Auth → OIDC Providers** in the sidebar.
3. Click **Configure provider**.
4. Fill in the form using the values from step 2's runbook.
5. Click **Save**.

If the discovery doc fetch fails, the modal surfaces the error inline. Most-common cause: a typo in the issuer URL.

Or via the CLI / MCP:

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
    "scopes": ["openid", "profile", "email"],
    "iat_window_seconds": 300,
    "jwks_cache_ttl_seconds": 3600
  }'
```

The MCP equivalent (`certctl_auth_create_oidc_provider`) accepts the same JSON shape.

### 4. Add the group → role mappings

Empty mapping list = nobody can log in via this provider (the fail-closed contract; pinned by `ErrGroupsUnmapped`). Add at least one mapping BEFORE announcing the SSO endpoint to users.

Via the GUI: **Auth → OIDC Providers → <provider> → Group → role mappings → Add**.

Via the API:

```bash
curl -X POST https://<your-certctl-host>:8443/api/v1/auth/oidc/group-mappings \
  -H "Authorization: Bearer ${CERTCTL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_id": "<provider-id-from-step-3>",
    "group_name": "engineering@example.com",
    "role_id": "r-operator"
  }'
```

A typical setup adds two or three mappings: `engineers → r-operator`, `viewers → r-viewer`, optionally `admins → r-admin`. For Entra ID, use group object IDs (GUIDs) NOT names; for Auth0, use the bare group name from inside the namespaced claim array.

### 5. (Optional) Configure first-admin bootstrap

If your deployment has no admin actor yet AND you want the first OIDC-authenticated user from a specific group to become admin (instead of using the env-var-token bootstrap path), set:

```bash
export CERTCTL_BOOTSTRAP_ADMIN_GROUPS=admins
export CERTCTL_BOOTSTRAP_OIDC_PROVIDER_ID=<provider-id-from-step-3>
```

Restart the server. The first user with the `admins` group claim from that provider becomes admin on login per tenant. Subsequent logins go through normal group-role mapping. Audit row on every grant (`bootstrap.oidc_first_admin`).

If you already have an admin actor (likely — you needed one to run step 3), the bootstrap hook silently falls through to normal mapping; no harm done. The probe is one-shot per tenant and can't double-grant.

### 6. Verify with a single test user

Before announcing the SSO endpoint to your users, verify the full login flow with a test user from your IdP:

1. Open `https://<your-certctl-host>:8443/login` in a fresh incognito window.
2. The page should render `Sign in with <provider>` button(s) above the API-key form. If not, check that `getAuthInfo` is returning the `oidc_providers` field — `curl https://<your-host>:8443/api/v1/auth/info` should show the configured provider(s).
3. Click the provider button. The browser redirects to the IdP, you authenticate, and the IdP redirects back. You should land on the certctl dashboard.
4. Navigate to **Auth → Sessions**. You should see a row with your own actor ID and the current timestamp.
5. Confirm the audit row:

   ```bash
   curl https://<your-host>:8443/api/v1/audit?category=auth \
     -H "Authorization: Bearer ${CERTCTL_API_KEY}" \
     | jq '.events[] | select(.action == "auth.oidc_login_succeeded")'
   ```

   You should see a row attributed to the federated user with `details.provider_id` matching your configuration.

If any step fails, see the **Troubleshooting** section below.

### 7. Announce the SSO endpoint

Once step 6 passes, the SSO endpoint is operational. Tell your users to log in via `https://<your-host>:8443/login` and click the provider button. API-key auth continues to work for automation; the two paths coexist.

Optional GUI hardening:

- If you want the API-key form hidden once OIDC is configured, the operator can add a frontend feature flag in a follow-on commit. Default behavior keeps both paths visible (the API-key form stays for break-glass + Bearer-mode deploys).
- If you want to revoke a user's session immediately (e.g. an employee left), use **Auth → Sessions → All actors (admin) → <user> → Revoke**. The next request from that user's browser fails 401.

## Rollback

If you need to disable OIDC:

1. Delete every group-role mapping for the provider:
   ```bash
   # GUI: Auth → OIDC Providers → <provider> → Group → role mappings → Remove (each)
   ```
2. Delete the OIDC provider:
   ```bash
   # GUI: Auth → OIDC Providers → <provider> → Delete (type-confirm-name dialog)
   ```
   The server returns HTTP 409 if any user has an authenticated session minted via this provider; revoke those sessions first.
3. The `Sign in with <provider>` button disappears from the login page on the next `getAuthInfo` round-trip (typically the next page load).
4. Existing sessions continue to work until idle/absolute expiry. To force-revoke them, **Auth → Sessions → All actors (admin) → revoke each row**.

API-key auth continues to work throughout this rollback; you do not need to re-bootstrap or change any other configuration.

## Troubleshooting

**"Discovery doc fetch failed" at provider creation.**
The most common cause is a typo in the issuer URL. Curl the URL manually:
```bash
curl -v https://<idp-host>/<path>/.well-known/openid-configuration
```
If that returns 404, fix the issuer URL.

**"IdP downgrade-attack defense" rejected provider creation.**
Your IdP advertises HS256/HS384/HS512 or `none` in `id_token_signing_alg_values_supported`. Configure the IdP to advertise only RS256 / RS512 / ES256 / ES384 / EdDSA before re-creating the provider in certctl. The relevant runbook section walks this.

**Login redirects to IdP, user authenticates, but the callback redirects back to `/login` with "no roles assigned".**
The user authenticated successfully but their groups didn't match any configured mapping (`ErrGroupsUnmapped`). Check:
- The user is a member of the IdP group you mapped.
- The group-claim mapper is configured correctly at the IdP (the runbook walks per-IdP).
- The group name in your certctl mapping exactly matches what the IdP emits — case-sensitive, no leading slash for Keycloak full-path-OFF.

Decode the ID token at jwt.io against the IdP's JWKS to see exactly what's in the `groups` claim.

**`ErrIssuerMismatch` even though the discovery doc looks correct.**
The `iss` claim in the ID token must match `OIDCProvider.IssuerURL` byte-for-byte. Some IdPs include / omit a trailing slash; check the per-IdP runbook section on `iss` formatting.

**`oidc: pre-login session not found or already consumed`.**
The user clicked the OIDC login button, then the browser tab idled past the 10-minute pre-login TTL OR the user opened the IdP login in a new tab and consumed the row from the first one. Have them retry from the login page.

**`oidc: state parameter mismatch (replay or forgery)`.**
Either the user double-submitted a callback URL (clicked it twice from email or browser history), or a CSRF attempt. The pre-login row is single-use; second consumption returns `ErrPreLoginNotFound`. Have them retry from the login page.

**`Sessions revoked but the user can still hit the API.`**
Check the Phase 4 session contract: the cookie is HMAC-validated on every request, but the actual database row is what `Revoke` deletes. If your reverse proxy is caching the response or the `certctl_session` cookie wasn't actually cleared on the client, the cookie hits the server's session middleware which returns 401 on the missing-row lookup. The middleware never serves stale data; the issue is upstream of certctl in this case.

**JWKS rotation: an IdP rotated its signing key and existing users start failing login.**
Click **Refresh discovery cache** on the OIDC provider detail page (or `POST /api/v1/auth/oidc/providers/<id>/refresh`). The certctl service re-fetches discovery + JWKS. New tokens validate immediately. The Phase 10 integration test exercises this drill end to end.

**Database row count drift.**
After OIDC is live, expect to see new rows under:
- `oidc_providers` (one per configured provider)
- `group_role_mappings` (one per configured mapping)
- `users` (one per first OIDC-authenticated user; certctl auto-upserts on login)
- `sessions` (one per logged-in browser session; idle 1h / absolute 8h GC)
- `session_signing_keys` (one active + retained-history rows post rotation)
- `oidc_pre_login_sessions` (transient; 10-minute TTL, scheduler-GC'd)

All ten of these tables are tenant-scoped (`tenant_id` column); single-tenant deployments use the seeded `t-default` tenant.

## What you can do next

- Run [`docs/operator/oidc-runbooks/<your-idp>.md`](../operator/oidc-runbooks/index.md) end to end to fill in the validation checklist + sign-off line.
- Read [`docs/operator/auth-benchmarks.md`](../operator/auth-benchmarks.md) for the steady-state + cold-cache performance baselines.
- Review the [`auth-threat-model.md`](../operator/auth-threat-model.md) Bundle 2 sections to understand the failure modes the OIDC + sessions surface defends against.
- Schedule a rotation reminder for the OIDC `client_secret` (typically 6-12 months; the IdP doesn't auto-rotate it). Edit the provider via the GUI when the time comes; leaving `client_secret` blank in the edit form preserves the existing ciphertext, providing a value rotates.

## Cross-references

- [`docs/operator/oidc-runbooks/index.md`](../operator/oidc-runbooks/index.md) — per-IdP setup guides.
- [`docs/operator/security.md`](../operator/security.md) — overall auth surface incl. this Bundle 2 OIDC layer.
- [`docs/operator/auth-threat-model.md`](../operator/auth-threat-model.md) — threat model.
- [`docs/operator/auth-benchmarks.md`](../operator/auth-benchmarks.md) — performance baselines.
- [`docs/reference/auth-standards-implemented.md`](../reference/auth-standards-implemented.md) — RFC + CWE evidence list.
- `internal/auth/oidc/` — OIDC service implementation.
- `internal/auth/session/` — session minting + middleware + signing-key rotation.
