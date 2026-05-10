# Okta OIDC runbook

> Last reviewed: 2026-05-10

This runbook wires certctl's OIDC SSO surface against [Okta](https://www.okta.com/), a commercial cloud IdP. Okta offers a free developer tier (`https://dev-NNNNN.okta.com`) suitable for evaluation; production runs on a paid Workforce Identity tenant.

For the canonical reference + mental model, read [keycloak.md](keycloak.md) first; this runbook only documents the Okta-specific deltas.

## Prerequisites

**On the Okta side:**

- A Workforce Identity tenant (or free Developer Edition account at <https://developer.okta.com/signup/>).
- Super Admin or Application Admin role in your Okta tenant.
- Network reachability from certctl-server to `https://<your-org>.okta.com/.well-known/openid-configuration` OR to a custom authorization server endpoint if you're using one (`https://<your-org>.okta.com/oauth2/<auth-server-id>/.well-known/openid-configuration`).

**On the certctl side:** same as Keycloak.

## IdP-side configuration

### 1. Create the OIDC application

In the Okta admin console:

**Applications → Applications → Create App Integration**:

- Sign-in method: **OIDC - OpenID Connect**.
- Application type: **Web Application**.
- Click **Next**.

App config:

- App integration name: `certctl`.
- Logo: optional.
- Grant types: **Authorization Code** (CHECK). Leave Refresh Token unchecked unless you have a specific reason — certctl doesn't currently use refresh tokens.
- Sign-in redirect URIs: `https://<your-certctl-host>:8443/auth/oidc/callback`.
- Sign-out redirect URIs: optional; leave empty unless you also configure RP-initiated logout.
- Trusted Origins: leave default.
- Assignments → Controlled access: **Limit access to selected groups** (recommended; pick the `certctl-*` groups from step 3 below).
- Click **Save**.

On the saved app's **General** tab, copy the **Client ID** and **Client secret** (under Client Credentials). The secret is shown once on creation — copy it immediately or rotate via "Generate new secret".

### 2. Pick or create an authorization server

Okta has TWO authorization-server tiers:

- **The Org Authorization Server** at `https://<your-org>.okta.com` — emits ID tokens with limited claims; cannot host custom claims directly. Use for the simplest setup.
- **A Custom Authorization Server** at `https://<your-org>.okta.com/oauth2/<auth-server-id>` — fully configurable scopes + claims + access policies. The free developer tier ships with a default custom server at `/oauth2/default`. Recommended for production.

For this runbook we use the default custom server: `https://<your-org>.okta.com/oauth2/default`.

### 3. Create the groups + assign users

**Directory → Groups → Add Group**:

- Repeat for `certctl-engineers`, `certctl-viewers`, optionally `certctl-admins`.

**Directory → People → <user> → Groups**: assign each user to the appropriate `certctl-*` group(s).

Then go back to the App from step 1 and on the **Assignments** tab, assign the `certctl-*` groups to the application. Without this assignment Okta will reject the user's login attempt at the IdP layer with "User is not assigned to the client application".

### 4. Configure the groups claim

This is the load-bearing Okta-specific step. The default authorization server does NOT emit a `groups` claim out of the box — you have to define it.

**Security → API → Authorization Servers → default → Claims → Add Claim**:

- Name: `groups`.
- Include in token type: **ID Token, Always** (also tick Access Token if you want the userinfo-fallback path to work).
- Value type: **Groups**.
- Filter: pick **Matches regex** with the value `certctl-.*` so only the `certctl-*` groups are emitted (saves on token size; users in dozens of unrelated groups get a bloated token otherwise).
- Disable claim: off.
- Include in: **Any scope** (or pin to `openid` if you want the claim only on the certctl-flow).
- Click **Create**.

### 5. (Optional) Add `email` and `profile` claims

The default custom server already emits `email` and `name` under the `profile` and `email` scopes — no action needed unless you've stripped them from a custom config.

## certctl-side configuration

```bash
curl -X POST https://<your-certctl-host>:8443/api/v1/auth/oidc/providers \
  -H "Authorization: Bearer ${CERTCTL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Okta",
    "issuer_url": "https://your-org.okta.com/oauth2/default",
    "client_id": "<paste-from-step-1>",
    "client_secret": "<paste-from-step-1>",
    "redirect_uri": "https://certctl.example.com:8443/auth/oidc/callback",
    "groups_claim_path": "groups",
    "groups_claim_format": "string-array",
    "fetch_userinfo": false,
    "scopes": ["openid", "profile", "email"],
    "iat_window_seconds": 300,
    "jwks_cache_ttl_seconds": 3600
  }'
```

Notes:

- `issuer_url` MUST match exactly what Okta emits as the `iss` claim. For the default custom server it's `https://<your-org>.okta.com/oauth2/default` (no trailing slash). The org server's issuer is just `https://<your-org>.okta.com` (no `/oauth2/...` path). Mismatching either side trips certctl's `ErrIssuerMismatch` sentinel.
- The `groups` scope is NOT required in the scopes list — Okta emits the claim based on the claim definition's "Include in: any scope" setting. Adding `groups` to the scopes list is harmless if your custom server has the scope defined.

Add the group→role mappings: `certctl-engineers` → `r-operator`, `certctl-viewers` → `r-viewer`, `certctl-admins` → `r-admin`.

## Verification

End-to-end login + audit + Sessions checks are identical to Keycloak.

**Okta-specific:** the audit row's `details.subject` will be Okta's user UID (a 20-char alphanumeric string starting with `00u`), stable across email changes. The certctl `users` table's `oidc_subject` column will hold this UID.

**Optional Okta smoke test in CI:** Phase 10 ships an opt-in smoke test at `internal/auth/oidc/integration_okta_smoke_test.go` (build tags `integration && okta_smoke`). Set `OKTA_ISSUER` + `OKTA_CLIENT_ID` + `OKTA_CLIENT_SECRET` env vars and run `make okta-smoke-test` to drive a discovery + RefreshKeys round-trip against your live tenant. Pre-reqs: enable the Resource Owner Password (ROPC) grant on the application (Sign-On tab → Grant types → Resource Owner Password) for the smoke test only; production certctl uses auth-code-with-PKCE.

**JWKS-rotation drill:** Okta auto-rotates signing keys every ~3 months and publishes the new key alongside the old in the JWKS doc for ~1 month overlap. Manual rotation: **Security → API → Authorization Servers → default → Keys → "Generate new key"**. After rotation, click "Refresh discovery cache" in certctl's GUI; new tokens validate immediately.

## Troubleshooting

**"User is not assigned to the client application" at the Okta login screen.**
You created the app + the user but didn't assign the user to the app via a group. Either assign the user directly (App → Assignments → Assign to People) or assign the `certctl-*` groups to the app (App → Assignments → Assign to Groups).

**Login completes but `groups` claim is empty in the ID token.**
Most common Okta gotcha — the default custom server doesn't emit `groups` until you define the claim (step 4 above). Decode the ID token at jwt.io to confirm. If the claim is defined but empty, check the regex filter in step 4 — `certctl-.*` matches names like `certctl-engineers` but NOT `engineers`.

**`ErrIssuerMismatch` after correctly configuring the discovery URL.**
The issuer claim Okta puts in the ID token MUST match `OIDCProvider.IssuerURL` byte-for-byte, including trailing slash. The default custom server emits `https://<your-org>.okta.com/oauth2/default` (no trailing slash); the org server emits `https://<your-org>.okta.com`. Don't append a trailing slash to either.

**Login succeeds but the certctl `User.Email` is empty.**
The `email` scope wasn't requested OR the user's email isn't verified at Okta. Add `email` to the certctl scopes config and ensure Okta's user has a verified primary email.

**Okta returns "PKCE code verifier required".**
The certctl service hard-codes PKCE-S256 on every login (RFC 9700 mandate). If Okta is rejecting the verifier, the most likely cause is a misconfigured app type — confirm the Okta application is "Web Application" (which supports auth-code + PKCE), not "Single-Page Application" (which has different token-binding rules) or "Native App".

**Custom-server access policies blocking the login.**
By default the `default` custom authorization server has an "Access Policy" with one rule allowing all clients + all users. If you've tightened this (production hygiene), add a rule that allows the `certctl` client + the `certctl-*` groups: **Security → API → Authorization Servers → default → Access Policies → <policy> → Add Rule**.

## Validation checklist

Same as [keycloak.md](keycloak.md#validation-checklist), with Okta-specific values + the access-policy check above.

Sign-off: _______________ (operator) on _______________ (date).
