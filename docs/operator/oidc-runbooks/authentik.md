# Authentik OIDC runbook

> Last reviewed: 2026-05-10

This runbook wires certctl's OIDC SSO surface against [Authentik](https://goauthentik.io/), a free / open-source IdP that runs on-prem or self-hosted. Authentik shares the canonical "string-array groups claim under the `groups` key" pattern with Keycloak — the differences are in the admin console UX and the explicit "property mapping" abstraction.

For the canonical reference + mental model, read [keycloak.md](keycloak.md) first; this runbook only documents the Authentik-specific deltas.

## Prerequisites

**On the Authentik side:**

- Authentik ≥ 2024.10 (stable channel).
- Admin access to the Authentik admin console at `https://<authentik-host>/if/admin/`.
- Network reachability from certctl-server to `https://<authentik-host>/application/o/<application-slug>/.well-known/openid-configuration`.

**On the certctl side:** same as Keycloak — `CERTCTL_CONFIG_ENCRYPTION_KEY` set, an admin actor holding `auth.oidc.create` + `auth.oidc.edit`, Bundle 2 server build.

## IdP-side configuration

### 1. Create the OAuth2 / OpenID Provider

In the Authentik admin console:

**Applications → Providers → Create**:

- Type: **OAuth2/OpenID Provider**.
- Name: `certctl`.
- Authorization flow: `default-provider-authorization-explicit-consent` (or `default-provider-authorization-implicit-consent` if you don't want a consent screen on every login).
- Click **Next**.

Protocol settings:

- Client type: **Confidential**.
- Client ID: leave the auto-generated value OR set to `certctl` for clarity.
- Client Secret: copy the auto-generated value to a secure scratchpad — you'll paste it into certctl.
- Redirect URIs/Origins: `https://<your-certctl-host>:8443/auth/oidc/callback` (one entry, exact match).
- Signing Key: pick an **RSA-2048 or larger** key. Authentik defaults to ECDSA-P256 in newer versions; either is fine — both are in certctl's allow-list.
- Subject mode: **Based on the User's hashed ID** (default; emits a stable opaque `sub`).
- Include claims in id_token: **on**.
- Click **Finish**.

### 2. Create the Application

Applications are how Authentik attaches a Provider to users + groups + policies.

**Applications → Applications → Create**:

- Name: `certctl`.
- Slug: `certctl` (becomes part of the issuer URL: `https://<authentik-host>/application/o/certctl/`).
- Provider: pick the `certctl` provider you just created.
- Policy engine mode: **any** (default).
- Click **Create**.

### 3. Configure the groups property mapping

Authentik emits group claims via "property mappings" — explicit objects rather than Keycloak's mapper-on-the-client model.

By default, the **Authentik default-OAuth Mapping: Proxy outpost** scope already includes the user's groups under a `groups` claim (string-array, matches what certctl expects). To verify or override:

**Customization → Property Mappings → Filter "Scope Mapping"**:

- Find or create one named `groups` with scope `groups` and expression:
  ```python
  return [group.name for group in user.ak_groups.all()]
  ```
- Description: `Emits the user's group names as a string-array claim`.

Then on the **Provider → certctl → Edit → Advanced protocol settings**, ensure **Scopes** includes `groups` (and `profile` and `email` if you want richer User records on the certctl side).

### 4. Create the groups + assign users

**Directory → Groups → Create**:

- Name: `certctl-engineers`. Repeat for `certctl-viewers` (and optionally `certctl-admins`).

**Directory → Users → <user> → Edit → Groups**: pick the appropriate `certctl-*` group(s) for each user.

### 5. (Optional) Bind the application to specific groups

If you want certctl to reject login attempts from users outside the `certctl-*` groups at the IdP layer (defense-in-depth on top of certctl's fail-closed `ErrGroupsUnmapped`):

**Applications → certctl → Policy / Group / User Bindings → Create binding**:

- Type: **Group**.
- Group: pick the union of `certctl-*` groups you want to allow.
- Enabled: on.

## certctl-side configuration

Identical to Keycloak — only the issuer URL differs:

```bash
curl -X POST https://<your-certctl-host>:8443/api/v1/auth/oidc/providers \
  -H "Authorization: Bearer ${CERTCTL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Authentik",
    "issuer_url": "https://authentik.example.com/application/o/certctl/",
    "client_id": "<paste-the-client-id>",
    "client_secret": "<paste-the-client-secret>",
    "redirect_uri": "https://certctl.example.com:8443/auth/oidc/callback",
    "groups_claim_path": "groups",
    "groups_claim_format": "string-array",
    "fetch_userinfo": false,
    "scopes": ["openid", "profile", "email", "groups"],
    "iat_window_seconds": 300,
    "jwks_cache_ttl_seconds": 3600
  }'
```

Authentik emits `groups` in the ID token by default once the property mapping is configured. The `scopes` array MUST include `groups` to trigger the claim emission — Authentik is stricter than Keycloak about scope-gating claims.

Add the group→role mappings the same way as Keycloak: `certctl-engineers` → `r-operator`, `certctl-viewers` → `r-viewer`.

## Verification

End-to-end login + audit + Sessions checks are identical to Keycloak.

**Authentik-specific check:** the audit row's `details.subject` will be Authentik's hashed user ID (a 64-char hex), not the username. This is intentional and correct — the `sub` claim must be opaque + stable across user-attribute changes.

**JWKS-rotation drill:** Authentik rotates signing keys via **System → Tokens & App Passwords → Certificates** (rename of "Crypto" in newer versions). Add a new RSA-2048 cert, switch the Provider's Signing Key to the new one, then click "Refresh discovery cache" in certctl's GUI to evict the cache.

## Troubleshooting

**Provider creation fails with "could not load discovery document".**
The issuer URL needs the trailing slash for some Authentik versions: `https://authentik.example.com/application/o/certctl/` (slash after the slug). Without the slash, Authentik returns a 301 redirect that Go's HTTP client follows but discovery parsing chokes on the redirect target.

**Login completes but user lands on "no roles assigned".**
Decode the ID token at jwt.io against Authentik's JWKS. Check whether the `groups` claim is present + non-empty. If empty, the property mapping isn't wired — go back to step 3.

**`groups` claim missing entirely.**
Authentik gates the `groups` claim behind the `groups` scope. Verify:
- The certctl OIDCProvider config has `"scopes": ["openid", "profile", "email", "groups"]`.
- The Authentik provider's "Scopes" list includes `groups`.

**Authentik emits the user's full DN as the `sub` claim.**
Some Authentik configurations use **Subject mode: Based on the User's email** which surfaces the email as `sub`. This works but tightly couples certctl's User table to email mutability; recommend switching to "hashed ID" mode for new deployments. Existing User rows in certctl's `users` table will have email-shaped `oidc_subject` columns; that's fine and stable as long as the user's email never changes.

## Validation checklist

Same as [keycloak.md](keycloak.md#validation-checklist), with Authentik-specific values for issuer URL + group names + signing-key rotation steps.

Sign-off: _______________ (operator) on _______________ (date).
