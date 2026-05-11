# Auth0 OIDC runbook

> Last reviewed: 2026-05-10

This runbook wires certctl's OIDC SSO surface against [Auth0](https://auth0.com/), a commercial cloud IdP (now part of Okta but operationally distinct). Auth0 has a free developer tier suitable for evaluation; production runs on a paid B2B / B2C plan.

For the canonical reference + mental model, read [keycloak.md](keycloak.md) first; this runbook only documents the Auth0-specific deltas.

## The big Auth0 quirk: namespaced custom claims

Auth0 imposes a hard rule: any custom claim emitted from an Action MUST use a namespaced URL-shape key (e.g. `https://your-namespace/groups`). Auth0 silently strips claims that look like standard OIDC claims (`groups`, `roles`, `permissions`, etc.) when emitted from an Action — this is a security feature to prevent claim-spoofing.

certctl handles this via the `groups_claim_path` config. If your Action emits `https://your-namespace/groups`, set `OIDCProvider.groups_claim_path` to that exact URL. The hand-rolled groupclaim resolver at `internal/auth/oidc/groupclaim/resolver.go` recognizes URL-shape paths (anything starting with `http://` or `https://`) and treats the entire string as a single literal key — it does NOT split on `/`.

Set `groups_claim_format` to `string-array`; the underlying claim shape is still a JSON array of group-name strings, just stored under a URL-shape key.

## Prerequisites

**On the Auth0 side:**

- An Auth0 tenant (free dev tier at <https://auth0.com/signup> works). Tenant URL looks like `https://<tenant-name>.<region>.auth0.com`.
- Owner or Auth0 Administrator role.
- Network reachability from certctl-server to `https://<tenant>.auth0.com/.well-known/openid-configuration`.

**On the certctl side:** same as Keycloak.

## IdP-side configuration

### 1. Pick a namespace string

Decide on a unique URL-shape namespace for certctl's custom claims. It does NOT have to resolve to a real domain; Auth0 just requires it to be URL-shape and unique within your tenant. A reasonable choice:

```
https://certctl.example.com/auth/
```

Use that prefix for every custom claim; for groups specifically:

```
https://certctl.example.com/auth/groups
```

We'll refer to this as `<NS>/groups` in the rest of this runbook.

### 2. Create the Application

In the Auth0 dashboard:

**Applications → Applications → Create Application**:

- Name: `certctl`.
- Application Type: **Regular Web Applications**.
- Click **Create**.

On the saved app's **Settings** tab:

- Application Login URI: blank (Auth0 doesn't need it for the auth-code flow).
- Allowed Callback URLs: `https://<your-certctl-host>:8443/auth/oidc/callback` (one entry, exact match).
- Allowed Logout URLs: optional.
- Allowed Web Origins: `https://<your-certctl-host>:8443`.
- Token Endpoint Authentication Method: **Post** (default; matches the certctl service's expectation of `client_secret_post`).
- Save Changes.

Copy the **Domain** (this is the issuer base — `https://<tenant>.auth0.com`), **Client ID**, and **Client Secret** from the same Settings page.

### 3. Configure the connection (where users live)

If you're using Auth0's Database connection (default username + password), the existing **Username-Password-Authentication** connection works. For SSO to Google / Microsoft / SAML, configure those connections under **Authentication → Enterprise** or **Authentication → Social** and ensure the connection is enabled on the certctl Application (App → Connections tab).

### 4. Define the groups

Auth0 doesn't have a first-class "Groups" concept like Okta or Keycloak — you have THREE options to model groups, each with tradeoffs:

**Option A: User app_metadata (simplest, recommended for dev tier).**

Each user has a `app_metadata` JSON blob you can set via the Management API, the dashboard, or a post-registration script. Stick the groups in there:

```json
{
  "groups": ["certctl-engineers"]
}
```

In the Auth0 dashboard, **User Management → Users → <user> → app_metadata**: paste the JSON above and Save.

**Option B: Auth0 Authorization Extension (paid plans, recommended for production).**

Install the Authorization Extension from **Marketplace → Extensions → Authorization**. It adds a first-class "Groups" concept with UI for assignment + nested groups. Read the extension's docs; it emits groups under `<NS>/groups` automatically once enabled.

**Option C: Roles + Permissions (Auth0's RBAC primitive).**

Use **User Management → Roles** to define roles like `certctl-engineer` + `certctl-viewer`. Assign roles to users. Have your Action emit role names as a `groups` claim. This is what Auth0 documents as the canonical pattern; it's slightly heavier than Option A but more discoverable in the dashboard.

This runbook uses **Option A** for clarity; the Action below reads from `app_metadata.groups`.

### 5. Write the Action that emits the groups claim

**Actions → Library → Create Action → Build from scratch**:

- Name: `certctl-emit-groups`.
- Trigger: **Login / Post Login**.
- Runtime: Node 18.
- Click **Create**.

Paste this code:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  const namespace = "https://certctl.example.com/auth/";
  const groups = (event.user.app_metadata && event.user.app_metadata.groups) || [];
  if (groups.length > 0) {
    api.idToken.setCustomClaim(namespace + "groups", groups);
    api.accessToken.setCustomClaim(namespace + "groups", groups);
  }
};
```

Replace `https://certctl.example.com/auth/` with your namespace from step 1. Click **Deploy**.

Then bind the Action to the Login flow:

**Actions → Flows → Login**: drag `certctl-emit-groups` from the Custom tab into the flow, between Start and Complete. Click **Apply**.

### 6. Verify the claim in a test login

Auth0's **Authentication → Authentication Profile → Try It** button or the **Logs → Real-time Logs** page can show you the issued ID token in real time. Decode at jwt.io to confirm `<NS>/groups` is present + populated.

## certctl-side configuration

```bash
curl -X POST https://<your-certctl-host>:8443/api/v1/auth/oidc/providers \
  -H "Authorization: Bearer ${CERTCTL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Auth0",
    "issuer_url": "https://<tenant>.auth0.com/",
    "client_id": "<paste-from-step-2>",
    "client_secret": "<paste-from-step-2>",
    "redirect_uri": "https://certctl.example.com:8443/auth/oidc/callback",
    "groups_claim_path": "https://certctl.example.com/auth/groups",
    "groups_claim_format": "string-array",
    "fetch_userinfo": false,
    "scopes": ["openid", "profile", "email"],
    "iat_window_seconds": 300,
    "jwks_cache_ttl_seconds": 3600
  }'
```

Critical:

- `issuer_url` includes the **trailing slash** for Auth0 (`https://<tenant>.auth0.com/`). Auth0's `iss` claim emits with the trailing slash; mismatching trips `ErrIssuerMismatch`.
- `groups_claim_path` is the **full namespaced URL**, not the bare `groups` key. The certctl resolver treats this as a single literal lookup key against the ID token claims map (no path-walking through `/`).

Add the group→role mappings: `certctl-engineers` → `r-operator`, etc. The mapping table maps the group VALUES (the strings inside the claim's array), not the claim path.

## Verification

End-to-end login + audit + Sessions checks are identical to Keycloak. The audit row's `details.subject` will be Auth0's user_id (e.g. `auth0|abc123…` for database users, `google-oauth2|...` for federated), stable across email changes.

## Troubleshooting

**`ErrGroupsUnmapped` even though I see groups in the ID token at jwt.io.**

Check `groups_claim_path` exactly matches the namespaced key in the token. A common mistake: setting `groups_claim_path` to `groups` (the bare key) when the actual claim key is `https://certctl.example.com/auth/groups` (the namespaced version). The resolver's URL-shape detection is what makes the namespaced path work; if the claim path doesn't start with `http://` or `https://`, the resolver tries to walk it as a dot-separated path and fails.

**The `<NS>/groups` claim is missing from the ID token.**

- Action not bound to the Login flow: revisit step 5's "Apply" step.
- Action returns early because `event.user.app_metadata.groups` is undefined: confirm the user has the metadata set.
- Trying to set the claim under a non-namespaced key (e.g. `api.idToken.setCustomClaim("groups", groups)`): Auth0 silently drops it. Always use the namespace prefix.

**Auth0 returns "Service not found" or "Invalid audience".**

This usually means the certctl client wasn't authorized to access the userinfo endpoint or the application's `audience` setting conflicts with the OIDC discovery doc. The certctl service uses the Application's `client_id` as the `audience` claim — confirm Auth0 is emitting tokens with `aud = <client_id>` (decode at jwt.io).

**Login redirects loop between Auth0 and certctl.**

Most often a callback-URL mismatch — Auth0's "Allowed Callback URLs" must contain the EXACT certctl callback URL including port + scheme. Wildcards aren't allowed in production.

**`email_verified` is `false` and certctl rejects the user.**

certctl doesn't currently gate on `email_verified` — the User row stores email regardless. If your operator policy requires verified-only, add an Action that throws on `event.user.email_verified === false`:

```javascript
if (!event.user.email_verified) {
  api.access.deny("email-not-verified");
}
```

## Validation checklist

Same as [keycloak.md](keycloak.md#validation-checklist) with Auth0-specific values, plus:

- [ ] The `<NS>/groups` claim is present in the ID token (verify via jwt.io decode).
- [ ] Removing a user's group from `app_metadata.groups` causes the next login to land on "no roles assigned".
- [ ] The Auth0 dashboard's **Logs → Real-time Logs** shows the certctl callback completing with HTTP 302 to the dashboard.

Sign-off: _______________ (operator) on _______________ (date).
