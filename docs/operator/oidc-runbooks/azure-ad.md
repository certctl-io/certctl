# Microsoft Entra ID (Azure AD) OIDC runbook

> Last reviewed: 2026-05-10

This runbook wires certctl's OIDC SSO surface against [Microsoft Entra ID](https://learn.microsoft.com/entra/), formerly Azure AD. Entra ID is Microsoft's commercial cloud IdP; it's the default IdP for any organization on Microsoft 365 / Azure.

For the canonical reference + mental model, read [keycloak.md](keycloak.md) first; this runbook only documents the Entra-ID-specific deltas.

## The big Entra ID quirk: groups claim emits OBJECT IDs, not names

Entra ID's `groups` claim emits a JSON array of **group object IDs (GUIDs)**, not human-readable names. A user in `Engineering Group` and `Cert Operators` will see something like:

```json
{
  "groups": [
    "8b9b1faa-4e83-471e-8b00-7d99c3e2a5f1",
    "f00cf1e2-2db1-4cdf-a1ba-1234567890ab"
  ]
}
```

**You must configure your certctl group→role mappings against these GUIDs**, not against `Engineering Group` or `Cert Operators`. There are workarounds (cloud-only group display names + the optional claims path; see the alternative below) but the GUID-based approach is the only one that works reliably across all Entra ID configurations.

This is by design at Microsoft — group names are mutable and not globally unique within a tenant; object IDs are immutable and globally unique. Operators on Microsoft 365 / Azure deployments are accustomed to managing access by GUID.

## Prerequisites

**On the Entra ID side:**

- A Microsoft 365 tenant or standalone Azure AD tenant. Free Azure AD tier is sufficient; paid tiers (P1/P2) unlock conditional access + SCIM provisioning + risk-based auth, none of which are required for the basic OIDC integration.
- Application Administrator or Global Administrator role.
- Network reachability from certctl-server to `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration`.

**On the certctl side:** same as Keycloak.

## IdP-side configuration

### 1. Register the application

In the [Entra ID admin center](https://entra.microsoft.com/):

**Applications → App registrations → New registration**:

- Name: `certctl`.
- Supported account types: **Accounts in this organizational directory only** (single-tenant; matches the typical operator use case).
- Redirect URI: **Web** + `https://<your-certctl-host>:8443/auth/oidc/callback`.
- Click **Register**.

On the saved app's **Overview** page, copy:

- **Application (client) ID** → certctl's `client_id`.
- **Directory (tenant) ID** → goes into the issuer URL.

### 2. Create a client secret

**App → Certificates & secrets → Client secrets → New client secret**:

- Description: `certctl-server`.
- Expires: 6 months / 12 months / 24 months — your choice. Set a calendar reminder; Entra ID does NOT auto-rotate secrets.
- Click **Add**.

Copy the **Value** column immediately — it's shown ONCE on creation. The certctl provider's `client_secret` field gets this value.

(Production hardening: prefer **Certificates** over secrets for client authentication; certctl currently supports `client_secret_post` only, but a follow-on bundle can add `private_key_jwt` for cert-based client auth. Track this if you have a hard requirement against shared secrets.)

### 3. Add the `groups` claim to the token

**App → Token configuration → Add groups claim**:

- Pick **Security groups** (covers most operators) OR **Groups assigned to the application** (more granular but requires Premium).
- Token type: **ID token** + **Access token** (both, so userinfo fallback works).
- Customize emit format for ID/access: leave as **Group ID** (default; this is the GUID-based path the runbook is structured around).
- Click **Save**.

If you instead want display names in the claim (only works for cloud-only groups; on-prem-synced groups continue to emit GUIDs regardless):

- Customize emit format → **Cloud-only group display names**.
- BUT — note this works only for groups created in Entra ID itself, not groups synced from on-prem AD. Hybrid environments will have inconsistent claims.

### 4. Add the optional `email` and `profile` claims

By default Entra ID's ID token does NOT include `email` — Microsoft considers email part of the "OIDC profile" but only emits it under specific conditions. To force emission:

**App → Token configuration → Add optional claim → ID token → email**.

You may also want `family_name`, `given_name`, `preferred_username` for richer User records on the certctl side.

### 5. Grant the API permissions

**App → API permissions**:

- Microsoft Graph → Delegated permissions → ensure these are granted (most are default):
  - `openid`
  - `profile`
  - `email`
  - `offline_access` (optional; for refresh tokens — certctl doesn't use them currently).
- Click **Grant admin consent** if your tenant requires it.

### 6. (Optional) Restrict who can sign in

By default any user in your tenant can attempt to sign in to the app. To restrict to specific users / groups:

**Enterprise applications → certctl → Properties → Assignment required: Yes**.
Then **Users and groups → Add user/group** and pick the `cert-engineers` / `cert-viewers` Entra ID groups.

## certctl-side configuration

```bash
curl -X POST https://<your-certctl-host>:8443/api/v1/auth/oidc/providers \
  -H "Authorization: Bearer ${CERTCTL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Entra ID",
    "issuer_url": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "client_id": "<application-id>",
    "client_secret": "<client-secret-value>",
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

- `issuer_url` MUST include `/v2.0` at the end for the v2.0 endpoint. The v1.0 endpoint emits tokens with a different `iss` shape and is NOT supported by certctl. The discovery doc at `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration` confirms the right path.
- `<tenant-id>` is the Directory (tenant) ID GUID from step 1.

### Add the group→role mappings (GUID-keyed)

Get the GUIDs of your engineering / viewer groups:

**Entra ID → Groups → All groups → <group> → Overview → Object ID**.

Then in certctl:

```bash
# Engineering group → r-operator
curl -X POST https://<your-certctl-host>:8443/api/v1/auth/oidc/group-mappings \
  -H "Authorization: Bearer ${CERTCTL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_id": "<provider-id>",
    "group_name": "8b9b1faa-4e83-471e-8b00-7d99c3e2a5f1",
    "role_id": "r-operator"
  }'
```

Repeat for every group you want to map. **Document the GUID-to-name mapping in your operator runbook** — without it, the next operator looking at certctl's mappings page sees a wall of GUIDs with no way to know which is which. Consider naming the mapping descriptively if your group-mapping schema supports it (Bundle 2 doesn't yet — group-mapping descriptions are a parking-lot item for a follow-on bundle).

## Verification

End-to-end login + audit + Sessions checks are identical to Keycloak.

**Entra-ID-specific:** the audit row's `details.subject` will be Microsoft's `oid` claim (a GUID, the user's object ID), stable across UPN / email changes. The certctl `users` table's `oidc_subject` column holds this GUID.

**JWKS-rotation:** Microsoft auto-rotates signing keys on a documented schedule (every ~6 weeks). The discovery doc + JWKS endpoint always serve the union of active + recently-active keys, so in-flight logins continue to validate. No manual operator action needed in steady state. If you suspect a stuck cache after a Microsoft-side rotation, click "Refresh discovery cache" in the certctl GUI to evict.

## Troubleshooting

**Login completes; ID token contains a `hasgroups: true` claim instead of `groups`.**

Entra ID emits this when a user is in too many groups (>200 by default for ID tokens, >150 for access tokens) — Microsoft truncates the claim and tells the consumer to use Microsoft Graph to look up the full list. certctl does NOT currently support the Graph fallback path (it's a follow-on bundle item).

Workarounds:

- Reduce the user's group membership to <200 (rarely practical in large tenants).
- Restrict the `groups` claim to "Groups assigned to the application" (Token configuration step 3 above) instead of "Security groups". The "assigned" set is bounded by the app's user assignments and stays under the limit.
- Use Entra ID's optional `wids` (well-known IDs) claim if you only care about admin/non-admin distinction; certctl can be configured against `wids` by setting `groups_claim_path` accordingly.

**`groups` claim missing entirely.**

Step 3 wasn't completed — Entra ID does NOT emit `groups` by default. Add the claim via Token configuration before users will see it.

**`ErrIssuerMismatch` even though the `tid` in the token matches.**

The v2.0 endpoint emits `iss = https://login.microsoftonline.com/<tenant-id>/v2.0` (no trailing slash). The v1.0 endpoint emits `iss = https://sts.windows.net/<tenant-id>/`. Confirm certctl's `issuer_url` matches v2.0 exactly — no trailing slash, includes `/v2.0`.

**On-prem-synced groups emit GUIDs even when "Cloud-only display names" is selected.**

Expected behavior — Microsoft only emits display names for groups created in Entra ID itself (cloud-only). On-prem-synced groups always emit object IDs. The hybrid case is unfixable from the IdP side; either map against GUIDs (recommended) or migrate the relevant groups to cloud-only.

**The `email` claim is empty even though the user has a primary email.**

Entra ID's `email` claim only populates when:
1. The user has a "Primary email" set on their Entra ID profile (often blank for B2B guest users).
2. The optional claim was added in step 4.

For B2B guests, the `preferred_username` claim usually carries the email-shape login. You can configure certctl to use `preferred_username` as the user's display name fallback, but the `User.Email` column will remain blank — that's expected for guests.

**Conditional Access policies blocking the login.**

If your tenant has Conditional Access requiring MFA for new applications, certctl will see the user redirected through the MFA challenge. This works transparently — the certctl service doesn't care that MFA was performed; it only validates the resulting ID token. If MFA is failing for the user, debug at the Entra ID side (Sign-in logs).

## Validation checklist

Same as [keycloak.md](keycloak.md#validation-checklist), with these additions:

- [ ] The ID token's `groups` claim is a string-array of GUIDs (decode at jwt.io).
- [ ] Each certctl group-mapping uses the GUID, not a human-readable name.
- [ ] A user with >200 groups successfully logs in (or the operator has documented the limitation + workaround in their internal runbook).
- [ ] The Entra ID **Sign-in logs** view shows the certctl login event with status "Success".

Sign-off: _______________ (operator) on _______________ (date).
