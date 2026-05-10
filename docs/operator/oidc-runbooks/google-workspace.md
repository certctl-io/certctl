# Google Workspace OIDC runbook (broker via Keycloak)

> Last reviewed: 2026-05-10

This runbook wires certctl's OIDC SSO surface against [Google Workspace](https://workspace.google.com/) (formerly G Suite). Google's OIDC implementation has a well-known limitation that makes it unsuitable for direct integration with certctl: **the ID token does not emit a groups claim**, so there is no way for certctl's `ErrGroupsUnmapped` fail-closed contract to resolve a user's role assignment.

The recommended pattern is to **broker Google Workspace through Keycloak (or Authentik)** as a federated identity provider. The end-user still signs in with their Google account, but certctl talks to Keycloak — which DOES emit groups — instead of talking to Google directly.

For the canonical reference + mental model, read [keycloak.md](keycloak.md) first; this runbook builds on top of it.

## The Google Workspace quirk in detail

**What Google emits in an ID token:** `iss`, `aud`, `sub`, `azp`, `exp`, `iat`, `email`, `email_verified`, `name`, `picture`, `given_name`, `family_name`, `locale`, `hd` (hosted domain). That's it.

**What it does NOT emit:** `groups`, `roles`, `permissions`, or any indicator of the user's Google Workspace organizational unit / group membership.

There is a **Cloud Identity Groups API** at `https://cloudidentity.googleapis.com/v1/groups/-/memberships:searchTransitiveGroups` that lets a privileged service account look up a user's groups, but:

1. It requires a service account with domain-wide delegation, which is a major security surface to grant to certctl.
2. It's a separate REST call after the OIDC flow, not a claim — certctl's group-claim resolver is path-shape, not API-shape.
3. The latency budget of an extra API call per login is non-trivial in steady state.

For these reasons, the broker pattern is strongly preferred. If you absolutely cannot deploy a broker, see "Direct integration without groups" at the bottom of this runbook for a degraded mode where every Google-authenticated user gets a single fixed role.

## Architecture: broker pattern

```
end user → Google Workspace login → Keycloak (federated IdP) → certctl
                                       ↑
                                       │
                          adds groups claim from Keycloak's group store
                          (NOT from Google)
```

In this topology:

- The end user's authentication credentials live at Google.
- The user's group / role assignments live at Keycloak (manually or via SCIM provisioning from Google).
- certctl talks ONLY to Keycloak. From certctl's perspective this is identical to the [keycloak.md](keycloak.md) runbook.

## Prerequisites

- A running Keycloak instance with a realm dedicated to certctl. Read [keycloak.md](keycloak.md) and complete that runbook FIRST against a local-only test user. Verify end-to-end OIDC works against Keycloak before adding Google as a federated provider.
- A Google Workspace tenant where you have Super Admin access OR can ask your Workspace admin to create OAuth credentials.
- A Google Cloud project (free; same console as Workspace).

## IdP-side configuration

### Step 1: create a Google OAuth client

In the Google Cloud Console (`https://console.cloud.google.com/`):

**APIs & Services → OAuth consent screen → Configure**:

- User Type: **Internal** (restricts to your Workspace domain) OR **External** (any Google account; usually NOT what you want for an internal cert-management tool).
- App name: `certctl SSO via Keycloak`.
- User support email: your team's address.
- Authorized domains: add the domain Keycloak runs on.
- Save.

**APIs & Services → Credentials → Create Credentials → OAuth client ID**:

- Application type: **Web application**.
- Name: `certctl-via-keycloak`.
- Authorized redirect URIs: `https://<keycloak-host>/realms/<realm-name>/broker/google/endpoint` — this is Keycloak's default federated-IdP callback URL. Get the exact URL from Keycloak in step 2 below.
- Click **Create**.

Copy the **Client ID** and **Client secret**.

### Step 2: add Google as a federated identity provider in Keycloak

In the Keycloak admin console (`https://<keycloak-host>/admin/`):

**Realm → Identity providers → Add provider → Google**:

- Alias: `google` (becomes part of the broker URL).
- Display name: `Google Workspace`.
- Client ID: paste from step 1.
- Client secret: paste from step 1.
- Default scopes: `openid profile email`.
- Hosted Domain: your Workspace domain (e.g. `example.com`); restricts to your tenant.
- Sync mode: **Force** (rewrites the user's first/last name/email from Google on every login; the alternative `Import` only writes on first login).
- Trust email: **on** (Google verifies emails; certctl-Keycloak chain inherits the trust).
- Click **Save**.

The **Redirect URI** field at the top of the saved provider's page shows the exact URL you should have entered in Google's console at step 1. Re-verify match.

### Step 3: configure group assignment in Keycloak

This is the load-bearing step — we're explicitly NOT trusting Google for groups, so Keycloak has to provide them.

**Option A: Manual group assignment in Keycloak.**

Federated users from Google appear in **Users** in Keycloak after their first login. You assign them to `certctl-engineers` / `certctl-viewers` / etc. groups in Keycloak's UI manually. Pro: simple. Con: doesn't scale; new hires can't log in until an operator adds them to a group.

**Option B: Default groups via "Default Groups" realm config.**

**Realm settings → User registration → Default Groups → Add**: pick the lowest-privilege group (e.g. `certctl-viewers`). Every new federated user lands here automatically; operators promote individual users to higher groups as needed.

**Option C: Mapper that derives groups from Google claims.**

If your Google Workspace has organizational units that align with your role split, you can add a Keycloak **Identity Provider Mapper** that maps `hd` (hosted domain) or a custom Google directory custom-schema field to a Keycloak group. This is moderately fragile and Workspace-version-dependent; recommend B for most operators.

**Option D: SCIM provisioning from Google to Keycloak.**

Google Workspace can SCIM-push group memberships to Keycloak via the SCIM-for-Google-Cloud-Identity feature. Heavyweight; recommend only if you already have SCIM infrastructure.

This runbook uses **Option B** (default group) for clarity.

### Step 4: verify the broker flow at Keycloak alone

Before bringing certctl into the picture:

1. Log out of Keycloak's admin console.
2. Hit `https://<keycloak-host>/realms/<realm-name>/account` in an incognito window.
3. Click "Sign in" — Keycloak's login page should now show **Sign in with Google Workspace** as a button below the local login form.
4. Click it; authenticate via Google; you should land on Keycloak's account page.
5. Back in the admin console, the user appears under **Users**. Confirm they're in the default group (Option B).

Only proceed to step 5 when Keycloak alone works end to end.

### Step 5: configure certctl against Keycloak (NOT against Google)

Follow the [keycloak.md](keycloak.md) runbook. Use the realm + client + groups configuration you set up there. The `OIDCProvider.issuer_url` is `https://<keycloak-host>/realms/<realm-name>` — Keycloak's URL, not Google's.

When the user clicks "Sign in with Keycloak" on certctl's login page, the browser flow is:

1. certctl → Keycloak authorize endpoint.
2. Keycloak's login page shows **Sign in with Google Workspace** + the local login form. User clicks Google.
3. Keycloak → Google authorize endpoint. User authenticates at Google.
4. Google → Keycloak callback (`/broker/google/endpoint`). Keycloak resolves the user, assigns the default group.
5. Keycloak → certctl callback. certctl sees a normal Keycloak ID token with the `groups` claim populated by Keycloak.
6. certctl mints the session.

End-to-end the user clicks twice (Keycloak's "Sign in with Google" button + Google's consent / login). Subsequent logins skip the consent screen if Google's session is fresh.

## Verification

End-to-end login + audit + Sessions checks are identical to Keycloak. The key Google-Workspace-specific check:

- The `users.oidc_subject` column in certctl's database should contain the Keycloak-side stable subject (a UUID), NOT the Google subject. Decode the certctl-side ID token and confirm `iss` is Keycloak's URL, `sub` is the Keycloak UUID. Don't confuse the certctl ID token with Google's ID token (which lives one hop upstream and certctl never sees directly).

## Direct integration without groups (NOT RECOMMENDED)

If broker deployment is impossible:

1. Configure certctl with `issuer_url = https://accounts.google.com`, `client_id` + `client_secret` from your Google OAuth client (with redirect URI pointed at certctl directly).
2. Add a SINGLE group→role mapping where `group_name` is the empty string. **Wait — certctl rejects empty group names.** This is the structural reason this mode doesn't work: the fail-closed contract requires a real group claim to match.

The actual workaround is to manually add EVERY operator's email to a per-email mapping, OR to add a custom claim emitter at a thin proxy in front of Google. Both are hacks; the broker pattern is strictly better. We document the constraint here so future operators don't burn cycles trying to make it work.

## Troubleshooting

**Federated Google login completes at Keycloak but the user lands on "no roles assigned" at certctl.**

The user authenticated through Google → Keycloak successfully but Keycloak didn't assign them a group (Option A wasn't completed for that user, or Option B's default group isn't mapped on the certctl side). Check:

- Keycloak → Users → <user> → Groups: is the user in any `certctl-*` group?
- certctl → Auth → OIDC Providers → Keycloak → Group → role mappings: is that group mapped?

**Google login fails with "redirect_uri_mismatch".**

The Google OAuth client's authorized redirect URI doesn't match Keycloak's broker callback URL exactly. Re-fetch the URL from Keycloak (Identity Providers → Google → Redirect URI field) and paste it verbatim into Google's console.

**Google auto-closes the consent prompt and returns "access_denied".**

Workspace admin policies may block third-party app access. Either the Google OAuth client wasn't approved by the Workspace admin (Google Workspace Admin Console → Security → API controls → Trusted apps), or the OAuth consent screen is configured for "External" but the user is from a different Workspace. Switch to "Internal" if everyone signing in is in the same Workspace.

**Keycloak log shows "Federated identity returned no email claim".**

You requested OAuth scopes other than `openid profile email`. Re-add `email` to the Default Scopes on the Keycloak Identity Provider config.

**Sign-out from certctl doesn't sign the user out of Google.**

Expected. certctl revokes its own session; Google's session continues independently. If the user needs to fully log out, they sign out at https://accounts.google.com/Logout. The certctl + Keycloak chain is the standard "single sign-on, separate sign-outs" model.

## Validation checklist

Same as [keycloak.md](keycloak.md#validation-checklist), with these additions:

- [ ] Google → Keycloak federation works without certctl in the loop (step 4 above passes).
- [ ] A first-time Google sign-in lands the user in the Keycloak default group (or whatever Option you picked).
- [ ] The certctl audit row's `details.subject` is the Keycloak UUID, NOT Google's `sub` (which would be a Google account ID).
- [ ] Removing a user from Google Workspace causes their NEXT certctl session-validate to fail (after their existing session expires) — verify with a deactivated test user.

Sign-off: _______________ (operator) on _______________ (date).
