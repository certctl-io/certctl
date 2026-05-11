# OIDC / SSO runbooks — per-IdP setup guides

> Last reviewed: 2026-05-10

This is the index for the per-IdP setup runbooks that ship with Auth Bundle 2 (OIDC + sessions). Pick the runbook that matches your identity provider; each one walks you through the IdP-side configuration, the certctl-side configuration, end-to-end verification, and the most common troubleshooting paths.

For the threat model behind certctl's OIDC implementation, see [`auth-threat-model.md`](../auth-threat-model.md). For the RBAC primitive that group→role mappings target, see [`rbac.md`](../rbac.md). For the underlying protocol details (PKCE, state, nonce, JWKS rotation, fail-closed semantics), see the OIDC service docstring at [`internal/auth/oidc/service.go`](../../../internal/auth/oidc/service.go).

## Choose your runbook

| IdP | Tier | Group claim shape | Quirks | Runbook |
|---|---|---|---|---|
| Keycloak | Free / open-source | `string-array` against `groups` | None — canonical reference | [keycloak.md](keycloak.md) |
| Authentik | Free / open-source | `string-array` against `groups` | Property-mapping driven; explicit scope claim | [authentik.md](authentik.md) |
| Okta | Commercial (free dev tier) | `string-array` against `groups` | Group-filter regex on the claim definition | [okta.md](okta.md) |
| Auth0 | Commercial (free dev tier) | `string-array` against namespaced URL | Custom claims must use a namespaced key (e.g. `https://your-namespace/groups`) and are emitted via an Action | [auth0.md](auth0.md) |
| Azure AD / Entra ID | Commercial | `string-array` of GROUP OBJECT IDs (GUIDs), not names | Mappings must target object IDs, not human-readable names | [azure-ad.md](azure-ad.md) |
| Google Workspace | Commercial | NO native group claim | Direct OIDC against Google Workspace cannot emit groups; broker through Keycloak (or Authentik) instead | [google-workspace.md](google-workspace.md) |

## Common shape

Every runbook follows the same five-section layout so you can scan across IdPs:

1. **Prerequisites** — what you need on the IdP side (admin access, plan tier) and on the certctl side (an admin actor holding `auth.oidc.create` + `auth.oidc.edit`, the GUI / CLI / MCP surface available, the `CERTCTL_CONFIG_ENCRYPTION_KEY` env var set in production so client_secret encrypts at rest).
2. **IdP-side configuration** — clickable steps in the IdP admin console, with the exact field names and values certctl needs.
3. **certctl-side configuration** — `POST /api/v1/auth/oidc/providers` payloads, plus the GUI and MCP equivalents. The wire shape is the same across every IdP; only the values differ.
4. **Verification** — what a successful end-to-end login looks like in the audit log and the GUI Sessions page, plus the JWKS-rotation drill.
5. **Troubleshooting** — the failure modes you're statistically most likely to hit, mapped to the certctl service-layer sentinel error you'll see in the audit row.

## Cross-IdP recurring concepts

These show up in every runbook; understand them once and skim the rest.

**Redirect URI.** Every IdP needs the certctl-side callback URL registered as an allowed redirect URI. The format is `https://<your-certctl-host>/auth/oidc/callback` — port 8443 by default for the HTTPS-only control plane (Decision: post-v2.2 the platform is HTTPS-only, no plaintext port). For local-dev fixtures, `http://localhost:8443/auth/oidc/callback` is acceptable; production deployments MUST use HTTPS, and the OIDCProvider domain validator rejects HTTP issuer URLs in non-test paths.

**Client secret rotation.** Every IdP issues a `client_secret` for the confidential client (certctl is always a confidential client; public clients aren't supported because we have a server-side place to keep the secret). Rotating at the IdP requires the operator to PUT the new secret into certctl via the GUI's "Edit provider" dialog or `certctl_auth_update_oidc_provider` MCP tool — leaving `client_secret` empty in the update payload preserves the existing ciphertext, providing a value rotates.

**JWKS cache TTL.** The certctl service caches the IdP's JWKS document for `jwks_cache_ttl_seconds` (default 3600). When the IdP rotates a signing key, in-flight logins that try to validate a new-key-signed token against the stale cache fail with `ErrJWKSUnreachable` until the next refresh. Operators have two options: wait out the TTL, or click "Refresh discovery cache" in the GUI's OIDC Provider Detail page (`POST /api/v1/auth/oidc/providers/{id}/refresh`) to force-evict the cache. The Phase 10 Keycloak integration test exercises this drill end to end.

**Group→role mappings are fail-closed.** The certctl service refuses to mint a session for a user whose IdP-supplied groups don't match ANY configured mapping (`ErrGroupsUnmapped` → HTTP 401 to the user with a "no roles assigned" page). This is intentional — empty mapping ≠ "let everyone in," it means "this provider is not yet configured for any role." Operators add at least one mapping (typically `<engineers-group>` → `r-operator`) BEFORE rolling out OIDC to users.

**Nonce + state + PKCE-S256 are non-negotiable.** Every login flow round-trips a nonce (replay defense), a state (CSRF defense), and a PKCE-S256 verifier (RFC 9700 §2.1.1 mandate). `plain` PKCE is rejected at the service-layer sentinel level. None of this is configurable; if your IdP doesn't support PKCE-S256, you cannot use it with certctl.

**IdP downgrade-attack defense.** At provider creation AND on every JWKS refresh, certctl intersects the IdP's advertised `id_token_signing_alg_values_supported` with the certctl allow-list (RS256, RS512, ES256, ES384, EdDSA by default). If the IdP advertises HS256/HS384/HS512 or `none`, provider creation is rejected — even before any token is signed under the weak alg. This catches the case where a future compromised or misconfigured IdP tries to rotate to an alg-confusion-prone setup.

## When you finish a runbook

Each per-IdP runbook ends with a **validation checklist** the operator runs against a real production-tier deployment. Run through the matrix end-to-end against your IdP and mark your sign-off in the runbook's footer — that gives the next operator (or the next you) a dated record of what's been verified to work.

## Related docs

- [RBAC operator reference](../rbac.md) — roles, permissions, scope-down + bootstrap flow.
- [Auth threat model](../auth-threat-model.md) — API-key + OIDC + session compromise scenarios; v3 WebAuthn pairing.
- [Security posture](../security.md) — overall auth surface incl. this Bundle 2 OIDC layer.
- [API keys → RBAC migration](../../migration/api-keys-to-rbac.md) — the Bundle 1 upgrade flow your operator likely already ran.
