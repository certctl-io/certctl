# Authentication & authorization threat model

> Last reviewed: 2026-05-10

This document describes the attack surface around authentication and
authorization in certctl after Bundle 1 (the RBAC primitive) AND Bundle
2 (OIDC + sessions + back-channel logout + break-glass) land. It
complements [`rbac.md`](rbac.md) and the per-IdP runbooks at
[`oidc-runbooks/index.md`](oidc-runbooks/index.md) - those docs
explain how to USE the controls; this one explains what those controls
defend against and which threats they explicitly do NOT close.

The post-Bundle-2 attack surface is meaningfully wider than Bundle 1's:
Bundle 1 closed the API-key axis (one credential type, one validation
path); Bundle 2 adds OIDC-federated humans, session cookies with
length-prefixed HMAC + CSRF, back-channel logout, OIDC first-admin
bootstrap, and a default-OFF break-glass admin path. Each surface
brings its own threat catalogue + mitigations, documented below
alongside the Bundle 1 ones.

## Threat actors

1. **External attacker with no credential** - probing the public
   HTTP surface. The default trust boundary for everything except
   the protocol-level endpoints (ACME / SCEP / EST / OCSP / CRL,
   which authenticate via embedded credentials per their own RFCs).
2. **Authenticated caller with the wrong role** - has a valid API
   key but the role doesn't grant the requested operation. The
   primary RBAC threat model.
3. **Compromised API key** - attacker holds a valid Bearer token
   that an honest operator originally provisioned. The key may
   carry any role.
4. **Insider operator** - legitimate access; potentially trying
   to escalate privilege or bypass the approval workflow.
5. **Compromised audit reviewer (auditor role)** - read-only
   access to audit events but otherwise untrusted.

The following actors are NEW with Bundle 2:

6. **OIDC-federated end user** - authenticates via the
   organization's IdP (Keycloak / Okta / Auth0 / Entra ID / Authentik
   / Workspace-via-broker). The user's credential lives at the IdP;
   certctl never sees it. Attack vectors center on token forgery,
   session hijacking, and group-claim manipulation.
7. **Stolen session cookie holder** - attacker holds a valid
   `certctl_session` cookie value (typically via XSS, network MITM,
   or a developer who pasted a token into a chat / pastebin). Holds
   the attacker-side ability to make requests as the legitimate user
   until the cookie expires (idle 1h / absolute 8h defaults) or is
   revoked.
8. **Compromised IdP** - the upstream IdP itself is rogue: signs
   tokens for arbitrary users, mints groups arbitrarily, etc. Largely
   out of certctl's control; mitigations are bounded to "the audit
   trail records the source provider on every login, blast radius is
   bounded by group_role_mapping configured for that provider."
9. **Break-glass-password holder (Phase 7.5 path)** - operator with
   the local Argon2id password set up for SSO outages. Bypasses the
   OIDC + group-claim layer entirely. The default-OFF posture is the
   load-bearing mitigation; once enabled the password is the entire
   attack surface.

## Defenses Bundle 1 ships

### API-key authentication

- API keys live in `CERTCTL_API_KEYS_NAMED` (env-var) or
  `api_keys` (DB row, written by Bundle 1 Phase 6 bootstrap and
  the future role-management API). Keys hash via SHA-256; the
  middleware compares hashes via `crypto/subtle.ConstantTimeCompare`
  to defeat timing attacks.
- The auth middleware populates `ActorIDKey` / `ActorTypeKey` /
  `TenantIDKey` on every authenticated request context. Audit rows
  attribute every action to the named-key actor instead of the
  pre-Bundle-1 hardcoded `api-key-user` placeholder.
- Demo mode (`CERTCTL_AUTH_TYPE=none`) injects the synthetic
  `actor-demo-anon` actor with admin grants. Production deploys
  MUST NOT use demo mode.

### Authorization (RBAC)

- Every gated handler routes through `auth.RequirePermission` (or
  the router-level `rbacGate` wrap from Phase 3.5). The middleware
  resolves the actor's effective permissions via the
  `Authorizer.CheckPermission` service-layer call; on miss, the
  handler returns HTTP 403 BEFORE the body runs. This is the
  load-bearing gate.
- The five admin-only fine-grained perms (`cert.bulk_revoke` /
  `crl.admin` / `scep.admin` / `est.admin` /
  `ca.hierarchy.manage`) are seeded into `r-admin` only. To
  delegate one, an operator creates a custom role with the
  specific perm and grants it to the right actor.
- The auditor split: `r-auditor` holds only `audit.read` +
  `audit.export`. Pinned by the
  `internal/domain/auth/auditor_test.go` invariants. A regulator
  with the auditor key cannot read certificates, profiles,
  issuers, or any mutating surface.
- The privilege-escalation guard: granting or revoking a role
  requires the caller to hold `auth.role.assign` (enforced in
  `internal/service/auth/actor_role_service.go`). A non-admin
  cannot self-grant admin.
- The reserved-actor guard: mutations against `actor-demo-anon`
  return HTTP 409 from the service layer
  (`ErrAuthReservedActor`). The synthetic actor is operator-
  inaccessible.

### Day-0 bootstrap

- `CERTCTL_BOOTSTRAP_TOKEN` is constant-time-compared by
  `EnvTokenStrategy.Validate`. The strategy is one-shot via
  `sync.Mutex`-guarded `consumed` bool; the second call returns
  `ErrDisabled` (HTTP 410), not `ErrInvalidToken` (HTTP 401), so
  a probing attacker cannot distinguish "wrong token, retry"
  from "already consumed".
- The strategy also re-probes admin existence on every Validate.
  If an admin actor lands during the gap between Available and
  Validate, the second caller still gets HTTP 410.
- The minted plaintext key is written to the response body once.
  It is NEVER logged. The token-leak hygiene test in
  `internal/api/handler/auth_bootstrap_test.go` redirects
  `slog.Default` to a buffer and grep-asserts that neither the
  bootstrap token nor the minted key appears in any log line,
  audit row, or HTTP header.
- The minted key is hashed before persistence. Lost key →
  rotate via the regular RBAC API; the plaintext is not
  recoverable from the DB.

### Approval workflow + Phase 9 loophole closure

- `CertificateProfile.RequiresApproval=true` gates two surfaces:
  (a) issuance + renewal of every cert pointing at the profile,
  (b) edits to the profile itself (Bundle 1 Phase 9). The Phase 9
  closure prevents the flip-flop bypass where an admin disables
  approval, mutates, re-enables.
- Same-actor self-approve is rejected at the service layer with
  `ErrApproveBySameActor` for both `cert_issuance` and
  `profile_edit` kinds. Two-person integrity is the load-bearing
  invariant; pinned by tests in
  `internal/service/approval_test.go`.

### Audit trail

- Every mutating operation flows through `AuditService.RecordEvent`
  or `RecordEventWithCategory`. Bundle 1 Phase 8 added the
  `event_category` column with a `CHECK` constraint enforcing
  the closed enum (`cert_lifecycle` / `auth` / `config`); the
  category surfaces the auth-mutation slice to the auditor view.
- The WORM trigger from migration 000018
  (`audit_events_worm_trigger`) blocks `UPDATE` and `DELETE` at
  the database layer. Even an admin DB user cannot tamper with
  audit history without dropping the trigger.
- Bundle-6's redactor (`internal/service/audit_redact.go`)
  scrubs credentials + PII from the `details` JSONB before
  persistence; an `_redacted_keys` field surfaces what the
  redactor took out for compliance review.

### Protocol-endpoint allowlist

ACME / SCEP / EST / OCSP / CRL endpoints authenticate via
embedded credentials defined by their own RFCs (JWS-signed,
challenge passwords, mTLS, public-by-RFC). The auth middleware
explicitly bypasses these via `IsProtocolEndpoint`. The Phase 12
`internal/api/router/phase12_protocol_allowlist_test.go` pins
the invariant at three layers (middleware bypass, allowlist
constant, router-level no-rbacGate-wraps-protocol-paths).

## Defenses Bundle 2 ships

### OIDC token validation (Phase 3)

- **Algorithm allow-list, never `none`, never HMAC.** The service-
  layer pinning lives in `internal/auth/oidc/service.go::disallowedAlgs`
  and the IdP-downgrade-attack defense in
  `Service.guardAdvertisedAlgs`. At provider creation AND on every
  `RefreshKeys`, the IdP's advertised
  `id_token_signing_alg_values_supported` is intersected with the
  allow-list (RS256 / RS512 / ES256 / ES384 / EdDSA). If the IdP
  advertises HS256/HS384/HS512 or `none` AT ALL, provider creation
  is rejected - the IdP has not yet signed a single token, but the
  service refuses to trust an IdP that COULD sign one with a weak
  alg. coreos/go-oidc additionally enforces the allow-list per-token
  at verify time as defense-in-depth against an upstream library
  regression.
- **Exact `iss` match.** ID-token `iss` claim must equal the
  configured `OIDCProvider.IssuerURL` byte-for-byte (sentinel
  `ErrIssuerMismatch`). A token from a different IdP - even one
  with the same `aud` - cannot ride a misconfigured provider row.
- **`aud` + `azp` checks.** Service-layer re-verification of the
  audience claim (must include `client_id`) plus the `azp` claim
  for multi-aud tokens (per OIDC core §3.1.3.7 step 5; sentinels
  `ErrAudienceMismatch`, `ErrAZPRequired`, `ErrAZPMismatch`). An
  attacker with a token issued for a different client cannot replay
  it against certctl.
- **`at_hash` REQUIRED when access_token is present.** OIDC core
  treats `at_hash` as a "MAY"; certctl tightens to "MUST"
  (`ErrATHashRequired`). A substituted access token cannot ride
  alongside a clean ID token through the verifier.
- **Single-use state + nonce.** Both 32-byte random server-generated
  values, persisted in the pre-login row keyed by the cookie. The
  pre-login row is consumed via `DELETE...RETURNING` on lookup
  (atomic single-use). `subtle.ConstantTimeCompare` on both. State
  replay returns `ErrPreLoginNotFound`; nonce mismatch returns
  `ErrNonceMismatch`.
- **PKCE-S256 mandatory.** RFC 9700 §2.1.1 requires PKCE on auth-
  code; certctl hard-codes S256 via `oauth2.GenerateVerifier` +
  `oauth2.S256ChallengeOption`. The `plain` method is not just
  unsupported - the `ErrPKCEPlainRejected` sentinel exists so a
  future regression that surfaces a plain path trips a test.
- **`iat` window.** Configurable per-provider (default 300s, capped
  at 600s by the domain validator). Defends against clock-skew
  attacks where an attacker submits a stale-but-valid token.
- **JWKS rotation handled transparently** by coreos/go-oidc's built-
  in cache, plus the operator-triggered `Service.RefreshKeys` for
  forced refresh (and the auto-refresh on JWKS-cache TTL expiry,
  default 3600s).
- **JWKS-fetch failure during a key rotation: fail closed.** The
  service maps go-oidc's network errors to `ErrJWKSUnreachable`
  (HTTP 503 to the in-flight login). Existing sessions are
  untouched. No exponential backoff, no auto-retry; the operator
  triages.
- **Encrypted `client_secret` at rest.** AES-256-GCM via
  `internal/crypto.EncryptIfKeySet` (the same v3-blob path issuer
  + target credentials use). The `client_secret_encrypted` column
  is `json:"-"` on the domain type so a misconfigured handler
  cannot wire-leak.

### Session minting + cookies (Phases 4 + 6)

- **Length-prefixed HMAC.** Cookie wire format is
  `v1.<session_id>.<signing_key_id>.<base64url-no-pad(HMAC-SHA256)>`.
  HMAC input is **length-prefixed** as `len(sid):sid:len(kid):kid`
  - NOT bare-concat. The bare-concat form admits a collision
  attack: `<a, bc>` and `<ab, c>` produce identical HMAC inputs,
  letting a forger swap one byte across the boundary. Pinned by
  `TestComputeHMAC_LengthPrefixDefeatsConcatCollision` +
  `TestService_Validate_ConcatenationCollisionDefeatedByLengthPrefix`.
  The `v1.` version prefix is reserved; unknown prefixes are
  rejected with no fallback.
- **Cookie hardening.** `HttpOnly=true` (no JS access; defends XSS
  cookie theft), `Secure=true` (HTTPS-only; defends network MITM
  given HTTPS-Everywhere v2.2 milestone), `SameSite=Lax` default
  (configurable to Strict via `CERTCTL_SESSION_SAMESITE`), `Path=/`,
  no domain attribute (host-only).
- **Idle + absolute timeouts.** 1h idle / 8h absolute defaults
  (configurable via `CERTCTL_SESSION_IDLE_TIMEOUT` /
  `_ABSOLUTE_TIMEOUT`). The session row tracks `last_seen_at`,
  `idle_expires_at`, `absolute_expires_at` independently; the
  scheduler's `sessionGCLoop` (default 1h) sweeps expired rows.
- **CSRF defense.** Plaintext CSRF token in the JS-readable
  `certctl_csrf` cookie (intentionally `HttpOnly=false` so the GUI
  reads it for the `X-CSRF-Token` header). SHA-256 hash on the
  session row. `CSRFMiddleware` on state-changing methods uses
  `subtle.ConstantTimeCompare` against the hash. API-key actors
  (no session row) are CSRF-exempt - pinned by the bundle-1-compat
  CI guard.
- **Optional defense-in-depth IP / UA bind** (default OFF;
  `CERTCTL_SESSION_BIND_IP` / `_BIND_USER_AGENT`). Mismatch
  returns `ErrSessionIPMismatch` / `ErrSessionUAMismatch`. Use
  with care - mobile clients on changing networks fail closed.
- **Signing-key rotation primitive.** `RotateSigningKey` mints a
  new HMAC key; the old key stays valid for the configured
  retention window (default 24h via
  `CERTCTL_SESSION_SIGNING_KEY_RETENTION`) so existing cookies
  validate during the rollover. Past retention, the old key's row
  is dropped and any cookie still signed under it returns
  `ErrSigningKeyNotFound`.
- **EnsureInitialSigningKey is fail-fatal at server boot.** Wired
  in `cmd/server/main.go` via `logger.Error + os.Exit(1)` so a
  server with a broken DB or RNG cannot boot into a state where
  session validation is impossible.
- **Pre-login cookie discriminated from post-login.** Pre-login
  carries the `pl-` id prefix; post-login carries `ses-`. Defense-
  in-depth: `Validate` rejects pre-login cookies (pinned by
  `TestService_Validate_RejectsPreLoginCookieAtPostLoginGate`) so a
  stolen pre-login cookie cannot be replayed against the post-login
  gate.

### Back-channel logout (Phase 5)

- **OpenID Connect Back-Channel Logout 1.0** (NOT RFC 8414).
  Endpoint: `POST /auth/oidc/back-channel-logout`. The IdP signs a
  logout JWT and POSTs it to certctl when a user logs out at the
  IdP. The handler validates the JWT against the IdP's JWKS via
  the same alg allow-list as the login flow.
- **Required claims pinned.** `iss` / `aud` / `iat` / `jti` /
  `events` (with the spec-mandated logout event type); exactly
  one of `sub` / `sid`; `nonce` MUST be absent (per spec §2.4
  - logout tokens MUST NOT carry a nonce). All four pinned by
  Phase 5 negative tests.
- **`jti`-based replay defense.** The Phase 5 implementation
  tracks recently-seen `jti` values to defeat logout-token replay
  attacks where an attacker captures a logout JWT and replays it.
- **Cache-Control: no-store** on the response per spec §2.5.

### OIDC first-admin bootstrap (Phase 7)

- **Coexists with Bundle 1's env-var-token bootstrap.** Both can be
  configured; the admin-existence probe ensures only one wins.
- **Group-scoped.** `CERTCTL_BOOTSTRAP_ADMIN_GROUPS` is a comma-
  separated allowlist of IdP group names; users in any one of those
  groups become admins on FIRST login per tenant. Non-empty
  intersection with the user's resolved groups is required.
- **One-shot per tenant via admin-existence probe.** Once any actor
  holds `r-admin` in the tenant, the bootstrap hook silently falls
  through to normal mapping (no admin grant). Operators rely on
  this to avoid an "always-admin-on-login" backdoor.
- **Explicit OIDC provider gate.** `CERTCTL_BOOTSTRAP_OIDC_PROVIDER_ID`
  pins which provider's tokens are eligible. A multi-IdP deploy
  cannot have any provider's group claims become admin.
- **Audit row on every grant.** `bootstrap.oidc_first_admin` event
  with `event_category=auth` + INFO log; the auditor monitors.

### Break-glass admin (Phase 7.5)

- **Default-OFF.** `CERTCTL_BREAKGLASS_ENABLED=false` is the default;
  the entire surface (4 endpoints) is disabled. Operators flip it
  on during SSO incidents and back off after recovery.
- **Surface invisibility via 404-not-403.** Every endpoint returns
  HTTP 404 when disabled - public login AND admin endpoints. A
  scanner cannot distinguish "endpoint disabled" from "endpoint
  doesn't exist." All five service-layer methods short-circuit with
  `ErrDisabled` before any DB lookup; the handler maps to
  `http.NotFound`.
- **Argon2id with OWASP 2024 params.** `m=64MiB`, `t=3`, `p=4`,
  16-byte salt, 32-byte output, per-password random salt, PHC-format
  hash. The hash column is `json:"-"` so handlers cannot wire-leak.
- **Lockout state machine.** `CERTCTL_BREAKGLASS_LOCKOUT_THRESHOLD`
  (default 5) failures within
  `CERTCTL_BREAKGLASS_LOCKOUT_RESET_INTERVAL` (default 1h) trip a
  `CERTCTL_BREAKGLASS_LOCKOUT_DURATION` lock (default 30s; bumped
  from 100ms after the test discovered Argon2id verify itself takes
  ~80-200ms each, making a millisecond-scale lockout invisible).
  Atomic single-statement `IncrementFailure` defeats concurrent
  racing attempts. Idempotent `ResetFailureCount`.
- **Constant-time across all failure paths.** `verifyDummy()` runs a
  real Argon2id pass against an all-zeros throwaway salt on the
  no-credential and locked-account paths so all three failure modes
  (wrong password / locked / no actor) take statistically
  indistinguishable time. Pinned by
  `TestPhase7_5_ConstantTimeAcrossWrongPasswordAndNoCredentialPaths`
  (asserts within 5x ratio on durations).
- **Audit row + WARN log at boot.** `auth.breakglass_login_*`
  events with `event_category=auth`. `cmd/server/main.go` emits a
  WARN-level log when `ENABLED=true` so the operator's log review
  notices an over-long enablement.
- **Rate limit on the public login endpoint.** 5 attempts/minute
  via the existing `middleware.NewRateLimiter`.

## Bundle 2 threat catalogue

The following sub-sections enumerate the threat surface introduced by
Bundle 2 and the mitigations the platform ships. They are deliberately
exhaustive - if a threat is listed here it has a concrete mitigation
or a documented "operator-driven, out of scope" framing. New threats
discovered post-2026-05-10 should be added here with a dated commit
note.

### OIDC token forgery vectors and mitigations

| Vector | Mitigation |
|---|---|
| Alg confusion (HS256 token signed with the IdP's public key) | Alg allow-list rejects HS256 / HS384 / HS512 / `none`. Service-layer + go-oidc enforce in two layers. IdP-downgrade-attack defense at provider-creation time. |
| Audience injection (token issued for a different client) | Service-layer `aud` re-check post-go-oidc verify; multi-aud tokens require matching `azp`. Sentinels `ErrAudienceMismatch` / `ErrAZPRequired` / `ErrAZPMismatch`. |
| Issuer mismatch (token from a different IdP with the same alg + key shape) | Exact `iss` string match (`ErrIssuerMismatch`). The 21-case Phase 3 negative-test matrix pins the byte-for-byte requirement. |
| Nonce replay (capturing a fresh token + replaying with the same nonce) | Single-use nonce stored in the pre-login row; `LookupAndConsume` is `DELETE...RETURNING` (atomic). Second use returns `ErrPreLoginNotFound`. |
| State replay (CSRF on the IdP redirect) | Same single-use mechanism as nonce. State is `subtle.ConstantTimeCompare`d. |
| `at_hash` substitution (clean ID token with a swapped access token) | `at_hash` REQUIRED when access_token present (Phase 3 tightening of OIDC core's MAY → MUST). `ErrATHashRequired` if missing; `ErrATHashMismatch` if non-matching. |
| `iat` window manipulation (stale token replay) | `iat_window_seconds` configurable per-provider (default 300, cap 600). Future `iat` returns `ErrIATInFuture`; older-than-window returns `ErrIATTooOld`. |
| JWKS rotation mid-login | coreos/go-oidc's built-in cache + auto-refresh on TTL expiry. Operator-triggered `Service.RefreshKeys` for forced refresh. |
| JWKS-fetch failure during a key rotation | `ErrJWKSUnreachable` (HTTP 503 to in-flight login). Existing sessions untouched. Operator clicks "Refresh discovery cache" once IdP recovers. No exponential backoff. |

### Session hijacking vectors and mitigations

| Vector | Mitigation |
|---|---|
| Cookie theft via XSS | `HttpOnly` on the session cookie; CSP headers from Bundle B's H-1 work prevent inline-script execution. |
| Cookie theft via network MITM | `Secure` flag + TLS 1.3-only control plane (HTTPS-Everywhere v2.2 milestone). |
| CSRF on state-changing methods | `SameSite=Lax` default + double-submit-cookie pattern with hashed CSRF token on the session row. CSRFMiddleware fires on POST/PUT/PATCH/DELETE for session-authenticated callers; API-key actors are exempt. |
| Session-cookie forgery via concatenation collision | Length-prefixed HMAC input (`len(sid):sid:len(kid):kid`). Pinned by two tests + a doc-block at the top of `service.go`. |
| Stolen-cookie replay (attacker uses a valid cookie until expiry) | Short idle timeout (1h default) + admin-revoke-all-for-actor + back-channel logout from IdP + GUI session revocation. |
| Cross-tab session interference | Cookie value is opaque + length-prefixed; tabs sharing the cookie share the session row. Sign-out in one tab calls `POST /auth/logout`; the next request from any tab gets a missing-row 401. |
| Session-row race on sign-out vs in-flight request | `Validate` is the single point that reads the row; missing row = 401. There is no "stale read" path because every request re-validates. |

### IdP compromise scenarios

A rogue IdP issues malicious tokens (signs tokens for arbitrary users,
mints arbitrary groups, etc.). Mitigations are largely out of certctl's
control - the trust root is the IdP. Documented behaviors:

- **Operator should monitor IdP audit logs.** Federated identity is
  only as trustworthy as the IdP it federates from. The `iss` claim
  on every certctl audit row points at the source IdP so the
  operator can correlate against IdP-side audit.
- **Operator can rotate group-role mappings from the GUI without
  redeploying.** If the IdP is compromised but not yet
  decommissioned, the operator can dial down access via
  `Auth → OIDC Providers → <provider> → Group → role mappings`
  and remove every mapping. Subsequent logins fail closed
  (`ErrGroupsUnmapped`); existing sessions continue until expiry.
- **The audit trail records every OIDC login including the source
  provider.** Blast radius is bounded by the `group_role_mapping`
  table for that provider. A compromised provider configured with
  only `engineers → r-operator` cannot escalate to `r-admin` via
  any token forgery.
- **The provider-delete path returns 409 when sessions exist for it.**
  `ErrOIDCProviderInUse` forces the operator to revoke the
  provider's active sessions before deletion - prevents accidental
  loss of audit lineage on a hot incident.

### Back-channel logout failure modes

| Mode | Behavior | Mitigation |
|---|---|---|
| IdP unreachable | certctl never receives the logout signal; sessions persist until idle/absolute timeout (1h/8h defaults). | Operator keeps absolute timeout short relative to risk tolerance. Manual revoke via GUI is always available. |
| Logout token signature invalid | certctl returns 400; no session revoked; `auth.oidc_back_channel_logout_failed` audit row. | Operator-monitored audit row surfaces forged-logout-token attempts. |
| Logout token replay (attacker captures + replays a valid logout JWT) | `jti`-based deduplication rejects the replay; first delivery succeeds, second returns 400. | Pinned by Phase 5 negative tests. |
| Logout token alg confusion | Same alg allow-list as the login flow; HS-family rejected. | Phase 3 alg allow-list applies to BCL too (same `Provider.RemoteKeySet`). |
| Missing `events` claim | Spec §2.4 requires the OIDC-defined logout event type; missing returns 400. | Pinned by negative test. |
| `nonce` claim present | Spec §2.4 requires `nonce` MUST NOT appear in logout tokens; presence returns 400. | Pinned by negative test. |

### Group-claim manipulation

Per-IdP group-claim shapes are documented in
[`oidc-runbooks/index.md`](oidc-runbooks/index.md). Manipulation
threats:

| Vector | Mitigation |
|---|---|
| Operator misconfigures mapping (e.g. `engineers → r-admin` instead of `r-operator`) | `auth.group_mapping_added` / `_removed` audit row with `event_category=auth`. The auditor role monitors. |
| Operator misconfigures `groups_claim_path` (e.g. `groups` when Auth0 emits `https://your-namespace/groups`) | User's group claim is ignored, user lands at "no roles assigned" screen. The GUI's OIDC provider detail page surfaces the configured path so the operator can verify. |
| IdP renames a group (e.g. `engineers → eng-team`) | Mappings silently break; users get fewer roles than expected. `auth.oidc_login_unmapped_groups` audit row fires on every such login; auditor monitors for unexpected spikes. |
| IdP user maintainer adds a user to an unintended group | Group is mapped to a higher-privilege role than intended; user gets the role on next login. Bounded blast radius: the group→role mapping is what they got, not arbitrary admin. Defense-in-depth: review mappings periodically; the auditor role can pull `auth.oidc_login_succeeded` rows by `details.subject` to spot drift. |

### Bootstrap phase risks (post-Bundle-2)

This section extends Bundle 1's bootstrap section with the OIDC
first-admin path.

| Vector | Mitigation |
|---|---|
| `CERTCTL_BOOTSTRAP_TOKEN` (Bundle 1 fallback) leaks | One-shot via `consumed` bool + admin-existence probe. Both arms close the path the moment any admin lands. (Bundle 1.) |
| `CERTCTL_BOOTSTRAP_ADMIN_GROUPS` misconfigured to a wide group (e.g. `everyone`) | Unintended user becomes admin on first OIDC login. Mitigation: scope-down via `certctl-cli auth keys scope-down --suggest`. Operators configure narrow groups. The audit row on `bootstrap.oidc_first_admin` surfaces every grant. |
| Both bootstrap strategies enabled simultaneously | Whichever fires first wins; the second sees admin-already-exists and falls through to normal mapping. No double-admin landing. |
| `CERTCTL_BOOTSTRAP_OIDC_PROVIDER_ID` left unset with multi-IdP deploy | Hook fires on ANY provider's tokens. Mitigation: explicit gate documented in `cmd/server/main.go` startup logging; operator audit reviewed pre-tag. |

### Break-glass risks (Phase 7.5)

| Vector | Mitigation |
|---|---|
| Phished password (operator gives password to attacker) | Bypasses OIDC + every group-claim gate. Mitigation: default-OFF posture; lockout after 5 failures; WebAuthn pairing (v3 / Decision 12) closes the gap properly. |
| Brute-force online | Lockout state machine + 5/min rate limit on `/auth/breakglass/login`. |
| Brute-force offline (DB compromise) | Argon2id with OWASP 2024 params (~80-200ms per verify). Cracking remains expensive even with GPU. |
| Operator forgets to disable post-incident | Break-glass becomes a permanent backdoor. Mitigation: WARN log at boot when ENABLED=true; audit row on every break-glass login; runbook prescribes "disable within 24h of SSO recovery." |
| Side-channel timing on no-credential vs wrong-password vs locked | All three paths take statistically indistinguishable time via `verifyDummy()`. Pinned by the timing-statistical test. |
| Surface fingerprinting (scanner identifies break-glass exists) | All four endpoints return 404 (NOT 403) when disabled. Surface-invisibility - identical to a non-existent route. |
| Reserved-actor `actor-demo-anon` mutation via break-glass admin | Service layer rejects with `ErrAuthReservedActor` (HTTP 409). Same gate as the Bundle 1 RBAC path. |

### Token-leak hygiene (the explicit grep policy)

ID tokens, access tokens, refresh tokens, authorization codes, PKCE
verifiers, state, nonce, signing keys, break-glass passwords MUST
NEVER appear in any log line at any level.

The invariant is enforced by per-package `logging_test.go` files that
redirect `slog.Default` to a buffer, run the service paths, and
grep-assert the secret values are absent from every captured line.
Bundle 1's `internal/auth/bootstrap/service_test.go` is the pattern.
Phases 3, 4, and 7.5 follow the same shape:

- `internal/auth/oidc/logging_test.go` - token / code / verifier /
  state / nonce / cookie / client_secret / alg name absent from
  HandleAuthRequest, HandleCallback, alg-rejection, and provider-
  load paths.
- `internal/auth/session/service_test.go` - signing-key bytes absent
  from cookie-mint + validate paths.
- `internal/auth/breakglass/service_test.go` - plaintext password +
  Argon2id hash absent from every audit row + log line +
  HTTP-response shape (json:"-" probe via `json.Marshal`).

The `details` JSONB column on `audit_events` runs through
Bundle-6's redactor (`internal/service/audit_redact.go`) before
persistence; the redactor's allow-list is conservative enough that
adding a new token-shaped field to a new audit row defaults to
redacted, not leaked.

## Threats Bundle 1 does NOT close (Bundle 2 closure status)

The list below was the Bundle-1-era deferred-threats catalogue.
Status updated 2026-05-10 to reflect what Bundle 2 closed and what
remains deferred. **The label "Bundle 1 does NOT close" is preserved
for historical traceability**; readers should consult the marker at
the end of each item for current status.

1. **OIDC / SAML / WebAuthn federation** - ✅ OIDC closed (Bundle 2
   Phases 1-7); SAML deferred to v3; WebAuthn deferred to v3
   (Decision 12 - WebAuthn pairs with break-glass for hardware-
   token-MFA). The break-glass path (Phase 7.5) is a partial
   mitigation for the no-MFA case during SSO incidents.
2. **Session management** - ✅ closed (Bundle 2 Phases 4 + 6). HMAC-
   signed `certctl_session` cookie with length-prefixed wire format,
   1h idle / 8h absolute expiry, scheduler-driven GC, server-side
   revocation list (delete the row), GUI's "Sessions" page surfaces
   own + all-actor revocation, back-channel logout from the IdP.
3. **Local password accounts (break-glass)** - ✅ closed (Bundle 2
   Phase 7.5). Argon2id + lockout + default-OFF + 404-not-403
   surface invisibility. NOT for general human auth - only the
   "SSO is broken, need admin access right now" path. WebAuthn
   pairing on the v3 roadmap.
4. **Time-bound role grants / JIT elevation** - **still deferred to
   v3.** The schema still reserves `actor_roles.expires_at` with no
   UI/API to set it. Bundle 2 introduces session-level idle/absolute
   expiry but does not propagate that to role grants.
5. **MFA / hardware tokens for the operator console** - ⚠️ partial
   closure. WebAuthn / FIDO2 second factor remains v3 (Decision 12).
   Bundle 2's break-glass (Phase 7.5) provides a separate password
   factor that operators can pair with OIDC, but it's not a true
   second factor on the OIDC login path - the OIDC IdP remains the
   sole token source on the federation path.
6. **Rate limiting on the bootstrap endpoint** - acceptable
   (one-shot by construction; per-IP rate limiting on the broader
   API is in place via Bundle C's `middleware.NewRateLimiter`).
   Bundle 2 adds the same rate-limit primitive to the break-glass
   `/auth/breakglass/login` endpoint at 5/min.
7. **`scope_id` FK enforcement** - **still deferred.** Operators can
   grant a permission at scope `profile`/`p-bogus` without the
   bogus profile existing. The gate still works (no rows match at
   request time) but a strict 404 on grant would be cleaner.
   `TODO(bundle-2)` comment is now `TODO(v3)`.
8. **OIDC-first-admin bootstrap** - ✅ closed (Bundle 2 Phase 7).
   `CERTCTL_BOOTSTRAP_ADMIN_GROUPS` + `CERTCTL_BOOTSTRAP_OIDC_PROVIDER_ID`
   env vars + group-scoped + admin-existence-probe.
9. **GUI E2E suite via Playwright** - **still deferred** to a
   follow-on bundle. The Phase 8 GUI ships 28 new Vitest unit-test
   cases (5 new test files); full Playwright E2E for the 15 flow
   checks from the Bundle 2 prompt's Phase 8 (auth-code login +
   group-claim parsing + revoke-revokes-session + JWKS rotation +
   etc.) is the operator's call on whether to land before tag.

## Threats Bundle 2 does NOT close

These are the v3 / future-work deferrals at the post-Bundle-2 mark:

1. **WebAuthn / FIDO2 second factor** - operator console is OIDC
   (or break-glass password) only. No hardware-token requirement
   even on the admin path. Decision 12.
2. **Time-bound role grants / JIT elevation** - the
   `actor_roles.expires_at` column exists, no UI/API yet.
3. **SAML federation** - OIDC only. Operators on SAML-only IdPs use
   the broker pattern (run Keycloak as a SAML-to-OIDC bridge); see
   the Google Workspace runbook for the same broker shape.
4. **Multi-tenant data isolation activation** - the schema and
   repository layer carry tenant_id columns + the Phase 13 query-
   coverage CI guard, but tenant ACLs are not enforced. Bundle 2
   ships single-tenant only (`t-default` seeded). The managed-
   service hosting work (operator decision item) is where multi-
   tenant flips on.
5. **HSM / FIPS-validated signing key for sessions** - the session
   signing key is software-only (HMAC-SHA256, in-memory key
   material, encrypted at rest via `internal/crypto`). Operators
   in FIPS 140-3 environments need to supply their own
   `Signer` implementation; the abstraction at
   `internal/crypto/signer/` accommodates this but no PKCS#11
   driver ships yet.
6. **OIDC RP-initiated logout** (the "/end_session_endpoint" flow
   where certctl signs a logout token + redirects the browser to
   the IdP). Bundle 2 implements ONLY the back-channel flow (IdP →
   certctl). Operators wanting the full bidirectional logout pair
   wait on a follow-on bundle.
7. **GUI E2E via Playwright** - tracked alongside #9 above.
8. **Per-IdP runbook external-tester sign-off** - encouraged via
   the operator-sign-off footers in `oidc-runbooks/*.md` but NOT a
   merge gate (operator decision 2026-05-10; the earlier
   "≥ 2 external testers" requirement was retired).

## Compliance mapping

The control set in this document supports the following
framework requirements. This is a mapping; it is not a claim of
formal certification.

- **SOC 2 CC6.1** (logical access controls) - RBAC primitive
  with role-based gating on every mutating endpoint.
- **SOC 2 CC6.3** (privileged access management) - `r-admin`
  role separation + role-grant audit trail with two-person
  integrity on approval-tier profile edits.
- **HIPAA §164.312(b)** (audit controls) - `event_category`
  column lets the auditor role review authentication / authorization
  changes specifically. WORM trigger keeps the audit table
  append-only at the database layer.
- **NIST SSDF PO.5.2** (separation of duties) - two-person
  integrity for compliance-tier issuance via the
  `RequiresApproval` flow + Bundle 1 Phase 9's closure of the
  flip-flop bypass.
- **FedRAMP AU-9** (audit information protection) - WORM
  enforcement + auditor-only read access (the auditor role
  cannot mutate, the WORM trigger blocks UPDATE/DELETE).
- **PCI-DSS §10** (audit logging) - every mutating operation
  emits an audit row with actor + action + resource + timestamp +
  category. The audit table is append-only.

## Operator-facing checks

Run these periodically to verify the controls are working.

1. `certctl-cli auth keys list` - confirm no unexpected actor
   holds `r-admin`. Audit any new admin grants against the audit
   log.
2. `SELECT actor, action, COUNT(*) FROM audit_events WHERE
   action LIKE 'approval_%' AND timestamp > NOW() - INTERVAL '7
   days' GROUP BY actor, action;` - confirm approvals are
   happening and not concentrated in a single approver.
3. `SELECT COUNT(*) FROM audit_events WHERE actor =
   'system-bypass';` - MUST return 0 in production. A non-zero
   count means `CERTCTL_APPROVAL_BYPASS=true` was set; production
   deploys MUST leave it unset.
4. `SELECT actor, COUNT(*) FROM audit_events WHERE action =
   'bootstrap.consume';` - MUST return at most one row per
   tenant. Multiple rows means the bootstrap endpoint was called
   more than once, which the strategy's one-shot guard should
   have prevented; investigate.
5. `certctl-cli auth me` while authenticated as the auditor
   key - `effective_permissions` must contain `audit.read` +
   `audit.export` ONLY. Any other permission means a role grant
   widened the auditor's surface; revoke immediately.

The following checks are NEW with Bundle 2:

6. `SELECT COUNT(*) FROM oidc_providers;` - confirm only the
   expected providers are configured. An unexpected row is a
   compromise indicator. Cross-check with the
   `auth.oidc_provider_created` audit row to find when + by whom.
7. `SELECT actor_id, COUNT(*) FROM sessions WHERE NOT revoked AND
   absolute_expires_at > NOW() GROUP BY actor_id ORDER BY 2 DESC;`
   - confirm no actor has an unexpectedly large session count.
   Multi-session-per-actor is normal (laptop + phone), but a single
   actor with 50+ active sessions is a compromised-key signal.
8. `SELECT COUNT(*) FROM audit_events WHERE action LIKE
   'auth.oidc_login_unmapped_groups' AND timestamp > NOW() -
   INTERVAL '7 days';` - non-zero rows mean users are completing
   IdP authentication but failing the group-mapping step. Either
   the IdP renamed a group, or an unauthorized user attempted
   access. Investigate.
9. `SELECT COUNT(*) FROM audit_events WHERE action LIKE
   'auth.breakglass_%' AND timestamp > NOW() - INTERVAL '7 days';`
   - non-zero rows in steady state mean break-glass is being used
   outside an SSO incident OR was left enabled. Confirm
   `CERTCTL_BREAKGLASS_ENABLED` is `false` in non-incident windows.
10. `SELECT COUNT(*) FROM audit_events WHERE action =
    'bootstrap.oidc_first_admin';` - MUST return at most one row
    per tenant. Multiple rows means the OIDC bootstrap hook fired
    more than once per tenant, which the admin-existence probe
    should have prevented; investigate.
11. `SELECT COUNT(*) FROM session_signing_keys WHERE retired_at IS
    NOT NULL AND retired_at < NOW() - INTERVAL '7 days';` - retired
    keys past the retention window should have been GC'd. Non-zero
    rows mean the scheduler's `sessionGCLoop` is wedged.

## Cross-references

Bundle 1 (RBAC) anchors:

- [`rbac.md`](rbac.md) - the operator how-to
- [`security.md`](security.md) - the wider security posture
- [`approval-workflow.md`](approval-workflow.md) - the two-person
  integrity gate
- [`docs/migration/api-keys-to-rbac.md`](../migration/api-keys-to-rbac.md) - 
  upgrade flow
- `internal/auth/` - middleware + keystore + RequirePermission +
  bootstrap
- `internal/service/auth/` - Authorizer + privilege-escalation
  guard + reserved-actor guard
- `migrations/000029_rbac.up.sql` - schema + seed
- `migrations/000030_rbac_admin_perms.up.sql` - five admin-only
  fine-grained perms
- `migrations/000032_audit_category.up.sql` - auditor surface
- `migrations/000033_approval_kinds.up.sql` - approval-bypass
  closure

Bundle 2 (OIDC + sessions + back-channel logout + break-glass) anchors:

- [`oidc-runbooks/index.md`](oidc-runbooks/index.md) - per-IdP setup
  guides (Keycloak / Authentik / Okta / Auth0 / Entra ID / Google
  Workspace) with cross-IdP recurring concepts at the top
- `internal/auth/oidc/` - OIDC service (HandleAuthRequest /
  HandleCallback / RefreshKeys), hand-rolled groupclaim resolver,
  alg allow-list, IdP downgrade-attack defense
- `internal/auth/session/` - session service (length-prefixed HMAC,
  cookie minting, idle/absolute expiry, signing-key rotation, GC),
  CSRF middleware, chained-auth combinator
- `internal/auth/breakglass/` - default-OFF break-glass admin
  (Argon2id + lockout + constant-time + surface-invisibility)
- `internal/auth/oidc/testfixtures/` - Phase 10 Keycloak
  testcontainers harness (`//go:build integration`)
- `migrations/000034_oidc_providers.up.sql` - OIDC providers +
  group-role mappings tables
- `migrations/000035_sessions.up.sql` - sessions + session-signing-
  keys tables
- `migrations/000036_users.up.sql` - users (federated-human
  identity) table
- `migrations/000037_oidc_pre_login.up.sql` - pre-login table + 7
  new auth permissions
- `migrations/000038_breakglass_credentials.up.sql` - break-glass
  credentials table + 2 new permissions
- `scripts/ci-guards/N-bundle-2-security-empty-preserved.sh` -
  OpenAPI security: [] count guard
- `scripts/ci-guards/bundle-1-compat-regression.sh` -
  Bundle-1-only-compat assertions (5 invariants)
- `scripts/ci-guards/bundle-1-to-2-upgrade-regression.sh` -
  upgrade-path assertions (6 invariants)
