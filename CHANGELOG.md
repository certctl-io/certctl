# Changelog

## Unreleased

### Security (BREAKING — silent-elevation closure)

- **HIGH-10 actor-role scope is now enforced (Audit 2026-05-11 A-1).**
  Pre-fix, `actor_roles.scope_type` / `scope_id` (added in migration 000043
  by the HIGH-10 closure) were persisted by Grant + accepted on the handler
  body + surfaced through the GUI/MCP — but the load-bearing
  `EffectivePermissions` SQL never read them. A profile-scoped grant
  silently elevated to global at authorization time. Canonical CRIT-5
  lying-field shape, replicated. **The post-fix authorization narrows
  correctly**: every existing `actor_roles` row with `scope_type != 'global'`
  now takes effect.

  > **Operator advisory:** if you used the HIGH-10 scope-bound role-grant
  > API between commit `551812b` and the v2.1.0 tag (the column was
  > populated but ignored), the grants were silently global. After
  > upgrading, audit `SELECT actor_id, role_id, scope_type, scope_id FROM
  > actor_roles WHERE scope_type != 'global'` and confirm the narrowing
  > reflects intent. If an actor was granted a scoped role but expected
  > global behavior, re-grant with `scope_type=global`.

### Security (BREAKING)

- **Federated-user deactivation now actually blocks login (Audit 2026-05-11 A-2).**
  The MED-11 closure shipped `users.deactivated_at` + `DELETE /api/v1/auth/users/{id}`
  + cascade-session-revoke, but the column was a "lying field" three legs over: the
  postgres user repository never SELECTed it (so `User.DeactivatedAt` always read
  nil), the `Update` SQL never wrote it (so the handler's mutation was a no-op),
  and the OIDC `upsertUser` path never checked it (so the next login under the
  same `(provider, subject)` tuple re-minted a session and re-elevated the user).
  The cascade-revoke remained correct for the current cookie only. **Operator
  advisory: if you deactivated a federated user between the MED-11 closure
  (Bundle 2 merge `dea5053`) and the v2.1.0 release tag, verify the user cannot
  OIDC-log-in after upgrading — the column took no effect at login time before
  this fix. If needed, re-run the deactivation against the upgraded server.**
  Closure: `userColumns` + `scanUser` now read `deactivated_at` via `sql.NullTime`;
  `Create` + `Update` write it explicitly; `upsertUser` returns the new
  `ErrUserDeactivated` sentinel before mutating fields (preserves `last_login_at`
  forensics on rejected logins); `classifyOIDCFailure` surfaces the rejection
  as audit category `user_deactivated`. Self-deactivate guard on
  `DELETE /api/v1/auth/users/{id}` returns HTTP 409 + audit row
  `auth.user_deactivate_self_rejected` (prevents an admin from one-way-door
  locking themselves out via the standard handler — break-glass remains the
  recovery path). New inverse endpoint `POST /api/v1/auth/users/{id}/reactivate`
  (gated `auth.user.deactivate` — reactivation is the inverse op, not a separate
  privilege) clears `deactivated_at`; emits audit row `auth.user_reactivated`.
  Sessions revoked at deactivation stay revoked across reactivation — the user
  must complete a fresh OIDC login. GUI: `UsersPage.tsx` now renders a Reactivate
  button on deactivated rows. CWE-862 (missing authorization at the user-state
  boundary). SOC 2 CC6.3 + ISO 27001 A.9.2.6 compliance-table-flipping fix.
- **`__Host-` cookie prefix on all three auth cookies (Audit 2026-05-10 MED-14).**
  The session cookie, CSRF cookie, and OIDC pre-login cookie are renamed from
  `certctl_session` / `certctl_csrf` / `certctl_oidc_pending` to
  `__Host-certctl_session` / `__Host-certctl_csrf` / `__Host-certctl_oidc_pending`
  to gain browser-enforced subdomain-takeover protection (a `__Host-*` cookie can
  only be set with `Path=/` + `Secure` + no `Domain` attribute, and the browser
  rejects subdomain attempts to overwrite it). **Active sessions invalidate on
  the rolling deploy that lands this change** — operators must re-authenticate
  once after upgrading. The GUI's CSRF cookie reader was updated in lockstep.
  See `docs/migration/oidc-enable.md` for operator-facing detail.

### Security

- **OIDC `allowed_email_domains` now editable in the GUI (Audit 2026-05-11 A-3).**
  The backend gate that rejects logins whose email domain is outside the
  configured allowlist landed in v2.1.0 (CRIT-5 closure, 2026-05-10), but the
  GUI never exposed the field — GUI-driven operators had to use the API
  directly to configure tenant isolation against multi-tenant IdPs (Auth0,
  Azure AD common endpoint, Google Workspace). The OIDCProvidersPage create
  modal and OIDCProviderDetailPage detail view now render a chip-style
  multi-input with client-side validation that mirrors the backend rules
  (no `@`, no whitespace, no wildcards, lowercase-only FQDNs). The read-only
  view renders an explicit "any (no gate configured)" sentinel when the list
  is empty so operators can tell "not configured" apart from "field is
  invisible." A "Clear all" button on the edit form is gated by a confirm
  dialog that warns about removing the tenant gate. **Operator advisory: if
  you provisioned OIDC providers via the GUI between v2.1.0 and this fix,
  verify `allowed_email_domains` matches your tenant policy — the field was
  configurable only via API / MCP / direct SQL during that window.** Per-IdP
  runbooks for multi-tenant IdPs in `docs/operator/oidc-runbooks/` already
  documented the field; the GUI now matches.

- **Pre-login cookie Path widened from `/auth/oidc/` to `/` (Audit MED-14
  follow-on).** Required to satisfy the `__Host-` prefix's `Path=/` rule. The
  cookie lifetime is unchanged (10 minutes) and only the callback handler
  consumes it; the wider path scope is harmless.

- **RFC 9207 `iss` URL parameter check on OIDC callback (Audit 2026-05-10
  MED-17).** When the matched IdP's discovery doc advertises
  `authorization_response_iss_parameter_supported: true`, certctl now requires
  the `iss` query parameter on `/auth/oidc/callback` and enforces a
  constant-time compare against the configured provider's `IssuerURL`. Mismatch
  rejects with HTTP 400; the audit row's `failure_category` distinguishes
  `iss_param_missing` / `iss_param_mismatch` (RFC 9207 leg) from the existing
  `id_token_iss_mismatch` (in-token iss claim leg). Closes the mix-up-attack
  defense for modern Keycloak, Authentik, and public-trust CAs that ship
  RFC-9207 discovery. Providers that don't advertise support (the majority
  today) keep pre-fix behavior — back-compat is preserved.

- **Auth GUI batch (Audit 2026-05-10 MED-4/7/8/10/11/12 + LOW-1/11/12 +
  HIGH-10 GUI).** New backend endpoints land alongside their GUI
  consumers: `GET /api/v1/auth/users` + `DELETE /api/v1/auth/users/{id}`
  (auth.user.read / auth.user.deactivate; migration 000045 adds
  `users.deactivated_at` plus the two new permissions); `GET
  /api/v1/auth/runtime-config` (auth.role.assign) returning a sanitized
  flat-map of deployed CERTCTL_* values (no secrets leaked — only
  set/unset booleans and counts); `GET
  /api/v1/auth/oidc/providers/{id}/jwks-status` (auth.oidc.list)
  returning the per-provider verifier counters (refresh count, last
  refresh / error timestamps, rejected JWS count, RFC 9207 iss-param
  flag). New `UsersPage` lists federated identities + soft-deactivates.
  `AuthSettingsPage` gains the runtime-config panel. `KeysPage`'s
  assign-role modal now collects `scope_type` / `scope_id` /
  `expires_at`. `RoleDetailPage`'s add-permission form gains the same
  scope picker, and the Delete button is hidden on the 7 default
  system roles (server already rejected, this is pure UX).
  `AuthProvider` renders a sticky red demo-mode banner when
  `auth_type=none`. `actor-demo-anon` rows on `KeysPage` already had
  buttons disabled.

- **11 new MCP tools (Audit 2026-05-10 MED-13).** Approval workflow
  (`certctl_approval_list` / `_get` / `_approve` / `_reject`), break-glass
  credential admin (`certctl_breakglass_list` / `_set_password` /
  `_unlock` / `_remove`), bootstrap status + consume
  (`certctl_bootstrap_status` / `_consume`), and audit category filter
  (`certctl_audit_list_with_category`). All route through the existing
  HTTP client so server-side permission gates fire unchanged.
  `certctl_bootstrap_consume`'s tool description carries an explicit
  "NEVER WIRE THIS TO AUTONOMOUS OPERATION" warning — a leaked
  bootstrap token mints a fresh admin API key bypassing every other
  access-control gate, so the tool is for one-shot manual operator
  invocation only.

- **JWKS auto-refresh on cache-miss (Audit 2026-05-10 MED-6).** When
  the IdP rotates its signing key between pre-login + callback, the
  cached JWKS no longer contains the kid referenced by the inbound ID
  token's JWS header. Pre-fix, the verify failed with a generic error
  and the operator had to manually call `POST
  /api/v1/auth/oidc/providers/{id}/refresh`. The service now detects
  the kid-not-in-cache shape (`isKidMismatchError`) and runs a
  one-shot `RefreshKeys` (evict cache → re-fetch discovery + JWKS →
  re-run alg-downgrade defense) before retrying the verify exactly
  once. Bounded recovery: a second failure surfaces as
  `ErrJWKSUnreachable` per the original branches; no retry loop. A
  separate matcher (`isKidMismatchError`) is intentionally narrow
  so generic signature failures don't trigger refresh.

- **OIDC provider test endpoint (Audit 2026-05-10 MED-5).** New
  `POST /api/v1/auth/oidc/test` dry-runs an OIDC provider configuration
  without persisting: fetches the discovery doc, runs the alg-downgrade
  defense, detects RFC 9207 iss-parameter advertisement, and confirms
  JWKS reachability. Returns `TestDiscoveryResult{discovery_succeeded,
  jwks_reachable, supported_alg_values, iss_param_supported, errors[]}`
  so the GUI (forthcoming) can render per-check status rows. Per-leg
  failures ride in the response body's `errors` array; only a malformed
  request body trips 400. Gate: `auth.oidc.create`. Audit row
  `auth.oidc_provider_tested` carries the success/failure summary.

- **Pre-login UA / source-IP binding on OIDC callback (Audit 2026-05-10
  MED-16).** RFC 9700 §4.7.1 defense against stolen-pre-login-cookie replay
  by a different browser / source. Migration `000044_prelogin_uaip` adds
  `client_ip` + `user_agent` to `oidc_pre_login_sessions`; values captured at
  `/auth/oidc/login` are constant-time compared at `/auth/oidc/callback`.
  Mismatches return HTTP 400 with audit `failure_category` =
  `prelogin_ua_mismatch` or `prelogin_ip_mismatch`. Two operator escape
  hatches: `CERTCTL_OIDC_PRELOGIN_REQUIRE_UA` and
  `CERTCTL_OIDC_PRELOGIN_REQUIRE_IP` (both default `true`) — operators on
  enterprise proxies that rewrite UA, or dual-stack v4/v6 environments where
  source IP routinely flips, can disable the affected leg. The binding column
  is persisted even when enforcement is off, so retroactive forensics remain
  possible. Empty values on either side pass through (rolling-deploy +
  headless-proxy compat).

## v2.1.0 - Auth Bundles 1 + 2: RBAC primitive + OIDC SSO + sessions ⚠️

> **SECURITY: AUDIT YOUR API KEYS.**
>
> Bundle 1 ships role-based authorization. Every existing API key
> configured via `CERTCTL_API_KEYS_NAMED` (or the legacy
> `CERTCTL_AUTH_SECRET`) is mapped to the **r-admin role on the first
> upgrade boot** so existing automation keeps working unchanged. Most
> keys do NOT need full admin power; downgrade them before tagging
> the next release.
>
> Recommended post-upgrade flow:
>
> ```bash
> # 1. List every key with its current role:
> certctl-cli auth keys list
>
> # 2. Walk an interactive prompt that downgrades each key:
> certctl-cli auth keys scope-down
>
> # 3. Or get a heuristic suggestion based on 30 days of audit history:
> certctl-cli auth keys scope-down --suggest
> certctl-cli auth keys scope-down --suggest --apply   # applies the suggestion
>
> # 4. Or drive scope-down from a JSON config (Helm post-upgrade hook):
> certctl-cli auth keys scope-down --non-interactive ./scope-down.json
> ```
>
> The synthetic `actor-demo-anon` actor (used when
> `CERTCTL_AUTH_TYPE=none` is configured) is system-managed and
> excluded from the prompt loop.

What else changed in v2.1.0:

- **Audit 2026-05-10 CRIT-1 closure — wire-layer RBAC enforcement.**
  The Bundle 1 + Bundle 2 audit surfaced that the permission catalogue
  was enforced on ~24 admin-only routes only; the bulk of state-changing
  routes (`POST /api/v1/certificates`, `PUT /api/v1/profiles/{id}`,
  `DELETE /api/v1/issuers/{id}`, `POST /api/v1/agents/{id}/csr`, even
  `POST /api/v1/auth/roles` + `POST /api/v1/auth/keys/{id}/roles`) had
  no `rbacGate` wrap. A `r-viewer` Bearer was essentially `r-admin`
  minus five fine-grained verbs at the wire layer (CWE-862). This
  release wraps every state-changing + read endpoint with
  `rbacGate` (global scope) or `rbacGateScoped` (per-profile / per-
  issuer scope-bound grants), and adds an AST-level CI guard
  (`TestRouterRBACGateCoverage`) that fails when a new route is
  registered without enforcement. Catalogue extended via migration
  000039 with 30 permissions covering `cert.edit`, `job.*`,
  `approval.*`, `policy.*`, `team.*`, `owner.*`, `notification.*`,
  `discovery.*`, `network_scan.*`, `healthcheck.*`, `digest.*`,
  `verification.*`, `stats.read`, `metrics.read`. **AUDIT YOUR
  KEYS** (the scope-down call-out above) now translates to real
  reduction in blast radius. Auditor pin preserved at exactly
  `{audit.read, audit.export}`.

- **RBAC primitive shipped.** `tenants`, `roles`, `permissions`,
  `role_permissions`, `actor_roles` tables (migration 000029); 33-permission
  canonical catalogue; 7 default roles (`admin`, `operator`, `viewer`,
  `agent`, `mcp`, `cli`, `auditor`); per-handler permission gates via
  `auth.RequirePermission` middleware (replaces the legacy
  `IsAdmin` boolean check on the 5 admin-only handlers).
- **Day-0 admin bootstrap.** Set `CERTCTL_BOOTSTRAP_TOKEN` on a fresh
  deploy and POST a single curl call against `/api/v1/auth/bootstrap` to
  mint the first admin API key; one-shot, never logged, and locks
  closed once any admin actor exists. Migration 000031 ships the
  `api_keys` table that stores the SHA-256 hash; the plaintext is
  shown in the response body once and never persisted.
- **Auditor role split.** New `auditor` role holds only `audit.read`
  + `audit.export`. Compliance reviewers can read the audit trail
  without holding mutation power. Migration 000032 adds
  `audit_events.event_category` so auditors can filter to
  authentication-related events specifically.
- **`/v1/auth/check` enrichment.** Response now includes the actor's
  standing roles and effective permissions, so the GUI gates
  affordances from a single fetch on app boot.
- **Approval-bypass closure.** Edits to a profile that has (or
  would have) `RequiresApproval=true` now route through the
  `ApprovalService` two-person integrity gate (Phase 9). Migration
  000033 adds `approval_kind` + `payload` to
  `issuance_approval_requests` so cert-issuance and profile-edit
  approvals share the same workflow. Same-actor self-approve is
  rejected with `ErrApproveBySameActor` for both kinds. Closes the
  flip-flop loophole where an admin could disable approval, mutate,
  re-enable. Documented at
  [`docs/reference/profiles.md`](docs/reference/profiles.md).
- **GUI: Roles / API Keys / Auth Settings / Approvals queue.**
  Four new pages under `/auth/*` consume `/v1/auth/me` for
  permission-aware rendering. The Approvals queue blocks
  self-approve at the client layer (Approve/Reject buttons hidden
  when requested_by == current actor_id) on top of the server-side
  enforcement. AuditPage gains a category filter (cert_lifecycle /
  auth / config) for the auditor view.
- **MCP server gains 12 RBAC tools.** Operators driving certctl
  from Claude / VS Code / any MCP client get parity with the GUI
  + CLI. Each tool routes through the same HTTP handler; permission
  gates fire server-side.
- **OpenAPI catalogues every new route.** Every Bundle 1 endpoint
  ships with an `operationId`; the parity test guards against drift.
- **Coverage gates.** `internal/auth/` and `internal/service/auth/`
  now have ≥85% coverage floors in `.github/coverage-thresholds.yml`.
  The 12-path negative-test list from the Bundle 1 prompt is
  fully covered (path #12 deferred with in-tree TODO).
- **Protocol-endpoint allowlist pinned at three layers.** The
  middleware bypass (`auth.IsProtocolEndpoint`), the router-level
  `AuthExemptRouterRoutes` constant, and a new
  `phase12_protocol_allowlist_test.go` AST scan all guard against
  accidentally wrapping ACME / SCEP / EST / OCSP / CRL routes in
  `rbacGate`.
- **Bundle 2: OIDC + sessions + back-channel logout + break-glass.**
  Auth Bundle 2 ships in the same v2.1.0 release. Operators get OIDC
  SSO support for Keycloak / Authentik / Okta / Auth0 / Microsoft
  Entra ID / Google Workspace (via Keycloak broker), HMAC-signed
  session cookies with idle/absolute timeouts + CSRF defense,
  back-channel logout per OpenID Connect Back-Channel Logout 1.0,
  and a default-OFF break-glass admin path with Argon2id passwords
  for SSO-broken incidents. API-key auth keeps working unchanged
  alongside; existing automation needs no changes. Migration walkthrough
  at [`docs/migration/oidc-enable.md`](docs/migration/oidc-enable.md);
  per-IdP setup guides at
  [`docs/operator/oidc-runbooks/index.md`](docs/operator/oidc-runbooks/index.md).
- **OIDC token validation pinned at three layers.** Algorithm
  allow-list (RS256/RS512/ES256/ES384/EdDSA only) with HS-family + `none`
  rejected at the service-layer sentinel; IdP-downgrade-attack defense
  at provider creation AND every JWKS RefreshKeys (intersects the IdP's
  advertised `id_token_signing_alg_values_supported` against the allow-
  list, rejects providers that advertise weak algs even before any
  token is signed); OIDC Core §3.1.3.7 re-verification of `iss` /
  `aud` / `azp` / `at_hash` (REQUIRED-when-access_token-present per
  Phase 3 tightening of the spec MAY → MUST) / `exp` / `iat` window
  / `nonce` constant-time-compare. PKCE-S256 mandatory; `plain`
  rejected. Single-use state + nonce via atomic `DELETE...RETURNING`
  on consume.
- **Session cookies use length-prefixed HMAC.** The cookie wire format
  is `v1.<session_id>.<signing_key_id>.<base64url-no-pad(HMAC-SHA256)>`
  with HMAC input `len:sid:len:kid` (NOT bare-concat) to defeat
  concatenation collisions. `HttpOnly` + `Secure` + `SameSite=Lax`
  default; `SameSite=Strict` configurable via `CERTCTL_SESSION_SAMESITE`.
  Idle timeout 1h / absolute 8h defaults; scheduler GC sweeps expired
  rows hourly. Signing keys rotate via the new `RotateSigningKey`
  primitive; the old key stays valid for `CERTCTL_SESSION_SIGNING_KEY_RETENTION`
  (default 24h) so existing cookies validate during rollover.
- **CSRF defense via double-submit-cookie + hashed-token-on-row.**
  Plaintext CSRF token in the JS-readable `certctl_csrf` cookie
  (intentionally `HttpOnly=false` for the GUI to echo into the
  `X-CSRF-Token` header); SHA-256 hash on the session row;
  `subtle.ConstantTimeCompare` in the new `CSRFMiddleware`. API-key
  actors are CSRF-exempt (no session row in context).
- **OIDC `client_secret` encrypted at rest.** AES-256-GCM v3 blob
  format (magic 0x03 + salt(16) + nonce(12) + ciphertext+tag) using
  the existing `CERTCTL_CONFIG_ENCRYPTION_KEY`. Encryption invariant
  pinned by an integration test asserting ciphertext != plaintext +
  v3 blob shape + round-trip recovery + wrong-passphrase fails.
- **OIDC first-admin bootstrap.** New `CERTCTL_BOOTSTRAP_ADMIN_GROUPS`
  + `CERTCTL_BOOTSTRAP_OIDC_PROVIDER_ID` env vars: the first
  OIDC-authenticated user with a matching group claim becomes admin
  per tenant. Coexists with the Bundle 1 env-var-token bootstrap;
  the admin-existence probe ensures only one wins. Audit row
  (`bootstrap.oidc_first_admin`) on every grant.
- **Break-glass admin (default-OFF).** New `CERTCTL_BREAKGLASS_ENABLED`
  env var (default `false`). When enabled, the local Argon2id-password
  admin path bypasses OIDC + group-claim layers — intended ONLY for
  SSO-broken incidents. Argon2id with OWASP 2024 params (m=64 MiB,
  t=3, p=4); lockout after 5 failures (configurable); constant-time
  across all failure paths via `verifyDummy`; surface invisibility
  (HTTP 404 on every endpoint when disabled, NOT 403). WARN log at
  server boot when enabled. WebAuthn/FIDO2 second factor pairing on
  the v3 roadmap (Decision 12).
- **GUI: OIDC Providers + Group → Role Mappings + Sessions + login
  buttons.** Four new pages under `/auth/*` consume the Bundle 2 API
  surface. Login page renders one "Sign in with X" button per
  configured OIDC provider (in addition to the API-key form, which
  remains as a fallback for Bearer-mode + break-glass paths). Sessions
  page exposes own-sessions + admin all-actors view. Every actionable
  element is permission-gated server-side via `auth.oidc.*` and
  `auth.session.*` perms; client-side hide is UX layer. Logout button
  in the sidebar fires `POST /auth/logout` to clear the session
  server-side before redirecting to login.
- **MCP server gains 11 OIDC + session tools.** `certctl_auth_list_oidc_providers`,
  `_get_oidc_provider`, `_create_oidc_provider`, `_update_oidc_provider`,
  `_delete_oidc_provider`, `_refresh_oidc_provider`,
  `_list_group_mappings`, `_add_group_mapping`, `_remove_group_mapping`,
  `_list_sessions`, `_revoke_session`. Operator-facing MCP tool count
  goes 12 (Bundle 1 RBAC) → 23 across the auth surface. Total MCP
  tool count: `grep -cE 'mcp\.AddTool\(' internal/mcp/tools*.go` ≈ 150.
- **Per-IdP runbooks: 6 production-tier setup guides** at
  `docs/operator/oidc-runbooks/`. Each runbook follows a consistent
  five-section layout (Prerequisites / IdP-side config / certctl-side
  config / Verification / Troubleshooting + Validation checklist with
  operator sign-off line). Keycloak is the canonical reference;
  Authentik / Okta / Auth0 / Entra ID / Google Workspace document the
  IdP-specific deltas (Auth0's namespaced custom claims; Entra ID's
  group OBJECT IDs; Google Workspace's missing-groups-claim limitation
  + the recommended Keycloak broker pattern).
- **Threat model extended.** [`docs/operator/auth-threat-model.md`](docs/operator/auth-threat-model.md)
  ships 5 new "Defenses Bundle 2 ships" subsections + 8 new threat-
  catalogue subsections (OIDC token forgery / session hijacking / IdP
  compromise / back-channel logout failure modes / group-claim
  manipulation / bootstrap risks / break-glass risks / token-leak
  hygiene). 6 new SQL-shaped operator-facing checks. New "Threats
  Bundle 2 does NOT close" section enumerating the 8 v3-backlog items
  (WebAuthn / JIT elevation / SAML / multi-tenant activation /
  HSM-FIPS / OIDC RP-initiated logout / Playwright / per-IdP
  external-tester sign-off).
- **Performance baselines documented.** [`docs/operator/auth-benchmarks.md`](docs/operator/auth-benchmarks.md)
  ships four benchmarks with measured baselines on a 4 vCPU /
  8 GiB / Postgres 16 / Go 1.25 floor: `BenchmarkSession_SteadyState`
  p99 5 µs (target < 1 ms; 200× under), `BenchmarkSession_ColdProcess`
  p99 7.1 ms (target < 10 ms), `BenchmarkOIDC_SteadyState` p99 1.5 ms
  (target < 5 ms), `BenchmarkOIDC_ColdCache` operator-runs against
  live Keycloak via `make benchmark-auth-coldcache`.
- **Standards + RFC implementation table.** [`docs/reference/auth-standards-implemented.md`](docs/reference/auth-standards-implemented.md)
  ships 13 RFC / standard rows + 14 CWE rows with concrete file paths
  + negative-test anchors per row. NOT a compliance-mapping doc per
  the operator's 2026-05-05 retired-compliance-docs decision; the
  doc explicitly says "build the framework mapping yourself against
  the rows here using the framework-mapping methodology your audit
  firm prescribes; this project does not own that mapping."
- **Coverage gates held at floor 90 across all four Bundle 2
  packages.** `internal/auth/oidc/` 93.7%, `internal/auth/session/`
  94.9%, `internal/auth/breakglass/` 91.5%, `internal/auth/user/domain/`
  96.4%. NO held-low-with-rationale entry — the Phase 13 prompt's
  anti-Bundle-1-mistake rule held. Bundle 1's existing 85% floors
  for `internal/auth/` + `internal/service/auth/` stay 85
  (already-shipped-and-accepted) per the prompt's explicit
  inheritance rule.
- **Multi-tenant query CI guard.** New `scripts/ci-guards/multi-tenant-query-coverage.sh`
  (ratchet-style, baseline 32 at v2.1.0 close): greps every
  SELECT/UPDATE/DELETE in `internal/repository/postgres/` against
  10 tenant-aware tables, fails on regression OR improvement (forces
  the operator to lift / lower the baseline visibly). Forward-compat
  protection so a future Bundle 3 / managed-service multi-tenant
  activation can flip the switch without finding silent
  tenant-data-leak bugs in shipped queries.
- **Phase 10 Keycloak testcontainers integration test.** New build-tag-
  gated suite at `internal/auth/oidc/testfixtures/` + `integration_keycloak_test.go`
  drives the full OIDC flow against a live Keycloak container booted
  by testcontainers-go. 5-test matrix: discovery + JWKS load, full
  PKCE auth-code happy path with HTTP form scraping, logout-revokes-
  session, JWKS rotation, unmapped-groups-fails-closed. Reuses one
  container across the matrix to amortize the 60-90s boot. Optional
  Okta smoke test (build-tagged `integration && okta_smoke`) for live
  tenant validation. New Makefile targets: `make keycloak-integration-test`
  + `make okta-smoke-test` + `make benchmark-auth-coldcache`.
- **OpenAPI surface extended.** New `cookieAuth` security scheme
  (apiKey/cookie/`certctl_session`) alongside the existing
  `bearerAuth`. 13 new Bundle 2 endpoints across the OIDC + session
  + group-mapping CRUD surface; 4 break-glass endpoints with
  surface-invisibility framing. The N-bundle-2-security-empty-preserved
  CI guard locks the `security: []` opt-out count at ≥ 14 so existing
  public endpoints stay public.
- **Bundle-1-only compat regression CI guard.** New
  `scripts/ci-guards/bundle-1-compat-regression.sh` asserts the
  load-bearing invariants that protect the Bundle-1-only-deploy
  case (session middleware defers-to-next, CSRF passthrough on
  missing session row, ChainAuthSessionThenBearer wired, public
  OIDC routes in AuthExempt allowlist, AuthInfo guards on
  OIDCProvidersResolver != nil). Sibling
  `bundle-1-to-2-upgrade-regression.sh` asserts the upgrade-path
  invariants (migrations 000034..000038 are CREATE TABLE IF NOT EXISTS
  + BEGIN/COMMIT-wrapped + no DROP TABLE / ALTER...DROP COLUMN
  against 19 protected Bundle-1 tables + ON CONFLICT DO NOTHING on
  permission seed).

Migration ordering, idempotency, and downgrade are documented in
[`docs/migration/api-keys-to-rbac.md`](docs/migration/api-keys-to-rbac.md)
(API-key → RBAC, Bundle 1) and [`docs/migration/oidc-enable.md`](docs/migration/oidc-enable.md)
(API-key → OIDC, Bundle 2). The threat model lives at
[`docs/operator/auth-threat-model.md`](docs/operator/auth-threat-model.md).
Day-2 RBAC operations live at [`docs/operator/rbac.md`](docs/operator/rbac.md).
RFC + CWE evidence at [`docs/reference/auth-standards-implemented.md`](docs/reference/auth-standards-implemented.md).

## v2.0.68 - Image registry path changed ⚠️

> **Image registry path changed.** Starting this release, container images publish to `ghcr.io/certctl-io/certctl-server` and `ghcr.io/certctl-io/certctl-agent`. Existing pulls from `ghcr.io/shankar0123/certctl-{server,agent}:<tag>` continue to work for previously-published tags (the registry never deletes images), but the `:latest` tag at the old path stops moving forward at this release. Update your `docker pull` paths, `docker-compose.yml` `image:` keys, or Helm `image.repository` values to receive future updates. Old `git clone` / `git push` / install-script / API URLs continue to redirect forever - only the container-registry path changed.

This is the only operator-action-required change in v2.0.68. Other changes in this release are cosmetic URL refreshes after the GitHub-org transfer from `shankar0123/certctl` to `certctl-io/certctl` (HTTP redirects mean no other operator action is required) plus an internal contextcheck lint fix in the agent. Full commit list is on the [GitHub release page](https://github.com/certctl-io/certctl/releases/tag/v2.0.68).

---

certctl no longer maintains a hand-edited per-version changelog. Per-release
notes are auto-generated from commit messages between consecutive tags.

**Where to find what changed in a given release:**

- **[GitHub Releases](https://github.com/certctl-io/certctl/releases)** - every
  tag has an auto-generated "What's Changed" section pulled from the commits
  between that tag and the previous one, plus per-release supply-chain
  verification instructions (Cosign / SLSA / SBOM).
- **`git log <prev-tag>..<this-tag> --oneline`** - same content, locally.

**Why no hand-edited CHANGELOG.md:**

certctl is solo-developed and pushes directly to master. Maintaining a
hand-edited CHANGELOG meant the file drifted (entries piled into
`[unreleased]` and never got promoted to per-version sections when tags were
cut). A stale CHANGELOG is worse than no CHANGELOG - it signals abandoned
maintenance to security-conscious operators doing diligence.

The auto-generated release notes work here because commit messages follow a
descriptive convention: `<area>: <summary>` with a longer body for non-trivial
changes (see `git log v2.0.50..HEAD` for the established pattern). Anyone
reading the GitHub Releases page can see exactly what landed in each version
without depending on the author to manually update a separate file.

**For the historical record:** earlier versions (pre-v2.2.0 and the [2.2.0]
tag itself) had a hand-edited CHANGELOG. That content is preserved in
[git history](https://github.com/certctl-io/certctl/blob/v2.2.0/CHANGELOG.md)
at the v2.2.0 tag.
