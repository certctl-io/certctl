# Authentication & authorization threat model

> Last reviewed: 2026-05-09

This document describes the attack surface around authentication and
authorization in certctl after Bundle 1 (the RBAC primitive) lands.
It complements [`rbac.md`](rbac.md) - that doc explains how to use
the controls; this one explains what those controls defend against
and which threats they explicitly do NOT close.

For Bundle 2's OIDC + sessions extensions, this document will be
updated. The Bundle 1 boundary is "API-key auth + RBAC primitive +
day-0 bootstrap"; OIDC-federated humans, session cookies,
revocation lists, WebAuthn, and break-glass local accounts are
Bundle 2 scope.

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

## Threats Bundle 1 does NOT close

These are NOT defended; some are deferred to Bundle 2, others
are out-of-scope for the project entirely.

1. **OIDC / SAML / WebAuthn federation** - Bundle 2.
2. **Session management** - there is no session cookie, no
   server-side revocation list. Each Bearer token is the bearer
   credential. To revoke a key, delete the `actor_roles` rows or
   remove the env-var entry; there is no "log out everywhere"
   button. Bundle 2.
3. **Local password accounts (break-glass)** - Bundle 2.
4. **Time-bound role grants / JIT elevation** - the schema
   reserves `actor_roles.expires_at` but no UI/API to set it.
   Bundle 2 or v3.
5. **MFA / hardware tokens for the operator console** - 
   Bundle 2.
6. **Rate limiting on the bootstrap endpoint** - the endpoint
   is one-shot by construction (consumed flag + admin-existence
   probe), so a brute-force attack on the token has at most the
   single attempt before the path closes. Per-IP rate limiting
   on the broader API is still in place via Bundle C's
   `middleware.NewRateLimiter`.
7. **`scope_id` FK enforcement** - operators can grant a
   permission at scope `profile`/`p-bogus` without the bogus
   profile existing. The gate still works (no rows match at
   request time) but a strict 404 on grant would be cleaner. See
   `RoleRepository.AddPermission` `TODO(bundle-2)` comment in
   `internal/repository/postgres/auth.go`.
8. **OIDC-first-admin bootstrap** - Bundle 1 ships only the
   env-var-token strategy. Bundle 2 adds the OIDC-group-claim
   strategy alongside (the `Strategy` interface in
   `internal/auth/bootstrap/` is already in place).
9. **GUI E2E suite via Playwright** - the prompt asked for
   nine end-to-end flow tests. Bundle 1 ships 19 React Testing
   Library + Vitest tests covering the same surface; full
   Playwright land in Phase 12-extended work.

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

## Cross-references

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
