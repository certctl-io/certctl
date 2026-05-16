# certctl Security Posture & Operator Guidance

> Last reviewed: 2026-05-11

This document collects the operator-facing security guidance that the source
code's per-finding comment blocks reference. Each section names the audit
finding it closes, the threat model, and the operator action required (if
any).

## OCSP responder availability

**Audit reference:** CWE-770 (uncontrolled resource consumption); RFC
6960 (OCSP); RFC 7633 (Must-Staple).

certctl ships an OCSP responder at `/.well-known/pki/ocsp/{issuer_id}/{serial}`
that signs a fresh response per request. The unauth handler chain
applies the same per-key rate limiter the authenticated chain uses;
per-IP keying applies because OCSP traffic is unauthenticated. Without
this defense an attacker could DoS the responder and force fail-open
relying parties to accept revoked certificates as valid.

The rate limiter alone does not solve the underlying revocation-bypass risk.
**The architectural fix is for issued certificates to carry the OCSP
Must-Staple TLS Feature extension** (RFC 7633, OID 1.3.6.1.5.5.7.1.24). When
present, conforming TLS clients refuse to negotiate a session unless the
server staples a fresh signed OCSP response in the TLS handshake. This shifts
revocation enforcement from the client's discretion (which most fail-open by
default) to a hard requirement that the connection cannot complete without
proof of non-revocation.

### Operator action

For certificates issued to systems where revocation correctness matters:

1. **Configure the issuer profile to set `must-staple: true`.** Out-of-the-box
   profiles in `migrations/seed.sql` do not set this; operators add it at
   profile-creation time via the API or by editing seed data.
2. **Confirm the relying party honors the extension.** OpenSSL ≥ 1.1.0,
   Firefox, and Chrome 84+ all enforce Must-Staple. Older clients silently
   ignore it.
3. **Confirm the deployment target is configured for OCSP stapling** so the
   server can actually deliver the stapled response in the handshake.
 - **nginx:** `ssl_stapling on; ssl_stapling_verify on;`
 - **Apache:** `SSLUseStapling on`
 - **HAProxy:** `set ssl ocsp-response /path/to/response.der`
 - **Envoy:** `ocsp_staple_policy: must_staple`

### What this does NOT cover

- **CRL fallback.** Must-Staple does not affect CRL behavior. Operators with
  CRL-based relying parties should use the rate-limit + caching defense
  alone; there is no client-side equivalent to Must-Staple for CRLs.
- **Self-issued certs in air-gapped networks.** When the relying party
  cannot reach the OCSP responder at all (the threat model the audit
  cited), Must-Staple is the only mechanism that closes the bypass. CRL
  distribution similarly requires the relying party to fetch the CRL,
  which is also subject to the same network-availability concern.

## Postgres transport encryption

**Audit references:** SEC-013 (advisory) and SEC-014 (host-port bind),
both closed in Sprint 2 of the 2026-Q2 acquisition audit
(2026-05-16).

The full upgrade procedure (sslmode flags, CA bundle paths, Helm chart
values, AWS RDS / Google Cloud SQL / Azure Database notes) lives at
[docs/operator/database-tls.md](database-tls.md). The summary of the
two operator-visible defenses certctl ships:

### SEC-014 — Postgres host port is loopback-only

`deploy/docker-compose.yml` and `deploy/docker-compose.test.yml` both
publish Postgres on `127.0.0.1:5432:5432` rather than `5432:5432`.
The default Docker port-binding behavior is to bind to `0.0.0.0`,
which exposes Postgres on every interface of the host — including any
public-facing NICs the operator did not realize were attached. The
loopback bind closes that footgun without breaking the
certctl-server hop (which goes over the `certctl-network` Docker
bridge, not over the host port).

Operators who genuinely need to reach Postgres from another host —
e.g. a separate metrics box running `postgres_exporter` — should
either (1) attach that host into the same Docker network, (2) tunnel
through SSH (`ssh -L`), or (3) re-publish the port with explicit
`bind:` configuration and a documented network-layer access control.
Loosening the loopback bind without one of those is a regression.

### SEC-013 — advisory WARN on external `sslmode=disable`

`internal/config/config.go::Validate` emits an `slog.Warn` (NOT a
fail-closed error) when `CERTCTL_DATABASE_URL` parses as a Postgres
URL with `sslmode=disable` AND the host is outside the local
safelist (`localhost` / `127.0.0.1` / `::1` / `postgres` /
`certctl-postgres` / `*.svc.cluster.local`). The advisory exists
because the legitimate compose / Helm topology genuinely uses
`sslmode=disable` over the Docker bridge — failing closed would
break the production-shaped quickstart — but pointing
`CERTCTL_DATABASE_URL` at a managed-Postgres host (RDS, Cloud SQL,
Azure Database) without flipping `sslmode` to `verify-full` puts
the entire control plane's Postgres traffic on the wire in
cleartext. The WARN surfaces that landmine on every boot so the
operator notices it in the journal even if the rest of the boot
sequence looks healthy.

To clear the WARN: set `CERTCTL_DATABASE_URL` to a URL with
`sslmode=verify-full` and `sslrootcert=<ca-bundle-path>`. The full
procedure (CA-bundle materialization, Helm chart values, secret-
manager wiring) is in
[docs/operator/database-tls.md](database-tls.md).

## Encryption at rest

PBKDF2-SHA256 at 600,000 rounds (OWASP 2024 Password
Storage Cheat Sheet floor) for the operator-supplied passphrase that
derives the AES-256-GCM key for sensitive config columns. v3 blob format
with a per-ciphertext random salt; v1/v2 read fallback for legacy rows.
See [internal/crypto/encryption.go](../../internal/crypto/encryption.go) and
the accompanying tests for the format spec.

## Authentication surface

Two layers decide auth-exempt status:

1. **Router layer:** `internal/api/router/router.go::AuthExemptRouterRoutes`
 - the endpoints registered via direct `r.mux.Handle` without going
   through the middleware chain (`/health`, `/ready`, `/api/v1/auth/info`,
   `/api/v1/version`, plus `/api/v1/auth/bootstrap` GET + POST for the
   first-admin path).
2. **Dispatch layer:** `internal/api/router/router.go::AuthExemptDispatchPrefixes`
 - URL-prefix routing in `cmd/server/main.go::buildFinalHandler` for
   `/.well-known/pki/*`, `/.well-known/est/*`, `/.well-known/est-mtls`,
   and `/scep[/...]*` (incl. `/scep-mtls`).

Both lists have AST-walking regression tests (`auth_exempt_test.go`) that
fail CI if a new bypass lands without updating the documented constant.

### Role-based authorization

Role-based authorization runs on top of API-key authentication. Every
gated handler routes through the `auth.RequirePermission` middleware
(or its router-level wrap `rbacGate`); the middleware resolves the
actor's effective permissions via the service-layer
`Authorizer.CheckPermission` and returns HTTP 403 BEFORE the handler
body runs on miss. The seven default roles (`admin` / `operator` /
`viewer` / `agent` / `mcp` / `cli` / `auditor`), 33-permission
canonical catalogue, and the auditor split (`r-auditor` holds only
`audit.read` + `audit.export`) are seeded by migration 000029.

For the operator how-to, see [`rbac.md`](rbac.md). For the
threat model + compliance mapping, see
[`auth-threat-model.md`](auth-threat-model.md). For the upgrade
flow from an API-key-only deployment, see
[`docs/migration/api-keys-to-rbac.md`](../migration/api-keys-to-rbac.md).

### Day-0 admin bootstrap

Fresh deployments where no admin actor exists yet can mint the
first admin via `POST /api/v1/auth/bootstrap` - set
`CERTCTL_BOOTSTRAP_TOKEN`, POST a single curl with the token, and
the server returns the plaintext key value once. The token is
constant-time-compared; the strategy is one-shot via mutex; the
admin-existence probe re-closes the path once an admin lands.
The token is NEVER logged. The minted plaintext key flows only
into the HTTP response body. See
[`rbac.md`](rbac.md#day-0-bootstrap-first-admin-path) for the
full flow.

### Approval-bypass closure

`CertificateProfile.RequiresApproval=true` profiles route both
issuance/renewal AND profile edits through the
`ApprovalService` two-person integrity gate. The flip-flop loophole
(an admin disabling approval, mutating, re-enabling) is closed by
gating profile-edit through the same approval flow. Same-actor
self-approve is rejected at the service layer with
`ErrApproveBySameActor`. See
[`docs/reference/profiles.md`](../reference/profiles.md) for the
full gate semantics.

### OIDC federation

OIDC SSO runs on top of the API-key + RBAC foundation. Operators
configure one or more identity providers (Keycloak, Authentik, Okta,
Auth0, Entra ID, or Google Workspace via Keycloak broker); end users
sign in at the IdP, certctl validates the returned ID token, and a
session cookie is minted.

The token-validation pipeline pins:

- Algorithm allow-list: RS256 / RS512 / ES256 / ES384 / EdDSA only.
  HS256 / HS384 / HS512 / `none` are rejected at the service-layer
  sentinel level.
- IdP-downgrade-attack defense at provider creation AND every
  RefreshKeys: the IdP's advertised
  `id_token_signing_alg_values_supported` is intersected with the
  allow-list; a provider that advertises HS-family is rejected
  before any token is signed under the weak alg.
- Exact `iss` match (`ErrIssuerMismatch`).
- `aud` membership + `azp` for multi-aud tokens (per OIDC core
  §3.1.3.7 step 5).
- `at_hash` REQUIRED-when-access_token-present (a tightening of the
  spec MAY → MUST so a substituted access token cannot ride alongside
  a clean ID token).
- Single-use state + nonce (32-byte random server-generated;
  atomic `DELETE...RETURNING` on consume).
- PKCE-S256 mandatory; `plain` rejected.
- Configurable `iat` window (default 300s, capped 600s).
- JWKS cache with operator-triggered RefreshKeys + auto-refresh on
  TTL expiry (default 3600s); JWKS-fetch failure during a key
  rotation returns 503 to the in-flight login (existing sessions
  untouched).

OIDC `client_secret` is encrypted at rest via AES-256-GCM (v3 blob
format: magic 0x03 + salt(16) + nonce(12) + ciphertext+tag) using
the `CERTCTL_CONFIG_ENCRYPTION_KEY` passphrase. The encryption
invariant is pinned by an integration test
(`internal/repository/postgres/oidc_encryption_invariant_test.go`)
that asserts ciphertext != plaintext + correct blob shape +
round-trip recovery + wrong-passphrase fails.

Per-IdP setup guides at
[`oidc-runbooks/index.md`](oidc-runbooks/index.md) cover Keycloak,
Authentik, Okta, Auth0, Entra ID, and Google Workspace.

### Sessions + back-channel logout

Successful OIDC login mints a session cookie:
`v1.<session_id>.<signing_key_id>.<base64url-no-pad(HMAC-SHA256)>`.
The HMAC input is **length-prefixed** as `len:sid:len:kid` to defeat
concatenation-collision attacks on bare-concat designs. Cookie
attributes:

- `HttpOnly=true` (no JS access; defends XSS cookie theft).
- `Secure=true` (HTTPS-only; defends network MITM).
- `SameSite=Lax` default (configurable to Strict via
  `CERTCTL_SESSION_SAMESITE`).
- `Path=/`, host-only.

Idle timeout default 1h; absolute timeout default 8h; both
configurable via `CERTCTL_SESSION_IDLE_TIMEOUT` and
`CERTCTL_SESSION_ABSOLUTE_TIMEOUT`. The scheduler's
`sessionGCLoop` (default 1h interval) sweeps expired rows.

CSRF defense: plaintext CSRF token in the JS-readable
`certctl_csrf` cookie (intentionally `HttpOnly=false` for the GUI
to echo into the `X-CSRF-Token` header); SHA-256 hash on the
session row; `subtle.ConstantTimeCompare` in `CSRFMiddleware`.
API-key actors are CSRF-exempt (no session row in context).

Session signing keys rotate via `RotateSigningKey`; the old key
stays valid for `CERTCTL_SESSION_SIGNING_KEY_RETENTION` (default
24h) so existing cookies validate during rollover. Past retention,
the old key's row is dropped and any cookie still signed under it
returns `ErrSigningKeyNotFound`. `EnsureInitialSigningKey` is
fail-fatal at server boot.

Back-channel logout per **OpenID Connect Back-Channel Logout 1.0**
(NOT RFC 8414): `POST /auth/oidc/back-channel-logout` accepts a
JWT-signed logout token from the IdP, validates the JWT against
the IdP's JWKS (same alg allow-list as login), pins required
claims (`iss` / `aud` / `iat` / `jti` / `events`; exactly one of
`sub` / `sid`; `nonce` MUST be absent), defeats replay via
`jti`-based deduplication, and revokes matching sessions.

For threat-model coverage of these surfaces, see
[`auth-threat-model.md`](auth-threat-model.md). For the
operator-runnable performance baselines, see
[`auth-benchmarks.md`](auth-benchmarks.md).

### OIDC first-admin bootstrap

Coexists with the env-var-token bootstrap path. When the
operator sets `CERTCTL_BOOTSTRAP_ADMIN_GROUPS` + (optionally)
`CERTCTL_BOOTSTRAP_OIDC_PROVIDER_ID`, the first user with one of
those IdP groups becomes admin on first login per tenant.
Subsequent users go through normal mapping. The admin-existence
probe ensures only one wins between the two bootstrap paths;
once any actor holds `r-admin`, the OIDC bootstrap hook silently
falls through to normal mapping. Audit row on every grant
(`bootstrap.oidc_first_admin`, `event_category=auth`).

### Break-glass admin

Default-OFF (`CERTCTL_BREAKGLASS_ENABLED=false`). When enabled,
the local-password admin path bypasses OIDC + group-claim layers;
intended ONLY for SSO-broken incidents.

- Argon2id with OWASP 2024 params (m=64 MiB, t=3, p=4, 16-byte
  salt, 32-byte output, per-password random salt, PHC-format
  hash). Hash column is `json:"-"` so handlers cannot wire-leak.
- Lockout state machine: 5 failures (default; configurable via
  `CERTCTL_BREAKGLASS_LOCKOUT_THRESHOLD`) within 1h reset window
  (`_LOCKOUT_RESET_INTERVAL`) trips a 30s lockout (`_LOCKOUT_DURATION`).
  Atomic single-statement IncrementFailure defeats concurrent
  racing attempts.
- Constant-time across all failure paths via `verifyDummy()` —
  wrong-password / locked-account / no-actor all take statistically
  indistinguishable time.
- Surface invisibility: when disabled, ALL four endpoints return
  HTTP 404 (NOT 403). Scanners cannot distinguish "endpoint
  disabled" from "endpoint doesn't exist".
- WARN log at server boot when `ENABLED=true`; audit row on every
  break-glass login (`auth.breakglass_login_*`,
  `event_category=auth`); WebAuthn/FIDO2 second factor pairing
  on the v3 roadmap (Decision 12).

Operator should DISABLE break-glass within 24h of SSO recovery
to avoid a permanent backdoor; the runbook at
[`auth-threat-model.md#break-glass-risks-phase-75`](auth-threat-model.md)
documents the full state machine.

### Demo-to-production cutover (Audit 2026-05-11 A-8)

Migration `000029_rbac.up.sql` unconditionally seeds an
`actor-demo-anon → r-admin` row into `actor_roles`. This row is the
runtime principal injected by the demo-mode middleware when
`CERTCTL_AUTH_TYPE=none`. Under any non-`none` auth type the row is
DORMANT — the middleware chain never resolves to it. But its existence
is a footgun: a future regression that resolves an unauthenticated
request to `actor-demo-anon` (a misrouted CORS preflight, a fallback in
a new auth-exempt route) would silently re-elevate to admin.

certctl-server detects this residue at startup and emits a WARN log +
an `auth.demo_residual_grants_detected` audit row listing every grant
present on `actor-demo-anon`. **Every production deploy will see this
WARN on first boot** — the migration baseline is part of the install,
not a side effect of running demo mode.

Operator workflow at production cutover:

1. Drain the WARN by calling the cleanup endpoint with an admin API key:

   ```bash
   curl -X POST --cacert deploy/test/certs/ca.crt \
        -H "Authorization: Bearer $ADMIN_KEY" \
        https://certctl.example.com:8443/api/v1/auth/demo-residual/cleanup
   # → {"removed": 1}
   ```

   The endpoint is gated `auth.role.assign` (admin-class) and refuses
   to run when `CERTCTL_AUTH_TYPE=none` (HTTP 503 — the residue IS the
   active runtime state at that auth type). The cleanup is idempotent;
   a second call returns `{"removed": 0}` and still leaves an audit row.

   Equivalent SQL for operators preferring direct DB access:

   ```sql
   DELETE FROM actor_roles WHERE actor_id = 'actor-demo-anon';
   ```

2. To make subsequent boots refuse startup if the row reappears (the
   most paranoid stance), set:

   ```
   CERTCTL_DEMO_MODE_RESIDUAL_STRICT=true
   ```

   With the flag set, any `actor-demo-anon` row under a non-`none`
   auth type causes certctl-server to log the WARN AND exit non-zero
   before binding the HTTPS listener. Default is `false` (WARN only).

3. The CI guard `scripts/ci-guards/no-new-synthetic-admin.sh` pins the
   set of source files that may reference the `actor-demo-anon` literal.
   New runtime code paths that resolve to the synthetic actor are
   rejected at PR time so the credibility gap stays closed.

### Migrating an existing deployment to OIDC

An existing API-key-only deployment that wants to add OIDC follows
the step-by-step at
[`docs/migration/oidc-enable.md`](../migration/oidc-enable.md):
configure CERTCTL_CONFIG_ENCRYPTION_KEY, pick + configure an IdP
per the relevant runbook, configure the certctl-side OIDCProvider
+ group→role mappings, verify the login flow against a single
test user, then announce the SSO endpoint to the rest of the
organization.

## Per-user rate limiting

Authenticated callers are bucketed by API-key name;
unauthenticated callers (probes, OCSP relying parties, EST/SCEP enrollees)
are bucketed by source IP. `RPS` and `BurstSize` are per-key budgets.
`PerUserRPS` / `PerUserBurstSize` give authenticated clients a separate
budget when set non-zero.

## API key rotation

**Audit reference:** L-004. CWE-924 (improper enforcement of message integrity during transmission in a communication channel) - operator UX variant.

certctl's API keys are configured via the `CERTCTL_API_KEYS_NAMED` env var
(format `name1:key1,name2:key2:admin`) and parsed at startup into an
in-memory list. There is no DB-resident key store, no GUI, no `/api/v1/keys`
endpoint - the env var IS the key inventory.

The env var supports a **double-key rotation window**: two entries can share a
name during the rollover, and both keys validate. Operators run the
rotation as:

1. **Generate the new key.** `openssl rand -hex 32` produces a 256-bit
   value with sufficient entropy.

2. **Append the new entry to `CERTCTL_API_KEYS_NAMED`** alongside the
   existing one:
   ```
   CERTCTL_API_KEYS_NAMED="alice:OLDKEY:admin,alice:NEWKEY:admin"
   ```
   Both entries MUST carry the same admin flag - startup fails loud if
   they don't (a non-admin shouldn't share an identity with an admin).

3. **Restart certctl.** A startup INFO log confirms the rotation window
   is active:
   ```
   INFO api-key rotation window active name=alice entries=2 see=docs/security.md::api-key-rotation
   ```

4. **Roll the new key out to all clients.** Both keys validate during
   this phase. Audit-trail actor + per-user rate-limit bucket stay
   consistent across the rollover (both entries produce the same
   `UserKey` context value, the shared name).

5. **Remove the old entry** from `CERTCTL_API_KEYS_NAMED`:
   ```
   CERTCTL_API_KEYS_NAMED="alice:NEWKEY:admin"
   ```

6. **Restart certctl.** OLDKEY now fails with 401. Rotation complete.

The rotation window has no operator-set timeout - it lasts for as long
as both entries are in the env var. Best practice is a 24-72h window
covering a full deploy cadence; if a client hasn't rolled to NEWKEY by
the end of step 4, extend the window before step 5.

### What the contract guarantees

- Two entries with the same `name`: **allowed** if both have the same
  `admin` flag.
- Two entries with the same `name` but mismatched admin: **rejected at
  startup** (privilege escalation guard).
- Two entries with the same `(name, key)` pair: **rejected at startup**
  (typo guard - rotation requires DIFFERENT keys under the same name).
- Single-entry steady state: the simple legacy behaviour.

### What the contract does NOT do

- **No automatic expiration of OLDKEY.** The operator removes the entry
  in step 5; certctl doesn't track timestamps. A future enhancement
  could add a `rotated_at` annotation if operators ask for it.
- **No GUI / API for key management.** Keys are env-var only by design;
  building a key-management surface is a separate feature project.
- **No revocation list.** If a key leaks, the only path is to remove it
  from the env var and restart. That's appropriate for a small env-var
  inventory; it would not scale to a per-user-key-issued model.

## Security carve-outs &amp; operator-tunable defaults

Phase 2 of the architecture diligence remediation (2026-05-13)
consolidated the following carve-outs into one canonical section so
operators reviewing security posture have a single search target. Each
entry cites the exact file:line of the carve-out, why it exists, and
what the operator should do.

### TLS verification — dev escape hatches

certctl has three `InsecureSkipVerify=true` sites that are dev/probe
escape hatches, never enabled by default in production:

- **Agent dev escape** — `cmd/agent/main.go:179` (wired from
  `cmd/agent/main.go:61` config field + `cmd/agent/main.go:1371` CLI
  flag). Operators flip this only when debugging an agent against a
  self-signed control plane that hasn't been added to the agent's
  trust store. Document as `--insecure-skip-verify` in the agent's
  install runbook; the agent logs a startup WARN any time the flag
  is set. SEC-M3 pins that the carve-out is intentional.
- **Agent verification probe** — `cmd/agent/verify.go:78`. The probe
  intentionally opens a TLS connection with verification disabled so
  it can inspect any certificate the endpoint serves (including
  self-signed or expired ones — that's the whole point of a probe).
  The probe never returns trust state to a security-relevant code
  path; it only reads cert metadata. SEC-M3 pins this.
- **tlsprobe (network scanner)** — `internal/tlsprobe/probe.go:54`.
  Same rationale as the agent verify probe — network discovery must
  introspect any certificate it finds, including the ones with the
  problems we're scanning for. SEC-M3 pins this.

### F5 target connector — `InsecureSkipVerify` per-config

The F5 target connector exposes an `Insecure: bool` field on its
per-target config blob (default `false`). When set,
`internal/connector/target/f5/f5.go:134` builds the HTTP client with
`InsecureSkipVerify: config.Insecure`. SEC-M5 closure: operator
opt-in for self-signed F5 BIG-IP device certs; mitigation is to run
the F5 + the proxy-agent on a network-segmented internal subnet.
Document in the F5 connector's per-target setup guide.

### ACME issuer — `CERTCTL_ACME_INSECURE` (now gated on ACK)

`internal/connector/issuer/acme/acme.go:201` builds the ACME HTTP
client with `InsecureSkipVerify: true` for the Pebble integration
test path. The per-issuer runtime setting comes from
`CERTCTL_ACME_INSECURE` (`internal/config/config.go:2116`); Phase 2
SEC-M4 closure (2026-05-13) added the fail-closed gate so the operator
must ALSO set `CERTCTL_ACME_INSECURE_ACK=true` for the server to boot.
Production deploys must never set either flag. The boot-time WARN log
at `cmd/server/main.go:611` continues to fire for the ACK'd case so
every restart logs the reminder.

### CSP `'unsafe-inline'` on `style-src`

`internal/api/middleware/securityheaders.go:58` ships the dashboard
CSP with `style-src 'self' 'unsafe-inline'`. This is required because
Tailwind compiles utility classes into a single stylesheet at build
time, but inline-style attributes appear in the dashboard via inline
`<svg>` elements + Recharts' `<ResponsiveContainer>` injecting inline
width/height. SEC-L1 closure: the carve-out is necessary today; the
planned tightening flow is the frontend audit's FE-H2 (icon library)
+ decorative-SVG sweep that then unlocks the CSP hardening (drops
`'unsafe-inline'`).

### Break-glass admin — Argon2id rest-defense reminder

The break-glass admin path (`docs/operator/runbooks/disaster-recovery.md`)
hashes the operator-supplied password with Argon2id and stores the
hash in the `breakglass_credentials` table. SEC-L2 reminder: the
strength of the rest-defense is operator-supplied — pick a password
with sufficient entropy (≥ 64 random bits via `openssl rand -base64
12`) and rotate after every use. Argon2id resists offline cracking
but an operator-supplied "Password123" hashes the same way.

### Body-size limit (1 MB default) — operator-tunable

The `http.MaxBytesReader` wrap caps inbound request bodies at 1 MB
by default. The cap is necessary defense against unbounded-body DOS
but catches legitimate operator workflows:

- Bulk truststore PEM bundle uploads (CA bundles for federated trust
  stores can be > 1 MB).
- Multi-MB CRL pushes via the CRL-cache endpoint.
- Bulk-import of certificates with embedded chains.

SEC-L3 closure: operators raise the cap via `CERTCTL_MAX_BODY_SIZE`
(units: bytes; e.g. `CERTCTL_MAX_BODY_SIZE=10485760` for 10 MB).
Document in `deploy/ENVIRONMENTS.md`.

### Demo Compose placeholder credentials

`deploy/docker-compose.demo.yml` ships `CERTCTL_AUTH_SECRET=change-me-in-production`,
`CERTCTL_CONFIG_ENCRYPTION_KEY=change-me-32-char-encryption-key`, and
`CERTCTL_API_KEY=change-me-in-production` as documented demo
defaults. The runtime `Validate()` fail-closed guards
(`internal/config/config.go::Validate`, Bundle 2 2026-05-12) refuse
to start if those literal strings reach a non-demo config. Phase 2
DEPL-M2 closure adds a CI guard
(`scripts/ci-guards/no-change-me-in-prod-compose.sh`) that fails the
build at PR time if a `change-me-*` literal leaks into a non-demo
compose file — catching the regression one layer before the runtime
guard fires.

### Kubernetes NetworkPolicy — operator-opt-in

`deploy/helm/certctl/templates/networkpolicy.yaml` ships the template
but `deploy/helm/certctl/values.yaml` defaults `networkPolicy.enabled:
false`. DEPL-M3 rationale: most Kubernetes clusters don't have a
NetworkPolicy controller installed (kind / minikube / fresh k3s); a
default-enabled NetworkPolicy renders fine but produces no
enforcement, and bare-metal `kube-router`-style controllers may
interpret a permissive default differently. Production deploys with a
real NetworkPolicy controller (Calico, Cilium, Antrea) flip the
values key to `true` and tune the policy in their values overlay.
Document the production-enable in
`docs/operator/runbooks/ha.md` (added Phase 2 DEPL-H1).

## Reporting a vulnerability

Email `certctl@proton.me`. Coordinated disclosure preferred; we will
acknowledge within 72h.
