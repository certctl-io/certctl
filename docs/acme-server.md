# certctl ACME Server (Built-in)

certctl ships an RFC 8555 + RFC 9773 ARI ACME server endpoint at
`/acme/profile/<profile-id>/*`. Any RFC 8555 client (cert-manager 1.15+,
Caddy, Traefik, win-acme, certbot, Posh-ACME) can integrate with certctl
as an ACME issuer with no certctl-side modification — closing the
"deploy a certctl agent on every K8s node" friction that costs deals to
external PKI vendors today.

> **Phase status (2026-05-03):** Phase 1b — directory + new-nonce +
> new-account + account/{id} update + JWS verifier (RFC 7515 + go-jose
> v4). An ACME client can now run new-account end-to-end and register
> against a profile. Orders + challenges + key rollover + revocation +
> ARI land in subsequent phases. Track shipped phases via
> `git log --grep='acme-server:'`.

## Configuration

All ACME-server config uses the `CERTCTL_ACME_SERVER_*` env-var prefix
(distinct from `CERTCTL_ACME_*` which configures the consumer-side
issuer connector). The struct definition lives in
`internal/config/config.go::ACMEServerConfig`.

| Env var                                          | Default                | Phase | Description |
|--------------------------------------------------|------------------------|-------|-------------|
| `CERTCTL_ACME_SERVER_ENABLED`                    | `false`                | 1a    | Master enable flag. Phase 1a's handler is constructed unconditionally so the registry shape stays stable; routes are registered in `internal/api/router/router.go::RegisterHandlers` regardless. Operators flip this on after configuring per-profile auth_mode. |
| `CERTCTL_ACME_SERVER_DEFAULT_AUTH_MODE`          | `trust_authenticated`  | 1a    | Default value for `certificate_profiles.acme_auth_mode` on newly-created profiles. Existing profiles retain their stored value. Per-profile column is the source of truth at request time. |
| `CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID`         | `""`                   | 1a    | When set, `/acme/*` shorthand mirrors `/acme/profile/<DefaultProfileID>/*` for single-profile deployments. When empty, requests to the shorthand return RFC 7807 + RFC 8555 §6.7 `userActionRequired`. |
| `CERTCTL_ACME_SERVER_NONCE_TTL`                  | `5m`                   | 1a    | How long an issued ACME nonce remains valid before the JWS verifier (Phase 1b) returns `urn:ietf:params:acme:error:badNonce` per RFC 8555 §6.5.1. Tune up if cert-manager + certctl clocks frequently skew. |
| `CERTCTL_ACME_SERVER_TOS_URL`                    | `""`                   | 1a    | Optional `meta.termsOfService` URL in the directory document. |
| `CERTCTL_ACME_SERVER_WEBSITE`                    | `""`                   | 1a    | Optional `meta.website` URL in the directory document. |
| `CERTCTL_ACME_SERVER_CAA_IDENTITIES`             | (empty)                | 1a    | Comma-separated `meta.caaIdentities` list. |
| `CERTCTL_ACME_SERVER_EAB_REQUIRED`               | `false`                | 1a    | `meta.externalAccountRequired` advertisement. EAB enforcement is a follow-up; Phase 1a only advertises. |
| `CERTCTL_ACME_SERVER_ORDER_TTL`                  | `24h`                  | 2     | Reserved field, parsed in Phase 1a so operators can set it ahead of Phase 2's order endpoints. |
| `CERTCTL_ACME_SERVER_AUTHZ_TTL`                  | `24h`                  | 2     | Reserved. |
| `CERTCTL_ACME_SERVER_HTTP01_CONCURRENCY`         | `10`                   | 3     | Reserved. |
| `CERTCTL_ACME_SERVER_DNS01_RESOLVER`             | `8.8.8.8:53`           | 3     | Reserved. |
| `CERTCTL_ACME_SERVER_DNS01_CONCURRENCY`          | `10`                   | 3     | Reserved. |
| `CERTCTL_ACME_SERVER_TLSALPN01_CONCURRENCY`      | `10`                   | 3     | Reserved. |

## Per-profile auth mode

Two modes per `certificate_profiles.acme_auth_mode`:

- **`trust_authenticated`** (default for internal PKI). The JWS-
  authenticated ACME account is trusted to issue certs for any
  identifier the profile policy allows; there is no per-identifier
  ownership proof. The most common certctl use case.
- **`challenge`**. Full HTTP-01 + DNS-01 + TLS-ALPN-01 validation per
  RFC 8555 §8. Required when certctl is exposing public-trust-style PKI.

A single certctl-server can serve both modes simultaneously — the mode
is read from the bound profile's column at request time, not cached at
server start. Operators can flip a profile's mode via SQL and the next
order picks up the new mode without restart.

The `CERTCTL_ACME_SERVER_DEFAULT_AUTH_MODE` env var sets the default
value for newly-created profiles (e.g. via the certctl API). Existing
profile rows retain whatever value they were created with.

## TLS trust bootstrap (read this before configuring cert-manager)

When certctl-server uses a self-signed TLS bootstrap cert
(`deploy/test/certs/server.crt` is the demo default; see
[`docs/tls.md`](./tls.md)), cert-manager 1.15+ will refuse to talk to
the directory URL unless the certctl root is trusted. The fix lives in
`ClusterIssuer.spec.acme.caBundle`:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: certctl-test
spec:
  acme:
    server: https://certctl.example.com:8443/acme/profile/prof-corp/directory
    email: ops@example.com
    caBundle: |
      LS0tLS1CRUdJTi...   # base64-encoded PEM of certctl's self-signed root
    privateKeySecretRef:
      name: certctl-test-account-key
    solvers:
      - http01:
          ingress:
            class: nginx
```

The `caBundle` value is the base64-encoded PEM of the root that signed
your certctl-server's TLS certificate. Extract it from your operator
bootstrap (e.g. `cat deploy/test/certs/ca.crt | base64 -w0`).

This is the single biggest first-time-deploy footgun on the cert-manager
integration path. The full cert-manager walkthrough lands in Phase 6;
the `caBundle` requirement is flagged here in Phase 1a's docs because
operators hit it the moment they try to point a real ACME client at
certctl.

## Endpoints (Phase 1b)

Routes registered in `internal/api/router/router.go::RegisterHandlers`:

| Method | Path                                       | RFC ref         | Auth     | Description |
|--------|--------------------------------------------|-----------------|----------|-------------|
| GET    | `/acme/profile/{id}/directory`             | RFC 8555 §7.1.1 | unauth   | Per-profile directory document. |
| HEAD   | `/acme/profile/{id}/new-nonce`             | RFC 8555 §7.2   | unauth   | Returns 200 + Replay-Nonce header. |
| GET    | `/acme/profile/{id}/new-nonce`             | RFC 8555 §7.2   | unauth   | Returns 204 + Replay-Nonce header. |
| POST   | `/acme/profile/{id}/new-account`           | RFC 8555 §7.3   | JWS jwk  | Register a new account; idempotent re-registration of an existing JWK returns the existing row. |
| POST   | `/acme/profile/{id}/account/{acc_id}`      | RFC 8555 §7.3.2 + §7.3.6 | JWS kid | Update contact list, deactivate, or POST-as-GET (RFC 8555 §6.3) to fetch the account. |
| GET    | `/acme/directory`                          | RFC 8555 §7.1.1 | unauth   | Shorthand path; mirrors per-profile when `CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID` is set. |
| HEAD   | `/acme/new-nonce`                          | RFC 8555 §7.2   | unauth   | Shorthand. |
| GET    | `/acme/new-nonce`                          | RFC 8555 §7.2   | unauth   | Shorthand. |
| POST   | `/acme/new-account`                        | RFC 8555 §7.3   | JWS jwk  | Shorthand. |
| POST   | `/acme/account/{acc_id}`                   | RFC 8555 §7.3.2 + §7.3.6 | JWS kid | Shorthand. |

The remaining RFC 8555 endpoints (`new-order`, `order/{id}`,
`order/{id}/finalize`, `authz/{id}`, `challenge/{id}`, `cert/{id}`,
`key-change`, `revoke-cert`, `renewal-info`) are advertised in the
directory document but not yet served — clients hitting them get a 404
until subsequent phases land. The directory document includes their
URLs because RFC 8555 doesn't permit a partial directory.

## JWS verification (Phase 1b)

Every JWS-authenticated POST runs through the verifier at
`internal/api/acme/jws.go::VerifyJWS`. The verifier enforces:

1. The JWS parses as a flattened single-signature object (multi-sig is
   rejected per RFC 8555 §6.2).
2. The signature algorithm is in the closed allow-list `{RS256, ES256,
   EdDSA}` per RFC 8555 §6.2 — `none`, `HS256`, and every other alg
   are refused at parse time.
3. The protected header carries exactly one of `kid` (registered
   account) or `jwk` (new-account flow); endpoints declare which they
   require.
4. The protected header `url` matches the inbound request URL exactly.
5. The protected header `nonce` is consumed against the
   `acme_nonces` store; missing / replayed / expired nonces return
   `urn:ietf:params:acme:error:badNonce` per RFC 8555 §6.5.1.
6. On the `kid` path: the kid URL round-trips against the canonical
   per-profile shape, the referenced account exists, and its status
   is `valid`. Deactivated / revoked accounts cannot authenticate.
7. The signature verifies against the resolved key (registered
   account's stored JWK on the kid path; embedded jwk on the jwk path).

Every state-mutating account operation (create, contact update,
deactivate) writes its `acme_accounts` row and an `audit_events` row
inside one `repository.Transactor.WithinTx` call — the canonical
certctl atomicity contract (matches `service.CertificateService.Create`
at `internal/service/certificate.go:131`).

## Phases (cross-reference)

| Phase | Status      | Surface |
|-------|-------------|---------|
| 1a    | live        | directory + new-nonce + per-profile routing |
| 1b    | live        | new-account + account/{id} + JWS verifier (RFC 7515 + go-jose v4) |
| 2     | not yet     | orders + authzs + finalize + cert download (trust_authenticated mode end-to-end) |
| 3     | not yet     | HTTP-01 + DNS-01 + TLS-ALPN-01 challenge validation |
| 4     | not yet     | key rollover + revocation + ARI (RFC 9773) |
| 5     | not yet     | cert-manager integration test + production hardening |
| 6     | not yet     | full operator-facing reference + walkthroughs + threat model |

Track shipped phases via `git log --grep='acme-server:' --oneline`.

## Operational notes (Phase 1a)

- **Schema:** `migrations/000025_acme_server.up.sql` adds 5 ACME tables
  + the `certificate_profiles.acme_auth_mode` column. Phase 1a actively
  uses only `acme_nonces`. The full schema ships now so the migration
  is stable and Phases 1b-4 don't need additional `CREATE TABLE`
  migrations.

- **Replay protection:** nonces are persisted in `acme_nonces` (NOT
  in-memory). They survive server restart, which is required for the
  RFC 8555 §6.5 replay defense to hold against a multi-replica
  certctl-server fleet behind a load balancer.

- **Metrics:** the service layer exposes per-op atomic counters via
  `service.ACMEService.Metrics().Snapshot()`:
  - `certctl_acme_directory_total`
  - `certctl_acme_directory_failures_total`
  - `certctl_acme_new_nonce_total`
  - `certctl_acme_new_nonce_failures_total`

  Phase 1b will extend with `new_account` counters; Phase 2 with order
  / finalize / cert; Phase 3 with per-challenge-type counters.

- **Audit:** Phase 1a is read-mostly (directory + nonce). Phase 1b's
  account-creation path will route through the canonical
  `s.tx.WithinTx(...)` + `auditService.RecordEventWithTx(...)` pattern
  so every account state mutation is paired with an `audit_events`
  row.
