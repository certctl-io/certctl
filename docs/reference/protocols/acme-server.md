# certctl ACME Server (Built-in)

> Last reviewed: 2026-05-05

certctl ships an RFC 8555 + RFC 9773 ARI ACME server endpoint at
`/acme/profile/<profile-id>/*`. Any RFC 8555 client (cert-manager 1.15+,
Caddy, Traefik, win-acme, certbot, Posh-ACME) can integrate with certctl
as an ACME issuer with no certctl-side modification — closing the
"deploy a certctl agent on every K8s node" friction that costs deals to
external PKI vendors today.

> **Phase status (2026-05-03):** Phase 6 — full operator-facing
> reference. The functional surface is complete (Phases 1a-5); this
> doc is the canonical procurement-readability reference. New: client-
> walkthrough docs for [cert-manager](./acme-cert-manager-walkthrough.md),
> [Caddy](./acme-caddy-walkthrough.md), and
> [Traefik](./acme-traefik-walkthrough.md); a dedicated
> [threat model](./acme-server-threat-model.md); a section-by-section
> RFC 8555 + RFC 9773 conformance statement; a 5-failure-mode
> troubleshooting playbook; a tested-clients version pinning table.
> Track shipped phases via `git log --grep='acme-server:'`.

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
| `CERTCTL_ACME_SERVER_ARI_ENABLED`                | `true`                 | 4     | Toggles the RFC 9773 ARI surface — both the `renewalInfo` URL in the directory document and the GET `/renewal-info/<cert-id>` handler. Set to `false` to drop ARI from the directory; ACME clients fall back to static renewal scheduling. |
| `CERTCTL_ACME_SERVER_ARI_POLL_INTERVAL`          | `6h`                   | 4     | Server-policy `Retry-After` value the ARI handler emits on a 200 response. RFC 9773 §4.2 leaves this server-policy. Tighten to `1h` for short-lived certs; loosen to `24h` for standard 90-day certs. |
| `CERTCTL_ACME_SERVER_RATE_LIMIT_ORDERS_PER_HOUR` | `100`                  | 5     | Per-account orders/hour cap. `0` disables. Hits return RFC 7807 + RFC 8555 §6.7 `urn:ietf:params:acme:error:rateLimited` with `Retry-After`. In-memory token-bucket; restart wipes the counter (eventual-consistency caps are acceptable). |
| `CERTCTL_ACME_SERVER_RATE_LIMIT_CONCURRENT_ORDERS` | `5`                  | 5     | Per-account cap on simultaneously-active orders (status in pending/ready/processing). `0` disables. Same RFC 7807 + RFC 8555 §6.7 problem shape as the per-hour cap. |
| `CERTCTL_ACME_SERVER_RATE_LIMIT_KEY_CHANGE_PER_HOUR` | `5`                | 5     | Per-account key-rollover cap. `0` disables. Default 5/hour: rollovers should be rare; a flood is an attack signal. |
| `CERTCTL_ACME_SERVER_RATE_LIMIT_CHALLENGE_RESPONDS_PER_HOUR` | `60`       | 5     | Per-challenge-id respond cap. `0` disables. Defends against retry storms from a misbehaving client. Keyed by challenge-id (not account-id) so a flood against one challenge doesn't drain the account's whole budget. |
| `CERTCTL_ACME_SERVER_GC_INTERVAL`                | `1m`                   | 5     | Tick interval for the ACME GC scheduler loop. On each tick: (1) DELETE used / expired nonces; (2) UPDATE pending authzs whose `expires_at < NOW()` to `expired`; (3) UPDATE pending/ready/processing orders whose `expires_at < NOW()` to `invalid`. Each sweep is a single SQL statement; the loop is idempotent + bounded by a 1m per-sweep timeout. `0` disables the loop. |

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

## Auth-mode decision tree

Use `trust_authenticated` when:

- The certctl deployment serves **internal-only PKI** (intranet certs,
  service-mesh certs, IoT bootstrap). Identifiers in your CSRs are
  controlled by your infrastructure, not by the public Internet.
- You don't have HTTP/DNS reachability **from certctl-server back to
  the ACME client's solver** (e.g., the client lives in an isolated
  network segment certctl-server can't reach).
- You want the simplest cert-manager integration: cert-manager submits
  a CSR, certctl issues; no out-of-band ownership proof.
- You're issuing under your own root CA whose trust is operator-managed
  (NOT WebPKI). Public CAs cannot use this mode — RFC 8555 §8 ownership
  proof is non-negotiable for public-trust roots.

Use `challenge` when:

- The deployment is **public-trust-style PKI** — even if your root is
  privately operated, you want CA/Browser Forum-style ownership-proof
  semantics so a stolen account key can't be used to issue for arbitrary
  identifiers.
- You have HTTP-01 / DNS-01 / TLS-ALPN-01 reachability from the
  certctl-server to the ACME client's solver. (HTTP-01 needs port 80
  ingress to the client; DNS-01 needs DNS recursion; TLS-ALPN-01 needs
  port 443 ingress.)
- You want defense-in-depth: an account-key compromise costs the
  attacker nothing without also compromising the solver-side
  infrastructure.

A single certctl-server can run both modes simultaneously — the auth
mode is a per-profile column on `certificate_profiles.acme_auth_mode`,
read at request time. Operators flip a profile's mode via SQL or the
profile API, and the next order picks up the new mode without restart.

## Endpoints

Routes registered in `internal/api/router/router.go::RegisterHandlers`:

| Method | Path                                                  | RFC ref         | Auth     | Description |
|--------|-------------------------------------------------------|-----------------|----------|-------------|
| GET    | `/acme/profile/{id}/directory`                        | RFC 8555 §7.1.1 | unauth   | Per-profile directory document. |
| HEAD   | `/acme/profile/{id}/new-nonce`                        | RFC 8555 §7.2   | unauth   | Returns 200 + Replay-Nonce header. |
| GET    | `/acme/profile/{id}/new-nonce`                        | RFC 8555 §7.2   | unauth   | Returns 204 + Replay-Nonce header. |
| POST   | `/acme/profile/{id}/new-account`                      | RFC 8555 §7.3   | JWS jwk  | Register a new account; idempotent re-registration of an existing JWK returns the existing row. |
| POST   | `/acme/profile/{id}/account/{acc_id}`                 | RFC 8555 §7.3.2 + §7.3.6 | JWS kid | Update contact list, deactivate, or POST-as-GET (RFC 8555 §6.3) to fetch the account. |
| POST   | `/acme/profile/{id}/new-order`                        | RFC 8555 §7.4   | JWS kid | Submit an order; identifier validation runs before order creation. |
| POST   | `/acme/profile/{id}/order/{ord_id}`                   | RFC 8555 §7.4   | JWS kid | POST-as-GET fetch of an order's current state. |
| POST   | `/acme/profile/{id}/order/{ord_id}/finalize`          | RFC 8555 §7.4   | JWS kid | Submit the CSR + finalize. Issues + persists managed cert row + version. |
| POST   | `/acme/profile/{id}/authz/{authz_id}`                 | RFC 8555 §7.5   | JWS kid | POST-as-GET fetch of an authorization. |
| POST   | `/acme/profile/{id}/challenge/{chall_id}`             | RFC 8555 §7.5.1 | JWS kid | Submit a challenge for validation. Dispatches to a bounded-concurrency worker pool; clients poll authz for the eventual result. |
| POST   | `/acme/profile/{id}/cert/{cert_id}`                   | RFC 8555 §7.4.2 | JWS kid | POST-as-GET cert chain download (PEM). |
| POST   | `/acme/profile/{id}/key-change`                       | RFC 8555 §7.3.5 | JWS kid (outer) + jwk (inner) | Doubly-signed account-key rollover. |
| POST   | `/acme/profile/{id}/revoke-cert`                      | RFC 8555 §7.6   | JWS kid OR jwk | Revoke a cert via the issuing account's key OR the cert's own private key. Routes through the certctl revocation pipeline. |
| GET    | `/acme/profile/{id}/renewal-info/{cert_id}`           | RFC 9773        | unauth   | Fetch the suggested renewal window for a cert (cert-id is `base64url(AKI).base64url(serial)` per RFC 9773 §4.1). Response carries `Retry-After`. |
| GET    | `/acme/directory`                                     | RFC 8555 §7.1.1 | unauth   | Shorthand path; mirrors per-profile when `CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID` is set. |
| HEAD   | `/acme/new-nonce`                                     | RFC 8555 §7.2   | unauth   | Shorthand. |
| GET    | `/acme/new-nonce`                                     | RFC 8555 §7.2   | unauth   | Shorthand. |
| POST   | `/acme/new-account`                                   | RFC 8555 §7.3   | JWS jwk  | Shorthand. |
| POST   | `/acme/account/{acc_id}`                              | RFC 8555 §7.3.2 + §7.3.6 | JWS kid | Shorthand. |
| POST   | `/acme/new-order`                                     | RFC 8555 §7.4   | JWS kid | Shorthand. |
| POST   | `/acme/order/{ord_id}`                                | RFC 8555 §7.4   | JWS kid | Shorthand. |
| POST   | `/acme/order/{ord_id}/finalize`                       | RFC 8555 §7.4   | JWS kid | Shorthand. |
| POST   | `/acme/authz/{authz_id}`                              | RFC 8555 §7.5   | JWS kid | Shorthand. |
| POST   | `/acme/cert/{cert_id}`                                | RFC 8555 §7.4.2 | JWS kid | Shorthand. |
| POST   | `/acme/key-change`                                    | RFC 8555 §7.3.5 | JWS kid (outer) + jwk (inner) | Shorthand. |
| POST   | `/acme/revoke-cert`                                   | RFC 8555 §7.6   | JWS kid OR jwk | Shorthand. |
| GET    | `/acme/renewal-info/{cert_id}`                        | RFC 9773        | unauth   | Shorthand. |

After Phase 4, the full RFC 8555 + RFC 9773 surface is live. RFC 8739
(short-lived certs) and EAB enforcement remain follow-up work; cert-
manager + boulder-tested clients work today against the surface above.

## RFC 8555 + RFC 9773 conformance statement

Honest disclosure of what's implemented, where, and what's not. Procurement
engineers running gap analyses against cert-manager + Let's Encrypt's
conformance posture should read this section before anything else.

### Implemented

| Section | Surface | Phase | First commit |
|---------|---------|-------|--------------|
| RFC 8555 §6.2  | JWS auth + RS256/ES256/EdDSA allow-list | 1b | `27bd660` |
| RFC 8555 §6.3  | POST-as-GET                            | 1b | `27bd660` |
| RFC 8555 §6.4  | URL-header binding to request URL      | 1b | `27bd660` |
| RFC 8555 §6.5  | Replay-Nonce + DB-backed nonce store   | 1a | `e146b00` |
| RFC 8555 §6.7  | RFC 7807 problem documents             | 1a | `e146b00` |
| RFC 8555 §7.1  | Directory                              | 1a | `e146b00` |
| RFC 8555 §7.2  | new-nonce HEAD + GET                   | 1a | `e146b00` |
| RFC 8555 §7.3  | new-account + idempotent re-registration | 1b | `27bd660` |
| RFC 8555 §7.3.2 + §7.3.6 | account update + deactivation | 1b | `27bd660` |
| RFC 8555 §7.3.5 | doubly-signed key rollover            | 4 | `0299e4a` |
| RFC 8555 §7.4  | new-order + finalize + cert download   | 2 | `4ee486e` |
| RFC 8555 §7.5  | authz POST-as-GET                      | 2 | `4ee486e` |
| RFC 8555 §7.5.1 | challenge response                    | 3 | `7e22204` |
| RFC 8555 §7.6  | revoke-cert (kid + jwk paths)          | 4 | `0299e4a` |
| RFC 8555 §8.3  | HTTP-01 challenge validator            | 3 | `7e22204` |
| RFC 8555 §8.4  | DNS-01 challenge validator             | 3 | `7e22204` |
| RFC 8737       | TLS-ALPN-01 challenge validator        | 3 | `7e22204` |
| RFC 9773       | ACME Renewal Information (ARI)         | 4 | `0299e4a` |

### Not implemented (procurement-honest)

| Spec area | Status | Notes |
|-----------|--------|-------|
| RFC 8555 §7.3.4 — External Account Binding (EAB) | **Not implemented.** | Advertised in directory `meta.externalAccountRequired` but enforcement is a follow-up. Operators relying on EAB for account-creation gating should layer an upstream WAF. |
| RFC 8555 §8.4 + §7.4 — Wildcard with `*.` prefix > 1 level | **Not implemented.** | Single-level wildcards (e.g. `*.example.com`) work end-to-end. Multi-level wildcards (`*.*.example.com`) are RFC-spec-ambiguous and rejected at the identifier-validation layer. |
| RFC 8738 — Short-lived certs | **Not implemented.** | Operators wanting <7-day validity tune the bound issuer's TTL directly via `CertificateProfile.MaxTTLSeconds`; the ACME wire shape doesn't expose a separate notion. |
| Cross-CA proxying | **Not implemented.** | Each profile binds to one issuer. Multi-CA federation (one ACME account → multi-CA selection per identifier) is roadmap. |
| RFC 8555 §6.7 — `accountDoesNotExist` problem with hint URL | Partial. | Sentinel returns `accountDoesNotExist`; the optional hint URL embedding the `kid` is not emitted. cert-manager doesn't consume it. |

If a procurement-side gap analysis turns up something not in either
table above, the answer is "we don't know yet" — operator-side issues
welcome.

## Finalize routing through `CertificateService.Create` (Phase 2 architecture)

The finalize path mirrors how every other certctl issuance surface
(EST, SCEP, agent, REST API) routes through the canonical pipeline:

1. JWS-verify the request (`internal/api/acme/jws.go`).
2. Validate the CSR's DNS-name set equals the order's identifier set
   exactly (case-folded). Mismatches return RFC 8555
   `urn:ietf:params:acme:error:badCSR`.
3. Update the order row to `status=processing` (`s.tx.WithinTx` +
   `auditService.RecordEventWithTx` — atomic with audit row).
4. Issue the cert via the bound profile's `IssuerConnector` adapter
   (same `IssueCertificate(ctx, commonName, sans, csrPEM, ekus,
   maxTTLSeconds, mustStaple)` call EST/SCEP/agent take).
5. Insert the `managed_certificates` row via
   `service.CertificateService.Create(ctx, *ManagedCertificate, actor)`.
   Source is stamped `domain.CertificateSourceACME` so operators can
   bulk-revoke ACME-issued certs by filtering on `Source=ACME`.
6. Insert the `certificate_versions` row +
   transition the order to `status=valid` with `certificate_id` set
   (one final `WithinTx` covering both writes + the audit row).

This means RenewalPolicy, CertificateProfile, per-issuer-type
Prometheus metrics, audit rows, and revocation-pipeline integration
all apply uniformly to ACME-issued certs via the same code path that
already serves EST/SCEP/agent/REST issuance.

The atomicity boundary: there is a brief window between step 5 (cert
exists) and step 6 (order shows valid) where the order row still says
`processing`. Phase 5's GC scheduler reconciles. The actor string on
audit rows is `acme:<account-id>`.

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
| 2     | live        | orders + authzs + finalize + cert download (trust_authenticated mode end-to-end) |
| 3     | live        | HTTP-01 + DNS-01 + TLS-ALPN-01 challenge validation (challenge mode end-to-end) |
| 4     | live        | key rollover (RFC 8555 §7.3.5) + revoke-cert (§7.6) + ARI (RFC 9773) |
| 5     | live        | rate limits + GC sweeper + kind-driven cert-manager integration test + lego conformance harness + k6 ACME-flow scenario |
| 6     | live        | full operator-facing reference + walkthroughs (cert-manager / Caddy / Traefik) + threat model + RFC-8555 conformance statement + troubleshooting + version pinning |

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

## Phase 4 — key rollover, revocation, ARI

### How do I rotate my ACME account key?

RFC 8555 §7.3.5 defines a doubly-signed JWS for the rollover. The OUTER
JWS is signed by the OLD account key (kid path); its payload IS the
INNER JWS, which is signed by the NEW account key (jwk path). cert-
manager and lego do this for you transparently — `lego renew --key-rotate`
or the cert-manager `Issuer.spec.acme.privateKeySecretRef` rollover.

Server-side validation:

1. Outer JWS verifies against the registered account's current key.
2. Inner JWS verifies against the embedded NEW jwk (proves possession).
3. Inner payload `account` matches outer `kid`.
4. Inner payload `oldKey` thumbprint-equals the registered key.
5. Inner protected `url` equals outer protected `url`.
6. New JWK thumbprint not already registered against the same profile.
7. `SELECT … FOR UPDATE` on the account row serializes concurrent
   rollovers; the loser sees the winner's new thumbprint and is told
   to retry (409).

### How do I revoke an ACME-issued cert?

Two auth paths per RFC 8555 §7.6:

- **kid path:** sign with your account key. The server checks the
  account "owns" the cert via `acme_orders.certificate_id` lookup.
- **jwk path:** sign with the cert's own private key. The server
  extracts the cert's public key, computes the JWK, and asserts it
  matches the embedded jwk thumbprint.

Either path routes through `service.RevocationSvc.RevokeCertificateWithActor`
— the same pipeline the GUI revoke button, bulk-revocation, and the
ACME-consumer issuer use. So the cert-row update + revocation row + audit
row are all atomic in one `WithinTx`, the issuer is best-effort
notified, and the OCSP response cache is invalidated.

Reason codes follow RFC 5280 §5.3.1; codes 8 (removeFromCRL) and 10
(aACompromise) are not in certctl's `domain.ValidRevocationReasons`
set so they clamp to `unspecified`.

### What is ARI?

RFC 9773 ACME Renewal Information. Clients GET
`/acme/profile/<id>/renewal-info/<cert-id>` (unauthenticated) and
receive a JSON document with `suggestedWindow.start` and `.end` —
the server's recommendation for when to renew. The response also
carries `Retry-After` (RFC 9773 §4.2) hinting at the next-poll cadence.

Cert-id format is `base64url(authorityKeyIdentifier).base64url(serial)`
per RFC 9773 §4.1.

Window math:

- Cert with a bound renewal policy: window starts at
  `notAfter - RenewalWindowDays`, ends at `notAfter - RenewalWindowDays/2`.
  So a 30-day window cert with notAfter 2026-06-30 emits start=2026-05-31,
  end=2026-06-15. Boulder-shape default that lets cert-manager schedule
  inside our renewal window.
- No policy: window is the last 33% of validity.
- Past expiry: window is "now" → "now + 24h" (renew immediately).

Disable ARI globally with `CERTCTL_ACME_SERVER_ARI_ENABLED=false`. The
URL drops out of the directory; the route is still registered but
returns 404 — clients fall back to static renewal scheduling.

## Phase 5 — operational guidance

### Rate limiting

Production deployments serving multiple ACME profiles or fleets should
keep the default rate limits in place. The four caps:

- `RATE_LIMIT_ORDERS_PER_HOUR` (100) — per-account new-order cap. A
  cert-manager Certificate that auto-renews at the 1/3 mark of its
  validity (90-day cert → ~30-day renewal) consumes ~12 orders/year
  per managed Certificate. 100/hour is generous for any plausible
  fleet.
- `RATE_LIMIT_CONCURRENT_ORDERS` (5) — per-account cap on
  pending/ready/processing orders. Stops a runaway client from
  starving DB-row throughput. Tune up only if you observe legitimate
  bursts.
- `RATE_LIMIT_KEY_CHANGE_PER_HOUR` (5) — rollovers are rare; a flood
  is an attack signal. Tune down to 1/hour if your operator
  procedure mandates manual rollovers only.
- `RATE_LIMIT_CHALLENGE_RESPONDS_PER_HOUR` (60) — per-challenge cap,
  defends against retry storms.

Hits return RFC 8555 §6.7 `rateLimited` Problem with a `Retry-After`
header. cert-manager 1.15+ honors the header; lego too. Older clients
may not — that's the client's problem, not certctl's.

The buckets are **in-memory + per-replica**. A 3-replica certctl-
server fleet behind a load balancer effectively has 3× the configured
throughput (each replica's bucket fills independently). For
deployments where this matters operationally, the right answer is a
shared rate-limit store — that's a follow-up; not blocking for the
current threat model where same-account requests typically pin to
the same replica via session affinity.

### GC sweeper

The scheduler runs the GC sweep every `GC_INTERVAL` (default 1m). Each
sweep is three independent SQL statements:

1. `DELETE FROM acme_nonces WHERE used = TRUE OR expires_at < NOW()`.
2. `UPDATE acme_authorizations SET status='expired' WHERE status='pending' AND expires_at < NOW()`.
3. `UPDATE acme_orders SET status='invalid', error=... WHERE status IN ('pending','ready','processing') AND expires_at < NOW()`.

Each statement is bounded by a 1-minute per-sweep timeout. A failing
sweep is logged + retried on the next tick; a tick that overruns its
budget is skipped (the existing-tick atomic-Bool guard prevents
overlap). Counts are exposed via `certctl_acme_gc_*` Prometheus
metrics.

### cert-manager integration test

`make acme-cert-manager-test` brings up a kind cluster, installs
cert-manager 1.15.0, helm-deploys certctl-server with
`acmeServer.enabled=true`, and verifies a Certificate resource issues
end-to-end. Skipped in CI by default (kind is too heavy for per-PR);
operators run locally on workstation. See
`deploy/test/acme-integration/` for the YAML + Go test harness.

### lego RFC conformance harness

`make acme-rfc-conformance-test` drives lego v4 against a hermetic
certctl-server stack, exercising register → new-order → finalize.
Operators run this when shipping behavior changes to the ACME surface
to confirm a real third-party client still works.

### k6 ACME flows scenario

`deploy/test/loadtest/k6/acme_flow.js` exercises the unauthenticated
surface (directory + new-nonce + ARI) at 100 VUs × 5m. JWS-signed
flows are out of scope for k6 (no JWS support); they're covered by
the lego conformance harness above. Baseline numbers + thresholds in
`deploy/test/loadtest/README.md`.

## Troubleshooting

The five failure modes operators hit most often + the canonical fix
for each.

### `cert-manager logs: 400 Bad Request: badNonce`

**Cause:** Either a nonce was replayed (a buggy client retries the
same JWS), the cert-manager + certctl-server clocks differ by more
than `CERTCTL_ACME_SERVER_NONCE_TTL` (default 5 min), or the
nonce-store row was reaped between issuance and use.

**Fix:** First check NTP on both sides. If clocks are healthy,
lengthen `CERTCTL_ACME_SERVER_NONCE_TTL` to 10m or 15m. If the
problem persists, check for a multi-replica certctl-server fleet
without sticky session affinity — the nonce DB row lives on one
replica; if the JWS POST hits a different replica before replication
catches up, you observe spurious `badNonce`. Solution: pin client
sessions to a single replica via load-balancer cookie / `kid`-hash
routing, OR shorten replication lag if your DB is the bottleneck.

### `cert-manager logs: x509: certificate signed by unknown authority`

**Cause:** cert-manager refuses to talk to the directory URL because
its TLS chain doesn't terminate at a root in cert-manager's trust
store. certctl-server's bootstrap cert (Phase 1a, `deploy/test/certs/server.crt`)
is self-signed.

**Fix:** Add the `caBundle` field to your `ClusterIssuer.spec.acme` —
see the [TLS trust bootstrap](#tls-trust-bootstrap-read-this-before-configuring-cert-manager)
section above for the 3-step recipe. This is **the** single biggest
first-time-deploy footgun on the cert-manager integration path.

### HTTP-01 validator returns `connection refused`

**Cause:** The HTTP-01 solver's Ingress / Service is not reachable
from certctl-server's network. Common subcases: (a) the cert-manager
http-solver pod is on a private network certctl-server can't reach;
(b) a firewall blocks port 80 inbound to the solver's address; (c)
the Ingress class annotation doesn't match an installed ingress
controller; (d) your DNS still points at an old IP.

**Fix:** From the certctl-server pod, `curl -v
http://<identifier>/.well-known/acme-challenge/<token>` and read the
network error. If the curl fails the same way, the network path is
the issue. If curl works but the validator fails, check the validator
log lines — the SSRF guard rejects reserved IPs (RFC1918, link-local,
cloud-metadata 169.254.169.254). Public-trust style profiles that
need to reach RFC1918 solvers must be moved to `trust_authenticated`
mode OR the solver must be exposed on a routable address.

### DNS-01 validator returns `NXDOMAIN`

**Cause:** DNS provider hasn't propagated the `_acme-challenge.<domain>`
TXT record yet. Most providers have a 30s-2m propagation lag. cert-manager
retries by default, but Phase-5 rate limits (default 60/hour per
challenge-id) can truncate the retry budget.

**Fix:** Verify TXT propagation with `dig +short TXT _acme-challenge.<domain>
@<your-resolver>`. If the answer is empty, the issue is upstream. If
it's populated but certctl reports NXDOMAIN, check
`CERTCTL_ACME_SERVER_DNS01_RESOLVER` (default `8.8.8.8:53`) is
reachable from certctl-server's network egress. Operators on isolated
networks need a private resolver; configure accordingly + own the
cache-poisoning posture (see [threat
model](./acme-server-threat-model.md)).

### Certificate Ready=False with `rejectedIdentifier`

**Cause:** The CSR includes an identifier (CommonName or SAN) that the
bound certificate profile's policy rejects. certctl runs syntactic +
profile-policy validation **before** order creation; the order never
reaches the database.

**Fix:** The reject reason is in the `subproblems` array of the RFC
8555 §6.7 problem document. Decode the JSON, look at `subproblems[].detail`,
and adjust either the CSR or the profile policy. Common causes:
SAN-not-in-`AllowedIdentifierWildcards`, EKU-not-in-`AllowedEKUs`,
TTL-exceeds-`MaxTTLSeconds`. Validation logic lives in
`internal/api/acme/identifier.go::ValidateIdentifiers` +
`internal/domain/profile.go` — read those if the profile-policy rule
isn't obvious.

## Version pinning + tested clients

certctl's ACME server is tested against the following client versions.
Other versions probably work; these are the ones the integration suite
exercises end-to-end.

| Client | Tested version | Where it's pinned |
|--------|----------------|-------------------|
| cert-manager | 1.15.0 | `deploy/test/acme-integration/cert-manager-install.sh::CERT_MANAGER_VERSION` |
| lego (RFC 8555 conformance harness) | v4.x latest | `deploy/test/acme-integration/conformance-lego.sh` (operator installs via `go install github.com/go-acme/lego/v4/cmd/lego@latest`) |
| kind (cluster bootstrap) | v0.20+ | `deploy/test/acme-integration/kind-config.yaml` schema requirement |
| Caddy | 2.7.x | Phase 6 walkthrough (`docs/acme-caddy-walkthrough.md`) |
| Traefik | 3.0+ | Phase 6 walkthrough (`docs/acme-traefik-walkthrough.md`) |

Operators reporting issues with untested-version clients should include
the client version + the precise wire-level error (curl-captured request
+ response body) so we can pin a regression test if applicable.

## FAQ

### Why two auth modes? Isn't `challenge` strictly more secure?

`challenge` is strictly more secure for **public-trust** PKI — RFC 8555
§8 ownership proof is the entire point of cert-manager + Let's Encrypt.
For **internal PKI**, the threat model is different: the network itself
is the security boundary (mTLS service mesh, firewalled VPC, identifier-
namespace controlled by the operator). Forcing every internal cert to
go through a solver round-trip adds operational toil with no security
gain. `trust_authenticated` is the certctl-specific mode that
acknowledges this — the ACME account is the proof, not the solver.

### How does this differ from `cert-manager → Let's Encrypt with certctl as a separate step`?

Two integrations vs one. With certctl as the ACME endpoint, cert-manager
does its native flow (Certificate → Order → CSR → Secret) and certctl
mints the cert directly, recording it under its own
`managed_certificates` table with full audit + renewal-policy + bulk-
revocation surface. With Let's Encrypt as the ACME endpoint, you have
to run a separate cert-manager-uploads-to-certctl webhook OR maintain
two parallel cert tracks. The native-ACME-server path is operationally
simpler.

### Can I use ACME endpoints from outside the K8s cluster?

Yes. The endpoints are HTTPS over the certctl-server's listener (port
8443 by default). Caddy on a VM, win-acme on a Windows server, or
Posh-ACME on a Mac all integrate against
`https://<certctl-server>:8443/acme/profile/<profile-id>/directory`.
The TLS-trust-bootstrap requirement applies the same way — see the
[Caddy walkthrough](./acme-caddy-walkthrough.md) for the OS-trust-store
recipe.

### How do I migrate manually-issued certs to ACME-issued ones?

Not yet automatic. Operators migrating: keep the old `managed_certificates`
rows; create new ones via the ACME flow; flip targets one by one. A
dedicated bulk-migration tool is on the roadmap (post-2.1.0). Track
via the master prompt's roadmap section in
`cowork/acme-server-endpoint-prompt.md`.

### What audit-log events fire on each ACME operation?

Every state mutation writes an `audit_events` row. Actor strings:
`acme:<account-id>` for kid-path requests; `acme-cert-key:<serial>`
for jwk-path revoke; `acme-system:gc` for scheduler-driven sweeps.
Event-name catalog:

| Event name | Fired by | Resource type |
|------------|----------|---------------|
| `acme_account_created` | new-account | `acme_account` |
| `acme_account_contact_updated` | account update | `acme_account` |
| `acme_account_deactivated` | account deactivate | `acme_account` |
| `acme_account_key_rolled` | key-change | `acme_account` |
| `acme_order_created` | new-order | `acme_order` |
| `acme_order_finalized` | finalize | `acme_order` |
| `acme_challenge_processing` | challenge-respond (dispatch) | `acme_challenge` |
| `acme_challenge_completed` | validator callback | `acme_challenge` |
| `certificate_revoked` | revoke-cert (routes through `RevocationSvc`) | `certificate` |

Querying by actor prefix (`actor LIKE 'acme:%'`) reconstructs the full
history of any ACME-issued cert.

### Is there a threat model document?

Yes — [`docs/acme-server-threat-model.md`](./acme-server-threat-model.md).
Read before writing a security review.

## See also

- [cert-manager integration walkthrough](./acme-cert-manager-walkthrough.md)
- [Caddy integration walkthrough](./acme-caddy-walkthrough.md)
- [Traefik integration walkthrough](./acme-traefik-walkthrough.md)
- [Threat model](./acme-server-threat-model.md)
- [TLS trust bootstrap reference](./tls.md)
- [Architecture (control-plane)](./architecture.md)
