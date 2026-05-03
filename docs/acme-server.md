# certctl ACME Server (Built-in)

certctl ships an RFC 8555 + RFC 9773 ARI ACME server endpoint at
`/acme/profile/<profile-id>/*`. Any RFC 8555 client (cert-manager 1.15+,
Caddy, Traefik, win-acme, certbot, Posh-ACME) can integrate with certctl
as an ACME issuer with no certctl-side modification — closing the
"deploy a certctl agent on every K8s node" friction that costs deals to
external PKI vendors today.

> **Phase status (2026-05-03):** Phase 4 — closes the RFC 8555 surface
> beyond the issuance happy-path: doubly-signed key rollover (§7.3.5),
> revoke-cert via either account-key or cert-key (§7.6), and RFC 9773
> ACME Renewal Information. ACME clients can now rotate their account
> keys, revoke certs through the ACME surface (rather than only the
> certctl GUI/API), and fetch ARI for proactive renewal scheduling.
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
