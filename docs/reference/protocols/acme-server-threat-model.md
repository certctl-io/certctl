# ACME Server — Threat Model

> Last reviewed: 2026-05-05

Security posture for the certctl ACME server endpoint
(`/acme/profile/<id>/*`). Read this before opening a PR that changes
the JWS verifier, the challenge validators, the rate limiter, or the
GC sweeper.

The threat model lives in this dedicated doc (rather than `docs/acme-server.md`)
because security-review reviewers want a single concentrated reference.
Production deployments under audit should treat this doc as the
canonical answer to "how does certctl resist X?"

## Threat surface map

The ACME server has four ingress surfaces:

1. **JWS-authenticated POST endpoints** — new-account, new-order,
   finalize, key-change, revoke-cert, account update, order POST-as-GET.
   Authenticated by an ECDSA / RSA / EdDSA signature over the request.
2. **Unauthenticated GET endpoints** — directory, new-nonce, ARI
   (renewal-info). Read-only; no authn.
3. **Outbound challenge validators** — HTTP-01, DNS-01, TLS-ALPN-01.
   The certctl-server initiates outbound calls to operator-provided
   identifiers (the SAN list of the requested cert).
4. **Scheduler-driven GC sweeper** — internal-only; no inbound surface.

Threat actors:

- **External Internet attacker** — no certctl credentials; can hit
  unauthenticated endpoints + observe TLS metadata.
- **Authenticated ACME account holder (low-trust)** — has a valid
  account on a profile but should be bounded by profile policy +
  rate limits.
- **On-path attacker** between certctl-server and a challenge target
  (HTTP-01 / DNS-01 / TLS-ALPN-01).
- **Compromised cert holder** — has the private key of a previously-
  issued cert and wants to revoke/exfiltrate.
- **Malicious operator with profile-write access** — can change a
  profile's `acme_auth_mode` or policy, but is the trusted boundary
  per certctl's threat model. Out of scope here; covered by certctl's
  RBAC + audit log.

## JWS forgery resistance

The verifier (`internal/api/acme/jws.go`) accepts only the closed
allow-list `{RS256, ES256, EdDSA}`. The allow-list is passed to
`jose.ParseSigned` so go-jose rejects every other algorithm at parse
time, before any signature work.

Specific attacks blocked:

- **Algorithm confusion (`alg: none`)** — RFC 7515 §6.1's classic
  unauthenticated-fallback. Not in allow-list; rejected at parse.
- **HS256 substitution (alg-confusion via symmetric)** — symmetric
  algs aren't in the allow-list; rejected at parse.
- **Replayed nonce** — every JWS carries a nonce consumed via
  `acme_nonces.UPDATE … WHERE used = FALSE` (a single statement;
  Postgres row-locking serializes the writes). A second consume of
  the same nonce sees `RowsAffected=0` and the verifier returns
  `badNonce`.
- **URL spoofing** — the protected-header `url` field MUST match the
  request URL exactly (RFC 8555 §6.4); a JWS signed for one URL
  cannot be replayed against another.
- **Multi-signature JWS** — RFC 8555 §6.2 forbids; the verifier
  rejects `len(jws.Signatures) != 1` explicitly.
- **kid-vs-jwk confusion** — exactly one MUST be present per RFC 8555
  §6.2; both-present and neither-present are rejected.
- **kid round-trip mismatch** — the verifier's `AccountKID` closure
  computes the canonical kid URL for the resolved account-id and
  compares to the inbound `kid`; cross-profile replay is rejected
  because the canonical URL differs.

The doubly-signed key-rollover JWS (RFC 8555 §7.3.5, Phase 4) gets
its own dedicated verifier in `internal/api/acme/keychange.go`.
Inner-only invariants enforced: MUST use `jwk` not `kid`, payload
`account` MUST equal outer `kid`, payload `oldKey` MUST canonicalize-
equal the registered key (RFC 7638 thumbprint, constant-time
compare), inner `url` MUST equal outer `url`.

## Nonce store integrity

Nonces are persisted in PostgreSQL (`acme_nonces` table; migration
000025) with a TTL set by `CERTCTL_ACME_SERVER_NONCE_TTL` (default
5 min). The Phase 5 GC sweeper deletes used / expired rows every 1
minute by default.

Why DB-backed and not in-memory:

- **Survives restart** — a multi-replica certctl-server fleet behind
  a load balancer can issue a nonce on replica A and consume it on
  replica B. In-memory state would force sticky sessions globally,
  which the operator can't guarantee in all topologies.
- **Atomic consume** — a single `UPDATE ... WHERE used = FALSE`
  statement is the consume primitive; Postgres row-locking guarantees
  exactly one of two concurrent consumes wins.
- **Expiry-bounded** — even if the GC sweeper were disabled, the
  nonce TTL is enforced at consume time
  (`AND expires_at > NOW()` in the UPDATE).

A nonce-store-side compromise would let an attacker forge nonces.
Mitigation: the nonce table is in the same Postgres instance certctl
already trusts; a DB compromise is broader than ACME-specific.

## HTTP-01 SSRF resistance

The HTTP-01 validator (Phase 3, `internal/api/acme/validators.go`)
fetches `http://<identifier>/.well-known/acme-challenge/<token>`
where the identifier is operator/client-controlled. Without
mitigation, this is a textbook SSRF surface — internal services on
RFC1918 / link-local / cloud-metadata addresses would be reachable.

Mitigations (defense in depth):

1. **Pre-dial check** — `validation.ValidateSafeURL` rejects URLs
   whose host parses as a literal reserved IP. Cheap early bail.
2. **Per-dial check** — `validation.SafeHTTPDialContext` is installed
   on the `http.Transport`. Every dial re-resolves DNS, rejects
   reserved IPs, and **pins the resolved IP** (`net.JoinHostPort(ips[0],
   port)`) so a racing DNS rebinding cannot substitute a different IP
   between resolve and connect.
3. **Per-redirect check** — Go's HTTP client re-dials on 3xx; the
   `DialContext` runs again, applying the same SSRF guards.
4. **Body cap** — the validator's `io.LimitReader` caps response
   bodies at 16 KiB. A misbehaving target cannot DoS the validator
   pool with a multi-GB response.
5. **Bounded redirects** — the validator caps redirects at 10 (Go
   default). A redirect-loop target is bounded.

Reserved IP set: loopback (127.0.0.0/8 + ::1), link-local
(169.254.0.0/16 + fe80::/10), all RFC1918 (10/8, 172.16/12, 192.168/16),
cloud-metadata literals (169.254.169.254 explicitly), broadcast,
multicast, IPv4-mapped-IPv6 to a reserved IPv4. See
`internal/validation/ssrf.go::isReservedIPForDial` for the full set.

CodeQL alert #23 flags `client.Do(req)` in the SCEP-probe call site
as `go/request-forgery` despite the dial-time guard; the analyzer
can't trace through a custom `Transport.DialContext`. Operator-
acknowledged false positive (CLAUDE.md task #10) — see the SCEP
probe's same-shaped defense for the audit trail.

## DNS-01 cache poisoning posture

The DNS-01 validator queries
`_acme-challenge.<domain>` against a single resolver configured by
`CERTCTL_ACME_SERVER_DNS01_RESOLVER` (default `8.8.8.8:53`).

Threat: an operator running a private resolver (typical in air-gapped
deployments) inherits that resolver's cache-poisoning posture. A
poisoned resolver could attest a TXT record the legitimate domain
owner never published, allowing an attacker who controls the
resolver to forge ACME challenges.

Mitigation:

- Default `8.8.8.8:53` is Google Public DNS — DNSSEC-validating,
  operationally hardened, well-monitored.
- Operators choosing a private resolver own the cache-poisoning
  posture. The doc explicitly flags this in
  `docs/acme-server.md` § Configuration.
- DNSSEC-validation is **not** enforced by the validator itself —
  the validator trusts the resolver's answer. Operators wanting
  strict DNSSEC validation should use a DNSSEC-validating resolver
  (e.g. `1.1.1.1` or a self-hosted Unbound).

## TLS-ALPN-01 challenge interception

RFC 8737 §3 explicitly says the validator MUST NOT verify the
challenge target's certificate chain — the proof lives in the
embedded `id-pe-acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31)
of the cert presented during the TLS handshake, not in the chain
itself.

Implementation: `internal/api/acme/validators.go::TLSALPN01Validator`
sets `tls.Config.InsecureSkipVerify = true` with a dedicated
`//nolint:gosec` annotation citing RFC 8737 §3 and the L-001
documentation row in `docs/tls.md`.

What this means for on-path attackers:

- An on-path attacker between certctl-server and the challenge target
  CAN intercept the TLS handshake and present a forged cert. The
  proof is the embedded extension byte-equality, which the attacker
  cannot generate without the account key — so interception alone
  doesn't grant cert issuance.
- An attacker who has the account key already controls the account
  per RFC 8555; the TLS-ALPN-01 validator's interception window adds
  no incremental capability.

The integrity property TLS-ALPN-01 actually provides: the challenge
target proves possession of the account-key-derived key authorization
on a TLS connection bound to the requested identifier (port 443 of
the SAN). Operators wanting CA/Browser-Forum-style WebPKI strictness
should run a dedicated public-trust CA, not certctl.

## Rate-limit tuning

Phase 5 in-memory token buckets with per-(action, key) isolation.
Defaults:

- `RATE_LIMIT_ORDERS_PER_HOUR=100` per account.
- `RATE_LIMIT_CONCURRENT_ORDERS=5` per account (pending/ready/processing).
- `RATE_LIMIT_KEY_CHANGE_PER_HOUR=5` per account.
- `RATE_LIMIT_CHALLENGE_RESPONDS_PER_HOUR=60` per challenge-id.

Tuning:

- **Too loose** → enables abuse vectors. A compromised account could
  burn DB-row throughput; a runaway client could fill the validator
  pool.
- **Too tight** → legitimate flake-out. cert-manager's exponential
  backoff after a `rateLimited` problem is conservative; a 1-hour
  cooldown is a long time for an operator hitting an unexpected limit.

Defaults are intentionally conservative on the loose-side — 100/hour
is generous for any plausible per-account fleet (a 50k-cert
deployment renewing at the 1/3-validity mark consumes ~12
orders/year/cert ≈ 600k orders/year ≈ 70 orders/hour even spread
evenly across accounts). Tighter limits are appropriate for
deployments with many low-trust accounts.

The buckets are in-memory + per-replica. A 3-replica certctl-server
fleet effectively has 3× the configured per-account throughput
because each replica's bucket fills independently. For deployments
where this matters operationally, the right answer is a shared rate-
limit store (Redis / Postgres-backed); not blocking for current
threat model where same-account requests typically pin to the same
replica via session affinity.

## Audit trail

Every ACME state mutation writes a row to `audit_events`. Actor strings
distinguish the auth path:

- `acme:<account-id>` — kid-path requests (the requesting account
  signed the JWS).
- `acme-cert-key:<serial>` — jwk-path revoke (the cert's own private
  key signed the JWS).
- `acme-system:gc` — scheduler-driven sweeps (no client request).

Operators querying by actor prefix can reconstruct the full history
of any ACME-issued cert. See
`docs/acme-server.md` § FAQ "What audit-log events fire" for the
event-name catalog.

## Out-of-scope threats

Documented to set scope expectations for security reviewers:

- **DDoS at the TLS layer** — the certctl-server's TLS listener +
  upstream load balancer / WAF handle this. The ACME-specific rate
  limits don't substitute for upstream DDoS protection.
- **cert-manager-side compromise** — if cert-manager is compromised,
  it has both the account key and the private keys of every issued
  cert. Out of certctl's trust boundary; operators run cert-manager
  with the same care they'd run any other secret-bearing operator.
- **Compromised certctl-server filesystem** — the bootstrap CA key
  lives at `deploy/test/certs/ca.key` (or the operator-managed
  equivalent). A filesystem compromise is broader than ACME-specific
  and is covered by certctl's HSM / signer-driver architecture (see
  `docs/architecture.md` "Signer abstraction").
- **Postgres compromise** — the nonce table, account JWKs, and
  audit log all live in the same Postgres instance. A DB compromise
  is broader than ACME-specific and is the operator's responsibility
  to mitigate via standard DB-hardening practices.
- **Supply-chain attacks against go-jose / lib/pq** — handled by
  Dependabot + the `make verify` security gate; not ACME-specific.

## See also

- [`docs/acme-server.md`](./acme-server.md) — operator-facing reference.
- [`docs/tls.md`](./tls.md) — TLS posture, including the L-001
  table of `InsecureSkipVerify` justifications (TLS-ALPN-01 row).
- [`internal/api/acme/jws.go`](../internal/api/acme/jws.go) — verifier
  source.
- [`internal/api/acme/validators.go`](../internal/api/acme/validators.go)
  — challenge validator pool.
- [`internal/validation/ssrf.go`](../internal/validation/ssrf.go) —
  SSRF-defense primitives.
