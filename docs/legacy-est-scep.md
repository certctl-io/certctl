# Legacy EST / SCEP Clients — TLS 1.2 Reverse-Proxy Runbook

**Audit reference:** Bundle F / M-023. PCI-DSS v4.0 Req 4 §2.2.5; CWE-326.

certctl's control plane pins `tls.Config.MinVersion = tls.VersionTLS13`
(`cmd/server/tls.go:131`). Some embedded EST (RFC 7030) and SCEP (RFC 8894)
clients only speak TLS 1.0/1.1/1.2 — those clients cannot complete the
handshake against certctl directly. This runbook documents the supported
operator pattern: terminate the legacy TLS version at a front-door reverse
proxy and pass the request through to certctl over TLS 1.3.

## Why TLS 1.3 minimum

certctl's audit posture, the SOC 2 / PCI-DSS / NIST SP 800-57 compliance
mappings, and the M-001 PBKDF2 work factor all assume modern transport
crypto. TLS 1.2 with the cipher suites still in the wild has known
attack surface (BEAST, POODLE, ROBOT, raccoon — all CVE-categorized);
allowing TLS 1.2 directly on the certctl listener would invalidate the
guarantee that the server-side encryption chain is the strongest the
ecosystem currently supports.

## When this runbook applies

You need this if **all three** are true:

1. You operate certctl with EST or SCEP enabled (`CERTCTL_EST_ENABLED=true`
   or `CERTCTL_SCEP_ENABLED=true`).
2. Your enrolling clients are embedded devices (printers, network
   appliances, IoT boards, legacy MFPs, point-of-sale terminals) whose TLS
   stack pre-dates 2018 and only speaks TLS 1.2 or older.
3. Replacing those clients is not feasible on a 6-month horizon.

If your enrolling clients are modern (any current Linux/Windows/macOS
host, anything Go-based, anything Rust/Python/Node from 2019 onward),
they speak TLS 1.3 natively and this runbook is unnecessary — point them
straight at certctl on `:8443`.

## Architecture

```
                          ┌─── TLS 1.2/1.3 ────┐         ┌─── TLS 1.3 ───┐
[legacy EST/SCEP client]──>│ nginx / HAProxy   │────────>│ certctl :8443 │
                          │ reverse proxy      │         │               │
                          └────────────────────┘         └───────────────┘
        Allowed TLS 1.2                  Re-encrypts as TLS 1.3
```

The reverse proxy:

- Terminates the legacy-version TLS handshake on the public-facing port.
- Forwards the request to certctl over TLS 1.3 on a private network.
- (For EST mTLS) forwards the client certificate via an
  `X-SSL-Client-Cert` header that certctl reads only when the connection
  arrives from a configured-trusted source IP.

## nginx config

```nginx
upstream certctl_backend {
    # Private-network address; not reachable from outside the proxy host.
    server 10.0.0.10:8443;
}

server {
    listen 443 ssl http2;
    server_name est.example.com;

    # Public-facing legacy listener. ssl_protocols includes TLSv1.2 explicitly.
    # Keep ssl_ciphers conservative — only the strong AEAD suites that
    # PCI-DSS Req 4 §2.2.5 still allows under TLS 1.2.
    ssl_certificate     /etc/nginx/certs/est.example.com.fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/est.example.com.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;

    # mTLS for EST: optional client cert, verified against the EST CA.
    ssl_client_certificate /etc/nginx/certs/est-clients-ca.pem;
    ssl_verify_client      optional;

    location ~ ^/\.well-known/(est|pki) {
        # Forward the client cert (if presented) to certctl over the
        # private hop. The current certctl implementation IGNORES the
        # X-SSL-Client-Cert header (header-agnostic by default — see
        # the certctl-side configuration section below). EST/SCEP
        # authentication still works correctly because both protocols
        # carry their own auth (CSR signature for EST, challengePassword
        # for SCEP) inside the request body.
        proxy_set_header X-SSL-Client-Cert  $ssl_client_escaped_cert;
        proxy_set_header X-Forwarded-For    $remote_addr;
        proxy_set_header X-Forwarded-Proto  $scheme;

        # The proxy-to-certctl hop is itself TLS 1.3.
        proxy_pass https://certctl_backend;
        proxy_ssl_protocols TLSv1.3;
        proxy_ssl_verify    on;
        proxy_ssl_trusted_certificate /etc/nginx/certs/certctl-internal-ca.pem;
    }

    # SCEP endpoints — same pattern, no client-cert requirement
    # (SCEP authenticates via challengePassword inside the CSR).
    location ^~ /scep {
        proxy_set_header X-Forwarded-For    $remote_addr;
        proxy_set_header X-Forwarded-Proto  $scheme;
        proxy_pass https://certctl_backend;
        proxy_ssl_protocols TLSv1.3;
        proxy_ssl_verify    on;
        proxy_ssl_trusted_certificate /etc/nginx/certs/certctl-internal-ca.pem;
    }
}
```

## HAProxy config (alternative)

```
frontend est_legacy
    bind *:443 ssl crt /etc/haproxy/certs/est.example.com.pem alpn h2,http/1.1 \
        ssl-min-ver TLSv1.2 \
        ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

    acl is_est_path  path_beg /.well-known/est
    acl is_pki_path  path_beg /.well-known/pki
    acl is_scep_path path_beg /scep
    use_backend certctl_backend if is_est_path or is_pki_path or is_scep_path
    default_backend certctl_modern

backend certctl_backend
    server certctl 10.0.0.10:8443 ssl verify required \
        ca-file /etc/haproxy/certs/certctl-internal-ca.pem \
        ssl-min-ver TLSv1.3
    http-request set-header X-Forwarded-For %[src]
    http-request set-header X-Forwarded-Proto https
```

## certctl-side configuration

The current implementation is **header-agnostic**: certctl ignores any
`X-SSL-Client-Cert` / `X-Forwarded-For` headers from the proxy. EST
authentication still happens via in-protocol CSR signature + profile
policy (RFC 7030 §3.2.3); SCEP authentication still happens via the
`challengePassword` attribute embedded in the CSR (RFC 8894 §3.2). Both
mechanisms are inside the request body and survive the reverse-proxy
hop without server-side header trust.

**Why this is the correct default:** trusting a proxy-supplied header
for client identity opens a header-spoofing attack surface that requires
careful design (CIDR allowlist of trusted proxies, fail-closed defaults,
explicit operator opt-in). The Bundle F closure of M-023 ships the
TLS-bridge guidance as documentation only; a future commit can extend
certctl with proxy-header trust if and when an operator demonstrates a
deployment shape that requires it. Until that lands, the runbook above
is operationally complete: legacy EST and SCEP clients continue to
authenticate via their in-protocol mechanisms, and the reverse proxy is
purely a TLS-version bridge.

If your deployment requires proxy-supplied client identity (e.g., the
proxy terminates mTLS and you want certctl to record the client-cert
subject in the audit trail beyond what the CSR carries), open an issue
and a future commit will add a header-trust contract behind two
fail-closed env vars: a CIDR allowlist of trusted proxies, plus an
explicit opt-in toggle. Both knobs would be required together; setting
only one would fail loud at startup. Until that work ships, the
header-agnostic default described above is the only supported
configuration.

## PCI-DSS Req 4 §2.2.5 attestation

PCI-DSS v4.0 §2.2.5 ("strong cryptography for authentication/transmission
of cardholder data") considers TLS 1.2 with strong cipher suites
acceptable for the foreseeable future, with the explicit caveat that NIST
or the PCI Council may shorten the deprecation window if a TLS 1.2
weakness is published. The configuration above:

- Pins TLS 1.2 + TLS 1.3 only (no SSLv3, TLS 1.0, TLS 1.1).
- Uses only AEAD cipher suites with forward secrecy (ECDHE-* with GCM or
  ChaCha20-Poly1305).
- Re-encrypts to TLS 1.3 on the proxy-to-certctl hop.

This is PCI-DSS Req 4 v4.0 compliant. Auditors looking for the
attestation should be pointed at this section + the proxy's TLS config.

## What this runbook does NOT cover

- **Replacing the legacy clients.** That's the long-term fix; this
  runbook is the bridge while you're migrating.
- **Network segmentation.** The reverse proxy assumes the proxy-to-certctl
  hop is on a network that an external attacker can't reach. If it's
  not, you need a deeper architecture review.
- **Client-cert revocation.** EST mTLS revocation is the relying party's
  responsibility. certctl's EST handler accepts the cert; the proxy can
  enforce CRL/OCSP via `ssl_crl_path` (nginx) or `crl-file` (HAProxy).

## When TLS 1.2 itself sunsets

PCI-DSS, NIST, and major browsers will eventually deprecate TLS 1.2.
When that happens, this runbook becomes obsolete; the only path forward
will be to replace the legacy clients. Subscribe to RSS feeds at the
following sources to catch the deprecation announcement before it
becomes a compliance failure:

- https://www.pcisecuritystandards.org/news_events/
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/  (SP 800-52 revisions)

## SCEP RFC 8894 native implementation (post-2026-04-29)

Prior to this bundle, certctl's SCEP server parsed `PKCS#7 SignedData` and
treated the encapsulated content as a raw `PKCS#10 CSR` (the file-internal
"MVP" comment at `internal/api/handler/scep.go:217` flagged this). That
worked for lightweight MDM agents but failed against ChromeOS and most
production MDM clients which expect full RFC 8894 wire format:
`SignedData` wrapping an `EnvelopedData` encrypting the CSR to the RA
cert's public key, with `signerInfo` POPO over the auth-attrs.

The new RFC 8894 path runs FIRST; on any parse failure it falls through
to the legacy MVP raw-CSR path so existing operators see no behavior
change for their lightweight clients.

### Required: RA cert + key

The RFC 8894 path requires a Registration Authority cert + key pair.
Clients encrypt their CSR to the RA cert's public key (RFC 8894 §3.2.2);
the certctl server uses the RA key to decrypt and to sign the outbound
CertRep PKIMessage signerInfo (RFC 8894 §3.3.2).

| Env var | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_SCEP_RA_CERT_PATH` | (none) | Path to PEM-encoded RA certificate. **Required when `CERTCTL_SCEP_ENABLED=true`.** |
| `CERTCTL_SCEP_RA_KEY_PATH` | (none) | Path to PEM-encoded RA private key matching `CERTCTL_SCEP_RA_CERT_PATH`. File MUST be mode `0600` (preflight refuses world-readable). |

Generate the RA pair (any RSA-2048+ or ECDSA-P256+ pair signed by your
root or sub-CA works):

```bash
# RSA-2048 RA pair, valid 1 year, signed by your root.
openssl req -new -newkey rsa:2048 -nodes -keyout ra.key -out ra.csr \
  -subj "/CN=corp-ca-RA"
openssl x509 -req -in ra.csr -days 365 \
  -CA root.crt -CAkey root.key -CAcreateserial \
  -extfile <(printf "extendedKeyUsage=emailProtection,1.3.6.1.5.5.7.3.4") \
  -out ra.crt

chmod 0600 ra.key       # required — preflight rejects world-readable keys
chmod 0644 ra.crt
mv ra.key ra.crt /etc/certctl/scep/

export CERTCTL_SCEP_ENABLED=true
export CERTCTL_SCEP_RA_CERT_PATH=/etc/certctl/scep/ra.crt
export CERTCTL_SCEP_RA_KEY_PATH=/etc/certctl/scep/ra.key
export CERTCTL_SCEP_CHALLENGE_PASSWORD=$(openssl rand -hex 32)
```

The startup preflight in `cmd/server/main.go::preflightSCEPRACertKey`
validates: file existence, key file mode 0600, cert/key match, cert
non-expired, RSA-or-ECDSA public-key algorithm. Failures `os.Exit(1)`
with a structured log line identifying the offending profile.

### Capability advertisement (`GetCACaps`)

```
POSTPKIOperation
SHA-256
SHA-512
AES
SCEPStandard
Renewal
```

ChromeOS specifically looks for `POSTPKIOperation` (non-base64 POST),
`AES` (the now-implemented CBC content encryption), `SCEPStandard` (RFC
8894 conformance), and `Renewal` (RenewalReq messageType-17 support).
Older Cisco IOS clients also accept `SHA-256` and `SHA-512` per RFC 8894
§3.5.2.

### Supported messageTypes

| Type | RFC 8894 § | Behavior |
| --- | --- | --- |
| `PKCSReq` (19) | §3.3.1 | Initial enrollment. Signer cert is the device's transient self-signed key. |
| `RenewalReq` (17) | §3.3.1.2 | Re-enrollment. Signer cert MUST be a previously-issued cert from this issuer; service-side `verifyRenewalSignerCertChain` enforces. |
| `GetCertInitial` (20) | §3.3.3 | Polling for pending requests. v1 returns `FAILURE+badCertID` because deferred-issuance isn't supported (every PKCSReq either succeeds or fails synchronously). |
| `CertRep` (3) | §3.3.2 | Server response — never inbound. |

### MVP backward-compatibility path

Lightweight clients that send a stripped `SignedData` containing a raw
CSR (no `EnvelopedData` wrapper, no `signerInfo` POPO) keep working: the
handler tries the RFC 8894 path FIRST; on any parse failure it falls
through to the legacy `extractCSRFromPKCS7` path. The legacy path uses
the CSR's `challengePassword` attribute the same way as the RFC 8894
path. Operators with existing lightweight-client deploys see zero
behavior change.

### Multi-profile dispatch (`/scep/<pathID>`)

Real enterprise deploys run multiple SCEP endpoints from one certctl
instance — corp-laptop CA, IoT CA, server CA — each with its own
issuer + RA pair + challenge password. Configure via the indexed env-var
form documented in [`features.md`](features.md): set
`CERTCTL_SCEP_PROFILES=corp,iot,server` (a comma-separated list of
profile names), then for each name supply the per-profile env-vars
prefixed with `CERTCTL_SCEP_PROFILE_<NAME>_` followed by the suffix
keys `_ISSUER_ID`, `_PROFILE_ID`, `_CHALLENGE_PASSWORD`, `_RA_CERT_PATH`,
`_RA_KEY_PATH`. The `<NAME>` token resolves to the upper-cased profile
name from the list. Each profile is independently validated at startup;
per-profile failures log the offending PathID.

The router exposes `/scep/corp`, `/scep/iot`, `/scep/server`. The legacy
`/scep` root remains for the single-profile flat-env-var case (when
`CERTCTL_SCEP_PROFILES` is unset). Per-profile preflight validates each
RA pair independently; failures log the offending PathID.

### ChromeOS Admin Console pointer

In Google Admin Console → Devices → Networks → Certificates, register
certctl's `/scep[/<pathID>]` URL as the SCEP server. Enter the challenge
password from `CERTCTL_SCEP_CHALLENGE_PASSWORD` (or per-profile
`CERTCTL_SCEP_PROFILE_<NAME>_CHALLENGE_PASSWORD`). ChromeOS pulls
`GetCACert` first to retrieve the RA cert, then enrolls via
PKIOperation.

### RA cert rotation

The RA cert is loaded once at startup and persisted in the handler's
struct field; rotation requires a server restart (mirrors the
`CERTCTL_SERVER_TLS_CERT_PATH` precedent in `cmd/server/tls.go`). The
recommended cadence is annual rotation with a 30-day overlap during
which both old + new RA certs are listed in `GetCACert`'s response (set
the cert chain accordingly in your sub-CA hierarchy).

### Must-staple per-profile policy (RFC 7633)

When a `CertificateProfile` has `MustStaple = true`, the local issuer
adds the `id-pe-tlsfeature` extension (OID `1.3.6.1.5.5.7.1.24`,
non-critical, value `SEQUENCE OF INTEGER {5}`) to every issued cert.
Browsers + modern TLS libraries that see this extension fail-closed on
missing OCSP stapling responses — defense against revocation-bypass via
OCSP blackholing.

**Default policy:** `false`. Operators opt in once they've confirmed the
TLS reverse proxy / load balancer staples OCSP responses. NGINX,
HAProxy, Envoy all support stapling but it requires explicit config —
turning must-staple on without verifying the TLS path will hard-fail
browsers.

Recommended for: Intune-deployed device certs (modern TLS clients);
SCEP profiles serving general / legacy clients (ChromeOS, IoT) should
stay `false` until the TLS path is verified.

### mTLS sibling route (Phase 6.5, opt-in)

SCEP is documented as application-layer-auth — the challenge password
is the authentication boundary per RFC 8894 §3.2. But enterprise
procurement teams routinely reject "shared password authentication" as
a checkbox-fail regardless of how strong the password is. The clean
answer: a **sibling** route at `/scep-mtls/<pathID>` that requires
client-cert auth at the handler layer AND ALSO accepts the challenge
password (defense in depth, not replacement). Devices present a
bootstrap cert from a trusted CA (e.g. a manufacturing-time cert),
then SCEP-enroll for their long-lived cert. Same model Apple's MDM and
Cisco's BRSKI use.

**Opt in per profile** by setting two env vars:

```
CERTCTL_SCEP_PROFILE_<NAME>_MTLS_ENABLED=true
CERTCTL_SCEP_PROFILE_<NAME>_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH=/etc/certctl/scep/<name>-bootstrap-cas.pem
```

The trust bundle is a PEM file containing the bootstrap-CA certs the
operator allows to enroll. Operators with multiple bootstrap CAs
concatenate them. The startup preflight
(`cmd/server/main.go::preflightSCEPMTLSTrustBundle`) validates: file
exists, parses as PEM, contains ≥1 cert, none expired. Failures
`os.Exit(1)` with a structured log identifying the offending PathID.

**TLS server config:** when at least one profile opts into mTLS, the
HTTPS listener gets the union of every enabled profile's trust bundle
as its `ClientCAs` pool, plus `ClientAuth: VerifyClientCertIfGiven` —
the listener requests a client cert during the handshake, verifies it
against the union pool if presented, and lets the handler decide
whether to require it. This means the SAME listener serves both
`/scep[/<pathID>]` (no client cert required) and `/scep-mtls/<pathID>`
(cert required). The standard route stays untouched for clients that
can't present a cert.

**Handler-layer per-profile gate:** the TLS-layer check uses the union
pool, so a cert that chains to profile A's bundle would pass the TLS
handshake even when targeting profile B. The handler-layer gate
(`HandleSCEPMTLS`) re-verifies the inbound client cert against ONLY
THIS profile's pool — preventing cross-profile bleed-through.

**Auth chain on the mTLS sibling route:**

1. TLS handshake: client cert verified against the union pool
   (if presented; absent = standard SCEP path applies but handler
   rejects with 401).
2. Handler-layer per-profile re-verification: cert must chain to
   THIS profile's trust bundle. Mismatch = 401.
3. Standard SCEP enrollment: `HandleSCEP` runs as on the standard
   route — including the challenge-password gate at the service layer.

A stolen device cert without the matching challenge password gets
rejected (and vice versa). Both layers are independently required.

**Operator workflow** for migrating from challenge-password-only to
challenge+mTLS:

1. Generate a bootstrap CA + issue a bootstrap cert per device (out
   of band — typically manufacturing-time, MDM-pushed, or a separate
   PKI flow). 
2. Distribute the trust bundle to certctl as the
   `_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH`.
3. Set `_MTLS_ENABLED=true` for the profile, restart certctl.
4. Devices now have TWO valid enrollment URLs:
   `/scep/<pathID>` (challenge-password-only, legacy) and
   `/scep-mtls/<pathID>` (cert + challenge, new).
5. Roll out config to fleet that switches devices to the new URL.
6. Once the fleet has migrated, remove `_CHALLENGE_PASSWORD` from the
   profile (Validate() will keep the gate when MTLSEnabled=true so
   the password requirement doesn't go away — the password is still
   the application-layer auth boundary).

### Microsoft Intune dynamic-challenge dispatcher (Phase 8, opt-in)

When SCEP sits behind the Microsoft Intune Certificate Connector, devices
present an Intune-issued signed challenge (a JWT-like blob over a JSON
claim payload) instead of the static `_CHALLENGE_PASSWORD`. Phase 8 wires
a per-profile dispatcher that validates these signed challenges against
the Connector's signing-cert trust anchor and binds the asserted device
identity to the inbound CSR. Static challenge passwords still work as a
fallback so heterogeneous fleets (some Intune-enrolled, some not) keep
working.

**Per-profile env vars** (all default to off; legacy/static-only profiles
need no changes):

```
CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_ENABLED=true
CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_CONNECTOR_CERT_PATH=/etc/certctl/intune-corp.pem
CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_AUDIENCE=https://certctl.example.com/scep/corp
CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_CHALLENGE_VALIDITY=60m
CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_PER_DEVICE_RATE_LIMIT_24H=3
```

**Trust-anchor extraction:** the operator extracts the Connector
installation's signing cert (from the Connector's certificate store on
the Windows host running the Connector — Microsoft does not publish a
direct download) and writes a PEM bundle to the configured path.
Multiple Connectors in HA = concatenate their certs.

**Trust-anchor reload:** the holder re-reads the bundle on `SIGHUP` (the
same signal that rotates the server's TLS cert). A bad reload (parse
error, expired cert) keeps the OLD pool in place — operators get a
recoverable failure window rather than a service-down. Rotate the file
on disk, then `kill -HUP <certctl-pid>` to apply with no restart.

**Replay protection:** in-memory cache of seen challenge nonces with TTL
= `_CHALLENGE_VALIDITY` (default 60m). Sized for 100k entries, which
covers a ~25 RPS Intune fleet's steady-state. The same challenge
submitted twice within the TTL is rejected with `ErrChallengeReplay`.

**Per-device rate limit:** sliding-window-log limiter keyed by
`(claim.Subject, claim.Issuer)`. Default 3 enrollments per 24h covers
legitimate first-cert + recovery + post-wipe re-enrollment but blocks a
compromised Connector signing key from issuing many DIFFERENT valid
challenges for the same device. Set the var to `0` to disable.

**Audit + observability:** Intune enrollments emit
`audit_event.action="scep_pkcsreq_intune"` (or
`"scep_renewalreq_intune"`) so operators can grep the audit log to count
Intune-vs-static enrollments. Per-failure-mode reason flows into the log
line; the metric label set is `success / signature_invalid / expired /
not_yet_valid / wrong_audience / replay / rate_limited / claim_mismatch
/ unknown_version / malformed`.

**Compliance-state hook (V3-Pro plug-in seam):** a nil-default
`ComplianceCheck` field on `SCEPService` lets a future Pro module plug
in a Microsoft Graph compliance API call between challenge validation
and certificate issuance. V2 ships the seam (one struct field + one
setter + one nil-guarded call site) so Pro is plug-in code, not a
dispatcher refactor.

**Mixed-mode (recommended):** keep `_CHALLENGE_PASSWORD` set even when
Intune is enabled. Devices that don't go through Intune (manual
enrollment, on-prem MDM bridges) continue to enroll via the static path;
the dispatcher routes Intune-shaped challenges (length > 200 + exactly
two dots) to the validator and falls through to the static compare
otherwise.

### Operational notes

- **Audit:** every enrollment emits an `audit_event` row with action
  `scep_pkcsreq` (initial) or `scep_renewalreq` (renewal); operators
  can grep the audit log to distinguish. Intune-dispatched enrollments
  use `scep_pkcsreq_intune` and `scep_renewalreq_intune` respectively.
- **Body-size cap:** `http.MaxBytesReader` middleware caps request
  bodies at `CERTCTL_MAX_BODY_SIZE` (default 1MB); SCEP PKIMessages are
  typically <50KB so the default cap is generous.
- **HTTPS-only:** the SCEP endpoint inherits the TLS-1.3-pinned control
  plane; there is no plaintext fallback.
- **For Microsoft Intune deployments, see [`scep-intune.md`](scep-intune.md)** —
  architecture, NDES-replacement migration playbook, Intune SCEP profile
  field mapping, trust-anchor extraction recipe, troubleshooting matrix,
  operational monitoring, V3-Pro deferrals, and the Microsoft support
  statement (with Microsoft Learn URLs procurement teams ask for).
- **For per-profile SCEP observability** (RA cert expiry countdown,
  mTLS sibling-route status, challenge-password-set indicator, and
  the full SCEP audit log filter), the admin GUI page lives at `/scep`
  with three tabs: **Profiles** (default), **Intune Monitoring**,
  **Recent Activity**. See `scep-intune.md::Operational monitoring`
  for the Intune-specific tab inside it.

## Related docs

- [`tls.md`](tls.md) — the certctl-internal TLS configuration (HTTPS-only
  control plane, MinVersion pin)
- [`security.md`](security.md) — overall security posture
- [`database-tls.md`](database-tls.md) — Postgres TLS opt-in (Bundle B / M-018)
