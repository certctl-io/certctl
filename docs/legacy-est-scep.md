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
issuer + RA pair + challenge password. Configure via:

```
CERTCTL_SCEP_PROFILES=corp,iot,server
CERTCTL_SCEP_PROFILE_CORP_ISSUER_ID=iss-corp-laptop
CERTCTL_SCEP_PROFILE_CORP_PROFILE_ID=prof-corp-tls
CERTCTL_SCEP_PROFILE_CORP_CHALLENGE_PASSWORD=...
CERTCTL_SCEP_PROFILE_CORP_RA_CERT_PATH=/etc/certctl/scep/corp-ra.crt
CERTCTL_SCEP_PROFILE_CORP_RA_KEY_PATH=/etc/certctl/scep/corp-ra.key
# ... per profile name in CERTCTL_SCEP_PROFILES
```

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
`CERTCTL_TLS_CERT_PATH` precedent in `cmd/server/tls.go`). The
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

### Operational notes

- **Audit:** every enrollment emits an `audit_event` row with action
  `scep_pkcsreq` (initial) or `scep_renewalreq` (renewal); operators
  can grep the audit log to distinguish.
- **Body-size cap:** `http.MaxBytesReader` middleware caps request
  bodies at `CERTCTL_MAX_BODY_SIZE` (default 1MB); SCEP PKIMessages are
  typically <50KB so the default cap is generous.
- **HTTPS-only:** the SCEP endpoint inherits the TLS-1.3-pinned control
  plane; there is no plaintext fallback.
- **Forward reference:** for Microsoft Intune deployments specifically,
  see [`scep-intune.md`](scep-intune.md) (the doc Phase 11 of the
  master bundle ships).

## Related docs

- [`tls.md`](tls.md) — the certctl-internal TLS configuration (HTTPS-only
  control plane, MinVersion pin)
- [`security.md`](security.md) — overall security posture
- [`database-tls.md`](database-tls.md) — Postgres TLS opt-in (Bundle B / M-018)
