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
        # private hop. certctl's EST handler reads X-SSL-Client-Cert
        # only when the connection's source IP is in
        # CERTCTL_EST_PROXY_TRUSTED_SOURCES — without that allowlist
        # the header is ignored to prevent spoofing.
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

Two env vars on the certctl process control the proxy-trust contract:

```
# Comma-separated CIDR ranges that certctl will trust to set
# X-SSL-Client-Cert and X-Forwarded-For headers. Any other source has
# those headers stripped before reaching the EST/SCEP handlers.
# Default: empty (no proxy trust — header-spoofing attempt = 403).
CERTCTL_EST_PROXY_TRUSTED_SOURCES=10.0.0.0/24

# When set, the certctl EST handler treats X-SSL-Client-Cert as
# authoritative for client identity (instead of requiring an inbound
# mTLS handshake). MUST be paired with CERTCTL_EST_PROXY_TRUSTED_SOURCES.
CERTCTL_EST_TRUST_PROXY_CLIENT_CERT_HEADER=true
```

The two-key contract is intentional: setting `TRUST_PROXY_CLIENT_CERT_HEADER`
without a non-empty `TRUSTED_SOURCES` is rejected at startup with a
fail-loud error. Spoofing the `X-SSL-Client-Cert` header is the obvious
attack against this configuration and the dual-knob design forces an
operator to think about it.

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

## Related docs

- [`tls.md`](tls.md) — the certctl-internal TLS configuration (HTTPS-only
  control plane, MinVersion pin)
- [`security.md`](security.md) — overall security posture
- [`database-tls.md`](database-tls.md) — Postgres TLS opt-in (Bundle B / M-018)
