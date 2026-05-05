# GlobalSign Atlas HVCA Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the GlobalSign Atlas High Volume
> CA (HVCA) issuer connector. For the connector-development context
> (interface contract, registry, ports/adapters), see the
> [connector index](index.md).

## Overview

GlobalSign Atlas HVCA REST API with **dual authentication**: mTLS
for the TLS handshake AND API key/secret headers for request
authorization. Region-aware base URLs (EMEA, APAC, Americas).

Implementation lives at `internal/connector/issuer/globalsign/`
(mTLS keypair cache shared at
`internal/connector/issuer/mtlscache/`).

## When to use this connector

Use the GlobalSign Atlas HVCA connector when:

- You're a GlobalSign Atlas customer issuing high volumes of
  publicly trusted certificates (the "HV" in HVCA).
- You want region-pinned issuance for compliance or latency
  reasons (EMEA / APAC / Americas regional endpoints).
- You're prepared to manage both mTLS client certs AND
  API key/secret credentials in tandem.

Look elsewhere when:

- You only need DV public-trust and your CA is reachable via ACME —
  the [ACME connector](acme.md) is simpler.
- The dual-auth burden (mTLS + API key + API secret) is heavier
  than your environment needs — DigiCert (API key only) or Entrust
  (mTLS only) are simpler to operate.

## Configuration

| Setting | Required | Default | Description |
|---|---|---|---|
| `CERTCTL_GLOBALSIGN_API_URL` | Yes | — | Atlas HVCA API URL (region-specific) |
| `CERTCTL_GLOBALSIGN_API_KEY` | Yes | — | API key for request authentication |
| `CERTCTL_GLOBALSIGN_API_SECRET` | Yes | — | API secret for request authentication |
| `CERTCTL_GLOBALSIGN_CLIENT_CERT_PATH` | Yes | — | Path to mTLS client certificate PEM |
| `CERTCTL_GLOBALSIGN_CLIENT_KEY_PATH` | Yes | — | Path to mTLS client private key PEM |
| `CERTCTL_GLOBALSIGN_SERVER_CA_PATH` | No | system trust store | PEM bundle used to verify the Atlas API server certificate. Set this for private/lab Atlas deployments whose server TLS chain is not in the host's default trust bundle. |
| `CERTCTL_GLOBALSIGN_POLL_MAX_WAIT_SECONDS` | No | `600` (10m) | Bounded-polling deadline for `GetOrderStatus`. GlobalSign tracks orders by serial number rather than order ID; the polling shape is identical. |

## Authentication

Dual — mTLS client certificate for TLS handshake plus `X-API-Key`
and `X-API-Secret` headers on every request. Both must be valid
or the request fails.

## TLS verification

The connector always verifies the server certificate. When
`server_ca_path` is set, the PEM bundle at that path is used as
the trust anchor; otherwise the host's system trust store is
used. TLS 1.2 is the minimum protocol version.

## Issuance model

`POST /v2/certificates` returns a serial number. Certificate PEM
is available after validation completes. Typically resolves
within seconds for DV. `GetOrderStatus` polls the certificate
endpoint.

## mTLS keypair caching (audit fix #10)

The parsed client certificate plus a precomputed `*http.Transport`
(with `ServerCAPath` pinning preserved when configured) are cached
on the connector after the first API call. Steady-state calls
reuse the cached transport — no per-call disk read or
`tls.X509KeyPair` parse.

Rotation is picked up automatically via mtime polling: when the
cert file's mtime advances beyond the last-loaded value, the next
API call re-parses and rebuilds the transport.

Operator workflow: `mv -f new.crt /etc/certctl/globalsign/client.crt`
(mtime changes), no process restart required, takes effect on the
next API call. `os.Stat` errors during rotation surface as
connector errors rather than silently serving stale credentials.

## Revocation

CRL and OCSP are managed by GlobalSign. certctl records
revocations locally and notifies GlobalSign via
`PUT /v2/certificates/{serial}/revoke`.

## Operator playbook

### Rotating mTLS client material

Same flow as the [Entrust connector](entrust.md): place the new
cert at the configured path, mtime changes, next API call picks
up the new keypair. `ServerCAPath` pin (when configured) is
preserved across the rebuild.

### Rotating API key / secret

Rotate in the Atlas dashboard, then either restart certctl-server
or hot-swap via `PUT /api/v1/issuers/{id}`. The registry's
Rebuild path replaces the connector with the new credentials. The
mTLS transport cache stays warm across the swap (mTLS material
hasn't changed) — only the per-request headers are new.

### Region selection

Atlas HVCA has region-specific base URLs. Use the URL that
matches your account's contracted region; the connector does no
region-routing on its own.

## Related docs

- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [Entrust connector](entrust.md) — mTLS-only commercial alternative
- [DigiCert connector](digicert.md) — API-key-only commercial alternative
- [Async CA polling](../protocols/async-ca-polling.md) — the bounded-polling primitive
