# EJBCA (Keyfactor) Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the EJBCA issuer connector. For
> the connector-development context (interface contract, registry,
> ports/adapters), see the [connector index](index.md).

## Overview

The EJBCA connector calls the EJBCA REST API for self-hosted
open-source and Keyfactor enterprise CAs. It supports dual
authentication: mTLS (default) or OAuth2 Bearer token, selectable
via configuration.

Implementation lives at `internal/connector/issuer/ejbca/`.

## When to use this connector

Use the EJBCA connector when:

- You already run EJBCA Community Edition or Keyfactor EJBCA
  Enterprise as your internal CA and want certctl to drive the
  lifecycle automation (renewal, deployment, alerts) on top.
- You need EJBCA's certificate-profile and end-entity-profile
  policy enforcement — those policies stay in EJBCA and certctl
  passes the profile names through.
- You need approval-pending workflows (humans approve enrollments)
  — EJBCA supports the 201-Accepted async path.

Look elsewhere when:

- You want a simpler internal CA without EJBCA's operational weight
  — Vault PKI, step-ca, or the Local CA issuer are lighter.
- You need a managed CA (no servers to run) — Google CAS or AWS
  ACM PCA on cloud, or DigiCert / Sectigo for commercial PKI.

## Configuration

| Setting | Required | Default | Description |
|---|---|---|---|
| `CERTCTL_EJBCA_API_URL` | Yes | — | EJBCA REST API base URL |
| `CERTCTL_EJBCA_AUTH_MODE` | No | `mtls` | Auth mode: `mtls` or `oauth2` |
| `CERTCTL_EJBCA_CLIENT_CERT_PATH` | mTLS | — | Path to client certificate PEM (mTLS mode) |
| `CERTCTL_EJBCA_CLIENT_KEY_PATH` | mTLS | — | Path to client key PEM (mTLS mode) |
| `CERTCTL_EJBCA_TOKEN` | OAuth2 | — | Bearer token (oauth2 mode) |
| `CERTCTL_EJBCA_CA_NAME` | Yes | — | EJBCA CA name |
| `CERTCTL_EJBCA_CERT_PROFILE` | No | — | EJBCA certificate profile |
| `CERTCTL_EJBCA_EE_PROFILE` | No | — | EJBCA end-entity profile |

## Authentication

Configurable via `auth_mode`:

- **`mtls`** — client certificate and key are loaded for the TLS
  handshake. This is the default and the more common deployment
  mode for EJBCA.
- **`oauth2`** — the token is sent as `Authorization: Bearer
  {token}`. Use when EJBCA is fronted by an OAuth2-aware reverse
  proxy or when integrating with Keyfactor's identity provider.

The mTLS keypair is cached on the connector after the first API
call and reused for the lifetime of the process; rotation is
picked up automatically via mtime polling on the cert file (see
the mtls keypair caching note in the [connector
index](index.md#built-in-ejbca-keyfactor)).

## Issuance model

`POST /v1/certificate/pkcs10enroll` with base64-encoded CSR.
Returns base64-encoded certificate PEM. EJBCA 9.3+ creates
end-entity and issues cert in a single call. Approval-pending
enrollments return 201 with a tracking ID; certctl's
`GetOrderStatus` polls until the certificate is available.

## Revocation

EJBCA requires both issuer DN and serial number for revocation.
The connector stores these as a composite `OrderID` in
`issuer_dn::serial` format.

CRL and OCSP are managed by the EJBCA instance. certctl records
revocations locally and notifies EJBCA via
`PUT /v1/certificate/{issuer_dn}/{serial}/revoke`.

## Operator playbook

### mTLS rotation without downtime

`mv -f new.crt /etc/certctl/ejbca/client.crt` (mtime changes), no
process restart required. The next API call re-parses the file
and rebuilds the `*http.Transport`. `os.Stat` errors during
rotation surface as connector errors rather than silently serving
stale credentials.

### Switching from mTLS to OAuth2

Update the issuer config via `PUT /api/v1/issuers/{id}` with the
new `auth_mode: oauth2` and `token`. The registry's Rebuild path
replaces the connector without restart. Prior issuance state
(serial numbers, cert state) is unaffected.

### Diagnosing approval-pending hangs

If `GetOrderStatus` consistently times out, the operator approval
queue in EJBCA is the most common cause. The connector consumes
the shared bounded-polling primitive — see
[async-ca-polling.md](../protocols/async-ca-polling.md) for the
schedule shape and tuning approach.

## Related docs

- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [Async CA polling](../protocols/async-ca-polling.md) — bounded-polling primitive
- [Approval workflow](../../operator/approval-workflow.md) — certctl-side two-person integrity (separate from EJBCA's approval queue, but addresses the same shape of risk on the certctl side)
