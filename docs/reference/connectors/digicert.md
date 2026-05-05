# DigiCert CertCentral Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the DigiCert CertCentral issuer
> connector. For the connector-development context (interface
> contract, registry, ports/adapters), see the
> [connector index](index.md).

## Overview

The DigiCert connector integrates with DigiCert's CertCentral REST
API for ordering and managing certificates from DigiCert's commercial
public CA. It supports Domain Validated (DV), Organization Validated
(OV), and Extended Validated (EV) certificates, with async order
processing for OV/EV.

Implementation lives at `internal/connector/issuer/digicert/`.

## When to use this connector

Use the DigiCert connector when:

- You're already a DigiCert CertCentral customer and want certctl to
  drive issuance, renewal, and deployment from the same platform that
  manages your internal PKI.
- You need OV or EV certificates that require DigiCert to validate
  organization details before issuance.
- You want one tool that covers both internal CAs (Vault, Local,
  step-ca) and a public-trust commercial CA.

Look elsewhere when:

- You only need DV certificates and Let's Encrypt / ZeroSSL is an
  acceptable issuer — use the ACME connector instead.
- You need self-hosted PKI with no commercial CA dependency — use
  Vault PKI, step-ca, or the Local CA issuer.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_DIGICERT_API_KEY` | — | DigiCert API key (sent in `X-DC-DEVKEY` header) |
| `CERTCTL_DIGICERT_ORG_ID` | — | DigiCert organization ID |
| `CERTCTL_DIGICERT_PRODUCT_TYPE` | `ssl_basic` | Certificate product (e.g. `ssl_basic`, `ssl_plus`, `ssl_ev`) |
| `CERTCTL_DIGICERT_BASE_URL` | `https://www.digicert.com/services/v2` | DigiCert API base URL |
| `CERTCTL_DIGICERT_POLL_MAX_WAIT_SECONDS` | `600` | Bounded-polling deadline for `GetOrderStatus` |

## Authentication

API key passed via `X-DC-DEVKEY` header. The organization ID is sent
in the request body (not the header). No mTLS or OAuth2 required.

## Issuance model

- **DV certificates** — typically issue immediately; the
  `/order/certificate/create` API may return the PEM in the same
  response.
- **OV / EV certificates** — require DigiCert-side validation
  (vetting org documents, checking domain ownership). The API
  returns 201 with an order ID; certctl's `GetOrderStatus` polls
  until the certificate is retrievable.

`GetOrderStatus` runs bounded internal polling (5s/15s/45s/2m/5m
capped, ±20% jitter, default 10-minute deadline). For OV/EV orders
where humans approve enrollments, bump
`CERTCTL_DIGICERT_POLL_MAX_WAIT_SECONDS` to a value that comfortably
covers the approval window — see
[async-ca-polling.md](../protocols/async-ca-polling.md) for the
schedule shape and tuning guidance.

## Revocation

CRL and OCSP are managed by DigiCert. Clients should validate
certificate status against DigiCert's infrastructure. certctl
records the revocation locally (audit row + cert state) but does
**not** call DigiCert's revoke endpoint — operators revoke through
DigiCert's dashboard or the CertCentral REST API directly. This
keeps the certctl revocation flow simple at the cost of one extra
manual step on revocation.

## Operator playbook

### API key rotation

Rotate the API key in DigiCert's dashboard, then either restart
certctl-server with the new value in `CERTCTL_DIGICERT_API_KEY` or
hot-swap via `PUT /api/v1/issuers/{id}` so the registry's Rebuild
path replaces the connector with the new key. No certificate
state is invalidated by the rotation — the new key just signs
future API calls.

### Diagnosing slow OV/EV issuance

DigiCert's OV/EV vetting is a human process and can take hours to
days. Bumping `CERTCTL_DIGICERT_POLL_MAX_WAIT_SECONDS` lets a
single tick wait through the full approval window, but the better
operational pattern is to issue OV/EV certs well ahead of expiry
so the bounded poll deadline is short. The renewal scheduler's
"alert at T-30 days" default exists for exactly this reason.

## Related docs

- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [Async CA polling](../protocols/async-ca-polling.md) — the bounded-polling primitive
- [ACME server](../protocols/acme-server.md) — alternative issuer for DV-only workflows
