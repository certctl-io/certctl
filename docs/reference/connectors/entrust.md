# Entrust Certificate Services Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the Entrust CA Gateway issuer
> connector. For the connector-development context (interface
> contract, registry, ports/adapters), see the
> [connector index](index.md).

## Overview

The Entrust connector calls the Entrust CA Gateway REST API with
mutual TLS client-certificate authentication. It supports
synchronous issuance (200 OK with PEM) and approval-pending flows
(201 Accepted with async polling).

Implementation lives at `internal/connector/issuer/entrust/` (the
mTLS keypair cache is shared at
`internal/connector/issuer/mtlscache/`).

## When to use this connector

Use the Entrust connector when:

- You're an Entrust Certificate Services customer using the CA
  Gateway as the integration surface.
- You need approval-pending workflows where humans approve
  enrollments before issuance.
- You want mTLS-authenticated issuance against a commercial CA
  with no API keys to rotate.

Look elsewhere when:

- You only need DV / OV public-trust and your CA is reachable via
  ACME — use the [ACME connector](acme.md) for a simpler path.
- You're not already an Entrust customer — DigiCert, Sectigo, and
  GlobalSign are comparable commercial alternatives, with
  different auth shapes.

## Configuration

| Setting | Required | Default | Description |
|---|---|---|---|
| `CERTCTL_ENTRUST_API_URL` | Yes | — | Entrust CA Gateway base URL |
| `CERTCTL_ENTRUST_CLIENT_CERT_PATH` | Yes | — | Path to mTLS client certificate PEM |
| `CERTCTL_ENTRUST_CLIENT_KEY_PATH` | Yes | — | Path to mTLS client private key PEM |
| `CERTCTL_ENTRUST_CA_ID` | Yes | — | Certificate Authority ID (from `GET /certificate-authorities`) |
| `CERTCTL_ENTRUST_PROFILE_ID` | No | — | Optional enrollment profile ID |
| `CERTCTL_ENTRUST_POLL_MAX_WAIT_SECONDS` | No | `600` (10m) | Bounded-polling deadline for `GetOrderStatus` |

For approval-pending workflows where humans approve enrollments,
bump `CERTCTL_ENTRUST_POLL_MAX_WAIT_SECONDS` to `86400` (24h) so a
single tick can wait through the approval window.

## Authentication

Mutual TLS — the client certificate and key are loaded via
`tls.LoadX509KeyPair()` and attached to the HTTP transport. No API
key or token required.

## Issuance model

Enrollment via
`POST /v1/certificate-authorities/{caId}/enrollments`. Returns 200
with PEM immediately for auto-approved enrollments, or 201
Accepted with a tracking ID for approval-pending orders.
`GetOrderStatus` polls the enrollment endpoint.

## mTLS keypair caching (audit fix #10)

The parsed client certificate plus a precomputed `*http.Transport`
are cached on the connector after the first API call. Steady-state
calls reuse the cached transport — no per-call disk read or
`tls.X509KeyPair` parse.

Rotation is picked up automatically via mtime polling: when the
cert file's mtime advances beyond the last-loaded value, the next
API call re-parses and rebuilds the transport.

Operator workflow: `mv -f new.crt /etc/certctl/entrust/client.crt`
(mtime changes), no process restart required, takes effect on the
next API call. `os.Stat` errors during rotation surface as
connector errors rather than silently serving stale credentials.

## Revocation

CRL and OCSP are managed by Entrust. certctl records revocations
locally and notifies Entrust via
`PUT /v1/certificate-authorities/{caId}/certificates/{serial}/revoke`.

## Related docs

- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [GlobalSign Atlas HVCA](globalsign.md) — comparable mTLS-authenticated commercial CA
- [Async CA polling](../protocols/async-ca-polling.md) — the bounded-polling primitive
- [Approval workflow](../../operator/approval-workflow.md) — certctl-side two-person integrity (separate from Entrust's approval queue)
