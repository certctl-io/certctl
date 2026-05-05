# Sectigo SCM Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the Sectigo Certificate Manager
> (SCM) issuer connector. For the connector-development context
> (interface contract, registry, ports/adapters), see the
> [connector index](index.md).

## Overview

The Sectigo connector integrates with Sectigo Certificate Manager's
REST API for ordering and managing DV, OV, and EV certificates.
Like DigiCert, it uses an async order model: submit an enrollment,
receive an `sslId`, then poll for completion.

Implementation lives at `internal/connector/issuer/sectigo/`.

## When to use this connector

Use the Sectigo SCM connector when:

- You're already a Sectigo Certificate Manager customer (formerly
  Comodo CA / SecureTrust SCM).
- You need OV / EV certificates that Sectigo validates before
  issuance.
- You want certctl to drive renewal lifecycle on top of Sectigo's
  commercial issuance.

Look elsewhere when:

- You're using Sectigo through their ACME endpoint — the
  [ACME connector](acme.md) is a simpler path.
- You only need DV certificates and want a free public-trust CA —
  Let's Encrypt or ZeroSSL via the ACME connector.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_SECTIGO_CUSTOMER_URI` | — | Sectigo customer URI (organization identifier) |
| `CERTCTL_SECTIGO_LOGIN` | — | API account login |
| `CERTCTL_SECTIGO_PASSWORD` | — | API account password |
| `CERTCTL_SECTIGO_ORG_ID` | — | Organization ID (integer) |
| `CERTCTL_SECTIGO_CERT_TYPE` | — | Certificate type ID (integer, from `/ssl/v1/types`) |
| `CERTCTL_SECTIGO_TERM` | `365` | Certificate validity in days |
| `CERTCTL_SECTIGO_BASE_URL` | `https://cert-manager.com/api` | Sectigo API base URL |
| `CERTCTL_SECTIGO_POLL_MAX_WAIT_SECONDS` | `600` | Bounded-polling deadline for `GetOrderStatus` |

## Authentication

Three custom headers on every request: `customerUri`, `login`,
and `password`. No mTLS or OAuth2.

## Issuance model

`POST /ssl/v1/enroll` returns an `sslId`. DV certificates may
issue immediately; OV/EV certificates require Sectigo-side
validation and poll-based completion.

`GetOrderStatus` runs bounded internal polling
(5s/15s/45s/2m/5m capped, ±20% jitter, default 10-minute
deadline). The `collectNotReady` sentinel (cert approved but not
yet retrievable) rides the same backoff schedule. Bump
`CERTCTL_SECTIGO_POLL_MAX_WAIT_SECONDS` for OV/EV workflows where
human approval extends past 10 minutes — see
[async-ca-polling.md](../protocols/async-ca-polling.md) for the
schedule shape and tuning guidance.

## Revocation

CRL and OCSP are managed by Sectigo. certctl records revocations
locally and notifies Sectigo via `/ssl/v1/revoke/{sslId}`. Unlike
DigiCert (no auto-notify), Sectigo's revocation is part of the
connector's revoke path.

## Operator playbook

### Credential rotation

Rotate the API password in Sectigo's admin portal, then either
restart certctl-server with the new value in
`CERTCTL_SECTIGO_PASSWORD` or hot-swap via `PUT /api/v1/issuers/{id}`.
The registry's Rebuild path replaces the connector with the new
credentials. No certificate state is invalidated.

### Diagnosing slow OV/EV issuance

Sectigo's OV/EV vetting is human-driven and can take hours to
days. The same operational pattern as DigiCert applies: issue OV/EV
certs well ahead of expiry so the bounded poll deadline is short.

## Related docs

- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [Async CA polling](../protocols/async-ca-polling.md) — the bounded-polling primitive
- [DigiCert connector](digicert.md) — comparable commercial CA alternative
- [ACME connector](acme.md) — simpler path when Sectigo is reachable via ACME
