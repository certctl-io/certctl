# Vault PKI Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the HashiCorp Vault PKI issuer
> connector. For the connector-development context (interface contract,
> registry, ports/adapters), see the
> [connector index](index.md).

## Overview

The Vault PKI connector integrates with HashiCorp Vault's PKI secrets
engine using its native `/sign` API with token-based authentication.
The flow is purely synchronous — Vault returns the signed certificate
in the same HTTP response that submits the CSR — so there is no
challenge-solving or async polling on the certctl side.

Implementation lives at `internal/connector/issuer/vault/`. The
factory key is `Vault`; the registry binds it under whatever issuer
ID the operator picks (e.g. `iss-vault`).

## When to use this connector

Use the Vault PKI connector when:

- Your organization already runs Vault as the system of record for
  internal certificates.
- You want a synchronous, low-latency issuance path with no challenge
  flow (no DNS records, no HTTP-01).
- You want certctl to manage the lifecycle (renewal scheduling,
  deployment, alerts) while Vault keeps the signing material.

Look elsewhere when:

- Public-trust certificates are required — Vault PKI is internal-only.
  Use ACME (Let's Encrypt, ZeroSSL, Sectigo) or DigiCert / Sectigo SCM
  for public-trust workloads.
- The Vault PKI engine is not already deployed and you don't want to
  run Vault. The Local CA issuer is a simpler self-contained path for
  small internal CAs.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_VAULT_ADDR` | — | Vault server address (e.g. `https://vault.internal:8200`) |
| `CERTCTL_VAULT_TOKEN` | — | Vault auth token with permissions on the PKI mount |
| `CERTCTL_VAULT_MOUNT` | `pki` | PKI secrets engine mount path |
| `CERTCTL_VAULT_ROLE` | — | PKI role name for certificate signing |
| `CERTCTL_VAULT_TTL` | `8760h` | Certificate validity period (TTL) |

Vault issues certificates synchronously via the
`/v1/{mount}/sign/{role}` API with `X-Vault-Token` header
authentication. The issued certificate is parsed to extract serial
number, validity dates, and chain information.

## Token TTL and automatic renewal

This was Top-10 fix #5 from the 2026-05-03 issuer-coverage audit.

certctl-server periodically calls `POST /v1/auth/token/renew-self` at
half the token's TTL to keep the integration alive without manual
rotation. The cadence is read from a one-shot `lookup-self` at
startup and re-derived on every successful renewal — so a short
bootstrap token that gets renewed up to a longer Max TTL shifts to
the longer cadence automatically.

The renewal loop emits the
`certctl_vault_token_renewals_total{result="success"|"failure"|"not_renewable"}`
Prometheus counter so operators see expiry trouble in Grafana before
issuance breaks.

When Vault returns `renewable: false` (configured Max TTL reached),
the loop logs a WARN, increments `{result="not_renewable"}`, and
exits. The operator must rotate the Vault token and either restart
certctl-server or use the GUI / MCP issuer-update path to swap the
token in place — the registry's Rebuild path re-Starts the lifecycle
on the new connector.

Per-tick failures (e.g. transient 5xx, brief network blips) bump
`{result="failure"}` and the loop keeps ticking. Only the explicit
`renewable: false` case stops it.

## MaxTTL enforcement (M11c)

When a certificate profile defines a maximum TTL, the Vault connector
overrides the TTL string in the signing request to ensure the issued
certificate does not exceed the profile limit. This is applied
**before** Vault's own role-level max TTL — so the effective limit is
the minimum of (profile.MaxTTL, role.MaxLeaseTTL).

## Revocation and CRL/OCSP

CRL and OCSP are managed by Vault itself. Clients should validate
certificate status against Vault's own CRL/OCSP endpoints
(`GET /v1/{mount}/crl` and Vault's OCSP responder). certctl does not
generate local CRL/OCSP for Vault-issued certificates. Revocation is
recorded locally (audit row + cert state) but Vault is the
authoritative source for relying parties.

## Operator playbook

### Token rotation without downtime

Two paths:

1. **Restart-driven.** Update `CERTCTL_VAULT_TOKEN` env var on the
   server, restart certctl-server. The renewal loop picks up the new
   token's lookup-self response and resumes ticking.
2. **Hot-swap via API/GUI.** `PUT /api/v1/issuers/{id}` with the
   updated config; the registry's Rebuild path replaces the connector
   without restart. Use this when Vault's Max TTL has been reached
   and the existing token can no longer be renewed.

### Diagnosing renewal failures

Watch
`certctl_vault_token_renewals_total{result="not_renewable"}` and
`{result="failure"}`. Sustained failures with no `not_renewable`
generally indicate Vault unreachability or token-policy drift; a
spike in `not_renewable` is the canonical signal that a Max TTL
boundary was hit and operator action is required.

## Related docs

- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [Issuer hierarchy primitive](../intermediate-ca-hierarchy.md) — how Vault sits as a sub-CA under another issuer
- [Async CA polling](../protocols/async-ca-polling.md) — the bounded-polling primitive used by other issuers; Vault is synchronous so does not consume it
