# step-ca (Smallstep) Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the step-ca issuer connector.
> For the connector-development context (interface contract,
> registry, ports/adapters), see the [connector index](index.md).

## Overview

The step-ca connector integrates with Smallstep's step-ca private
CA using its native `/sign` API with JWK provisioner
authentication. Issuance is synchronous — submit a CSR plus a
provisioner-signed token, get back a signed certificate in the
same response.

This is simpler than ACME for internal PKI: no challenge solving,
no domain validation, just CSR + auth token → signed certificate.
For ACME-based step-ca usage, point the ACME connector at
step-ca's ACME directory URL instead.

Implementation lives at `internal/connector/issuer/stepca/`.

## When to use this connector

Use the step-ca connector when:

- You already run step-ca as your internal CA and want certctl to
  drive lifecycle automation on top.
- You want synchronous issuance against an internal CA without
  ACME's challenge dance.
- You want certctl to enforce profile / MaxTTL policy on step-ca-
  issued certs.

Look elsewhere when:

- You want to use step-ca's ACME directory — that path goes
  through the [ACME connector](acme.md) instead, which gives you
  ACME features (ARI, EAB, profile selection) on top.
- You don't already run step-ca and want a simpler internal CA —
  the [Local CA](local-ca.md) issuer is a one-process alternative.

## Configuration

```json
{
  "ca_url": "https://ca.internal:9000",
  "provisioner_name": "certctl",
  "provisioner_key_path": "/etc/certctl/stepca/provisioner.json",
  "provisioner_password": "...",
  "root_cert_path": "/etc/certctl/stepca/root_ca.crt",
  "validity_days": 90
}
```

Environment variables:

- `CERTCTL_STEPCA_URL` — step-ca server URL
- `CERTCTL_STEPCA_PROVISIONER` — JWK provisioner name
- `CERTCTL_STEPCA_KEY_PATH` — Path to provisioner private key
  (JWK JSON)
- `CERTCTL_STEPCA_PASSWORD` — Provisioner key password

## Authentication: JWK provisioner

A JWK provisioner is created in step-ca with a passphrase-encrypted
private key (JSON Web Key format). certctl signs short-lived
proof-of-authorization tokens with the provisioner key for each
issuance request. The provisioner password is needed to decrypt the
JWK on disk; it is held in memory by certctl-server.

Rotation: rotate the JWK provisioner in step-ca, distribute the new
JWK + password to certctl, then either restart certctl-server or
hot-swap via `PUT /api/v1/issuers/{id}` so the registry's Rebuild
path replaces the connector with the new provisioner config.

## MaxTTL enforcement (M11c)

When a certificate profile defines a maximum TTL, the step-ca
connector caps the `NotAfter` field to ensure the issued
certificate does not exceed the profile limit, regardless of the
step-ca provisioner's own maximum.

## Revocation and CRL/OCSP

step-ca-issued certificates rely on step-ca's own CRL/OCSP
infrastructure. certctl's local CRL/OCSP endpoints
(`GET /.well-known/pki/crl/{issuer_id}` and
`GET /.well-known/pki/ocsp/{issuer_id}/{serial}`, served
unauthenticated per RFC 5280 §5 / RFC 6960 / RFC 8615) are
populated from step-ca's revocation data if available, but clients
should validate against step-ca's endpoints for the authoritative
status.

## Related docs

- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [ACME connector](acme.md) — alternative path to step-ca via its ACME directory URL
- [Local CA issuer](local-ca.md) — simpler internal-CA alternative when step-ca isn't already deployed
