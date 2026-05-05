# Google CAS Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the Google Cloud Certificate
> Authority Service (CAS) issuer connector. For the
> connector-development context (interface contract, registry,
> ports/adapters), see the [connector index](index.md).

## Overview

Google Cloud Certificate Authority Service is a managed private CA
on GCP. Issuance is synchronous via the CAS REST API with OAuth2
service-account auth.

Implementation lives at `internal/connector/issuer/googlecas/`.

## When to use this connector

Use the Google CAS connector when:

- Your workloads are GCP-native and you want the CA to live inside
  your GCP project (for blast radius, IAM, and audit reasons).
- You want IAM-bound service-account auth instead of API keys to
  rotate.
- You need GCP-native CRL distribution and audit logging served by
  Google.

Look elsewhere when:

- You're not on GCP — AWS ACM Private CA or Azure Key Vault are
  the cloud-native equivalents on those platforms.
- You need public-trust certificates — CAS is private only.
- You don't already pay for CAS (it has a non-trivial monthly
  cost). Vault, step-ca, or the Local CA issuer are free
  self-hosted alternatives.

## Configuration

| Setting | Required | Default | Description |
|---|---|---|---|
| `CERTCTL_GOOGLE_CAS_PROJECT` | Yes | — | GCP project ID |
| `CERTCTL_GOOGLE_CAS_LOCATION` | Yes | — | GCP region (e.g. `us-central1`) |
| `CERTCTL_GOOGLE_CAS_CA_POOL` | Yes | — | CA pool name |
| `CERTCTL_GOOGLE_CAS_CREDENTIALS` | Yes | — | Path to service account JSON |
| `CERTCTL_GOOGLE_CAS_TTL` | No | `8760h` | Default certificate TTL |

## Authentication

OAuth2 service account. The connector reads a service account
JSON file, signs a JWT with the private key, and exchanges it for
an access token at Google's token endpoint. Tokens are cached and
refreshed automatically (5 min before expiry) so the connector
doesn't pay token-mint latency on every request.

## Revocation

CRL and OCSP are managed by Google CAS directly. certctl records
revocations locally and notifies Google CAS via the revoke
endpoint. CAS's CRL distribution and audit logging serve the
resulting status to verifying clients.

## Operator playbook

### Service-account key rotation

1. Generate a new service-account key in the GCP IAM console.
2. Distribute the new JSON to the certctl host at the
   `CERTCTL_GOOGLE_CAS_CREDENTIALS` path (overwrite or use a new
   path).
3. Either restart certctl-server with the new env var or hot-swap
   via `PUT /api/v1/issuers/{id}` so the registry's Rebuild path
   replaces the connector.
4. Delete the old key in GCP IAM after the next successful
   issuance proves the new key works.

### Required IAM roles

The service account needs `roles/privateca.certificateRequester`
(or a custom role with `privateca.certificates.create` and
`privateca.certificates.get`) on the CA pool. Add
`roles/privateca.certificateAuthorityUser` if the connector also
needs to read the issuing CA cert chain.

## Related docs

- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [AWS ACM PCA](aws-acm-pca.md) — AWS equivalent
- [Async CA polling](../protocols/async-ca-polling.md) — bounded-polling primitive (Google CAS is synchronous so doesn't consume it)
