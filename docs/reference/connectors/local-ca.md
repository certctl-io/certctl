# Local CA Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the Local CA issuer. For the
> connector-development context (interface contract, registry,
> ports/adapters), see the [connector index](index.md).

## Overview

The Local CA issuer signs certificates using Go's `crypto/x509`
library directly inside certctl-server. There is no external CA
service involved — certctl owns the signing key and emits
certificates synchronously.

Implementation lives at `internal/connector/issuer/local/`.

## When to use this connector

Use the Local CA when:

- You're standing up an internal-only PKI and don't want to operate
  a separate CA service (Vault, step-ca, EJBCA).
- You want certctl to be the single point of administration:
  signing key, profile policy, CRL and OCSP responder, and
  lifecycle automation all live in one process.
- You want sub-CA mode to chain into an enterprise root (ADCS,
  HSM-backed root, or another upstream CA) so existing trust
  stores validate certctl-issued leaves automatically.

Look elsewhere when:

- You need a public-trust certificate — the Local CA is internal
  only. Use ACME or DigiCert / Sectigo for public trust.
- You want signing material backed by an HSM or cloud KMS — that
  is on the roadmap (the `internal/crypto/signer/` driver
  abstraction exists; HSM, cloud KMS, and SSH-CA drivers don't
  yet ship). Until those drivers ship, sub-CA mode pointing at a
  hardware-protected root is the closest production posture.

## Modes

### Self-signed mode (default)

Creates a CA on first use (in memory), issues certificates with
proper serial numbers, validity periods, SANs, and key usage
extensions. Designed for development and demos — certificates are
self-signed and not trusted by browsers without operator-side
trust-store work.

### Sub-CA mode (production)

Loads a CA certificate and private key from disk
(`CERTCTL_CA_CERT_PATH` + `CERTCTL_CA_KEY_PATH`). The CA cert was
signed by an upstream CA (e.g. ADCS), so all issued certificates
chain to the enterprise root trust hierarchy. Clients that
already trust the enterprise root automatically trust
certctl-issued certs.

Supports RSA, ECDSA, and PKCS#8 key formats. If the paths are not
set, the connector falls back to self-signed mode. The loaded
certificate must have `IsCA=true` and `KeyUsageCertSign`.

### Tree mode (Rank 8 — multi-level CA hierarchy)

When `Issuer.HierarchyMode = "tree"` is set on the issuer row, the
connector reads the active CA hierarchy from the
`intermediate_cas` table and assembles `IssuanceResult.ChainPEM`
by walking the `parent_ca_id` ancestry from the issuing leaf CA up
to the root.

Tree mode is operator-managed via the admin-gated
`/api/v1/issuers/{id}/intermediates` and
`/api/v1/intermediates/{id}` endpoints (`POST` to create / sign
children, `GET` to list / inspect, `POST .../retire` to two-phase
retire). The signing path is shared with single-mode (cert is
signed via `c.caCert` + `c.caSigner` from the on-disk issuing CA
cert+key); only the chain bytes differ.

RFC 5280 §3.2 (self-signed root validation), §4.2.1.9 (path-length
tightening), and §4.2.1.10 (NameConstraints subset semantics) are
enforced at the service layer fail-closed. The default is
`single`, byte-identical to the pre-Rank-8 historical flow.

See [intermediate-ca-hierarchy.md](../intermediate-ca-hierarchy.md)
for the operator runbook covering 4-level boundary, 3-level policy,
and 2-level internal-PKI patterns, and the migration runbook for
flipping a single-mode issuer to tree.

## Configuration

```json
{
  "ca_common_name": "CertCtl Local CA",
  "validity_days": 90,
  "ca_cert_path": "/etc/certctl/ca/ca.pem",
  "ca_key_path": "/etc/certctl/ca/ca-key.pem"
}
```

## CRL and OCSP (M15b)

The Local CA serves DER-encoded X.509 CRLs unauthenticated at
`GET /.well-known/pki/crl/{issuer_id}` (RFC 5280 §5, RFC 8615,
`Content-Type: application/pkix-crl`) with 24-hour validity.

An embedded OCSP responder at
`GET /.well-known/pki/ocsp/{issuer_id}/{serial}` (RFC 6960,
`Content-Type: application/ocsp-response`) returns signed OCSP
responses for issued certificates (good / revoked / unknown
status).

Both endpoints are reachable by relying parties with no certctl
API credentials, which is how standard TLS clients, browsers, and
hardware appliances consume these resources.

Certificates with profile TTL < 1 hour automatically skip
CRL/OCSP — expiry is treated as sufficient revocation for
short-lived credentials.

## Extended Key Usage support (M27)

The Local CA respects EKU constraints from certificate profiles
and adjusts key usage flags accordingly:

- **S/MIME** (`emailProtection` EKU) →
  `DigitalSignature | ContentCommitment`.
- **TLS** (`serverAuth` / `clientAuth` EKU) →
  `DigitalSignature | KeyEncipherment`.

This enables a single CA to issue TLS, S/MIME, code signing, and
timestamping certificates from one issuer row.

## MaxTTL enforcement (M11c)

When a certificate profile defines a maximum TTL, the Local CA
caps the `NotAfter` field to `min(validity_days, maxTTL)`. This
ensures certificates never exceed the profile's configured
lifetime regardless of the issuer's `validity_days` setting.

## L-014 file-on-disk threat-model carve-out

In file-driver mode (the default), the CA private key sits on the
certctl-server filesystem as a PEM at `CERTCTL_CA_KEY_PATH`. This
is a standard internal-PKI posture but means filesystem
compromise of the certctl host equals signing-key compromise.
Mitigations:

- **Filesystem permissions.** Mode 0600, owned by the certctl
  service user. The connector preflight refuses to load a key
  whose mode is wider than 0600.
- **Sub-CA rotation.** Rotate the certctl sub-CA cert+key
  periodically (yearly is a sensible default) so a captured key
  has a bounded blast-radius window.
- **Filesystem audit.** Add an `auditctl` watch on the key path;
  any read/write attempt outside certctl-server's process is
  logged.
- **Move to alternate signer drivers when they ship.** The
  `internal/crypto/signer/` interface is the integration seam;
  HSM (PKCS#11), cloud KMS, and SSH-CA drivers will close the
  filesystem-residency leg without changing the rest of the
  signing path.

## Related docs

- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [ADCS integration](adcs.md) — sub-CA mode rooted at ADCS
- [Intermediate CA hierarchy](../intermediate-ca-hierarchy.md) — tree mode operator runbook
- [CRL and OCSP](../protocols/crl-ocsp.md) — RFC 5280 / RFC 6960 endpoint reference
