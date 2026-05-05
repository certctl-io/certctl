# Active Directory Certificate Services (ADCS) Integration — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for integrating certctl with Microsoft
> ADCS as the enterprise root. For the connector-development context
> (interface contract, registry, ports/adapters), see the
> [connector index](index.md).

## Overview

ADCS integration is **not** a separate connector. certctl integrates
with ADCS via the **sub-CA mode** of the Local CA issuer: certctl
operates as a subordinate CA whose signing certificate was issued by
ADCS, so all certctl-issued certificates chain back to the enterprise
ADCS root.

This is the canonical pattern for Windows-shop deployments where
ADCS is already the root of trust and operators want certctl to
handle automation (lifecycle, renewal, deployment, alerts) without
ADCS having to support a non-Microsoft REST API surface.

## When to use this integration

Use ADCS sub-CA mode when:

- ADCS is your enterprise root and you don't want to introduce a
  parallel root of trust.
- You want all certctl-issued certificates to validate against the
  ADCS chain that's already in your Windows trust stores, mobile
  device profiles, and load-balancer configurations.
- You need certctl's automation surface (ACME, SCEP, EST, profile
  policy, scheduler, deployment connectors) but want ADCS to remain
  the signing authority for the root.

Look elsewhere when:

- You want certctl to issue from its own root of trust — use the
  Local CA issuer in self-signed mode.
- ADCS is being decommissioned or replaced — the migration path
  from ADCS to Vault PKI / step-ca / Local CA needs its own
  rollout plan; that's not what this connector covers.

## How sub-CA mode works

The Local CA issuer loads a pre-signed CA certificate and key from
disk:

- `CERTCTL_CA_CERT_PATH` — path to the certctl signing cert PEM
  (the one ADCS issued).
- `CERTCTL_CA_KEY_PATH` — path to the matching private key PEM.

Every leaf certctl issues is signed with this key, and the chain
returned to clients includes both the certctl signing cert and the
ADCS root (so verifying clients see a complete chain to the
enterprise root).

The signing certificate certctl uses is just a normal CA cert with
`Basic Constraints: CA=true` and an appropriate path-length
constraint. ADCS issues this certificate using its standard
"Subordinate Certification Authority" template; the operator just
takes the resulting cert + key and points certctl at them.

## Operator playbook

### Provisioning the certctl sub-CA

1. Generate a new keypair for certctl on the host that will run it
   (or in the HSM / KMS the operator wants to delegate signing to,
   via the `internal/crypto/signer/` driver interface when alternate
   drivers are configured).
2. Build a CSR with `Basic Constraints: CA=true`, the operator's
   chosen path-length constraint, and key usages including
   `keyCertSign` and `cRLSign`.
3. Submit the CSR to ADCS using the Subordinate Certification
   Authority template (or a custom template that grants those key
   usages).
4. Place the signed certctl-cert and the matching key at
   `CERTCTL_CA_CERT_PATH` / `CERTCTL_CA_KEY_PATH`.
5. Restart certctl-server (or Rebuild the issuer via the API).
   Subsequent issuance chains to the ADCS root.

### Rotating the sub-CA cert

When the certctl sub-CA cert is approaching expiry:

1. Generate a new keypair (re-keying is recommended at sub-CA
   rotation time).
2. CSR + ADCS signing cycle as above.
3. Stage the new cert and key at fresh paths
   (`CERTCTL_CA_CERT_PATH_NEW` etc.) and follow the
   [intermediate-CA hierarchy
   runbook](../intermediate-ca-hierarchy.md) for the cutover. The
   key concern is overlap: both the old and new sub-CA certs must
   chain to the ADCS root during the rollover so existing leaves
   keep validating.

### Revocation chain

CRL and OCSP for ADCS-rooted leaves are handled by certctl's CRL
distribution point and OCSP responder
([crl-ocsp.md](../protocols/crl-ocsp.md)). The ADCS root publishes
its own CRL covering the certctl sub-CA cert; relying parties walk
both CDP entries to determine the full revocation status.

## Related docs

- [Local CA issuer](index.md#built-in-local-ca) — the connector this integration uses
- [Intermediate CA hierarchy](../intermediate-ca-hierarchy.md) — how certctl manages multi-level CA trees, including ADCS-rooted setups
- [CRL and OCSP](../protocols/crl-ocsp.md) — how relying parties validate ADCS-rooted leaves
- [Architecture](../architecture.md) — `internal/crypto/signer/` driver interface for HSM / KMS / cloud-KMS alternatives to file-on-disk for the certctl sub-CA private key
