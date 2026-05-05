# Azure Key Vault Target Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the Azure Key Vault target
> connector. For the connector-development context (interface
> contract, registry, atomic deploy primitive shared across all
> targets), see the [connector index](index.md).

## Overview

The Azure Key Vault target connector deploys certificates into
Azure Key Vault — the Azure-managed cert/secret store that
Application Gateway / Front Door / App Service / Container Apps
consume by KID URI. Rank 5 (Azure half) of the 2026-05-03
Infisical deep-research deliverable.

Implementation lives at `internal/connector/target/azurekv/`.

## When to use this connector

Use the Azure Key Vault target connector when:

- TLS terminates at Azure-managed edges (Application Gateway,
  Front Door, App Service, Container Apps) and those services
  consume certs by Key Vault KID URI.
- You need short-lived Azure credentials (managed identity,
  workload identity) rather than long-lived service-principal
  secrets.
- You need cross-region or cross-cloud-environment Key Vault
  endpoints (US-Gov `.vault.usgovcloudapi.net`, China
  `.vault.azure.cn`).

Look elsewhere when:

- The target is an Azure VM running NGINX / IIS / HAProxy
  directly — those connectors are simpler.
- The cert is for an internal Azure service that doesn't read
  from Key Vault (e.g. a custom .NET app reading PEM from disk).

## Configuration

```json
{
  "vault_url": "https://my-vault.vault.azure.net",
  "certificate_name": "api-prod",
  "tags": {"env": "production", "app": "api-gateway"},
  "credential_mode": "managed_identity"
}
```

| Field | Default | Description |
|---|---|---|
| `vault_url` | (required) | Key Vault DNS endpoint (`https://<vault-name>.vault.azure.net`). For US-Gov: `.vault.usgovcloudapi.net`; for China: `.vault.azure.cn`. |
| `certificate_name` | (required) | Cert object name in the vault (1-127 chars, alphanumeric + hyphens). Versions are auto-generated per import. |
| `tags` | — | Tags applied at every import (Key Vault carries tags forward across versions, unlike ACM). Reserved keys `certctl-managed-by` + `certctl-certificate-id` are set automatically. |
| `credential_mode` | `default` | One of `default` / `managed_identity` / `client_secret` / `workload_identity`. See "Auth recipes" below. |

## RBAC role (minimum permissions)

The off-the-shelf builtin role **Key Vault Certificates Officer**
covers everything. For minimum-permission deploys, use a custom
role with these data-plane operations on the vault scope
(`/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>`):

```
Microsoft.KeyVault/vaults/certificates/import/action
Microsoft.KeyVault/vaults/certificates/read
Microsoft.KeyVault/vaults/certificates/listversions/read
```

## Auth recipes

- **AKS workload identity (`credential_mode: workload_identity`)
  — recommended for AKS deploys.** Annotate the agent's
  ServiceAccount with
  `azure.workload.identity/client-id=<app-id>`. The AKS
  cluster's OIDC issuer + the federated credential on the app
  registration handle token exchange; no long-lived secrets.
- **Managed identity (`credential_mode: managed_identity`) —
  recommended for VM / App Service deploys.** Assign a
  system-assigned or user-assigned managed identity to the
  host; certctl-server / agent picks it up via IMDS. Pin
  `credential_mode` rather than letting `default` fall through
  to env vars (defends against accidental local-dev creds
  leaking into production).
- **Service principal (`credential_mode: client_secret`).**
  Configure `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` +
  `AZURE_CLIENT_SECRET` env vars on the agent. NOT recommended
  for production — long-lived client secret risk; rotate via
  Key Vault soft-delete recovery if leaked.
- **Default (`credential_mode: default` or unset).** SDK's
  `DefaultAzureCredential` walks env vars → managed identity →
  Azure CLI fallback. Useful for local-dev where the operator
  already has `az login` active.
- **Long-lived secrets in connector Config NOT supported** —
  same procurement-readability rule as AWS ACM.

## Atomic-rollback contract + Azure-version semantics

Every `DeployCertificate` snapshots the existing latest version
via `GetCertificate(name, "" /* latest */)` BEFORE calling
`ImportCertificate`. After import, the connector re-fetches the
latest version and compares serial numbers.

On serial-mismatch, the connector calls `ImportCertificate`
again with the snapshotted CER bytes (re-PFX'd with the
operator's key) — **as a NEW VERSION**. Key Vault doesn't
support "version-restore" without soft-delete recovery (which we
keep off the minimum-RBAC surface). The version history will
show e.g. v1=initial, v2=failed-renewal, v3=rollback-of-v2;
operators reading audit dashboards filter by tag.

### Soft-delete caveat

V2 doesn't manage Key Vault soft-delete recovery. If a previous
version was soft-deleted out-of-band (e.g. operator ran
`az keyvault certificate delete`), the rollback re-imports the
snapshot bytes as a new version rather than restoring the
soft-deleted version. Operators alerting on rollback frequency
should also watch for soft-delete events.

## App Gateway / Front Door attachment recipe

```hcl
data "azurerm_key_vault_certificate" "certctl_managed" {
  name         = "api-prod"
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_application_gateway" "main" {
  # ...
  ssl_certificate {
    name                = "certctl-managed"
    key_vault_secret_id = data.azurerm_key_vault_certificate.certctl_managed.secret_id
  }
}
```

Application Gateway / Front Door reference the cert by KID URI;
certctl rotates the version under the same name, and the AGW /
Front Door reference auto-resolves to the latest version (the
SDK's behaviour when the KID points to
`/certificates/<name>/<version>` vs `/certificates/<name>`
differs — the latter auto-tracks "latest"; the former pins).
**Pin the version-less KID for auto-tracking renewals.**

## Threat model carve-outs

- **Cert key bytes never written to disk on the agent.** PFX
  wrapping happens in memory (PKCS#12 via
  `software.sslmate.com/src/go-pkcs12`); the base64-encoded PFX
  is passed straight to the SDK's `ImportCertificate` call.
- **Provenance tags are mandatory.** Same
  `certctl-managed-by=certctl` +
  `certctl-certificate-id=<mc-id>` shape as AWS ACM. Operators
  identifying a stray Key Vault cert match against
  `certctl-managed-by`.
- **No long-lived Azure credentials in `Config`.** `Config`
  carries vault URL + cert name + operator tags + credential
  mode only. Auth is the Azure SDK credential chain.
- **`credential_mode: managed_identity` is the recommended
  production posture.** Defends against accidental env-var
  creds leaking into deployments where the host already has a
  managed identity assigned.

## Procurement checklist crib

Paste into security review:

- certctl uses Azure managed identity (or workload identity for
  AKS), not long-lived service-principal secrets.
- The cert key is held only in agent memory during the PFX wrap
  + import call; never written to disk.
- Every imported Key Vault cert is tagged with
  `certctl-managed-by=certctl` +
  `certctl-certificate-id=<mc-id>` for forensic traceability.
- Failed imports trigger automatic rollback by re-importing the
  snapshotted previous version's bytes; both outcomes are
  surfaced via Prometheus.
- The minimum RBAC role is 3 data-plane actions; Activity Log
  captures every API call for compliance audits.

## ValidateOnly contract

Key Vault has no dry-run API; `ValidateOnly` returns
`target.ErrValidateOnlyNotSupported`. Operators preview deploys
via `ValidateConfig` + `az keyvault certificate show
--vault-name <name> --name <cert>`.

## Related docs

- [Connector index](index.md) — interface contract, registry, deploy primitive
- [AWS ACM target](aws-acm.md) — AWS equivalent target
- [Cloud targets runbook](../../operator/runbooks/cloud-targets.md) — operator playbook covering both AWS ACM and Azure KV
