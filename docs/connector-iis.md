# Microsoft IIS Connector — Operator Deep-Dive

> Per Phase 14 of the deploy-hardening II master bundle.

## Overview

The IIS connector (`internal/connector/target/iis/`) deploys TLS
certs to Windows IIS servers via PowerShell (`Import-PfxCertificate`
+ `New-WebBinding` + SNI binding). Pre-deploy snapshot of the
existing thumbprint allows rollback if the new binding fails.

## Vendor versions tested

- **Windows Server 2019** with IIS 10
- **Windows Server 2022** with IIS 10

## CI runner constraint

Per frozen decision 0.4: Windows containers run only on Windows
hosts. Linux CI runners CAN'T run the IIS sidecar. IIS e2e tests
run on a separate `windows-vendor-e2e` GitHub Actions matrix job
on `windows-latest` runners. Operators on Linux-only CI use
`//go:build integration && !no_iis` to skip.

## Per-quirk operator guidance

### App-pool recycle (opt-in)

`TestVendorEdge_IIS_AppPoolRecycle_OptInForCertChange_E2E`

By default, IIS picks up new SSL bindings without app-pool
recycle (the binding-edit path is hot). Some sites need recycle
to fully reload (e.g., apps that cache cert handles).

**Operator action:** set `AppPoolRecycle: true` per-target. The
connector then runs `Restart-WebAppPool <pool>` after binding update.

### SNI multi-binding per site

`TestVendorEdge_IIS_SNIMultiBindingPerSite_DeployUpdatesCorrectBinding_E2E`

When a site has multiple SNI bindings (different hostnames on
the same site), connector targets the binding matching the
operator-supplied hostname. Other bindings unchanged.

### CCS (Centralized Certificate Store)

`TestVendorEdge_IIS_CCSCentralizedCertStoreVariant_DeployToSharedStore_E2E`

CCS is the file-based variant where multiple IIS servers share
a UNC path of cert files. Connector writes to the shared path;
all IIS servers pick it up automatically.

### WinRM remote vs local PowerShell

`TestVendorEdge_IIS_WinRMRemotePath_vs_LocalPowerShellPath_BothWork_E2E`

Two code paths produce equivalent cert installs:
- `WinRMHost: ""` → local PowerShell (agent runs on the IIS server)
- `WinRMHost: "iis.example"` → remote PowerShell via WinRM

Both rotate the same way. WinRM path requires network reachability
to port 5985/5986.

### Server 2019 vs 2022 PowerShell compat

`TestVendorEdge_IIS_WindowsServer2019_vs_2022_PowerShellCompat_E2E`

`Import-PfxCertificate` + `New-WebBinding` semantics are stable
across server versions. PowerShell 5.1 (2019) + PowerShell 7.x
(2022) both work.

### Friendly name

`TestVendorEdge_IIS_FriendlyNameUpdatedOnRotation_E2E`

Connector preserves operator-supplied `FriendlyName` on the cert
across rotation. Useful for IIS GUI identification.

### HTTP/2 + ALPN

`TestVendorEdge_IIS_HTTP2ALPNPreserved_E2E`

IIS h2 negotiation preserved across cert rotation. The
`netsh http show sslcert` ALPN attribute survives the binding swap.

### Binding-type validation

`TestVendorEdge_IIS_BindingTypeHttpsValidated_E2E`

Connector refuses to deploy to non-`https` bindings (e.g., `http`,
`net.tcp`). Surfaces actionable error.

### ARR reverse-proxy

`TestVendorEdge_IIS_ARRReverseProxyCertRotation_E2E`

Sites using Application Request Routing as reverse proxy: cert
rotation does not invalidate ARR routes. The cert-binding edit
is independent of the ARR config.

### Atomic SNI binding swap

`TestVendorEdge_IIS_RemovePreviousBindingOnRotate_E2E`

Connector removes the previous SNI binding BEFORE inserting the
new one (atomicity at the IIS API level). Prevents brief
window where two bindings serve different certs for the same
hostname.

## Troubleshooting matrix

| Symptom | Test name | Operator action |
|---|---|---|
| Cert installed but app pool serving old cert | `AppPoolRecycle_OptInForCertChange_E2E` | set `AppPoolRecycle: true` |
| Wrong SNI binding updated | `SNIMultiBindingPerSite_E2E` | verify hostname selector |
| Permission denied on cert install | n/a | agent must run as administrator |
| WinRM connection failed | `WinRMRemotePath_vs_LocalPowerShellPath_E2E` | check WinRM port 5985/5986 reachability |
| h2 negotiation broken post-rotate | `HTTP2ALPNPreserved_E2E` | re-run `netsh http add sslcert` with `appid + clientcertnegotiation=enable` |

## V3-Pro deferrals

- IIS Application Initialization module integration (warm cert
  cache after rotation).
- Azure Key Vault + IIS integration (operator opt-in).

## Related docs

- [Atomic deploy + post-verify + rollback](deployment-atomicity.md)
- [Vendor compatibility matrix](deployment-vendor-matrix.md)
