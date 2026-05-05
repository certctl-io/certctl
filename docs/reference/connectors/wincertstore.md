# Windows Certificate Store Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the Windows Certificate Store
> target connector. For the connector-development context (interface
> contract, registry, atomic deploy primitive shared across all
> targets), see the [connector index](index.md).

## Overview

The Windows Certificate Store connector imports certificates into
the Windows cert store via PowerShell, **without managing IIS site
bindings**. Use this for non-IIS Windows services that read
certificates from the cert store: Exchange, RDP, SQL Server, ADFS,
LSA-protected services, etc.

Same injectable `PowerShellExecutor` pattern as the IIS connector,
with optional WinRM proxy mode for agentless deployment to remote
Windows hosts.

Implementation lives at `internal/connector/target/wincertstore/`.

## When to use this connector

Use the Windows Certificate Store connector when:

- The target is a Windows service that reads certs from the
  Windows cert store (Exchange transport TLS, RDP listener, SQL
  Server SSL endpoint, ADFS token-signing cert, etc.).
- You don't want IIS-binding management (use the
  [IIS connector](iis.md) for that).
- You're deploying via an in-host agent (`mode: local`) or via
  WinRM from a proxy agent (`mode: winrm`).

Look elsewhere when:

- The target is IIS with site bindings — use the
  [IIS connector](iis.md) for binding management.
- The target reads certs from a JKS / PKCS#12 keystore — use the
  [Java Keystore](jks.md) connector.

## Configuration

```json
{
  "store_name": "My",
  "store_location": "LocalMachine",
  "friendly_name": "Production API Cert",
  "remove_expired": true
}
```

| Field | Default | Description |
|---|---|---|
| `store_name` | `"My"` | Windows cert store name (My, Root, WebHosting, etc.) |
| `store_location` | `"LocalMachine"` | `"LocalMachine"` or `"CurrentUser"` |
| `friendly_name` | — | Optional friendly name for the imported certificate |
| `remove_expired` | `false` | Remove expired certs with same CN after import |
| `mode` | `"local"` | `"local"` (agent-local) or `"winrm"` (remote) |
| `winrm_host` | — | WinRM hostname (required for winrm mode) |
| `winrm_port` | 5985 | WinRM port (5985 HTTP, 5986 HTTPS) |
| `winrm_username` | — | WinRM username (required for winrm mode) |
| `winrm_password` | — | WinRM password (required for winrm mode) |
| `winrm_https` | `false` | Use HTTPS for WinRM |
| `winrm_insecure` | `false` | Skip TLS verification for WinRM |
| `exec_deadline` | `60s` | Per-PowerShell-subprocess cap that fires only when the caller's `ctx` has no deadline of its own. A caller-supplied deadline always wins; this is a safety net so a hung WinRM session or stuck `Cert:` provider call cannot block the deploy worker indefinitely. Operators on slow links can extend with e.g. `"exec_deadline": "5m"`. |

## Deploy modes

### `mode: local`

Runs PowerShell in-process on the agent host. Requires the agent
to be installed on the Windows target itself. Best fit for
single-host services (a Windows server running Exchange or SQL
Server alone).

### `mode: winrm`

Runs PowerShell remotely via WinRM from a proxy agent. Best fit
for fleets where you don't want to install the certctl agent on
every Windows host. Use HTTPS WinRM (port 5986) with
`winrm_insecure: false` for production; HTTP WinRM (5985) is
acceptable on operator-controlled networks.

## Operator playbook

### Selecting the right store

- `My` — personal cert store under LocalMachine. Default for
  Exchange transport TLS, SQL Server, RDP, most service-account
  workloads.
- `Root` — trusted root CA store. **Don't import leaves here.**
  This is for adding trust anchors only.
- `WebHosting` — alternative store for IIS websites; the IIS
  connector typically uses `My` instead.

### Removing expired certs

`remove_expired: true` cleans up old cert versions with the same
Subject CN after a successful import. Useful in long-running
fleets where the cert store accumulates dozens of expired entries
over years of rotations.

### Handling private-key permissions

Imported certs land with the Network Service account having read
access by default. For services running as a different account
(e.g. a domain user for SQL Server), the operator needs to grant
that account read access to the private key after import — this
isn't automated by the connector. Use the post-deploy
`reload_command` to run a `Set-Acl` step if you need it.

## Related docs

- [Connector index](index.md) — interface contract, registry, deploy primitive
- [IIS connector](iis.md) — IIS site-binding management on top of the cert store
- [Java Keystore](jks.md) — JVM-based service alternative
