# NGINX Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Per Phase 14 of the deploy-hardening II master bundle. Operator-grade
> documentation for the NGINX target connector. For the
> connector-development context (interface contract, registry, atomic
> deploy primitive shared across all targets), see the
> [connector index](index.md).

## Overview

The NGINX connector (`internal/connector/target/nginx/`) is the
canonical implementation of the deploy-hardening I atomic + verify
+ rollback contract (Bundle I Phase 4). Every other file-based
connector models on this one.

## Vendor versions tested

- **NGINX 1.25 LTS** (current LTS branch)
- **NGINX 1.27 stable** (current stable branch)

Older versions (1.18 EOL'd 2021, 1.20 EOL'd 2022) are explicitly
out of scope per frozen decision 0.1.

## Deploy contract

Every cert deploy follows the Bundle I `deploy.Apply(ctx, plan)`
flow:

1. **Idempotency check** — SHA-256 over cert+chain+key bytes; skip
   if all match destination.
2. **Pre-deploy backup** — copy existing files to
   `<path>.certctl-bak.<unix-nanos>`.
3. **Atomic write** — temp-file + chown + atomic rename per
   destination.
4. **PreCommit (validate)** — runs `nginx -t` per the operator's
   `validate_command`. Failure aborts; no live cert touched.
5. **Atomic rename** — temp → final for every File entry.
6. **PostCommit (reload)** — runs `nginx -s reload` per the
   operator's `reload_command`.
7. **Post-deploy TLS verify** — dials the configured endpoint;
   pulls leaf cert SHA-256; compares against deployed bytes.
   Mismatch triggers automatic rollback.

## Per-quirk operator guidance

### SSL session cache holds old cert

`TestVendorEdge_NGINX_SSLSessionCacheHoldsOldCert_E2E`

NGINX's `ssl_session_cache` (default `shared:SSL:10m`) keeps TLS
session IDs valid for `ssl_session_timeout` (default 5min). Clients
that resume via session ID see the OLD cert until their session
expires.

**Operator action:** this is documented behavior, not a bug.
Tune via `ssl_session_timeout 5m;` (default) or shorter if your
cert rotation cadence demands. Post-deploy verify in certctl will
return the NEW cert from a fresh handshake (no session resumption);
warm clients see the OLD cert until session-cache eviction.

### SNI multi-server-name binding

`TestVendorEdge_NGINX_SNIMultiServerName_DeployBindsCorrectVhost_E2E`

When NGINX has multiple `server { server_name a.example b.example; }`
blocks, the operator deploys with metadata pointing at the
specific vhost. Connector binds to that vhost only; other vhosts
remain unchanged.

### IPv6 dual-stack

`TestVendorEdge_NGINX_IPv6DualStackBindsBoth_E2E`

NGINX listening on `0.0.0.0:443` + `[::]:443` serves the new cert
on both stacks after a single deploy.

**Operator action:** if your post-deploy verify endpoint resolves
to IPv6 only on some networks but IPv4 only on others, configure
`PostDeployVerifyAttempts: 5` to cover both paths.

### Reload vs restart

`TestVendorEdge_NGINX_ReloadVsRestart_NoConnectionDrop_E2E`

`nginx -s reload` (graceful) preserves in-flight TLS connections
via worker handoff. `nginx -s stop && nginx` drops them.

**Operator action:** never use restart for cert rotation. The
connector's default `reload_command: nginx -s reload` is correct.

### Binary upgrade

`TestVendorEdge_NGINX_UpgradeBinaryHotReload_E2E`

`nginx -s upgrade` rolls out a new binary without dropping
connections. Not commonly used; documented for ops teams that do
rolling NGINX binary upgrades.

### Config syntax error → rollback

`TestVendorEdge_NGINX_ConfigSyntaxError_RollbackRestoresPreviousCert_E2E`

If `nginx -t` rejects the staged config, the deploy package's
PreCommit gate fires before the atomic rename — no live file is
touched. The cert directory is exactly as it was.

### Missing intermediate

`TestVendorEdge_NGINX_MissingIntermediate_DeployedButValidationCatchesAtPostVerify_E2E`

If the operator deploys a leaf-only cert (no intermediate), NGINX
will start serving it but downstream clients fail chain validation.
The connector's post-deploy TLS verify catches this via cert chain
walk; rollback fires automatically.

### Access log privacy

`TestVendorEdge_NGINX_AccessLogPrivacy_NoCertBytesLeakInLogs_E2E`

NGINX's default `access_log` and `error_log` formats do NOT include
SSL key bytes. The connector does not modify NGINX's logging config.

**Operator action:** if you've customized `log_format` to include
`$ssl_*` variables, audit the format string for sensitive fields.

### Per-version reload-command compat

`TestVendorEdge_NGINX_NGINX125_vs_127_ReloadCommandCompatible_E2E`

`nginx -s reload` semantics are identical between 1.25 LTS and
1.27 stable. No per-version branch needed in operator config.

### High-concurrency deploy under load

`TestVendorEdge_NGINX_HighConcurrencyDeployUnderLoad_E2E`

NGINX's worker handoff during reload is graceful; concurrent TLS
handshakes during a deploy succeed without 5xx errors.

## Troubleshooting matrix

| Symptom | Test name | Root cause | Operator action |
|---|---|---|---|
| Old cert returned 5min after deploy | `SSLSessionCacheHoldsOldCert_E2E` | session cache TTL | tune `ssl_session_timeout` |
| Wrong vhost serves new cert | `SNIMultiServerName_E2E` | misconfigured server_name selector | verify vhost metadata |
| Post-verify fails on IPv6 | `IPv6DualStackBindsBoth_E2E` | flaky DNS resolution | `PostDeployVerifyAttempts: 5` |
| Connection drops on cert change | n/a | using restart instead of reload | use `nginx -s reload` |
| Deploy aborts with `nginx -t` error | `ConfigSyntaxError_RollbackRestoresPreviousCert_E2E` | bad config (not deploy's fault) | fix config; redeploy |
| Chain-validation failure post-deploy | `MissingIntermediate_E2E` | leaf-only cert | include full chain in deploy |

## V3-Pro deferrals

- Pin NGINX `ssl_session_ticket_key` rotation interaction with cert
  rotation (rare; documented but not tested).
- NGINX Plus `dyn_pem` API integration (commercial; not V2 scope).

## Related docs

- [Atomic deploy + post-verify + rollback](deployment-atomicity.md)
  — the Bundle I primitive every connector consumes.
- [Vendor compatibility matrix](deployment-vendor-matrix.md)
- [Connectors reference](connectors.md)
