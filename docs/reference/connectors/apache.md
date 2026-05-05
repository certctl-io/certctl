# Apache httpd Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Per Phase 14 of the deploy-hardening II master bundle. For the
> connector-development context (interface contract, registry, atomic
> deploy primitive shared across all targets), see the
> [connector index](index.md).

## Overview

The Apache connector (`internal/connector/target/apache/`) deploys
TLS certs to Apache 2.4 LTS via separate cert/chain/key files +
`apachectl configtest` validate + `apachectl graceful` reload.
Mirrors the canonical NGINX template (Bundle I Phase 5).

## Vendor versions tested

- **Apache httpd 2.4 LTS** (only LTS branch; 2.6 is dev branch)

## Per-quirk operator guidance

### Multi-vhost cert-by-vhost

`TestVendorEdge_Apache_MultiVhostCertByVhost_DeployIsolated_E2E`

When Apache has multiple `<VirtualHost>` blocks each with its own
`SSLCertificateFile`, connector deploys to the matching vhost
only. Other vhosts unchanged.

### `apachectl graceful-stop` drains cleanly

`TestVendorEdge_Apache_ApachectlGracefulStop_DrainsCleanly_E2E`

`apachectl graceful` (the connector default) preserves in-flight
TLS connections. `apachectl restart` drops them.

### `mod_ssl` absent

`TestVendorEdge_Apache_ModSSLAbsent_DeployFailsWithActionableError_E2E`

If `mod_ssl` isn't loaded, `apachectl configtest` fails with
"Invalid command 'SSLCertificateFile'". Connector surfaces this
verbatim — operator action: `LoadModule ssl_module modules/mod_ssl.so`.

### `.htaccess` interactions

`TestVendorEdge_Apache_HtaccessRequireSSL_NotImpactedByDeploy_E2E`

`.htaccess` rules requiring SSL are not impacted by cert rotation.
The `Require` directive evaluates per-request against the
connection's TLS state, not the cert file.

### Apache 2.4 LTS reload semantics pinned

`TestVendorEdge_Apache_Apache24LTSReloadSemanticsPinned_E2E`

`apachectl graceful` semantics stable across 2.4.x patch versions.
No per-version branch needed.

### Syntax error rollback

`TestVendorEdge_Apache_SyntaxErrorRollback_E2E`

`apachectl configtest` failure aborts before atomic rename. Live
cert untouched.

### Per-vhost key ownership

`TestVendorEdge_Apache_PerVhostKeyOwnership_E2E`

When multiple vhosts share the same key file, ownership is
preserved across rotation. When each vhost has its own key,
per-file ownership is preserved per Bundle I Phase 5.

### Reload preserves connections

`TestVendorEdge_Apache_ReloadVsRestart_PreservesConnections_E2E`

In-flight TLS sessions survive `apachectl graceful` worker
swap. Documented in `docs/deployment-atomicity.md`.

### SNI server_name binding

`TestVendorEdge_Apache_SNIServerNameDeployBindsCorrect_E2E`

When deploy specifies `server_name` metadata, connector targets
the matching `<VirtualHost>` block.

### Cert chain ordering

`TestVendorEdge_Apache_ChainOrderingNormalized_E2E`

Apache requires leaf cert FIRST in `SSLCertificateFile` (or
chain in `SSLCertificateChainFile`). Connector preserves operator-
supplied ordering across rotation.

## V3-Pro deferrals

- Apache 2.6 (when it ships LTS).
- mod_md (Apache's built-in ACME) interop.

## Related docs

- [Atomic deploy + post-verify + rollback](deployment-atomicity.md)
- [Vendor compatibility matrix](deployment-vendor-matrix.md)
