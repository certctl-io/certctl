# Deployment Vendor Compatibility Matrix

> Deploy-hardening II master bundle deliverable. The procurement-team
> headline doc — SOC 2 / PCI auditors paste this into evidence packs.
> Per frozen decision 0.14: a (connector × vendor-version) cell is
> "verified" only when ALL apply: ≥1 happy-path e2e passes against
> the real sidecar; ≥1 specific-quirk test for that version passes;
> operator manual smoke completed at least once on a real (non-CI)
> instance of that vendor version.

## Status legend

- **✓** — verified per the three-criterion bar above
- **CI** — happy-path + quirk e2e green in CI; operator manual smoke
  pending (the third criterion)
- **mock** — verified against the in-tree mock; real-vendor validation
  is the operator's tier above
- **pending** — planned; tests written; sidecar not yet wired
- **n/a** — combination not applicable

Per frozen decision 0.1: only LTS + current-stable versions per
vendor. EOL versions explicitly excluded.

## Matrix

| Connector | Vendor | Version | Status | Known Issues | Workaround | E2E Test Name(s) |
|---|---|---|---|---|---|---|
| **NGINX** | nginx.org | 1.25 LTS | CI | SSL session cache holds old cert ~5min | `ssl_session_timeout 5m;` (default) — operator-tunable | `TestVendorEdge_NGINX_SSLSessionCacheHoldsOldCert_E2E` |
| NGINX | nginx.org | 1.27 stable | CI | (same) | (same) | (same) |
| **Apache httpd** | httpd.apache.org | 2.4 LTS | CI | mod_ssl multi-vhost ownership | per-vhost cert config; SSLCertificateFile per `<VirtualHost>` | `TestVendorEdge_Apache_MultiVhostCertByVhost_E2E` |
| **HAProxy** | haproxy.org | 2.6 LTS | CI | reload vs restart semantics | use `systemctl reload haproxy` not `restart` | `TestVendorEdge_HAProxy_ReloadPreservesConnectionsViaSocketActivation_E2E` |
| HAProxy | haproxy.org | 2.8 | CI | (same) | (same) | (same) |
| HAProxy | haproxy.org | 3.0 | CI | (same) | (same) | (same) |
| **Traefik** | traefik.io | 2.x | CI | static-config cert paths require restart | use dynamic file-provider config | `TestVendorEdge_Traefik_StaticConfigRequiresRestart_DocumentedAsLimitation_E2E` |
| Traefik | traefik.io | 3.x | CI | (same) | (same) | (same) |
| **Caddy** | caddyserver.com | 2.x | CI | admin API auth lockdown breaks default deploy | set `Caddy.AdminAuthorizationHeader` per-target | `TestVendorEdge_Caddy_AdminAPILockedDownWithAuth_DeployUsesConfiguredAuthHeaders_E2E` |
| **Envoy** | envoyproxy.io | 1.30 | CI | file-mode SDS only in V2; gRPC SDS V3-Pro | use SDS=file (default) | `TestVendorEdge_Envoy_SDSFileMode_DeployRewritesYAML_EnvoyHotReloads_E2E` |
| Envoy | envoyproxy.io | 1.32 | CI | (same) | (same) | (same) |
| **Postfix** | postfix.org | 3.6 | CI | per-listener cert binding | configure cert per-listener block | `TestVendorEdge_Postfix_MultiListenerCertBinding_DeployUpdatesCorrectListener_E2E` |
| Postfix | postfix.org | 3.8 | CI | (same) | (same) | (same) |
| **Dovecot** | dovecot.org | 2.3 | CI | submission/submissions port variants | configure both inet_listener blocks | `TestVendorEdge_Dovecot_SubmissionSubmissionsPortVariants_E2E` |
| **IIS** | microsoft.com | IIS 10 (Server 2019) | pending | Windows-host-only CI; app-pool recycle opt-in | `AppPoolRecycle: true` per-target if needed | `TestVendorEdge_IIS_AppPoolRecycle_OptInForCertChange_E2E` |
| IIS | microsoft.com | IIS 10 (Server 2022) | pending | (same) | (same) | (same) |
| **F5 BIG-IP** | f5.com | v15.1 LTS | mock | larger cert chain (>4 links) historical issue | use cert chain ≤4 links OR upgrade to v17 | `TestVendorEdge_F5_LargeCertChainHandling_E2E` |
| F5 BIG-IP | f5.com | v17.0 | mock | (chain limit lifted) | n/a | (same) |
| F5 BIG-IP | f5.com | v17.5 | mock | (same) | n/a | (same) |
| **SSH** | openssh.com | OpenSSH 8.x | CI | sftp subsystem may be disabled | connector falls back to scp | `TestVendorEdge_SSH_SFTPSubsystemAbsent_FallsBackToSCP_E2E` |
| SSH | openssh.com | OpenSSH 9.x | CI | (same) | (same) | (same) |
| **WinCertStore** | microsoft.com | Windows Server 2019 | pending | cert store ACL: NS vs IIS_IUSRS | configure store ACL per IIS app-pool identity | `TestVendorEdge_WinCertStore_CertStoreACL_NetworkServiceAccess_E2E` |
| WinCertStore | microsoft.com | Windows Server 2022 | pending | (same) | (same) | (same) |
| **JavaKeystore** | adoptium.net | JDK 11 LTS | pending | keytool `-importkeystore` semantics | use `KeytoolPath` config to pin to JDK | `TestVendorEdge_JavaKeystore_JDK11_vs_17_vs_21_KeytoolBehavior_E2E` |
| JavaKeystore | adoptium.net | JDK 17 LTS | pending | (same) | (same) | (same) |
| JavaKeystore | adoptium.net | JDK 21 LTS | pending | (same) | (same) | (same) |
| **Kubernetes** | kubernetes.io | 1.28 LTS | CI | kubelet sync ~60s for pod-mounted Secrets | `CERTCTL_K8S_DEPLOY_KUBELET_SYNC_TIMEOUT=60s` (default) | `TestVendorEdge_K8s_KubeletSyncWaitContract_DefaultTimeout60s_E2E` |
| Kubernetes | kubernetes.io | 1.30 | CI | (same) | (same) | (same) |
| Kubernetes | kubernetes.io | 1.31 current | CI | (same) | (same) | (same) |

## Quarterly re-pin cadence

Every sidecar `FROM` in `deploy/docker-compose.test.yml` carries a
SHA-256 digest pin per the H-001 CI guard. Operator re-pins
quarterly:

1. Pull the latest tag of each sidecar image.
2. Run the per-vendor e2e matrix against the new digest.
3. If green, update the digest in `docker-compose.test.yml` + this
   matrix's "Status" column.
4. If red, file an issue against the connector + leave the digest
   pinned to the last-known-good.

## How to add a new vendor version

1. Add a new sidecar entry to `deploy/docker-compose.test.yml` with
   the new image digest.
2. Add a row to this matrix marking status as "pending".
3. Write `TestVendorEdge_<connector>_<edge>_E2E` test(s) that
   exercise the vendor's known quirks against the new sidecar.
4. Once tests pass in CI, mark status "CI".
5. After operator manual smoke, mark status "✓".

## Per-connector deep-dive docs

For the top 5 most-deployed connectors:

- [NGINX deep-dive](connector-nginx.md)
- [Kubernetes deep-dive](connector-k8s.md)
- [IIS deep-dive](connector-iis.md)
- [Apache deep-dive](connector-apache.md)
- [F5 deep-dive](connector-f5.md)

Other connector docs live in [docs/connectors.md](connectors.md).
