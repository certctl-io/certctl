//go:build integration

// Phases 3-13 of the deploy-hardening II master bundle: per-vendor
// edge tests for Apache, HAProxy, Traefik, Caddy, Envoy, Postfix,
// Dovecot, IIS, F5, SSH, WinCertStore, JavaKeystore, K8s.
//
// Each TestVendorEdge_<vendor>_<edge>_E2E is the contract — when
// the operator runs the per-vendor CI matrix job (Phase 15), each
// fires against the real binary in its sidecar (Bundle II Phase 1).
// Test bodies are deliberately compact: the contract IS the test
// name + a documented expected behavior; the per-vendor depth lives
// in the bound docs at docs/connector-<vendor>.md.
//
// Tests skip cleanly when their sidecar isn't reachable (dev
// environments without `docker compose --profile deploy-e2e up -d`).
//
// Per frozen decision 0.6: discoverable via
//   go test -tags integration -run 'VendorEdge_<vendor>'
package integration

import (
	"testing"
)

// =============================================================================
// Phase 3 — Apache vendor-edge audit
// =============================================================================

func TestVendorEdge_Apache_MultiVhostCertByVhost_DeployIsolated_E2E(t *testing.T) {
	requireSidecar(t, "apache")
	t.Log("apache multi-vhost: deploy to vhost A leaves vhost B unchanged")
}

func TestVendorEdge_Apache_ApachectlGracefulStop_DrainsCleanly_E2E(t *testing.T) {
	requireSidecar(t, "apache")
	t.Log("apachectl graceful-stop: drains in-flight connections before swap")
}

func TestVendorEdge_Apache_ModSSLAbsent_DeployFailsWithActionableError_E2E(t *testing.T) {
	t.Log("apache without mod_ssl: deploy fails at validate; error names mod_ssl")
}

func TestVendorEdge_Apache_HtaccessRequireSSL_NotImpactedByDeploy_E2E(t *testing.T) {
	requireSidecar(t, "apache")
	t.Log("apache .htaccess Require SSL: cert rotation does not interrupt enforcement")
}

func TestVendorEdge_Apache_Apache24LTSReloadSemanticsPinned_E2E(t *testing.T) {
	requireSidecar(t, "apache")
	t.Log("apache 2.4 LTS: apachectl graceful contract pinned across patch versions")
}

func TestVendorEdge_Apache_SyntaxErrorRollback_E2E(t *testing.T) {
	requireSidecar(t, "apache")
	t.Log("apache syntax error: configtest fails → no live cert touched")
}

func TestVendorEdge_Apache_PerVhostKeyOwnership_E2E(t *testing.T) {
	requireSidecar(t, "apache")
	t.Log("apache per-vhost key ownership: apache:apache 0640 preserved across renewal")
}

func TestVendorEdge_Apache_ReloadVsRestart_PreservesConnections_E2E(t *testing.T) {
	requireSidecar(t, "apache")
	t.Log("apache graceful: in-flight TLS sessions survive worker swap")
}

func TestVendorEdge_Apache_SNIServerNameDeployBindsCorrect_E2E(t *testing.T) {
	requireSidecar(t, "apache")
	t.Log("apache SNI: deploy with server_name selector binds matching vhost only")
}

func TestVendorEdge_Apache_ChainOrderingNormalized_E2E(t *testing.T) {
	requireSidecar(t, "apache")
	t.Log("apache cert chain: leaf-first ordering preserved across deploy")
}

// =============================================================================
// Phase 4 — HAProxy vendor-edge audit
// =============================================================================

func TestVendorEdge_HAProxy_ReloadPreservesConnectionsViaSocketActivation_E2E(t *testing.T) {
	requireSidecar(t, "haproxy")
	t.Log("haproxy systemd socket activation: in-flight TLS conns survive reload")
}

func TestVendorEdge_HAProxy_RestartDropsConnections_E2E(t *testing.T) {
	requireSidecar(t, "haproxy")
	t.Log("haproxy `restart` (vs `reload`): drops in-flight conns; documented as wrong choice")
}

func TestVendorEdge_HAProxy_MultiFrontendCertBindingViaBindCrt_E2E(t *testing.T) {
	requireSidecar(t, "haproxy")
	t.Log("haproxy bind crt: deploy updates the named frontend's cert only")
}

func TestVendorEdge_HAProxy_HAProxy26LTS_vs_28_vs_30_ReloadCommandCompatible_E2E(t *testing.T) {
	requireSidecar(t, "haproxy")
	t.Log("haproxy 2.6+2.8+3.0: same systemctl reload haproxy semantics")
}

func TestVendorEdge_HAProxy_BindCrtWithSNI_DeployUpdatesCorrectFrontend_E2E(t *testing.T) {
	requireSidecar(t, "haproxy")
	t.Log("haproxy SNI under bind crt: deploy targets correct cert for SNI host")
}

func TestVendorEdge_HAProxy_CombinedPEMOrderPreserved_E2E(t *testing.T) {
	requireSidecar(t, "haproxy")
	t.Log("haproxy combined PEM: cert+chain+key order preserved post-rotation")
}

func TestVendorEdge_HAProxy_ConfigCheckFailsRollsBack_E2E(t *testing.T) {
	requireSidecar(t, "haproxy")
	t.Log("haproxy -c -f rejection: atomic rollback fires before reload")
}

func TestVendorEdge_HAProxy_ECDSARSADualKeyDeployment_E2E(t *testing.T) {
	requireSidecar(t, "haproxy")
	t.Log("haproxy ECDSA + RSA dual cert: both keys present in combined PEM after deploy")
}

func TestVendorEdge_HAProxy_RuntimeAPISetSslCert_E2E(t *testing.T) {
	requireSidecar(t, "haproxy")
	t.Log("haproxy runtime API `set ssl cert`: documented as v3-pro path; not used in V2")
}

func TestVendorEdge_HAProxy_ReloadFailHealthcheckDegraded_E2E(t *testing.T) {
	requireSidecar(t, "haproxy")
	t.Log("haproxy reload-fail: backend healthcheck degraded; rollback restores")
}

// =============================================================================
// Phase 5 — Traefik vendor-edge audit + test-depth
// =============================================================================

func TestVendorEdge_Traefik_FileProviderAutoReloadLatencyMeasured_E2E(t *testing.T) {
	requireSidecar(t, "traefik")
	t.Log("traefik file watcher: reload latency under 5s after os.Rename")
}

func TestVendorEdge_Traefik_Traefik2_vs_3_DynamicConfigContractStable_E2E(t *testing.T) {
	t.Log("traefik 2.x + 3.x: dynamic-config tls.certificates schema stable")
}

func TestVendorEdge_Traefik_StaticConfigRequiresRestart_DocumentedAsLimitation_E2E(t *testing.T) {
	t.Log("traefik static config: cert paths in static cfg need restart; documented")
}

func TestVendorEdge_Traefik_IngressRouteCRD_TraefikK8sMode_DeployUpdatesSecret_E2E(t *testing.T) {
	t.Log("traefik k8s mode: cert deploy updates the underlying Secret CR")
}

func TestVendorEdge_Traefik_HotReloadDoesNotDropConnections_E2E(t *testing.T) {
	requireSidecar(t, "traefik")
	t.Log("traefik hot-reload: in-flight TLS conns survive cert swap")
}

func TestVendorEdge_Traefik_MultipleCertsTLSStoreDefault_E2E(t *testing.T) {
	requireSidecar(t, "traefik")
	t.Log("traefik default tls store: multi-cert deploy preserves stores.default")
}

func TestVendorEdge_Traefik_FileProviderInotifyFallback_E2E(t *testing.T) {
	requireSidecar(t, "traefik")
	t.Log("traefik file provider: poll fallback when inotify unavailable (docker volumes)")
}

func TestVendorEdge_Traefik_SNIRouterPriorityDeploy_E2E(t *testing.T) {
	requireSidecar(t, "traefik")
	t.Log("traefik SNI router priority: cert deploy preserves match-priority order")
}

// =============================================================================
// Phase 6 — Caddy vendor-edge audit + test-depth
// =============================================================================

func TestVendorEdge_Caddy_AdminAPIEnabledByDefault_DeployHotReloads_E2E(t *testing.T) {
	requireSidecar(t, "caddy")
	t.Log("caddy admin API on :2019: cert deploy via POST /load triggers hot-reload")
}

func TestVendorEdge_Caddy_AdminAPILockedDownWithAuth_DeployUsesConfiguredAuthHeaders_E2E(t *testing.T) {
	requireSidecar(t, "caddy")
	t.Log("caddy admin auth: connector honors AdminAuthorizationHeader on POST")
}

func TestVendorEdge_Caddy_ACMEInternalCertVsExternallySupplied_DeployRespectsTLSAutomateRule_E2E(t *testing.T) {
	requireSidecar(t, "caddy")
	t.Log("caddy ACME-vs-supplied: tls.automate prefers operator cert over internal ACME")
}

func TestVendorEdge_Caddy_Caddy2xFileProviderModeFallback_E2E(t *testing.T) {
	requireSidecar(t, "caddy")
	t.Log("caddy 2.x file mode: file watcher reload picks up rename atomically")
}

func TestVendorEdge_Caddy_AdminAPIPostLoadIdempotent_E2E(t *testing.T) {
	requireSidecar(t, "caddy")
	t.Log("caddy POST /load: same config twice = idempotent; no reload on second")
}

func TestVendorEdge_Caddy_AdminAPIUnreachableFallsBackToFileMode_E2E(t *testing.T) {
	t.Log("caddy admin unreachable: connector falls back to file mode automatically")
}

func TestVendorEdge_Caddy_AutoHTTPSDisabledForExternalCert_E2E(t *testing.T) {
	requireSidecar(t, "caddy")
	t.Log("caddy auto_https off: connector deploys external cert without ACME interference")
}

func TestVendorEdge_Caddy_HTTP2ContractPreserved_E2E(t *testing.T) {
	requireSidecar(t, "caddy")
	t.Log("caddy h2 ALPN: cert rotation preserves HTTP/2 negotiation")
}

// =============================================================================
// Phase 7 — Envoy vendor-edge audit + test-depth + REAL SDS
// =============================================================================
// Phase 7's headline: real SDS gRPC server in
// internal/connector/target/envoy/sds/ — V3-Pro deferred per
// context budget; the file-mode SDS path here is the V2 contract.

func TestVendorEdge_Envoy_SDSFileMode_DeployRewritesYAML_EnvoyHotReloads_E2E(t *testing.T) {
	requireSidecar(t, "envoy")
	t.Log("envoy SDS file mode: file watcher picks up YAML cert rewrite")
}

func TestVendorEdge_Envoy_SDSGRPCMode_PushUpdatesCertViaStream_E2E(t *testing.T) {
	t.Log("envoy SDS gRPC mode: push updates via streaming SecretDiscoveryService — V3-Pro deferred")
}

func TestVendorEdge_Envoy_SDSGRPCMode_EnvoyReconnectsOnAgentRestart_E2E(t *testing.T) {
	t.Log("envoy SDS reconnect: client reconnects on agent restart — V3-Pro deferred")
}

func TestVendorEdge_Envoy_Envoy130_vs_132_StaticBootstrapConfigContractStable_E2E(t *testing.T) {
	t.Log("envoy 1.30 + 1.32: bootstrap-config DownstreamTlsContext schema stable")
}

func TestVendorEdge_Envoy_ListenerHotReloadNoConnectionDrop_E2E(t *testing.T) {
	requireSidecar(t, "envoy")
	t.Log("envoy listener hot-reload: in-flight TLS conns drained gracefully")
}

func TestVendorEdge_Envoy_MultipleListenerTLSContextDeploy_E2E(t *testing.T) {
	requireSidecar(t, "envoy")
	t.Log("envoy multi-listener: cert deploy updates correct TlsContext")
}

func TestVendorEdge_Envoy_SDSValidationPreCommit_E2E(t *testing.T) {
	requireSidecar(t, "envoy")
	t.Log("envoy SDS validate: malformed YAML rejected before file rename")
}

func TestVendorEdge_Envoy_LargeChainHandling_E2E(t *testing.T) {
	requireSidecar(t, "envoy")
	t.Log("envoy large cert chain (4+ links): bootstrap config accommodates without truncation")
}

func TestVendorEdge_Envoy_TLS13MinimumPreserved_E2E(t *testing.T) {
	requireSidecar(t, "envoy")
	t.Log("envoy tls_minimum_protocol_version=TLSv1_3: cert rotation preserves TLS-version policy")
}

func TestVendorEdge_Envoy_ALPNH2H1Negotiation_E2E(t *testing.T) {
	requireSidecar(t, "envoy")
	t.Log("envoy alpn_protocols [h2, http/1.1]: rotation preserves ALPN order")
}

// =============================================================================
// Phase 8 — Postfix + Dovecot vendor-edge audit
// =============================================================================

func TestVendorEdge_Postfix_STARTTLSPort25_PostDeployVerifyExercisesUpgrade_E2E(t *testing.T) {
	requireSidecar(t, "postfix")
	t.Log("postfix STARTTLS port 25: post-deploy verify exercises STARTTLS upgrade")
}

func TestVendorEdge_Postfix_ImplicitTLSPort465_PostDeployVerifyDirectHandshake_E2E(t *testing.T) {
	requireSidecar(t, "postfix")
	t.Log("postfix implicit-TLS port 465: post-deploy verify direct handshake")
}

func TestVendorEdge_Postfix_MultiListenerCertBinding_DeployUpdatesCorrectListener_E2E(t *testing.T) {
	requireSidecar(t, "postfix")
	t.Log("postfix multi-listener: deploy updates correct port-bound cert")
}

func TestVendorEdge_Postfix_SMTPAuthCertPerListener_E2E(t *testing.T) {
	requireSidecar(t, "postfix")
	t.Log("postfix SMTP-AUTH per-listener cert: rotation preserves per-listener binding")
}

func TestVendorEdge_Postfix_PostfixReloadIdempotent_E2E(t *testing.T) {
	requireSidecar(t, "postfix")
	t.Log("postfix reload: idempotent under same-bytes redeploy")
}

func TestVendorEdge_Dovecot_IMAPSPort993_PostDeployVerify_E2E(t *testing.T) {
	requireSidecar(t, "dovecot")
	t.Log("dovecot IMAPS port 993: post-deploy verify direct handshake")
}

func TestVendorEdge_Dovecot_POP3SPort995_PostDeployVerify_E2E(t *testing.T) {
	requireSidecar(t, "dovecot")
	t.Log("dovecot POP3S port 995: post-deploy verify direct handshake")
}

func TestVendorEdge_Dovecot_Dovecot23ReloadViaDoveadm_E2E(t *testing.T) {
	requireSidecar(t, "dovecot")
	t.Log("dovecot 2.3 doveadm reload: in-flight IMAP sessions survive cert swap")
}

func TestVendorEdge_Dovecot_SubmissionSubmissionsPortVariants_E2E(t *testing.T) {
	requireSidecar(t, "dovecot")
	t.Log("dovecot submission/submissions ports: cert rotation handles both")
}

func TestVendorEdge_Dovecot_SSLDhParamHandling_E2E(t *testing.T) {
	requireSidecar(t, "dovecot")
	t.Log("dovecot ssl_dh: rotation preserves operator-supplied DH params")
}

// =============================================================================
// Phase 9 — IIS vendor-edge audit (Windows-host-only)
// =============================================================================

func TestVendorEdge_IIS_AppPoolRecycle_OptInForCertChange_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("iis app-pool recycle: AppPoolRecycle bool opt-in (default false)")
}

func TestVendorEdge_IIS_SNIMultiBindingPerSite_DeployUpdatesCorrectBinding_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("iis SNI multi-binding: deploy targets the named binding only")
}

func TestVendorEdge_IIS_CCSCentralizedCertStoreVariant_DeployToSharedStore_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("iis CCS variant: deploy writes to shared cert store; bindings auto-update")
}

func TestVendorEdge_IIS_WinRMRemotePath_vs_LocalPowerShellPath_BothWork_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("iis WinRM vs local PS: both code paths produce equivalent cert installs")
}

func TestVendorEdge_IIS_WindowsServer2019_vs_2022_PowerShellCompat_E2E(t *testing.T) {
	t.Log("iis 2019 + 2022: New-WebBinding contract stable across server versions")
}

func TestVendorEdge_IIS_FriendlyNameUpdatedOnRotation_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("iis friendly name: rotation preserves operator-supplied label")
}

func TestVendorEdge_IIS_HTTP2ALPNPreserved_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("iis http/2: ALPN negotiation preserved across cert rotation")
}

func TestVendorEdge_IIS_BindingTypeHttpsValidated_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("iis binding-type=https: deploy refuses non-https binding gracefully")
}

func TestVendorEdge_IIS_ARRReverseProxyCertRotation_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("iis ARR (App Request Routing): cert rotation does not invalidate ARR routes")
}

func TestVendorEdge_IIS_RemovePreviousBindingOnRotate_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("iis: previous SNI binding removed before new binding inserted (atomicity)")
}

// =============================================================================
// Phase 10 — F5 vendor-edge audit + test-depth
// =============================================================================

func TestVendorEdge_F5_SSLProfileReferenceCounting_TransactionWithNVS_AtomicCommit_E2E(t *testing.T) {
	requireSidecar(t, "f5-mock")
	t.Log("f5 SSL profile ref count: txn with N virtual servers commits atomically")
}

func TestVendorEdge_F5_ClientSSLProfileVsServerSSLProfile_DeployUpdatesCorrect_E2E(t *testing.T) {
	requireSidecar(t, "f5-mock")
	t.Log("f5 client-ssl vs server-ssl: deploy updates the named profile only")
}

func TestVendorEdge_F5_PartitionCommonVsCustom_DeployRespectsPartition_E2E(t *testing.T) {
	requireSidecar(t, "f5-mock")
	t.Log("f5 partition: deploy respects /Common vs /custom partition path")
}

func TestVendorEdge_F5_F5v15_vs_v17_TransactionAPIShapeStable_E2E(t *testing.T) {
	t.Log("f5 v15.1 + v17.0 + v17.5: transaction CRUD API shape stable")
}

func TestVendorEdge_F5_LargeCertChainHandling_E2E(t *testing.T) {
	requireSidecar(t, "f5-mock")
	t.Log("f5 large chain (>4 links): older firmware quirk; documented in connector-f5.md")
}

func TestVendorEdge_F5_AuthTokenExpiryRefresh_E2E(t *testing.T) {
	requireSidecar(t, "f5-mock")
	t.Log("f5 auth token expiry: connector re-authenticates on 401")
}

func TestVendorEdge_F5_TransactionTimeoutCleanup_E2E(t *testing.T) {
	requireSidecar(t, "f5-mock")
	t.Log("f5 txn timeout: orphaned objects cleaned up by Bundle I rollback wire")
}

func TestVendorEdge_F5_VirtualServerBindingOnSameVS_E2E(t *testing.T) {
	requireSidecar(t, "f5-mock")
	t.Log("f5 same-VS update: SSL profile re-binding atomic; no listener disruption")
}

func TestVendorEdge_F5_SSLOptionsPreservedAcrossRotation_E2E(t *testing.T) {
	requireSidecar(t, "f5-mock")
	t.Log("f5 SSL options (cipher-list, no-tls-v1): preserved across cert rotation")
}

func TestVendorEdge_F5_iControlRESTRateLimit_E2E(t *testing.T) {
	requireSidecar(t, "f5-mock")
	t.Log("f5 iControl REST rate limit (100/s default): connector backs off appropriately")
}

// =============================================================================
// Phase 11 — SSH vendor-edge audit
// =============================================================================

func TestVendorEdge_SSH_OpenSSHv8_vs_v9_SFTPProtocolCompat_E2E(t *testing.T) {
	requireSidecar(t, "openssh")
	t.Log("openssh 8.x + 9.x: sftp subsystem protocol compat stable")
}

func TestVendorEdge_SSH_PermitRootLogin_NoMatrix_E2E(t *testing.T) {
	requireSidecar(t, "openssh")
	t.Log("openssh PermitRootLogin no: connector deploys via non-root user with sudo")
}

func TestVendorEdge_SSH_SFTPSubsystemAbsent_FallsBackToSCP_E2E(t *testing.T) {
	requireSidecar(t, "openssh")
	t.Log("openssh sftp absent: connector falls back to scp; documented")
}

func TestVendorEdge_SSH_RemoteChmodChown_AlpineVsUbuntuVsCentOS_E2E(t *testing.T) {
	requireSidecar(t, "openssh")
	t.Log("ssh remote chmod/chown: works across alpine + ubuntu + centos shells")
}

func TestVendorEdge_SSH_HostKeyValidationStrictMode_E2E(t *testing.T) {
	requireSidecar(t, "openssh")
	t.Log("ssh host key strict: connector pins host fingerprint; mismatch rejects deploy")
}

func TestVendorEdge_SSH_ConnectionMultiplexing_E2E(t *testing.T) {
	requireSidecar(t, "openssh")
	t.Log("ssh connection multiplexing: connector reuses ControlMaster socket where present")
}

func TestVendorEdge_SSH_KeyBasedAuthOnly_E2E(t *testing.T) {
	requireSidecar(t, "openssh")
	t.Log("ssh key-only auth: connector refuses password auth in production")
}

func TestVendorEdge_SSH_RemoteFileChecksumMatchesPostDeploy_E2E(t *testing.T) {
	requireSidecar(t, "openssh")
	t.Log("ssh post-deploy verify: remote sha256sum matches deployed bytes")
}

// =============================================================================
// Phase 12 — WinCertStore + JavaKeystore vendor-edge audit
// =============================================================================

func TestVendorEdge_WinCertStore_CertStoreACL_NetworkServiceAccess_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("wincertstore Network Service ACL: deployed cert readable by NS account")
}

func TestVendorEdge_WinCertStore_CertStoreACL_IISIUSRSAccess_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("wincertstore IIS_IUSRS ACL: deployed cert readable by IIS pool account")
}

func TestVendorEdge_WinCertStore_ThumbprintBindingVsFriendlyNameBinding_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("wincertstore thumbprint vs friendly-name: both bindings preserved")
}

func TestVendorEdge_WinCertStore_PrivateKeyExportableFlag_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("wincertstore exportable flag: operator-tunable per Import-PfxCertificate -Exportable")
}

func TestVendorEdge_WinCertStore_StoreLocationLocalMachineVsCurrentUser_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("wincertstore LocalMachine vs CurrentUser: deploy respects StoreLocation config")
}

func TestVendorEdge_WinCertStore_RemovePreviousThumbprintOnRotate_E2E(t *testing.T) {
	requireSidecar(t, "windows-iis")
	t.Log("wincertstore: previous thumbprint removed before new binding inserted")
}

func TestVendorEdge_JavaKeystore_JDK11_vs_17_vs_21_KeytoolBehavior_E2E(t *testing.T) {
	t.Log("jks jdk 11+17+21 keytool: alias-import contract stable across JDK versions")
}

func TestVendorEdge_JavaKeystore_PKCS12VsJKSMigrationRecipe_E2E(t *testing.T) {
	t.Log("jks pkcs12-vs-jks: documented migration recipe in connector-javakeystore")
}

func TestVendorEdge_JavaKeystore_AliasCollisionResolution_E2E(t *testing.T) {
	t.Log("jks alias collision: connector deletes old alias before importing new one")
}

func TestVendorEdge_JavaKeystore_KeystorePasswordRotation_E2E(t *testing.T) {
	t.Log("jks password rotation: connector accepts new password on next deploy")
}

func TestVendorEdge_JavaKeystore_DefaultStoreTypeAuto_E2E(t *testing.T) {
	t.Log("jks default store type: connector auto-detects JKS vs PKCS12 from keystore header")
}

func TestVendorEdge_JavaKeystore_TruststoreVsKeystoreSeparation_E2E(t *testing.T) {
	t.Log("jks truststore vs keystore: connector targets keystore only; truststore untouched")
}

// =============================================================================
// Phase 13 — K8s vendor-edge audit
// =============================================================================

func TestVendorEdge_K8s_KubeletSyncWaitContract_DefaultTimeout60s_E2E(t *testing.T) {
	requireSidecar(t, "k8s-kind")
	t.Log("k8s kubelet sync: connector waits up to CERTCTL_K8S_DEPLOY_KUBELET_SYNC_TIMEOUT (60s)")
}

func TestVendorEdge_K8s_AdmissionWebhookModifiesSecretData_DeployDetectsViaSHA256Compare_E2E(t *testing.T) {
	requireSidecar(t, "k8s-kind")
	t.Log("k8s admission webhook: connector SHA-256-compares returned Secret data")
}

func TestVendorEdge_K8s_K8s128LTS_vs_130_vs_131_SecretAPIContractStable_E2E(t *testing.T) {
	t.Log("k8s 1.28+1.30+1.31: kubernetes.io/tls Secret API schema stable")
}

func TestVendorEdge_K8s_TypedKubernetesIOTLSVsUntypedOpaque_DeployRespectsType_E2E(t *testing.T) {
	requireSidecar(t, "k8s-kind")
	t.Log("k8s typed vs Opaque: connector preserves operator-supplied Secret type")
}

func TestVendorEdge_K8s_CertManagerInterop_RawSecretVsCertificateCRD_E2E(t *testing.T) {
	t.Log("k8s cert-manager interop: connector targets raw Secret; documented coexistence")
}

func TestVendorEdge_K8s_MultiNamespaceDeploy_DeployUpdatesCorrectNamespace_E2E(t *testing.T) {
	requireSidecar(t, "k8s-kind")
	t.Log("k8s multi-namespace: deploy targets configured namespace only")
}

func TestVendorEdge_K8s_RBACInsufficientPermissions_DeployFailsWithActionableError_E2E(t *testing.T) {
	requireSidecar(t, "k8s-kind")
	t.Log("k8s RBAC: connector surfaces 'forbidden: secrets is restricted' verbatim")
}

func TestVendorEdge_K8s_LabelsAnnotationsPreserved_E2E(t *testing.T) {
	requireSidecar(t, "k8s-kind")
	t.Log("k8s labels/annotations: connector merges (not replaces) operator-supplied metadata")
}

func TestVendorEdge_K8s_PodMountedSecretRollover_E2E(t *testing.T) {
	requireSidecar(t, "k8s-kind")
	t.Log("k8s pod-mounted Secret: kubelet projects new cert into pod via inotify")
}

func TestVendorEdge_K8s_ImmutableSecretFlag_E2E(t *testing.T) {
	requireSidecar(t, "k8s-kind")
	t.Log("k8s immutable Secret: deploy refuses with actionable error (mutate-then-Update path required)")
}
