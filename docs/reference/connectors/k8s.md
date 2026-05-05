# Kubernetes Secrets Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Per Phase 14 of the deploy-hardening II master bundle. For the
> connector-development context (interface contract, registry, atomic
> deploy primitive shared across all targets), see the
> [connector index](index.md).

## Overview

The K8s connector (`internal/connector/target/k8ssecret/`) deploys
TLS certs into `kubernetes.io/tls` Secrets. Atomic at the API
server level (Update is transactional); the post-deploy verify
SHA-256-compares the returned Secret data against deployed bytes
(defends against admission webhooks that modify cert data).

## Vendor versions tested

- **Kubernetes 1.28 LTS**
- **Kubernetes 1.30**
- **Kubernetes 1.31** (current stable)

## Per-quirk operator guidance

### Kubelet sync wait contract

`TestVendorEdge_K8s_KubeletSyncWaitContract_DefaultTimeout60s_E2E`

After Secret update, kubelet projects new cert bytes into
pod-mounted volumes. Default sync interval ~60s. The connector
waits up to `CERTCTL_K8S_DEPLOY_KUBELET_SYNC_TIMEOUT` (default
60s).

**Operator action:** for slow clusters (large pod count, slow
node DNS), tune the env var upward. For fast clusters, the
default is fine.

### Admission webhook mutation

`TestVendorEdge_K8s_AdmissionWebhookModifiesSecretData_DeployDetectsViaSHA256Compare_E2E`

Some admission webhooks (Vault Agent Injector, OPA Gatekeeper)
mutate Secret data on Update. The connector pulls the Secret
back after Update and SHA-256-compares against deployed bytes.
Mismatch surfaces as deploy failure.

### Multi-version API stability

`TestVendorEdge_K8s_K8s128LTS_vs_130_vs_131_SecretAPIContractStable_E2E`

`kubernetes.io/tls` Secret schema (data.tls.crt + data.tls.key)
is stable across 1.28-1.31. No per-version branch needed.

### Typed vs Opaque Secret

`TestVendorEdge_K8s_TypedKubernetesIOTLSVsUntypedOpaque_DeployRespectsType_E2E`

Connector preserves operator-supplied Secret type. Typed
`kubernetes.io/tls` is the canonical form; untyped `Opaque` is
preserved for operators with legacy automation that expects it.

### Cert-manager interop

`TestVendorEdge_K8s_CertManagerInterop_RawSecretVsCertificateCRD_E2E`

Connector targets raw Secrets, NOT cert-manager `Certificate` CRs.
Operators using cert-manager should NOT also point certctl at the
same Secret name (cert-manager will overwrite). Documented
coexistence: certctl handles non-cert-manager Secrets;
cert-manager handles its own.

### Multi-namespace

`TestVendorEdge_K8s_MultiNamespaceDeploy_DeployUpdatesCorrectNamespace_E2E`

Connector targets the configured `Namespace` only. Cross-namespace
deploys require multiple connector entries.

### RBAC errors

`TestVendorEdge_K8s_RBACInsufficientPermissions_DeployFailsWithActionableError_E2E`

Connector surfaces the K8s API's `forbidden: secrets is restricted`
error verbatim. Operator action: bind a Role with
`secrets: get,update,create` verbs to the agent's ServiceAccount.

### Labels + annotations preservation

`TestVendorEdge_K8s_LabelsAnnotationsPreserved_E2E`

Connector merges (not replaces) operator-supplied metadata. Custom
labels/annotations on the Secret survive cert rotation.

### Pod-mounted Secret rollover

`TestVendorEdge_K8s_PodMountedSecretRollover_E2E`

When a pod mounts the Secret as a volume, kubelet projects new
cert bytes into the pod's filesystem after sync. Pods watching
the file (via inotify or polling) pick up the new cert without
restart.

### Immutable Secret flag

`TestVendorEdge_K8s_ImmutableSecretFlag_E2E`

K8s Secrets can be marked `immutable: true` for performance.
Update fails with actionable error; operator must drop the flag,
update, then re-apply if desired.

## V3-Pro deferrals

- cert-manager `Certificate` CR interop as first-class deploy
  target (V3-Pro: certctl as cert-manager external issuer).
- Multi-cluster federation (deploy a single cert across N
  clusters with single connector entry).

## Related docs

- [Atomic deploy + post-verify + rollback](../deployment-model.md)
- [Vendor compatibility matrix](../vendor-matrix.md)
