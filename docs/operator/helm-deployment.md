# Helm Deployment

> Last reviewed: 2026-05-05

Operator runbook for deploying certctl on Kubernetes via the bundled Helm chart at `deploy/helm/certctl/`.

## Prereqs

- Kubernetes cluster, v1.27+
- `kubectl` configured and authenticated
- `helm` v3.13+
- Storage class for the PostgreSQL StatefulSet PVC
- TLS cert source: either an operator-supplied `kubernetes.io/tls` Secret OR a cert-manager `ClusterIssuer` / `Issuer`. The chart refuses to render without one. See [`tls.md`](tls.md) for the four cert provisioning patterns.

## Install

```bash
helm install certctl deploy/helm/certctl/ \
  --namespace certctl \
  --create-namespace \
  --set server.apiKey=$(openssl rand -hex 32) \
  --set postgres.password=$(openssl rand -hex 32) \
  --set server.tls.existingSecret=certctl-server-tls
```

`server.apiKey` and `postgres.password` should be high-entropy values. The example above generates them inline; production deployments use a secrets manager (Vault, External Secrets Operator, AWS Secrets Manager) instead.

## What you get

- **Server Deployment** with a configurable replica count (default 1; HA needs sticky sessions on the ACME server's nonce path)
- **PostgreSQL StatefulSet** with PVC-backed persistence
- **Agent DaemonSet** with one agent per node (configurable via `agent.daemonset.enabled=false` if you don't want the in-cluster agent)
- Health probes (`/health` liveness + `/ready` readiness)
- Security contexts: non-root, read-only root filesystem
- Optional Ingress (off by default; opt in via `ingress.enabled=true`)

## Cert source patterns

### Pattern 1 — operator-supplied Secret (recommended for non-cert-manager shops)

```bash
kubectl create secret tls certctl-server-tls \
  --cert=server.crt --key=server.key \
  --namespace certctl

helm install certctl deploy/helm/certctl/ \
  --namespace certctl \
  --set server.tls.existingSecret=certctl-server-tls
```

### Pattern 2 — cert-manager Certificate CR (recommended for cert-manager shops)

```bash
helm install certctl deploy/helm/certctl/ \
  --namespace certctl \
  --set server.tls.certManager.enabled=true \
  --set server.tls.certManager.issuerRef.name=my-cluster-issuer \
  --set server.tls.certManager.issuerRef.kind=ClusterIssuer
```

### Refuses to render without one of the above

```bash
helm install certctl deploy/helm/certctl/ --namespace certctl
# Error: server.tls.existingSecret OR server.tls.certManager.enabled must be set
```

The render-time guard catches the missing config at `helm install` time, not at pod-crash-loop time.

## Verify the install

```bash
kubectl wait --for=condition=Ready --timeout=3m \
  -n certctl pod -l app.kubernetes.io/name=certctl-server

kubectl port-forward -n certctl svc/certctl-server 8443:8443 &

# Bundle the TLS root from the Secret to verify
kubectl get secret -n certctl certctl-server-tls -o jsonpath='{.data.ca\.crt}' \
  | base64 -d > /tmp/certctl-ca.crt
curl --cacert /tmp/certctl-ca.crt https://localhost:8443/health
# {"status":"healthy"}
```

If the Secret has no `ca.crt` key (operator-supplied Secrets often don't), use `tls.crt` as the bundle. For a self-signed cert the two files are identical; for a chained cert distribute the root CA bundle separately via ConfigMap.

## Upgrade

```bash
helm upgrade certctl deploy/helm/certctl/ \
  --namespace certctl \
  --reuse-values
```

Postgres state survives the upgrade (the PVC is retained). The server / agent images bump per the chart's `image.tag`. See [`docs/archive/upgrades/`](../archive/upgrades/) for version-specific upgrade guidance.

### 2026-05-16 — ServiceMonitor TLS default flipped (DEPL-004)

Acquisition-audit DEPL-004 closure. Pre-2026-05-16, `monitoring.serviceMonitor.tlsConfig` was empty by default and the chart template fell through to an implicit `insecureSkipVerify: true`. Post-2026-05-16, the values.yaml default is a real TLS verify against the chart's CA (caFile + serverName matching the existingSecret mount path the chart's Prometheus integration produces).

The new default works out of the box for the canonical install (the chart's `existingSecret` or cert-manager-emitted Secret mounted at `/etc/prometheus/secrets/certctl-ca/`):

```yaml
# Default in values.yaml (no operator action required for the
# canonical install path).
monitoring:
  serviceMonitor:
    enabled: true
    tlsConfig:
      caFile: /etc/prometheus/secrets/certctl-ca/ca.crt
      serverName: certctl-server
```

Operators whose Prometheus pod mounts the CA bundle at a different path override `caFile`:

```yaml
monitoring:
  serviceMonitor:
    enabled: true
    tlsConfig:
      caFile: /path/to/your/ca.crt
      serverName: your-cert-CN
```

Operators who genuinely need `insecureSkipVerify` (demo / dev clusters) must opt in **explicitly** — blanking the `tlsConfig` block trips the chart's `{{ fail }}` guard at render time:

```yaml
monitoring:
  serviceMonitor:
    enabled: true
    tlsConfig:
      insecureSkipVerify: true
```

There is no way to inherit the pre-2026-05-16 implicit-skipVerify behavior silently. Operators with `monitoring.serviceMonitor.enabled: false` (the chart default) need no action — the template short-circuits before the `tlsConfig` block.

## Configuration reference

Every value is documented at `deploy/helm/certctl/values.yaml`. Common tweaks:

- `server.replicaCount` — replica count (default 1)
- `server.resources.{requests,limits}` — pod resource bounds
- `agent.daemonset.enabled` — toggle the in-cluster agent (default true)
- `postgres.storageSize` — PVC size (default 10Gi)
- `ingress.enabled` + `ingress.host` — opt into Ingress

## Troubleshooting

**Pod crash-loops with TLS error.** Cert + key in the Secret don't pair. Verify with `openssl x509 -modulus -in server.crt -noout | md5` against `openssl rsa -modulus -in server.key -noout | md5` — outputs must match.

**Agent DaemonSet pods can't reach the server.** Service DNS / NetworkPolicy issue. Confirm the agent's `CERTCTL_SERVER_URL` env points at the in-cluster service name (`https://certctl-server.certctl.svc.cluster.local:8443`).

**Postgres won't start.** PVC permissions. Check `kubectl describe pvc -n certctl certctl-postgres` and confirm the storage class supports `fsGroup`.

## Related docs

- [`tls.md`](tls.md) — cert provisioning patterns + SIGHUP rotation
- [`security.md`](security.md) — production security posture
- [`runbooks/disaster-recovery.md`](runbooks/disaster-recovery.md) — Postgres restore + recovery procedures
- [`docs/archive/upgrades/`](../archive/upgrades/) — version-specific upgrade procedures
