# High-Availability Deployment Runbook

> Last reviewed: 2026-05-13

<!-- Phase 2 DEPL-H1 closure -->


certctl's Helm chart ships with conservative single-replica defaults
that produce a working `helm install` against any Kubernetes cluster.
Production HA is operator-opt-in across three values surfaces — none
of which the chart flips on your behalf.

This runbook documents the three changes, why they default off, and
the smallest-possible HA values overlay.

---

## Why HA is opt-in (not default)

Three load-bearing reasons the chart defaults are `replicas: 1` and
`podDisruptionBudget.enabled: false`:

1. **A 1-replica deployment works on every cluster.** A multi-replica
   default with `minAvailable: 2` would render a PDB at install time;
   if the cluster has fewer than 2 nodes available (single-node
   `kind` / `minikube` / fresh `k3s` clusters), Helm renders fine but
   the first `kubectl rollout` blocks indefinitely waiting for the
   second replica that can never schedule. Defaulting off keeps the
   demo path one-command.

2. **Postgres is a singleton in the bundled chart.** The chart's
   `postgres-statefulset.yaml` runs ONE Postgres pod. Scaling the
   server tier past 1 replica without an externalized Postgres + a
   pgbouncer-style proxy doesn't actually buy HA at the DB tier — the
   single Postgres pod is the failure domain. Operators who want true
   HA route Postgres to a managed service (RDS, Cloud SQL, AlloyDB,
   AKS-managed-Postgres, Aiven) or run their own cluster (Patroni,
   CloudNativePG, Zalando postgres-operator). See the
   [external-Postgres values example](../../deploy/helm/examples/values-external-db.yaml).

3. **Session affinity is HTTPS-only.** The control plane is HTTPS-only
   (TLS 1.3 pinned). Adding `sessionAffinity: ClientIP` to the
   server Service mid-deployment when a sticky front-end LB is in
   play (NGINX Ingress, Cloud LB with backend service) is the right
   default for OIDC + RBAC session cookies. But operators who terminate
   TLS at a different layer (Envoy mesh, Cloudflare in front of the
   cluster) may have already solved affinity upstream — flipping it
   on by default would over-constrain those paths.

## The smallest production-HA overlay

Three Helm values to flip:

```yaml
# values-ha.yaml — copy into your overlay and edit to taste.

server:
  # ≥ 2 replicas is the minimum for the PDB to render. 3 gives you
  # a true rolling-restart tolerance window (1 down for upgrade,
  # 2 still serving) without dropping below minAvailable.
  replicas: 3

  service:
    # Required when the front-end LB doesn't already enforce
    # session affinity. OIDC + RBAC session cookies need to land
    # on the same backend pod for the session lifetime.
    sessionAffinity: ClientIP

podDisruptionBudget:
  # Renders the PDB template; controller-side voluntary disruptions
  # (node-drain for k8s upgrade, cluster-autoscaler scale-down)
  # respect this floor.
  enabled: true
  # With server.replicas: 3, minAvailable: 2 leaves headroom for one
  # rolling restart at a time.
  minAvailable: 2
  # maxUnavailable is mutually exclusive with minAvailable; pick one.
  # maxUnavailable: 1
```

Apply with:

```bash
helm upgrade certctl deploy/helm/certctl/ -f values-ha.yaml
```

## What you still own as the operator

Three things the chart does not solve, even at `replicas: 3`:

1. **Postgres HA.** Route to an externalized Postgres (managed cloud
   or operator-managed cluster). The chart's bundled StatefulSet
   pod is a development/single-AZ pattern, not a production HA path.
2. **TLS material lifecycle.** The chart accepts an `existingSecret`
   for the server cert; rotating it is operator-side automation.
   The dashboard + agent can issue their own certs via the local CA
   (eat-your-own-dogfood); the operator can wire `cert-manager` if
   they prefer that path.
3. **Backup CronJob.** Phase 4 of the architecture diligence
   remediation plan (DEPL-H2) ships a `backup-cronjob.yaml` template;
   until that lands, backups are operator-run per the existing
   `docs/operator/runbooks/postgres-backup.md` runbook.

## Cross-references

- `deploy/helm/certctl/values.yaml` lines 19, 446, 566 — the three
  defaults this runbook documents.
- `docs/operator/runbooks/postgres-backup.md` — Postgres backup
  runbook (today, operator-run).
- `docs/operator/runbooks/disaster-recovery.md` — DR procedure.
- Phase 4 (Helm Chart, DR, And Ops Surface) of the architecture
  diligence remediation plan tracks the chart-level work
  (backup CronJob, PrometheusRule starter, migration hook, etc.).
