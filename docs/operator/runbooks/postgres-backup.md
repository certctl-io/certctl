# Runbook: PostgreSQL backup for certctl

> Last reviewed: 2026-05-16

Use this when:
- You're setting up a new certctl deployment and need a backup policy
  before going to production.
- A buyer or auditor asks "where's the backup automation?" and you need
  to point at the recommended cadence + procedure.
- You're rotating the encryption key, swapping CAs, or doing any other
  destructive maintenance and want a snapshot to roll back to.

certctl does not ship a built-in backup daemon. Postgres is the system
of record for every piece of certctl state that isn't on the
operator's filesystem (CA keys, OCSP responder keys, SCEP/EST trust
bundles — see "Operator-managed (NOT in DB)" in the
[disaster-recovery runbook](disaster-recovery.md#postgres-restore));
backing it up is treated as a standard PostgreSQL operations task
that the operator owns end-to-end with their existing tooling.

This page is the recommended recipe.

## What to back up

| Layer                              | Tool                                                                    | Cadence                  |
|---|---|---|
| `certctl` database (the row data)  | `pg_dump` (logical) **or** `pg_basebackup` + WAL archive (physical PIT) | ≥ daily, retention ≥ 30d |
| CA cert + key (`CERTCTL_CA_CERT_PATH`, `CERTCTL_CA_KEY_PATH`) | Out-of-band file backup (operator's existing secret-management tool) | On change |
| SCEP RA cert + key (per profile)   | Out-of-band file backup                                                 | On change                |
| OCSP responder keys                | Out-of-band file backup (`CERTCTL_OCSP_RESPONDER_KEY_DIR`)              | On change                |
| Trust-anchor PEM bundles           | Out-of-band file backup                                                 | On change                |
| Env vars (auth secret, etc.)       | Operator's secret-management tool (Vault, AWS Secrets Manager, etc.)    | On rotation              |

A backup of only the Postgres database without the operator-managed
file material is **not a complete restore artifact** — see the
[disaster-recovery runbook's Postgres-restore section](disaster-recovery.md#postgres-restore)
for the full inventory. The DR runbook owns the restore procedure;
this page owns the capture procedure.

## Logical backup (recommended for most deployments)

`pg_dump -Fc` produces a portable compressed dump that's easy to
restore into a fresh Postgres instance at any version ≥ the dump's
source version. Best for deployments where the DB is small enough
that a full logical dump fits the backup window (rough rule of thumb:
under a million `managed_certificates` rows + corresponding history).

### docker-compose

```bash
# 1. Snapshot. Run from any host that can reach the postgres container.
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
docker compose -f deploy/docker-compose.yml exec -T postgres \
  pg_dump --format=custom --no-owner --no-acl --dbname=certctl \
  > "certctl-${TIMESTAMP}.dump"

# 2. Verify integrity (catch transport / truncation bugs early).
docker run --rm -v "$PWD:/dumps" -w /dumps postgres:16-alpine \
  pg_restore --list "certctl-${TIMESTAMP}.dump" > /dev/null \
  && echo "OK: pg_restore --list parses the dump cleanly" \
  || { echo "CORRUPT DUMP"; exit 1; }

# 3. Move to durable storage (S3, GCS, NFS, encrypted-at-rest blob
# storage of your choice). DO NOT leave the dump on the certctl host
# alone — that defeats the purpose of having a backup.
aws s3 cp "certctl-${TIMESTAMP}.dump" "s3://your-bucket/certctl/"
```

### Kubernetes (with the bundled Helm chart)

```bash
# 1. Snapshot via kubectl exec into the postgres StatefulSet pod.
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
NAMESPACE=certctl
kubectl exec -n "$NAMESPACE" statefulset/postgres -- \
  pg_dump --format=custom --no-owner --no-acl --dbname=certctl \
  > "certctl-${TIMESTAMP}.dump"

# 2. Same verification step as above.
# 3. Same off-host storage step as above.
```

### Restore (cross-reference)

The restore procedure lives in
[disaster-recovery.md § Postgres restore](disaster-recovery.md#postgres-restore).
The key reminders: stop certctl first, restore the DB, run any
migrations newer than the snapshot, truncate the CRL + OCSP caches,
then restart.

## Physical / PITR backup (large fleets, RPO < 1h)

Logical dumps have a coarse RPO (the last successful dump). For
deployments where ≤ 1h of cert-issuance history loss is unacceptable,
pair Postgres physical backups with continuous WAL archiving:

- `pg_basebackup` for the initial seed
- `archive_command = '<your-WAL-archiver>'` in `postgresql.conf` to
  ship every WAL segment off the host as it closes
- `pgbackrest` or `wal-g` for the operational layer (both are
  battle-tested, support encryption, and integrate cleanly with S3 /
  GCS / Azure Blob)

certctl ships nothing in this layer — it's standard PostgreSQL DBA
work, and shipping a bespoke recipe would just be a worse version of
what `pgbackrest` already does. The
[pgbackrest configuration guide](https://pgbackrest.org/configuration.html)
is the authoritative reference.

## Automation paths

certctl ships an **opt-in Helm CronJob** for the in-cluster-Postgres
case (the most common bundled-deploy shape). The template lives at
`deploy/helm/certctl/templates/backup-cronjob.yaml` and is gated by
`backup.enabled` in `values.yaml`. Default OFF; flip it on with one
toggle and a sink choice. For managed Postgres (AWS RDS / GCP Cloud
SQL / Azure DB) the operator relies on the provider's PITR layer;
this CronJob is intentionally scoped to the in-cluster-Postgres path.

### Enabling the bundled CronJob

```bash
# PVC sink (in-cluster persistent volume — simplest)
helm upgrade --install certctl charts/certctl \
  --set backup.enabled=true \
  --set backup.sink=pvc \
  --set backup.pvc.storageClassName=<your-storage-class> \
  --set backup.pvc.size=20Gi \
  --set backup.schedule="0 2 * * *"

# S3 sink (off-cluster, recommended for any deploy past the lab)
kubectl create secret generic certctl-backup-aws \
  --from-literal=AWS_ACCESS_KEY_ID=AKIA... \
  --from-literal=AWS_SECRET_ACCESS_KEY=... \
  --namespace certctl
helm upgrade --install certctl charts/certctl \
  --set backup.enabled=true \
  --set backup.sink=s3 \
  --set backup.s3.bucket=my-certctl-backups \
  --set backup.s3.region=us-east-1 \
  --set backup.s3.credentialsSecret=certctl-backup-aws \
  --set backup.schedule="0 2 * * *"
```

The CronJob runs `pg_dump --format=custom --no-owner --no-acl
--dbname=certctl` (the same shape as the manual command earlier in
this runbook, so a manual dump and a Job dump are byte-comparable)
and ships the artifact to the configured sink. Off-host retention
is the sink's responsibility — S3 lifecycle rules or PVC snapshot
retention on the storage class, not the CronJob.

### When the bundled CronJob is NOT the answer

- **Managed Postgres (AWS RDS / GCP Cloud SQL / Azure DB).** Use the
  provider's built-in PITR; configure retention ≥ 30 days. The
  certctl deployment surface is the connection string alone — no
  CronJob to run.
- **Self-hosted Postgres on a VM (no Kubernetes).** Use a systemd
  timer + `pg_dump` + `restic` (or `borgbackup`) to encrypted
  off-host storage. The bundled CronJob has no equivalent on bare
  VMs.
- **Already running pgbackrest / wal-g.** Keep using it. The bundled
  CronJob is for the operator who doesn't yet have a backup posture,
  not a replacement for production-grade WAL-shipping.

### Recovery objectives

The bundled CronJob targets the same RPO/RTO that any nightly-dump
strategy gives you:

- **RPO ≈ 24h** at the default `0 2 * * *` schedule (you lose at
  most one day of writes if Postgres burns down). Tighten by running
  every 6h or 1h; tighten further by switching to WAL-shipping
  (out of scope for the bundled CronJob).
- **RTO ≈ 30–60min** for the restore drill below — drop the dump
  into a fresh Postgres instance, point certctl at it, confirm
  routes return 200. Empirically measured during the
  [disaster-recovery runbook](disaster-recovery.md) drill.

If your contractual RPO is below 24h, run pgbackrest WAL-shipping
alongside (or instead of) the CronJob.

## Verification — what to dry-run quarterly

A backup you've never restored is a backup you don't have. Add this
to your quarterly on-call rotation:

1. Pick the most recent dump from the previous quarter.
2. Stand up a throwaway Postgres instance (Docker, kind, anything).
3. `pg_restore -d certctl <the dump>`.
4. Bring up a certctl-server container pointed at the throwaway DB
   (`CERTCTL_DATABASE_URL=postgres://certctl:...@throwaway/...`).
5. Confirm `/api/v1/version` returns 200, `/api/v1/certificates`
   lists the expected rows, and the scheduler logs show no
   migration-version mismatch.
6. Tear down. Note the timing in your DR registry.

The [disaster-recovery runbook](disaster-recovery.md) covers what to
do when this dry-run reveals a gap.

## CI restore verification

> Acquisition-audit DEPL-005 + DATA-012 closure (Sprint 4 ACQ,
> 2026-05-16). The quarterly dry-run above is the operator-side
> proof; the workflow below is the upstream-side proof.

The certctl repo ships a weekly GitHub Actions workflow that
exercises the **exact** pg_dump shape this runbook recommends
(`--format=custom --no-owner --no-acl`) against a real Postgres
container, then asserts the audit_events hash chain round-trips
byte-for-byte across the dump → restore boundary. A regression in
the dump format, in a Postgres minor bump, or in migration 000047's
canonical-payload serialization would surface in the next Monday
run instead of on a customer's restore day.

- **Workflow:** [`.github/workflows/backup-restore.yml`](../../../.github/workflows/backup-restore.yml)
  — Mondays 07:00 UTC + `workflow_dispatch`. Postgres service
  container pinned to the same SHA256 digest as
  `deploy/docker-compose.yml`.
- **Harness:** [`deploy/test/backup-restore-smoke.sh`](../../../deploy/test/backup-restore-smoke.sh)
  — runs the workload → `pg_dump -Fc` → `DROP SCHEMA public CASCADE`
  → `pg_restore` → verify cycle. Locally runnable against any
  reachable Postgres (it DROPs the schema, so do not point it at
  data you care about).
- **Workload + verifier:** [`deploy/test/backupsmoke/main.go`](../../../deploy/test/backupsmoke/main.go)
  — generates 24 synthetic `audit_events` rows representing an
  issue/renew/revoke/auth-login cycle, snapshots the chain head
  before the backup, and after restore runs
  `audit_events_verify_chain()` to confirm `first_break_id IS NULL`.

The CI workflow is not a replacement for the quarterly operator
dry-run — it does not exercise the operator-managed file material
(CA keys, RA keys, trust anchors) listed in the "What to back up"
table above. Treat it as the dump-shape regression test; the
quarterly run remains the full-restore correctness test.

## Related reading

- [`docs/operator/runbooks/disaster-recovery.md`](disaster-recovery.md) — the restore companion
- [`docs/operator/secret-custody.md`](../secret-custody.md) — what
  the operator-managed file material (CA keys, RA keys, trust
  anchors) contains, why it lives outside the DB, and what it costs
  to lose
