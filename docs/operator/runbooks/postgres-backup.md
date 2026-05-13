# Runbook: PostgreSQL backup for certctl

> Last reviewed: 2026-05-13

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

This is the gap an acquisition reviewer typically wants to see filled.
certctl ships no backup CronJob template in the Helm chart — the
operator owns this layer because:

1. The right tool depends on the deployment topology (in-cluster
   Postgres vs. managed Postgres vs. self-hosted on a VM).
2. The right secret-management integration depends on the operator's
   existing stack (Vault, AWS Secrets Manager, GCP Secret Manager,
   sealed-secrets, External Secrets).
3. The right storage backend depends on the operator's existing
   off-host blob storage.

A bundled CronJob would be a half-answer for any operator with an
established backup posture, and would have to be torn out before
production. Three sample recipes that cover the common cases:

- **In-cluster Postgres → S3:** a CronJob running an alpine image with
  `aws-cli` + the `pg_dump` command above, output piped to
  `aws s3 cp`. Cosign-signed if your supply-chain policy requires it.
- **Managed Postgres (AWS RDS / GCP Cloud SQL / Azure DB):** rely on
  the cloud provider's built-in PITR backup; configure retention
  ≥ 30 days; the certctl deployment surface is the connection string
  alone.
- **Self-hosted VM:** systemd timer + `pg_dump` + `restic` (or
  `borgbackup`) to encrypted off-host storage.

Tracked in [WORKSPACE-ROADMAP.md](../../../WORKSPACE-ROADMAP.md) as a
post-v2.1.0 nice-to-have: an opt-in Helm CronJob template for the
in-cluster-Postgres-to-S3 case as a starter. The right time to ship
it is when a real operator asks for it; speculatively shipping it
without that signal would just produce a template every deployment
ends up rewriting.

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

## Related reading

- [`docs/operator/runbooks/disaster-recovery.md`](disaster-recovery.md) — the restore companion
- [`docs/operator/secret-custody.md`](../secret-custody.md) — what
  the operator-managed file material (CA keys, RA keys, trust
  anchors) contains, why it lives outside the DB, and what it costs
  to lose
