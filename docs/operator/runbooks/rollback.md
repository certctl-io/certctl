# Runbook: Helm rollback for certctl

> Last reviewed: 2026-05-14

Use this when:
- A `helm upgrade` rolled out a bad release and the operator wants to
  return to the previous working state.
- A schema migration shipped a change the operator wants to back out.
- An emergency change needs reverting and forward-fix isn't yet
  available.

This page covers `helm rollback` mechanics + the cases where
rollback is NOT enough on its own (schema migrations are the main
one).

## What `helm rollback` does

`helm rollback <release> [revision]` re-applies the manifests from a
previous Helm revision. It re-creates / updates Kubernetes objects to
match that revision's template output and is safe for:

- **Deployment image bumps:** rolls the container image back to the
  previous tag. Pods restart with the old image.
- **ConfigMap / Secret content changes:** old values land in the
  config; pods that consume them via `envFrom` or volume mounts get
  the prior values on the next restart.
- **Resource requests / limits / replica count:** the spec changes
  back to the prior values. Kubernetes reschedules pods accordingly.
- **Service / Ingress / NetworkPolicy changes:** networking flips
  back to the previous shape immediately.

## What `helm rollback` does NOT do

The Kubernetes layer is reversible; the **database schema is not**.
This is the single most common gap in a rollback plan.

### Schema migrations are forward-only by design

certctl's migrations under `migrations/` are numbered up-migrations
(`NNNNNN_*.up.sql`) with paired down-migrations
(`NNNNNN_*.down.sql`) shipped alongside. The `postgres.RunMigrations`
path applied at server boot only runs the `*.up.sql` files. The
`*.down.sql` files exist for development reference + a hypothetical
"surgical revert" path but are **not invoked by `helm rollback`**.

The implication: if `v2.1.0 → v2.2.0` ships migrations 000100,
000101, 000102 (adding columns, changing constraints, dropping
indexes), then `helm rollback` to v2.1.0 takes you back to the v2.1.0
container image — but the database still has migrations 000100-102
applied. The v2.1.0 server code doesn't know about those columns; it
either ignores them (best case) or fails to start (if the schema
diverged in a way the older code can't tolerate).

### When is rollback safe without a schema revert?

Migrations are **additive-only** in 90%+ of cases. The categories:

| Migration class | Safe to roll back without schema revert? | Why |
|---|---|---|
| Add column with default | Yes | Old code ignores the new column |
| Add table | Yes | Old code doesn't reference the table |
| Add index | Yes | Old code doesn't depend on the index existing |
| Add CHECK / FOREIGN KEY constraint | Usually yes | Only fails on row data inserted by new code that violates the old code's constraints |
| Rename column / table | NO | Old code's queries reference the original name |
| Drop column / table | NO (data loss) | New code already stopped writing the column; old code expects it |
| Type change (`VARCHAR(40)` → `TEXT`) | Usually yes | Old code's column read still works |
| Backfill a column | Yes | Old code ignores the backfilled value |

If your upgrade only added columns / tables / indexes, `helm
rollback` is sufficient. If it renamed or dropped anything, you need
a database-level revert.

## Procedure: standard rollback (additive-only migrations)

```bash
# 1. Identify the target revision
helm history certctl -n <namespace>

# 2. Take a backup BEFORE rolling back (defense in depth — if
#    rollback exposes a data corruption issue, restore is the only
#    path back)
#    See docs/operator/runbooks/postgres-backup.md for the canonical
#    pg_dump invocation.

# 3. Roll back to the chosen revision
helm rollback certctl <revision> -n <namespace> --wait --timeout 5m

# 4. Verify
kubectl get pods -n <namespace> -l app.kubernetes.io/instance=certctl
kubectl logs -n <namespace> -l app.kubernetes.io/component=server --tail=50
```

Watch for migration-version mismatch warnings in the server logs. If
the older server code refuses to start because the schema is ahead
of what it knows about, escalate to "rollback with schema revert."

## Procedure: rollback with schema revert

This is the rare case. Use it when:
- A column / table was renamed or dropped in the rolled-up release.
- The older code refuses to start with the newer schema.

```bash
# 1. Take a fresh backup right NOW (the current schema is what we're
#    reverting from; if anything goes wrong we want a clean
#    forward-recovery option)
kubectl exec -n <namespace> statefulset/certctl-postgres -- \
  pg_dump --format=custom --no-owner --no-acl --dbname=certctl \
  > "certctl-pre-rollback-$(date -u +%Y%m%dT%H%M%SZ).dump"

# 2. Stop the server Deployment to prevent it from writing to the
#    database during the revert
kubectl scale deploy/certctl-server -n <namespace> --replicas=0

# 3. Apply the relevant *.down.sql files manually, one at a time, in
#    reverse migration-number order. Example for reverting two
#    migrations:
NEW=000102  # newest migration on the running schema
OLD=000100  # oldest migration to revert (inclusive)
for MIG in 000102 000101 000100; do
  kubectl exec -i -n <namespace> statefulset/certctl-postgres -- \
    psql --user=certctl --dbname=certctl \
    < migrations/${MIG}_*.down.sql
done

# 4. Manually update the schema_migrations table to reflect the
#    reverted state (the migration runner's bookkeeping)
kubectl exec -n <namespace> statefulset/certctl-postgres -- \
  psql --user=certctl --dbname=certctl -c \
  "DELETE FROM schema_migrations WHERE version > $((OLD - 1));"

# 5. NOW run helm rollback. The server pod will start with a schema
#    that matches its code.
helm rollback certctl <revision> -n <namespace> --wait --timeout 5m
```

The `*.down.sql` files are tested but only against pristine schemas —
they may not handle every data shape a production database
accumulates. ALWAYS take a backup first; the down-migrations are
a recovery tool, not a transactional contract.

## Procedure: full restore (when revert isn't tractable)

When a down-migration would lose data (drop columns / tables that
hold rows the older code can't read but the newer code populated), a
full restore is the only safe path. This is the procedure described
in
[`docs/operator/runbooks/disaster-recovery.md`](disaster-recovery.md#postgres-restore).
The summary:

1. Stop certctl.
2. Take a backup of the CURRENT schema (defense in depth).
3. Restore the LAST backup taken BEFORE the bad upgrade.
4. Roll the Helm release back to the matching code version.
5. Restart certctl.
6. Re-run any audited writes that happened in the window between the
   backup and the bad upgrade (read the audit log; the API surface
   is recoverable).

The DR runbook owns the canonical commands.

## Common pitfalls

- **Forgetting the backup before rollback.** A schema-revert path is
  not safe without a fresh backup. If something goes wrong mid-revert
  and your most recent backup is from last night, you've lost any
  cert-issuance history between then and now.
- **Rolling back the chart without rolling back the database state**
  on a release that included a destructive migration (drop column,
  drop table). Symptoms: old code starts, queries fail with
  "column does not exist," server crashes in a loop. Recovery
  requires schema revert OR full restore.
- **Letting the agents drift.** `helm rollback` updates the agent
  DaemonSet's image too — agents on different versions than the
  server may produce incompatible CSR payloads. After rollback,
  confirm agent images are at the matching version via
  `kubectl get daemonset certctl-agent -o jsonpath='{.spec.template.spec.containers[0].image}'`.
- **GHCR images pinned by digest:** the rollback restores the prior
  `image:` value from the Helm template. If your operator workflow
  uses `image.digest` pinning, the digest comes back too — make
  sure that digest still exists on ghcr.io. They do persist; old
  tags are never deleted, but a private mirror may have garbage-collected.

## Related reading

- [`docs/operator/runbooks/postgres-backup.md`](postgres-backup.md) —
  the backup procedure that's the precondition for any
  schema-revert path.
- [`docs/operator/runbooks/disaster-recovery.md`](disaster-recovery.md) —
  the full restore procedure when rollback isn't tractable.
- [`docs/migration/api-keys-to-rbac.md`](../../migration/api-keys-to-rbac.md) —
  example of a migration that the runtime supports rolling back via
  feature flag (rare).
