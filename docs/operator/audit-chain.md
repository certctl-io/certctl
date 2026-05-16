# Audit-trail tamper-evidence (audit_events hash chain)

> Last reviewed: 2026-05-16

Sprint 6 COMP-001-HASH closure. The `audit_events` table has two
layered defenses against history rewrites:

| Layer | Migration | What it blocks |
|---|---|---|
| **WORM trigger** | `000018_audit_events_worm.up.sql` | The application role cannot `UPDATE` or `DELETE` rows (tamper-**prevention**). |
| **Hash chain** | `000047_audit_events_hash_chain.up.sql` | A compliance superuser (DB-superuser-equivalent) who bypasses the WORM trigger CAN still rewrite rows, but the rewrite is **detectable** — every subsequent `audit_events_verify_chain()` walk reports the first broken row's id + position (tamper-**evidence**). |

This document covers the hash-chain layer. The WORM layer is
documented inline in `migrations/000018_audit_events_worm.up.sql`.

## Why a hash chain in addition to WORM

The WORM trigger documents (in its header comment) that a compliance
superuser role exists by design — backup-restore, retention purges,
and breach-recovery operators need a way through. Without a hash
chain, that role can rewrite any row's `actor` / `action` / `details`
content with no on-disk trace.

HIPAA §164.312(b), FedRAMP AU-9, and NIST 800-53 AU-10 want
tamper-**evidence**, not just tamper-prevention. The hash chain
provides it: every row carries a `row_hash = sha256(prev_hash || id
|| actor || actor_type || action || resource_type || resource_id
|| details::text || timestamp_iso8601_utc || event_category)`, and
the genesis row's `prev_hash` is `NULL`. Mutating any field in any
row breaks the chain at that row's position; the verifier returns
the first break.

## The verifier function

`audit_events_verify_chain()` is a STABLE plpgsql function shipped
in migration 000047. It walks every row in `(timestamp ASC, id ASC)`
order, recomputes each row's expected hash, and returns:

```
first_break_id  TEXT  -- NULL if the chain validated end-to-end
first_break_pos INT   -- 0-indexed position of the first break
row_count       INT   -- rows walked (= position + 1 on break, else table size)
```

Call it directly from psql:

```sql
SELECT first_break_id, first_break_pos, row_count FROM audit_events_verify_chain();
```

## Scheduled verification + Prometheus exposure

The scheduler's `auditChainVerifyLoop` calls the verifier every
`CERTCTL_AUDIT_CHAIN_VERIFY_INTERVAL` (default 6h) and writes the
results into the `AuditChainCounter` instance shared with the
metrics handler. Four metrics get exposed at
`/api/v1/metrics/prometheus`:

| Metric | Type | Meaning |
|---|---|---|
| `certctl_audit_chain_break_detected_total` | counter | Sticky once non-zero — the actionable alarm. |
| `certctl_audit_chain_verify_total` | counter | Walks completed. Cross-check that the loop is alive. |
| `certctl_audit_chain_rows` | gauge | Most recent walk's row count. |
| `certctl_audit_chain_last_verified_at` | gauge | Unix seconds of most recent walk (0 = never). |

The recommended alert rule is:

```
ALERT AuditChainBreak
  IF certctl_audit_chain_break_detected_total > 0
  FOR 1m
  LABELS { severity = "page", category = "compliance" }
  ANNOTATIONS {
    summary = "audit_events hash chain break detected — investigate immediately",
    runbook = "<your-runbook-url>/audit-chain-break"
  }
```

Cross-check `certctl_audit_chain_last_verified_at` (should advance
roughly every `CERTCTL_AUDIT_CHAIN_VERIFY_INTERVAL`) and
`certctl_audit_chain_verify_total` (should increment monotonically).
A stalled `_verified_at` with an unchanged `_verify_total` means the
scheduler loop has died — page on that too.

## Performance notes

The walk is `O(N)` plpgsql over the `audit_events` table. On
testcontainers + postgres:16-alpine the cost scales linearly:

| Row count | Walk duration (approx) |
|---|---|
| 10k | < 50 ms |
| 100k | < 500 ms |
| 1M | 2-3 s |
| 10M | 25-30 s |

A 5-minute per-tick context timeout (in
`internal/scheduler/scheduler.go::runAuditChainVerify`) bounds the
worst case. Fleets with > 10M audit rows should consider:

1. Lengthening `CERTCTL_AUDIT_CHAIN_VERIFY_INTERVAL` to 24h.
2. Pre-aggregating older rows (out of scope today — would require a
   "chain checkpoint" concept that re-anchors the genesis hash to a
   snapshot's row_hash; future work if needed).

## What to do when a break is detected

1. **Don't panic, don't auto-remediate.** The break is a forensic
   signal, not a self-healing event.
2. **Capture the position + id.** The metric exposes both, but the
   sticky in-memory state (`AuditChainCounter.BrokenAtID`) only
   records the first break. SQL the verifier yourself to enumerate
   downstream breaks:

   ```sql
   SELECT first_break_id, first_break_pos, row_count FROM audit_events_verify_chain();
   ```

3. **Snapshot the table.** `pg_dump --table=audit_events --data-only`
   to a chain-of-custody location. The next investigative step is
   recovering the original row content from the most recent backup
   that pre-dates the tampering — without this snapshot you can't
   tell which write order caused the divergence.
4. **Audit the compliance-superuser credential trail.** The break
   implies someone with non-app DB credentials wrote to
   `audit_events`. Rotate the credential, investigate every recent
   session that authenticated under it, and review the WAL for the
   write.
5. **Restore + cross-reference.** If you keep streaming WAL or
   periodic snapshots, restore a known-good snapshot to a sandbox
   and `EXCEPT`-diff the two `audit_events` tables to enumerate
   every mutated row.

## Backfill behavior

Migration 000047 backfills existing `audit_events` rows in
`(timestamp ASC, id ASC)` order during its transaction. The WORM
trigger is temporarily `DISABLE`d for the duration; subsequent
`ENABLE` is a no-op equivalent. The migration is idempotent — a
re-run sees `row_hash IS NULL` rows as the only backfill targets, so
already-hashed rows are not touched.

Once backfill completes, `row_hash` becomes `NOT NULL`. `prev_hash`
remains nullable so the genesis row (first row in the chain) stays
representable.

## Operator configuration

| Env var | Default | Notes |
|---|---|---|
| `CERTCTL_AUDIT_CHAIN_VERIFY_INTERVAL` | `6h` | Tick cadence for the scheduler's verify loop. Zero or negative is ignored. |

## See also

- `migrations/000047_audit_events_hash_chain.up.sql` — migration source.
- `migrations/000018_audit_events_worm.up.sql` — paired WORM trigger.
- `internal/repository/postgres/audit_chain_test.go` — testcontainers integration tests.
- `internal/repository/postgres/audit_worm_test.go` — WORM behaviour tests.
- `internal/scheduler/scheduler.go::auditChainVerifyLoop` — scheduler loop.
- `internal/service/audit_chain_metric.go` — `AuditChainCounter`.
- `internal/api/handler/metrics.go` — Prometheus exposer.
