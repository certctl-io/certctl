# Scheduler HA Semantics

> Last reviewed: 2026-05-13

What happens when you run more than one `certctl-server` replica? Which scheduler loops are safe to run on every replica simultaneously, which need leader election, and which silently duplicate work today?

This page closes Bundle 4 audit findings **D8** (singleton loop ambiguity) and **HIGH-1 + MED-2** (HA semantics across the scheduler surface). It is a per-loop inventory of the 15 scheduler loops in `internal/scheduler/scheduler.go`, classified by HA-safety.

## TL;DR

The only loops that are HA-safe today via `FOR UPDATE SKIP LOCKED` job claiming are `jobProcessorLoop` and `jobRetryLoop`. Every other loop is *intra-process* idempotent (a per-replica `sync/atomic.Bool` guard prevents a single replica from running the same loop twice at once) but is *cross-replica* duplicative — two replicas tick at the same interval and both do the work.

For ten of the fourteen non-job-claim loops this is harmless: the work is read-only DB scanning that produces idempotent side effects (e.g., create-job-if-not-exists, send-notification-once-per-event-via-DB-ledger), and duplicate execution wastes CPU but cannot corrupt data. For four loops (`notificationProcessLoop`, `digestLoop`, `crlGenerationLoop`, `cloudDiscoveryLoop`) duplicate execution produces observable duplicate side effects: duplicate emails, duplicate webhooks, duplicate CRL writes. v2.1.0 supports `server.replicas > 1` for read availability and api throughput, but operators running multi-replica should accept these four duplication classes or pin replicas to 1 until the leader-election work lands.

True leader-election via Postgres advisory lock or Kubernetes lease is tracked in `WORKSPACE-ROADMAP.md` as a v3 work item.

## Per-loop inventory

The 15 loops live in `internal/scheduler/scheduler.go`. Each is a `func (s *Scheduler) <name>Loop(ctx context.Context)` driven by a `time.Ticker`. The intra-process guard pattern is `sync/atomic.Bool` `CompareAndSwap(false, true)` at the top of the loop body — pre-Bundle-4 every loop already had this guard. Bundle 4 added the cross-replica classification below.

| # | Loop | HA mode | Side-effect duplication risk under N>1 replicas |
|---|---|---|---|
| 1 | `renewalCheckLoop` | **Idempotent** — creates renewal jobs via `service.CheckExpiringCertificates`. | None. Duplicate ticks try to create the same `RenewalRequested` job; service-layer dedup (cert_id + status uniqueness window) collapses the second. Result: 2× CPU, 1× job, no data corruption. |
| 2 | `jobProcessorLoop` | **HA-safe** — `service.ProcessPendingJobs` ultimately calls `repository/postgres.JobRepository.ClaimPendingJobs` which uses `SELECT ... FOR UPDATE SKIP LOCKED`. | None. Postgres guarantees exactly-once row claim per tick across the replica set. |
| 3 | `jobRetryLoop` | **HA-safe** — `service.RetryFailedJobs` uses the same `ClaimPendingJobs` primitive (Bundle 1 audit fix H-6, commit `6cb4414`). | None. |
| 4 | `jobTimeoutLoop` | **HA-safe-ish** — `service.TimeoutStalledJobs` UPDATEs with `WHERE status = 'Running' AND started_at < $cutoff` inside a single statement. Two replicas may UPDATE the same row but the second UPDATE sees `Running → Failed` already applied and matches zero rows. | None. |
| 5 | `agentHealthCheckLoop` | **Idempotent** — UPDATEs `agents SET operational_status = 'Offline' WHERE last_heartbeat < $cutoff`. Two replicas running the same UPDATE land the same final state. | None. |
| 6 | `notificationProcessLoop` | **Duplicates** — reads pending notification queue, dispatches to Slack / PagerDuty / SMTP / Teams / OpsGenie, marks dispatched. The dispatch and the "mark dispatched" are not in a single transaction; two replicas can both dispatch the same notification before the mark lands. | **Duplicate webhook + email sends**. Bounded — at most N duplicates for N replicas — but operator-observable. |
| 7 | `notificationRetryLoop` | **Duplicates** — same shape as `notificationProcessLoop`. | Same as #6. |
| 8 | `shortLivedExpiryCheckLoop` | **Idempotent** — UPDATEs cert status to `Expired` based on `expires_at < NOW()`. Two replicas land the same status. | None. |
| 9 | `networkScanLoop` | **Idempotent** — invokes `service.NetworkScanService.ScanAllEnabledTargets` which iterates scan targets, probes each, and INSERTs discovered certs with `ON CONFLICT (fingerprint, agent_id, source_path) DO NOTHING`. | None on cert insertion. Duplicate TLS probes hit the operator's targets twice per tick. Operator may want to cap to 1 replica for low-egress-budget environments. |
| 10 | `digestLoop` | **Duplicates** — assembles the periodic digest email and dispatches via SMTP. Two replicas at the same digest tick both send. | **Duplicate digest emails**. |
| 11 | `healthCheckLoop` | **Idempotent** — runs the active TLS-fingerprint health-check sweep across deployed certs. Same idempotency story as #8. | None on state. Duplicate TLS probes to operator targets. |
| 12 | `cloudDiscoveryLoop` | **Duplicates the scan; idempotent on the result store** — fetches cert lists from AWS Secrets Manager / Azure Key Vault / GCP Secret Manager, INSERTs into discovered-certs with `ON CONFLICT DO NOTHING`. | **Duplicate AWS/Azure/GCP API calls** — bills operator cloud accounts 2× per tick on the discovery API surface. Storage stays clean. |
| 13 | `crlGenerationLoop` | **Duplicates the signing; last-writer wins on storage** — regenerates CRL DER blobs per issuer, writes to `certificate_revocation_lists` table with `UPDATE ... WHERE issuer_id = $1`. Two replicas sign two CRLs with two `thisUpdate` timestamps; the later UPDATE wins. | **Duplicate CA signing operations** (cost on HSM-backed issuers). CRL output is single-valued but the audit trail records both signings. |
| 14 | `acmeGCLoop` | **Idempotent** — DELETEs ACME nonce / authz / order rows older than the retention window. Two replicas race the same DELETEs; second one matches zero rows. | None. |
| 15 | `sessionGCLoop` | **Idempotent** — DELETEs expired session rows. Same shape as #14. | None. |

## What Bundle 4 closes

Bundle 4 does NOT introduce leader election. It introduces:

1. **Documented HA truth table** (this page) — operators know exactly which loops are safe to multi-replica and which produce operator-observable duplicates.
2. **Migration HA** via `pg_advisory_lock` + `schema_migrations` audit table (see `internal/repository/postgres/db.go::RunMigrations`). Pre-Bundle-4 every replica race-ran all 45 migrations on boot. Post-Bundle-4 the first replica acquires the lock, applies migrations, populates `schema_migrations`, releases the lock. Subsequent replicas block at the lock, then observe the audit table and skip every already-applied file.
3. **Rate-limit scope statement** at `docs/operator/rate-limit-scope.md` — process-local per-replica, restart-safe.

## What Bundle 4 does NOT close (deferred, tracked in WORKSPACE-ROADMAP.md)

- **Leader election** for `notificationProcessLoop`, `notificationRetryLoop`, `digestLoop`, `cloudDiscoveryLoop`, `crlGenerationLoop`. The cleanest implementation is a per-loop `pg_try_advisory_lock(lock_id)` at the top of `runX` so only one replica per tick claims the work, with a small leader-renewal mechanic for long-running loops. This would close the four duplicate-side-effect cases above. v3 work item.
- **Shared rate limits across replicas**. See `docs/operator/rate-limit-scope.md`.

## Operator guidance

**Single-replica deployments (Helm `server.replicas: 1` — the chart default)**: all 15 loops work as documented. No action needed.

**Multi-replica deployments**: review the four duplicate-side-effect loops above against your tolerance:

- If your alerting fan-out can swallow duplicate webhooks (PagerDuty deduplicates by `dedup_key`, Slack does not), set `server.replicas > 1` and accept the duplication.
- If your CRL signing uses an HSM with per-operation cost, pin to single-replica until leader election lands.
- If you're running cloud discovery against billed AWS/Azure/GCP secret-manager APIs and you have a 6 h discovery interval, the doubling is bearable; at 30 min intervals it doubles your API spend.

For any duplicate-side-effect class above, the operational mitigation is pinning `server.replicas: 1` and scaling vertically. The certctl-server process is CPU-bound on issuance and IO-bound on Postgres; a single replica handles substantial fleets when given enough cores + a fast database.

## Source-of-truth references

- Scheduler loops: `internal/scheduler/scheduler.go` (15 `<name>Loop` functions, search `^func \(s \*Scheduler\) [a-zA-Z]+Loop`).
- Job claim primitive: `internal/repository/postgres/job.go::ClaimPendingJobs` (Bundle 1 H-6 closure, commit `6cb4414`).
- Migration HA: `internal/repository/postgres/db.go::RunMigrations` (Bundle 4 closure).
- Rate-limit scope: `docs/operator/rate-limit-scope.md`.
- Load-test scope: `deploy/test/loadtest/README.md` ("What it explicitly does NOT measure").
