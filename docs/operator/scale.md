# Operator scale guide

> Last reviewed: 2026-05-14

Use this when:
- You're sizing a new certctl deployment for a target fleet count.
- You're scaling an existing deployment up from demo (15 certs / 1
  agent) to production (1K+ certs / 100+ agents).
- An auditor asks "what does this scale to?" and you want a documented
  answer that isn't "we haven't measured."

## DB connection pool

certctl's PostgreSQL connection pool is the single largest scale lever.
Pool exhaustion looks like 503s + agent poll timeouts + scheduler
falling behind on its loops. The default ships at 50 max open
connections (`CERTCTL_DATABASE_MAX_CONNS=50`), with idle = max/5 = 10
under the existing `internal/repository/postgres/db.go::NewDBWithMaxConns`
contract.

Operator-tune ladder:

| Fleet size                  | `CERTCTL_DATABASE_MAX_CONNS` | Postgres `max_connections` | Notes |
|---|---|---|---|
| ≤ 500 certs / 100 agents    | `50` (default)               | `100` (PG default)         | Demo + small deployments. Pool default sized for this. |
| 5K certs / 1K agents        | `100`                        | `200`                      | Postgres needs an explicit bump from the 100 default; reload required. |
| 50K certs / 10K agents      | `200`                        | `400`                      | Plus dedicated Postgres VM (separate from server host); shared_buffers ≥ 1Gi. |

Always leave headroom in Postgres's `max_connections` for backups
(`pg_dump` opens its own connection), ad-hoc psql sessions, and
replicas. The ratio `(server pool size × replicas) + 20` is a safe
floor for Postgres's `max_connections`.

**Numbers above the small-fleet row are operator-tuning starting
points, not validated ceilings.** Phase 8 of the architecture diligence
remediation will replace these with measured values from synthetic
fleets; until then, capture your own observations in a loadtest log
and tune against them.

## Scheduler tick budgets

certctl has 15 scheduler loops, each with its own cadence
(internal/scheduler/scheduler.go). The renewal scan is the hottest
loop on large fleets: it pulls every managed certificate, applies
each profile's renewal policy, and dispatches an issuance job per
cert that meets the threshold. The default cadence is `1h`
(`CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL`).

Phase 6 SCALE-M5 closure (2026-05-14) added per-ticker jitter via the
`internal/scheduler.JitteredTicker` wrapper. Each loop's interval is
unchanged; the wrapper adds ±10% randomized delay per tick so multiple
loops with the same nominal cadence don't co-fire and cause hour-
boundary CPU + DB spikes. For most fleets the visible effect is a
smoother CPU graph during the renewal scan.

**Renewal-sweep semaphore (SCALE-L1).** The renewal loop dispatches
concurrent issuance work behind a per-tick semaphore (default
`CERTCTL_RENEWAL_CONCURRENCY=25`). Under tick-budget pressure (a tick
that exceeds the loop interval), the semaphore can hold the entire
concurrency cap until the context cancels at next-tick boundary —
which is intentional. The drain happens via context cancellation; new
work isn't started past the deadline. Tests in
`internal/scheduler/` pin this drain behavior. Operators on large
fleets should:

1. Bump `CERTCTL_RENEWAL_CONCURRENCY` to 50 or 100 if the renewal scan
   consistently exceeds tick budget.
2. Also bump `CERTCTL_DATABASE_MAX_CONNS` proportionally — each
   concurrent renewal task opens its own pool connection during
   issuance / deployment.
3. Watch for the "renewal scan complete" log line per tick. If it's
   consistently late, you're under-provisioned.

## Async CA polling budgets (SCALE-M3)

DigiCert, Entrust, GlobalSign, and Sectigo are async issuers — they
accept a CSR, queue it on the CA side, and return a polling token.
The certctl server polls the CA's status endpoint until the cert is
ready or the deadline expires. The default poll-deadline is 10
minutes wall-clock (`asyncpoll.DefaultMaxWait`); after that the
issuance returns `StillPending` and the scheduler re-enqueues the
job for the next tick.

Priority chain when picking the actual deadline (highest → lowest):

1. Per-connector env: `CERTCTL_DIGICERT_POLL_MAX_WAIT_SECONDS`,
   `CERTCTL_ENTRUST_POLL_MAX_WAIT_SECONDS`,
   `CERTCTL_GLOBALSIGN_POLL_MAX_WAIT_SECONDS`,
   `CERTCTL_SECTIGO_POLL_MAX_WAIT_SECONDS`.
2. Global env: `CERTCTL_ASYNC_POLL_MAX_WAIT_SECONDS` (sets the
   process-wide default for all async-CA connectors that didn't set
   their per-connector value).
3. Package const: `asyncpoll.DefaultMaxWait = 10 * time.Minute`.

Operators with slow async CAs (Entrust certificate-mode in
particular can take 15-30 minutes during business hours) should
raise the per-connector value rather than the global; that way fast
issuers don't pay the polling cost.

## Cursor pagination caching (SCALE-L2)

Phase 6 SCALE-L2 closure (2026-05-14) added an ETag middleware at
`internal/api/middleware/etag.go` covering the top-5 read endpoints:
`/api/v1/certificates`, `/api/v1/jobs`, `/api/v1/agents`,
`/api/v1/audit`, `/api/v1/discovery/certificates`. The ETag is
derived from `(max-row-updated-at, row-count)` for the requested
filter; repeated requests with the same query return `304 Not
Modified` when the underlying data hasn't changed. The dashboard
benefits most — its polling loop on the certificates page is the
single largest read-traffic source on most deployments.

When the cache is effective, repeated reads bypass the
`SELECT COUNT(*) FROM <table>` query entirely. The cache invalidates
on any mutation to the table (the row-count + max-updated-at hash
flips).

Operators don't need to do anything to opt in — the middleware is
wired around the top-5 endpoints unconditionally. If you want to
verify it's working, check the `ETag:` response header on a list
endpoint and repeat the request with the same value in an
`If-None-Match:` header — the second request should return 304 with
an empty body.

## Profiling production

When the above ladder doesn't fit your shape, profile against your
specific workload. The
[performance-baselines.md](performance-baselines.md) runbook has
single-endpoint, inventory-walk, and renewal-scan recipes you can
adapt.

## Related reading

- [`docs/operator/performance-baselines.md`](performance-baselines.md) —
  per-endpoint baselines + how to re-baseline after upgrades.
- [`docs/operator/runbooks/postgres-backup.md`](runbooks/postgres-backup.md) —
  Postgres-side backup discipline (necessary precondition for any
  scale tuning).
- [`deploy/ENVIRONMENTS.md`](../../deploy/ENVIRONMENTS.md) — the
  full env-var inventory the values referenced above come from.
