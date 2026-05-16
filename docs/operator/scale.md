# Operator scale guide

> Last reviewed: 2026-05-16

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

## Scale-tier scenarios (SCALE-H2, Phase 8)

Phase 8 (2026-05-14) extended the k6 load-test harness with three new
scenarios that exercise the scale-relevant load surfaces the original
API tier left uncovered. They live behind a compose profile gate
(`docker compose --profile scale`) so the default `make loadtest`
stays focused on per-PR regression scope. The full set runs weekly on
the same `loadtest.yml` cron as the API + connector tier.

| Scenario | k6 file | Seed fixture | Sustained load |
|---|---|---|---|
| Bulk-renewal under load | `deploy/test/loadtest/k6/bulk_renewal.js` | 10,000 managed_certificates (`seed/01_bulk_renewal_certs.sql`) | 5 req/s POST `/api/v1/certificates/bulk-renew` × 5 min |
| ACME enrollment burst | `deploy/test/loadtest/k6/acme_burst.js` | (none — unauth surface) | 200 concurrent VUs × directory/nonce/ARI × 5 min |
| Agent heartbeat storm | `deploy/test/loadtest/k6/agent_storm.js` | 5,000 agents (`seed/02_agent_fleet.sql`) | 167 req/s POST `/api/v1/agents/{id}/heartbeat` × 5 min |

### Threshold contracts (regression guards, NOT measured baselines)

| Scenario | Metric | Threshold |
|---|---|---|
| Bulk-renewal | `http_req_duration{scenario:bulk_renewal}` p99 | < 5 s |
| Bulk-renewal | `http_req_duration{scenario:bulk_renewal}` p95 | < 2 s |
| Bulk-renewal | `http_req_failed{scenario:bulk_renewal}` | < 1% |
| ACME burst | `acme_directory_duration` p95 | < 500 ms |
| ACME burst | `acme_new_nonce_duration` p95 | < 300 ms |
| ACME burst | `acme_renewal_info_duration` p95 | < 800 ms |
| ACME burst | `http_req_failed{server_error:true}` 5xx-only | < 0.1% |
| Agent storm | `http_req_duration{scenario:agent_storm}` p99 | < 1 s |
| Agent storm | `http_req_duration{scenario:agent_storm}` p95 | < 500 ms |
| Agent storm | `http_req_failed{scenario:agent_storm}` | < 0.1% |

429 rate-limit responses on the ACME burst are EXPECTED — Phase 5's
per-account rate limiter SHOULD fire at sustained 200-VU pressure.
The custom `acme_rate_limited_count` Counter tracks how often it
fires; `acme_rate_limit_shape_ok` Counter verifies every 429 returns
the RFC 7807 `application/problem+json` shape with the
`urn:ietf:params:acme:error:rateLimited` type. A regression that
returned plain-text 429 or a different problem type would surface as
`(rate_limited_count - shape_ok_count) > 0` in the summary.

### Measured baseline

TEST-005 closure (Sprint 5, 2026-05-16) moved the baseline table out
of this file into its own canonical record:
[`docs/operator/scale-baseline-2026-Q2.md`](scale-baseline-2026-Q2.md).
That doc owns the capture procedure, the methodology, and the
per-scenario rows; this page links to it as the authoritative
source.

The split exists because the baseline table is mutable on every
loadtest workflow_dispatch run, while this page (the operator-facing
scale posture doc) changes only when the underlying scenarios or
thresholds change. Keeping them in separate files avoids
review-noise on per-capture commits.

Long-term k6 NDJSON artifacts beyond GHA's 90-day retention live at
[`deploy/test/loadtest-artifacts/`](../../deploy/test/loadtest-artifacts/).

### How to run the scale tier locally

```sh
# All three scenarios serially (~18 min total):
make loadtest-scale

# Individual scenarios (each ~6 min):
make loadtest-scale-bulk     # 10K cert bulk-renew
make loadtest-scale-acme     # 200 VU ACME burst
make loadtest-scale-agent    # 5K agent heartbeat storm
```

Each scenario boots its own copy of the loadtest compose stack
(postgres + tls-init + certctl-server) plus the `scale-seed` init
container that runs the SQL fixtures from `deploy/test/loadtest/seed/`.
The seed is idempotent (`ON CONFLICT … DO NOTHING`) so re-running a
scenario against the same compose stack is cheap.

### Documented limitations of the scale tier

- **JWS-signed ACME flows are not measured.** The ACME burst scenario
  hits the unauthenticated directory + new-nonce + ARI surface only.
  Measuring the JWS-signed POST hot path (new-account / new-order /
  finalize) requires bundling a JWS signer into the k6 driver (k6
  doesn't ship JWS). End-to-end JWS conformance is gated by
  `make acme-rfc-conformance-test` which drives `lego` against the
  same stack.
- **Scheduler renewal scan throughput.** The bulk-renewal scenario
  measures the inbound POST throughput; the scheduler's
  `jobProcessorLoop` drains the enqueued jobs at a fixed per-tick
  budget (`CERTCTL_RENEWAL_CONCURRENCY=25` default), and the
  throughput of that path is not amplified by adding more inbound
  bulk-renew calls. A future scenario could pull
  `/api/v1/jobs?status=pending` and measure drain time.
- **Production-sized Postgres.** The compose stack runs
  `postgres:16-alpine` with default config on a CI runner.
  Production deploys with `shared_buffers >= 1 GiB` + dedicated
  Postgres VM will have different query plans for the 10K-cert
  scan. The captured numbers translate directionally but the
  absolute ceiling is workload-specific — see the operator-tune
  ladder above for production sizing.
- **Pull-only deployment model.** Agent CSR submit, work-poll, and
  deploy-verify paths are intentionally out of scope. The heartbeat
  storm exercises the highest-frequency call on a typical fleet;
  the work-poll path runs at the same cadence but is cheap (empty
  set returned 99% of the time).

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
