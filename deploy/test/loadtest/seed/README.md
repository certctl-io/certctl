# Phase 8 load-test seed fixtures

Opt-in seed scripts that grow the loadtest DB from the demo-scale
fixture (~15 certs / ~10 agents from `migrations/seed_demo.sql`) to
fleet scale (10K certs + 5K agents) so the Phase 8 SCALE-H2 scenarios
measure something representative.

## When these run

The default `make loadtest` path does NOT touch this directory — the
API tier and connector tier scenarios run against the demo seed alone
and complete in ~5 minutes. The Phase 8 scenarios opt-in via the
`LOADTEST_SCALE_SEED=true` environment variable; when set, the
`certctl-loadtest-scale-seed` one-shot init container runs every
`*.sql` file in this directory in lexical order against the same
Postgres instance the server uses.

Compose service wiring (see `../docker-compose.yml`):
- Service: `scale-seed`
- Profile: `scale-seed` (compose `profiles:` gate; not started by
  default)
- Depends on: `postgres` (service_healthy) AND `certctl-server`
  (service_healthy — server runs schema migrations at boot so the
  seed runs AFTER tables exist)
- Order: lexical (`01_bulk_renewal_certs.sql` then
  `02_agent_fleet.sql`)
- Idempotent: every script uses `ON CONFLICT DO NOTHING` so re-running
  is a no-op.

## What gets seeded

| File | Rows | Purpose |
|---|---|---|
| `01_bulk_renewal_certs.sql` | 10,000 managed_certificates | Fleet shape for `bulk_renewal.js`. All linked to demo FKs (iss-local, o-alice, t-platform, rp-standard). Status `active`, expires_at distributed across the next 30 days so a 30-day renewal window considers every row eligible. Name prefix `loadtest-bulk-` so the k6 scenario can scope its bulk-renew criteria. |
| `02_agent_fleet.sql` | 5,000 agents | Fleet shape for `agent_storm.js`. Status `Online`, last_heartbeat_at staggered across prior 60s, name prefix `loadtest-agent-`. OS distribution: 80% linux / 10% windows / 10% darwin. Arch: 80% amd64 / 20% arm64. |

## How to run the Phase 8 scenarios locally

```bash
cd deploy/test/loadtest
LOADTEST_SCALE_SEED=true docker compose --profile scale-seed up --build \
    --abort-on-container-exit --exit-code-from k6-scale
```

Or via the dedicated Makefile target (preferred for CI parity):

```bash
make loadtest-scale
```

## Why SQL fixtures instead of a Go seed binary

- The certctl-server already boots from a clean DB and runs migrations
  + `seed_demo.sql` when `CERTCTL_DEMO_SEED=true`. Adding a third seed
  mode (loadtest-scale) would mean either a new
  `CERTCTL_LOADTEST_SEED` flag wired into `cmd/server/main.go` (cross-
  cutting change for one test path) or a separate seed binary (more
  compose surface).
- Raw SQL is the smallest viable change: each script is a single
  multi-row `INSERT … SELECT FROM generate_series(…)` plus a
  `DO $$ … RAISE NOTICE` confirmation block.
- Idempotency is straightforward via `ON CONFLICT … DO NOTHING` — the
  same pattern `seed_demo.sql` uses.

## Why these volumes specifically

- **10K certs.** The SCALE-H2 audit asked for "10K certs with
  renewal_at < now." Round number, fits in postgres:16-alpine on a
  CI runner without OOM, and large enough that the renewal selector's
  query plan is exercised (the demo's 15 rows would index-scan
  trivially).
- **5K agents.** Heartbeat at 30s cadence = ~167 heartbeats/sec
  sustained. That's well above the 50 req/s the existing API tier
  measures and stresses the agent.heartbeat handler's per-call cost
  (last_heartbeat_at UPDATE + the RBAC permission check + the
  audit-log row).

If a future scenario needs more rows (50K certs / 10K agents), add a
new `03_…sql` here and another scenario file. Don't grow the existing
files — re-running existing scenarios against a different fixture
shape would invalidate the captured baseline.

## Phase 8 audit reference

Source finding: SCALE-H2 in
`cowork/certctl-architecture-diligence-audit.html`.
Phase 8 closure commit: see `git log --grep='Phase 8'`.
