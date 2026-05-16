# Scale baseline — 2026 Q2 canonical-hardware capture

> Last reviewed: 2026-05-16

## What this file is

The canonical record of certctl's load-test baselines for the
2026-Q2 reporting window. TEST-005 closure (Sprint 5, 2026-05-16)
introduces this doc as the single source of truth for "what's the
scale ceiling?" — replacing the TBD-laden table at
[`docs/operator/scale.md`](scale.md#measured-baseline) that had been
unfilled since the scenarios shipped in Phase 8.

The numbers below come from the `loadtest` GitHub Actions workflow
running its three canonical scenarios on `ubuntu-latest` runners:

- `bulk-renewal` — 10,000-cert seed + criteria-mode
  `POST /api/v1/certificates/bulk-renew`, 200 concurrent VUs over 10
  minutes.
- `acme-burst` — 200 concurrent VUs hitting `/acme/directory`,
  `/acme/new-nonce`, and `/acme/renewal-info/<cert-id>` simultaneously.
- `agent-storm` — 5,000-agent seed + sustained
  `POST /api/v1/agents/{id}/heartbeat` at 167 RPS.

Thresholds enforced inline in `deploy/test/loadtest/k6.js` (p99 < 5s
for issuance-acceptance, p99 < 2s for list, error rate < 1%). k6 exits
non-zero on any breach, which propagates through `docker compose up
--exit-code-from k6 → make loadtest → workflow exit`.

## Capture procedure

1. Trigger the workflow:
   - **Actions** → `loadtest` → **Run workflow**, branch `master`.
   - Wait ~25 minutes for the three matrix legs to finish.
2. Download each scenario's artifact from the workflow run page:
   - `k6-scale-bulk-renewal-<run-id>`
   - `k6-scale-acme-burst-<run-id>`
   - `k6-scale-agent-storm-<run-id>`
   - Each archive contains the k6 `summary.json` + raw NDJSON
     points (90-day GHA retention).
3. Run `scripts/scale-baseline/extract.sh <run-id>` (see below) to
   pull the three artifacts and emit the table rows for this doc.
4. Paste the rows under the **Latest capture** section. Update
   `> Last reviewed:` to today.
5. Commit the artifacts you want long-term-retained to
   [`deploy/test/loadtest-artifacts/`](../../deploy/test/loadtest-artifacts/)
   using `git lfs` if the archives exceed 100 MB; otherwise commit
   them inline.

## Latest capture

| Scenario | Run ID | Date | p50 | p95 | p99 | Error rate | Peak server RSS | Notes |
|---|---|---|---|---|---|---|---|---|
| **bulk-renewal** | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | First post-TEST-005 capture; trigger via workflow_dispatch + extract via the procedure above. |
| **acme-burst** directory | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | — |
| **acme-burst** new-nonce | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | — |
| **acme-burst** renewal-info | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | — |
| **agent-storm** | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | _capture pending_ | — |

The "_capture pending_" placeholders are deliberate — the operator
fills them after the next `loadtest` workflow_dispatch run. Once
filled, replace these rows; do not edit them in place across runs
(the historical row stays as evidence).

## Why "ubuntu-latest" instead of RDS-shaped hardware

The audit's fix language preferred RDS-shaped Postgres on a
fixed-spec runner. ubuntu-latest's 2-vCPU / 7-GB-RAM shape is
narrower than typical production Postgres, but it has two virtues:

1. **Reproducibility.** Every operator + acquirer can reproduce the
   numbers; an RDS-shaped Postgres requires a paid AWS account.
2. **Conservative ceiling.** If the published numbers come from a
   constrained runner, real-world deployments on production Postgres
   sizes (db.m5.large +) only get better.

When an acquirer or operator asks for a production-equivalent
baseline, capture a second run on whatever infrastructure they want
to validate against and add it under a new **2026 Q3 capture**
section.

## Methodology

### Hardware

- **Runner:** GitHub Actions `ubuntu-latest` (currently Ubuntu 24.04, 2-vCPU, 7-GB RAM).
- **certctl image:** built from the same commit the workflow runs on.
- **Postgres:** `postgres:16-alpine@sha256:890480b08124ce7f79960a9bb16fe39729aa302bd384bfd7c408fee6c8f7adb7`, in-cluster, default config (no operator tuning).
- **Network:** runner localhost.

### Software

- **k6:** version pinned in `deploy/test/loadtest/Dockerfile`.
- **certctl tag:** the v* tag at workflow trigger time (matches `openapi.yaml info.version`).

### Metrics captured

- **p50 / p95 / p99 latency** — k6's `http_req_duration` percentiles.
- **Error rate** — k6 `http_req_failed` rate (non-2xx + connection errors).
- **Peak server RSS** — `docker stats` polled at 1-Hz for the
  duration of the run; `max(memory_stats.usage)` taken from the
  emitted JSON.
- **Acceptance gate** — the k6 thresholds in `k6.js`; if exceeded
  the workflow fails.

### What's NOT captured

- **Cold-start latency** — these are steady-state baselines after the
  k6 warmup ramp. Cold-start is a separate concern (renewal-loop
  startup, scheduler tick boundary), not covered by these scenarios.
- **WAN latency** — runs are localhost; production-WAN-RTT additions
  fall outside scope.
- **Federation overhead** — single-instance only; HA + replicas runs
  are a future deliverable.

## Related reading

- [`docs/operator/scale.md`](scale.md) — the operator-facing scale
  posture doc; baseline rows there point at this file.
- [`deploy/test/loadtest/README.md`](../../deploy/test/loadtest/README.md) —
  scenario semantics + how to read the k6 output.
- [`deploy/test/loadtest-artifacts/`](../../deploy/test/loadtest-artifacts/) —
  long-term archive of captured k6 results.
