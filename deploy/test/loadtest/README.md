# certctl Load-Test Harness

Closes the **#8 acquisition-readiness blocker** from the 2026-05-01 issuer
coverage audit (`cowork/issuer-coverage-audit-2026-05-01/RESULTS.md`).
Pre-fix, certctl had zero benchmarks or load tests for any API path; an
acquirer evaluating "can certctl handle our 50k-cert fleet at 47-day
rotation" had nothing to point at. This harness is the substantiation.

## What it measures

A k6 driver hits two scenarios in parallel for 5 minutes at a fixed 50 req/s:

1. **`POST /api/v1/certificates`** — the issuance-acceptance hot path.
   Exercises auth, JSON decode, validation, `service.CreateCertificate`,
   and the `managed_certificates` insert. This is the operator-facing
   request-acceptance throughput an automation client (Terraform,
   Crossplane, GitOps controller) would generate.
2. **`GET /api/v1/certificates?per_page=50`** — the most-trafficked read
   endpoint. Exercises pagination + filtering on the cert list query.

Latency is reported as `avg / min / med / p95 / p99 / max`. The error
floor is < 1% (any 4xx/5xx counts as failed).

## What it explicitly does NOT measure

- **Issuer connector latency.** Connector calls (DigiCert, ACME, Vault,
  AWS ACM PCA, etc.) happen asynchronously via the renewal scheduler.
  Their latency is pinned by the `certctl_issuance_duration_seconds{issuer_type=...}`
  Prometheus histogram (audit fix #4). Driving them through k6 would
  load-test someone else's API, which is wrong.
- **Full ACME enrollment flow.** The audit prompt mentioned ACME-via-
  pebble; sustained 100/s through a multi-RTT order/challenge/finalize
  flow requires pebble tuning + crypto helpers k6 doesn't ship out of
  the box. Deferred to a follow-up.
- **Bulk-revoke / bulk-renew.** Those are admin endpoints with their
  own throughput characteristics and warrant a separate scenario.
- **Scheduler concurrency under bulk renewal.** That's audit fix #9's
  scope; the harness here measures the API tier, not the scheduler.

## Threshold contract

Any future change that breaches one of these fails the test:

| Scenario | p95 | p99 | Error rate |
|---|---|---|---|
| `issuance_acceptance` | < 2 s | < 5 s | n/a |
| `list_certificates` | < 800 ms | < 2 s | n/a |
| All requests | n/a | n/a | < 1% |

These are the regression guards, not the SLO. The SLO is whatever the
operator chooses based on the baseline below.

## How to run

From the repo root:

```sh
make loadtest
```

This:

1. Builds the certctl image from the repo root `Dockerfile`.
2. Spins up postgres, the tls-init bootstrap, certctl-server (with
   `CERTCTL_DEMO_SEED=true` so the FK rows the script needs exist),
   and the k6 driver.
3. Runs the k6 script for ~5 minutes 5 seconds (5s stagger between
   scenarios + 5m duration).
4. Prints the summary text to stdout.
5. Exits non-zero if any threshold was breached.

The full machine-readable summary lands at
`deploy/test/loadtest/results/summary.json` (gitignored). The
human-readable summary lands at `results/summary.txt`.

To run against a server already booted on the host (skip the compose
spin-up):

```sh
docker run --rm \
  -e CERTCTL_BASE=https://localhost:8443 \
  -e CERTCTL_TOKEN=load-test-token \
  -e K6_INSECURE_SKIP_TLS_VERIFY=true \
  -v "$(pwd)/deploy/test/loadtest/k6.js:/scripts/k6.js:ro" \
  -v "$(pwd)/deploy/test/loadtest/results:/results" \
  --network host \
  grafana/k6:0.54.0 run /scripts/k6.js
```

## Current baseline

The first operator run captures real numbers and commits them into
this section. Pre-baseline this section reads "TBD — operator captures
on first `make loadtest` run." The numbers below are the agreed
minimum-acceptable thresholds, not the captured baseline; once captured,
the baseline goes here as a separate row so future regressions have a
diff target.

| Scenario | p50 | p95 | p99 | Error rate |
|---|---|---|---|---|
| **issuance_acceptance** (threshold) | — | < 2 s | < 5 s | < 1% |
| **issuance_acceptance** (baseline) | TBD | TBD | TBD | TBD |
| **list_certificates** (threshold) | — | < 800 ms | < 2 s | < 1% |
| **list_certificates** (baseline) | TBD | TBD | TBD | TBD |

**Methodology pinned at baseline capture:**
- Hardware: TBD (operator's workstation specs at capture time).
- Postgres: 16-alpine, default config.
- certctl: image built from this repo at the commit referenced below.
- Concurrency: 50 req/s sustained per scenario (100 req/s total).
- Duration: 5 minutes per scenario, 5s stagger.
- Auth: api-key (Bearer token, single key).
- Encryption: `CERTCTL_CONFIG_ENCRYPTION_KEY` set (32+ bytes).

To recapture the baseline after a tuning commit:

```sh
make loadtest
# Inspect deploy/test/loadtest/results/summary.txt for the new numbers.
# Update the table above + the methodology line, commit alongside the
# tuning commit.
```

## Interpreting a regression

If a future PR's `make loadtest` run pushes p99 above the threshold,
the make target exits non-zero and CI fails. The summary.txt prints
which threshold breached. Triage:

1. Look at the per-scenario `http_req_duration` p95 + p99 in
   `summary.json`. If only one scenario regressed, the change is
   localized to that endpoint's hot path.
2. Look at the `iteration_duration` per scenario — if total iteration
   time grew but `http_req_duration` is flat, the latency is in k6
   client setup (rare; suggests something changed in the script).
3. Compare against the committed baseline. If p99 was 800 ms at
   baseline and is now 1.5 s but still under the 5 s threshold, the
   change is below the regression guard but still meaningful — flag
   in the PR description.

The harness deliberately does NOT auto-tune. Tuning is informed by the
data; tuning commits land separately, each with their own captured
baseline update.

## CI cadence

Defined in `.github/workflows/loadtest.yml`:

- **`workflow_dispatch`** — manual trigger from the Actions tab. Used
  before tagging a release or after a meaningful tuning commit.
- **Weekly cron** — Mondays at 06:00 UTC. Catches gradual regressions
  from cumulative changes that no single PR triggered.

The workflow does **not** run per-push. Load tests are minutes long
and would not provide useful per-PR signal; per-push pressure goes
through `make verify` (which is fast) and the deploy-vendor-e2e job.

## Files in this directory

```
deploy/test/loadtest/
├── README.md         (this file)
├── docker-compose.yml
├── k6.js             (the load script)
├── certs/            (gitignored — tls-init writes here)
└── results/          (gitignored — k6 writes summary.{json,txt} here)
```

## Audit reference

`cowork/issuer-coverage-audit-2026-05-01/RESULTS.md` Top-10 fix #8.
