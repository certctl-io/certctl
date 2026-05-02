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

## Connector-tier baseline (Bundle 10 of the 2026-05-02 deployment-target audit)

Bundle 10 extended the harness to cover per-target-type handshake throughput
in addition to the API-tier issuance/list throughput documented above. The
docker-compose stack now boots four target sidecars (nginx, apache, haproxy,
f5-mock) each serving a starter cert from a shared `target-tls-init`
container, and k6 runs four additional scenarios — `nginx_handshake`,
`apache_handshake`, `haproxy_handshake`, `f5_handshake` — at sustained
100 conns/min for 5 minutes against each.

### What the connector tier measures

End-to-end TCP connect + TLS handshake + tiny HTTP request/response latency
per target type, tagged via the k6 `target_type` label so summary.json's
`connector_tier` section breaks the numbers out per sidecar:

```json
{
  "connector_tier": {
    "nginx":   { "p50": ..., "p95": ..., "p99": ..., "error_rate": ..., "iterations": ... },
    "apache":  { ... },
    "haproxy": { ... },
    "f5":      { ... }
  }
}
```

This validates the target sidecar daemons are operational under sustained
connection load. Procurement asks "can certctl's nginx target handle 5,000
endpoints at 47-day rotation?" — the connector code's correctness is pinned
by per-connector unit tests; **the underlying daemon's connection-rate
ceiling is what these scenarios pin**.

### What the connector tier explicitly does NOT measure (v1)

- **The full agent-driven deploy hot path.** v1 measures handshake
  throughput against the sidecars directly. v2 of the harness is a
  follow-up that POSTs cert requests bound to per-target-type targets,
  polls the deployments endpoint until the agent reports complete, and
  measures the full POST → poll → cert-served loop. v2 needs the agent
  registration + target-binding API surface plumbed end-to-end in the
  loadtest stack — meaningful work, but not a blocker for the connection-
  rate procurement question.
- **Kubernetes connector.** kind-in-docker requires `privileged: true`
  and is operationally fragile in CI. Deferred until Bundle 2 (real
  `k8s.io/client-go`) lands and a CI-friendly envtest harness is wired.
- **Real F5 BIG-IP.** The harness uses the in-tree `f5-mock-icontrol`
  Go server (already used by the deploy-vendor-e2e CI job). Real F5
  appliance benchmarking is out of scope; operators with a real F5
  vagrant box per `docs/connector-f5.md` can substitute it manually.

### Threshold contract

Defined in `k6.js`'s `thresholds` block. Any change pushing past these
fails the test:

| Target type | p95 | p99 | Error rate |
|---|---|---|---|
| `nginx`   | < 1 s   | < 3 s | < 1% (global) |
| `apache`  | < 1 s   | < 3 s | < 1% (global) |
| `haproxy` | < 1 s   | < 3 s | < 1% (global) |
| `f5`      | < 1.5 s | < 5 s | < 1% (global) |

f5-mock's threshold is looser because the iControl REST handler does
slightly more work per request (login+upload+install dance the F5
connector itself drives — not exercised here, but the daemon's request
handler is heavier).

### Connector-tier captured baseline

| Target type | p50 | p95 | p99 | Error rate | Iterations |
|---|---|---|---|---|---|
| **nginx** (threshold)   | — | < 1 s   | < 3 s | < 1% | n/a |
| **nginx** (baseline)    | TBD | TBD | TBD | TBD | TBD |
| **apache** (threshold)  | — | < 1 s   | < 3 s | < 1% | n/a |
| **apache** (baseline)   | TBD | TBD | TBD | TBD | TBD |
| **haproxy** (threshold) | — | < 1 s   | < 3 s | < 1% | n/a |
| **haproxy** (baseline)  | TBD | TBD | TBD | TBD | TBD |
| **f5** (threshold)      | — | < 1.5 s | < 5 s | < 1% | n/a |
| **f5** (baseline)       | TBD | TBD | TBD | TBD | TBD |

The em-dash placeholders are deliberate: do **not** commit numeric values
without running the loadtest on canonical hardware first. Numbers from a
developer laptop are misleading. The first `gh workflow run loadtest.yml`
on a clean GitHub runner captures the baseline; commit the captured numbers
into the table above as a follow-up commit alongside the methodology line.

**Methodology pinned at baseline capture (canonical hardware):**

- Hardware: GitHub-hosted `ubuntu-latest` runners (currently 4 vCPU /
  16 GiB / SSD-backed). Operator captures from `gh workflow run loadtest.yml`
  to keep the hardware constant across runs.
- Sidecar images: nginx:1.27-alpine, httpd:2.4-alpine, haproxy:2.9-alpine,
  in-tree f5-mock-icontrol (built from `deploy/test/f5-mock-icontrol/`).
- Concurrency: 100 conns/min sustained per target type (400 conns/min
  total across the four target scenarios + 100 req/s on the API tier).
- Duration: 5 minutes per scenario, 10s stagger between API tier and
  connector tier so warmup overlap doesn't skew the first 30 seconds.
- TLS: starter cert from `target-tls-init` (ECDSA P-256, multi-SAN). The
  loadtest scenarios connect with `K6_INSECURE_SKIP_TLS_VERIFY=true`.

To recapture the connector-tier baseline after a tuning commit affecting
target sidecars or the connector code:

```sh
make loadtest
# Inspect deploy/test/loadtest/results/summary.json for the
# connector_tier object and update the table above.
```

## Files in this directory

```
deploy/test/loadtest/
├── README.md         (this file)
├── docker-compose.yml
├── k6.js             (the load script)
├── certs/            (gitignored — tls-init writes here)
├── fixtures/         (Bundle 10: target sidecar configs + shared starter cert)
│   ├── nginx.conf
│   ├── httpd.conf
│   ├── haproxy.cfg
│   └── target-certs/ (gitignored — target-tls-init writes here)
└── results/          (gitignored — k6 writes summary.{json,txt} here)
```

## Audit references

- API tier:       `cowork/issuer-coverage-audit-2026-05-01/RESULTS.md` fix #8.
- Connector tier: `cowork/deployment-target-audit-2026-05-02/RESULTS.md` Bundle 10.
