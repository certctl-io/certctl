# Observability — what certctl emits, what it doesn't, and what survives a restart

> Last reviewed: 2026-05-13

Use this when:
- You're sizing certctl's observability surface against your existing
  metrics + tracing + logging stack and want to know exactly what
  drops in cleanly and what gaps you'll need to bridge.
- You're investigating a "weird metric" or planning a Grafana
  dashboard and need the canonical list of what's exposed.
- You're running multi-replica or restarting frequently and need to
  understand which counters reset.

certctl's observability posture is deliberately minimal-but-honest:
ship the surfaces an operator actually needs to wire into a Prometheus
+ Grafana + Loki stack, and don't make claims the implementation
can't back. This document is the canonical statement of what's
emitted, what's deferred, and why.

## Metrics — what's emitted

certctl exposes metrics through two endpoints on the control plane:

| Endpoint                          | Content-Type                                                      | Audience                         |
|---|---|---|
| `GET /api/v1/metrics`             | `application/json`                                                | Dashboards that prefer JSON, ad-hoc curl |
| `GET /api/v1/metrics/prometheus`  | `text/plain; version=0.0.4; charset=utf-8` (Prometheus exposition) | Prometheus, Grafana Agent, Datadog Agent, Victoria Metrics, any OpenMetrics-compatible scraper |

The Prometheus endpoint emits standard `# HELP` / `# TYPE` / metric
lines following the conventions at
[prometheus.io/docs/instrumenting/exposition_formats](https://prometheus.io/docs/instrumenting/exposition_formats/).
Metric names are lowercase, snake_case, and prefixed with `certctl_`.

The implementation is at
[`internal/api/handler/metrics.go`](../../internal/api/handler/metrics.go).

### What's covered

Run the endpoint against a live deployment for the authoritative list
(it expands as the service ships more metrics). At time of writing the
exposition includes:

- Certificate-inventory gauges: `certctl_certificate_total`,
  `certctl_certificate_active`, `certctl_certificate_expiring_soon`,
  `certctl_certificate_expired`, `certctl_certificate_revoked`.
- Per-issuer-type issuance histograms:
  `certctl_issuance_duration_seconds{issuer_type=…}` (the 2026-05-01
  issuer-coverage audit closure #4 — this is the load-bearing metric
  for per-issuer SLOs).
- Server uptime: `certctl_uptime_seconds`.

### Prometheus library vs hand-rolled exposition (acquisition diligence)

certctl writes Prometheus exposition format with `fmt.Fprintf` from
the metrics handler, not via the `github.com/prometheus/client_golang`
library. This is intentional for v2.x:

- The metric surface is shallow (gauges + a handful of histograms with
  static labels). The client library's value is on the registration +
  thread-safe accumulation side, neither of which is load-bearing for
  the current surface.
- The exposition output is pinned to the spec version explicitly
  (`version=0.0.4`) and is unit-tested against expected output at
  `internal/api/handler/stats_handler_test.go`.
- Swapping in `client_golang` is a mechanical migration when the
  metric surface grows (per-connector counters + RED-method histograms
  on every handler are the natural next surface), but it has no
  operator-visible behavior change today.

The migration is on the
[WORKSPACE-ROADMAP.md](../../WORKSPACE-ROADMAP.md) as a v3 item. If
you're an acquirer reading this: the question to ask is "does the
metric surface meet our SLO needs today" — not "is the right library
under the hood." If the answer to the first question is yes, the
second is a refactor, not a feature gap.

## Tracing — explicitly not yet shipped

certctl does **not** ship distributed tracing instrumentation today:

- No OpenTelemetry SDK setup in `cmd/server/main.go`.
- No OTLP exporter wired into outbound calls (issuer connectors,
  agent enrollment, etc.).
- The `go.opentelemetry.io/otel` packages that appear in
  [`go.mod`](../../go.mod) are indirect-only — they're transitive
  dependencies of `coreos/go-oidc` and similar.

This is honest: there is no in-process tracing surface to monitor,
correlate, or sample. If your environment requires end-to-end traces
across the certctl control plane + agents + issuer backends, this is
a gap you would close on the certctl side as part of a v3 work item.
Until then:

- Structured logs include a `request_id` you can correlate across
  the server log stream. See
  [`internal/api/middleware/request_id.go`](../../internal/api/middleware/request_id.go).
- The Prometheus histogram
  `certctl_issuance_duration_seconds{issuer_type=…}` carries the
  same per-issuer latency signal a trace span would, just without
  the per-request fan-out.

OpenTelemetry instrumentation is tracked in
[WORKSPACE-ROADMAP.md](../../WORKSPACE-ROADMAP.md) as a v3 item.

## Logging

certctl emits structured JSON logs to stdout via the stdlib
`log/slog` package. Every line carries `time`, `level`, `msg`, and —
where relevant — `request_id`, `actor_id`, and a contextual subject
(`certificate_id`, `issuer_id`, `agent_id`, etc.).

Log level is controlled by `CERTCTL_LOG_LEVEL` (`debug` / `info` /
`warn` / `error`); defaults to `info`. There is no in-process log
ingest — operators are expected to collect from container stdout
into their existing log pipeline (Loki, CloudWatch Logs, Datadog,
ELK, Splunk, etc.).

No log line contains private-key material, bearer tokens, OIDC
client secrets, or session cookies. The break-glass login path
explicitly scrubs the password before it reaches the audit subsystem
(see [`docs/operator/auth-threat-model.md`](auth-threat-model.md) §
"Break-glass token leak").

## Rate-limit behavior under restarts and replicas

Where rate limits exist, they are **per-process, in-memory,
reset-on-restart, and not shared across replicas**. This matters for
multi-replica deployments and for any compliance posture that asks
"what limits apply globally vs per-pod."

### Inventory

| Limiter                                              | Scope                | Window | Cap                            | Survives restart? | Shared across replicas? |
|---|---|---|---|---|---|
| Break-glass login (per source-IP)                    | `internal/api/handler/auth_breakglass.go` | 60s   | 5 attempts                     | No                | No                      |
| SCEP/Intune per-device challenge                     | `internal/scep/intune/`                   | 60s   | configurable (`*_PER_MINUTE`)  | No                | No                      |
| EST per-principal CSR enrollment                     | `internal/est/`                           | 60s   | configurable                   | No                | No                      |
| EST HTTP-Basic source-IP failed-auth                 | `internal/est/`                           | 60s   | configurable                   | No                | No                      |
| ACME per-account orders / key-change / challenge-respond | `internal/service/acme.go`            | 1h    | configurable                   | No                | No                      |

All five use the shared `internal/ratelimit/sliding_window.go`
primitive. Buckets live in a single per-process map guarded by a
mutex; the package-level cap prevents unbounded growth under
adversarial key cardinality (default 100,000 keys; oldest-by-newest-
timestamp evicted under pressure).

### Implications for multi-replica deployments

- **Effective per-replica cap is the documented cap.** A 2-replica
  deployment lets through up to 2× the per-key window cap before
  either replica rejects.
- **Restart resets the bucket.** A `kubectl rollout restart` empties
  the in-memory windows on every replica. An attacker who notices
  this could in principle re-issue burst attempts after every roll;
  the threat model accepts this because rollouts are operator-driven
  and the relevant endpoints already require credentials.
- **No cross-replica fan-out.** Rate-limit decisions on replica A
  are not visible to replica B. Sticky-session ingress routing (with
  `service.spec.sessionAffinity: ClientIP` on Kubernetes or the
  equivalent on your load balancer) tightens the effective cap to
  per-replica + per-source-IP rather than per-replica + per-source-IP
  for whichever pod the request happened to land on.

If your threat model requires globally-enforced rate limits across
replicas, the implementation surface is roughly: swap the per-process
map for a database-backed sliding window (or a Redis-backed equivalent
if you already run Redis). This is on the
[WORKSPACE-ROADMAP.md](../../WORKSPACE-ROADMAP.md) as a v3 item;
nothing in the certctl threat model today requires it.

### Where these numbers live

The configurable caps are exposed as `CERTCTL_*_PER_MINUTE` /
`CERTCTL_ACME_*_PER_HOUR` env vars — see the
[security posture](security.md) doc for the operator-facing
configuration surface. The hard-coded ones (break-glass 5/min) are
intentionally non-configurable as a defense-in-depth measure; the
auth subsystem owns that policy decision.

## Performance harness scope

The load-test harness at [`deploy/test/loadtest/`](../../deploy/test/loadtest/)
covers the API-tier hot paths (issuance acceptance + cert list). It
does NOT load-test issuer-connector round-trips (you'd be load-
testing someone else's API), full multi-RTT ACME enrollment flows,
bulk-revoke / bulk-renew admin paths, or scheduler concurrency under
bulk renewal. Each exclusion is justified in
[`deploy/test/loadtest/README.md`](../../deploy/test/loadtest/README.md)
under "What it explicitly does NOT measure." If your evaluation
requires a benchmark on one of those exclusions, the right next step
is a follow-up scenario in that directory.

The per-component benchmarks ship in-tree as Go `Benchmark*`
functions:
- `internal/auth/session/bench_test.go` — session signing + validation
  steady state and cold-process timing.
- `internal/auth/oidc/bench_test.go` — OIDC verify steady state.
- `internal/auth/oidc/bench_keycloak_test.go` — OIDC cold-cache timing
  (gated `//go:build integration`).

Authoritative benchmark numbers + threshold contracts:
[`docs/operator/auth-benchmarks.md`](auth-benchmarks.md) (auth
subsystem) and [`docs/operator/performance-baselines.md`](performance-baselines.md)
(general API tier).

## Related reading

- [`docs/operator/security.md`](security.md) — the broader hardening
  posture; this document is its observability subset.
- [`docs/operator/performance-baselines.md`](performance-baselines.md) — operator-runnable benchmarks against the API tier
- [`docs/operator/auth-benchmarks.md`](auth-benchmarks.md) — session
  + OIDC validation timings + threshold contracts
- [`deploy/test/loadtest/README.md`](../../deploy/test/loadtest/README.md) — k6 load-test harness scope + threshold contract
- [`docs/operator/runbooks/postgres-backup.md`](runbooks/postgres-backup.md) — operator-run backup recipe (separate file because it's a procedural runbook, not an observability claim)
