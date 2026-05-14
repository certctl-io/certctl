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

## Rate-limit behavior — configurable backend (memory or postgres)

The sliding-window-log rate limiters used across certctl's
authenticated-but-shared-credential code paths (break-glass login,
OCSP per-IP, cert-export per-actor, EST per-principal, EST
failed-basic source-IP) carry a **configurable backend**. The
operator picks between two implementations via
`CERTCTL_RATE_LIMIT_BACKEND`:

| Value      | When to use                                          |
|------------|------------------------------------------------------|
| `memory`   | Default. Single-replica deploys; sketchpad / dev.    |
| `postgres` | HA deploys (`server.replicas > 1`). Cross-replica-consistent. |

Phase 13 Sprint 13.2/13.3 (architecture diligence audit ARCH-M1
closure) replaced the prior single-process limitation with a
substantive close: when the operator opts into `postgres`, all
replicas share the same
`rate_limit_buckets` table (migration 000046) and per-key access is
arbitrated via `SELECT FOR UPDATE` row locks. A 3-replica cluster
hitting one rate-limited endpoint concurrently sees exactly the
configured cap succeed across the cluster — not 3× the cap as the
old per-process backend would have allowed.

### Operator decision tree

```
Single replica (server.replicas = 1, the helm chart default)?
  └─ Use CERTCTL_RATE_LIMIT_BACKEND=memory (the default; no action
     required). Bucket lookups stay in-process; zero DB round-trips
     on the hot path.

Two or more replicas?
  └─ Use CERTCTL_RATE_LIMIT_BACKEND=postgres. Two extra DB round-trips
     per Allow call (BEGIN ... SELECT FOR UPDATE ... UPDATE ... COMMIT);
     acceptable on the gated hot path. The Sprint 13.2 multi-replica
     integration test pins exactly-cap enforcement across N replicas
     as the closure proof.
```

### Inventory

| Limiter                                              | Scope                | Window | Cap                            |
|---|---|---|---|
| Break-glass login (per source-IP)                    | `internal/api/handler/auth_breakglass.go` | 60s   | 5 attempts                     |
| OCSP query (per source-IP)                           | `internal/api/handler/certificates.go`    | 60s   | configurable (`CERTCTL_OCSP_RATE_LIMIT_PER_IP_MIN`) |
| Cert export (per actor)                              | `internal/api/handler/export.go`          | 1h    | configurable (`CERTCTL_CERT_EXPORT_RATE_LIMIT_PER_ACTOR_HR`) |
| EST per-principal CSR enrollment                     | `internal/api/handler/est.go`             | 24h   | configurable (per-profile `RateLimitPerPrincipal24h`) |
| EST HTTP-Basic source-IP failed-auth                 | `internal/api/handler/est.go`             | 60m   | 10 attempts                    |
| SCEP/Intune per-device challenge                     | `internal/scep/intune/`                   | 60s   | configurable (`*_PER_MINUTE`)  |
| ACME per-account orders / key-change / challenge-respond | `internal/service/acme.go`            | 1h    | configurable                   |

The `CERTCTL_RATE_LIMIT_BACKEND` selector applies to the first five
(the cmd/server-wired limiters). The SCEP/Intune wrapper + the ACME
per-account limiter ride their own internal accounting today; both
are tracked as follow-ups in WORKSPACE-ROADMAP.md.

### Backend internals

Both backends share the algorithm: sliding-window log + per-key
bucket + prune-on-Allow.

**Memory backend (`memory`)** — per-process map keyed by bucket key;
mutex-guarded; package-level LRU cap prevents unbounded growth under
adversarial key cardinality (default 100,000 keys per limiter
instance; oldest-by-newest-timestamp evicted under pressure).
Implemented at `internal/ratelimit/sliding_window.go`.

**Postgres backend (`postgres`)** — same algorithm against the
`rate_limit_buckets` table:

```sql
CREATE TABLE rate_limit_buckets (
    bucket_key TEXT          PRIMARY KEY,
    timestamps TIMESTAMPTZ[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
```

`Allow(key, now)` opens a transaction, ensures the row exists
(`INSERT ... ON CONFLICT DO NOTHING`), acquires the row lock
(`SELECT ... FOR UPDATE`), prunes timestamps older than `now-window`,
compares the post-prune count against `maxN`, conditionally appends
`now`, persists, and commits. The row lock is what arbitrates across
replicas: replicas A and B firing simultaneous `Allow("k")` never
race because Postgres serializes the per-key row update across the
cluster. Implemented at
`internal/ratelimit/postgres_sliding_window.go`.

### Janitor sweep (postgres backend only)

The scheduler runs a `rate_limit_buckets` janitor every
`CERTCTL_RATE_LIMIT_JANITOR_INTERVAL` (default 5m, minimum 1m). The
sweep deletes rows whose `updated_at` is older than the longest
configured window any limiter uses (24h today, matching the EST
per-principal limiter). Idempotent; repeated sweeps find zero rows.
The memory backend's prune-on-Allow path keeps buckets short-lived
without a separate sweep, so the loop is a no-op when
`backend=memory`.

### Falsifiable closure proof

The Phase 13 Sprint 13.2 integration test
`internal/integration/ratelimit_multi_replica_test.go`
(`//go:build integration`) fires 100 concurrent `Allow("test-key")`
calls round-robined across 3 independent `PostgresSlidingWindowLimiter`
instances sharing one Postgres database (`cap=10`, `window=1m`) and
asserts exactly 10 succeed + 90 return `ErrRateLimited`. If the
cross-replica row lock weren't arbitrating, each replica would
independently let through ~3-4 requests, giving 12-15 successes
total. Re-run:

```
go test -tags=integration -count=1 -run TestRateLimit_MultiReplica \
    ./internal/integration/...
```

### Helm chart wiring

The helm chart at `deploy/helm/certctl/` exposes the backend via
`server.rateLimiting.backend` (default `memory`). To opt into the
postgres backend for an HA deploy:

```
helm upgrade --install certctl deploy/helm/certctl \
    --set server.replicas=3 \
    --set server.rateLimiting.backend=postgres \
    --set server.rateLimiting.janitorInterval=5m
```

`server.replicas > 1` without flipping `backend` to `postgres` works
fine — the limits stay per-process — but the operator gets a 2× /
3× / Nx effective cap depending on replica count. The chart does NOT
auto-flip on `replicas > 1` because some HA deploys deliberately want
per-process limits (sticky-session ingress + tight per-replica caps
to detect bot traffic at the edge before it hits the application).

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
