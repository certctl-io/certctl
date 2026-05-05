# Async-CA Polling — Operator Reference

> Last reviewed: 2026-05-05

Closes audit fix #5 from the 2026-05-01 issuer-coverage acquisition-readiness audit.

## What this is

Four issuer connectors talk to Certificate Authorities that issue
certificates **asynchronously** — `IssueCertificate` returns an order
ID immediately, and the caller (or scheduler) must call
`GetOrderStatus` later to retrieve the issued cert:

- **DigiCert** (CertCentral)
- **Sectigo** (Certificate Manager)
- **Entrust** (Certificate Services / CA Gateway)
- **GlobalSign** (Atlas HVCA)

Pre-fix, each connector's `GetOrderStatus` made one HTTP call per
invocation with no exponential backoff, no retry cap, and no deadline.
Under a renewal sweep, certctl would hammer the upstream CA's
rate-limit budget. A 429 response was treated as a hard error,
which then caused the scheduler to retry on the next tick — re-fanning
out the same call that just got rate-limited.

Post-fix, `GetOrderStatus` blocks for up to `PollMaxWait` (default
10 minutes) doing **bounded internal polling**:

```
attempt 1 → wait 5s  → attempt 2 → wait 15s → attempt 3 → wait 45s →
attempt 4 → wait 2m  → attempt 5 → wait 5m  → ... (capped at 5m)
```

±20% jitter applied at every wait so multiple certctl instances
never synchronize on the upstream CA's rate-limit window. The
`PollMaxWait` deadline is a hard cap; if the upstream still hasn't
completed by then, `GetOrderStatus` returns `StillPending` and the
scheduler can re-enqueue the job for a future tick.

## Status-code triage

Each connector classifies HTTP responses to drive polling decisions:

| Response | Meaning | Decision |
|---|---|---|
| 2xx + status="issued"/"completed" | Cert ready | Done — return the cert |
| 2xx + status="pending"/"processing" | Still working | StillPending — keep polling |
| 2xx + status="rejected"/"denied"/"failed" | Permanent | Done — return `OrderStatus{Status:"failed"}` |
| 2xx + parse failure | Body is broken | Failed — return error |
| 4xx (404/400/401/403) | Permanent client error | Failed — return error |
| 429 (rate limited) | Transient | StillPending — keep polling with backoff |
| 5xx | Transient | StillPending — keep polling with backoff |
| Network / TLS error | Transient | StillPending — keep polling with backoff |

## Operator tuning

Each connector exposes a `PollMaxWaitSeconds` config field and
matching env var:

| Connector | Env var | Default |
|---|---|---|
| DigiCert | `CERTCTL_DIGICERT_POLL_MAX_WAIT_SECONDS` | 600 (10m) |
| Sectigo | `CERTCTL_SECTIGO_POLL_MAX_WAIT_SECONDS` | 600 (10m) |
| Entrust | `CERTCTL_ENTRUST_POLL_MAX_WAIT_SECONDS` | 600 (10m) |
| GlobalSign | `CERTCTL_GLOBALSIGN_POLL_MAX_WAIT_SECONDS` | 600 (10m) |

Tune up (e.g., `86400` = 24 hours) for **Entrust approval-pending
workflows** where humans manually approve enrollments. Tune down (e.g.,
`60`) for high-throughput environments that prefer to recycle the
scheduler tick rather than block one renewal goroutine for minutes.

A value of 0 (or unset) falls back to the package default in
`internal/connector/issuer/asyncpoll`.

## Failure modes

**Upstream returns 429 forever.** The Poller respects the backoff
(5s → 15s → 45s → 2m → 5m), so a sustained 429 stream burns through
the full `PollMaxWait` budget with at most 7-8 attempts (instead of
~600 attempts at 1/sec). After `PollMaxWait` expires, `GetOrderStatus`
returns `StillPending`; the scheduler re-enqueues for the next tick.
The total request volume against the upstream is bounded by `tick
interval / minimum backoff` — typically 1-2 requests per minute even
under heavy load.

**Sectigo `collectNotReady` sentinel.** When the SCM status endpoint
reports `Issued` but the cert collect endpoint isn't yet ready, the
old code branched into a special "pending" return. Now that branch
returns `StillPending` from the poll closure, so the cert collection
rides the same backoff schedule.

**Entrust approval-pending.** The `AWAITING_APPROVAL` status maps to
`StillPending`. With the default `PollMaxWait=10m`, the scheduler
will re-enqueue once per tick if approval hasn't happened yet; with
`PollMaxWait=24h` the same renewal goroutine waits the full approval
window. Pick the latter when you have many approval-pending
enrollments per tick.

## Where the implementation lives

- `internal/connector/issuer/asyncpoll/asyncpoll.go` — shared `Poller`
  with backoff math, jitter, deadline, and ctx-aware cancellation.
- `internal/connector/issuer/digicert/digicert.go` —
  `pollOrderOnce` + `GetOrderStatus` orchestrator.
- `internal/connector/issuer/sectigo/sectigo.go` —
  `pollEnrollmentOnce` + status-code permanence triage
  (`isPermanentStatusError`).
- `internal/connector/issuer/entrust/entrust.go` —
  `pollEnrollmentOnce` + approval-pending mapping.
- `internal/connector/issuer/globalsign/globalsign.go` —
  `pollCertificateOnce` (serial-number tracking).
- `internal/connector/issuer/asyncpoll/asyncpoll_test.go` — 11 unit
  tests covering happy path, transient-then-success, Failed
  termination, MaxWait timeout, last-error wrap, ctx cancel,
  multiplicative backoff, jitter bounds, defaults.

## Audit blocker reference

the 2026-05-01 issuer coverage audit, Top-10 fix #5
(Part 1.5 finding #4: "No polling backoff for async CAs").
