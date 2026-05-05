# Configuration Reference

> Last reviewed: 2026-05-05

Compact reference for `CERTCTL_*` environment variables consumed by
`certctl-server` and `certctl-agent`. Most operators don't need to
touch these — defaults are tuned for the common case. Reach for them
when the system's behaviour needs tuning beyond what's exposed in the
GUI / API.

This page enumerates the operator-tunable knobs that don't have a
dedicated home elsewhere. Connector-specific env vars are documented
on the per-connector pages under
[`docs/reference/connectors/`](connectors/index.md). Protocol env
vars (ACME server, EST, SCEP) are documented under
[`docs/reference/protocols/`](protocols/). TLS env vars are
documented in [`docs/operator/tls.md`](../operator/tls.md).

## Scheduler intervals

The scheduler runs N background loops; intervals are tunable for
performance / contention tuning.

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL` | `2m` | How often the agent-health loop scans for stale heartbeats and transitions agents to `Unhealthy` / `Offline`. |
| `CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL` | `30s` | How often the job-processor loop dispatches `Pending` jobs to agents. |
| `CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL` | `1m` | How often the notification-dispatcher loop fans out queued alerts to channels. |
| `CERTCTL_SHORT_LIVED_EXPIRY_CHECK_INTERVAL` | `5m` | How often the short-lived-expiry loop watches certs whose TTL is less than 1h for imminent expiry. |

For the full scheduler topology (12 loops, 8 always-on + 4 opt-in)
see [`architecture.md`](architecture.md) "Scheduler topology".

## Job lifecycle

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_JOB_AWAITING_CSR_TIMEOUT` | `24h` | How long a job stays in `AwaitingCSR` before the scheduler marks it `Failed` (the agent never picked it up). |

## Rate limiting

The control plane API is rate-limited by default; tune for
high-volume environments (mass-rotation events, bulk imports).

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_RATE_LIMIT_ENABLED` | `true` | Master toggle. Disable only for trusted-network single-tenant deploys where the API is firewall-protected. |
| `CERTCTL_RATE_LIMIT_PER_USER_RPS` | `0` (= use global default) | Per-user requests-per-second cap. Zero opts each user into the global default in `internal/api/middleware`. |
| `CERTCTL_RATE_LIMIT_PER_USER_BURST` | `0` (= use global default) | Per-user token-bucket burst size. Same opt-in semantics. |

## Audit trail

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_AUDIT_FLUSH_TIMEOUT_SECONDS` | `30` | How long the audit-event flush worker waits for the buffered batch to drain before forcing a flush at shutdown. |

## Deploy verification

The deploy-hardening primitive wraps every cert deploy in
atomic-write + post-verify + rollback. These env vars tune the
post-deploy TLS verification phase.

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_VERIFY_DEPLOYMENT` | `true` | Master toggle for post-deploy TLS verify. Disable only for connectors / environments where the verify endpoint is not reachable from the agent. |
| `CERTCTL_VERIFY_DELAY` | `2s` | How long to wait after the reload command completes before the first verify-handshake attempt (gives the daemon time to pick up new keys). |
| `CERTCTL_VERIFY_TIMEOUT` | `10s` | Per-attempt TLS-handshake timeout. |
| `CERTCTL_DEPLOY_BACKUP_RETENTION` | `3` | How many `.certctl-bak.<unix-nanos>.<ext>` rollback snapshots to keep per target after a successful deploy. `0` uses the default of 3; `-1` opts out of pruning entirely. |

For the full deploy contract see
[`deployment-model.md`](deployment-model.md).

## Database

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_DATABASE_MIGRATIONS_PATH` | `./migrations` | Filesystem path to the `*.up.sql` / `*.down.sql` migration set. Override only when running `certctl-server` from a non-standard layout. |

## Agent

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_AGENT_ID` | (none — required) | The agent's unique ID, issued by `POST /api/v1/agents/register` and bundled into the agent's registration response. Pass via this env var when the agent runs as a systemd unit / container without the `-agent-id` CLI flag. |

## SCEP profile binding (single-profile back-compat)

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_SCEP_PROFILE_ID` | (empty) | Optional certificate profile ID for the legacy single-profile SCEP path. The multi-profile path uses `CERTCTL_SCEP_PROFILES=<list>` + `CERTCTL_SCEP_PROFILE_<NAME>_PROFILE_ID` instead — see [`scep-server.md`](protocols/scep-server.md). |

## Related references

- [`architecture.md`](architecture.md) — scheduler topology, system design, security model
- [`deployment-model.md`](deployment-model.md) — atomic write + verify + rollback contract
- [`operator/security.md`](../operator/security.md) — full security posture (auth, rate limits, encryption at rest)
- [`operator/tls.md`](../operator/tls.md) — control-plane TLS env vars
- Per-connector pages under [`reference/connectors/`](connectors/index.md) for connector-specific config
- Per-protocol pages under [`reference/protocols/`](protocols/) for ACME / SCEP / EST / CRL+OCSP / async-CA polling
