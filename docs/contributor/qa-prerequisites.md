# QA Prerequisites

> Last reviewed: 2026-05-05

Operational prereqs for running release QA against certctl. Before any of the contributor-facing testing surfaces (test-environment.md, gui-qa-checklist.md, release-sign-off.md) are useful, the local stack needs to be in a known-good state.

## Why manual QA on top of automated tests?

Automated tests mock dependencies and run in isolation. Manual QA validates the full integrated stack: real PostgreSQL, real HTTP, real agent binary, real file I/O, real scheduler timing. It catches issues that unit tests can't: migration ordering, Docker networking, env var parsing, browser rendering, and timing-dependent scheduler behavior.

## Environment setup

**Step 1: Start the full stack.**

```bash
cd deploy && docker compose -f docker-compose.demo.yml up --build -d
```

This builds three containers (postgres, certctl-server, certctl-agent) and runs them on a bridge network. The `--build` flag ensures you're testing the current code, not a stale image. The `demo` overlay seeds the database with realistic fixtures.

**Step 2: Wait for healthy state.**

```bash
for i in $(seq 1 30); do
  STATUS=$(docker compose ps --format json 2>/dev/null | jq -r 'select(.Health != null) | "\(.Name): \(.Health)"' 2>/dev/null)
  echo "$STATUS"
  echo "$STATUS" | grep -q "unhealthy\|starting" || break
  sleep 2
done
```

Why: Docker Compose starts containers in dependency order (postgres → server → agent), but "started" doesn't mean "ready." Health checks confirm postgres accepts connections, the server responds on `/health`, and the agent process is running.

**Step 3: Set shell variables used throughout the QA flow.**

```bash
export SERVER=https://localhost:8443
export API_KEY="change-me-in-production"
export AUTH="Authorization: Bearer $API_KEY"
export CT="Content-Type: application/json"
export CACERT="--cacert ./deploy/test/certs/ca.crt"
```

Every curl command in QA docs uses these variables. Setting them once avoids typos and keeps the docs copy-pasteable.

> **Note:** The default Docker Compose sets `CERTCTL_AUTH_TYPE: none` for the demo overlay, meaning auth is disabled. Tests that exercise auth require flipping this to `api-key`; instructions are in the relevant test docs.

**Step 4: Build CLI and MCP server binaries on the host.**

```bash
go build -o certctl-cli ./cmd/cli/...
go build -o certctl-mcp ./cmd/mcp-server/...
```

The CLI and MCP server are separate binaries that talk to the server over HTTP. Building them verifies the code compiles and produces the executables you'll test later.

## Demo data baseline

The seed data (`migrations/seed.sql` + `migrations/seed_demo.sql`) pre-populates the database with realistic fixtures. Confirm it loaded:

```bash
curl -s $CACERT -H "$AUTH" $SERVER/api/v1/stats/summary | jq .
```

**Expected shape:**

```json
{
  "total_certificates": 15,
  "active_certificates": ...,
  "expiring_certificates": ...,
  "expired_certificates": ...,
  "pending_renewals": ...
}
```

**Reference IDs in the demo data** (used across QA docs):

| Resource | IDs | Count |
|---|---|---|
| Teams | `t-platform`, `t-security`, `t-payments`, `t-frontend`, `t-data` | 5 |
| Owners | `o-alice`, `o-bob`, `o-carol`, `o-dave`, `o-eve` | 5 |
| Policies | `rp-standard`, `rp-urgent`, `rp-manual` | 3 |
| Issuers | `iss-local`, `iss-acme-le`, `iss-stepca`, `iss-digicert` | 4 |
| Agents | `ag-web-prod`, `ag-web-staging`, `ag-lb-prod`, `ag-iis-prod`, `ag-data-prod` | 5 |
| Targets | `tgt-nginx-prod`, `tgt-nginx-staging`, `tgt-f5-prod`, `tgt-iis-prod`, `tgt-nginx-data` | 5 |
| Profiles | `prof-standard-tls`, `prof-internal-mtls`, `prof-short-lived`, `prof-high-security` | 4 |
| Certificates | `mc-api-prod`, `mc-web-prod`, `mc-pay-prod`, etc. | 15 |
| Agent Groups | `ag-linux-prod`, `ag-linux-amd64`, `ag-windows`, `ag-datacenter-a`, `ag-manual` | 5 |
| Network Scan Targets | `nst-dc1-web`, `nst-dc2-apps`, `nst-dmz` | 3 |

## Once these are green

Move to the appropriate downstream surface:

- [`test-environment.md`](test-environment.md) — full local environment tutorial with real CAs (Pebble, step-ca, etc.)
- [`gui-qa-checklist.md`](gui-qa-checklist.md) — manual GUI test pass
- [`release-sign-off.md`](release-sign-off.md) — release-day checklist
- [`testing-strategy.md`](testing-strategy.md) — what we test in CI vs daily deep-scan vs manual QA
