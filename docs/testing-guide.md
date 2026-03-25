# certctl V2.0 Release QA Guide

Comprehensive manual testing playbook. Every test has a concrete command, an explanation of what it validates and why it matters, exact expected output, and an unambiguous pass/fail criterion. Run every test before tagging v2.0.0.

---

## Prerequisites

### Why manual QA on top of 900+ automated tests?

Automated tests mock dependencies and run in isolation. Manual QA validates the full integrated stack: real PostgreSQL, real HTTP, real agent binary, real file I/O, real scheduler timing. It catches issues that unit tests can't: migration ordering, Docker networking, env var parsing, browser rendering, and timing-dependent scheduler behavior.

### Environment Setup

**Step 1: Start the full stack.**

```bash
cd deploy && docker compose up --build -d
```

This builds three containers (postgres, certctl-server, certctl-agent) and runs them on a bridge network. The `--build` flag ensures you're testing the current code, not a stale image.

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

**Step 3: Set shell variables used throughout this guide.**

```bash
export SERVER=http://localhost:8443
export API_KEY="change-me-in-production"
export AUTH="Authorization: Bearer $API_KEY"
export CT="Content-Type: application/json"
```

Why: Every curl command in this guide uses these variables. Setting them once avoids typos and makes the guide copy-pasteable.

> **Note:** The default Docker Compose sets `CERTCTL_AUTH_TYPE: none`, meaning auth is disabled. Many auth tests in Part 2 require changing this to `api-key`. Instructions are provided in those tests.

**Step 4: Build CLI and MCP server binaries on the host.**

```bash
go build -o certctl-cli ./cmd/cli/...
go build -o certctl-mcp ./cmd/mcp-server/...
```

Why: The CLI and MCP server are separate binaries that talk to the server over HTTP. Building them verifies the code compiles and produces the executables you'll test later.

### Demo Data Baseline

The seed data (`migrations/seed.sql` + `migrations/seed_demo.sql`) pre-populates the database with realistic fixtures. Confirm it loaded:

```bash
curl -s -H "$AUTH" $SERVER/api/v1/stats/summary | jq .
```

**Expected output structure:**
```json
{
  "total_certificates": 15,
  "active_certificates": ...,
  "expiring_certificates": ...,
  "expired_certificates": ...,
  "pending_renewals": ...
}
```

**What's in the demo data (reference these IDs throughout the guide):**

| Resource | IDs | Count |
|----------|-----|-------|
| Teams | `t-platform`, `t-security`, `t-payments`, `t-frontend`, `t-data` | 5 |
| Owners | `o-alice`, `o-bob`, `o-carol`, `o-dave`, `o-eve` | 5 |
| Policies | `rp-standard`, `rp-urgent`, `rp-manual` | 3 |
| Issuers | `iss-local`, `iss-acme-le`, `iss-stepca`, `iss-digicert` | 4 |
| Agents | `ag-web-prod`, `ag-web-staging`, `ag-lb-prod`, `ag-iis-prod`, `ag-data-prod` | 5 |
| Targets | `tgt-nginx-prod`, `tgt-nginx-staging`, `tgt-f5-prod`, `tgt-iis-prod`, `tgt-nginx-data` | 5 |
| Profiles | `prof-standard-tls`, `prof-internal-mtls`, `prof-short-lived`, `prof-high-security` | 4 |
| Certificates | `mc-api-prod`, `mc-web-prod`, `mc-pay-prod`, `mc-dash-prod`, `mc-data-prod`, `mc-auth-prod`, `mc-cdn-prod`, `mc-mail-prod`, `mc-legacy-prod`, `mc-old-api`, `mc-api-stg`, `mc-web-stg`, `mc-grafana-prod`, `mc-vpn-prod`, `mc-wildcard-prod` | 15 |
| Agent Groups | `ag-linux-prod`, `ag-linux-amd64`, `ag-windows`, `ag-datacenter-a`, `ag-manual` | 5 |
| Network Scan Targets | `nst-dc1-web`, `nst-dc2-apps`, `nst-dmz` | 3 |

---

## Part 1: Infrastructure & Deployment

**What this validates:** The Docker Compose stack boots correctly, migrations apply, seed data loads, health checks work, and the system survives restarts.

**Why it matters:** If the deployment doesn't work out of the box, nobody evaluates the product. This is the first thing a new user or customer does.

### 1.1 Container Health

**Test 1.1.1 — PostgreSQL is accepting connections**

```bash
docker compose exec postgres pg_isready -U certctl
```

**What:** Checks if PostgreSQL is accepting connections on its default port.
**Why:** If postgres isn't ready, migrations can't run and the server can't start. This is the root dependency.
**Expected:** `/var/run/postgresql:5432 - accepting connections`
**PASS if** output contains "accepting connections". **FAIL** otherwise.

---

**Test 1.1.2 — Database schema applied (21 tables)**

```bash
docker compose exec postgres psql -U certctl -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';"
```

**What:** Counts tables in the public schema. The 7 migration files create 21 tables: `managed_certificates`, `certificate_versions`, `agents`, `deployment_targets`, `certificate_target_mappings`, `renewal_policies`, `jobs`, `audit_events`, `notification_events`, `issuers`, `policy_rules`, `policy_violations`, `teams`, `owners`, `certificate_profiles`, `agent_groups`, `agent_group_members`, `certificate_revocations`, `discovered_certificates`, `discovery_scans`, `network_scan_targets`.
**Why:** If any migration failed or was skipped, downstream features break silently. Counting tables catches this immediately.
**Expected:** `21`
**PASS if** count = 21. **FAIL** otherwise.

---

**Test 1.1.3 — Server liveness probe**

```bash
curl -s -w "\nHTTP %{http_code}\n" $SERVER/health
```

**What:** The `/health` endpoint returns 200 if the server process is running and the HTTP listener is bound.
**Why:** This is what Docker's health check calls. If it fails, the container restarts in a loop.
**Expected:**
```
{"status":"ok"}
HTTP 200
```
**PASS if** HTTP 200 and body contains `"status":"ok"`. **FAIL** otherwise.

---

**Test 1.1.4 — Server readiness probe**

```bash
curl -s -w "\nHTTP %{http_code}\n" $SERVER/ready
```

**What:** The `/ready` endpoint confirms the server can handle requests — database connection pool is initialized, migrations ran.
**Why:** Liveness ≠ readiness. The server can be alive (process running) but not ready (database unreachable). If `/ready` fails, the server started but can't serve real traffic.
**Expected:**
```
{"status":"ready"}
HTTP 200
```
**PASS if** HTTP 200 and body contains `"status":"ready"`. **FAIL** otherwise.

---

**Test 1.1.5 — Agent container is running**

```bash
docker compose ps certctl-agent --format json | jq -r '.Health'
```

**What:** Checks the agent container's health status (the Docker health check runs `pgrep -f certctl-agent`).
**Why:** The agent is a separate Go binary. If it crashes on startup (bad env vars, unreachable server), it won't register or poll for work.
**Expected:** `healthy`
**PASS if** output is `healthy`. **FAIL** otherwise.

---

**Test 1.1.6 — Demo seed data loaded (all 9 resource types)**

```bash
echo "=== Certificates ===" && curl -s -H "$AUTH" "$SERVER/api/v1/certificates?per_page=1" | jq '.total'
echo "=== Agents ===" && curl -s -H "$AUTH" "$SERVER/api/v1/agents" | jq '.total'
echo "=== Targets ===" && curl -s -H "$AUTH" "$SERVER/api/v1/targets" | jq '.total'
echo "=== Policies ===" && curl -s -H "$AUTH" "$SERVER/api/v1/policies" | jq '.total'
echo "=== Profiles ===" && curl -s -H "$AUTH" "$SERVER/api/v1/profiles" | jq '.total'
echo "=== Teams ===" && curl -s -H "$AUTH" "$SERVER/api/v1/teams" | jq '.total'
echo "=== Owners ===" && curl -s -H "$AUTH" "$SERVER/api/v1/owners" | jq '.total'
echo "=== Agent Groups ===" && curl -s -H "$AUTH" "$SERVER/api/v1/agent-groups" | jq '.total'
echo "=== Issuers ===" && curl -s -H "$AUTH" "$SERVER/api/v1/issuers" | jq '.total'
```

**What:** Queries every resource type and confirms expected counts from seed data.
**Why:** If seed data didn't load, every subsequent test that references demo IDs (like `mc-api-prod`) will 404. Catching this early saves hours of debugging.
**Expected:** Certificates=15, Agents≥5, Targets=5, Policies≥3, Profiles=4, Teams=5, Owners=5, Agent Groups=5, Issuers=4.
**PASS if** all counts match. **FAIL** if any count is lower than expected.

---

### 1.2 Graceful Shutdown & Persistence

**Test 1.2.1 — Server shuts down cleanly on SIGTERM**

```bash
docker compose stop certctl-server
docker compose logs certctl-server 2>&1 | tail -20
```

**What:** Sends SIGTERM to the server process and checks the last few log lines for a clean shutdown message.
**Why:** Ungraceful shutdown can corrupt in-flight database transactions, leave jobs in `Running` state permanently, or cause data loss. The server should finish active requests, close the DB pool, and exit 0.
**Expected:** Log lines showing orderly shutdown (e.g., `"scheduler shutting down"`, `"server stopped"`). No panic stack traces, no goroutine leak warnings.
**PASS if** shutdown logs are present and no panic traces. **FAIL** if panics or unclean exit.

```bash
# Restart for subsequent tests
docker compose start certctl-server && sleep 5
```

---

**Test 1.2.2 — Data persists across full restart**

```bash
docker compose down
docker compose up -d
sleep 15
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?per_page=1" | jq '{total: .total}'
```

**What:** Tears down and recreates all containers, then verifies data survived via the `postgres_data` volume.
**Why:** If the PostgreSQL volume isn't mounted correctly, `docker compose down` destroys all data. This catches volume misconfiguration.
**Expected:** `{"total": 15}` — same as before shutdown.
**PASS if** `total` = 15. **FAIL** if 0 or different count.

---

### 1.3 Environment Variable Overrides

**Test 1.3.1 — Custom port binding**

Edit `deploy/docker-compose.yml`: set `CERTCTL_SERVER_PORT: "9999"` and update the port mapping to `"9999:9999"`. Restart.

```bash
docker compose up -d certctl-server
sleep 5
curl -s -w "HTTP %{http_code}\n" http://localhost:9999/health
```

**What:** Confirms the server reads `CERTCTL_SERVER_PORT` and binds to the specified port.
**Why:** Production deployments often use non-default ports. If env var parsing is broken, the server silently binds to 8080 regardless.
**Expected:** `HTTP 200` on port 9999.
**PASS if** HTTP 200 on port 9999. **FAIL** otherwise. Reset port to 8443 after testing.

---

**Test 1.3.2 — Debug logging**

Edit `deploy/docker-compose.yml`: set `CERTCTL_LOG_LEVEL: "debug"`. Restart.

```bash
docker compose restart certctl-server
sleep 5
docker compose logs certctl-server 2>&1 | grep -c '"level":"DEBUG"'
```

**What:** Counts DEBUG-level log lines in server output after restart.
**Why:** Operators troubleshooting issues need debug logging. If the slog level filter doesn't work, they get no additional output despite setting debug.
**Expected:** Count > 0 (debug lines present).
**PASS if** count > 0. **FAIL** if 0. Reset to `info` after testing.

---

**Test 1.3.3 — Auth disabled with explicit none**

Verify the default Docker Compose has `CERTCTL_AUTH_TYPE: none`:

```bash
curl -s -w "\nHTTP %{http_code}\n" $SERVER/api/v1/certificates?per_page=1
```

**What:** Confirms that with `CERTCTL_AUTH_TYPE=none`, API requests work without an auth header.
**Why:** Demo/development mode must work without auth. If the none mode is broken, new users can't even try the product.
**Expected:** HTTP 200 with certificate data. No 401.
**PASS if** HTTP 200. **FAIL** if 401.

---

**Test 1.3.4 — Auth none produces warning log**

```bash
docker compose logs certctl-server 2>&1 | grep -i "auth.*none\|authentication.*disabled\|no auth"
```

**What:** Checks that the server logs a warning when running without authentication.
**Why:** Running without auth in production is dangerous. The warning ensures operators notice the misconfiguration.
**Expected:** At least one log line warning about auth being disabled.
**PASS if** warning present. **FAIL** if no warning found.

---

## Part 2: Authentication & Security

**What this validates:** API key enforcement, rate limiting, CORS headers, and secrets hygiene.

**Why it matters:** Without working auth, anyone on the network can manage your certificates. Without rate limiting, a single client can DoS the API. Without CORS, the GUI breaks from different origins.

> **Setup:** For auth tests 2.1.1–2.1.8, enable auth by editing `deploy/docker-compose.yml`:
> - Set `CERTCTL_AUTH_TYPE: api-key`
> - Add `CERTCTL_AUTH_SECRET: change-me-in-production`
> - Restart: `docker compose restart certctl-server && sleep 5`

### 2.1 API Key Authentication

**Test 2.1.1 — Request without auth header returns 401**

```bash
curl -s -w "\nHTTP %{http_code}\n" $SERVER/api/v1/certificates
```

**What:** Sends a request with no `Authorization` header while auth is enabled.
**Why:** If unauthenticated requests succeed, the auth middleware is broken and anyone can access the API.
**Expected:**
```
HTTP 401
```
**PASS if** HTTP 401. **FAIL** if any other status code.

---

**Test 2.1.2 — Request with wrong API key returns 401**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "Authorization: Bearer wrong-key-here" $SERVER/api/v1/certificates
```

**What:** Sends a request with an invalid API key.
**Why:** If wrong keys are accepted, the auth is not validating keys — any Bearer token passes. This is a critical security bug.
**Expected:** `HTTP 401`
**PASS if** HTTP 401. **FAIL** if 200.

---

**Test 2.1.3 — Request with valid API key returns 200**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" $SERVER/api/v1/certificates?per_page=1
```

**What:** Sends a request with the correct API key.
**Why:** Confirms the happy path — valid credentials are accepted.
**Expected:** `HTTP 200` with certificate data.
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 2.1.4 — /health accessible without auth (always)**

```bash
curl -s -w "\nHTTP %{http_code}\n" $SERVER/health
```

**What:** Verifies `/health` is accessible without credentials, even when auth is enabled.
**Why:** Load balancers and container orchestrators need to probe health without API keys. If health checks require auth, Docker restarts the container forever.
**Expected:** `HTTP 200`
**PASS if** HTTP 200 without any auth header. **FAIL** if 401.

---

**Test 2.1.5 — /ready accessible without auth (always)**

```bash
curl -s -w "\nHTTP %{http_code}\n" $SERVER/ready
```

**What:** Verifies `/ready` is accessible without credentials.
**Why:** Same as health — Kubernetes readiness probes must work without auth.
**Expected:** `HTTP 200`
**PASS if** HTTP 200. **FAIL** if 401.

---

**Test 2.1.6 — /api/v1/auth/info accessible without auth (GUI bootstrap)**

```bash
curl -s -w "\nHTTP %{http_code}\n" $SERVER/api/v1/auth/info
```

**What:** The auth info endpoint tells the GUI what auth mode is active. It must work before login.
**Why:** The React GUI calls this on page load to decide whether to show a login screen. If it requires auth, you can't even get to the login page — a chicken-and-egg problem.
**Expected:** HTTP 200 with JSON body containing auth mode (e.g., `{"auth_type":"api-key"}`).
**PASS if** HTTP 200 and body contains `auth_type`. **FAIL** if 401 or missing field.

---

**Test 2.1.7 — /api/v1/auth/check with valid key returns 200**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" $SERVER/api/v1/auth/check
```

**What:** Validates that the auth check endpoint confirms valid credentials.
**Why:** The GUI uses this after the user enters an API key to verify it works before proceeding.
**Expected:** `HTTP 200`
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 2.1.8 — /api/v1/auth/check without key returns 401**

```bash
curl -s -w "\nHTTP %{http_code}\n" $SERVER/api/v1/auth/check
```

**What:** Verifies that auth check rejects missing credentials.
**Why:** If auth check accepts requests without a key, the GUI would skip the login screen for unauthenticated users.
**Expected:** `HTTP 401`
**PASS if** HTTP 401. **FAIL** if 200.

---

### 2.2 Rate Limiting

> **Setup:** Ensure `CERTCTL_RATE_LIMIT_ENABLED: "true"`, `CERTCTL_RATE_LIMIT_RPS: "5"`, `CERTCTL_RATE_LIMIT_BURST: "10"` in docker-compose. Restart.

**Test 2.2.1 — Burst exceeds limit, returns 429 with Retry-After**

```bash
for i in $(seq 1 20); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "$AUTH" $SERVER/api/v1/certificates?per_page=1)
  echo "Request $i: HTTP $CODE"
done
```

**What:** Sends 20 rapid requests to exhaust the rate limit bucket (burst=10).
**Why:** Without rate limiting, a single misbehaving client can DoS the API, starving other users and the scheduler.
**Expected:** First ~10 requests return 200. Subsequent requests return 429.
**PASS if** at least one 429 appears in the output. **FAIL** if all 20 return 200.

---

**Test 2.2.2 — 429 response includes Retry-After header**

```bash
# Exhaust the bucket first
for i in $(seq 1 15); do curl -s -o /dev/null -H "$AUTH" $SERVER/api/v1/certificates?per_page=1; done
# Now check headers on the next request
curl -s -D - -o /dev/null -H "$AUTH" $SERVER/api/v1/certificates?per_page=1 | grep -i "retry-after"
```

**What:** After a 429, the response should include a `Retry-After` header telling the client how long to wait.
**Why:** Well-behaved clients use `Retry-After` for backoff. Without it, clients just hammer the server in a tight loop.
**Expected:** `Retry-After: <N>` header present.
**PASS if** `Retry-After` header is present. **FAIL** if missing.

---

**Test 2.2.3 — Rate limit bucket refills after waiting**

```bash
# Exhaust bucket
for i in $(seq 1 15); do curl -s -o /dev/null -H "$AUTH" $SERVER/api/v1/certificates?per_page=1; done
# Wait for refill (at 5 RPS, 10 tokens refill in 2 seconds)
sleep 3
# Should succeed now
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" $SERVER/api/v1/certificates?per_page=1
```

**What:** After waiting for the token bucket to refill, requests should succeed again.
**Why:** If the bucket never refills, the rate limiter is broken and clients are permanently blocked.
**Expected:** `HTTP 200` after the wait.
**PASS if** HTTP 200. **FAIL** if still 429 after 3-second wait.

---

### 2.3 CORS

> **Setup:** Set `CERTCTL_CORS_ORIGINS: "http://localhost:3000"` in docker-compose. Restart.

**Test 2.3.1 — Preflight OPTIONS with allowed origin returns CORS headers**

```bash
curl -s -D - -o /dev/null -X OPTIONS \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: GET" \
  $SERVER/api/v1/certificates
```

**What:** Sends a CORS preflight request from an allowed origin.
**Why:** Browsers send OPTIONS before cross-origin requests. If the server doesn't respond with proper CORS headers, the browser blocks the GUI's API calls entirely.
**Expected:** Headers include `Access-Control-Allow-Origin: http://localhost:3000`.
**PASS if** `Access-Control-Allow-Origin` header matches the requested origin. **FAIL** if missing or `*`.

---

**Test 2.3.2 — Request from disallowed origin has no CORS headers**

```bash
curl -s -D - -o /dev/null -X OPTIONS \
  -H "Origin: http://evil.example.com" \
  -H "Access-Control-Request-Method: GET" \
  $SERVER/api/v1/certificates
```

**What:** Sends a preflight from a non-allowed origin.
**Why:** If the server returns CORS headers for any origin, it's a cross-site request forgery vector — malicious sites can make API calls.
**Expected:** No `Access-Control-Allow-Origin` header in the response.
**PASS if** no `Access-Control-Allow-Origin` header. **FAIL** if the header is present.

---

**Test 2.3.3 — Wildcard CORS mode**

Set `CERTCTL_CORS_ORIGINS: "*"` in docker-compose, restart.

```bash
curl -s -D - -o /dev/null -X OPTIONS \
  -H "Origin: http://any-origin.example.com" \
  -H "Access-Control-Request-Method: GET" \
  $SERVER/api/v1/certificates | grep -i "access-control-allow-origin"
```

**What:** Verifies wildcard CORS mode accepts any origin.
**Why:** Development/demo setups often need wildcard CORS. This confirms the wildcard configuration path works.
**Expected:** `Access-Control-Allow-Origin: *`
**PASS if** header value is `*`. **FAIL** if missing.

---

### 2.4 Secrets Hygiene

**Test 2.4.1 — Private keys never in API responses (certificate detail)**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates/mc-api-prod" | grep -ci "private key\|BEGIN RSA\|BEGIN EC PRIVATE\|BEGIN PRIVATE"
```

**What:** Searches the full certificate detail response for private key material.
**Why:** If private keys leak via the API, anyone with API access can impersonate the server. This is a critical security violation.
**Expected:** Count = 0 (no private key strings found).
**PASS if** count = 0. **FAIL** if count > 0.

---

**Test 2.4.2 — Private keys never in API responses (certificate versions)**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates/mc-api-prod/versions" | grep -ci "private key\|BEGIN RSA\|BEGIN EC PRIVATE\|BEGIN PRIVATE"
```

**What:** Searches version history for private key material.
**Why:** Version history might accidentally include older keys. Even one leaked private key compromises the certificate.
**Expected:** Count = 0.
**PASS if** count = 0. **FAIL** if count > 0.

---

**Test 2.4.3 — Private keys never in API responses (agent work)**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/agents/ag-web-prod/work" | grep -ci "private key\|BEGIN RSA\|BEGIN EC PRIVATE\|BEGIN PRIVATE"
```

**What:** Searches the agent work endpoint for private key material.
**Why:** In agent keygen mode, the server should never possess the private key. If it leaks via the work endpoint, the keygen security model is broken.
**Expected:** Count = 0.
**PASS if** count = 0. **FAIL** if count > 0.

---

**Test 2.4.4 — Private keys never in server logs**

```bash
docker compose logs certctl-server 2>&1 | grep -ci "private key\|BEGIN RSA\|BEGIN EC PRIVATE\|BEGIN PRIVATE"
```

**What:** Searches all server log output for private key material.
**Why:** Logged private keys end up in log aggregators (Splunk, ELK), SIEM systems, and debug dumps — all accessible to operations staff who shouldn't have crypto material.
**Expected:** Count = 0.
**PASS if** count = 0. **FAIL** if count > 0.

---

**Test 2.4.5 — API key stored as SHA-256 hash (not plaintext)**

```bash
docker compose logs certctl-server 2>&1 | grep -ci "change-me-in-production"
```

**What:** Checks if the raw API key value appears in server logs.
**Why:** The server should hash API keys with SHA-256 for constant-time comparison. Logging the plaintext key exposes it to anyone with log access.
**Expected:** Count = 0 (key value does not appear in logs).
**PASS if** count = 0. **FAIL** if count > 0.

---

> **Cleanup:** Reset auth to `CERTCTL_AUTH_TYPE: none` and remove rate limit/CORS overrides for remaining tests. Restart: `docker compose restart certctl-server && sleep 5`

---

## Part 3: Certificate Lifecycle (CRUD)

**What this validates:** The core certificate inventory — creating, reading, updating, listing with filters/pagination/sorting, archiving, version history, and deployments.

**Why it matters:** Certificate CRUD is the foundation. Everything else (renewal, revocation, discovery, policy) depends on certificates existing and being queryable. If CRUD breaks, the product is unusable.

### 3.1 Create Certificates

**Test 3.1.1 — Create certificate with minimal fields**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "mc-test-minimal", "common_name": "minimal.test.local"}' \
  $SERVER/api/v1/certificates | jq .
```

**What:** Creates a certificate with only the required `common_name` field.
**Why:** The minimum viable cert creation must work for users who just want to track a certificate without all optional metadata.
**Expected:** HTTP 201. Response body contains `"id": "mc-test-minimal"` and `"common_name": "minimal.test.local"`.
**PASS if** HTTP 201 and response contains the ID. **FAIL** otherwise.

---

**Test 3.1.2 — Create certificate with all fields**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{
    "id": "mc-test-full",
    "common_name": "full.test.local",
    "sans": ["alt1.test.local", "alt2.test.local"],
    "owner_id": "o-alice",
    "issuer_id": "iss-local",
    "profile_id": "prof-standard-tls",
    "environment": "staging",
    "status": "Active"
  }' \
  $SERVER/api/v1/certificates | jq .
```

**What:** Creates a certificate with SANs, owner, issuer, profile, and environment.
**Why:** Production certs always have multiple attributes. All optional fields must be accepted and stored correctly.
**Expected:** HTTP 201. Response contains all provided fields with matching values.
**PASS if** HTTP 201 and `owner_id` = "o-alice", `issuer_id` = "iss-local", `profile_id` = "prof-standard-tls". **FAIL** if any field missing or mismatched.

---

**Test 3.1.3 — Create certificate with duplicate common_name**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "mc-test-dup", "common_name": "full.test.local"}' \
  $SERVER/api/v1/certificates
```

**What:** Attempts to create a second certificate with the same common_name as Test 3.1.2.
**Why:** Duplicate common names are valid (multiple certs for same domain, A/B deployment, canary). The system should allow this.
**Expected:** HTTP 201 — duplicate common_name is allowed (unique constraint is on ID, not CN).
**PASS if** HTTP 201. **FAIL** if 409 or 400 rejecting the duplicate CN.

---

### 3.2 List & Filter Certificates

**Test 3.2.1 — List certificates with pagination metadata**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?per_page=5" | jq '{total, page, per_page, items_count: (.items | length)}'
```

**What:** Lists certificates and verifies pagination metadata is present.
**Why:** Without pagination metadata, the GUI can't show page numbers or "showing X of Y."
**Expected:** `total` ≥ 15, `page` = 1, `per_page` = 5, `items_count` = 5.
**PASS if** all four fields present and items_count = 5. **FAIL** if pagination metadata missing.

---

**Test 3.2.2 — Filter by status**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?status=Active" | jq '{total, statuses: [.items[].status] | unique}'
```

**What:** Filters certificates to only Active status.
**Why:** Operators need to see only active certs (or only expiring, only expired). If filters don't work, they wade through the full inventory.
**Expected:** `statuses` array contains only `"Active"`.
**PASS if** every item has status "Active". **FAIL** if any non-Active status appears.

---

**Test 3.2.3 — Filter by owner**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?owner_id=o-alice" | jq '{total, owners: [.items[].owner_id] | unique}'
```

**What:** Filters by owner_id.
**Why:** Team leads need to see their team's certificates only. Broken owner filter forces them to search manually.
**Expected:** All items have `owner_id` = "o-alice".
**PASS if** all items match owner. **FAIL** if any mismatch.

---

**Test 3.2.4 — Filter by issuer**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?issuer_id=iss-local" | jq '{total, issuers: [.items[].issuer_id] | unique}'
```

**What:** Filters by issuer_id.
**Why:** When diagnosing issuer-specific issues (e.g., CA outage), operators need to see only certs from that issuer.
**Expected:** All items have `issuer_id` = "iss-local".
**PASS if** all match. **FAIL** if any mismatch.

---

**Test 3.2.5 — Filter by environment**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?environment=production" | jq '{total, envs: [.items[].environment] | unique}'
```

**What:** Filters by environment tag.
**Why:** Production vs staging separation is critical. Operators must be able to view only production certs during an incident.
**Expected:** All items have `environment` = "production".
**PASS if** all match. **FAIL** otherwise.

---

**Test 3.2.6 — Pagination: page 2**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?per_page=2&page=2" | jq '{page, per_page, items_count: (.items | length)}'
```

**What:** Fetches the second page with 2 items per page.
**Why:** Pagination must actually skip the first page's items. A common bug is returning the same items on every page.
**Expected:** `page` = 2, `per_page` = 2, `items_count` = 2. Items should be different from page 1.
**PASS if** page=2, per_page=2, items_count=2. **FAIL** otherwise.

---

**Test 3.2.7 — Sort descending by notAfter**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?sort=-notAfter&per_page=5" | jq '[.items[].not_after]'
```

**What:** Requests certificates sorted by expiration date, newest first.
**Why:** Operators usually want to see the latest-expiring certs at the top, or the soonest-expiring. Sort must work for the GUI's column headers to function.
**Expected:** Array of dates in descending order (each date ≥ the next).
**PASS if** dates are in descending order. **FAIL** if not sorted.

---

**Test 3.2.8 — Sort ascending by commonName**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?sort=commonName&per_page=5" | jq '[.items[].common_name]'
```

**What:** Sorts alphabetically by common name.
**Why:** Alphabetical sorting helps operators locate certs visually in long lists.
**Expected:** Array of names in ascending alphabetical order.
**PASS if** names are sorted A→Z. **FAIL** if not sorted.

---

**Test 3.2.9 — Sparse fields**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?fields=id,common_name,status&per_page=3" | jq '.items[0] | keys'
```

**What:** Requests only specific fields in the response.
**Why:** Large certificate records have many fields. Sparse fields reduce bandwidth for dashboards that only need ID + name + status.
**Expected:** Keys array contains only `["common_name", "id", "status"]` (or a subset including those three).
**PASS if** response items contain only the requested fields. **FAIL** if additional fields leak through.

---

**Test 3.2.10 — Cursor pagination: first page**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?page_size=5" | jq '{next_cursor, items_count: (.items | length)}'
```

**What:** Fetches the first page of cursor-based pagination.
**Why:** Cursor pagination is more efficient than offset pagination for large datasets — it doesn't skip rows. The `next_cursor` token must be present for the next page.
**Expected:** `next_cursor` is a non-empty string, `items_count` = 5.
**PASS if** `next_cursor` is non-null and non-empty. **FAIL** if missing.

---

**Test 3.2.11 — Cursor pagination: second page**

```bash
CURSOR=$(curl -s -H "$AUTH" "$SERVER/api/v1/certificates?page_size=5" | jq -r '.next_cursor')
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?page_size=5&cursor=$CURSOR" | jq '{items_count: (.items | length), first_id: .items[0].id}'
```

**What:** Uses the cursor token from page 1 to fetch page 2.
**Why:** If the cursor is broken (always returns page 1, or errors), pagination is unusable for large inventories.
**Expected:** `items_count` ≤ 5. `first_id` is different from the first item on page 1.
**PASS if** items are different from page 1. **FAIL** if same items returned.

---

**Test 3.2.12 — Time-range filter: expires_before**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?expires_before=2026-06-01T00:00:00Z" | jq '{total}'
```

**What:** Filters to certificates expiring before June 2026.
**Why:** Operators need to see what's expiring in the next N months for capacity planning and renewal scheduling.
**Expected:** `total` > 0 (some certs have near-term expiration dates in seed data).
**PASS if** total > 0 and all returned items have `not_after` before the specified date. **FAIL** if total = 0 when seed data has expiring certs.

---

### 3.3 Get, Update, Archive

**Test 3.3.1 — Get single certificate by ID**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/certificates/mc-api-prod" | jq '{id, common_name, status}'
```

**What:** Retrieves a specific certificate by ID.
**Why:** Certificate detail is the most common API call from the GUI.
**Expected:** HTTP 200. `id` = "mc-api-prod", `common_name` and `status` present.
**PASS if** HTTP 200 and `id` matches. **FAIL** otherwise.

---

**Test 3.3.2 — Get nonexistent certificate returns 404**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/certificates/mc-does-not-exist"
```

**What:** Requests a certificate ID that doesn't exist.
**Why:** The API must return 404, not 500. A 500 on missing resources indicates the handler doesn't check for not-found.
**Expected:** `HTTP 404`
**PASS if** HTTP 404. **FAIL** if 200 or 500.

---

**Test 3.3.3 — Update certificate fields**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X PUT -H "$AUTH" -H "$CT" \
  -d '{"environment": "staging", "owner_id": "o-bob"}' \
  $SERVER/api/v1/certificates/mc-test-minimal | jq '{id, environment, owner_id}'
```

**What:** Updates the environment and owner of a certificate.
**Why:** Certificates move between environments and change ownership. The update endpoint must accept partial updates.
**Expected:** HTTP 200. `environment` = "staging", `owner_id` = "o-bob".
**PASS if** HTTP 200 and updated fields match. **FAIL** otherwise.

---

**Test 3.3.4 — Archive (soft delete) certificate**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/certificates/mc-test-dup"
```

**What:** Archives a certificate (soft delete — marks inactive, not physically deleted).
**Why:** Hard deletes lose audit history. Archival preserves the record while removing it from active views.
**Expected:** HTTP 204 (No Content).
**PASS if** HTTP 204. **FAIL** otherwise.

---

**Test 3.3.5 — Get archived certificate behavior**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/certificates/mc-test-dup"
```

**What:** Attempts to fetch the archived certificate.
**Why:** Verifies the archive behavior — either returns 404 (hidden from normal queries) or returns with an archived status.
**Expected:** HTTP 404 or HTTP 200 with `status` = "Archived".
**PASS if** HTTP 404 or status = "Archived". **FAIL** if HTTP 200 with Active status.

---

### 3.4 Version History & Deployments

**Test 3.4.1 — Get certificate versions**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/certificates/mc-api-prod/versions" | jq '{count: (. | length), first_version: .[0].version}'
```

**What:** Retrieves the version history for a certificate.
**Why:** Version history enables rollback and audit. If versions aren't tracked, operators can't recover from a bad renewal.
**Expected:** HTTP 200 with an array of version objects. At least 1 version.
**PASS if** HTTP 200 and array length ≥ 1. **FAIL** otherwise.

---

**Test 3.4.2 — Get certificate deployments**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/certificates/mc-api-prod/deployments" | jq .
```

**What:** Retrieves deployment records for a certificate.
**Why:** Operators need to see where a cert is deployed (which targets) and deployment status.
**Expected:** HTTP 200 with deployment data (may be empty array if no deployments yet).
**PASS if** HTTP 200. **FAIL** if 404 or 500.

---

**Test 3.4.3 — Trigger deployment creates a job**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{}' \
  $SERVER/api/v1/certificates/mc-api-prod/deploy | jq .
```

**What:** Triggers a deployment job for the certificate.
**Why:** This is how operators push updated certs to targets. If deployment triggering is broken, renewed certs never reach the servers.
**Expected:** HTTP 200 or 202 with job ID or status message.
**PASS if** HTTP 200/202. **FAIL** if 404 or 500.

---

## Part 4: Renewal Workflow

**What this validates:** The full renewal lifecycle — triggering, job state transitions, agent keygen, CSR submission, and interactive approval.

**Why it matters:** Renewal is the core automated workflow. If renewals break, certificates expire in production.

### 4.1 Manual Renewal Trigger

**Test 4.1.1 — Trigger renewal creates job**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{}' \
  $SERVER/api/v1/certificates/mc-web-prod/renew | jq .
```

**What:** Triggers a manual renewal for `mc-web-prod`.
**Why:** Operators need to force renewal (compromised key, changed SANs). This is the manual override for the scheduled process.
**Expected:** HTTP 200/202. Response contains job information.
**PASS if** HTTP 200/202 with job data. **FAIL** if 404 or 500.

---

**Test 4.1.2 — Renewal job appears in jobs list**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/jobs?type=Renewal" | jq '{total, latest_job: .items[0] | {id, type, status, certificate_id}}'
```

**What:** Verifies the renewal job was created and appears in the jobs list filtered by type.
**Why:** If jobs aren't created, the renewal was silently dropped. The job list must reflect pending work.
**Expected:** `total` ≥ 1. Latest job has `type` = "Renewal" and `certificate_id` matching the renewed cert.
**PASS if** at least one Renewal job exists. **FAIL** if total = 0.

---

**Test 4.1.3 — Renewal on nonexistent certificate returns 404**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{}' \
  $SERVER/api/v1/certificates/mc-nonexistent/renew
```

**What:** Attempts renewal on a certificate that doesn't exist.
**Why:** Should return 404, not 500 or silently succeed with a ghost job.
**Expected:** `HTTP 404`
**PASS if** HTTP 404. **FAIL** if 200 or 500.

---

### 4.2 Job State Transitions

> **Note:** The Docker Compose demo uses `CERTCTL_KEYGEN_MODE=server`, so renewal jobs should transition through Pending → Running → Completed automatically via the scheduler's job processor loop (30s interval).

**Test 4.2.1 — Server keygen mode: job completes automatically**

```bash
# Get the job ID from the latest renewal
JOB_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/jobs?type=Renewal&per_page=1" | jq -r '.items[0].id')
echo "Job ID: $JOB_ID"
# Wait for the job processor (30s interval)
sleep 45
curl -s -H "$AUTH" "$SERVER/api/v1/jobs/$JOB_ID" | jq '{id, status, type}'
```

**What:** Verifies the renewal job transitions through states and completes in server keygen mode.
**Why:** If the job processor doesn't pick up and complete jobs, certificates never get renewed — the core automation is broken.
**Expected:** Status = "Completed" (or "Running" if still processing).
**PASS if** status is "Completed" or "Running". **FAIL** if still "Pending" after 45 seconds.

---

### 4.3 Interactive Approval

**Test 4.3.1 — Approve a job**

```bash
# Find a job that supports approval (or create one via renewal)
JOB_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/jobs?per_page=1" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "Approved for production deployment"}' \
  $SERVER/api/v1/jobs/$JOB_ID/approve
```

**What:** Approves a job that's in AwaitingApproval state.
**Why:** Some organizations require manual approval before certificates are deployed. The approve endpoint must work.
**Expected:** HTTP 200 (if job was in AwaitingApproval) or appropriate error (if job is in another state).
**PASS if** HTTP 200 or a clear error explaining the job isn't in an approvable state. **FAIL** if 500.

---

**Test 4.3.2 — Reject a job with reason**

```bash
JOB_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/jobs?per_page=1" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "Certificate SANs do not match requirements"}' \
  $SERVER/api/v1/jobs/$JOB_ID/reject
```

**What:** Rejects a job with a documented reason.
**Why:** Rejection must record the reason for audit trail. Without reasons, there's no accountability for why a renewal was blocked.
**Expected:** HTTP 200 (if approvable state) or clear error.
**PASS if** HTTP 200 or clear state error. **FAIL** if 500.

---

### 4.4 Agent Work Polling

**Test 4.4.1 — Agent work endpoint returns pending jobs**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/agents/ag-web-prod/work" | jq .
```

**What:** Polls the work endpoint for an agent to see pending deployment or CSR jobs.
**Why:** This is how agents discover they have work to do. If the work endpoint returns nothing when jobs exist, the agent sits idle.
**Expected:** HTTP 200 with job array (may be empty if no pending work).
**PASS if** HTTP 200. **FAIL** if 500.

---

**Test 4.4.2 — Agent reports job status**

```bash
# Get a job ID
JOB_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/jobs?per_page=1" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"status": "Completed", "message": "Certificate deployed successfully"}' \
  $SERVER/api/v1/agents/ag-web-prod/jobs/$JOB_ID/status
```

**What:** Agent reports back the outcome of a job it executed.
**Why:** Without status reporting, the server never knows if deployments succeeded or failed.
**Expected:** HTTP 200.
**PASS if** HTTP 200. **FAIL** if 404 or 500.

---

## Part 5: Revocation

**What this validates:** Certificate revocation, CRL generation, OCSP responses, and revocation audit trail.

**Why it matters:** When a private key is compromised, revocation is the emergency response. If revocation doesn't work, compromised certs remain trusted.

### 5.1 Revoke Certificates

**Test 5.1.1 — Revoke with default reason**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "unspecified"}' \
  $SERVER/api/v1/certificates/mc-test-minimal/revoke | jq .
```

**What:** Revokes a certificate with the default "unspecified" reason.
**Why:** Basic revocation must work. This is the most common revocation path.
**Expected:** HTTP 200. Certificate status changes to "Revoked".
**PASS if** HTTP 200 and response indicates revocation. **FAIL** otherwise.

---

**Test 5.1.2 — Revoke with reason: keyCompromise**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "keyCompromise"}' \
  $SERVER/api/v1/certificates/mc-test-full/revoke | jq .
```

**What:** Revokes with the keyCompromise reason (RFC 5280 code 1).
**Why:** Key compromise is the most critical revocation reason. CRL consumers use this to determine urgency.
**Expected:** HTTP 200.
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 5.1.3 — Revoke with reason: caCompromise**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "caCompromise"}' \
  $SERVER/api/v1/certificates/mc-legacy-prod/revoke | jq .
```

**Expected:** HTTP 200. **PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 5.1.4 — Revoke with reason: affiliationChanged**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "affiliationChanged"}' \
  $SERVER/api/v1/certificates/mc-old-api/revoke | jq .
```

**Expected:** HTTP 200. **PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 5.1.5 — Revoke with reason: superseded**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "superseded"}' \
  $SERVER/api/v1/certificates/mc-vpn-prod/revoke | jq .
```

**Expected:** HTTP 200. **PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 5.1.6 — Revoke with reason: cessationOfOperation**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "cessationOfOperation"}' \
  $SERVER/api/v1/certificates/mc-grafana-prod/revoke | jq .
```

**Expected:** HTTP 200. **PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 5.1.7 — Revoke with reason: certificateHold**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "certificateHold"}' \
  $SERVER/api/v1/certificates/mc-mail-prod/revoke | jq .
```

**Expected:** HTTP 200. **PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 5.1.8 — Revoke with reason: privilegeWithdrawn**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "privilegeWithdrawn"}' \
  $SERVER/api/v1/certificates/mc-cdn-prod/revoke | jq .
```

**Expected:** HTTP 200. **PASS if** HTTP 200. **FAIL** otherwise.

---

### 5.2 Revocation Edge Cases

**Test 5.2.1 — Revoke already-revoked certificate**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "keyCompromise"}' \
  $SERVER/api/v1/certificates/mc-test-full/revoke
```

**What:** Attempts to revoke a certificate that was already revoked in Test 5.1.2.
**Why:** Idempotency is important — re-revoking shouldn't error or create duplicate records. It should either succeed silently or return a clear "already revoked" response.
**Expected:** HTTP 200 (idempotent) or HTTP 409 (already revoked).
**PASS if** HTTP 200 or 409. **FAIL** if 500.

---

**Test 5.2.2 — Revoke nonexistent certificate**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "keyCompromise"}' \
  $SERVER/api/v1/certificates/mc-nonexistent/revoke
```

**What:** Attempts to revoke a certificate ID that doesn't exist.
**Why:** Must return 404, not 500.
**Expected:** `HTTP 404`
**PASS if** HTTP 404. **FAIL** if 200 or 500.

---

**Test 5.2.3 — Revoke with invalid reason**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "becauseISaidSo"}' \
  $SERVER/api/v1/certificates/mc-api-prod/revoke
```

**What:** Attempts revocation with an invalid reason code.
**Why:** Only RFC 5280 reason codes should be accepted. Invalid reasons indicate a buggy client.
**Expected:** HTTP 400 with validation error.
**PASS if** HTTP 400. **FAIL** if 200.

---

**Test 5.2.4 — Revocation appears in audit trail**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/audit?per_page=5" | jq '[.items[] | select(.action == "certificate.revoked" or .resource_type == "certificate") | {action, resource_id}] | first'
```

**What:** Verifies revocation events were recorded in the audit trail.
**Why:** Audit is a compliance requirement. Every revocation must be traceable.
**Expected:** At least one audit event related to certificate revocation.
**PASS if** revocation audit event found. **FAIL** if no revocation events.

---

### 5.3 CRL & OCSP

**Test 5.3.1 — JSON CRL endpoint**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/crl" | jq '{total: .total, entries_count: (.entries | length)}'
```

**What:** Fetches the JSON-formatted Certificate Revocation List.
**Why:** CRL is how relying parties check if a certificate has been revoked. The JSON CRL is the machine-readable API view.
**Expected:** HTTP 200. `total` > 0 (we revoked several certs above). Entries array contains serial numbers.
**PASS if** HTTP 200 and `total` > 0. **FAIL** if total = 0 or 500.

---

**Test 5.3.2 — DER CRL endpoint**

```bash
curl -s -D - -o /dev/null -H "$AUTH" "$SERVER/api/v1/crl/iss-local" | grep -i "content-type"
```

**What:** Fetches the DER-encoded X.509 CRL for the local issuer.
**Why:** Standard CRL consumers (browsers, TLS libraries) expect DER-encoded CRLs, not JSON. The Content-Type must be correct.
**Expected:** `Content-Type: application/pkix-crl`
**PASS if** Content-Type is `application/pkix-crl`. **FAIL** if JSON or other.

---

**Test 5.3.3 — OCSP: good response for non-revoked cert**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/ocsp/iss-local/mc-api-prod"
```

**What:** Queries the OCSP responder for a non-revoked certificate.
**Why:** OCSP is the real-time alternative to CRL. A "good" response means the cert is valid.
**Expected:** HTTP 200 with OCSP response indicating "good" status.
**PASS if** HTTP 200. **FAIL** if 500.

---

**Test 5.3.4 — OCSP: revoked response for revoked cert**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/ocsp/iss-local/mc-test-full"
```

**What:** Queries OCSP for a certificate we revoked earlier.
**Why:** OCSP must return "revoked" status for revoked certs. If it still returns "good," relying parties will trust a compromised certificate.
**Expected:** HTTP 200 with OCSP response indicating "revoked" status.
**PASS if** HTTP 200 and response indicates revoked. **FAIL** if response indicates "good".

---

**Test 5.3.5 — OCSP: unknown serial**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/ocsp/iss-local/nonexistent-serial"
```

**What:** Queries OCSP for a serial number the server doesn't recognize.
**Why:** OCSP must return "unknown" for serials it doesn't manage, not "good" (which would be a false positive).
**Expected:** HTTP 200 with OCSP "unknown" response, or HTTP 404.
**PASS if** response is "unknown" or 404. **FAIL** if "good".

---

## Part 6: Issuer Connectors

**What this validates:** CRUD operations for issuer connectors and the Local CA issuer functionality.

**Why it matters:** Issuers are the CAs that sign certificates. If issuer management is broken, no new certs can be issued.

### 6.1 Issuer CRUD

**Test 6.1.1 — List issuers shows seed data**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/issuers" | jq '{total, ids: [.items[].id]}'
```

**What:** Lists all issuers and verifies seed data loaded.
**Why:** Issuers must exist before any issuance or renewal can work.
**Expected:** `total` = 4. IDs include `iss-local`, `iss-acme-le`, `iss-stepca`, `iss-digicert`.
**PASS if** total = 4 and all 4 seed IDs present. **FAIL** otherwise.

---

**Test 6.1.2 — Get issuer detail**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/issuers/iss-local" | jq '{id, name, type}'
```

**What:** Fetches a specific issuer by ID.
**Why:** The detail view must show the issuer's type and configuration for troubleshooting.
**Expected:** HTTP 200. `id` = "iss-local", `type` present.
**PASS if** HTTP 200 and fields match. **FAIL** otherwise.

---

**Test 6.1.3 — Create issuer**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "iss-test", "name": "Test Issuer", "type": "local", "config": {}}' \
  $SERVER/api/v1/issuers | jq '{id, name, type}'
```

**What:** Creates a new issuer record.
**Why:** Organizations add new CAs as they grow. CRUD must support dynamic issuer management.
**Expected:** HTTP 201. `id` = "iss-test".
**PASS if** HTTP 201. **FAIL** otherwise.

---

**Test 6.1.4 — Update issuer**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X PUT -H "$AUTH" -H "$CT" \
  -d '{"name": "Updated Test Issuer"}' \
  $SERVER/api/v1/issuers/iss-test | jq '{id, name}'
```

**What:** Updates the issuer name.
**Expected:** HTTP 200. `name` = "Updated Test Issuer".
**PASS if** HTTP 200 and name updated. **FAIL** otherwise.

---

**Test 6.1.5 — Delete issuer**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/issuers/iss-test"
```

**What:** Deletes the test issuer.
**Expected:** HTTP 204.
**PASS if** HTTP 204. **FAIL** otherwise.

---

**Test 6.1.6 — Test issuer connection**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{}' \
  $SERVER/api/v1/issuers/iss-local/test | jq .
```

**What:** Tests the connection to the Local CA issuer.
**Why:** Before relying on an issuer for production certs, operators need to verify it's reachable and configured correctly.
**Expected:** HTTP 200 with success/status message.
**PASS if** HTTP 200. **FAIL** if 500 or connection error.

---

**Test 6.1.7 — Create issuer with missing name returns validation error**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "iss-bad", "type": "local"}' \
  $SERVER/api/v1/issuers
```

**What:** Attempts to create an issuer without the required `name` field.
**Why:** Input validation must catch missing required fields before they reach the database.
**Expected:** HTTP 400 with validation error.
**PASS if** HTTP 400. **FAIL** if 201.

---

**Test 6.1.8 — Create issuer with invalid type**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "iss-bad2", "name": "Bad Issuer", "type": "quantum-ca"}' \
  $SERVER/api/v1/issuers
```

**What:** Attempts to create an issuer with an unsupported type.
**Why:** Unknown issuer types would fail at issuance time. Better to reject early at creation.
**Expected:** HTTP 400.
**PASS if** HTTP 400. **FAIL** if 201.

---

## Part 7: Target Connectors & Deployment

**What this validates:** CRUD for deployment targets, including type-specific configuration for all 5 target types.

**Why it matters:** Targets are where certificates get deployed (NGINX, Apache, etc.). If target management is broken, certificates can't be pushed to production servers.

### 7.1 Target CRUD

**Test 7.1.1 — List targets shows seed data**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/targets" | jq '{total, ids: [.items[].id]}'
```

**What:** Lists all targets and verifies seed data.
**Expected:** `total` = 5. IDs include all seed target IDs.
**PASS if** total = 5. **FAIL** otherwise.

---

**Test 7.1.2 — Create NGINX target**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "tgt-test-nginx", "name": "Test NGINX", "type": "nginx", "config": {"cert_path": "/etc/ssl/cert.pem", "key_path": "/etc/ssl/key.pem", "reload_command": "nginx -s reload"}}' \
  $SERVER/api/v1/targets | jq '{id, name, type}'
```

**What:** Creates an NGINX target with type-specific config fields.
**Why:** Each target type has different config requirements (file paths, reload commands, etc.). The API must accept and store them.
**Expected:** HTTP 201. `type` = "nginx".
**PASS if** HTTP 201. **FAIL** otherwise.

---

**Test 7.1.3 — Create Apache target**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "tgt-test-apache", "name": "Test Apache", "type": "apache", "config": {"cert_path": "/etc/apache2/ssl/cert.pem", "key_path": "/etc/apache2/ssl/key.pem", "chain_path": "/etc/apache2/ssl/chain.pem", "reload_command": "apachectl graceful"}}' \
  $SERVER/api/v1/targets | jq '{id, type}'
```

**Expected:** HTTP 201. `type` = "apache".
**PASS if** HTTP 201. **FAIL** otherwise.

---

**Test 7.1.4 — Create HAProxy target**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "tgt-test-haproxy", "name": "Test HAProxy", "type": "haproxy", "config": {"combined_pem_path": "/etc/haproxy/certs/combined.pem", "reload_command": "systemctl reload haproxy"}}' \
  $SERVER/api/v1/targets | jq '{id, type}'
```

**Expected:** HTTP 201. `type` = "haproxy".
**PASS if** HTTP 201. **FAIL** otherwise.

---

**Test 7.1.5 — Create F5 BIG-IP target (stub)**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "tgt-test-f5", "name": "Test F5", "type": "f5-bigip", "config": {}}' \
  $SERVER/api/v1/targets | jq '{id, type}'
```

**Expected:** HTTP 201. `type` = "f5-bigip".
**PASS if** HTTP 201. **FAIL** otherwise.

---

**Test 7.1.6 — Create IIS target (stub)**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "tgt-test-iis", "name": "Test IIS", "type": "iis", "config": {}}' \
  $SERVER/api/v1/targets | jq '{id, type}'
```

**Expected:** HTTP 201. `type` = "iis".
**PASS if** HTTP 201. **FAIL** otherwise.

---

**Test 7.1.7 — Get target verifies type-specific config stored**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/targets/tgt-test-nginx" | jq '{id, type, config}'
```

**What:** Retrieves the NGINX target and verifies config fields were persisted.
**Why:** If type-specific config isn't stored, deployment will fail because the connector won't know file paths or reload commands.
**Expected:** `config` contains `cert_path`, `key_path`, `reload_command`.
**PASS if** config fields match what was created. **FAIL** if config is empty or missing fields.

---

**Test 7.1.8 — Update target config**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X PUT -H "$AUTH" -H "$CT" \
  -d '{"name": "Updated NGINX", "config": {"cert_path": "/new/path/cert.pem", "key_path": "/new/path/key.pem", "reload_command": "nginx -s reload"}}' \
  $SERVER/api/v1/targets/tgt-test-nginx | jq '{name, config}'
```

**What:** Updates the target configuration.
**Expected:** HTTP 200. `name` = "Updated NGINX", `config.cert_path` = "/new/path/cert.pem".
**PASS if** HTTP 200 and fields updated. **FAIL** otherwise.

---

**Test 7.1.9 — Delete target returns 204**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/targets/tgt-test-haproxy"
```

**Expected:** HTTP 204.
**PASS if** HTTP 204. **FAIL** if 200 or 500.

---

## Part 8: Agent Operations

**What this validates:** Agent registration, heartbeat reporting, metadata collection, work polling, and CSR submission.

**Why it matters:** Agents are the remote executors — they deploy certificates to target infrastructure. If agents can't register, heartbeat, or receive work, the deployment model collapses.

### 8.1 Agent CRUD & Registration

**Test 8.1.1 — Register new agent**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "ag-test-new", "name": "Test Agent"}' \
  $SERVER/api/v1/agents | jq '{id, name, status}'
```

**What:** Registers a new agent with the control plane.
**Why:** Agents self-register on first startup. If registration fails, the agent can't receive work.
**Expected:** HTTP 201. `id` = "ag-test-new".
**PASS if** HTTP 201. **FAIL** otherwise.

---

**Test 8.1.2 — List agents includes new agent**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/agents" | jq '{total, ids: [.items[].id]}'
```

**What:** Verifies the newly registered agent appears in the list.
**Expected:** `total` ≥ 6 (5 seed + 1 new). "ag-test-new" in IDs array.
**PASS if** ag-test-new appears in the list. **FAIL** if missing.

---

**Test 8.1.3 — Get agent detail with metadata**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/agents/ag-web-prod" | jq '{id, name, os, architecture, ip_address, version, status}'
```

**What:** Retrieves agent detail including system metadata reported via heartbeat.
**Why:** Fleet management requires knowing each agent's OS, architecture, and version for grouping and targeting.
**Expected:** HTTP 200. `os`, `architecture` fields present (from seed data metadata).
**PASS if** HTTP 200 and metadata fields present. **FAIL** if fields are null/missing.

---

### 8.2 Heartbeat

**Test 8.2.1 — Agent heartbeat updates last_heartbeat_at**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"os": "linux", "architecture": "amd64", "ip_address": "10.0.1.50", "version": "0.2.0"}' \
  $SERVER/api/v1/agents/ag-test-new/heartbeat
```

**What:** Sends a heartbeat with system metadata.
**Why:** Heartbeats keep the agent "alive" in the scheduler's health check. Missed heartbeats mark the agent offline.
**Expected:** HTTP 200.
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 8.2.2 — Heartbeat metadata stored**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/agents/ag-test-new" | jq '{os, architecture, ip_address, version}'
```

**What:** Verifies that heartbeat metadata was persisted.
**Expected:** `os` = "linux", `architecture` = "amd64", `ip_address` = "10.0.1.50", `version` = "0.2.0".
**PASS if** all 4 fields match. **FAIL** if any mismatch.

---

**Test 8.2.3 — Heartbeat for nonexistent agent**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{}' \
  $SERVER/api/v1/agents/ag-nonexistent/heartbeat
```

**What:** Sends a heartbeat for an agent that wasn't registered.
**Why:** Must return 404, not silently create a new agent record.
**Expected:** HTTP 404.
**PASS if** HTTP 404. **FAIL** if 200 or 201.

---

### 8.3 Agent Work & CSR

**Test 8.3.1 — Agent work polling returns jobs**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/agents/ag-web-prod/work" | jq .
```

**What:** Agent polls for pending work (deployments, CSR requests).
**Expected:** HTTP 200 with array of work items (may be empty).
**PASS if** HTTP 200. **FAIL** if 500.

---

**Test 8.3.2 — Agent work polling with no pending work**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/agents/ag-test-new/work" | jq .
```

**What:** Polls work for an agent with no pending jobs.
**Expected:** HTTP 200 with empty array or null.
**PASS if** HTTP 200 and empty/null response. **FAIL** if 500.

---

**Test 8.3.3 — Agent certificate pickup**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/agents/ag-web-prod/certificates/mc-api-prod" | jq .
```

**What:** Agent fetches a specific certificate's data for deployment.
**Expected:** HTTP 200 with certificate details.
**PASS if** HTTP 200 with cert data. **FAIL** if 404 or 500.

---

**Test 8.3.4 — Delete agent for cleanup**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/agents/ag-test-new"
```

**What:** Cleans up the test agent.
**Expected:** HTTP 204 or 200.
**PASS if** successful deletion. **FAIL** if 500.

---

## Part 9: Job System

**What this validates:** Job lifecycle — listing, filtering, detail view, cancellation, approval, and rejection.

**Why it matters:** Jobs are the execution engine for renewals and deployments. If jobs can't be queried, cancelled, or approved, operators lose control of the workflow.

### 9.1 Job Queries

**Test 9.1.1 — List jobs with pagination**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/jobs?per_page=5" | jq '{total, page, per_page, items_count: (.items | length)}'
```

**What:** Lists jobs with pagination metadata.
**Expected:** `total` ≥ 0, pagination fields present.
**PASS if** HTTP 200 and pagination metadata present. **FAIL** otherwise.

---

**Test 9.1.2 — Filter jobs by status**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/jobs?status=Completed" | jq '{total, statuses: [.items[].status] | unique}'
```

**What:** Filters jobs to only Completed status.
**Expected:** All items have `status` = "Completed".
**PASS if** all items match filter. **FAIL** if any mismatch.

---

**Test 9.1.3 — Filter jobs by type**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/jobs?type=Renewal" | jq '{total, types: [.items[].type] | unique}'
```

**What:** Filters jobs to only Renewal type.
**Expected:** All items have `type` = "Renewal".
**PASS if** all match. **FAIL** if any mismatch.

---

**Test 9.1.4 — Get job detail**

```bash
JOB_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/jobs?per_page=1" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/jobs/$JOB_ID" | jq '{id, type, status, certificate_id}'
```

**What:** Retrieves a specific job by ID.
**Expected:** HTTP 200 with full job record including `type`, `status`, `certificate_id`.
**PASS if** HTTP 200 and all fields present. **FAIL** otherwise.

---

**Test 9.1.5 — Get nonexistent job**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/jobs/job-nonexistent"
```

**Expected:** HTTP 404.
**PASS if** HTTP 404. **FAIL** if 200 or 500.

---

### 9.2 Job Actions

**Test 9.2.1 — Cancel pending job**

```bash
# Create a renewal to get a fresh job
curl -s -X POST -H "$AUTH" -H "$CT" -d '{}' $SERVER/api/v1/certificates/mc-data-prod/renew > /dev/null
JOB_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/jobs?per_page=1&type=Renewal" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{}' \
  $SERVER/api/v1/jobs/$JOB_ID/cancel | jq .
```

**What:** Cancels a pending job.
**Why:** Operators need to abort incorrect or unnecessary jobs before they execute.
**Expected:** HTTP 200. Status changes to "Cancelled".
**PASS if** HTTP 200. **FAIL** if 500 or if job cannot be cancelled.

---

**Test 9.2.2 — Cancel already-completed job**

```bash
# Find a completed job
JOB_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/jobs?status=Completed&per_page=1" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{}' \
  $SERVER/api/v1/jobs/$JOB_ID/cancel
```

**What:** Attempts to cancel a job that already completed.
**Why:** Completed jobs shouldn't be cancelable — the work is done. The API should return an appropriate error.
**Expected:** HTTP 400 or 409 (conflict — invalid state transition).
**PASS if** HTTP 400 or 409. **FAIL** if 200 (accepted invalid cancellation).

---

## Part 10: Policies & Profiles

**What this validates:** Policy engine CRUD, profile management, and the interaction between profiles and certificate behavior.

**Why it matters:** Policies enforce organizational standards (key type, max TTL, renewal windows). Profiles define certificate enrollment templates. Broken policies mean non-compliant certificates ship to production.

### 10.1 Policies

**Test 10.1.1 — List policies**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/policies" | jq '{total, ids: [.items[].id]}'
```

**Expected:** `total` ≥ 3 (seed: rp-standard, rp-urgent, rp-manual).
**PASS if** total ≥ 3. **FAIL** otherwise.

---

**Test 10.1.2 — Create policy**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "rp-test", "name": "Test Policy", "type": "scheduled", "config": {"renewal_window_days": 14, "alert_thresholds_days": [30, 14, 7]}}' \
  $SERVER/api/v1/policies | jq '{id, name, type}'
```

**Expected:** HTTP 201.
**PASS if** HTTP 201. **FAIL** otherwise.

---

**Test 10.1.3 — Get policy**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/policies/rp-test" | jq '{id, name, type}'
```

**Expected:** HTTP 200 with matching fields.
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 10.1.4 — Update policy**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X PUT -H "$AUTH" -H "$CT" \
  -d '{"name": "Updated Test Policy"}' \
  $SERVER/api/v1/policies/rp-test | jq '{name}'
```

**Expected:** HTTP 200. `name` = "Updated Test Policy".
**PASS if** HTTP 200 and name updated. **FAIL** otherwise.

---

**Test 10.1.5 — Delete policy**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/policies/rp-test"
```

**Expected:** HTTP 204.
**PASS if** HTTP 204. **FAIL** otherwise.

---

**Test 10.1.6 — Policy violations endpoint**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/policies/rp-standard/violations" | jq '{total}'
```

**What:** Lists policy violations for a specific policy.
**Why:** Operators need to see which certificates violate their policies.
**Expected:** HTTP 200 with violations array.
**PASS if** HTTP 200. **FAIL** if 500.

---

**Test 10.1.7 — Invalid policy type returns 400**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "rp-bad", "name": "Bad", "type": "quantum-policy"}' \
  $SERVER/api/v1/policies
```

**Expected:** HTTP 400 with validation error.
**PASS if** HTTP 400. **FAIL** if 201.

---

### 10.2 Certificate Profiles

**Test 10.2.1 — List profiles**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/profiles" | jq '{total, ids: [.items[].id]}'
```

**Expected:** `total` = 4 (seed profiles).
**PASS if** total = 4. **FAIL** otherwise.

---

**Test 10.2.2 — Create profile with crypto constraints**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "prof-test", "name": "Test Profile", "allowed_key_algorithms": ["RSA", "ECDSA"], "min_key_size": 2048, "max_ttl_hours": 8760}' \
  $SERVER/api/v1/profiles | jq '{id, name, allowed_key_algorithms}'
```

**What:** Creates a profile with key type constraints and max TTL.
**Why:** Profiles enforce crypto policy — only approved algorithms and key sizes can be used.
**Expected:** HTTP 201 with crypto constraint fields.
**PASS if** HTTP 201 and `allowed_key_algorithms` matches. **FAIL** otherwise.

---

**Test 10.2.3 — Get profile**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/profiles/prof-test" | jq '{id, name}'
```

**Expected:** HTTP 200.
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 10.2.4 — Update profile**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X PUT -H "$AUTH" -H "$CT" \
  -d '{"name": "Updated Test Profile", "max_ttl_hours": 720}' \
  $SERVER/api/v1/profiles/prof-test | jq '{name, max_ttl_hours}'
```

**Expected:** HTTP 200. Fields updated.
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 10.2.5 — Delete profile**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/profiles/prof-test"
```

**Expected:** HTTP 204.
**PASS if** HTTP 204. **FAIL** otherwise.

---

**Test 10.2.6 — Short-lived profile exists (TTL < 1 hour)**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/profiles/prof-short-lived" | jq '{id, name, max_ttl_hours, is_short_lived}'
```

**What:** Verifies the short-lived profile is configured with TTL < 1 hour.
**Why:** Short-lived certs skip CRL/OCSP — expiry IS revocation. The profile must be correctly flagged.
**Expected:** `max_ttl_hours` < 1 or `is_short_lived` = true.
**PASS if** profile exists and indicates short-lived. **FAIL** if missing.

---

## Part 11: Ownership, Teams & Agent Groups

**What this validates:** Organizational structure — teams, certificate owners, and dynamic agent grouping.

**Why it matters:** Ownership drives notification routing (who gets alerted when a cert expires). Agent groups enable fleet-wide policy application. Without these, operators can't manage at scale.

### 11.1 Teams

**Test 11.1.1 — List teams**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/teams" | jq '{total, ids: [.items[].id]}'
```

**Expected:** `total` = 5 (seed teams).
**PASS if** total = 5. **FAIL** otherwise.

---

**Test 11.1.2 — Team CRUD cycle**

```bash
# Create
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "t-test", "name": "Test Team"}' \
  $SERVER/api/v1/teams | jq '{id, name}'

# Get
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/teams/t-test" | jq '{id}'

# Update
curl -s -w "\nHTTP %{http_code}\n" -X PUT -H "$AUTH" -H "$CT" \
  -d '{"name": "Updated Test Team"}' \
  $SERVER/api/v1/teams/t-test | jq '{name}'

# Delete
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/teams/t-test"
```

**Expected:** Create = 201, Get = 200, Update = 200, Delete = 204.
**PASS if** all four operations return expected codes. **FAIL** if any fails.

---

### 11.2 Owners

**Test 11.2.1 — Owner CRUD with team assignment**

```bash
# Create owner with team
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "o-test", "name": "Test Owner", "email": "test@example.com", "team_id": "t-platform"}' \
  $SERVER/api/v1/owners | jq '{id, email, team_id}'
```

**What:** Creates an owner assigned to a team.
**Why:** Owner email is used for notification routing. Team assignment enables team-level queries.
**Expected:** HTTP 201. `team_id` = "t-platform".
**PASS if** HTTP 201 and team_id matches. **FAIL** otherwise.

---

**Test 11.2.2 — Get, update, delete owner**

```bash
# Get
curl -s -H "$AUTH" "$SERVER/api/v1/owners/o-test" | jq '{id, email}'
# Update
curl -s -X PUT -H "$AUTH" -H "$CT" -d '{"name": "Updated Owner"}' $SERVER/api/v1/owners/o-test | jq '{name}'
# Delete
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/owners/o-test"
```

**Expected:** Get = 200, Update = 200, Delete = 204.
**PASS if** all succeed. **FAIL** otherwise.

---

### 11.3 Agent Groups

**Test 11.3.1 — List agent groups**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/agent-groups" | jq '{total, ids: [.items[].id]}'
```

**Expected:** `total` = 5 (seed groups).
**PASS if** total = 5. **FAIL** otherwise.

---

**Test 11.3.2 — Create agent group with dynamic criteria**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "ag-test-group", "name": "Test Group", "match_os": "linux", "match_architecture": "amd64", "match_ip_cidr": "10.0.0.0/8"}' \
  $SERVER/api/v1/agent-groups | jq '{id, name, match_os}'
```

**What:** Creates a group with OS, architecture, and CIDR matching criteria.
**Why:** Dynamic groups automatically include agents matching the criteria — no manual membership management.
**Expected:** HTTP 201 with criteria fields.
**PASS if** HTTP 201. **FAIL** otherwise.

---

**Test 11.3.3 — Agent group membership endpoint**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/agent-groups/ag-linux-prod/members" | jq .
```

**What:** Lists agents that match the group's criteria.
**Why:** Operators need to see which agents fall into each group for policy assignment.
**Expected:** HTTP 200 with array of matching agents.
**PASS if** HTTP 200. **FAIL** if 500.

---

**Test 11.3.4 — Delete agent group returns 204**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/agent-groups/ag-test-group"
```

**Expected:** HTTP 204.
**PASS if** HTTP 204. **FAIL** if 200 (wrong status code for delete — regression test).

---

## Part 12: Notifications

**What this validates:** Notification creation, listing, and read status management.

**Why it matters:** Notifications are how certctl tells operators about important events (expiring certs, failed renewals, revocations). If notifications are lost or unreadable, operators miss critical events.

### 12.1 Notification Queries

**Test 12.1.1 — List notifications with pagination**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/notifications?per_page=5" | jq '{total, items_count: (.items | length), first_type: .items[0].type}'
```

**What:** Lists notifications with pagination.
**Expected:** `total` ≥ 6 (seed notifications). Items present.
**PASS if** HTTP 200 and total ≥ 1. **FAIL** if 500 or total = 0.

---

**Test 12.1.2 — Get single notification**

```bash
NOTIF_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/notifications?per_page=1" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/notifications/$NOTIF_ID" | jq '{id, type, read}'
```

**What:** Fetches a specific notification by ID.
**Expected:** HTTP 200 with notification detail including `type` and `read` fields.
**PASS if** HTTP 200 and fields present. **FAIL** otherwise.

---

**Test 12.1.3 — Mark notification as read**

```bash
NOTIF_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/notifications?per_page=1" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" $SERVER/api/v1/notifications/$NOTIF_ID/read
```

**What:** Marks a notification as read.
**Why:** Read/unread state lets operators track which notifications they've acknowledged.
**Expected:** HTTP 200.
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 12.1.4 — Mark already-read notification (idempotent)**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" $SERVER/api/v1/notifications/$NOTIF_ID/read
```

**What:** Marks the same notification as read again.
**Why:** Should be idempotent — marking an already-read notification shouldn't error.
**Expected:** HTTP 200.
**PASS if** HTTP 200. **FAIL** if 409 or 500.

---

**Test 12.1.5 — Get nonexistent notification**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/notifications/notif-nonexistent"
```

**Expected:** HTTP 404.
**PASS if** HTTP 404. **FAIL** if 200 or 500.

---

**Test 12.1.6 — Verify notification created from revocation**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/notifications?per_page=20" | jq '[.items[] | select(.type == "revocation" or .type == "certificate_revoked")] | length'
```

**What:** Checks that revocation events from Part 5 generated notifications.
**Why:** Revocation without notification means nobody knows a cert was revoked — defeating the purpose.
**Expected:** Count ≥ 1.
**PASS if** count ≥ 1. **FAIL** if 0.

---

## Part 13: Observability

**What this validates:** Dashboard stats, JSON/Prometheus metrics, and structured logging — the operator's visibility into system health.

**Why it matters:** Without observability, operators are flying blind. They can't tell if renewals are succeeding, how many certs are expiring, or whether the system is healthy.

### 13.1 Stats Endpoints

**Test 13.1.1 — Dashboard summary**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/stats/summary" | jq .
```

**What:** Fetches the high-level dashboard summary.
**Why:** This powers the four stat cards on the GUI dashboard.
**Expected:** HTTP 200 with fields: `total_certificates`, `active_certificates`, `expiring_certificates`, `expired_certificates`.
**PASS if** HTTP 200 and all four fields present with numeric values. **FAIL** otherwise.

---

**Test 13.1.2 — Certificates by status**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/stats/certificates-by-status" | jq .
```

**What:** Returns certificate count broken down by status.
**Why:** Powers the donut chart in the GUI. Each status (Active, Expiring, Expired, Revoked) should have a count.
**Expected:** HTTP 200 with array of `{status, count}` objects.
**PASS if** HTTP 200 and array contains status breakdowns. **FAIL** otherwise.

---

**Test 13.1.3 — Expiration timeline**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/stats/expiration-timeline?days=90" | jq .
```

**What:** Returns weekly expiration buckets for the next 90 days.
**Why:** Powers the expiration heatmap chart. Operators need to see when the next wave of renewals is due.
**Expected:** HTTP 200 with array of time-bucketed data points.
**PASS if** HTTP 200 with data array. **FAIL** otherwise.

---

**Test 13.1.4 — Job trends**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/stats/job-trends?days=30" | jq .
```

**What:** Returns job success/failure trends for the last 30 days.
**Expected:** HTTP 200 with trend data points.
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 13.1.5 — Issuance rate**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/stats/issuance-rate?days=30" | jq .
```

**What:** Returns certificate issuance rate over time.
**Expected:** HTTP 200 with rate data.
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 13.1.6 — Stats with invalid days parameter**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/stats/expiration-timeline?days=abc"
```

**What:** Sends an invalid non-numeric `days` parameter.
**Why:** Should default to a reasonable value or return 400 — not crash.
**Expected:** HTTP 200 (with default days) or HTTP 400.
**PASS if** HTTP 200 or 400. **FAIL** if 500.

---

### 13.2 JSON Metrics

**Test 13.2.1 — JSON metrics endpoint**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/metrics" | jq '{gauges: (.gauges | keys), counters: (.counters | keys), uptime_seconds}'
```

**What:** Fetches the JSON metrics endpoint.
**Why:** This is the machine-readable metrics format for custom integrations and monitoring.
**Expected:** HTTP 200. `gauges` contains certificate/agent metrics, `counters` contains job metrics, `uptime_seconds` > 0.
**PASS if** HTTP 200, gauges and counters present, uptime > 0. **FAIL** otherwise.

---

**Test 13.2.2 — Metric values are non-negative**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/metrics" | jq '[.gauges | to_entries[] | select(.value < 0)] | length'
```

**What:** Checks all gauge values are ≥ 0.
**Why:** Negative certificate counts or agent counts indicate a counting bug.
**Expected:** Length = 0 (no negative values).
**PASS if** count = 0. **FAIL** if any negative values found.

---

**Test 13.2.3 — Uptime is positive**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/metrics" | jq '.uptime_seconds'
```

**What:** Verifies the server reports positive uptime.
**Expected:** Value > 0.
**PASS if** uptime > 0. **FAIL** if 0 or negative.

---

### 13.3 Prometheus Metrics

**Test 13.3.1 — Prometheus content type**

```bash
curl -s -D - -o /dev/null -H "$AUTH" "$SERVER/api/v1/metrics/prometheus" | grep -i "content-type"
```

**What:** Verifies the Prometheus endpoint returns the correct Content-Type.
**Why:** Prometheus scrapers validate Content-Type. Wrong type = scrape failure = no monitoring.
**Expected:** `Content-Type: text/plain` (or `text/plain; version=0.0.4`).
**PASS if** Content-Type contains `text/plain`. **FAIL** otherwise.

---

**Test 13.3.2 — Prometheus output contains HELP lines**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/metrics/prometheus" | grep -c "^# HELP"
```

**What:** Counts `# HELP` comment lines (metric descriptions).
**Why:** HELP lines are required by the Prometheus exposition format. Missing = non-compliant.
**Expected:** Count ≥ 11 (one per metric).
**PASS if** count ≥ 11. **FAIL** if 0.

---

**Test 13.3.3 — Prometheus output contains TYPE lines**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/metrics/prometheus" | grep -c "^# TYPE"
```

**What:** Counts `# TYPE` annotations (gauge/counter declarations).
**Expected:** Count ≥ 11.
**PASS if** count ≥ 11. **FAIL** if 0.

---

**Test 13.3.4 — All 11 Prometheus metrics present**

```bash
METRICS=$(curl -s -H "$AUTH" "$SERVER/api/v1/metrics/prometheus")
for m in certctl_certificate_total certctl_certificate_active certctl_certificate_expiring_soon certctl_certificate_expired certctl_certificate_revoked certctl_agent_total certctl_agent_online certctl_job_pending certctl_job_completed_total certctl_job_failed_total certctl_uptime_seconds; do
  echo -n "$m: "
  echo "$METRICS" | grep -c "^$m "
done
```

**What:** Verifies all 11 documented Prometheus metrics are present in the output.
**Why:** Missing metrics mean missing dashboard panels in Grafana. Each metric was chosen for operational value.
**Expected:** Each metric reports count = 1 (present).
**PASS if** all 11 metrics show count = 1. **FAIL** if any shows 0.

---

**Test 13.3.5 — Prometheus metric values are parseable numbers**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/metrics/prometheus" | grep -v "^#" | grep -v "^$" | awk '{print $2}' | while read val; do
  echo "$val" | grep -qE '^[0-9]+(\.[0-9]+)?$' || echo "INVALID: $val"
done
```

**What:** Verifies all metric values are valid numbers (not NaN, not strings).
**Why:** Non-numeric values cause Prometheus scrape errors and break dashboards.
**Expected:** No "INVALID" lines printed.
**PASS if** no invalid values found. **FAIL** if any invalid values.

---

**Test 13.3.6 — Method not allowed on metrics (POST)**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" $SERVER/api/v1/metrics
```

**What:** Sends POST to a GET-only endpoint.
**Expected:** HTTP 405 (Method Not Allowed).
**PASS if** HTTP 405. **FAIL** if 200 or 500.

---

## Part 14: Audit Trail

**What this validates:** The immutable audit trail — listing, filtering, and verifying that API actions generate audit entries.

**Why it matters:** The audit trail is a compliance requirement (SOC 2, PCI-DSS). If events aren't recorded, the organization can't prove who did what and when.

### 14.1 Audit Queries

**Test 14.1.1 — List audit events**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/audit?per_page=5" | jq '{total, items_count: (.items | length)}'
```

**What:** Lists audit events with pagination.
**Expected:** `total` > 0 (seed data + actions from earlier tests). Items present.
**PASS if** HTTP 200 and total > 0. **FAIL** if 500 or total = 0.

---

**Test 14.1.2 — Get single audit event**

```bash
EVENT_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/audit?per_page=1" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/audit/$EVENT_ID" | jq '{id, action, actor, resource_type}'
```

**What:** Fetches a specific audit event by ID.
**Expected:** HTTP 200 with event detail including `action`, `actor`, `resource_type`.
**PASS if** HTTP 200 and fields present. **FAIL** otherwise.

---

**Test 14.1.3 — Filter audit by time range**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/audit?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z" | jq '{total}'
```

**What:** Filters audit events to a specific time range.
**Expected:** HTTP 200 with `total` > 0.
**PASS if** total > 0 for the current year range. **FAIL** if 0.

---

**Test 14.1.4 — Filter audit by actor**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/audit?actor=system" | jq '{total}'
```

**What:** Filters audit events by actor (system-generated events).
**Expected:** HTTP 200.
**PASS if** HTTP 200. **FAIL** if 500.

---

**Test 14.1.5 — Filter audit by resource type**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/audit?resource_type=certificate" | jq '{total}'
```

**What:** Filters to certificate-related audit events only.
**Expected:** HTTP 200 with total > 0.
**PASS if** HTTP 200 and total > 0. **FAIL** otherwise.

---

**Test 14.1.6 — Filter audit by action**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/audit?action=certificate.created" | jq '{total}'
```

**What:** Filters to a specific action type.
**Expected:** HTTP 200.
**PASS if** HTTP 200. **FAIL** if 500.

---

**Test 14.1.7 — API calls create audit entries**

```bash
# Make a distinct API call
curl -s -X POST -H "$AUTH" -H "$CT" -d '{"id":"mc-audit-test","common_name":"audit.test.local"}' $SERVER/api/v1/certificates > /dev/null
# Find the audit entry
sleep 2
curl -s -H "$AUTH" "$SERVER/api/v1/audit?per_page=5" | jq '[.items[] | select(.resource_id == "mc-audit-test")] | length'
```

**What:** Creates a certificate and verifies an audit event was recorded for it.
**Why:** Every API mutation must produce an audit entry. This confirms the audit middleware is wired correctly.
**Expected:** Count ≥ 1 (at least one audit event for the new cert).
**PASS if** count ≥ 1. **FAIL** if 0.

---

**Test 14.1.8 — Audit immutability (no PUT/DELETE)**

```bash
EVENT_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/audit?per_page=1" | jq -r '.items[0].id')
echo "=== PUT ==="
curl -s -w "HTTP %{http_code}\n" -X PUT -H "$AUTH" -H "$CT" -d '{}' "$SERVER/api/v1/audit/$EVENT_ID"
echo "=== DELETE ==="
curl -s -w "HTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/audit/$EVENT_ID"
```

**What:** Attempts to modify or delete an audit event.
**Why:** Audit trails must be immutable for compliance. If you can edit or delete events, the trail is unreliable.
**Expected:** Both return HTTP 405 (Method Not Allowed).
**PASS if** both return 405. **FAIL** if either returns 200 or 204.

---

## Part 15: Certificate Discovery (Filesystem + Network)

**What this validates:** Filesystem discovery (agents scanning for existing certs), network discovery (server-side TLS scanning), and the triage workflow.

**Why it matters:** Organizations often have thousands of unmanaged certificates scattered across servers. Discovery finds them so they can be brought under management.

### 15.1 Filesystem Discovery

**Test 15.1.1 — Submit discovery report**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{
    "agent_id": "ag-web-prod",
    "certificates": [{
      "common_name": "discovered.test.local",
      "serial_number": "ABC123",
      "issuer_dn": "CN=Test CA",
      "subject_dn": "CN=discovered.test.local",
      "not_before": "2026-01-01T00:00:00Z",
      "not_after": "2027-01-01T00:00:00Z",
      "key_algorithm": "RSA",
      "key_size": 2048,
      "fingerprint_sha256": "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
      "source_path": "/etc/ssl/certs/discovered.pem"
    }]
  }' \
  $SERVER/api/v1/agents/ag-web-prod/discoveries | jq .
```

**What:** Agent submits a filesystem scan report with one discovered certificate.
**Why:** This is the primary data ingestion path for discovery.
**Expected:** HTTP 200.
**PASS if** HTTP 200. **FAIL** if 400 or 500.

---

**Test 15.1.2 — Submit report with multiple certificates**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{
    "agent_id": "ag-web-prod",
    "certificates": [
      {"common_name": "multi1.test.local", "serial_number": "M001", "issuer_dn": "CN=CA", "subject_dn": "CN=multi1.test.local", "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "key_algorithm": "ECDSA", "key_size": 256, "fingerprint_sha256": "1111111111111111111111111111111111111111111111111111111111111111", "source_path": "/certs/multi1.pem"},
      {"common_name": "multi2.test.local", "serial_number": "M002", "issuer_dn": "CN=CA", "subject_dn": "CN=multi2.test.local", "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "key_algorithm": "RSA", "key_size": 4096, "fingerprint_sha256": "2222222222222222222222222222222222222222222222222222222222222222", "source_path": "/certs/multi2.pem"}
    ]
  }' \
  $SERVER/api/v1/agents/ag-web-prod/discoveries
```

**Expected:** HTTP 200. Both certificates stored.
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 15.1.3 — Duplicate fingerprint deduplication**

```bash
# Submit the same fingerprint again
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{
    "agent_id": "ag-web-prod",
    "certificates": [{"common_name": "discovered.test.local", "serial_number": "ABC123", "issuer_dn": "CN=Test CA", "subject_dn": "CN=discovered.test.local", "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "key_algorithm": "RSA", "key_size": 2048, "fingerprint_sha256": "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344", "source_path": "/etc/ssl/certs/discovered.pem"}]
  }' \
  $SERVER/api/v1/agents/ag-web-prod/discoveries
# Check total count hasn't doubled
curl -s -H "$AUTH" "$SERVER/api/v1/discovered-certificates" | jq '.total'
```

**What:** Submits the same certificate fingerprint a second time.
**Why:** Dedup by fingerprint prevents the same physical cert from creating multiple discovery records.
**Expected:** HTTP 200 on resubmission. Total count doesn't increase (upsert, not insert).
**PASS if** total is same as before resubmission. **FAIL** if total increased.

---

**Test 15.1.4 — List discovered certificates**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/discovered-certificates" | jq '{total, items_count: (.items | length)}'
```

**Expected:** HTTP 200. `total` ≥ 3 (from tests above).
**PASS if** total ≥ 3. **FAIL** otherwise.

---

**Test 15.1.5 — Filter by status: Unmanaged**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/discovered-certificates?status=Unmanaged" | jq '{total}'
```

**Expected:** HTTP 200. All items have Unmanaged status.
**PASS if** HTTP 200 and total > 0. **FAIL** if 500.

---

**Test 15.1.6 — Filter by agent_id**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/discovered-certificates?agent_id=ag-web-prod" | jq '{total}'
```

**Expected:** HTTP 200.
**PASS if** HTTP 200. **FAIL** if 500.

---

**Test 15.1.7 — Get discovered certificate detail**

```bash
DISC_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/discovered-certificates?per_page=1" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/discovered-certificates/$DISC_ID" | jq '{id, common_name, status, fingerprint_sha256}'
```

**Expected:** HTTP 200 with full discovery record.
**PASS if** HTTP 200 and all fields present. **FAIL** otherwise.

---

**Test 15.1.8 — Claim discovered certificate**

```bash
DISC_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/discovered-certificates?status=Unmanaged&per_page=1" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"managed_certificate_id": "mc-api-prod"}' \
  $SERVER/api/v1/discovered-certificates/$DISC_ID/claim
```

**What:** Claims (links) a discovered cert to an existing managed certificate.
**Why:** This is how operators bring discovered certs under certctl management.
**Expected:** HTTP 200. Status changes to "Managed".
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 15.1.9 — Dismiss discovered certificate**

```bash
DISC_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/discovered-certificates?status=Unmanaged&per_page=1" | jq -r '.items[0].id')
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"reason": "Known self-signed test cert"}' \
  $SERVER/api/v1/discovered-certificates/$DISC_ID/dismiss
```

**What:** Dismisses a discovered cert from the triage queue.
**Why:** Not every discovered cert needs management. Dismiss removes it from the "needs attention" view.
**Expected:** HTTP 200. Status changes to "Dismissed".
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 15.1.10 — List discovery scans**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/discovery-scans" | jq '{total}'
```

**What:** Lists discovery scan history.
**Expected:** HTTP 200 with scan records (from the submissions above).
**PASS if** HTTP 200 and total ≥ 1. **FAIL** otherwise.

---

**Test 15.1.11 — Discovery summary**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/discovery-summary" | jq .
```

**What:** Returns aggregate counts by discovery status.
**Expected:** HTTP 200 with counts for Unmanaged, Managed, Dismissed.
**PASS if** HTTP 200 and status counts present. **FAIL** otherwise.

---

### 15.2 Network Discovery

**Test 15.2.1 — List network scan targets (seed data)**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/network-scan-targets" | jq '{total, ids: [.items[].id]}'
```

**What:** Lists seed network scan targets.
**Expected:** `total` = 3 (nst-dc1-web, nst-dc2-apps, nst-dmz).
**PASS if** total = 3 and all 3 IDs present. **FAIL** otherwise.

---

**Test 15.2.2 — Create network scan target**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "nst-test", "name": "Test Scan Target", "cidrs": ["192.168.1.0/24"], "ports": [443, 8443], "scan_interval_hours": 12}' \
  $SERVER/api/v1/network-scan-targets | jq '{id, name, cidrs, ports}'
```

**What:** Creates a new network scan target with CIDR range and ports.
**Expected:** HTTP 201 with all fields.
**PASS if** HTTP 201 and `cidrs` contains "192.168.1.0/24". **FAIL** otherwise.

---

**Test 15.2.3 — Get scan target detail**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/network-scan-targets/nst-test" | jq '{id, cidrs, ports}'
```

**Expected:** HTTP 200 with matching fields.
**PASS if** HTTP 200. **FAIL** otherwise.

---

**Test 15.2.4 — Update scan target**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X PUT -H "$AUTH" -H "$CT" \
  -d '{"name": "Updated Target", "cidrs": ["192.168.1.0/24", "10.0.0.0/24"], "ports": [443]}' \
  $SERVER/api/v1/network-scan-targets/nst-test | jq '{name, cidrs}'
```

**Expected:** HTTP 200. `cidrs` now has 2 entries.
**PASS if** HTTP 200 and cidrs updated. **FAIL** otherwise.

---

**Test 15.2.5 — Delete scan target**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/network-scan-targets/nst-test"
```

**Expected:** HTTP 204.
**PASS if** HTTP 204. **FAIL** otherwise.

---

**Test 15.2.6 — Trigger manual scan**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{}' \
  $SERVER/api/v1/network-scan-targets/nst-dc1-web/scan
```

**What:** Triggers an immediate network scan on a target.
**Why:** Operators need to scan on-demand, not just on the 6h schedule.
**Expected:** HTTP 200 or 202.
**PASS if** HTTP 200/202. **FAIL** if 500.

---

**Test 15.2.7 — Invalid CIDR validation**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "nst-bad", "name": "Bad Target", "cidrs": ["not-a-cidr"], "ports": [443]}' \
  $SERVER/api/v1/network-scan-targets
```

**What:** Attempts to create a scan target with invalid CIDR notation.
**Why:** Bad CIDRs would cause the scanner to crash or scan random addresses.
**Expected:** HTTP 400 with validation error.
**PASS if** HTTP 400. **FAIL** if 201.

---

## Part 16: Enhanced Query API

**What this validates:** Advanced query features — sparse fields, sorting, cursor pagination, time-range filters, and combined filters.

**Why it matters:** These features reduce API bandwidth, enable efficient pagination for large inventories, and power the GUI's advanced filtering.

**Test 16.1.1 — Sparse fields: only requested fields returned**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?fields=id,common_name&per_page=3" | jq '.items[0] | keys'
```

**What:** Requests only `id` and `common_name` fields.
**Expected:** Keys array contains only `["common_name", "id"]`.
**PASS if** only requested fields present. **FAIL** if additional fields.

---

**Test 16.1.2 — Sort ascending: commonName**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?sort=commonName&per_page=5" | jq '[.items[].common_name]'
```

**Expected:** Names in ascending alphabetical order.
**PASS if** sorted A→Z. **FAIL** if unsorted.

---

**Test 16.1.3 — Sort descending: notAfter**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?sort=-notAfter&per_page=5" | jq '[.items[].not_after]'
```

**Expected:** Dates in descending order.
**PASS if** sorted newest→oldest. **FAIL** if unsorted.

---

**Test 16.1.4 — Sort by invalid field**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/certificates?sort=hackMe"
```

**What:** Attempts to sort by a field not in the whitelist.
**Why:** Sorting by arbitrary columns could be a SQL injection vector or expose internal fields.
**Expected:** HTTP 400 (invalid sort field) or HTTP 200 (ignored, default sort applied).
**PASS if** HTTP 400 or 200 with default ordering. **FAIL** if 500.

---

**Test 16.1.5 — Cursor pagination first page**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?page_size=3" | jq '{next_cursor, items_count: (.items | length)}'
```

**Expected:** `next_cursor` present, `items_count` = 3.
**PASS if** next_cursor non-null. **FAIL** if missing.

---

**Test 16.1.6 — Cursor pagination second page**

```bash
CURSOR=$(curl -s -H "$AUTH" "$SERVER/api/v1/certificates?page_size=3" | jq -r '.next_cursor')
FIRST_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/certificates?page_size=3" | jq -r '.items[0].id')
SECOND_PAGE_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/certificates?page_size=3&cursor=$CURSOR" | jq -r '.items[0].id')
echo "Page 1 first: $FIRST_ID, Page 2 first: $SECOND_PAGE_ID"
```

**Expected:** Different IDs on page 1 vs page 2.
**PASS if** IDs differ. **FAIL** if same.

---

**Test 16.1.7 — Time-range: expires_before**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?expires_before=2027-01-01T00:00:00Z" | jq '{total}'
```

**Expected:** HTTP 200 with total > 0.
**PASS if** total > 0. **FAIL** otherwise.

---

**Test 16.1.8 — Time-range: created_after**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?created_after=2025-01-01T00:00:00Z" | jq '{total}'
```

**Expected:** HTTP 200 with total > 0.
**PASS if** total > 0. **FAIL** otherwise.

---

**Test 16.1.9 — Combined filters**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?status=Active&sort=-notAfter&fields=id,common_name,status&per_page=5" | jq '{total, items_count: (.items | length), first_keys: (.items[0] | keys)}'
```

**What:** Combines status filter + sort + sparse fields + pagination in one query.
**Why:** Real-world API usage combines multiple features. They must work together, not interfere.
**Expected:** All items Active, sorted by notAfter desc, only requested fields present, max 5 items.
**PASS if** all constraints applied simultaneously. **FAIL** if any constraint ignored.

---

## Part 17: CLI Tool

**What this validates:** The `certctl-cli` binary — all subcommands, output formats, flag overrides, and error handling.

**Why it matters:** The CLI is how DevOps engineers interact with certctl in scripts, CI/CD, and terminals. If CLI commands are broken, automation pipelines fail.

### 17.1 Setup

```bash
export CERTCTL_SERVER_URL=$SERVER
export CERTCTL_API_KEY=$API_KEY
```

### 17.2 Certificate Commands

**Test 17.2.1 — List certificates (table format)**

```bash
./certctl-cli certs list
```

**What:** Lists certificates in the default table format.
**Expected:** Tabular output with columns (ID, Common Name, Status, etc.). At least 15 rows.
**PASS if** table renders with data. **FAIL** if error or empty.

---

**Test 17.2.2 — List certificates (JSON format)**

```bash
./certctl-cli --format json certs list
```

**What:** Lists certificates in JSON format.
**Expected:** Valid JSON array output.
**PASS if** valid JSON with certificate data. **FAIL** if parse error.

---

**Test 17.2.3 — Get specific certificate**

```bash
./certctl-cli certs get mc-api-prod
```

**What:** Fetches a specific cert by ID.
**Expected:** Certificate detail for mc-api-prod displayed.
**PASS if** output shows mc-api-prod details. **FAIL** if error.

---

**Test 17.2.4 — Get nonexistent certificate**

```bash
./certctl-cli certs get mc-nonexistent 2>&1
```

**What:** Fetches a cert that doesn't exist.
**Expected:** Error message (not a stack trace).
**PASS if** clean error message. **FAIL** if panic or no output.

---

**Test 17.2.5 — Renew certificate**

```bash
./certctl-cli certs renew mc-pay-prod
```

**What:** Triggers renewal via CLI.
**Expected:** Success message or job ID.
**PASS if** success output. **FAIL** if error.

---

**Test 17.2.6 — Revoke certificate with reason**

```bash
./certctl-cli certs revoke mc-auth-prod --reason superseded
```

**What:** Revokes via CLI with an RFC 5280 reason.
**Expected:** Success message indicating revocation.
**PASS if** success output. **FAIL** if error.

---

### 17.3 Agent & Job Commands

**Test 17.3.1 — List agents**

```bash
./certctl-cli agents list
```

**Expected:** Table with 5+ agents.
**PASS if** agent data displayed. **FAIL** if error.

---

**Test 17.3.2 — List jobs**

```bash
./certctl-cli jobs list
```

**Expected:** Table with job data.
**PASS if** job data displayed. **FAIL** if error.

---

### 17.4 System Commands

**Test 17.4.1 — Server status/health**

```bash
./certctl-cli status
```

**What:** Shows server health and summary stats.
**Expected:** Health status and cert/agent counts.
**PASS if** health info displayed. **FAIL** if connection error.

---

**Test 17.4.2 — CLI version**

```bash
./certctl-cli version
```

**Expected:** Version string (e.g., "certctl-cli version 0.1.0").
**PASS if** version displayed. **FAIL** if error.

---

### 17.5 Bulk Import

**Test 17.5.1 — Import single PEM file**

```bash
# Create a test PEM file
cat > /tmp/test-import.pem << 'CERTEOF'
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALRiMLAh++nfMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBaMBQxEjAQBgNVBAMM
CWltcG9ydC5tZTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96lXXvVJX5K+d4B
bJGjzyy/ET0X/D/gHfJCwA7RVbgWBZaDJpME5Iq7VB9rkDx0RGdVdMNVKxMJkjD
P4RnAgMBAAEwDQYJKoZIhvcNAQELBQADQQBxqT7OQHV1ZhEYOJxEkDvFqHFNeUP
IbN7t5YfSZmHnXjyNMGQeFnvHlJjOOPHHnpfp2KX7rqBLPrZnFJnHNFk
-----END CERTIFICATE-----
CERTEOF
./certctl-cli import /tmp/test-import.pem
```

**What:** Imports a PEM file containing one certificate.
**Expected:** Success message with import count.
**PASS if** import succeeds. **FAIL** if parse error.

---

### 17.6 Flag Overrides

**Test 17.6.1 — --server flag overrides env var**

```bash
./certctl-cli --server http://localhost:8443 status
```

**Expected:** Uses the flag value, not the env var.
**PASS if** status displayed. **FAIL** if connection error.

---

**Test 17.6.2 — --api-key flag overrides env var**

```bash
./certctl-cli --api-key "change-me-in-production" status
```

**Expected:** Uses the flag API key.
**PASS if** status displayed. **FAIL** if auth error.

---

**Test 17.6.3 — Missing server URL produces error**

```bash
unset CERTCTL_SERVER_URL
./certctl-cli certs list 2>&1
export CERTCTL_SERVER_URL=$SERVER  # Restore
```

**What:** Runs CLI with no server URL configured.
**Expected:** Error message about missing server URL (or defaults to localhost).
**PASS if** meaningful error or default fallback. **FAIL** if panic.

---

## Part 18: MCP Server

**What this validates:** The Model Context Protocol server — binary build, startup, tool registration, and tool invocation via JSON-RPC over stdio.

**Why it matters:** MCP is the AI adoption driver. If developers can manage certificates from Claude or Cursor, certctl becomes part of their daily workflow.

### 18.1 Build & Startup

**Test 18.1.1 — Binary builds successfully**

```bash
go build -o certctl-mcp ./cmd/mcp-server/... && echo "BUILD OK"
```

**Expected:** "BUILD OK" — no compile errors.
**PASS if** binary created. **FAIL** if compile error.

---

**Test 18.1.2 — Startup with valid env vars**

```bash
timeout 3 bash -c 'CERTCTL_SERVER_URL=$SERVER CERTCTL_API_KEY=$API_KEY ./certctl-mcp 2>&1' || true
```

**What:** Starts the MCP server and captures stderr output for 3 seconds.
**Why:** The server should print its version and backend URL on startup without errors.
**Expected:** Output contains version info. No panic or fatal error.
**PASS if** no errors in output. **FAIL** if panic or fatal.

---

**Test 18.1.3 — Missing CERTCTL_SERVER_URL behavior**

```bash
timeout 3 bash -c 'CERTCTL_API_KEY=$API_KEY ./certctl-mcp 2>&1' || true
```

**What:** Starts without a server URL.
**Expected:** Either defaults to localhost:8443 or prints an error. No panic.
**PASS if** no panic. **FAIL** if panic/crash.

---

### 18.2 Tool Registration

**Test 18.2.1 — Tool count verification (78 tools)**

```bash
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | \
  CERTCTL_SERVER_URL=$SERVER CERTCTL_API_KEY=$API_KEY timeout 5 ./certctl-mcp 2>/dev/null | \
  jq '.result.tools | length'
```

**What:** Sends a JSON-RPC `tools/list` request via stdin and counts registered tools.
**Why:** All 78 API endpoints must be exposed as MCP tools. Missing tools mean missing LLM capabilities.
**Expected:** `78`
**PASS if** count = 78. **FAIL** if different.

---

**Test 18.2.2 — All 16 resource domains present**

```bash
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | \
  CERTCTL_SERVER_URL=$SERVER CERTCTL_API_KEY=$API_KEY timeout 5 ./certctl-mcp 2>/dev/null | \
  jq '[.result.tools[].name | split("_")[0]] | unique | sort'
```

**What:** Extracts the domain prefix from each tool name and checks all 16 domains are represented.
**Expected:** Array includes prefixes for certificates, crl, issuers, targets, agents, jobs, policies, profiles, teams, owners, agent groups, audit, notifications, stats, metrics, health.
**PASS if** all 16 domains present. **FAIL** if any missing.

---

### 18.3 Tool Invocation

**Test 18.3.1 — List certificates via MCP**

```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_certificates","arguments":{}},"id":2}' | \
  CERTCTL_SERVER_URL=$SERVER CERTCTL_API_KEY=$API_KEY timeout 10 ./certctl-mcp 2>/dev/null | \
  jq '.result'
```

**What:** Invokes the `list_certificates` tool via JSON-RPC.
**Why:** Tool registration is necessary but not sufficient — the tool must actually proxy to the HTTP API and return data.
**Expected:** Result contains certificate data from the running server.
**PASS if** result contains certificate data. **FAIL** if error or empty.

---

**Test 18.3.2 — Get specific certificate via MCP**

```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_certificate","arguments":{"id":"mc-api-prod"}},"id":3}' | \
  CERTCTL_SERVER_URL=$SERVER CERTCTL_API_KEY=$API_KEY timeout 10 ./certctl-mcp 2>/dev/null | \
  jq '.result'
```

**What:** Invokes `get_certificate` with a known ID.
**Expected:** Result contains mc-api-prod certificate detail.
**PASS if** result contains the cert data. **FAIL** if error.

---

## Part 19: GUI Testing

**What this validates:** The web dashboard — 19 pages of operational UI.

**Why it matters:** Operators spend 80% of their time in the GUI. If it's broken, the product is broken, regardless of how good the API is.

Open `http://localhost:8443` in a browser.

### 19.1 Authentication Flow

| Test ID | Test | Action | Expected | Pass/Fail Criteria |
|---------|------|--------|----------|-------------------|
| 19.1.1 | Login page renders | Open dashboard URL | Login page with API key input field | PASS if login form visible |
| 19.1.2 | Invalid key error | Enter "wrong-key", submit | Error message displayed | PASS if error shown, not silent failure |
| 19.1.3 | Valid key login | Enter the correct API key | Redirect to dashboard | PASS if dashboard loads with data |

### 19.2 Dashboard Page

| Test ID | Test | Action | Expected | Pass/Fail Criteria |
|---------|------|--------|----------|-------------------|
| 19.2.1 | Stat cards | View dashboard | 4 stat cards with real numbers (total, active, expiring, expired) | PASS if all 4 show non-zero values |
| 19.2.2 | Expiration heatmap | View dashboard | Heatmap chart renders with data | PASS if chart visible with bars/cells |
| 19.2.3 | Renewal trends | View dashboard | Line chart renders | PASS if chart visible |
| 19.2.4 | Status distribution | View dashboard | Donut chart renders with legend | PASS if chart visible with segments |
| 19.2.5 | Issuance rate | View dashboard | Bar chart renders | PASS if chart visible |

### 19.3 Certificates Page

| Test ID | Test | Action | Expected | Pass/Fail Criteria |
|---------|------|--------|----------|-------------------|
| 19.3.1 | Table loads | Navigate to Certificates | Table with 15+ certs | PASS if table populated |
| 19.3.2 | Multi-select | Click checkboxes | Checkboxes toggle, select-all works | PASS if selection works |
| 19.3.3 | Bulk renew | Select certs, click Renew | Jobs created, progress indicator | PASS if renew triggered |
| 19.3.4 | Bulk revoke | Select certs, click Revoke | Reason modal appears | PASS if modal with RFC 5280 reasons |

### 19.4 Certificate Detail Page

| Test ID | Test | Action | Expected | Pass/Fail Criteria |
|---------|------|--------|----------|-------------------|
| 19.4.1 | All fields | Click a certificate | All metadata fields displayed | PASS if CN, SANs, dates, status shown |
| 19.4.2 | Version history | Scroll to versions | Current badge on latest, list of versions | PASS if Current badge visible |
| 19.4.3 | Rollback button | View previous version | Rollback button on non-current versions | PASS if button visible and clickable |
| 19.4.4 | Deployment timeline | View deployment section | 4-step visual timeline | PASS if timeline renders |
| 19.4.5 | Inline policy editor | Click edit on policy section | Dropdown selectors appear, save/cancel buttons | PASS if edit mode works |
| 19.4.6 | Revoke button | Click revoke | Reason modal, status updates after | PASS if revocation completes |

### 19.5 Other Pages

| Test ID | Test | Page | Expected | Pass/Fail Criteria |
|---------|------|------|----------|-------------------|
| 19.5.1 | Target wizard | Targets → New Target | 3-step wizard (type → config → review) | PASS if all 3 steps work |
| 19.5.2 | Audit filters | Audit | Time, actor, action filters work | PASS if filters change results |
| 19.5.3 | Audit export | Audit → Export | CSV/JSON file downloads | PASS if file downloads |
| 19.5.4 | Short-lived creds | Short-Lived | Certs with TTL < 1h, countdown timers | PASS if timers count down |
| 19.5.5 | Agent list | Agents | OS/Arch column visible | PASS if metadata shown |
| 19.5.6 | Agent detail | Click agent | System Information card | PASS if OS, arch, IP shown |
| 19.5.7 | Fleet overview | Fleet Overview | OS/arch grouping charts | PASS if pie charts render |

### 19.6 Cross-Cutting

| Test ID | Test | Action | Expected | Pass/Fail Criteria |
|---------|------|--------|----------|-------------------|
| 19.6.1 | Sidebar nav | Click all sidebar links | All pages load without errors | PASS if no broken routes |
| 19.6.2 | Logout | Click logout | Returns to login screen | PASS if login page shown |
| 19.6.3 | 401 redirect | Expire/remove auth token | Auto-redirect to login | PASS if login page shown |
| 19.6.4 | Dark theme | Check page styling | Dark background, readable text | PASS if theme consistent |

---

## Part 20: Background Scheduler

**What this validates:** The 6 background scheduler loops — renewal checks, job processing, agent health, notification processing, short-lived cert expiry, and network scanning.

**Why it matters:** The scheduler is the automation engine. Without it, nothing happens automatically — certs expire unnoticed, jobs sit pending, agents go stale, notifications never fire.

> **Tip:** Open a second terminal with `docker compose logs -f certctl-server` to watch scheduler log output in real time.

**Test 20.1.1 — Scheduler startup: all 6 loops registered**

```bash
docker compose logs certctl-server 2>&1 | grep -i "scheduler\|renewal check\|job processor\|health check\|notification\|short-lived\|network scan" | head -20
```

**What:** Checks server startup logs for scheduler loop registration.
**Why:** If a loop isn't registered, that automation never runs. Catching this at startup prevents days of "why didn't my cert renew?"
**Expected:** Log lines indicating all loops started (e.g., "scheduler starting").
**PASS if** scheduler startup message present. **FAIL** if no scheduler logs.

---

**Test 20.1.2 — Job processor loop fires (30s interval)**

```bash
# Trigger a renewal to create a pending job
curl -s -X POST -H "$AUTH" -H "$CT" -d '{}' $SERVER/api/v1/certificates/mc-dash-prod/renew > /dev/null
JOB_ID=$(curl -s -H "$AUTH" "$SERVER/api/v1/jobs?type=Renewal&per_page=1" | jq -r '.items[0].id')
echo "Job: $JOB_ID"
# Wait for processor (30s interval)
sleep 45
curl -s -H "$AUTH" "$SERVER/api/v1/jobs/$JOB_ID" | jq '{status}'
```

**What:** Creates a job and waits for the job processor to pick it up.
**Why:** If the 30-second loop isn't running, jobs never execute.
**Expected:** Status is "Running" or "Completed" after 45 seconds.
**PASS if** status is not "Pending". **FAIL** if still "Pending".

---

**Test 20.1.3 — Agent health check marks offline (2m interval)**

```bash
# Stop the agent container
docker compose stop certctl-agent
# Wait for health check interval (2 minutes + buffer)
echo "Waiting 150 seconds for health check..."
sleep 150
# Check agent status
curl -s -H "$AUTH" "$SERVER/api/v1/agents/ag-web-prod" | jq '{status}'
# Restart agent
docker compose start certctl-agent
```

**What:** Stops the agent and waits for the health check to mark it offline.
**Why:** If the health check doesn't detect stale agents, operators think agents are healthy when they're actually dead.
**Expected:** Agent status changes to "Offline" (or similar inactive status).
**PASS if** status indicates offline/inactive. **FAIL** if still "Online" after 2.5 minutes.

> **Alternative (log check):** If you don't want to wait 2.5 minutes:
> ```bash
> docker compose logs certctl-server 2>&1 | grep -i "health check\|agent.*offline\|stale"
> ```

---

**Test 20.1.4 — Notification processor fires (1m interval)**

```bash
# Check notification count before
BEFORE=$(curl -s -H "$AUTH" "$SERVER/api/v1/notifications" | jq '.total')
# Trigger an event that creates a notification (revocation generates one)
curl -s -X POST -H "$AUTH" -H "$CT" -d '{"reason": "superseded"}' $SERVER/api/v1/certificates/mc-wildcard-prod/revoke > /dev/null
# Wait for notification processor
sleep 90
AFTER=$(curl -s -H "$AUTH" "$SERVER/api/v1/notifications" | jq '.total')
echo "Before: $BEFORE, After: $AFTER"
```

**What:** Triggers a revocation and waits for the notification processor to create the notification.
**Expected:** `AFTER` > `BEFORE` (new notification created).
**PASS if** notification count increased. **FAIL** if unchanged.

---

**Test 20.1.5 — Short-lived expiry check (30s interval)**

```bash
docker compose logs certctl-server 2>&1 | grep -i "short-lived expiry\|short.lived.*check\|expire.*short"
```

**What:** Checks logs for evidence the short-lived expiry loop has run.
**Why:** Short-lived certs (TTL < 1 hour) rely on this loop for status transitions.
**Expected:** At least one log line about short-lived expiry check.
**PASS if** log line found. **FAIL** if no evidence of the loop running.

---

**Test 20.1.6 — Network scanner loop (conditional on env var)**

```bash
docker compose logs certctl-server 2>&1 | grep -i "network scan"
```

**What:** Checks if the network scanner loop is registered.
**Why:** The network scan loop is conditional on `CERTCTL_NETWORK_SCAN_ENABLED=true`. By default it's disabled. If enabled, it should log its startup.
**Expected:** If `CERTCTL_NETWORK_SCAN_ENABLED=true` is set, log line present. If not set, no log line (which is correct behavior).
**PASS if** behavior matches config. **FAIL** if enabled but no logs, or disabled but scanner running.

---

**Test 20.1.7 — Renewal check loop (1h interval — log verification)**

```bash
docker compose logs certctl-server 2>&1 | grep -i "renewal check"
```

**What:** Verifies the renewal check loop has fired at least once (it runs immediately on startup).
**Expected:** Log line about renewal check (completed or in progress).
**PASS if** log evidence found. **FAIL** if none.

---

**Test 20.1.8 — Scheduler graceful stop**

```bash
docker compose stop certctl-server
docker compose logs certctl-server 2>&1 | tail -10 | grep -i "scheduler\|shutting down\|shutdown"
docker compose start certctl-server && sleep 10
```

**What:** Stops the server and checks for clean scheduler shutdown.
**Why:** Scheduler goroutines must stop cleanly. Leaked goroutines cause resource exhaustion on repeated restarts.
**Expected:** Log line containing "scheduler shutting down" or similar. No panic traces.
**PASS if** clean shutdown log present. **FAIL** if panic or missing shutdown log.

---

## Part 21: Error Handling

**What this validates:** The API's behavior when given malformed, invalid, or unexpected input.

**Why it matters:** Production systems receive garbage input constantly — from buggy clients, scanners, and attackers. Every error path must return a clean error response, not a 500 or a panic.

**Test 21.1.1 — Malformed JSON body**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{this is not json}' \
  $SERVER/api/v1/certificates
```

**What:** Sends a body that isn't valid JSON.
**Expected:** HTTP 400 with error message.
**PASS if** HTTP 400. **FAIL** if 500.

---

**Test 21.1.2 — Missing required field**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "mc-no-cn"}' \
  $SERVER/api/v1/certificates
```

**What:** Creates a certificate without the required `common_name`.
**Expected:** HTTP 400 with validation error mentioning `common_name`.
**PASS if** HTTP 400. **FAIL** if 201 (accepted invalid input).

---

**Test 21.1.3 — Method not allowed**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" $SERVER/api/v1/stats/summary
```

**What:** Sends POST to a GET-only endpoint.
**Expected:** HTTP 405.
**PASS if** HTTP 405. **FAIL** if 200 or 500.

---

**Test 21.1.4 — Invalid query parameter**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/certificates?per_page=abc"
```

**What:** Sends a non-numeric value for a numeric parameter.
**Expected:** HTTP 400 or HTTP 200 with default value (graceful degradation).
**PASS if** HTTP 400 or 200. **FAIL** if 500.

---

**Test 21.1.5 — UTF-8 in common name**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '{"id": "mc-utf8-test", "common_name": "münchen.example.de"}' \
  $SERVER/api/v1/certificates | jq '{common_name}'
```

**What:** Creates a certificate with a UTF-8 common name (German umlaut).
**Why:** Internationalized domain names are real. The API must handle non-ASCII without corruption.
**Expected:** HTTP 201 with `common_name` preserved correctly.
**PASS if** HTTP 201 and common_name matches input. **FAIL** if 400 or garbled text.

---

**Test 21.1.6 — Concurrent requests (parallel curl)**

```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "$AUTH" "$SERVER/api/v1/certificates?per_page=1" &
done
wait
```

**What:** Sends 10 parallel requests.
**Why:** Concurrency bugs (race conditions, connection pool exhaustion) only appear under parallel load.
**Expected:** All 10 requests return HTTP 200.
**PASS if** all 10 return 200. **FAIL** if any return 500.

---

**Test 21.1.7 — Server survives internal error**

```bash
# Trigger an error condition
curl -s -o /dev/null $SERVER/api/v1/certificates/$(python3 -c "print('x'*10000)")
# Server should still respond
curl -s -w "\nHTTP %{http_code}\n" $SERVER/health
```

**What:** Sends a request with an extremely long path, then verifies the server is still alive.
**Why:** One bad request must not crash the process. The recovery middleware should catch panics.
**Expected:** Health check returns HTTP 200 after the bad request.
**PASS if** health returns 200. **FAIL** if server is unresponsive.

---

**Test 21.1.8 — Empty request body on POST**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST -H "$AUTH" -H "$CT" \
  -d '' \
  $SERVER/api/v1/certificates
```

**What:** Sends an empty body to a POST endpoint.
**Expected:** HTTP 400 (missing required fields).
**PASS if** HTTP 400. **FAIL** if 500.

---

## Part 22: Performance Spot Checks

**What this validates:** Basic response time benchmarks to catch obvious performance regressions.

**Why it matters:** An API that takes 5 seconds per request is unusable. These aren't load tests — they're sanity checks.

**Test 22.1.1 — List certificates < 200ms**

```bash
TIME=$(curl -s -o /dev/null -w "%{time_total}" -H "$AUTH" "$SERVER/api/v1/certificates?per_page=15")
echo "List certs: ${TIME}s"
```

**Expected:** `time_total` < 0.200 (200ms).
**PASS if** < 200ms. **FAIL** if > 200ms.

---

**Test 22.1.2 — Stats summary < 500ms**

```bash
TIME=$(curl -s -o /dev/null -w "%{time_total}" -H "$AUTH" "$SERVER/api/v1/stats/summary")
echo "Stats summary: ${TIME}s"
```

**Expected:** < 0.500 (500ms).
**PASS if** < 500ms. **FAIL** if > 500ms.

---

**Test 22.1.3 — Metrics < 200ms**

```bash
TIME=$(curl -s -o /dev/null -w "%{time_total}" -H "$AUTH" "$SERVER/api/v1/metrics")
echo "Metrics: ${TIME}s"
```

**Expected:** < 0.200.
**PASS if** < 200ms. **FAIL** if > 200ms.

---

**Test 22.1.4 — 50 health checks < 5 seconds total**

```bash
START=$(date +%s%N)
for i in $(seq 1 50); do
  curl -s -o /dev/null $SERVER/health
done
END=$(date +%s%N)
DURATION=$(( (END - START) / 1000000 ))
echo "50 health checks: ${DURATION}ms"
```

**Expected:** Total < 5000ms (100ms average per request).
**PASS if** < 5000ms. **FAIL** if > 5000ms.

---

## Part 23: Structured Logging Verification

**What this validates:** Server logs are properly structured JSON (slog), log levels work, and request IDs propagate across log lines.

**Why it matters:** Structured logs are essential for log aggregation (ELK, Splunk, Datadog). Unstructured `fmt.Printf` lines break JSON parsers. Missing request IDs make it impossible to correlate logs for a single request.

**Test 23.1.1 — Server logs are valid JSON**

```bash
docker compose logs certctl-server 2>&1 | tail -20 | while read line; do
  echo "$line" | jq . > /dev/null 2>&1 || echo "INVALID JSON: $line"
done
```

**What:** Parses each recent log line as JSON.
**Why:** If any line fails to parse, it's an unstructured `fmt.Printf` or panic trace leaking into the JSON stream.
**Expected:** No "INVALID JSON" lines (or only Docker metadata lines that aren't from the server).
**PASS if** all server-originated lines are valid JSON. **FAIL** if invalid JSON found.

---

**Test 23.1.2 — Log lines contain level field**

```bash
docker compose logs certctl-server 2>&1 | tail -10 | jq -r '.level // "MISSING"' 2>/dev/null | sort | uniq -c
```

**What:** Extracts the `level` field from log lines.
**Expected:** Values like "INFO", "DEBUG", "WARN", "ERROR". No "MISSING".
**PASS if** all lines have a level field. **FAIL** if "MISSING" appears.

---

**Test 23.1.3 — Request ID propagation**

```bash
# Make a request and capture request ID from response header
REQ_ID=$(curl -s -D - -o /dev/null -H "$AUTH" "$SERVER/api/v1/certificates?per_page=1" | grep -i "x-request-id" | tr -d '\r' | awk '{print $2}')
echo "Request ID: $REQ_ID"
# Search for it in logs
docker compose logs certctl-server 2>&1 | grep "$REQ_ID" | wc -l
```

**What:** Makes an API call, extracts the request ID from the response header, then searches for that ID in server logs.
**Why:** Request ID propagation lets operators trace a single request across all log lines it produced. Without it, debugging is guesswork.
**Expected:** Request ID found in at least 1 log line (ideally the access log line).
**PASS if** count ≥ 1. **FAIL** if 0 (request ID not propagated).

---

**Test 23.1.4 — Error logs at ERROR level**

```bash
docker compose logs certctl-server 2>&1 | jq -r 'select(.level == "ERROR") | .msg' 2>/dev/null | head -5
```

**What:** Checks if error-level log entries exist and have proper messages.
**Why:** Errors should be logged at ERROR level, not INFO. Wrong levels mean operators miss critical issues.
**Expected:** Either no ERROR lines (healthy system) or ERROR lines with descriptive messages (not empty).
**PASS if** ERROR entries have messages (or no errors at all). **FAIL** if empty/garbled error messages.

---

**Test 23.1.5 — No unstructured output in log stream**

```bash
docker compose logs certctl-server 2>&1 | grep -v "^certctl-server" | grep -cv "^{" || echo "0"
```

**What:** Counts log lines that don't start with `{` (i.e., not JSON).
**Why:** `fmt.Printf` calls in the Go code bypass slog and produce unstructured output that breaks log parsers.
**Expected:** Count = 0 (all lines are JSON).
**PASS if** 0 non-JSON lines. **FAIL** if > 0.

---

## Part 24: Documentation Verification

**What this validates:** Documentation accuracy against the running system. Claims in docs must match reality.

**Why it matters:** Inaccurate documentation destroys trust. If the README says "21 tables" but there are 19, or "78 MCP tools" but there are 76, evaluators question everything else too.

| Test ID | Document | Verification | Pass/Fail Criteria |
|---------|----------|-------------|-------------------|
| 24.1.1 | `README.md` | Feature list matches actual capabilities. Screenshot paths resolve. Mermaid diagram says "21 tables". | PASS if all claims verified |
| 24.1.2 | `docs/quickstart.md` | Every command in the quickstart works on a clean clone. | PASS if all commands succeed |
| 24.1.3 | `docs/concepts.md` | Terminology matches API field names and UI labels. | PASS if terminology consistent |
| 24.1.4 | `docs/architecture.md` | Component diagram matches `docker compose ps`. Says "21 tables", "78 MCP Tools", "900+ tests". | PASS if numbers match |
| 24.1.5 | `docs/connectors.md` | All 5 issuer types and 5 target types documented. F5/IIS marked as stubs. | PASS if all documented |
| 24.1.6 | `docs/features.md` | Endpoint count (93), MCP tools (78), table count (21), test count (900+) all accurate. | PASS if numbers match |
| 24.1.7 | `docs/demo-guide.md` | Demo walkthrough works against fresh `docker compose up`. | PASS if all steps work |
| 24.1.8 | `docs/demo-advanced.md` | All parts executable against running stack. Network discovery section present. | PASS if all executable |
| 24.1.9 | `docs/compliance.md` | Framework links resolve, mapping references real features. | PASS if links work |
| 24.1.10 | `docs/compliance-soc2.md` | API endpoints cited actually exist in the router. | PASS if endpoints exist |
| 24.1.11 | `docs/compliance-pci-dss.md` | Claims match implementation (audit trail, revocation, key management). | PASS if claims verified |
| 24.1.12 | `docs/compliance-nist.md` | Key management claims match agent keygen behavior. | PASS if claims verified |
| 24.1.13 | `docs/mcp.md` | Tool count = 78, domain count = 16, setup instructions work. | PASS if numbers match |
| 24.1.14 | `api/openapi.yaml` | Operation count = 93, matches all routes in router.go. | PASS if count matches |

**Verification command for OpenAPI parity:**

```bash
# Count OpenAPI operations
grep -c "operationId:" api/openapi.yaml
# Count router registrations
grep -c "r.Register\|r.mux.Handle" internal/api/router/router.go
```

**Expected:** Both return 93.
**PASS if** both counts = 93. **FAIL** if mismatch.

---

## Part 25: Regression Tests

**What this validates:** Specific bugs found and fixed during development. These prevent re-introduction.

**Why it matters:** Regression bugs are the most embarrassing — you already found and fixed them once. These tests ensure they stay fixed.

**Test 25.1.1 — DELETE endpoints return 204, not 200**

```bash
# Create and delete a target
curl -s -X POST -H "$AUTH" -H "$CT" -d '{"id":"tgt-regression","name":"Regression","type":"nginx","config":{}}' $SERVER/api/v1/targets > /dev/null
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "$AUTH" "$SERVER/api/v1/targets/tgt-regression")
echo "DELETE target: HTTP $CODE"

# Create and delete an agent group
curl -s -X POST -H "$AUTH" -H "$CT" -d '{"id":"ag-regression","name":"Regression Group"}' $SERVER/api/v1/agent-groups > /dev/null
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "$AUTH" "$SERVER/api/v1/agent-groups/ag-regression")
echo "DELETE agent group: HTTP $CODE"
```

**What:** Verifies DELETE endpoints return 204 (No Content), not 200.
**Why:** This was a real bug — handlers returned 200 for delete operations. The fix was applied in M15a.
**Expected:** Both return HTTP 204.
**PASS if** both 204. **FAIL** if either returns 200.

---

**Test 25.1.2 — per_page exceeding max falls back to default**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/certificates?per_page=9999" | jq '{per_page}'
```

**What:** Sends `per_page=9999` which exceeds the maximum (500).
**Why:** Bug: the handler was supposed to cap at 500 but instead rejected values > 500 and fell back to the default (50). The tests were written expecting cap-at-500 but the actual behavior is fall-back-to-50.
**Expected:** `per_page` = 50 (default fallback), not 500 or 9999.
**PASS if** per_page = 50. **FAIL** if 500 or 9999.

---

**Test 25.1.3 — Seed demo network scan targets present**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/network-scan-targets" | jq '{total, ids: [.items[].id] | sort}'
```

**What:** Verifies the 3 seed network scan targets were loaded.
**Why:** These were added during M21 and initially missed from seed data.
**Expected:** `total` = 3. IDs: `["nst-dc1-web", "nst-dc2-apps", "nst-dmz"]`.
**PASS if** total = 3 and all 3 IDs present. **FAIL** otherwise.

---

**Test 25.1.4 — OpenAPI spec operations match router**

```bash
echo "OpenAPI operations: $(grep -c 'operationId:' api/openapi.yaml)"
echo "Router registrations: $(grep -c 'r.Register\|r.mux.Handle' internal/api/router/router.go)"
```

**What:** Counts operations in the OpenAPI spec and route registrations in the router.
**Why:** The audit found the OpenAPI spec had 78 operations while the router had 93. This was fixed by adding 15 missing operations.
**Expected:** Both = 93.
**PASS if** both equal 93. **FAIL** if mismatch.

---

**Test 25.1.5 — Go service tests use strings.Contains, not errors.Is**

```bash
grep -rn "errors.Is.*errors.New\|errors.Is(.*err.*errors.New" internal/service/*_test.go | wc -l
```

**What:** Checks for the anti-pattern `errors.Is(err, errors.New(...))` which never matches because `errors.New` creates a new instance every time.
**Why:** This was a real bug in `TestTeamService_List_RepositoryError` — the test was passing for the wrong reason (both sides returned false). The fix was to use `strings.Contains`.
**Expected:** Count = 0 (no instances of the anti-pattern).
**PASS if** count = 0. **FAIL** if > 0.

---

## Release Sign-Off

All 25 parts must pass before tagging v2.0.0.

| Section | Pass? | Tester | Date | Notes |
|---------|-------|--------|------|-------|
| Part 1: Infrastructure & Deployment | ☐ | | | |
| Part 2: Authentication & Security | ☐ | | | |
| Part 3: Certificate Lifecycle (CRUD) | ☐ | | | |
| Part 4: Renewal Workflow | ☐ | | | |
| Part 5: Revocation | ☐ | | | |
| Part 6: Issuer Connectors | ☐ | | | |
| Part 7: Target Connectors & Deployment | ☐ | | | |
| Part 8: Agent Operations | ☐ | | | |
| Part 9: Job System | ☐ | | | |
| Part 10: Policies & Profiles | ☐ | | | |
| Part 11: Ownership, Teams & Agent Groups | ☐ | | | |
| Part 12: Notifications | ☐ | | | |
| Part 13: Observability (JSON + Prometheus) | ☐ | | | |
| Part 14: Audit Trail | ☐ | | | |
| Part 15: Certificate Discovery (Filesystem + Network) | ☐ | | | |
| Part 16: Enhanced Query API | ☐ | | | |
| Part 17: CLI Tool | ☐ | | | |
| Part 18: MCP Server | ☐ | | | |
| Part 19: GUI Testing | ☐ | | | |
| Part 20: Background Scheduler | ☐ | | | |
| Part 21: Error Handling | ☐ | | | |
| Part 22: Performance Spot Checks | ☐ | | | |
| Part 23: Structured Logging | ☐ | | | |
| Part 24: Documentation Verification | ☐ | | | |
| Part 25: Regression Tests | ☐ | | | |

**Automated tests (900+) must also be green.** CI passing is necessary but not sufficient — this manual QA catches integration issues that isolated unit tests miss.

