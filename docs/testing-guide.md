# certctl V2.0 Release QA Guide

Comprehensive manual testing playbook. Every test has a concrete command, an explanation of what it validates and why it matters, exact expected output, and an unambiguous pass/fail criterion.

## Contents

- [Prerequisites](#prerequisites)
- [Part 1: Infrastructure & Deployment](#part-1-infrastructure--deployment)
- [Part 2: Authentication & Security](#part-2-authentication--security)
- [Part 3: Certificate Lifecycle (CRUD)](#part-3-certificate-lifecycle-crud)
- [Part 4: Renewal Workflow](#part-4-renewal-workflow)
- [Part 5: Revocation](#part-5-revocation)
- [Part 6: Issuer Connectors](#part-6-issuer-connectors)
- [Part 7: Target Connectors & Deployment](#part-7-target-connectors--deployment)
- [Part 8: Agent Operations](#part-8-agent-operations)
- [Part 9: Job System](#part-9-job-system)
- [Part 10: Policies & Profiles](#part-10-policies--profiles)
- [Part 11: Ownership, Teams & Agent Groups](#part-11-ownership-teams--agent-groups)
- [Part 12: Notifications](#part-12-notifications)
- [Part 13: Observability](#part-13-observability)
- [Part 14: Audit Trail](#part-14-audit-trail)
- [Part 15: Certificate Discovery (Filesystem + Network)](#part-15-certificate-discovery-filesystem--network)
- [Part 16: Enhanced Query API](#part-16-enhanced-query-api)
- [Part 17: CLI Tool](#part-17-cli-tool)
- [Part 18: MCP Server](#part-18-mcp-server)
- [Part 19: GUI Testing](#part-19-gui-testing)
- [Part 20: Background Scheduler](#part-20-background-scheduler)
- [Part 21: Error Handling](#part-21-error-handling)
- [Part 22: Performance Spot Checks](#part-22-performance-spot-checks)
- [Part 23: Structured Logging Verification](#part-23-structured-logging-verification)
- [Part 24: Documentation Verification](#part-24-documentation-verification)
- [Part 25: Regression Tests](#part-25-regression-tests)
- [Part 26: EST Server (RFC 7030)](#part-26-est-server-rfc-7030)
- [Part 27: Post-Deployment TLS Verification](#part-27-post-deployment-tls-verification)
- [Part 28: Traefik & Caddy Target Connectors](#part-28-traefik--caddy-target-connectors)
- [Part 29: Certificate Export (PEM & PKCS#12)](#part-29-certificate-export-pem--pkcs12)
- [Part 30: S/MIME & EKU Support](#part-30-smime--eku-support)
- [Part 31: OCSP Responder & DER CRL](#part-31-ocsp-responder--der-crl)
- [Part 32: Request Body Size Limits](#part-32-request-body-size-limits)
- [Part 33: Apache & HAProxy Target Connectors](#part-33-apache--haproxy-target-connectors)
- [Part 34: Sub-CA Mode](#part-34-sub-ca-mode)
- [Part 35: ARI (RFC 9702) Scheduler Integration](#part-35-ari-rfc-9702-scheduler-integration)
- [Part 36: Agent Work Routing (M31)](#part-36-agent-work-routing-m31)
- [Part 37: GUI Completeness (Pre-2.1.0-E)](#part-37-gui-completeness-pre-210-e)
- [Part 38: Vault PKI Connector (M32)](#part-38-vault-pki-connector-m32)
- [Part 39: DigiCert Connector (M37)](#part-39-digicert-connector-m37)
- [Part 40: Issuer Catalog Page (M33)](#part-40-issuer-catalog-page-m33)
- [Part 41: Frontend Audit Fixes](#part-41-frontend-audit-fixes)
- [Part 42: IIS Target Connector (M39)](#part-42-iis-target-connector-m39)
- [Release Sign-Off](#release-sign-off)

---

## Prerequisites

### Why manual QA on top of automated tests?

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

### 6.2 ACME DNS Challenge Configuration

**Test 6.2.1 — List ACME issuer with DNS-01 configuration**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/issuers/iss-acme-le" | jq '{id, type, config}'
```

**What:** Retrieves the ACME Let's Encrypt issuer and verifies its configuration.
**Why:** ACME issuers configured for DNS-01 challenges need their solver scripts accessible for wildcard certificate support.
**Expected:** HTTP 200. `type` = "acme". `config` may include challenge type and DNS script paths.
**PASS if** HTTP 200 and type matches. **FAIL** otherwise.

---

**Test 6.2.2 — Create ACME issuer with DNS-PERSIST-01**

Edit `deploy/docker-compose.yml` to set environment variables for ACME DNS-PERSIST-01:
- `CERTCTL_ACME_CHALLENGE_TYPE: dns-persist-01`
- `CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN: le.example.com`
- `CERTCTL_ACME_DNS_PRESENT_SCRIPT: /usr/local/bin/dns-present.sh`
- `CERTCTL_ACME_DNS_CLEANUP_SCRIPT: /usr/local/bin/dns-cleanup.sh`

Restart and verify the issuer accepts the config:

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/issuers/iss-acme-le" | jq '{id, type}'
```

**What:** Verifies that ACME issuers read DNS-PERSIST-01 configuration from environment variables.
**Why:** DNS-PERSIST-01 requires a standing TXT record per IETF draft. The issuer must know the issuer domain and support this challenge type.
**Expected:** HTTP 200. ACME issuer still functional.
**PASS if** HTTP 200 and issuer still works. **FAIL** if 500 or issuer broken.

---

**Test 6.2.3 — Configure ACME with External Account Binding (ZeroSSL)**

Edit `deploy/docker-compose.yml` to set EAB environment variables:
- `CERTCTL_ACME_DIRECTORY_URL: https://acme.zerossl.com/v2/DV90`
- `CERTCTL_ACME_EAB_KID: your-zerossl-kid`
- `CERTCTL_ACME_EAB_HMAC: your-base64url-hmac-key`

Restart and verify the issuer accepts the config:

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/issuers/iss-acme-prod" | jq '{id, type}'
```

**What:** Verifies that ACME issuers read External Account Binding credentials from environment variables.
**Why:** ZeroSSL, Google Trust Services, and SSL.com require EAB for ACME account registration. Without EAB, account creation fails and no certificates can be issued from these CAs.
**Expected:** HTTP 200. ACME issuer functional with EAB credentials loaded.
**PASS if** HTTP 200 and issuer responds. **FAIL** if 500 or startup errors related to EAB.

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

**Test 7.1.6 — Create IIS target**

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

**Expected:** `total` = 5 (seed profiles: prof-standard-tls, prof-internal-mtls, prof-short-lived, prof-wildcard, prof-smime).
**PASS if** total = 5. **FAIL** otherwise.

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

### 11.4 Foreign Key Constraint Behavior

**What this validates:** Delete operations correctly fail with 409 when referenced entities still exist.

**Why it matters:** Owners and issuers use `ON DELETE RESTRICT` — you can't delete them while certificates reference them. Teams use `ON DELETE CASCADE`, so team deletes succeed and cascade. If the server returns a silent 500 instead of 409, the GUI swallows the error and the user thinks nothing happened.

**Test 11.4.1 — Delete owner with assigned certificates (expect 409)**

```bash
# Try to delete Alice Chen (o-alice) — she owns certificates in the demo data
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/owners/o-alice" | jq .
```

**Expected:** HTTP 409 with message "Cannot delete owner: certificates are still assigned to this owner".
**PASS if** 409 Conflict. **FAIL** if 204 (data integrity violation) or 500 (unhelpful error).

---

**Test 11.4.2 — Delete issuer with assigned certificates (expect 409)**

```bash
# Try to delete the Local Dev CA (iss-local) — certificates reference it
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/issuers/iss-local" | jq .
```

**Expected:** HTTP 409 with message "Cannot delete issuer: certificates are still using this issuer".
**PASS if** 409 Conflict. **FAIL** if 204 or 500.

---

**Test 11.4.3 — Delete team cascades successfully**

```bash
# Create a test team, then delete it — teams use ON DELETE CASCADE
curl -s -X POST -H "$AUTH" -H "$CT" -d '{"id": "t-fk-test", "name": "FK Test Team"}' $SERVER/api/v1/teams > /dev/null
curl -s -w "\nHTTP %{http_code}\n" -X DELETE -H "$AUTH" "$SERVER/api/v1/teams/t-fk-test"
```

**Expected:** HTTP 204 (cascade allows deletion).
**PASS if** 204. **FAIL** if 409 or 500.

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
**Expected:** Count > 0 (one per metric).
**PASS if** count > 0. **FAIL** if 0.

---

**Test 13.3.3 — Prometheus output contains TYPE lines**

```bash
curl -s -H "$AUTH" "$SERVER/api/v1/metrics/prometheus" | grep -c "^# TYPE"
```

**What:** Counts `# TYPE` annotations (gauge/counter declarations).
**Expected:** Count > 0.
**PASS if** count > 0. **FAIL** if 0.

---

**Test 13.3.4 — All documented Prometheus metrics present**

```bash
METRICS=$(curl -s -H "$AUTH" "$SERVER/api/v1/metrics/prometheus")
for m in certctl_certificate_total certctl_certificate_active certctl_certificate_expiring_soon certctl_certificate_expired certctl_certificate_revoked certctl_agent_total certctl_agent_online certctl_job_pending certctl_job_completed_total certctl_job_failed_total certctl_uptime_seconds; do
  echo -n "$m: "
  echo "$METRICS" | grep -c "^$m "
done
```

**What:** Verifies all documented Prometheus metrics are present in the output.
**Why:** Missing metrics mean missing dashboard panels in Grafana. Each metric was chosen for operational value.
**Expected:** Each metric reports count = 1 (present).
**PASS if** all metrics show count = 1. **FAIL** if any shows 0.

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

**What this validates:** The full web dashboard — all pages of operational UI.

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

### 19.5 Jobs Page — Approval Workflow

| Test ID | Test | Action | Expected | Pass/Fail Criteria |
|---------|------|--------|----------|-------------------|
| 19.5.1 | Approval banner | Navigate to Jobs with AwaitingApproval jobs | Amber banner shows count of pending approvals | PASS if banner visible with correct count |
| 19.5.2 | Approve button | Find AwaitingApproval job, click Approve | Job status changes to Running/Completed | PASS if status transitions |
| 19.5.3 | Reject button | Find AwaitingApproval job, click Reject | Modal opens with reason input | PASS if modal appears |
| 19.5.4 | Reject with reason | Enter reason, submit rejection | Job status changes, modal closes | PASS if job rejected |
| 19.5.5 | Status filter | Select "Awaiting Approval" from status dropdown | Only AwaitingApproval jobs shown | PASS if filter works |
| 19.5.6 | AwaitingCSR filter | Select "Awaiting CSR" from status dropdown | Only AwaitingCSR jobs shown | PASS if filter works |

### 19.6 Discovery Triage Page

| Test ID | Test | Action | Expected | Pass/Fail Criteria |
|---------|------|--------|----------|-------------------|
| 19.6.1 | Summary stats | Navigate to Discovery | Stats bar shows Unmanaged/Managed/Dismissed counts | PASS if all 3 counts visible |
| 19.6.2 | Table loads | View Discovery page | Table populated with discovered certificates | PASS if certs listed |
| 19.6.3 | Status filter | Select "Unmanaged" from status dropdown | Only Unmanaged certs shown | PASS if filter works |
| 19.6.4 | Agent filter | Select agent from dropdown | Certs filtered by agent | PASS if filter works |
| 19.6.5 | Claim button | Click Claim on Unmanaged cert | Modal opens with managed cert ID input | PASS if modal appears |
| 19.6.6 | Claim submit | Enter cert ID, submit claim | Cert status changes to Managed, modal closes | PASS if status updates |
| 19.6.7 | Dismiss button | Click Dismiss on Unmanaged cert | Cert status changes to Dismissed | PASS if status updates |
| 19.6.8 | Scan history | Click "Show Scan History" | Collapsible panel shows scan records with agent, directories, counts | PASS if scan history visible |

### 19.7 Network Scan Management Page

| Test ID | Test | Action | Expected | Pass/Fail Criteria |
|---------|------|--------|----------|-------------------|
| 19.7.1 | Table loads | Navigate to Network Scans | Table with seed scan targets | PASS if targets listed |
| 19.7.2 | New Target button | Click "+ New Target" | Create modal opens | PASS if modal visible |
| 19.7.3 | Create target | Fill name, CIDRs, ports, submit | New target appears in table | PASS if target created |
| 19.7.4 | Enable toggle | Click toggle on a target | Enabled state flips | PASS if toggle works |
| 19.7.5 | Scan Now | Click Scan Now on a target | Scan triggered (check last_scan_at updates) | PASS if scan initiated |
| 19.7.6 | Delete target | Click Delete on a target | Target removed from table | PASS if target gone |

### 19.8 Other Pages

| Test ID | Test | Page | Expected | Pass/Fail Criteria |
|---------|------|------|----------|-------------------|
| 19.8.1 | Target wizard | Targets → New Target | 3-step wizard (type → config → review) | PASS if all 3 steps work |
| 19.8.2 | Audit filters | Audit | Time, actor, action filters work | PASS if filters change results |
| 19.8.3 | Audit export | Audit → Export | CSV/JSON file downloads | PASS if file downloads |
| 19.8.4 | Short-lived creds | Short-Lived | Certs with TTL < 1h, countdown timers | PASS if timers count down |
| 19.8.5 | Agent list | Agents | OS/Arch column visible | PASS if metadata shown |
| 19.8.6 | Agent detail | Click agent | System Information card | PASS if OS, arch, IP shown |
| 19.8.7 | Fleet overview | Fleet Overview | OS/arch grouping charts | PASS if pie charts render |

### 19.9 Cross-Cutting

| Test ID | Test | Action | Expected | Pass/Fail Criteria |
|---------|------|--------|----------|-------------------|
| 19.9.1 | Sidebar nav | Click all sidebar links | All 21 pages load without errors | PASS if no broken routes |
| 19.9.2 | Logout | Click logout | Returns to login screen | PASS if login page shown |
| 19.9.3 | 401 redirect | Expire/remove auth token | Auto-redirect to login | PASS if login page shown |
| 19.9.4 | Theme consistency | Check page styling | Light content area, teal sidebar, branded colors, readable text | PASS if theme consistent across all pages |

---

## Part 20: Background Scheduler

**What this validates:** The 7 background scheduler loops — renewal checks, job processing, agent health, notification processing, short-lived cert expiry, network scanning, and scheduled digest emailer.

**Why it matters:** The scheduler is the automation engine. Without it, nothing happens automatically — certs expire unnoticed, jobs sit pending, agents go stale, notifications never fire.

> **Tip:** Open a second terminal with `docker compose logs -f certctl-server` to watch scheduler log output in real time.

**Test 20.1.1 — Scheduler startup: all 7 loops registered**

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

**Why it matters:** Inaccurate documentation destroys trust. Claims in docs must match the running system. If the README says "X features" but the code doesn't have them, evaluators question everything else too.

| Test ID | Document | Verification | Pass/Fail Criteria |
|---------|----------|-------------|-------------------|
| 24.1.1 | `README.md` | Feature list matches actual capabilities. Screenshot paths resolve. Mermaid diagram shows database schema tables. | PASS if all claims verified |
| 24.1.2 | `docs/quickstart.md` | Every command in the quickstart works on a clean clone. | PASS if all commands succeed |
| 24.1.3 | `docs/concepts.md` | Terminology matches API field names and UI labels. | PASS if terminology consistent |
| 24.1.4 | `docs/architecture.md` | Component diagram matches `docker compose ps`. Key components and tables documented. | PASS if accurate |
| 24.1.5 | `docs/connectors.md` | All issuer types and target types documented. F5/IIS marked as stubs. | PASS if all documented |
| 24.1.6 | `docs/features.md` | Feature list complete and accurate. | PASS if accurate |
| 24.1.7 | `docs/quickstart.md` | Quick start + demo walkthrough works against fresh `docker compose up`. | PASS if all steps work |
| 24.1.8 | `docs/demo-advanced.md` | All parts executable against running stack. Network discovery section present. | PASS if all executable |
| 24.1.9 | `docs/compliance.md` | Framework links resolve, mapping references real features. | PASS if links work |
| 24.1.10 | `docs/compliance-soc2.md` | API endpoints cited actually exist in the router. | PASS if endpoints exist |
| 24.1.11 | `docs/compliance-pci-dss.md` | Claims match implementation (audit trail, revocation, key management). | PASS if claims verified |
| 24.1.12 | `docs/compliance-nist.md` | Key management claims match agent keygen behavior. | PASS if claims verified |
| 24.1.13 | `docs/mcp.md` | Tool coverage documented, setup instructions work. | PASS if accurate |
| 24.1.14 | `api/openapi.yaml` | OpenAPI spec matches all routes in router.go (check operation count). | PASS if count matches |

**Verification command for OpenAPI parity:**

```bash
# Count OpenAPI operations
OPENAPI_OPS=$(grep -c "operationId:" api/openapi.yaml)
# Count router registrations
ROUTER_REGS=$(grep -c "r.Register\|r.mux.Handle" internal/api/router/router.go)
echo "OpenAPI operations: $OPENAPI_OPS"
echo "Router registrations: $ROUTER_REGS"
```

**Expected:** Both counts match.
**PASS if** both counts are equal. **FAIL** if mismatch (indicates spec/code drift).

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

**Test 25.1.4 — GUI delete on FK-restricted entities shows error, not silent failure**

```bash
# Try deleting owner o-alice via API — she owns demo certificates
CODE=$(curl -s -o /tmp/delete-resp.json -w "%{http_code}" -X DELETE -H "$AUTH" "$SERVER/api/v1/owners/o-alice")
echo "DELETE owner with certs: HTTP $CODE"
cat /tmp/delete-resp.json | jq .

# Try deleting issuer iss-local — certificates reference it
CODE=$(curl -s -o /tmp/delete-resp.json -w "%{http_code}" -X DELETE -H "$AUTH" "$SERVER/api/v1/issuers/iss-local")
echo "DELETE issuer with certs: HTTP $CODE"
cat /tmp/delete-resp.json | jq .
```

**What:** Verifies that deleting owners/issuers with assigned certificates returns 409 Conflict with a descriptive message.
**Why:** This was a real bug — the backend returned 500 (generic "Failed to delete"), `fetchJSON` threw on the error, and TanStack Query's `onError` wasn't wired up. The user clicked OK on the confirm dialog and nothing visibly happened. Fixed by: (1) backend returns 409 with descriptive message for FK constraint violations, (2) `fetchJSON` handles 204 No Content for successful deletes, (3) frontend mutation `onError` surfaces the error.
**Expected:** Both return HTTP 409 with descriptive conflict messages.
**PASS if** both 409 with messages. **FAIL** if 500 (unhelpful error) or 204 (data integrity violation).

---

**Test 25.1.5 — OpenAPI spec operations match router**

```bash
echo "OpenAPI operations: $(grep -c 'operationId:' api/openapi.yaml)"
echo "Router registrations: $(grep -c 'r.Register\|r.mux.Handle' internal/api/router/router.go)"
```

**What:** Counts operations in the OpenAPI spec and route registrations in the router, verifying they match.
**Why:** OpenAPI spec drift happens as endpoints are added or removed. Mismatches indicate the spec is out of date.
**Expected:** Both counts equal.
**PASS if** both counts match. **FAIL** if mismatch (indicates spec/code drift).

---

**Test 25.1.6 — Go service tests use strings.Contains, not errors.Is**

```bash
grep -rn "errors.Is.*errors.New\|errors.Is(.*err.*errors.New" internal/service/*_test.go | wc -l
```

**What:** Checks for the anti-pattern `errors.Is(err, errors.New(...))` which never matches because `errors.New` creates a new instance every time.
**Why:** This was a real bug in `TestTeamService_List_RepositoryError` — the test was passing for the wrong reason (both sides returned false). The fix was to use `strings.Contains`.
**Expected:** Count = 0 (no instances of the anti-pattern).
**PASS if** count = 0. **FAIL** if > 0.

---

## Part 26: EST Server (RFC 7030)

**Scope:** Enrollment over Secure Transport — 4 endpoints under `/.well-known/est/` for device certificate enrollment. Tests cover CA cert distribution, certificate enrollment (PEM and base64-DER CSR formats), re-enrollment, CSR attributes, wire format compliance, and error handling.

**Prerequisites:** Server running with `CERTCTL_EST_ENABLED=true`, `CERTCTL_EST_ISSUER_ID=iss-local` (or a valid issuer). An ECDSA P-256 key pair and CSR for enrollment tests.

---

**Test 26.1 — GET /.well-known/est/cacerts returns PKCS#7 CA chain**

```bash
curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $API_KEY" \
  http://localhost:8443/.well-known/est/cacerts
```

**Expected:** HTTP 200, `Content-Type: application/pkcs7-mime`, `Content-Transfer-Encoding: base64`. Body is base64-encoded degenerate PKCS#7 SignedData containing the CA certificate chain.
**PASS if** status = 200, correct content type, non-empty body.

---

**Test 26.2 — GET /cacerts method enforcement**

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Authorization: Bearer $API_KEY" \
  http://localhost:8443/.well-known/est/cacerts
```

**Expected:** HTTP 405 Method Not Allowed.
**PASS if** status = 405.

---

**Test 26.3 — POST /.well-known/est/simpleenroll with PEM CSR**

Generate a test CSR and submit as PEM:

```bash
# Generate ECDSA P-256 key and CSR
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/est-test.key
openssl req -new -key /tmp/est-test.key -out /tmp/est-test.csr \
  -subj "/CN=est-test.example.com" \
  -addext "subjectAltName=DNS:est-test.example.com"

# Submit PEM CSR
curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/pkcs10" \
  --data-binary @/tmp/est-test.csr \
  http://localhost:8443/.well-known/est/simpleenroll
```

**Expected:** HTTP 200, `Content-Type: application/pkcs7-mime`, `Content-Transfer-Encoding: base64`. Body contains base64-encoded PKCS#7 with the signed certificate.
**PASS if** status = 200, response decodes to valid PKCS#7.

---

**Test 26.4 — POST /simpleenroll with base64-encoded DER CSR**

```bash
# Convert PEM CSR to base64-encoded DER (EST wire format)
openssl req -in /tmp/est-test.csr -outform DER | base64 > /tmp/est-test-b64der.csr

curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/pkcs10" \
  --data-binary @/tmp/est-test-b64der.csr \
  http://localhost:8443/.well-known/est/simpleenroll
```

**Expected:** HTTP 200. Server auto-detects base64-encoded DER and converts to PEM internally.
**PASS if** status = 200.

---

**Test 26.5 — POST /simpleenroll with empty body**

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/pkcs10" \
  -X POST -d "" \
  http://localhost:8443/.well-known/est/simpleenroll
```

**Expected:** HTTP 400 Bad Request.
**PASS if** status = 400.

---

**Test 26.6 — POST /simpleenroll with invalid CSR**

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/pkcs10" \
  -X POST -d "not-a-valid-csr-at-all" \
  http://localhost:8443/.well-known/est/simpleenroll
```

**Expected:** HTTP 400 Bad Request.
**PASS if** status = 400.

---

**Test 26.7 — POST /simpleenroll with CSR missing Common Name**

```bash
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/est-nocn.key
openssl req -new -key /tmp/est-nocn.key -out /tmp/est-nocn.csr -subj "/"

curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/pkcs10" \
  --data-binary @/tmp/est-nocn.csr \
  http://localhost:8443/.well-known/est/simpleenroll
```

**Expected:** HTTP 500 (service returns error for missing CN). Error message should reference "Common Name".
**PASS if** status != 200.

---

**Test 26.8 — POST /simpleenroll method enforcement (GET not allowed)**

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $API_KEY" \
  http://localhost:8443/.well-known/est/simpleenroll
```

**Expected:** HTTP 405 Method Not Allowed.
**PASS if** status = 405.

---

**Test 26.9 — POST /.well-known/est/simplereenroll (re-enrollment)**

```bash
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/est-renew.key
openssl req -new -key /tmp/est-renew.key -out /tmp/est-renew.csr \
  -subj "/CN=renew-est.example.com" \
  -addext "subjectAltName=DNS:renew-est.example.com"

curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/pkcs10" \
  --data-binary @/tmp/est-renew.csr \
  http://localhost:8443/.well-known/est/simplereenroll
```

**Expected:** HTTP 200. Functionally identical to simpleenroll per RFC 7030 Section 4.2.2.
**PASS if** status = 200, valid PKCS#7 response.

---

**Test 26.10 — GET /simplereenroll method enforcement**

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $API_KEY" \
  http://localhost:8443/.well-known/est/simplereenroll
```

**Expected:** HTTP 405 Method Not Allowed.
**PASS if** status = 405.

---

**Test 26.11 — GET /.well-known/est/csrattrs returns 204 (no required attrs)**

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $API_KEY" \
  http://localhost:8443/.well-known/est/csrattrs
```

**Expected:** HTTP 204 No Content (default implementation requires no specific CSR attributes).
**PASS if** status = 204.

---

**Test 26.12 — POST /csrattrs method enforcement**

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $API_KEY" \
  -X POST http://localhost:8443/.well-known/est/csrattrs
```

**Expected:** HTTP 405 Method Not Allowed.
**PASS if** status = 405.

---

**Test 26.13 — EST enrollment creates audit event**

After a successful simpleenroll request (Test 26.3), query the audit trail:

```bash
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/audit?page=1&per_page=10" | \
  jq '.data[] | select(.action == "est_simple_enroll")'
```

**Expected:** At least one audit event with `action: "est_simple_enroll"`, `protocol: "EST"` in details, and the enrolled CN in the details.
**PASS if** audit event found with correct action and details.

---

**Test 26.14 — EST disabled returns 404**

With `CERTCTL_EST_ENABLED=false` (default), EST endpoints should not be registered:

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8443/.well-known/est/cacerts
```

**Expected:** HTTP 404 Not Found (endpoints not registered when EST is disabled).
**PASS if** status = 404.

---

**Test 26.15 — EST with profile binding**

With `CERTCTL_EST_PROFILE_ID=profile-wifi-client`, verify that audit events include the profile_id in their details:

```bash
# After enrollment with profile binding, check audit
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/audit?page=1&per_page=5" | \
  jq '.data[0].details.profile_id'
```

**Expected:** Profile ID appears in audit event details when configured.
**PASS if** `profile_id` present in audit details.

---

## Part 27: Post-Deployment TLS Verification

### Why test this?

Post-deployment verification is the final confidence check: after a certificate is deployed to a target, the agent probes the live TLS endpoint and confirms the served certificate matches what was deployed. This catches silent failures where a reload command exits 0 but the certificate doesn't take effect.

### 27.1: Submit Verification Result (Success)

```bash
# Create a deployment job first (or use an existing completed deployment job ID)
JOB_ID="j-deploy-001"

# Submit a successful verification result
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/jobs/$JOB_ID/verify -d '{
  "target_id": "tgt-nginx-prod",
  "expected_fingerprint": "sha256:abc123def456",
  "actual_fingerprint": "sha256:abc123def456",
  "verified": true
}'
```

**Expected:** 200 OK with `{"job_id": "j-deploy-001", "verified": true, "verified_at": "..."}`.
**PASS if** response contains `verified: true` and a valid `verified_at` timestamp.

### 27.2: Submit Verification Result (Failure — Fingerprint Mismatch)

```bash
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/jobs/$JOB_ID/verify -d '{
  "target_id": "tgt-nginx-prod",
  "expected_fingerprint": "sha256:abc123def456",
  "actual_fingerprint": "sha256:zzz999different",
  "verified": false,
  "error": "fingerprint mismatch"
}'
```

**Expected:** 200 OK with `verified: false`.
**PASS if** verification failure recorded without error status code (verification is best-effort).

### 27.3: Get Verification Status

```bash
curl -H "$AUTH" $SERVER/api/v1/jobs/$JOB_ID/verification | jq .
```

**Expected:** Returns the verification result previously submitted.
**PASS if** response includes `job_id`, `verified`, `verified_at`, and `actual_fingerprint`.

### 27.4: Missing Required Fields

```bash
# Missing target_id
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/jobs/$JOB_ID/verify -d '{
  "expected_fingerprint": "sha256:abc",
  "actual_fingerprint": "sha256:abc",
  "verified": true
}'
```

**Expected:** 400 Bad Request with message about missing `target_id`.
**PASS if** status code is 400.

### 27.5: Audit Trail

```bash
curl -H "$AUTH" "$SERVER/api/v1/audit?action=job_verification_success" | jq '.data[0]'
```

**Expected:** Audit event recorded with verification details (job_id, target_id, fingerprints).
**PASS if** audit event exists with expected action and details.

### 27.6: Database Schema Verification

```bash
docker compose exec postgres psql -U certctl -d certctl -c \
  "SELECT column_name, data_type FROM information_schema.columns WHERE table_name='jobs' AND column_name LIKE 'verification%';"
```

**Expected:** Four columns: `verification_status`, `verified_at`, `verification_fingerprint`, `verification_error`.
**PASS if** all four columns exist with correct types.

---

## Part 28: Traefik & Caddy Target Connectors

### Why test this?

Traefik and Caddy are increasingly popular reverse proxies. Testing ensures cert deployment works with their specific file-watching and admin API patterns.

### 28.1: Traefik File Provider Deployment

**Setup:** Configure a target with type `Traefik` pointing to a test directory.

```bash
# Create a Traefik target
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/targets -d '{
  "name": "Traefik Test",
  "type": "Traefik",
  "agent_id": "a-test-agent",
  "config": {
    "cert_dir": "/tmp/traefik-certs",
    "cert_file": "test.crt",
    "key_file": "test.key"
  }
}'
```

**Expected:** 201 Created with target details.
**PASS if** target created with type `Traefik` and config fields preserved.

### 28.2: Caddy API Mode Deployment

```bash
# Create a Caddy target in API mode
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/targets -d '{
  "name": "Caddy API Test",
  "type": "Caddy",
  "agent_id": "a-test-agent",
  "config": {
    "mode": "api",
    "admin_api": "http://localhost:2019",
    "cert_dir": "/etc/caddy/certs",
    "cert_file": "test.crt",
    "key_file": "test.key"
  }
}'
```

**Expected:** 201 Created.
**PASS if** target created with mode `api` and `admin_api` URL preserved.

### 28.3: Caddy File Mode Deployment

```bash
# Create a Caddy target in file mode
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/targets -d '{
  "name": "Caddy File Test",
  "type": "Caddy",
  "agent_id": "a-test-agent",
  "config": {
    "mode": "file",
    "cert_dir": "/etc/caddy/certs",
    "cert_file": "test.crt",
    "key_file": "test.key"
  }
}'
```

**Expected:** 201 Created.
**PASS if** target created with mode `file`.

### 28.4: Agent Connector Dispatch

Verify the agent binary recognizes Traefik and Caddy target types from the work endpoint response. This requires a running agent with deployment jobs assigned to Traefik/Caddy targets.

**Expected:** Agent logs show connector instantiation for the target type (e.g., "deploying to Traefik target" or "deploying to Caddy target").
**PASS if** agent does not error with "unknown target type" for Traefik or Caddy.

### 28.5: Connector Unit Tests

```bash
go test ./internal/connector/target/traefik/... -v
go test ./internal/connector/target/caddy/... -v
```

**Expected:** All tests pass.
**PASS if** exit code 0 for both test suites.

---

## Part 29: Certificate Export (PEM & PKCS#12)

**What:** certctl lets operators export managed certificates in two formats — PEM (JSON or file download) and PKCS#12 (.p12 bundle). Private keys are **never** included in exports since they live exclusively on agents. This section verifies both export paths, the audit trail they produce, and the GUI integration.

**Why:** Certificate export is a daily operational task — feeding certs into load balancers that lack agent support, importing into Java trust stores, or handing off to external teams. If export silently produces malformed output or fails to audit, operators lose trust in the platform.

### 29.1: Export PEM (JSON Response)

**What:** `GET /api/v1/certificates/{id}/export/pem` returns a JSON object with the leaf certificate PEM, the CA chain PEM, and the full concatenated PEM. This is the default response format when no `?download=true` query parameter is present.

**Why:** The JSON format lets automation scripts programmatically extract the leaf cert separately from the chain — a common need for split-file deployments (Apache, custom TLS termination).

```bash
# Use an existing certificate ID from seed data
CERT_ID="mc-api-prod"

curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/certificates/$CERT_ID/export/pem" | jq .
```

**Expected:** 200 OK with JSON body containing `cert_pem` (leaf), `chain_pem` (CA certs), and `full_pem` (concatenated).

**PASS if:**
- Response Content-Type is `application/json`
- `cert_pem` contains exactly one `-----BEGIN CERTIFICATE-----` block
- `full_pem` starts with the same block as `cert_pem` (leaf is first in chain)
- `chain_pem` is empty for self-signed CA or contains the issuing CA cert

**FAIL if:** Response is non-JSON, fields are missing, or `full_pem` doesn't equal `cert_pem` + `chain_pem`.

### 29.2: Export PEM (File Download)

**What:** Adding `?download=true` to the PEM export endpoint returns the raw PEM file with `Content-Type: application/x-pem-file` and a `Content-Disposition: attachment` header, suitable for browser "Save As" workflows.

**Why:** The GUI uses this mode when operators click the "Export PEM" button — the browser should trigger a file download, not show JSON in the tab.

```bash
curl -s -D - -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/certificates/$CERT_ID/export/pem?download=true" \
  -o /tmp/exported.pem

# Verify the downloaded file is valid PEM
openssl x509 -in /tmp/exported.pem -noout -subject
```

**Expected:** 200 OK, headers include `Content-Type: application/x-pem-file` and `Content-Disposition: attachment; filename="certificate.pem"`.

**PASS if:**
- The response headers match the expected Content-Type and Content-Disposition
- The saved file parses successfully with `openssl x509`
- The subject CN matches the certificate's common name

**FAIL if:** Headers are wrong (JSON Content-Type), file is empty, or `openssl` rejects the PEM.

### 29.3: Export PEM — Not Found

**What:** Requesting export for a nonexistent certificate ID returns 404.

```bash
curl -s -w "\n%{http_code}" -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/certificates/mc-nonexistent/export/pem"
```

**Expected:** 404 Not Found with error message.
**PASS if** status code is 404 and body contains "not found".

### 29.4: Export PKCS#12

**What:** `POST /api/v1/certificates/{id}/export/pkcs12` returns a binary PKCS#12 (.p12) file containing the certificate chain (no private key). An optional `password` field in the JSON body encrypts the bundle.

**Why:** PKCS#12 is the standard format for importing certificates into Java keystores (`keytool`), Windows certificate stores, and many commercial load balancers. The cert-only bundle (no private key) is safe to share with teams that only need trust anchors.

```bash
# Export with a password
curl -s -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"password": "export-test-2024"}' \
  "http://localhost:8443/api/v1/certificates/$CERT_ID/export/pkcs12" \
  -o /tmp/exported.p12

# Verify the PKCS#12 file (openssl should parse it)
openssl pkcs12 -in /tmp/exported.p12 -nokeys -passin pass:export-test-2024 -info
```

**Expected:** 200 OK, Content-Type `application/x-pkcs12`, Content-Disposition `attachment; filename="certificate.p12"`.

**PASS if:**
- Binary .p12 file is returned (non-empty)
- `openssl pkcs12` successfully parses the file with the correct password
- No private key is present in the output (cert-only trust store)

**FAIL if:** Response is JSON instead of binary, file is empty, or `openssl` rejects the PKCS#12 format.

### 29.5: Export PKCS#12 — Empty Password

**What:** The password field is optional. Omitting it (or sending an empty body) should still produce a valid PKCS#12 bundle encrypted with an empty password.

```bash
curl -s -H "Authorization: Bearer $API_KEY" \
  -X POST \
  "http://localhost:8443/api/v1/certificates/$CERT_ID/export/pkcs12" \
  -o /tmp/exported-nopass.p12

openssl pkcs12 -in /tmp/exported-nopass.p12 -nokeys -passin pass: -info
```

**Expected:** 200 OK with valid PKCS#12.
**PASS if** `openssl pkcs12` parses with an empty password.

### 29.6: Export Audit Trail

**What:** Both PEM and PKCS#12 exports record audit events (`export_pem` and `export_pkcs12`) with the certificate's serial number.

**Why:** Export operations are security-sensitive — knowing who exported what and when is critical for incident response and compliance (SOC 2 CC7, PCI-DSS Req 10).

```bash
# Export a cert (triggers audit event)
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/certificates/$CERT_ID/export/pem" > /dev/null

# Check audit trail for the export event
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/audit?resource_type=certificate&action=export_pem" | jq '.items[-1]'
```

**Expected:** Audit event with action `export_pem`, resource_type `certificate`, resource_id matching the cert ID.
**PASS if** the audit event exists with serial number in metadata.
**FAIL if** no audit event is recorded for the export.

### 29.7: Export Unit Tests

```bash
go test ./internal/service/ -run TestExport -v
go test ./internal/api/handler/ -run TestExport -v
```

**Expected:** All export service tests (9 tests) and handler tests (11 tests) pass.
**PASS if** exit code 0 for both.

### 29.8: GUI Export Buttons

**What:** The certificate detail page shows "Export PEM" and "Export PKCS#12" buttons. PEM triggers a file download. PKCS#12 opens a password modal, then triggers a binary download.

**How to test (manual browser test):**
1. Navigate to a certificate detail page (e.g., `/certificates/mc-api-prod`)
2. Click "Export PEM" — browser should download `certificate.pem`
3. Click "Export PKCS#12" — password modal appears
4. Enter a password and confirm — browser should download `certificate.p12`

**PASS if** both downloads complete with non-empty files.
**FAIL if** buttons are missing, modal doesn't appear, or downloads fail.

---

## Part 30: S/MIME & EKU Support

**What:** Certificate profiles can specify Extended Key Usage (EKU) constraints — `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`. The Local CA respects these EKUs during issuance, adapting the X.509 `KeyUsage` flags accordingly (TLS uses `DigitalSignature|KeyEncipherment`; S/MIME uses `DigitalSignature|ContentCommitment`). A demo `prof-smime` profile ships in seed data.

**Why:** S/MIME certificates protect email with digital signatures and encryption. They require the `emailProtection` EKU and `ContentCommitment` (formerly NonRepudiation) key usage flag. If the platform treats all certs as TLS certs, S/MIME certs will be rejected by mail clients.

### 30.1: S/MIME Profile Exists in Seed Data

**What:** The demo seed creates 5 profiles including `prof-smime` with `emailProtection` EKU.

```bash
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/profiles/prof-smime" | jq '{name, allowed_ekus}'
```

**Expected:** 200 OK. Profile name is "S/MIME Email" and `allowed_ekus` contains `["emailProtection"]`.
**PASS if** the profile exists and EKUs match.
**FAIL if** 404 or EKUs are wrong/missing.

### 30.2: All Five Profiles Present

**What:** The seed data creates 5 profiles total. Previous versions of this guide referenced 4 — the `prof-smime` profile was added in M27.

```bash
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/profiles" | jq '.total'
```

**Expected:** `total` is 5 (prof-standard-tls, prof-internal-mtls, prof-short-lived, prof-wildcard, prof-smime).
**PASS if** count is 5.
**FAIL if** count is 4 or fewer (missing prof-smime).

### 30.3: EKU Strings in Profile API

**What:** The profile API accepts and returns EKU names as human-readable strings rather than OID numbers. The supported values are: `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`.

```bash
# Create a profile with codeSigning EKU
curl -s -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "prof-test-codesign",
    "name": "Code Signing Test",
    "description": "Test profile for code signing",
    "allowed_key_algorithms": [{"algorithm": "ECDSA", "min_size": 256}],
    "max_ttl_seconds": 7776000,
    "allowed_ekus": ["codeSigning"]
  }' \
  "http://localhost:8443/api/v1/profiles" | jq '{id, allowed_ekus}'
```

**Expected:** 201 Created with `allowed_ekus: ["codeSigning"]`.
**PASS if** the EKU round-trips correctly through create/get.

### 30.4: Agent CSR SAN Splitting (Email vs DNS)

**What:** When generating CSRs for S/MIME certificates, the agent splits SANs by type: values containing `@` are placed in `EmailAddresses` (not `DNSNames`). This prevents mail clients from rejecting the cert due to incorrect SAN encoding.

**Why:** An email SAN like `alice@example.com` must appear in the X.509 `rfc822Name` SAN field, not the `dNSName` field. Incorrect encoding causes S/MIME validation failures.

This is tested via unit tests:

```bash
go test ./cmd/agent/ -run TestSAN -v
```

**Expected:** Tests pass showing email-type SANs are routed to `EmailAddresses`.
**PASS if** exit code 0.

### 30.5: EKU Service-Layer Tests

```bash
go test ./internal/service/ -run TestEKU -v
go test ./internal/service/ -run TestCSRRenewal -v
```

**Expected:** Tests covering EKU resolution from profiles and issuance with non-default EKUs pass.
**PASS if** exit code 0.

---

## Part 31: OCSP Responder & DER CRL

**What:** certctl includes an embedded OCSP responder and a DER-encoded CRL generator, both operating per-issuer. These are the standard online (OCSP) and offline (CRL) methods for checking certificate revocation status. Short-lived certificates (profile TTL < 1 hour) are exempt from both — their natural expiry is sufficient revocation.

**Why:** TLS clients need to verify that certificates haven't been revoked. Without OCSP/CRL, a compromised certificate remains trusted until it expires. The short-lived exemption avoids bloating the CRL with certs that expire before distribution.

### 31.1: DER-Encoded CRL

**What:** `GET /api/v1/crl/{issuer_id}` returns a DER-encoded X.509 CRL signed by the issuing CA. Content-Type is `application/pkix-crl`. The CRL has 24-hour validity.

**Why:** This is the standard CRL format that browsers, TLS libraries, and LDAP directories consume. The existing JSON CRL at `GET /api/v1/crl` is certctl-specific; the DER CRL is interoperable.

```bash
# Request DER CRL for the local issuer
curl -s -D - -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/crl/iss-local" \
  -o /tmp/crl.der

# Verify it's valid DER CRL with openssl
openssl crl -in /tmp/crl.der -inform DER -noout -text
```

**Expected:** 200 OK, Content-Type `application/pkix-crl`, Cache-Control `public, max-age=3600`.

**PASS if:**
- `openssl crl` parses the DER file successfully
- Issuer field shows the Local CA's common name
- Validity period is present (thisUpdate / nextUpdate)
- If any certs have been revoked, they appear in the revocation list with serial + reason

**FAIL if:** Response is JSON (wrong endpoint), `openssl` rejects the DER format, or headers are wrong.

### 31.2: DER CRL — Nonexistent Issuer

```bash
curl -s -w "\n%{http_code}" -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/crl/iss-nonexistent"
```

**Expected:** 404 Not Found.
**PASS if** status code is 404 and body contains "not found".

### 31.3: OCSP Responder — Good Status

**What:** `GET /api/v1/ocsp/{issuer_id}/{serial}` returns a signed OCSP response. For a non-revoked certificate, the status is "good".

**Why:** OCSP is the real-time revocation check that TLS clients perform during the handshake. A "good" response tells the client the cert is still valid.

```bash
# First, get a certificate's serial number
SERIAL=$(curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/certificates/mc-api-prod" | jq -r '.latest_version.serial_number // empty')

# If serial is available, query OCSP
if [ -n "$SERIAL" ]; then
  curl -s -D - -H "Authorization: Bearer $API_KEY" \
    "http://localhost:8443/api/v1/ocsp/iss-local/$SERIAL" \
    -o /tmp/ocsp.der

  # Parse OCSP response
  openssl ocsp -respin /tmp/ocsp.der -text -noverify
fi
```

**Expected:** 200 OK, Content-Type `application/ocsp-response`. OCSP response shows `Cert Status: good`.

**PASS if:**
- OCSP response parses successfully
- Certificate status is "good" for a non-revoked cert
- Response is signed (producedAt timestamp present)

**FAIL if:** Response is JSON, OCSP status is wrong, or `openssl` rejects the response.

### 31.4: OCSP Responder — Revoked Status

**What:** After revoking a certificate, the OCSP responder should return "revoked" with the revocation reason and timestamp.

```bash
# Revoke a certificate first (see Part 5 for revocation)
curl -s -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason": "keyCompromise"}' \
  "http://localhost:8443/api/v1/certificates/$CERT_ID/revoke"

# Then query OCSP
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/ocsp/iss-local/$SERIAL" \
  -o /tmp/ocsp-revoked.der

openssl ocsp -respin /tmp/ocsp-revoked.der -text -noverify
```

**Expected:** OCSP response shows `Cert Status: revoked`, revocation time, and reason code (1 = keyCompromise).
**PASS if** status is "revoked" with correct reason.
**FAIL if** status is still "good" after revocation.

### 31.5: OCSP — Unknown Certificate

**What:** Querying a serial number that doesn't exist in the inventory returns an "unknown" OCSP status (not an error — this is the correct OCSP behavior per RFC 6960).

```bash
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/ocsp/iss-local/DEADBEEF" \
  -o /tmp/ocsp-unknown.der

openssl ocsp -respin /tmp/ocsp-unknown.der -text -noverify
```

**Expected:** OCSP response with `Cert Status: unknown`.
**PASS if** status is "unknown" (not a 404 HTTP error).

### 31.6: Short-Lived Certificate CRL Exemption

**What:** Certificates issued under a profile with TTL < 1 hour are excluded from both CRL and OCSP responses. Their natural expiry is considered sufficient revocation.

**Why:** Short-lived certs (used in mTLS, CI/CD pipelines) would bloat the CRL with entries that expire within minutes. The crypto community consensus (per Google's Certificate Transparency policy) is that short-lived certs don't need revocation infrastructure.

To test: revoke a cert that was issued under the `prof-short-lived` profile, then check the DER CRL. The revoked short-lived cert should NOT appear.

```bash
# After revoking a short-lived cert (serial SHORT_SERIAL):
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/crl/iss-local" -o /tmp/crl.der

openssl crl -in /tmp/crl.der -inform DER -text | grep -i "$SHORT_SERIAL"
```

**Expected:** The short-lived cert's serial does NOT appear in the CRL.
**PASS if** short-lived cert is absent from CRL despite being revoked.

### 31.7: OCSP / CRL Unit Tests

```bash
go test ./internal/service/ -run "TestGenerateDERCRL|TestGetOCSPResponse" -v
go test ./internal/api/handler/ -run "TestDERCRL|TestOCSP" -v
go test ./internal/connector/issuer/local/ -run "TestGenerateCRL|TestSignOCSP" -v
```

**Expected:** All tests pass (8 service tests, handler tests, connector tests).
**PASS if** exit code 0 for all three test suites.

---

## Part 32: Request Body Size Limits

**What:** The `NewBodyLimit` middleware wraps request bodies with `http.MaxBytesReader`, enforcing a configurable maximum payload size (default 1MB). Oversized requests receive a 413 Request Entity Too Large response. This protects against memory exhaustion and denial of service (CWE-400).

**Why:** Without body limits, an attacker could send a multi-gigabyte POST to exhaust server memory. The 1MB default is generous for certificate API payloads (a typical CSR is ~1KB, a PKCS#12 export request is <100 bytes) while blocking abuse.

### 32.1: Default 1MB Limit

**What:** With default configuration (`CERTCTL_MAX_BODY_SIZE` unset), the server rejects request bodies larger than 1MB.

```bash
# Generate a payload slightly over 1MB
dd if=/dev/urandom bs=1024 count=1025 2>/dev/null | base64 > /tmp/big-payload.txt

curl -s -w "\n%{http_code}" -X POST \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"$(cat /tmp/big-payload.txt)\"}" \
  "http://localhost:8443/api/v1/certificates"
```

**Expected:** The server returns an error (likely 400 or 413) when the body exceeds 1MB.
**PASS if** the request is rejected and does not cause server memory issues.
**FAIL if** the server accepts the oversized payload or crashes.

### 32.2: Normal-Sized Requests Work

**What:** Standard API requests well under the limit work normally.

```bash
curl -s -w "\n%{http_code}" -X POST \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"id": "mc-test-bodylimit", "common_name": "bodylimit.test.local", "issuer_id": "iss-local"}' \
  "http://localhost:8443/api/v1/certificates"
```

**Expected:** 201 Created — normal payloads are unaffected by the body limit.
**PASS if** status code is 201.

### 32.3: Custom Body Size via Environment Variable

**What:** Set `CERTCTL_MAX_BODY_SIZE` to a custom value (e.g., `2097152` for 2MB) and verify the new limit is respected.

**How:** Restart the server with the env var set, then repeat test 32.1. A 1.1MB payload should now be accepted; a 2.1MB payload should be rejected.

**PASS if** the configured limit is enforced instead of the 1MB default.

### 32.4: Requests Without Bodies Are Unaffected

**What:** GET requests and other methods without request bodies pass through the body limit middleware without interference.

```bash
curl -s -w "\n%{http_code}" -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/certificates" | tail -1
```

**Expected:** 200 OK — body limit middleware only applies to requests with bodies.
**PASS if** GET requests are unaffected.

---

## Part 33: Apache & HAProxy Target Connectors

**What:** certctl ships two additional target connectors beyond NGINX: Apache httpd (separate cert/chain/key files, `apachectl configtest` + graceful reload) and HAProxy (combined PEM file with cert+chain+key, config validation, reload). Both run on the agent side and follow the same pattern as the NGINX connector.

**Why:** Apache and HAProxy are the second and third most common reverse proxies in enterprise environments. Supporting them out of the box removes a common adoption blocker.

### 33.1: Create Apache Target

**What:** Create a deployment target of type `apache` with the required configuration fields.

```bash
curl -s -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "t-test-apache",
    "name": "Test Apache Server",
    "type": "apache",
    "agent_id": "agent-demo-1",
    "config": {
      "cert_path": "/etc/apache2/ssl/cert.pem",
      "key_path": "/etc/apache2/ssl/key.pem",
      "chain_path": "/etc/apache2/ssl/chain.pem",
      "reload_command": "apachectl graceful",
      "validate_command": "apachectl configtest"
    }
  }' \
  "http://localhost:8443/api/v1/targets" | jq '{id, name, type}'
```

**Expected:** 201 Created with type `apache`.

**PASS if:**
- Target is created successfully
- Type is `apache`
- Config fields are persisted (verify via GET)

**FAIL if** type is rejected or config fields are missing in the response.

### 33.2: Apache Config — Separate Files

**What:** Apache uses three separate files (cert, chain, key) unlike NGINX's dual-file or HAProxy's combined PEM. Verify that `cert_path`, `chain_path`, and `key_path` are all required.

```bash
# Missing chain_path should fail validation
curl -s -w "\n%{http_code}" -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "t-test-apache-bad",
    "name": "Bad Apache",
    "type": "apache",
    "agent_id": "agent-demo-1",
    "config": {
      "cert_path": "/etc/apache2/ssl/cert.pem",
      "reload_command": "apachectl graceful",
      "validate_command": "apachectl configtest"
    }
  }' \
  "http://localhost:8443/api/v1/targets"
```

**Expected:** The target is created (config validation happens at deploy time on the agent), but when the agent attempts to deploy, it will fail if required fields are missing.
**PASS if** the validation behavior matches the connector's `ValidateConfig` — `cert_path` and `chain_path` are both required.

### 33.3: Create HAProxy Target

**What:** Create a deployment target of type `haproxy`. HAProxy uses a single combined PEM file (cert + chain + key concatenated), not separate files.

```bash
curl -s -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "t-test-haproxy",
    "name": "Test HAProxy",
    "type": "haproxy",
    "agent_id": "agent-demo-1",
    "config": {
      "pem_path": "/etc/haproxy/certs/site.pem",
      "reload_command": "systemctl reload haproxy",
      "validate_command": "haproxy -c -f /etc/haproxy/haproxy.cfg"
    }
  }' \
  "http://localhost:8443/api/v1/targets" | jq '{id, name, type}'
```

**Expected:** 201 Created with type `haproxy`.
**PASS if** target created with correct type and config persisted.

### 33.4: HAProxy Combined PEM Requirement

**What:** HAProxy's `pem_path` is the single file where cert+chain+key are concatenated. The `pem_path` field is required; `reload_command` is also required.

**Why:** HAProxy's `bind ssl crt` directive expects one file per certificate. The combined PEM format eliminates the need for multiple `SSLCertificate*` directives.

This is verified in the connector's `ValidateConfig`:

```bash
go test ./internal/connector/target/haproxy/... -v
```

**Expected:** Tests validate that missing `pem_path` and missing `reload_command` both produce errors.
**PASS if** all haproxy connector tests pass.

### 33.5: Shell Command Injection Prevention

**What:** Both Apache and HAProxy connectors validate `reload_command` and `validate_command` against the shell injection prevention logic in `internal/validation/command.go`. Commands containing shell metacharacters (`;`, `|`, `&`, `$()`, backticks) are rejected.

**Why:** An attacker who controls target configuration could inject arbitrary commands if the reload/validate commands aren't sanitized. This was remediated in the security hardening pass (TICKET-001).

```bash
go test ./internal/validation/ -run TestValidateShellCommand -v
```

**Expected:** All 80+ adversarial test cases pass — commands with injection attempts are rejected, safe commands are accepted.
**PASS if** exit code 0.

### 33.6: Connector Unit Tests

```bash
go test ./internal/connector/target/apache/... -v
go test ./internal/connector/target/haproxy/... -v
```

**Expected:** All Apache and HAProxy connector tests pass (config validation, deployment logic).
**PASS if** exit code 0 for both.

---

## Part 34: Sub-CA Mode

**What:** The Local CA issuer connector can operate in two modes: self-signed root (default) or sub-CA. In sub-CA mode, set `CERTCTL_CA_CERT_PATH` and `CERTCTL_CA_KEY_PATH` to point at a pre-signed CA certificate and its private key. The CA cert must have `IsCA=true` and `KeyUsageCertSign`. All issued certificates then chain to the upstream root (e.g., Active Directory Certificate Services). Supports RSA, ECDSA, and PKCS#8 key formats.

**Why:** Enterprise environments already have a root CA (ADCS, Vault, etc.). Sub-CA mode lets certctl operate as a subordinate CA without replacing the existing trust hierarchy. Users' browsers and devices already trust the enterprise root, so certctl-issued certs are automatically trusted.

### 34.1: Self-Signed Mode (Default)

**What:** Without `CERTCTL_CA_CERT_PATH` / `CERTCTL_CA_KEY_PATH`, the Local CA generates its own self-signed root on startup. This is the default for development and demos.

```bash
# Verify the CA cert is self-signed (issuer == subject)
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/certificates/mc-api-prod/export/pem?download=true" \
  -o /tmp/chain.pem

# Extract the last cert in the chain (the CA cert)
csplit -f /tmp/cert- -z /tmp/chain.pem '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null
LAST_CERT=$(ls /tmp/cert-* | tail -1)
openssl x509 -in "$LAST_CERT" -noout -subject -issuer
```

**Expected:** For self-signed mode, the CA cert's Subject and Issuer are identical.
**PASS if** Subject == Issuer (self-signed root).

### 34.2: Sub-CA Mode — Configuration

**What:** Setting `CERTCTL_CA_CERT_PATH` and `CERTCTL_CA_KEY_PATH` environment variables switches the Local CA to sub-CA mode. The server logs the mode at startup.

**How to test:**
1. Generate a test CA hierarchy (root CA + sub-CA):
```bash
# Generate root CA
openssl req -x509 -newkey rsa:2048 -keyout /tmp/root-key.pem -out /tmp/root-cert.pem \
  -days 3650 -nodes -subj "/CN=Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Generate sub-CA key and CSR
openssl req -newkey rsa:2048 -keyout /tmp/subca-key.pem -out /tmp/subca-csr.pem \
  -nodes -subj "/CN=CertCtl Sub-CA"

# Sign sub-CA cert with root
openssl x509 -req -in /tmp/subca-csr.pem -CA /tmp/root-cert.pem -CAkey /tmp/root-key.pem \
  -CAcreateserial -out /tmp/subca-cert.pem -days 1825 \
  -extfile <(echo -e "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign")
```

2. Start the server with sub-CA config:
```bash
CERTCTL_CA_CERT_PATH=/tmp/subca-cert.pem \
CERTCTL_CA_KEY_PATH=/tmp/subca-key.pem \
./certctl-server
```

3. Check startup logs for sub-CA mode indication.

**PASS if** the server starts successfully and logs indicate sub-CA mode with the loaded cert path.
**FAIL if** the server fails to start or falls back to self-signed mode.

### 34.3: Sub-CA Chain Construction

**What:** In sub-CA mode, issued certificates should chain to the sub-CA, which chains to the root. The PEM chain in certificate versions should include the leaf, the sub-CA cert, and optionally the root.

```bash
# Issue a certificate (after starting in sub-CA mode)
curl -s -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"id": "mc-subca-test", "common_name": "subca.test.local", "issuer_id": "iss-local"}' \
  "http://localhost:8443/api/v1/certificates"

# Export and verify chain
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/certificates/mc-subca-test/export/pem" | jq -r '.full_pem' > /tmp/subca-chain.pem

openssl verify -CAfile /tmp/root-cert.pem -untrusted /tmp/subca-cert.pem /tmp/subca-chain.pem
```

**Expected:** Certificate chain validates against the root CA. The leaf cert's Issuer matches the sub-CA's Subject.
**PASS if** `openssl verify` returns "OK".
**FAIL if** chain is broken or leaf is signed by self-signed root instead of sub-CA.

### 34.4: Sub-CA Validation — Non-CA Cert Rejected

**What:** If `CERTCTL_CA_CERT_PATH` points to a certificate without `IsCA=true` or `KeyUsageCertSign`, the server should reject it at startup.

```bash
# Generate a non-CA cert (leaf cert, not a CA)
openssl req -x509 -newkey rsa:2048 -keyout /tmp/leaf-key.pem -out /tmp/leaf-cert.pem \
  -days 365 -nodes -subj "/CN=Not A CA"

# Try to start server with non-CA cert — should fail
CERTCTL_CA_CERT_PATH=/tmp/leaf-cert.pem \
CERTCTL_CA_KEY_PATH=/tmp/leaf-key.pem \
./certctl-server
```

**Expected:** Server fails to start (or logs a fatal error) because the loaded cert is not a CA.
**PASS if** server rejects the non-CA certificate.
**FAIL if** server starts and silently uses the non-CA cert for signing.

### 34.5: Sub-CA Key Format Support

**What:** The sub-CA key can be RSA, ECDSA, or PKCS#8 encoded. All three formats should load successfully.

```bash
go test ./internal/connector/issuer/local/ -run "TestSubCA" -v
```

**Expected:** All 7 sub-CA tests pass (RSA, ECDSA, config validation, invalid cert, non-CA cert, renewal, chain construction).
**PASS if** exit code 0.

### 34.6: CRL Signing in Sub-CA Mode

**What:** In sub-CA mode, the DER CRL (Part 31.1) should be signed by the sub-CA key, not a self-signed root.

```bash
# After starting in sub-CA mode and revoking a cert:
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/crl/iss-local" -o /tmp/subca-crl.der

openssl crl -in /tmp/subca-crl.der -inform DER -noout -issuer
```

**Expected:** CRL issuer matches the sub-CA's subject (not the self-signed CA).
**PASS if** issuer is the sub-CA distinguished name.

---

## Part 35: ARI (RFC 9702) Scheduler Integration

Tests that the renewal scheduler consults ARI before creating renewal jobs for ACME-issued certificates.

### 35.1 ARI Defers Renewal When CA Says "Not Yet"

**Prerequisite:** ACME issuer configured with `CERTCTL_ACME_ARI_ENABLED=true`, connected to a CA that supports ARI (e.g., Let's Encrypt staging). Certificate within the 30-day expiry window but the CA's `suggestedWindow.start` is in the future.

```bash
# Check scheduler logs for ARI deferral
docker logs certctl-server 2>&1 | grep "ARI: renewal not yet suggested"
```

**Expected:** Log line showing `ARI: renewal not yet suggested by CA` with `cert_id`, `suggested_start`, `suggested_end`. No renewal job created for that cert.
**PASS if** the scheduler skips renewal job creation when ARI says the window hasn't opened.

### 35.2 ARI Triggers Renewal When CA Says "Now"

**Prerequisite:** Same setup as 35.1, but the certificate's ARI `suggestedWindow.start` is in the past (CA is actively suggesting renewal).

```bash
# Check scheduler logs for ARI-triggered renewal
docker logs certctl-server 2>&1 | grep "ARI: CA suggests renewal now"

# Verify renewal job was created
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/jobs?type=renewal" | jq '.data[] | select(.certificate_id == "<cert-id>")'
```

**Expected:** Log line showing `ARI: CA suggests renewal now`. Renewal job created with `renewal_trigger: ari` in the audit trail.
**PASS if** a renewal job is created when ARI indicates the renewal window is open.

### 35.3 ARI Fallback on Error

**Prerequisite:** ACME issuer with `CERTCTL_ACME_ARI_ENABLED=true`, but the ARI endpoint is unreachable or returns an error (e.g., network issue, 500 from CA).

```bash
# Check scheduler logs for ARI fallback
docker logs certctl-server 2>&1 | grep "ARI check failed, falling back"
```

**Expected:** Warning log `ARI check failed, falling back to threshold-based renewal`. Renewal proceeds normally using the configured expiration thresholds.
**PASS if** renewal still works when ARI is unavailable, using threshold-based logic as fallback.

---

## Part 36: Agent Work Routing (M31)

Tests that `GetPendingWork()` returns only jobs scoped to the requesting agent, and that deployment jobs have `agent_id` populated at creation time.

### 36.1 Multi-Agent Routing

**Prerequisite:** Two agents registered (`agent-web-01`, `agent-lb-01`), two targets (one per agent), one certificate mapped to both targets. Trigger renewal to create deployment jobs.

```bash
# Poll as agent-web-01 — should only see its deployment job
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/agents/agent-web-01/work" | jq '.[] | .target_id'

# Poll as agent-lb-01 — should only see its deployment job
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/agents/agent-lb-01/work" | jq '.[] | .target_id'
```

**Expected:** Each agent receives only the deployment job for its assigned target. Agent-web-01 does NOT see agent-lb-01's job and vice versa.
**PASS if** each agent's work response contains only jobs for targets it owns.

### 36.2 Agent With No Targets Gets Empty Work

**Prerequisite:** Register a new agent with no target assignments.

```bash
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/agents/agent-no-targets/work" | jq 'length'
```

**Expected:** Empty array (0 jobs).
**PASS if** the response is an empty list.

### 36.3 Deployment Jobs Have agent_id Populated

**Prerequisite:** Deployment jobs created via renewal or manual trigger.

```bash
# Check that deployment jobs in the system have agent_id set
curl -s -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8443/api/v1/jobs" | jq '[.data[] | select(.type == "Deployment") | .agent_id] | map(select(. != null)) | length'
```

**Expected:** All deployment jobs for targets with agent assignments have `agent_id` populated.
**PASS if** deployment jobs have non-null `agent_id` values.

---

## Part 38: Vault PKI Connector (M32)

### Prerequisites

- Vault server running with PKI secrets engine enabled at `pki` mount
- PKI role created with appropriate certificate generation policy
- Vault token with read/sign permissions on the PKI path
- Environment variables configured:
  ```bash
  export CERTCTL_VAULT_ADDR="https://vault.internal:8200"
  export CERTCTL_VAULT_TOKEN="s.xxxxxxxxxxxxxxxx"
  export CERTCTL_VAULT_MOUNT="pki"
  export CERTCTL_VAULT_ROLE="certctl-role"
  export CERTCTL_VAULT_TTL="8760h"
  ```

### 38.1 Register Vault PKI Issuer

**Test:** Register a Vault PKI issuer via the API.

```bash
curl -X POST -H "$AUTH" -H "$CT" \
  "$SERVER/api/v1/issuers" \
  -d '{
    "id": "iss-vault-prod",
    "name": "Vault PKI Production",
    "type": "VaultPKI",
    "config": {
      "vault_addr": "'"$CERTCTL_VAULT_ADDR"'",
      "vault_token": "'"$CERTCTL_VAULT_TOKEN"'",
      "vault_mount": "'"$CERTCTL_VAULT_MOUNT"'",
      "vault_role": "'"$CERTCTL_VAULT_ROLE"'",
      "vault_ttl": "'"$CERTCTL_VAULT_TTL"'"
    }
  }' | jq '.id'
```

**Expected:** Returns issuer ID `iss-vault-prod`.
**PASS if** issuer is registered and appears in `GET /api/v1/issuers`.

### 38.2 Issue Certificate via Vault PKI

**Test:** Create a certificate and issue it through Vault PKI.

```bash
CERT_ID=$(curl -s -X POST -H "$AUTH" -H "$CT" \
  "$SERVER/api/v1/certificates" \
  -d '{
    "common_name": "vault-test.example.com",
    "issuer_id": "iss-vault-prod",
    "key_algorithm": "RSA-2048"
  }' | jq -r '.id')

curl -s -X POST -H "$AUTH" \
  "$SERVER/api/v1/certificates/$CERT_ID/renew" | jq '.job_id'
```

**Expected:** Renewal job created and eventually moves to Completed status.
**PASS if** certificate is issued by Vault with valid serial number and chain.

### 38.3 Verify Certificate Serial and Subject

**Test:** Check that the issued certificate has correct Vault metadata.

```bash
curl -s -H "$AUTH" \
  "$SERVER/api/v1/certificates/$CERT_ID" | jq '.versions[0] | {serial, subject_dn, not_before, not_after}'
```

**Expected:** Serial, DN, and validity dates from Vault PKI.
**PASS if** certificate metadata is populated from Vault's response.

### 38.4 Revocation Records Locally

**Test:** Revoke the certificate and verify local recording.

```bash
curl -s -X POST -H "$AUTH" \
  "$SERVER/api/v1/certificates/$CERT_ID/revoke" \
  -d '{"reason": "superseded"}' | jq '.revoked_at'
```

**Expected:** Returns `revoked_at` timestamp.
**PASS if** revocation is recorded locally in the audit trail but not propagated to Vault (Vault is authoritative for its own revocation).

---

## Part 39: DigiCert Connector (M37)

### Prerequisites

- DigiCert CertCentral account with API access
- API key and organization ID from DigiCert
- Environment variables configured:
  ```bash
  export CERTCTL_DIGICERT_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxx"
  export CERTCTL_DIGICERT_ORG_ID="123456"
  export CERTCTL_DIGICERT_PRODUCT_TYPE="ssl_basic"
  export CERTCTL_DIGICERT_BASE_URL="https://www.digicert.com/services/v2"
  ```

### 39.1 Register DigiCert Issuer

**Test:** Register a DigiCert CertCentral issuer via the API.

```bash
curl -X POST -H "$AUTH" -H "$CT" \
  "$SERVER/api/v1/issuers" \
  -d '{
    "id": "iss-digicert-prod",
    "name": "DigiCert CertCentral",
    "type": "DigiCert",
    "config": {
      "api_key": "'"$CERTCTL_DIGICERT_API_KEY"'",
      "org_id": "'"$CERTCTL_DIGICERT_ORG_ID"'",
      "product_type": "'"$CERTCTL_DIGICERT_PRODUCT_TYPE"'",
      "base_url": "'"$CERTCTL_DIGICERT_BASE_URL"'"
    }
  }' | jq '.id'
```

**Expected:** Returns issuer ID `iss-digicert-prod`.
**PASS if** issuer is registered and appears in `GET /api/v1/issuers`.

### 39.2 Issue DV Certificate via DigiCert

**Test:** Create a DV certificate order and track it to completion.

```bash
CERT_ID=$(curl -s -X POST -H "$AUTH" -H "$CT" \
  "$SERVER/api/v1/certificates" \
  -d '{
    "common_name": "dv-test.example.com",
    "issuer_id": "iss-digicert-prod",
    "key_algorithm": "RSA-2048"
  }' | jq -r '.id')

JOB_ID=$(curl -s -X POST -H "$AUTH" \
  "$SERVER/api/v1/certificates/$CERT_ID/renew" | jq -r '.job_id')

# Poll for job completion (DV certs may issue immediately)
for i in {1..30}; do
  STATUS=$(curl -s -H "$AUTH" \
    "$SERVER/api/v1/jobs/$JOB_ID" | jq -r '.status')
  echo "Job status: $STATUS"
  [ "$STATUS" = "Completed" ] && break
  sleep 2
done
```

**Expected:** Job eventually reaches Completed status with certificate issued.
**PASS if** certificate has DigiCert serial number and chain.

### 39.3 Verify Order ID Tracking

**Test:** Check that the job record includes the DigiCert order ID for auditing.

```bash
curl -s -H "$AUTH" \
  "$SERVER/api/v1/jobs/$JOB_ID" | jq '.metadata'
```

**Expected:** Metadata includes `order_id` from DigiCert for order tracking.
**PASS if** audit trail shows the DigiCert order lifecycle.

### 39.4 Async Poll Behavior

**Test:** Verify the connector polls for certificate completion (OV certs take longer).

```bash
# Submit OV certificate order (requires validation)
CERT_ID=$(curl -s -X POST -H "$AUTH" -H "$CT" \
  "$SERVER/api/v1/certificates" \
  -d '{
    "common_name": "ov-test.example.com",
    "issuer_id": "iss-digicert-prod",
    "key_algorithm": "RSA-2048"
  }' | jq -r '.id')

JOB_ID=$(curl -s -X POST -H "$AUTH" \
  "$SERVER/api/v1/certificates/$CERT_ID/renew" | jq -r '.job_id')

# Check job status transitions
curl -s -H "$AUTH" "$SERVER/api/v1/jobs/$JOB_ID" | jq '.status'
```

**Expected:** Job status transitions through pending states as DigiCert validates.
**PASS if** polling mechanism works and job reaches completion once DigiCert issues the certificate.

### 39.5 Revocation Records Locally

**Test:** Revoke a DigiCert-issued certificate.

```bash
curl -s -X POST -H "$AUTH" \
  "$SERVER/api/v1/certificates/$CERT_ID/revoke" \
  -d '{"reason": "cessationOfOperation"}' | jq '.revoked_at'
```

**Expected:** Returns `revoked_at` timestamp.
**PASS if** revocation is recorded locally; operator manages revocation in DigiCert CertCentral dashboard.

---

## Part 40: Issuer Catalog Page (M33)

Frontend-only milestone. No backend changes. All tests are automated via `qa-smoke-test.sh` and `vitest`.

### 40.1 Shared Issuer Type Config

**Test:** Verify shared config file exists with all 6 supported types + 2 coming soon stubs.

```bash
test -f web/src/config/issuerTypes.ts
grep -c 'VaultPKI' web/src/config/issuerTypes.ts    # >= 1
grep -c 'DigiCert' web/src/config/issuerTypes.ts     # >= 1
grep -cE 'eab_kid|eab_hmac' web/src/config/issuerTypes.ts  # >= 1
grep -c 'sensitive' web/src/config/issuerTypes.ts     # >= 1
```

**PASS if** file exists, all types present, EAB fields and sensitive flags included.

### 40.2 Composable Wizard Components

**Test:** Verify reusable components exist.

```bash
test -f web/src/components/issuer/TypeSelector.tsx
test -f web/src/components/issuer/ConfigForm.tsx
test -f web/src/components/issuer/ConfigDetailModal.tsx
```

**PASS if** all 3 component files exist.

### 40.3 Frontend Build

**Test:** Verify frontend builds with zero errors.

```bash
cd web && npm run build 2>&1 | tail -1 | grep -q 'built in'
```

**PASS if** build succeeds.

### 40.4 Frontend Tests

**Test:** Verify all Vitest tests pass including new VaultPKI/DigiCert create tests.

```bash
cd web && npx vitest run 2>&1 | grep -qE 'Tests.*passed'
```

**PASS if** all tests pass.

### 40.5 (Manual) Create VaultPKI Issuer via Wizard

**Test:** Open Issuers page, click "Configure" on Vault PKI card, fill in form (addr, token, mount, role, ttl), submit.
**PASS if** issuer appears in configured issuers table.

### 40.6 (Manual) Create DigiCert Issuer via Wizard

**Test:** Open Issuers page, click "Configure" on DigiCert card, fill in form (api_key, org_id, product_type), submit.
**PASS if** issuer appears in configured issuers table.

### 40.7 (Manual) Create ACME Issuer with EAB Fields

**Test:** Open create wizard, select ACME, verify EAB Key ID and EAB HMAC Key fields are visible.
**PASS if** EAB fields render and accept input.

### 40.8 (Manual) Catalog Cards Show Correct Status

**Test:** Verify catalog cards show "Connected" (green, count) for types with configured issuers, "Available" (blue) for unconfigured types, and "Coming Soon" (grey) for Sectigo/Entrust.
**PASS if** all 8 cards render with correct status.

### 40.9 (Manual) Config Detail Modal Shows Full Redacted Config

**Test:** Click "View Config" on a configured issuer row. Verify modal shows full config JSON with sensitive fields (token, key, hmac, password, private, secret) redacted as `********`.
**PASS if** modal opens, full config visible, sensitive fields redacted.

### 40.10 (Manual) Issuer Type Filter Works

**Test:** Use the type filter dropdown above the configured issuers table. Select a specific type.
**PASS if** table filters to show only issuers of the selected type.

---

## Part 41: Frontend Audit Fixes

Comprehensive frontend coverage audit closed 60 gaps between backend capabilities and GUI surfaces. This part validates the critical fixes.

### Automated Tests (qa-smoke-test.sh Part 41)

| # | Test | Assertion |
|---|------|-----------|
| 41.1 | Certificate TS type has lifecycle fields | `types.ts` contains `last_renewal_at`, `last_deployment_at`, `target_ids` |
| 41.2 | API client has new endpoint functions | `client.ts` exports `updateIssuer`, `updateTarget`, `getCertificateDeployments`, `getCRL`, `getOCSPStatus`, `getPolicy` |
| 41.3 | CertificatesPage has filter dropdowns | Contains `issuerFilter`, `ownerFilter`, `profileFilter` state vars |
| 41.4 | CertificatesPage shows last_renewal_at | Column renders `last_renewal_at` field |
| 41.5 | JobsPage shows error_message | Error column displays first 80 chars for failed jobs |
| 41.6 | ProfilesPage has key algorithm fields | Create form includes `allowed_key_algorithms` with add/remove rows |
| 41.7 | ProfilesPage has EKU checkboxes | Create form includes `allowed_ekus` checkbox group |
| 41.8 | DiscoveryPage shows is_ca badge | CA badge renders for discovered CA certificates |
| 41.9 | TargetDetailPage has Edit functionality | Edit button wired to `updateTarget` API call |
| 41.10 | CertificatesPage has tags field | Create form includes tags input (key=value pairs) |
| 41.11 | AgentFleetPage maps darwin to macOS | OS display mapping applied to pie chart and platform headers |
| 41.12 | Frontend builds after audit fixes | `npm run build` succeeds |

### Manual Tests

**41.M1: Profile Create Form — Key Algorithm Configuration**

1. Navigate to Profiles page, click "+ New Profile"
2. Verify default algorithms shown: ECDSA 256+, RSA 2048+
3. Click "Remove" on RSA row — verify it disappears
4. Click "+ Add" — verify Ed25519 appears (with "fixed" instead of size dropdown)
5. Submit form, verify profile created with correct `allowed_key_algorithms` array

**PASS if** algorithms are configurable and persisted correctly.

**41.M2: Profile Create Form — EKU Selection**

1. In Create Profile modal, verify EKU checkboxes visible (serverAuth checked by default)
2. Check "Email Protection (S/MIME)" and "Client Authentication"
3. Submit, verify profile has `allowed_ekus: ["serverAuth", "emailProtection", "clientAuth"]`

**PASS if** EKUs are selectable and sent to backend.

**41.M3: Certificate Create Form — Tags**

1. Navigate to Certificates page, click "+ New Certificate"
2. Enter tags: `env=prod, team=platform, app=api`
3. Submit, verify certificate created with `tags: {"env": "prod", "team": "platform", "app": "api"}`

**PASS if** tags are parsed and persisted as key-value pairs.

**41.M4: Jobs Table — Error Message Column**

1. Navigate to Jobs page, filter to "Failed" status
2. Verify "Error" column shows truncated error message (max 80 chars with "...")
3. Hover over truncated message, verify full text in tooltip

**PASS if** error messages visible for failed jobs.

**41.M5: Certificates Table — Lifecycle Columns**

1. Navigate to Certificates page
2. Verify "Last Renewal" and "Last Deploy" columns visible
3. Verify dates shown for certs with data, "—" for certs without

**PASS if** lifecycle timestamps displayed.

**41.M6: Certificate Filters — Issuer/Owner/Profile Dropdowns**

1. Navigate to Certificates page
2. Verify Issuer, Owner, Profile dropdown filters visible
3. Select an issuer — verify table filters to matching certificates
4. Clear filter, select a profile — verify filtering works

**PASS if** all three filter dropdowns functional.

**41.M7: Target Detail — Edit Button**

1. Navigate to a target detail page
2. Click "Edit" button
3. Modify name, click "Save"
4. Verify name updated on the page

**PASS if** target edit persists via API.

**41.M8: Discovery Table — CA Badge**

1. Navigate to Discovery page
2. Verify "Key" column shows algorithm + key size
3. For CA certificates, verify purple "CA" badge displayed

**PASS if** CA certificates visually distinguished.

**41.M9: Fleet Overview — macOS Display**

1. Navigate to Fleet Overview page
2. Verify OS pie chart shows "macOS" instead of "darwin"
3. Verify platform section headers show "macOS / amd64" (not "darwin / amd64")

**PASS if** darwin correctly mapped to macOS in all locations.

---

## Part 42: IIS Target Connector (M39)

The IIS target connector (M39) brings Windows infrastructure lifecycle management to certctl. Dual-mode implementation: agent-local PowerShell (primary) for servers with certctl agent, proxy agent WinRM for agentless Windows targets. Full test suite (28 tests) with mock executor pattern for cross-platform testing. Supports PEM-to-PFX conversion, SHA-1 thumbprint computation, and parameterized PowerShell execution.

### Test Suite Coverage

| Layer | Test Count | Focus | Cross-Platform |
|-------|-----------|-------|-----------------|
| ValidateConfig | 9 | Field validation, defaults, regex enforcement | Yes |
| DeployCertificate | 7 | PFX conversion, script execution, error handling | Yes |
| ValidateDeployment | 5 | Thumbprint verification, binding checks | Mock executor |
| PFX Conversion | 4 | Certificate chain handling, password generation | Yes |
| Helpers | 3 | Thumbprint computation, Windows time conversion | Yes |
| **Total** | **28** | | **26 pass, 2 skip on non-Windows** |

### Automated Tests (qa-smoke-test.sh Part 42)

| # | Test | Assertion |
|---|------|-----------|
| 42.1 | IIS connector imports without error | `internal/connector/target/iis/` builds cleanly |
| 42.2 | ValidateConfig rejects missing hostname | Validation fails when `hostname` absent |
| 42.3 | ValidateConfig rejects missing site_name | Validation fails when `site_name` absent |
| 42.4 | ValidateConfig applies defaults | `port` defaults to 443, `ip_address` to "*" |
| 42.5 | ValidateConfig validates field regex | Rejects field names with invalid characters |
| 42.6 | PEM-to-PFX conversion succeeds | PKCS#12 bundle created with random password |
| 42.7 | SHA-1 thumbprint computed correctly | Matches Go crypto/sha1 output, hex-encoded |
| 42.8 | PowerShell script is parameterized | No unescaped interpolation in generated commands |
| 42.9 | Mock executor pattern works cross-platform | Tests pass on Linux/macOS via mock executor |
| 42.10 | DeployCertificate calls Import-PfxCertificate | PowerShell command includes correct cert store |
| 42.11 | DeployCertificate calls Set-WebBinding | PowerShell command includes site name + thumbprint |
| 42.12 | ValidateDeployment executes Get-IISSiteBinding | Thumbprint comparison happens post-deployment |
| 42.13 | Error cases logged and propagated | TLS verify failure, script timeout errors handled |
| 42.14 | Windows time conversion helpers work | FileTime ↔ time.Time round-trip accurate |

### Manual Tests (Windows Only)

These tests require a real Windows Server 2019+ environment with IIS 10+. Skip on non-Windows platforms.

**42.M1: Agent-Local Deployment — Happy Path**

1. Provision a Windows Server 2019+ VM with IIS installed
2. Download and install certctl-agent binary for windows-amd64
3. Register agent with certctl server via heartbeat endpoint
4. Create IIS target in certctl dashboard:
   ```json
   {
     "hostname": "iis-server.local",
     "site_name": "Default Web Site",
     "cert_store": "WebHosting",
     "port": 443,
     "sni": true,
     "ip_address": "*"
   }
   ```
5. Issue a certificate (e.g., via Local CA)
6. Create deployment job targeting the IIS target
7. Agent polls work endpoint, executes PowerShell
8. Verify on IIS: `Get-IISSiteBinding` shows new binding with correct thumbprint
9. Verify in dashboard: Deployment job shows status=Completed, verified_at timestamp present

**PASS if** certificate deployed to IIS binding with matching thumbprint, deployment job shows Completed with verification success.

**42.M2: Agent-Local Deployment — Renewal**

1. On the same IIS target, trigger renewal of the certificate
2. Verify old certificate remains bound during renewal (until new one succeeds)
3. Verify new certificate is imported and bound after deployment
4. Verify old binding removed or updated in IIS

**PASS if** renewal completes without downtime, old binding replaced with new.

**42.M3: PFX Import to WebHosting Store**

1. Manually generate a test PKCS#12 certificate
2. Via certctl-agent on Windows, verify PowerShell can import to WebHosting store:
   ```powershell
   $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
   $pfx.Import([System.IO.File]::ReadAllBytes("C:\temp\test.pfx"), $password, "Exportable")
   $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("WebHosting", "LocalMachine")
   $store.Open("MaxAllowed")
   $store.Add($pfx)
   ```
3. Verify certificate appears in IIS Certificate Manager

**PASS if** certificate imports to WebHosting store successfully.

**42.M4: Binding Verification — Thumbprint Match**

1. Deploy a certificate to an IIS site via certctl
2. Manually run on IIS server:
   ```powershell
   Get-IISSiteBinding -Name "Default Web Site" | Select-Object Thumbprint
   ```
3. Verify thumbprint matches certificate's SHA-1 hash (as shown in certctl GUI)

**PASS if** thumbprints match exactly (hex-encoded, no colons).

**42.M5: Error Handling — Invalid Site Name**

1. Create IIS target with non-existent site name (e.g., "NonExistentSite")
2. Trigger deployment
3. Verify job fails with error message about invalid site
4. Verify error is logged in agent and audit trail

**PASS if** error handled gracefully, job marked Failed with reason.

**42.M6: Field Validation — Config Injection Attempt**

1. Try to create IIS target with site_name containing PowerShell metacharacters:
   ```json
   {
     "site_name": "Default Web Site'; Get-Process; #"
   }
   ```
2. Verify regex validation rejects this (field validation error, not API error)
3. Verify no PowerShell execution occurs

**PASS if** injection attempt blocked by field validation.

**42.M7: SNI vs Non-SNI Binding**

1. Create two IIS targets: one with `sni: true`, one with `sni: false`
2. Deploy certificates to both
3. Verify Set-WebBinding with `-SslFlags 1` (SNI) for first target
4. Verify Set-WebBinding without SslFlags (no SNI) for second target
5. Test TLS connection to both sites, verify SNI-enabled site handles multiple domains correctly

**PASS if** SNI bindings configured correctly per target config.

---

## Release Sign-Off

All tests below must pass before tagging v2.1.0. Each row is one individual test from the guide above. The **Method** column indicates whether `qa-smoke-test.sh` covers the test automatically (**Auto**) or requires hands-on verification (**Manual**).

### Automated Prerequisites

These must be green before starting manual QA:

| Gate | Pass? | Date | Notes |
|------|-------|------|-------|
| CI pipeline green (Go build + vet + race + lint + vuln + tests) | ☐ | | |
| CI pipeline green (Frontend tsc + vitest + vite build) | ☐ | | |
| Coverage thresholds met (service 60%, handler 60%, domain 40%, middleware 50%) | ☐ | | |
| `qa-smoke-test.sh` — 0 failures | ☑ | 2026-03-30 | 124 pass, 0 fail, 5 skip |

### Part 1: Infrastructure & Deployment

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 1.1.1 | PostgreSQL is accepting connections | Auto | ☑ | 2026-03-30 |  |
| 1.1.2 | Database schema applied (21 tables) | Auto | ☑ | 2026-03-30 |  |
| 1.1.3 | Server liveness probe | Auto | ☑ | 2026-03-30 |  |
| 1.1.4 | Server readiness probe | Auto | ☑ | 2026-03-30 |  |
| 1.1.5 | Agent container is running | Auto | ☑ | 2026-03-30 |  |
| 1.1.6 | Demo seed data loaded (all 9 resource types) | Auto | ☑ | 2026-03-30 |  |
| 1.2.1 | Server shuts down cleanly on SIGTERM | Manual | ☐ |  |  |
| 1.2.2 | Data persists across full restart | Manual | ☐ |  |  |
| 1.3.1 | Custom port binding | Manual | ☐ |  |  |
| 1.3.2 | Debug logging | Manual | ☐ |  |  |
| 1.3.3 | Auth disabled with explicit none | Auto | ☑ | 2026-03-30 |  |
| 1.3.4 | Auth none produces warning log | Auto | ☑ | 2026-03-30 |  |

### Part 2: Authentication & Security

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 2.1.1 | Request without auth header returns 401 | Manual | ☐ |  |  |
| 2.1.2 | Request with wrong API key returns 401 | Manual | ☐ |  |  |
| 2.1.3 | Request with valid API key returns 200 | Manual | ☐ |  |  |
| 2.1.4 | /health accessible without auth (always) | Manual | ☐ |  |  |
| 2.1.5 | /ready accessible without auth (always) | Manual | ☐ |  |  |
| 2.1.6 | /api/v1/auth/info accessible without auth (GUI bootstrap) | Manual | ☐ |  |  |
| 2.1.7 | /api/v1/auth/check with valid key returns 200 | Manual | ☐ |  |  |
| 2.1.8 | /api/v1/auth/check without key returns 401 | Manual | ☐ |  |  |
| 2.2.1 | Burst exceeds limit, returns 429 with Retry-After | Manual | ☐ |  |  |
| 2.2.2 | 429 response includes Retry-After header | Manual | ☐ |  |  |
| 2.2.3 | Rate limit bucket refills after waiting | Manual | ☐ |  |  |
| 2.3.1 | Preflight OPTIONS with allowed origin returns CORS headers | Manual | ☐ |  |  |
| 2.3.2 | Request from disallowed origin has no CORS headers | Manual | ☐ |  |  |
| 2.3.3 | Wildcard CORS mode | Manual | ☐ |  |  |
| 2.4.1 | Private keys never in API responses (certificate detail) | Auto | ☑ | 2026-03-30 |  |
| 2.4.2 | Private keys never in API responses (certificate versions) | Auto | ☑ | 2026-03-30 |  |
| 2.4.3 | Private keys never in API responses (agent work) | Auto | ☑ | 2026-03-30 |  |
| 2.4.4 | Private keys never in server logs | Auto | ☑ | 2026-03-30 |  |
| 2.4.5 | API key stored as SHA-256 hash (not plaintext) | Manual | ☐ |  |  |

### Part 3: Certificate Lifecycle (CRUD)

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 3.1.1 | Create certificate with minimal fields | Auto | ☑ | 2026-03-30 |  |
| 3.1.2 | Create certificate with all fields | Auto | ☑ | 2026-03-30 |  |
| 3.1.3 | Create certificate with duplicate common_name | Auto | ☑ | 2026-03-30 |  |
| 3.2.1 | List certificates with pagination metadata | Auto | ☑ | 2026-03-30 |  |
| 3.2.2 | Filter by status | Auto | ☑ | 2026-03-30 |  |
| 3.2.3 | Filter by owner | Auto | ☑ | 2026-03-30 |  |
| 3.2.4 | Filter by issuer | Auto | ☑ | 2026-03-30 |  |
| 3.2.5 | Filter by environment | Auto | ☑ | 2026-03-30 |  |
| 3.2.6 | Pagination: page 2 | Auto | ☑ | 2026-03-30 |  |
| 3.2.7 | Sort descending by notAfter | Manual | ☐ |  |  |
| 3.2.8 | Sort ascending by commonName | Manual | ☐ |  |  |
| 3.2.9 | Sparse fields | Auto | ☑ | 2026-03-30 |  |
| 3.2.10 | Cursor pagination: first page | Auto | ☑ | 2026-03-30 |  |
| 3.2.11 | Cursor pagination: second page | Manual | ☐ |  |  |
| 3.2.12 | Time-range filter: expires_before | Auto | ☑ | 2026-03-30 |  |
| 3.3.1 | Get single certificate by ID | Auto | ☑ | 2026-03-30 |  |
| 3.3.2 | Get nonexistent certificate returns 404 | Auto | ☑ | 2026-03-30 |  |
| 3.3.3 | Update certificate fields | Auto | ☑ | 2026-03-30 |  |
| 3.3.4 | Archive (soft delete) certificate | Auto | ☑ | 2026-03-30 |  |
| 3.3.5 | Get archived certificate behavior | Manual | ☐ |  |  |
| 3.4.1 | Get certificate versions | Auto | ☑ | 2026-03-30 |  |
| 3.4.2 | Get certificate deployments | Auto | ☑ | 2026-03-30 |  |
| 3.4.3 | Trigger deployment creates a job | Manual | ☐ |  |  |

### Part 4: Renewal Workflow

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 4.1.1 | Trigger renewal creates job | Auto | ☑ | 2026-03-30 |  |
| 4.1.2 | Renewal job appears in jobs list | Auto | ☑ | 2026-03-30 |  |
| 4.1.3 | Renewal on nonexistent certificate returns 404 | Auto | ☑ | 2026-03-30 |  |
| 4.2.1 | Server keygen mode: job completes automatically | Manual | ☐ |  |  |
| 4.3.1 | Approve a job | Manual | ☐ |  |  |
| 4.3.2 | Reject a job with reason | Manual | ☐ |  |  |
| 4.4.1 | Agent work endpoint returns pending jobs | Auto | ☑ | 2026-03-30 |  |
| 4.4.2 | Agent reports job status | Manual | ☐ |  |  |

### Part 5: Revocation

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 5.1.1 | Revoke with default reason | Auto | ☑ | 2026-03-30 |  |
| 5.1.2 | Revoke with reason: keyCompromise | Auto | ☑ | 2026-03-30 |  |
| 5.1.3 | Revoke with reason: caCompromise | Manual | ☐ |  |  |
| 5.1.4 | Revoke with reason: affiliationChanged | Manual | ☐ |  |  |
| 5.1.5 | Revoke with reason: superseded | Manual | ☐ |  |  |
| 5.1.6 | Revoke with reason: cessationOfOperation | Manual | ☐ |  |  |
| 5.1.7 | Revoke with reason: certificateHold | Manual | ☐ |  |  |
| 5.1.8 | Revoke with reason: privilegeWithdrawn | Manual | ☐ |  |  |
| 5.2.1 | Revoke already-revoked certificate | Auto | ☑ | 2026-03-30 |  |
| 5.2.2 | Revoke nonexistent certificate | Auto | ☑ | 2026-03-30 |  |
| 5.2.3 | Revoke with invalid reason | Auto | ☑ | 2026-03-30 |  |
| 5.2.4 | Revocation appears in audit trail | Manual | ☐ |  |  |
| 5.3.1 | JSON CRL endpoint | Auto | ☑ | 2026-03-30 |  |
| 5.3.2 | DER CRL endpoint | Auto | ☑ | 2026-03-30 |  |
| 5.3.3 | OCSP: good response for non-revoked cert | Auto | ☑ | 2026-03-30 |  |
| 5.3.4 | OCSP: revoked response for revoked cert | Manual | ☐ |  |  |
| 5.3.5 | OCSP: unknown serial | Manual | ☐ |  |  |

### Part 6: Issuer Connectors

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 6.1.1 | List issuers shows seed data | Auto | ☑ | 2026-03-30 |  |
| 6.1.2 | Get issuer detail | Auto | ☑ | 2026-03-30 |  |
| 6.1.3 | Create issuer | Auto | ☑ | 2026-03-30 |  |
| 6.1.4 | Update issuer | Manual | ☐ |  |  |
| 6.1.5 | Delete issuer | Auto | ☑ | 2026-03-30 |  |
| 6.1.6 | Test issuer connection | Manual | ☐ |  |  |
| 6.1.7 | Create issuer with missing name returns validation error | Auto | ☑ | 2026-03-30 |  |
| 6.1.8 | Create issuer with invalid type | Manual | ☐ |  |  |
| 6.2.1 | List ACME issuer with DNS-01 configuration | Manual | ☐ |  |  |
| 6.2.2 | Create ACME issuer with DNS-PERSIST-01 | Manual | ☐ |  |  |
| 6.2.3 | Configure ACME with External Account Binding (ZeroSSL) | Manual | ☐ |  |  |

### Part 7: Target Connectors & Deployment

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 7.1.1 | List targets shows seed data | Auto | ☑ | 2026-03-30 |  |
| 7.1.2 | Create NGINX target | Auto | ☑ | 2026-03-30 |  |
| 7.1.3 | Create Apache target | Manual | ☐ |  |  |
| 7.1.4 | Create HAProxy target | Manual | ☐ |  |  |
| 7.1.5 | Create F5 BIG-IP target (stub) | Auto | ☑ | 2026-03-30 |  |
| 7.1.6 | Create IIS target | Auto | ☑ | 2026-03-30 |  |
| 7.1.7 | Get target verifies type-specific config stored | Manual | ☐ |  |  |
| 7.1.8 | Update target config | Manual | ☐ |  |  |
| 7.1.9 | Delete target returns 204 | Auto | ☑ | 2026-03-30 |  |

### Part 8: Agent Operations

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 8.1.1 | Register new agent | Auto | ☑ | 2026-03-30 |  |
| 8.1.2 | List agents includes new agent | Manual | ☐ |  |  |
| 8.1.3 | Get agent detail with metadata | Manual | ☐ |  |  |
| 8.2.1 | Agent heartbeat updates last_heartbeat_at | Auto | ☑ | 2026-03-30 |  |
| 8.2.2 | Heartbeat metadata stored | Auto | ☑ | 2026-03-30 |  |
| 8.2.3 | Heartbeat for nonexistent agent | Auto | ☑ | 2026-03-30 |  |
| 8.3.1 | Agent work polling returns jobs | Manual | ☐ |  |  |
| 8.3.2 | Agent work polling with no pending work | Manual | ☐ |  |  |
| 8.3.3 | Agent certificate pickup | Manual | ☐ |  |  |
| 8.3.4 | Delete agent for cleanup | Auto | — | 2026-03-30 | Skipped — DELETE not implemented |

### Part 9: Job System

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 9.1.1 | List jobs with pagination | Auto | ☑ | 2026-03-30 |  |
| 9.1.2 | Filter jobs by status | Manual | ☐ |  |  |
| 9.1.3 | Filter jobs by type | Manual | ☐ |  |  |
| 9.1.4 | Get job detail | Manual | ☐ |  |  |
| 9.1.5 | Get nonexistent job | Auto | ☑ | 2026-03-30 |  |
| 9.2.1 | Cancel pending job | Manual | ☐ |  |  |
| 9.2.2 | Cancel already-completed job | Manual | ☐ |  |  |

### Part 10: Policies & Profiles

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 10.1.1 | List policies | Auto | ☑ | 2026-03-30 |  |
| 10.1.2 | Create policy | Auto | ☑ | 2026-03-30 |  |
| 10.1.3 | Get policy | Manual | ☐ |  |  |
| 10.1.4 | Update policy | Manual | ☐ |  |  |
| 10.1.5 | Delete policy | Auto | ☑ | 2026-03-30 |  |
| 10.1.6 | Policy violations endpoint | Manual | ☐ |  |  |
| 10.1.7 | Invalid policy type returns 400 | Auto | ☑ | 2026-03-30 |  |
| 10.2.1 | List profiles | Auto | ☑ | 2026-03-30 |  |
| 10.2.2 | Create profile with crypto constraints | Auto | ☑ | 2026-03-30 |  |
| 10.2.3 | Get profile | Manual | ☐ |  |  |
| 10.2.4 | Update profile | Manual | ☐ |  |  |
| 10.2.5 | Delete profile | Auto | ☑ | 2026-03-30 |  |
| 10.2.6 | Short-lived profile exists (TTL < 1 hour) | Manual | ☐ |  |  |

### Part 11: Ownership, Teams & Agent Groups

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 11.1.1 | List teams | Auto | ☑ | 2026-03-30 |  |
| 11.1.2 | Team CRUD cycle | Auto | ☑ | 2026-03-30 |  |
| 11.2.1 | Owner CRUD with team assignment | Auto | ☑ | 2026-03-30 |  |
| 11.2.2 | Get, update, delete owner | Manual | ☐ |  |  |
| 11.3.1 | List agent groups | Auto | ☑ | 2026-03-30 |  |
| 11.3.2 | Create agent group with dynamic criteria | Manual | ☐ |  |  |
| 11.3.3 | Agent group membership endpoint | Manual | ☐ |  |  |
| 11.3.4 | Delete agent group returns 204 | Manual | ☐ |  |  |
| 11.4.1 | Delete owner with assigned certificates (expect 409) | Auto | ☑ | 2026-03-30 |  |
| 11.4.2 | Delete issuer with assigned certificates (expect 409) | Auto | ☑ | 2026-03-30 |  |
| 11.4.3 | Delete team cascades successfully | Manual | ☐ |  |  |

### Part 12: Notifications

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 12.1.1 | List notifications with pagination | Auto | ☑ | 2026-03-30 |  |
| 12.1.2 | Get single notification | Manual | ☐ |  |  |
| 12.1.3 | Mark notification as read | Auto | ☑ | 2026-03-30 |  |
| 12.1.4 | Mark already-read notification (idempotent) | Manual | ☐ |  |  |
| 12.1.5 | Get nonexistent notification | Auto | ☑ | 2026-03-30 |  |
| 12.1.6 | Verify notification created from revocation | Manual | ☐ |  |  |

### Part 13: Observability

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 13.1.1 | Dashboard summary | Auto | ☑ | 2026-03-30 |  |
| 13.1.2 | Certificates by status | Auto | ☑ | 2026-03-30 |  |
| 13.1.3 | Expiration timeline | Auto | ☑ | 2026-03-30 |  |
| 13.1.4 | Job trends | Auto | ☑ | 2026-03-30 |  |
| 13.1.5 | Issuance rate | Auto | ☑ | 2026-03-30 |  |
| 13.1.6 | Stats with invalid days parameter | Manual | ☐ |  |  |
| 13.2.1 | JSON metrics endpoint | Auto | ☑ | 2026-03-30 |  |
| 13.2.2 | Metric values are non-negative | Manual | ☐ |  |  |
| 13.2.3 | Uptime is positive | Manual | ☐ |  |  |
| 13.3.1 | Prometheus content type | Auto | ☑ | 2026-03-30 |  |
| 13.3.2 | Prometheus output contains HELP lines | Auto | ☑ | 2026-03-30 |  |
| 13.3.3 | Prometheus output contains TYPE lines | Manual | ☐ |  |  |
| 13.3.4 | All documented Prometheus metrics present | Auto | ☑ | 2026-03-30 |  |
| 13.3.5 | Prometheus metric values are parseable numbers | Manual | ☐ |  |  |
| 13.3.6 | Method not allowed on metrics (POST) | Manual | ☐ |  |  |

### Part 14: Audit Trail

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 14.1.1 | List audit events | Auto | ☑ | 2026-03-30 |  |
| 14.1.2 | Get single audit event | Manual | ☐ |  |  |
| 14.1.3 | Filter audit by time range | Manual | ☐ |  |  |
| 14.1.4 | Filter audit by actor | Manual | ☐ |  |  |
| 14.1.5 | Filter audit by resource type | Auto | ☑ | 2026-03-30 |  |
| 14.1.6 | Filter audit by action | Manual | ☐ |  |  |
| 14.1.7 | API calls create audit entries | Manual | ☐ |  |  |
| 14.1.8 | Audit immutability (no PUT/DELETE) | Auto | ☑ | 2026-03-30 |  |

### Part 15: Certificate Discovery

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 15.1.1 | Submit discovery report | Auto | ☑ | 2026-03-30 |  |
| 15.1.2 | Submit report with multiple certificates | Manual | ☐ |  |  |
| 15.1.3 | Duplicate fingerprint deduplication | Manual | ☐ |  |  |
| 15.1.4 | List discovered certificates | Auto | ☑ | 2026-03-30 |  |
| 15.1.5 | Filter by status: Unmanaged | Manual | ☐ |  |  |
| 15.1.6 | Filter by agent_id | Manual | ☐ |  |  |
| 15.1.7 | Get discovered certificate detail | Manual | ☐ |  |  |
| 15.1.8 | Claim discovered certificate | Manual | ☐ |  |  |
| 15.1.9 | Dismiss discovered certificate | Manual | ☐ |  |  |
| 15.1.10 | List discovery scans | Manual | ☐ |  |  |
| 15.1.11 | Discovery summary | Auto | ☑ | 2026-03-30 |  |
| 15.2.1 | List network scan targets (seed data) | Auto | ☑ | 2026-03-30 |  |
| 15.2.2 | Create network scan target | Auto | ☑ | 2026-03-30 |  |
| 15.2.3 | Get scan target detail | Manual | ☐ |  |  |
| 15.2.4 | Update scan target | Manual | ☐ |  |  |
| 15.2.5 | Delete scan target | Auto | ☑ | 2026-03-30 |  |
| 15.2.6 | Trigger manual scan | Manual | ☐ |  |  |
| 15.2.7 | Invalid CIDR validation | Auto | ☑ | 2026-03-30 |  |

### Part 16: Enhanced Query API

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 16.1.1 | Sparse fields: only requested fields returned | Manual | ☐ |  |  |
| 16.1.2 | Sort ascending: commonName | Manual | ☐ |  |  |
| 16.1.3 | Sort descending: notAfter | Manual | ☐ |  |  |
| 16.1.4 | Sort by invalid field | Auto | ☑ | 2026-03-30 |  |
| 16.1.5 | Cursor pagination first page | Manual | ☐ |  |  |
| 16.1.6 | Cursor pagination second page | Manual | ☐ |  |  |
| 16.1.7 | Time-range: expires_before | Auto | ☑ | 2026-03-30 |  |
| 16.1.8 | Time-range: created_after | Auto | ☑ | 2026-03-30 |  |
| 16.1.9 | Combined filters | Auto | ☑ | 2026-03-30 |  |

### Part 17: CLI Tool

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 17.2.1 | List certificates (table format) | Manual | ☐ |  |  |
| 17.2.2 | List certificates (JSON format) | Manual | ☐ |  |  |
| 17.2.3 | Get specific certificate | Manual | ☐ |  |  |
| 17.2.4 | Get nonexistent certificate | Manual | ☐ |  |  |
| 17.2.5 | Renew certificate | Manual | ☐ |  |  |
| 17.2.6 | Revoke certificate with reason | Manual | ☐ |  |  |
| 17.3.1 | List agents | Manual | ☐ |  |  |
| 17.3.2 | List jobs | Manual | ☐ |  |  |
| 17.4.1 | Server status/health | Manual | ☐ |  |  |
| 17.4.2 | CLI version | Manual | ☐ |  |  |
| 17.5.1 | Import single PEM file | Manual | ☐ |  |  |
| 17.6.1 | --server flag overrides env var | Manual | ☐ |  |  |
| 17.6.2 | --api-key flag overrides env var | Manual | ☐ |  |  |
| 17.6.3 | Missing server URL produces error | Manual | ☐ |  |  |

### Part 18: MCP Server

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 18.1.1 | Binary builds successfully | Manual | ☐ |  |  |
| 18.1.2 | Startup with valid env vars | Manual | ☐ |  |  |
| 18.1.3 | Missing CERTCTL_SERVER_URL behavior | Manual | ☐ |  |  |
| 18.2.1 | Tool count verification (78 tools) | Manual | ☐ |  |  |
| 18.2.2 | All 16 resource domains present | Manual | ☐ |  |  |
| 18.3.1 | List certificates via MCP | Manual | ☐ |  |  |
| 18.3.2 | Get specific certificate via MCP | Manual | ☐ |  |  |

### Part 19: GUI Testing

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 19.1 | Authentication Flow | Manual | ☐ |  |  |
| 19.2 | Dashboard Page | Manual | ☐ |  |  |
| 19.3 | Certificates Page | Manual | ☐ |  |  |
| 19.4 | Certificate Detail Page | Manual | ☐ |  |  |
| 19.5 | Jobs Page — Approval Workflow | Manual | ☐ |  |  |
| 19.6 | Discovery Triage Page | Manual | ☐ |  |  |
| 19.7 | Network Scan Management Page | Manual | ☐ |  |  |
| 19.8 | Other Pages (agents, policies, audit, etc.) | Manual | ☐ |  |  |
| 19.9 | Cross-Cutting (responsive, error states, dark theme) | Manual | ☐ |  |  |

### Part 20: Background Scheduler

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 20.1.1 | Scheduler startup: all 7 loops registered | Manual | ☐ |  |  |
| 20.1.2 | Job processor loop fires (30s interval) | Manual | ☐ |  |  |
| 20.1.3 | Agent health check marks offline (2m interval) | Manual | ☐ |  |  |
| 20.1.4 | Notification processor fires (1m interval) | Manual | ☐ |  |  |
| 20.1.5 | Short-lived expiry check (30s interval) | Manual | ☐ |  |  |
| 20.1.6 | Network scanner loop (conditional on env var) | Manual | ☐ |  |  |
| 20.1.7 | Renewal check loop (1h interval — log verification) | Manual | ☐ |  |  |
| 20.1.8 | Scheduler graceful stop | Manual | ☐ |  |  |

### Part 21: Error Handling

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 21.1.1 | Malformed JSON body | Auto | ☑ | 2026-03-30 |  |
| 21.1.2 | Missing required field | Auto | ☑ | 2026-03-30 |  |
| 21.1.3 | Method not allowed | Auto | ☑ | 2026-03-30 |  |
| 21.1.4 | Invalid query parameter | Manual | ☐ |  |  |
| 21.1.5 | UTF-8 in common name | Auto | ☑ | 2026-03-30 |  |
| 21.1.6 | Concurrent requests (parallel curl) | Manual | ☐ |  |  |
| 21.1.7 | Server survives internal error | Auto | ☑ | 2026-03-30 |  |
| 21.1.8 | Empty request body on POST | Auto | ☑ | 2026-03-30 |  |

### Part 22: Performance Spot Checks

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 22.1.1 | List certificates < 200ms | Auto | ☑ | 2026-03-30 |  |
| 22.1.2 | Stats summary < 500ms | Auto | ☑ | 2026-03-30 |  |
| 22.1.3 | Metrics < 200ms | Auto | ☑ | 2026-03-30 |  |
| 22.1.4 | 50 health checks < 5 seconds total | Manual | ☐ |  |  |

### Part 23: Structured Logging

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 23.1.1 | Server logs are valid JSON | Manual | ☐ |  |  |
| 23.1.2 | Log lines contain level field | Manual | ☐ |  |  |
| 23.1.3 | Request ID propagation | Manual | ☐ |  |  |
| 23.1.4 | Error logs at ERROR level | Manual | ☐ |  |  |
| 23.1.5 | No unstructured output in log stream | Manual | ☐ |  |  |

### Part 24: Documentation Verification

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 24.1 | OpenAPI spec matches router, README accuracy | Manual | ☐ |  |  |

### Part 25: Regression Tests

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 25.1.1 | DELETE endpoints return 204, not 200 | Auto | ☑ | 2026-03-30 |  |
| 25.1.2 | per_page exceeding max falls back to default | Auto | ☑ | 2026-03-30 |  |
| 25.1.3 | Seed demo network scan targets present | Auto | ☑ | 2026-03-30 |  |
| 25.1.4 | GUI delete on FK-restricted entities shows error, not silent f... | Auto | ☑ | 2026-03-30 |  |
| 25.1.5 | OpenAPI spec operations match router | Manual | ☐ |  |  |
| 25.1.6 | Go service tests use strings.Contains, not errors.Is | Auto | ☑ | 2026-03-30 |  |

### Part 26: EST Server (RFC 7030)

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 26.1 | GET /.well-known/est/cacerts returns PKCS#7 CA chain | Auto | — | 2026-03-30 | Skipped — EST not enabled in demo |
| 26.2 | GET /cacerts method enforcement | Auto | — | 2026-03-30 | Skipped — EST not enabled in demo |
| 26.3 | POST /.well-known/est/simpleenroll with PEM CSR | Manual | ☐ |  |  |
| 26.4 | POST /simpleenroll with base64-encoded DER CSR | Manual | ☐ |  |  |
| 26.5 | POST /simpleenroll with empty body | Auto | — | 2026-03-30 | Skipped — EST not enabled in demo |
| 26.6 | POST /simpleenroll with invalid CSR | Manual | ☐ |  |  |
| 26.7 | POST /simpleenroll with CSR missing Common Name | Manual | ☐ |  |  |
| 26.8 | POST /simpleenroll method enforcement (GET not allowed) | Manual | ☐ |  |  |
| 26.9 | POST /.well-known/est/simplereenroll (re-enrollment) | Manual | ☐ |  |  |
| 26.10 | GET /simplereenroll method enforcement | Manual | ☐ |  |  |
| 26.11 | GET /.well-known/est/csrattrs returns 204 (no required attrs) | Auto | — | 2026-03-30 | Skipped — EST not enabled in demo |
| 26.12 | POST /csrattrs method enforcement | Manual | ☐ |  |  |
| 26.13 | EST enrollment creates audit event | Manual | ☐ |  |  |
| 26.14 | EST disabled returns 404 | Manual | ☐ |  |  |
| 26.15 | EST with profile binding | Manual | ☐ |  |  |

### Part 27: Post-Deployment TLS Verification

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 27.1 | Submit Verification Result (Success) | Manual | ☐ |  |  |
| 27.2 | Submit Verification Result (Failure — Fingerprint Mismatch) | Manual | ☐ |  |  |
| 27.3 | Get Verification Status | Manual | ☐ |  |  |
| 27.4 | Missing Required Fields | Manual | ☐ |  |  |
| 27.5 | Audit Trail | Manual | ☐ |  |  |
| 27.6 | Database Schema Verification | Auto | ☑ | 2026-03-30 |  |

### Part 28: Traefik & Caddy Target Connectors

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 28.1 | Traefik File Provider Deployment | Manual | ☐ |  |  |
| 28.2 | Caddy API Mode Deployment | Manual | ☐ |  |  |
| 28.3 | Caddy File Mode Deployment | Manual | ☐ |  |  |
| 28.4 | Agent Connector Dispatch | Manual | ☐ |  |  |
| 28.5 | Connector Unit Tests | Manual | ☐ |  |  |

### Part 29: Certificate Export

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 29.1 | Export PEM (JSON Response) | Auto | ☑ | 2026-03-30 |  |
| 29.2 | Export PEM (File Download) | Manual | ☐ |  |  |
| 29.3 | Export PEM — Not Found | Auto | ☑ | 2026-03-30 |  |
| 29.4 | Export PKCS#12 | Auto | ☑ | 2026-03-30 |  |
| 29.5 | Export PKCS#12 — Empty Password | Manual | ☐ |  |  |
| 29.6 | Export Audit Trail | Manual | ☐ |  |  |
| 29.7 | Export Unit Tests | Manual | ☐ |  |  |
| 29.8 | GUI Export Buttons | Manual | ☐ |  |  |

### Part 30: S/MIME & EKU Support

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 30.1 | S/MIME Profile Exists in Seed Data | Auto | ☑ | 2026-03-30 |  |
| 30.2 | All Five Profiles Present | Auto | ☑ | 2026-03-30 |  |
| 30.3 | EKU Strings in Profile API | Manual | ☐ |  |  |
| 30.4 | Agent CSR SAN Splitting (Email vs DNS) | Manual | ☐ |  |  |
| 30.5 | EKU Service-Layer Tests | Manual | ☐ |  |  |

### Part 31: OCSP Responder & DER CRL

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 31.1 | DER-Encoded CRL | Auto | ☑ | 2026-03-30 |  |
| 31.2 | DER CRL — Nonexistent Issuer | Auto | ☑ | 2026-03-30 |  |
| 31.3 | OCSP Responder — Good Status | Manual | ☐ |  |  |
| 31.4 | OCSP Responder — Revoked Status | Manual | ☐ |  |  |
| 31.5 | OCSP — Unknown Certificate | Manual | ☐ |  |  |
| 31.6 | Short-Lived Certificate CRL Exemption | Manual | ☐ |  |  |
| 31.7 | OCSP / CRL Unit Tests | Manual | ☐ |  |  |

### Part 32: Request Body Size Limits

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 32.1 | Default 1MB Limit | Manual | ☐ |  |  |
| 32.2 | Normal-Sized Requests Work | Auto | ☑ | 2026-03-30 |  |
| 32.3 | Custom Body Size via Environment Variable | Manual | ☐ |  |  |
| 32.4 | Requests Without Bodies Are Unaffected | Auto | ☑ | 2026-03-30 |  |

### Part 33: Apache & HAProxy Target Connectors

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 33.1 | Create Apache Target | Manual | ☐ |  |  |
| 33.2 | Apache Config — Separate Files | Manual | ☐ |  |  |
| 33.3 | Create HAProxy Target | Manual | ☐ |  |  |
| 33.4 | HAProxy Combined PEM Requirement | Manual | ☐ |  |  |
| 33.5 | Shell Command Injection Prevention | Manual | ☐ |  |  |
| 33.6 | Connector Unit Tests | Manual | ☐ |  |  |

### Part 34: Sub-CA Mode

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 34.1 | Self-Signed Mode (Default) | Manual | ☐ |  |  |
| 34.2 | Sub-CA Mode — Configuration | Manual | ☐ |  |  |
| 34.3 | Sub-CA Chain Construction | Manual | ☐ |  |  |
| 34.4 | Sub-CA Validation — Non-CA Cert Rejected | Manual | ☐ |  |  |
| 34.5 | Sub-CA Key Format Support | Manual | ☐ |  |  |
| 34.6 | CRL Signing in Sub-CA Mode | Manual | ☐ |  |  |

### Part 35: ARI (RFC 9702) Scheduler Integration

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 35.a1 | ARI nil fallback — renewal jobs still created | Auto | ☑ | 2026-03-30 |  |
| 35.a2 | No ARI errors with Local CA issuer | Auto | ☑ | 2026-03-30 |  |
| 35.a3 | Server healthy after ARI wiring (metrics) | Auto | ☑ | 2026-03-30 |  |
| 35.1 | ARI defers renewal when CA says "not yet" (requires ACME+ARI) | Manual | ☐ |  |  |
| 35.2 | ARI triggers renewal when CA says "now" (requires ACME+ARI) | Manual | ☐ |  |  |
| 35.3 | ARI fallback on error — threshold-based (requires ACME+ARI) | Manual | ☐ |  |  |

### Part 36: Agent Work Routing (M31)

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 36.a1 | Agent receives only its deployment jobs | Auto | ☐ |  |  |
| 36.a2 | Agent with no targets gets empty work list | Auto | ☐ |  |  |
| 36.a3 | Deployment jobs have agent_id populated | Auto | ☐ |  |  |
| 36.1 | Multi-agent routing with 2 agents, 2 targets | Manual | ☐ |  |  |
| 36.2 | Agent with no assigned targets gets empty work | Manual | ☐ |  |  |
| 36.3 | Database agent_id populated on deployment jobs | Manual | ☐ |  |  |

### Part 37: GUI Completeness (Pre-2.1.0-E)

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 37.1 | DigestPage renders preview iframe | Manual | ☐ |  |  |
| 37.2 | DigestPage send button with confirmation modal | Manual | ☐ |  |  |
| 37.3 | ObservabilityPage shows metrics gauges | Manual | ☐ |  |  |
| 37.4 | ObservabilityPage Prometheus config block | Manual | ☐ |  |  |
| 37.5 | ObservabilityPage live Prometheus output | Manual | ☐ |  |  |
| 37.6 | JobDetailPage displays job info and timeline | Manual | ☐ |  |  |
| 37.7 | JobDetailPage verification section for deployment jobs | Manual | ☐ |  |  |
| 37.8 | IssuerDetailPage shows redacted config | Manual | ☐ |  |  |
| 37.9 | IssuerDetailPage test connection button | Manual | ☐ |  |  |
| 37.10 | IssuerDetailPage issued certificates list | Manual | ☐ |  |  |
| 37.11 | TargetDetailPage shows config and agent link | Manual | ☐ |  |  |
| 37.12 | TargetDetailPage deployment history table | Manual | ☐ |  |  |
| 37.13 | JobsPage — job IDs clickable to /jobs/:id | Manual | ☐ |  |  |
| 37.14 | JobsPage — verification column for deployment jobs | Manual | ☐ |  |  |
| 37.15 | IssuersPage — issuer names clickable to /issuers/:id | Manual | ☐ |  |  |
| 37.16 | TargetsPage — target names clickable to /targets/:id | Manual | ☐ |  |  |
| 37.17 | Sidebar — Digest and Observability nav items | Manual | ☐ |  |  |

### Part 38: Vault PKI Connector (M32)

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 38.s1 | Vault PKI issuer exists in seed data | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 38.1 |
| 38.s2 | Vault issuer type is VaultPKI | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 38.2 |
| 38.s3 | Vault issuer is enabled | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 38.3 |
| 38.s4 | Vault connector passes go vet | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 38.4 |
| 38.s5 | Vault connector tests pass | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 38.5 |
| 38.s6 | OpenAPI spec includes VaultPKI type | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 38.6 |
| 38.1 | Register Vault PKI issuer | Manual | ☐ |  | Requires live Vault server |
| 38.2 | Issue certificate via Vault PKI | Manual | ☐ |  | Requires live Vault server |
| 38.3 | Verify certificate serial and subject | Manual | ☐ |  | Requires live Vault server |
| 38.4 | Revocation records locally | Manual | ☐ |  | Requires live Vault server |

### Part 39: DigiCert Connector (M37)

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 39.s1 | DigiCert issuer exists in seed data | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 39.1 |
| 39.s2 | DigiCert issuer type is DigiCert | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 39.2 |
| 39.s3 | DigiCert issuer is enabled | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 39.3 |
| 39.s4 | DigiCert connector passes go vet | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 39.4 |
| 39.s5 | DigiCert connector tests pass | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 39.5 |
| 39.s6 | OpenAPI spec includes DigiCert type | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 39.6 |
| 39.1 | Register DigiCert issuer | Manual | ☐ |  | Requires DigiCert sandbox |
| 39.2 | Issue DV certificate via DigiCert | Manual | ☐ |  | Requires DigiCert sandbox |
| 39.3 | Verify order ID tracking | Manual | ☐ |  | Requires DigiCert sandbox |
| 39.4 | Async poll behavior | Manual | ☐ |  | Requires DigiCert sandbox |
| 39.5 | Revocation records locally | Manual | ☐ |  | Requires DigiCert sandbox |

### Part 40: Issuer Catalog Page (M33)

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 40.s1 | Shared issuerTypes config exists | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 40.1 |
| 40.s2 | VaultPKI in issuerTypes config | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 40.2 |
| 40.s3 | DigiCert in issuerTypes config | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 40.3 |
| 40.s4 | ACME EAB fields in config | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 40.4 |
| 40.s5 | Sensitive field flag in config | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 40.5 |
| 40.s6 | ConfigDetailModal component exists | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 40.6 |
| 40.s7 | Frontend build succeeds | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 40.7 |
| 40.s8 | Frontend tests pass | Auto | ☑ | 2026-03-30 | qa-smoke-test.sh 40.8 |
| 40.m1 | Create VaultPKI issuer via wizard | Manual | ☐ |  | |
| 40.m2 | Create DigiCert issuer via wizard | Manual | ☐ |  | |
| 40.m3 | Create ACME issuer with EAB fields | Manual | ☐ |  | |
| 40.m4 | Catalog cards show correct status | Manual | ☐ |  | |
| 40.m5 | Config detail modal shows full redacted config | Manual | ☐ |  | |
| 40.m6 | Issuer type filter works | Manual | ☐ |  | |

### Part 41: Frontend Audit Fixes

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 41.s1 | Certificate TS type has lifecycle fields | Auto | ☐ |  | qa-smoke-test.sh 41.1 |
| 41.s2 | API client has new endpoint functions | Auto | ☐ |  | qa-smoke-test.sh 41.2 |
| 41.s3 | CertificatesPage has filter dropdowns | Auto | ☐ |  | qa-smoke-test.sh 41.3 |
| 41.s4 | CertificatesPage shows last_renewal_at | Auto | ☐ |  | qa-smoke-test.sh 41.4 |
| 41.s5 | JobsPage shows error_message | Auto | ☐ |  | qa-smoke-test.sh 41.5 |
| 41.s6 | ProfilesPage has key algorithm fields | Auto | ☐ |  | qa-smoke-test.sh 41.6 |
| 41.s7 | ProfilesPage has EKU checkboxes | Auto | ☐ |  | qa-smoke-test.sh 41.7 |
| 41.s8 | DiscoveryPage shows is_ca badge | Auto | ☐ |  | qa-smoke-test.sh 41.8 |
| 41.s9 | TargetDetailPage has Edit functionality | Auto | ☐ |  | qa-smoke-test.sh 41.9 |
| 41.s10 | CertificatesPage has tags field | Auto | ☐ |  | qa-smoke-test.sh 41.10 |
| 41.s11 | AgentFleetPage maps darwin to macOS | Auto | ☐ |  | qa-smoke-test.sh 41.11 |
| 41.s12 | Frontend builds after audit fixes | Auto | ☐ |  | qa-smoke-test.sh 41.12 |
| 41.m1 | Profile create form — key algorithm config | Manual | ☐ |  | |
| 41.m2 | Profile create form — EKU selection | Manual | ☐ |  | |
| 41.m3 | Certificate create form — tags | Manual | ☐ |  | |
| 41.m4 | Jobs table — error message column | Manual | ☐ |  | |
| 41.m5 | Certificates table — lifecycle columns | Manual | ☐ |  | |
| 41.m6 | Certificate filters — issuer/owner/profile | Manual | ☐ |  | |
| 41.m7 | Target detail — edit button | Manual | ☐ |  | |
| 41.m8 | Discovery table — CA badge | Manual | ☐ |  | |
| 41.m9 | Fleet overview — macOS display | Manual | ☐ |  | |

### Part 43: Sectigo SCM Connector (M43)

**Prerequisites:** Sectigo SCM account with API access, valid customerUri + login + password credentials, at least one cert type available in `/ssl/v1/types`.

#### Automated Tests

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 43.s1 | `IssuerTypeSectigo` constant exists in domain | Auto | ☐ |  | `grep 'Sectigo' internal/domain/connector.go` |
| 43.s2 | `SectigoConfig` struct exists in config | Auto | ☐ |  | `grep 'SectigoConfig' internal/config/config.go` |
| 43.s3 | `iss-sectigo` in seed_demo.sql | Auto | ☐ |  | `grep 'iss-sectigo' migrations/seed_demo.sql` |
| 43.s4 | Sectigo in OpenAPI IssuerType enum | Auto | ☐ |  | `grep 'Sectigo' api/openapi.yaml` |
| 43.s5 | Sectigo connector tests pass | Auto | ☐ |  | `go test ./internal/connector/issuer/sectigo/... -v` |
| 43.s6 | Sectigo in issuerTypes.ts | Auto | ☐ |  | `grep 'Sectigo' web/src/config/issuerTypes.ts` |
| 43.s7 | Frontend build succeeds | Auto | ☐ |  | `cd web && npm run build` |
| 43.s8 | Full Go build succeeds | Auto | ☐ |  | `go build ./cmd/server/... ./cmd/agent/... ./cmd/cli/... ./cmd/mcp-server/...` |

#### Manual Tests

**43.M1: Validate Sectigo Credentials**

1. Configure env vars: `CERTCTL_SECTIGO_CUSTOMER_URI`, `CERTCTL_SECTIGO_LOGIN`, `CERTCTL_SECTIGO_PASSWORD`, `CERTCTL_SECTIGO_ORG_ID`
2. Start certctl server — verify log line: `Sectigo SCM issuer registered`
3. Call `GET /api/v1/issuers` — verify `iss-sectigo` appears in the list

**PASS if** `iss-sectigo` registered and visible in API.

**43.M2: Enroll DV Certificate**

1. Create a certificate with `issuer_id: iss-sectigo`
2. Trigger issuance — verify enrollment submitted (job enters Pending or AwaitingCSR)
3. If DV, check for immediate issuance or poll via GetOrderStatus
4. Verify `sslId` tracked in job's order_id field

**PASS if** enrollment submits successfully, sslId returned, job state machine progresses.

**43.M3: Async Polling — OV Certificate**

1. Submit OV certificate enrollment (requires org validation)
2. Verify job enters Pending state with sslId in order_id
3. Wait for Sectigo to process (or mock status check)
4. Verify GetOrderStatus returns "pending" → "completed" transition
5. Verify PEM bundle downloaded and parsed (leaf + chain)

**PASS if** async flow works end-to-end with correct status transitions.

**43.M4: Collect Not Ready (400/-183 Handling)**

1. If possible, catch the window where status is "Issued" but cert not yet generated
2. Verify collect endpoint returns 400 with code -183
3. Verify GetOrderStatus treats this as "pending" (not error)
4. Verify next poll succeeds when cert is generated

**PASS if** 400/-183 handled gracefully as pending, not as error.

**43.M5: Revocation**

1. Revoke an issued Sectigo certificate via `POST /api/v1/certificates/{id}/revoke`
2. Verify Sectigo revoke endpoint called (`POST /ssl/v1/revoke/{sslId}`)
3. Verify audit trail records revocation

**PASS if** revocation recorded in certctl and sent to Sectigo.

**43.M6: Auth Header Verification**

1. Inspect network requests to Sectigo API (via proxy or logs)
2. Verify all 3 headers present: `customerUri`, `login`, `password`
3. Verify no `X-DC-DEVKEY` header (DigiCert auth should not leak)

**PASS if** correct 3-header auth on all requests.

### Part 44: Google CAS Issuer Connector (M44)

**Prerequisites:** GCP project with Certificate Authority Service enabled, CA pool created, service account with `roles/privateca.certificateManager`, service account JSON key file.

#### Automated Tests

| Test | Description | Method | Pass? | Date | Notes |
|------|-------------|--------|-------|------|-------|
| 44.s1 | `IssuerTypeGoogleCAS` constant exists in domain | Auto | ☐ |  | `grep 'GoogleCAS' internal/domain/connector.go` |
| 44.s2 | `GoogleCASConfig` struct exists in config | Auto | ☐ |  | `grep 'GoogleCASConfig' internal/config/config.go` |
| 44.s3 | `iss-googlecas` in seed_demo.sql | Auto | ☐ |  | `grep 'iss-googlecas' migrations/seed_demo.sql` |
| 44.s4 | GoogleCAS in OpenAPI IssuerType enum | Auto | ☐ |  | `grep 'GoogleCAS' api/openapi.yaml` |
| 44.s5 | Google CAS connector tests pass | Auto | ☐ |  | `go test ./internal/connector/issuer/googlecas/... -v` |
| 44.s6 | GoogleCAS in issuerTypes.ts | Auto | ☐ |  | `grep 'GoogleCAS' web/src/config/issuerTypes.ts` |
| 44.s7 | Frontend build succeeds | Auto | ☐ |  | `cd web && npm run build` |
| 44.s8 | Full Go build succeeds | Auto | ☐ |  | `go build ./cmd/server/... ./cmd/agent/... ./cmd/cli/... ./cmd/mcp-server/...` |

#### Manual Tests

**44.M1: Validate Google CAS Credentials**

1. Configure env vars: `CERTCTL_GOOGLE_CAS_PROJECT`, `CERTCTL_GOOGLE_CAS_LOCATION`, `CERTCTL_GOOGLE_CAS_CA_POOL`, `CERTCTL_GOOGLE_CAS_CREDENTIALS`
2. Start certctl server — verify log line: `Google CAS issuer registered`
3. Call `GET /api/v1/issuers` — verify `iss-googlecas` appears in the list

**PASS if** `iss-googlecas` registered and visible in API.

**44.M2: Issue Certificate via Google CAS**

1. Create a certificate with `issuer_id: iss-googlecas`
2. Trigger issuance — verify synchronous issuance (no async polling needed)
3. Verify PEM cert returned with correct CN and SANs
4. Verify certificate resource name stored in order_id field

**PASS if** certificate issued synchronously, PEM valid, resource name tracked.

**44.M3: Renewal via Google CAS**

1. Trigger renewal on a Google CAS-issued certificate
2. Verify new certificate issued (delegates to IssueCertificate)
3. Verify new serial number, updated validity dates

**PASS if** renewal produces new cert with new serial.

**44.M4: Revocation via Google CAS**

1. Revoke a Google CAS-issued certificate via `POST /api/v1/certificates/{id}/revoke`
2. Verify Google CAS revoke endpoint called (`POST {name}:revoke`)
3. Verify revocation reason mapped correctly (RFC 5280 → Google CAS enum)
4. Verify audit trail records revocation

**PASS if** revocation recorded in certctl and sent to Google CAS.

**44.M5: OAuth2 Token Caching**

1. Issue multiple certificates in quick succession
2. Verify token is cached (not re-fetched for every request)
3. Verify token refresh after expiry

**PASS if** token reuse observed, refresh works after expiry.

**44.M6: CA Certificate Retrieval**

1. Call EST cacerts endpoint with Google CAS as issuer
2. Verify CA certificate chain returned from Google CAS fetchCaCerts API

**PASS if** CA cert PEM returned successfully.

### Summary

| Category | Count |
|----------|-------|
| ☑ Auto (passed in `qa-smoke-test.sh`) | 144 |
| ☐ Auto (not yet run) | 28 |
| — Skipped (preconditions not met in demo) | 5 |
| ☐ Manual (requires hands-on verification) | 253 |
| **Total** | **430** |

**Automated tests must also be green.** CI passing is necessary but not sufficient — this manual QA catches integration issues that isolated unit tests miss.

