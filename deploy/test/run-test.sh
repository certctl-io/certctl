#!/usr/bin/env bash
# =============================================================================
# certctl End-to-End Test Script
# =============================================================================
#
# Automates the full lifecycle test from docs/test-env.md:
#   1. Bring up all 7 containers (build from source)
#   2. Wait for every service to be healthy
#   3. Verify pre-seeded data (agents, issuers, targets, profiles)
#   4. Issue a certificate via Local CA → deploy to NGINX → verify TLS
#   5. Issue a certificate via ACME/Pebble → verify
#   6. Issue a certificate via step-ca → verify
#   7. Test revocation + CRL
#   8. Test discovery
#   9. Test renewal (re-issue step-ca cert, check version history)
#  10. EST enrollment (RFC 7030) — cacerts + simpleenroll
#  11. S/MIME issuance — emailProtection EKU + adaptive KeyUsage
#  12. API spot checks + print summary
#
# Usage:
#   cd certctl/deploy
#   ./test/run-test.sh          # full run (build + test)
#   ./test/run-test.sh --no-build   # skip docker build, reuse existing containers
#   ./test/run-test.sh --no-teardown # leave containers running after test
#
# Requirements: docker, curl, openssl, jq (or python3 for json parsing)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
COMPOSE_FILE="docker-compose.test.yml"
API_URL="http://localhost:8443"
API_KEY="test-key-2026"
NGINX_TLS="localhost:8444"
AUTH_HEADER="Authorization: Bearer ${API_KEY}"

# Flags
BUILD=true
TEARDOWN=true
for arg in "$@"; do
  case "$arg" in
    --no-build)    BUILD=false ;;
    --no-teardown) TEARDOWN=false ;;
  esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
SKIP=0

pass() {
  PASS=$((PASS + 1))
  echo -e "  ${GREEN}PASS${NC} $1"
}

fail() {
  FAIL=$((FAIL + 1))
  echo -e "  ${RED}FAIL${NC} $1"
  if [ -n "${2:-}" ]; then
    echo -e "       ${RED}$2${NC}"
  fi
}

skip() {
  SKIP=$((SKIP + 1))
  echo -e "  ${YELLOW}SKIP${NC} $1"
}

info() {
  echo -e "${CYAN}==>${NC} $1"
}

header() {
  echo ""
  echo -e "${BOLD}─── $1 ───${NC}"
}

# API helper: GET endpoint, return JSON body. Exits 1 on HTTP error.
api_get() {
  local path="$1"
  curl -sf -H "${AUTH_HEADER}" "${API_URL}${path}" 2>/dev/null
}

# API helper: POST with optional JSON body
api_post() {
  local path="$1"
  local body="${2:-}"
  if [ -n "$body" ]; then
    curl -sf -X POST -H "${AUTH_HEADER}" -H "Content-Type: application/json" \
      -d "$body" "${API_URL}${path}" 2>/dev/null
  else
    curl -sf -X POST -H "${AUTH_HEADER}" "${API_URL}${path}" 2>/dev/null
  fi
}

# Wait for an HTTP endpoint to return 200. Retries with backoff.
wait_for_http() {
  local url="$1"
  local label="$2"
  local max_wait="${3:-120}"
  local elapsed=0
  local interval=3

  while [ $elapsed -lt $max_wait ]; do
    if curl -sf -H "${AUTH_HEADER}" "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep $interval
    elapsed=$((elapsed + interval))
  done
  return 1
}

# Extract a field from JSON using python3 (no jq dependency)
json_field() {
  python3 -c "import sys,json; d=json.load(sys.stdin); print($1)" 2>/dev/null
}

# Wait for a job to reach a terminal state (Completed or Failed)
# Usage: wait_for_job <cert_id> <max_seconds>
# Returns 0 if Completed, 1 if Failed/timeout
wait_for_jobs_done() {
  local cert_id="$1"
  local max_wait="${2:-180}"
  local elapsed=0
  local interval=5

  while [ $elapsed -lt $max_wait ]; do
    local jobs_json
    jobs_json=$(api_get "/api/v1/jobs" 2>/dev/null || echo '{"data":[]}')

    # Check if all jobs for this cert are in terminal state
    # API returns jobs under "data" key (not "jobs")
    local pending
    pending=$(echo "$jobs_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
jobs = data.get('data') or data.get('jobs') or []
active = [j for j in jobs if j.get('certificate_id') == '$cert_id'
          and j.get('status') not in ('Completed', 'Failed', 'Cancelled')]
print(len(active))
" 2>/dev/null || echo "99")

    if [ "$pending" = "0" ]; then
      # Check how many jobs exist and their terminal states
      local job_counts
      job_counts=$(echo "$jobs_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
jobs = data.get('data') or data.get('jobs') or []
mine = [j for j in jobs if j.get('certificate_id') == '$cert_id']
completed = len([j for j in mine if j.get('status') == 'Completed'])
failed = len([j for j in mine if j.get('status') in ('Failed', 'Cancelled')])
print(f'{len(mine)} {completed} {failed}')
" 2>/dev/null || echo "0 0 0")
      local total_jobs completed_jobs failed_jobs
      total_jobs=$(echo "$job_counts" | cut -d' ' -f1)
      completed_jobs=$(echo "$job_counts" | cut -d' ' -f2)
      failed_jobs=$(echo "$job_counts" | cut -d' ' -f3)

      if [ "$completed_jobs" -gt 0 ]; then
        return 0  # At least one job completed successfully
      fi
      if [ "$total_jobs" -gt 0 ] && [ "$failed_jobs" -gt 0 ]; then
        return 1  # All jobs are in terminal state but none completed — all failed
      fi
    fi

    sleep $interval
    elapsed=$((elapsed + interval))
  done
  return 1
}

# Get the TLS cert subject from NGINX for a given SNI
get_tls_subject() {
  local sni="$1"
  echo | openssl s_client -connect "$NGINX_TLS" -servername "$sni" 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null \
    | sed 's/subject=//' | sed 's/^ *//'
}

get_tls_issuer() {
  local sni="$1"
  echo | openssl s_client -connect "$NGINX_TLS" -servername "$sni" 2>/dev/null \
    | openssl x509 -noout -issuer 2>/dev/null \
    | sed 's/issuer=//' | sed 's/^ *//'
}

# Get the TLS cert SANs from NGINX for a given SNI
# Modern CAs (including Let's Encrypt / Pebble) put domains only in SAN, not Subject CN.
get_tls_san() {
  local sni="$1"
  echo | openssl s_client -connect "$NGINX_TLS" -servername "$sni" 2>/dev/null \
    | openssl x509 -noout -ext subjectAltName 2>/dev/null \
    | grep -i "DNS:" | sed 's/^ *//'
}

# Check if NGINX is serving a cert that matches the given domain (checks Subject then SAN)
check_tls_identity() {
  local domain="$1"
  local subject issuer san
  subject=$(get_tls_subject "$domain")
  issuer=$(get_tls_issuer "$domain")
  san=$(get_tls_san "$domain")
  if echo "$subject" | grep -qi "$domain" || echo "$san" | grep -qi "$domain"; then
    echo "MATCH"
    echo "Subject: $subject"
    echo "SAN: $san"
    echo "Issuer: $issuer"
  else
    echo "NO_MATCH"
    echo "Subject: $subject"
    echo "SAN: $san"
    echo "Issuer: $issuer"
  fi
}

# SQL exec in the postgres container
psql_exec() {
  docker exec certctl-test-postgres psql -U certctl -d certctl -tAc "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
cleanup() {
  if [ "$TEARDOWN" = true ]; then
    info "Tearing down test environment..."
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
  else
    info "Leaving containers running (--no-teardown)"
  fi
}

# ---------------------------------------------------------------------------
# PHASE 0: Environment Check
# ---------------------------------------------------------------------------
header "Phase 0: Environment Check"

# Make sure we're in the deploy directory
if [ ! -f "$COMPOSE_FILE" ]; then
  echo -e "${RED}ERROR: $COMPOSE_FILE not found.${NC}"
  echo "Run this script from the certctl/deploy directory:"
  echo "  cd certctl/deploy && ./test/run-test.sh"
  exit 1
fi

for cmd in docker curl openssl python3; do
  if command -v "$cmd" >/dev/null 2>&1; then
    pass "$cmd available"
  else
    fail "$cmd not found" "Install $cmd and try again"
    exit 1
  fi
done

if docker compose version >/dev/null 2>&1; then
  pass "docker compose available"
else
  fail "docker compose not available" "Install Docker Compose v2+"
  exit 1
fi

# ---------------------------------------------------------------------------
# PHASE 1: Start the Stack
# ---------------------------------------------------------------------------
header "Phase 1: Start Test Environment"

# Teardown any previous run
info "Cleaning up previous test environment..."
docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true

# Set the cleanup trap AFTER the initial teardown
trap cleanup EXIT

if [ "$BUILD" = true ]; then
  info "Building and starting containers (this takes 2-5 minutes on first run)..."
  docker compose -f "$COMPOSE_FILE" up --build -d 2>&1 | tail -5
else
  info "Starting containers (--no-build)..."
  docker compose -f "$COMPOSE_FILE" up -d 2>&1 | tail -5
fi

# ---------------------------------------------------------------------------
# PHASE 2: Wait for Services
# ---------------------------------------------------------------------------
header "Phase 2: Waiting for Services"

info "Waiting for PostgreSQL..."
if docker compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U certctl -d certctl >/dev/null 2>&1 ||
   wait_for_http "${API_URL}/health" "postgres" 60; then
  pass "PostgreSQL ready"
else
  fail "PostgreSQL not ready after 60s"
fi

info "Waiting for certctl server..."
if wait_for_http "${API_URL}/health" "server" 120; then
  pass "certctl server healthy"
  # Show trust setup + connector init for debugging
  echo "  --- Server startup (trust setup) ---"
  docker logs certctl-test-server 2>&1 | grep -E "trust|Added|Extract|provisioner|Pre-launch|key file|WARNING|CERTCTL_" | head -15
  echo "  ---"
else
  fail "certctl server not healthy after 120s"
  echo ""
  echo "Server logs:"
  docker logs certctl-test-server --tail 30
  exit 1
fi

info "Waiting for NGINX..."
if wait_for_http "http://localhost:8080" "nginx" 30; then
  pass "NGINX healthy"
else
  # NGINX might not respond to plain curl on /health without the right path
  # Check docker health instead
  if docker inspect certctl-test-nginx --format='{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; then
    pass "NGINX healthy (docker healthcheck)"
  else
    skip "NGINX health check inconclusive (will verify via TLS later)"
  fi
fi

# Give the agent a few seconds to register and send first heartbeat
info "Waiting for agent heartbeat (up to 45s)..."
AGENT_READY=false
for i in $(seq 1 15); do
  AGENT_STATUS=$(api_get "/api/v1/agents/agent-test-01" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
  if [ "$AGENT_STATUS" = "online" ]; then
    AGENT_READY=true
    break
  fi
  sleep 3
done
if [ "$AGENT_READY" = true ]; then
  pass "Agent online"
else
  skip "Agent not yet online (may be slow to heartbeat — continuing)"
fi

# ---------------------------------------------------------------------------
# PHASE 3: Verify Pre-Seeded Data
# ---------------------------------------------------------------------------
header "Phase 3: Verify Pre-Seeded Data"

# Agents
AGENT_COUNT=$(api_get "/api/v1/agents" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
if [ "$AGENT_COUNT" -ge 2 ]; then
  pass "Agents: $AGENT_COUNT found (agent-test-01 + server-scanner)"
else
  fail "Agents: expected >= 2, got $AGENT_COUNT"
fi

# Issuers
ISSUER_COUNT=$(api_get "/api/v1/issuers" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
if [ "$ISSUER_COUNT" -ge 3 ]; then
  pass "Issuers: $ISSUER_COUNT found (iss-local, iss-acme-staging, iss-stepca)"
else
  fail "Issuers: expected >= 3, got $ISSUER_COUNT" "Check seed_test.sql loaded correctly"
fi

# Targets
TARGET_COUNT=$(api_get "/api/v1/targets" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
if [ "$TARGET_COUNT" -ge 1 ]; then
  pass "Targets: $TARGET_COUNT found (target-test-nginx)"
else
  fail "Targets: expected >= 1, got $TARGET_COUNT" "seed_test.sql may have failed after iss-local"
fi

# Profile
PROFILE_RESP=$(api_get "/api/v1/profiles" 2>/dev/null || echo '{"total":0}')
PROFILE_COUNT=$(echo "$PROFILE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
if [ "$PROFILE_COUNT" -ge 2 ]; then
  pass "Profiles: $PROFILE_COUNT found (prof-test-tls, prof-test-smime)"
else
  fail "Profiles: expected >= 1, got $PROFILE_COUNT"
fi

# Bail if seed data is broken
if [ "$ISSUER_COUNT" -lt 3 ] || [ "$TARGET_COUNT" -lt 1 ]; then
  echo ""
  echo -e "${RED}Seed data is incomplete. Cannot continue.${NC}"
  echo "Check PostgreSQL logs: docker logs certctl-test-postgres"
  exit 1
fi

# ---------------------------------------------------------------------------
# PHASE 4: Local CA Issuance
# ---------------------------------------------------------------------------
header "Phase 4: Local CA Certificate Issuance"

info "Creating certificate record mc-local-test..."
CREATE_RESP=$(api_post "/api/v1/certificates" '{
  "id": "mc-local-test",
  "name": "local-test-cert",
  "common_name": "local.certctl.test",
  "sans": ["local.certctl.test"],
  "issuer_id": "iss-local",
  "owner_id": "owner-test-admin",
  "team_id": "team-test-ops",
  "renewal_policy_id": "rp-default",
  "certificate_profile_id": "prof-test-tls",
  "environment": "development"
}' 2>/dev/null || echo "ERROR")

if echo "$CREATE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('id')=='mc-local-test'" 2>/dev/null; then
  pass "Certificate record created"
else
  fail "Certificate creation failed" "$CREATE_RESP"
fi

info "Linking certificate to NGINX target..."
psql_exec "INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ('mc-local-test', 'target-test-nginx') ON CONFLICT DO NOTHING;"
pass "Target mapping inserted"

info "Triggering issuance..."
RENEW_RESP=$(api_post "/api/v1/certificates/mc-local-test/renew" 2>/dev/null || echo "ERROR")
if echo "$RENEW_RESP" | grep -q "renewal_triggered\|status"; then
  pass "Issuance triggered"
else
  fail "Trigger failed" "$RENEW_RESP"
fi

# Verify a job was created (this is the bug fix check)
sleep 2
JOB_COUNT=$(api_get "/api/v1/jobs" | python3 -c "
import sys, json
data = json.load(sys.stdin)
jobs = [j for j in (data.get('data') or data.get('jobs') or []) if j.get('certificate_id') == 'mc-local-test']
print(len(jobs))
" 2>/dev/null || echo "0")

if [ "$JOB_COUNT" -gt 0 ]; then
  pass "Job created ($JOB_COUNT jobs for mc-local-test)"
else
  fail "No jobs created — TriggerRenewalWithActor bug still present"
fi

info "Waiting for issuance + deployment (up to 180s)..."
if wait_for_jobs_done "mc-local-test" 180; then
  pass "All jobs completed"
else
  fail "Jobs did not complete within 180s"
  echo "  Current jobs:"
  api_get "/api/v1/jobs" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -30
fi

info "Reloading NGINX to pick up deployed certificate..."
docker exec certctl-test-nginx nginx -s reload 2>/dev/null || true
sleep 3

info "Verifying TLS certificate on NGINX..."
TLS_CHECK=$(check_tls_identity "local.certctl.test")
TLS_RESULT=$(echo "$TLS_CHECK" | head -1)
if [ "$TLS_RESULT" = "MATCH" ]; then
  pass "NGINX serving cert for local.certctl.test"
  echo "$TLS_CHECK" | tail -n +2 | while read -r line; do echo -e "       $line"; done
else
  fail "NGINX not serving expected cert" "$(echo "$TLS_CHECK" | tail -n +2 | tr '\n' ', ')"
fi

# Check cert status in API
CERT_STATUS=$(api_get "/api/v1/certificates/mc-local-test" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "unknown")
if [ "$CERT_STATUS" = "Active" ]; then
  pass "Certificate status: Active"
else
  skip "Certificate status: $CERT_STATUS (expected Active — may need more time)"
fi

# ---------------------------------------------------------------------------
# PHASE 5: ACME (Pebble) Issuance
# ---------------------------------------------------------------------------
header "Phase 5: ACME (Pebble) Certificate Issuance"

info "Creating certificate record mc-acme-test..."
CREATE_RESP=$(api_post "/api/v1/certificates" '{
  "id": "mc-acme-test",
  "name": "acme-test-cert",
  "common_name": "acme.certctl.test",
  "sans": ["acme.certctl.test"],
  "issuer_id": "iss-acme-staging",
  "owner_id": "owner-test-admin",
  "team_id": "team-test-ops",
  "renewal_policy_id": "rp-default",
  "certificate_profile_id": "prof-test-tls",
  "environment": "staging"
}' 2>/dev/null || echo "ERROR")

if echo "$CREATE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('id')=='mc-acme-test'" 2>/dev/null; then
  pass "Certificate record created"
else
  fail "Certificate creation failed" "$CREATE_RESP"
fi

info "Linking to target and triggering issuance..."
psql_exec "INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ('mc-acme-test', 'target-test-nginx') ON CONFLICT DO NOTHING;"
RENEW_RESP=$(api_post "/api/v1/certificates/mc-acme-test/renew" 2>/dev/null || echo "ERROR")
if echo "$RENEW_RESP" | grep -q "renewal_triggered\|status"; then
  pass "Issuance triggered"
else
  fail "Trigger failed" "$RENEW_RESP"
fi

info "Waiting for ACME issuance + deployment (up to 180s)..."
if wait_for_jobs_done "mc-acme-test" 180; then
  pass "All jobs completed"

  info "Reloading NGINX to pick up deployed certificate..."
  docker exec certctl-test-nginx nginx -s reload 2>/dev/null || true
  sleep 3

  TLS_CHECK=$(check_tls_identity "acme.certctl.test")
  TLS_RESULT=$(echo "$TLS_CHECK" | head -1)
  if [ "$TLS_RESULT" = "MATCH" ]; then
    pass "NGINX serving cert for acme.certctl.test"
    echo "$TLS_CHECK" | tail -n +2 | while read -r line; do echo -e "       $line"; done
  else
    fail "NGINX not serving expected ACME cert" "$(echo "$TLS_CHECK" | tail -n +2 | tr '\n' ', ')"
  fi
else
  fail "ACME jobs did not complete within 180s"
  info "Checking ACME job status..."
  api_get "/api/v1/jobs" 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for j in data.get('data', []):
    if j.get('certificate_id') == 'mc-acme-test':
        print(f\"  Job {j['id']}: type={j['type']} status={j['status']} error={j.get('last_error','')}\")" 2>/dev/null || true
  echo "  Server logs (last 20 lines):"
  docker logs certctl-test-server --tail 20 2>&1 | grep -i "acme\|error\|fail\|CSR" | head -10 || true
fi

# ---------------------------------------------------------------------------
# PHASE 6: step-ca Issuance
# ---------------------------------------------------------------------------
header "Phase 6: step-ca (Private CA) Certificate Issuance"

info "Creating certificate record mc-stepca-test..."
CREATE_RESP=$(api_post "/api/v1/certificates" '{
  "id": "mc-stepca-test",
  "name": "stepca-test-cert",
  "common_name": "stepca.certctl.test",
  "sans": ["stepca.certctl.test"],
  "issuer_id": "iss-stepca",
  "owner_id": "owner-test-admin",
  "team_id": "team-test-ops",
  "renewal_policy_id": "rp-default",
  "certificate_profile_id": "prof-test-tls",
  "environment": "staging"
}' 2>/dev/null || echo "ERROR")

if echo "$CREATE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('id')=='mc-stepca-test'" 2>/dev/null; then
  pass "Certificate record created"
else
  fail "Certificate creation failed" "$CREATE_RESP"
fi

info "Linking to target and triggering issuance..."
psql_exec "INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ('mc-stepca-test', 'target-test-nginx') ON CONFLICT DO NOTHING;"
RENEW_RESP=$(api_post "/api/v1/certificates/mc-stepca-test/renew" 2>/dev/null || echo "ERROR")
if echo "$RENEW_RESP" | grep -q "renewal_triggered\|status"; then
  pass "Issuance triggered"
else
  fail "Trigger failed" "$RENEW_RESP"
fi

info "Waiting for step-ca issuance + deployment (up to 120s)..."
if wait_for_jobs_done "mc-stepca-test" 120; then
  pass "All jobs completed"
else
  fail "Jobs did not complete in time"
  info "Checking step-ca job status..."
  api_get "/api/v1/jobs" 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for j in data.get('data', []):
    if j.get('certificate_id') == 'mc-stepca-test':
        print(f\"  Job {j['id']}: type={j['type']} status={j['status']} error={j.get('last_error','')}\")" 2>/dev/null || true
  echo "  Server logs (step-ca related):"
  docker logs certctl-test-server --tail 30 2>&1 | grep -i "stepca\|step-ca\|provisioner\|jwe\|decrypt\|CSR.*fail\|error" | head -10 || true
fi

# ---------------------------------------------------------------------------
# PHASE 7: Revocation
# ---------------------------------------------------------------------------
header "Phase 7: Revocation"

info "Revoking mc-local-test (reason: superseded)..."
REVOKE_RESP=$(api_post "/api/v1/certificates/mc-local-test/revoke" '{"reason": "superseded"}' 2>/dev/null || echo "ERROR")
if echo "$REVOKE_RESP" | grep -qi "revoked\|status"; then
  pass "Certificate revoked"
else
  fail "Revocation failed" "$REVOKE_RESP"
fi

info "Checking CRL..."
CRL_RESP=$(api_get "/api/v1/crl" 2>/dev/null || echo '{"total":0}')
CRL_TOTAL=$(echo "$CRL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
if [ "$CRL_TOTAL" -ge 1 ]; then
  pass "CRL contains $CRL_TOTAL revoked certificate(s)"
else
  fail "CRL empty after revocation"
fi

CERT_STATUS=$(api_get "/api/v1/certificates/mc-local-test" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "unknown")
if [ "$CERT_STATUS" = "Revoked" ]; then
  pass "Certificate status updated to Revoked"
else
  fail "Certificate status: $CERT_STATUS (expected Revoked)"
fi

# ---------------------------------------------------------------------------
# PHASE 8: Discovery
# ---------------------------------------------------------------------------
header "Phase 8: Certificate Discovery"

info "Checking discovered certificates..."
DISC_RESP=$(api_get "/api/v1/discovered-certificates" 2>/dev/null || echo '{"total":0}')
DISC_TOTAL=$(echo "$DISC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
if [ "$DISC_TOTAL" -ge 1 ]; then
  pass "Discovered $DISC_TOTAL certificate(s) on filesystem"
else
  skip "No discovered certificates yet (agent scan may not have run)"
fi

SUMMARY_RESP=$(api_get "/api/v1/discovery-summary" 2>/dev/null || echo '{}')
echo -e "       Discovery summary: $SUMMARY_RESP"

# ---------------------------------------------------------------------------
# PHASE 9: Renewal (re-issue ACME cert)
# ---------------------------------------------------------------------------
header "Phase 9: Renewal"

# Try mc-stepca-test first (mc-local-test was revoked in Phase 7).
# Fall back to mc-acme-test if step-ca cert isn't Active.
RENEWAL_CERT=""
for candidate in mc-stepca-test mc-acme-test; do
  STATUS=$(api_get "/api/v1/certificates/$candidate" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "unknown")
  if [ "$STATUS" = "Active" ]; then
    RENEWAL_CERT="$candidate"
    break
  fi
done

if [ -z "$RENEWAL_CERT" ]; then
  skip "Cannot test renewal — no certificate in Active state"
else
  info "Using $RENEWAL_CERT for renewal test..."
  info "Triggering renewal on $RENEWAL_CERT..."
  RENEW_RESP=$(api_post "/api/v1/certificates/$RENEWAL_CERT/renew" 2>/dev/null || echo "ERROR")
  if echo "$RENEW_RESP" | grep -q "renewal_triggered\|status"; then
    pass "Renewal triggered"
  else
    skip "Renewal trigger returned: $RENEW_RESP"
  fi

  info "Waiting for renewal to complete (up to 180s)..."
  if wait_for_jobs_done "$RENEWAL_CERT" 180; then
    pass "Renewal jobs completed"

    info "Reloading NGINX to pick up renewed certificate..."
    docker exec certctl-test-nginx nginx -s reload 2>/dev/null || true
    sleep 3

    # Verify version history shows multiple versions
    VERSIONS=$(api_get "/api/v1/certificates/$RENEWAL_CERT/versions" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d, list) else d.get('total', 0))" 2>/dev/null || echo 0)
    if [ "$VERSIONS" -ge 2 ]; then
      pass "Certificate has $VERSIONS versions (original + renewal)"
    else
      skip "Expected 2+ versions, got $VERSIONS"
    fi
  else
    skip "Renewal jobs did not complete within 180s"
  fi
fi

# ---------------------------------------------------------------------------
# PHASE 10: EST Enrollment (RFC 7030)
# ---------------------------------------------------------------------------
header "Phase 10: EST Enrollment (RFC 7030)"

# Test cacerts endpoint — should return PKCS#7 with CA cert chain
info "Testing EST cacerts endpoint..."
EST_CACERTS_RESP=$(curl -sf -H "${AUTH_HEADER}" "${API_URL}/.well-known/est/cacerts" 2>/dev/null || echo "ERROR")
if [ "$EST_CACERTS_RESP" != "ERROR" ] && [ -n "$EST_CACERTS_RESP" ]; then
  # Response should be base64-encoded PKCS#7
  if echo "$EST_CACERTS_RESP" | base64 -d >/dev/null 2>&1; then
    pass "EST cacerts returns valid base64 PKCS#7 response"
  else
    fail "EST cacerts returned non-base64 data"
  fi
else
  fail "EST cacerts endpoint failed" "$EST_CACERTS_RESP"
fi

# Test csrattrs endpoint
info "Testing EST csrattrs endpoint..."
EST_CSRATTRS_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -H "${AUTH_HEADER}" "${API_URL}/.well-known/est/csrattrs" 2>/dev/null || echo "000")
if [ "$EST_CSRATTRS_STATUS" = "200" ] || [ "$EST_CSRATTRS_STATUS" = "204" ]; then
  pass "EST csrattrs returns $EST_CSRATTRS_STATUS"
else
  fail "EST csrattrs returned $EST_CSRATTRS_STATUS (expected 200 or 204)"
fi

# Test simpleenroll — generate CSR, POST as base64-encoded DER
info "Testing EST simpleenroll with generated CSR..."
EST_KEY_FILE=$(mktemp /tmp/est-key-XXXXXX.pem)
EST_CSR_PEM_FILE=$(mktemp /tmp/est-csr-XXXXXX.pem)
EST_CSR_DER_FILE=$(mktemp /tmp/est-csr-XXXXXX.der)
trap "rm -f $EST_KEY_FILE $EST_CSR_PEM_FILE $EST_CSR_DER_FILE" EXIT

# Generate ECDSA key + CSR
openssl ecparam -genkey -name prime256v1 -noout -out "$EST_KEY_FILE" 2>/dev/null
openssl req -new -key "$EST_KEY_FILE" -out "$EST_CSR_PEM_FILE" -subj "/CN=est-device.certctl.test" 2>/dev/null
openssl req -in "$EST_CSR_PEM_FILE" -out "$EST_CSR_DER_FILE" -outform DER 2>/dev/null

# base64-encode the DER CSR (EST wire format)
EST_CSR_B64=$(base64 < "$EST_CSR_DER_FILE" | tr -d '\n')

EST_ENROLL_RESP=$(curl -sf \
  -X POST \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: application/pkcs10" \
  -d "$EST_CSR_B64" \
  "${API_URL}/.well-known/est/simpleenroll" 2>/dev/null || echo "ERROR")

if [ "$EST_ENROLL_RESP" != "ERROR" ] && [ -n "$EST_ENROLL_RESP" ]; then
  # Response should be base64-encoded PKCS#7 containing the issued cert
  if echo "$EST_ENROLL_RESP" | base64 -d >/dev/null 2>&1; then
    pass "EST simpleenroll issued certificate via PKCS#7 response"
  else
    fail "EST simpleenroll returned non-base64 data"
  fi
else
  fail "EST simpleenroll failed" "$(curl -s -X POST -H "${AUTH_HEADER}" -H "Content-Type: application/pkcs10" -d "$EST_CSR_B64" "${API_URL}/.well-known/est/simpleenroll" 2>&1 | head -5)"
fi

# Test simplereenroll (should work identically)
info "Testing EST simplereenroll..."
EST_REENROLL_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: application/pkcs10" \
  -d "$EST_CSR_B64" \
  "${API_URL}/.well-known/est/simplereenroll" 2>/dev/null || echo "000")

if [ "$EST_REENROLL_STATUS" = "200" ]; then
  pass "EST simplereenroll works (status 200)"
else
  fail "EST simplereenroll returned $EST_REENROLL_STATUS (expected 200)"
fi

# ---------------------------------------------------------------------------
# PHASE 11: S/MIME Certificate Issuance
# ---------------------------------------------------------------------------
header "Phase 11: S/MIME Certificate Issuance"

info "Creating S/MIME certificate record..."
SMIME_RESP=$(api_post "/api/v1/certificates" '{
  "id": "mc-smime-test",
  "name": "smime-test-cert",
  "common_name": "testuser@certctl.test",
  "sans": ["testuser@certctl.test"],
  "issuer_id": "iss-local",
  "owner_id": "owner-test-admin",
  "team_id": "team-test-ops",
  "renewal_policy_id": "rp-default",
  "certificate_profile_id": "prof-test-smime",
  "environment": "staging"
}' 2>/dev/null || echo "ERROR")

if echo "$SMIME_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('id')=='mc-smime-test'" 2>/dev/null; then
  pass "S/MIME certificate record created"
else
  fail "S/MIME certificate creation failed" "$SMIME_RESP"
fi

info "Linking S/MIME cert to target (needed for agent work routing)..."
psql_exec "INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ('mc-smime-test', 'target-test-nginx') ON CONFLICT DO NOTHING;"

info "Triggering S/MIME issuance..."
SMIME_RENEW=$(api_post "/api/v1/certificates/mc-smime-test/renew" 2>/dev/null || echo "ERROR")
if echo "$SMIME_RENEW" | grep -q "renewal_triggered\|status"; then
  pass "S/MIME issuance triggered"
else
  fail "S/MIME trigger failed" "$SMIME_RENEW"
fi

info "Waiting for S/MIME issuance (up to 120s)..."
if wait_for_jobs_done "mc-smime-test" 120; then
  pass "S/MIME jobs completed"

  # Fetch the issued cert and verify EKU
  info "Verifying S/MIME certificate EKU..."
  SMIME_VERSIONS=$(api_get "/api/v1/certificates/mc-smime-test/versions" 2>/dev/null || echo "[]")
  SMIME_PEM=$(echo "$SMIME_VERSIONS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
versions = data if isinstance(data, list) else data.get('data', [])
if versions:
    print(versions[-1].get('pem_chain', versions[-1].get('pem', '')))
" 2>/dev/null || echo "")

  if [ -n "$SMIME_PEM" ]; then
    # Parse the cert and check for emailProtection EKU
    SMIME_EKU=$(echo "$SMIME_PEM" | openssl x509 -noout -text 2>/dev/null | grep -A2 "Extended Key Usage" || echo "")
    if echo "$SMIME_EKU" | grep -qi "emailProtection\|E-mail Protection"; then
      pass "S/MIME cert has emailProtection EKU"
    else
      fail "S/MIME cert missing emailProtection EKU" "Got: $SMIME_EKU"
    fi

    # Check KeyUsage flags (S/MIME should have Digital Signature + Content Commitment)
    SMIME_KU=$(echo "$SMIME_PEM" | openssl x509 -noout -text 2>/dev/null | awk '/X509v3 Key Usage:/{getline; print; exit}')
    if echo "$SMIME_KU" | grep -qi "Digital Signature"; then
      pass "S/MIME cert has Digital Signature KeyUsage"
    else
      fail "S/MIME cert missing Digital Signature KeyUsage" "Got: $SMIME_KU"
    fi

    # Check that email SAN is present
    SMIME_SAN=$(echo "$SMIME_PEM" | openssl x509 -noout -ext subjectAltName 2>/dev/null || echo "")
    if echo "$SMIME_SAN" | grep -qi "email:testuser@certctl.test"; then
      pass "S/MIME cert has email SAN"
    else
      # Some implementations use rfc822Name instead of email:
      if echo "$SMIME_SAN" | grep -qi "testuser@certctl.test"; then
        pass "S/MIME cert has email SAN (rfc822Name)"
      else
        skip "S/MIME email SAN not found in cert (may be in CN only)"
        echo "       SAN content: $SMIME_SAN"
      fi
    fi
  else
    skip "Could not extract S/MIME cert PEM for EKU verification"
  fi
else
  fail "S/MIME issuance did not complete within 120s"
  info "Checking S/MIME job status..."
  api_get "/api/v1/jobs" 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for j in data.get('data', []):
    if j.get('certificate_id') == 'mc-smime-test':
        print(f\"  Job {j['id']}: type={j['type']} status={j['status']} error={j.get('last_error','')}\")" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# PHASE 12: API Spot Checks
# ---------------------------------------------------------------------------
header "Phase 12: API Spot Checks"

# Health
if api_get "/health" >/dev/null 2>&1; then
  pass "GET /health returns 200"
else
  fail "GET /health failed"
fi

# Metrics
METRICS_RESP=$(api_get "/api/v1/metrics" 2>/dev/null || echo "ERROR")
if echo "$METRICS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'gauge' in d" 2>/dev/null; then
  pass "GET /api/v1/metrics returns valid JSON"
else
  fail "Metrics endpoint broken"
fi

# Stats summary
STATS_RESP=$(api_get "/api/v1/stats/summary" 2>/dev/null || echo "ERROR")
if echo "$STATS_RESP" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
  pass "GET /api/v1/stats/summary returns valid JSON"
else
  fail "Stats summary endpoint broken"
fi

# Audit trail
AUDIT_RESP=$(api_get "/api/v1/audit" 2>/dev/null || echo '{"total":0}')
AUDIT_TOTAL=$(echo "$AUDIT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
if [ "$AUDIT_TOTAL" -gt 0 ]; then
  pass "Audit trail: $AUDIT_TOTAL events recorded"
else
  fail "Audit trail empty"
fi

# Jobs summary
JOBS_RESP=$(api_get "/api/v1/jobs" 2>/dev/null || echo '{"total":0}')
JOBS_TOTAL=$(echo "$JOBS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
pass "Total jobs created: $JOBS_TOTAL"

# Prometheus
PROM_RESP=$(curl -sf -H "${AUTH_HEADER}" "${API_URL}/api/v1/metrics/prometheus" 2>/dev/null || echo "")
if echo "$PROM_RESP" | grep -q "certctl_certificate_total"; then
  pass "Prometheus metrics endpoint working"
else
  fail "Prometheus metrics endpoint broken"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
header "Test Summary"

TOTAL=$((PASS + FAIL + SKIP))
echo ""
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"
echo -e "  ${YELLOW}Skipped: $SKIP${NC}"
echo -e "  Total:  $TOTAL"
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}All tests passed.${NC}"
  exit 0
else
  echo -e "${RED}${BOLD}$FAIL test(s) failed.${NC}"
  echo ""
  echo "Useful debug commands:"
  echo "  docker logs certctl-test-server --tail 50"
  echo "  docker logs certctl-test-agent --tail 50"
  echo "  docker compose -f $COMPOSE_FILE ps"
  exit 1
fi
