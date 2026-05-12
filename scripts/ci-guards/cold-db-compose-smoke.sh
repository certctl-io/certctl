#!/usr/bin/env bash
# scripts/ci-guards/cold-db-compose-smoke.sh
#
# Per post-v2.1.0 anti-rot item 6 (Auditable Codebase Bundle).
#
# The bug class this catches: a migration whose .up.sql is broken in a
# way the unit tests / integration suite misses because they reuse a
# warm DB across runs. The canonical case: 2026-05-09 migration
# 000045's broken INSERT, surfaced only by a cold `docker compose up`
# and fixed in commit 6444e13. This guard runs that very check on
# every push.
#
# Workflow:
#   1. docker compose down -v --remove-orphans         (wipe volumes)
#   2. docker compose up -d                            (cold boot)
#   3. wait up to 5 min for healthchecks               (postgres,
#                                                       certctl-server,
#                                                       certctl-agent)
#   4. mint a day-0 admin via /api/v1/auth/bootstrap   (Bundle 1 path)
#   5. issue + renew + revoke a certificate            (HTTP API)
#   6. assert audit rows for each step
#   7. docker compose down -v                          (clean up)
#
# Total runtime: ~3-5 min on warm Docker, ~5-10 min cold.
#
# Failure paths dump `docker compose logs` for every service to make
# CI failures actionable without a re-run.
#
# This script is invoked by .github/workflows/ci.yml::cold-db-compose-smoke.
# Runs locally for developers via `bash scripts/ci-guards/cold-db-compose-smoke.sh`.

set -e
set -o pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT/deploy"

# Tunables (the CI job overrides these as needed).
STARTUP_TIMEOUT_SECONDS="${COLD_DB_SMOKE_STARTUP_TIMEOUT:-300}"   # 5 min
PROBE_TIMEOUT_SECONDS="${COLD_DB_SMOKE_PROBE_TIMEOUT:-180}"       # 3 min
SERVER_URL="${COLD_DB_SMOKE_SERVER_URL:-https://localhost:8443}"
CACERT_PATH="${COLD_DB_SMOKE_CACERT:-${REPO_ROOT}/deploy/test/certs/ca.crt}"

# --- helpers ----------------------------------------------------------------

log() { echo "[cold-db-smoke] $*"; }

dump_logs_on_failure() {
  log "FAILURE — dumping service logs:"
  docker compose ps || true
  for svc in postgres certctl-server certctl-agent certctl-tls-init; do
    echo
    echo "==== $svc ===="
    docker compose logs --no-color --tail 200 "$svc" 2>&1 || true
  done
}

trap 'dump_logs_on_failure' ERR

wait_for_service_healthy() {
  local svc="$1" deadline=$(( $(date +%s) + STARTUP_TIMEOUT_SECONDS ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local state
    state="$(docker compose ps --format json "$svc" 2>/dev/null | python3 -c '
import json, sys
try:
    line = sys.stdin.read().strip()
    if not line:
        print("not-up")
        sys.exit(0)
    # docker compose ps emits one JSON object per line (NDJSON) on newer
    # versions; older versions emit a JSON array. Handle both.
    if line.startswith("["):
        rows = json.loads(line)
    else:
        rows = [json.loads(l) for l in line.splitlines() if l.strip()]
    if not rows:
        print("not-up")
    else:
        print(rows[0].get("Health", rows[0].get("State", "?")))
except Exception as e:
    print(f"err: {e}")
')"
    if [ "$state" = "healthy" ] || [ "$state" = "running" ]; then
      log "  $svc → $state"
      return 0
    fi
    sleep 2
  done
  log "  $svc did NOT reach healthy within $STARTUP_TIMEOUT_SECONDS s (last state: $state)"
  return 1
}

http_call() {
  # http_call <method> <path> [data_json]
  local method="$1" path="$2" data="${3:-}"
  local args=(--silent --show-error --max-time 30 -X "$method" "$SERVER_URL$path")
  if [ -f "$CACERT_PATH" ]; then
    args+=(--cacert "$CACERT_PATH")
  else
    args+=(--insecure)
  fi
  if [ -n "${KEY:-}" ]; then
    args+=(-H "Authorization: Bearer $KEY")
  fi
  if [ -n "$data" ]; then
    args+=(-H "Content-Type: application/json" -d "$data")
  fi
  curl "${args[@]}"
}

# --- the smoke ---------------------------------------------------------------

log "1/7 down -v --remove-orphans (wiping postgres volume)"
docker compose down -v --remove-orphans 2>&1 | tail -3 || true

log "2/7 up -d (cold boot)"
docker compose up -d 2>&1 | tail -3

log "3/7 waiting for healthchecks (timeout ${STARTUP_TIMEOUT_SECONDS}s/svc)"
wait_for_service_healthy postgres
wait_for_service_healthy certctl-server
# certctl-agent depends on the demo seed having run; only wait when
# CERTCTL_DEMO_SEED=true is in effect (the bundled clean compose
# doesn't always seed). Best-effort.
wait_for_service_healthy certctl-agent || log "  (agent healthcheck skipped — non-demo compose)"

log "4/7 minting day-0 admin via /api/v1/auth/bootstrap"
TOKEN="$(openssl rand -base64 32 | tr -d '\n')"
# Restart the server with the bootstrap token so the strategy is
# active. Compose --env-file is the lightest path.
echo "CERTCTL_BOOTSTRAP_TOKEN=$TOKEN" > /tmp/_smoke.env
docker compose --env-file /tmp/_smoke.env up -d --force-recreate certctl-server 2>&1 | tail -2
sleep 5
wait_for_service_healthy certctl-server

BOOTSTRAP_BODY="$(http_call POST /api/v1/auth/bootstrap "{\"token\":\"$TOKEN\",\"actor_name\":\"smoke-admin\"}")"
KEY="$(echo "$BOOTSTRAP_BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["key_value"])')"
if [ -z "$KEY" ]; then
  log "  bootstrap did NOT return a key_value — body was:"
  echo "$BOOTSTRAP_BODY"
  exit 1
fi
log "  admin minted (actor=smoke-admin)"

log "5/7 issuing a test certificate"
# Use the default profile + demo CA. The exact shape may need a tweak
# depending on the compose's seeded issuers — fail loudly with the
# response body if the API rejects the request.
ISSUE_BODY='{"common_name":"smoke-test.local","profile_id":"profile-default","environment":"test","owner_id":"o-platform"}'
ISSUE_RESP="$(http_call POST /api/v1/certificates "$ISSUE_BODY")"
CERT_ID="$(echo "$ISSUE_RESP" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("id") or d.get("certificate",{}).get("id",""))')"
if [ -z "$CERT_ID" ]; then
  log "  issue failed; response body:"
  echo "$ISSUE_RESP"
  exit 1
fi
log "  cert issued: $CERT_ID"

log "6/7 renewing the certificate"
http_call POST "/api/v1/certificates/$CERT_ID/renew" >/dev/null
log "  renewed"

log "7/7 revoking the certificate + asserting audit rows"
http_call POST "/api/v1/certificates/$CERT_ID/revoke" '{"reason":"smoke-test"}' >/dev/null
AUDIT_BODY="$(http_call GET "/api/v1/audit?limit=50")"
for action in cert.issued cert.renewed cert.revoked; do
  if ! echo "$AUDIT_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); evs=d.get('events') or d.get('audit',{}).get('events') or []; sys.exit(0 if any(e.get('action')=='$action' for e in evs) else 1)"; then
    log "  MISSING audit row: $action"
    echo "$AUDIT_BODY" | head -200
    exit 1
  fi
done
log "  audit rows present: cert.issued, cert.renewed, cert.revoked"

log "DONE — tearing down"
trap - ERR
docker compose down -v 2>&1 | tail -2
rm -f /tmp/_smoke.env
log "PASS"
