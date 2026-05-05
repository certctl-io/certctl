# Performance Baselines

> Last reviewed: 2026-05-05

Operator-runnable benchmarks for spot-checking certctl performance against published baselines. Useful as a regression detector after upgrades or infra changes.

## Why these specific spots?

certctl's hot paths are dominated by three workloads:

1. **API request handling** — auth, rate-limit decision, route dispatch, DB read
2. **Renewal scheduler** — periodic scan + dispatch
3. **Certificate inventory queries** — large list returns with sparse fields

The baselines below cover those three.

## Baseline #1: API request handling (single endpoint)

Hit a hot read endpoint with a tight loop and compare against the baseline.

```bash
SERVER=https://localhost:8443
CACERT="--cacert ./deploy/test/certs/ca.crt"
AUTH="Authorization: Bearer change-me-in-production"

# Warm the connection pool (5 requests, discard timing)
for i in $(seq 1 5); do
  curl -s $CACERT -H "$AUTH" $SERVER/api/v1/stats/summary > /dev/null
done

# Measured run: 100 requests, capture mean latency
time (for i in $(seq 1 100); do
  curl -s $CACERT -H "$AUTH" $SERVER/api/v1/stats/summary > /dev/null
done)
```

**Baseline (M3 MacBook Pro, Docker Desktop):** real time under 5 seconds for 100 sequential requests = mean ~50ms p50.

If you're seeing > 100ms mean, something is wrong: PostgreSQL connection pool exhaustion, agent flooding the work-poll endpoint, or rate-limiter mis-tuned.

## Baseline #2: Inventory list with cursor pagination

```bash
# Cursor-paginated full inventory walk
NEXT=""
PAGES=0
START=$(date +%s)
while true; do
  RESP=$(curl -s $CACERT -H "$AUTH" "$SERVER/api/v1/certificates?limit=100&cursor=$NEXT")
  NEXT=$(echo "$RESP" | jq -r '.next_cursor // empty')
  PAGES=$((PAGES + 1))
  [ -z "$NEXT" ] && break
done
END=$(date +%s)
echo "Walked $PAGES pages in $((END - START))s"
```

**Baseline:** for the demo dataset (15 certificates, 1 page), under 1 second total. For a 1000-cert inventory (10 pages of 100), under 3 seconds total = ~300ms per page.

If you're seeing > 1s per page on a 1000-cert inventory, the cursor index on `managed_certificates(created_at, id)` is missing or the query plan went wrong.

## Baseline #3: Scheduler tick (renewal scan)

The renewal scheduler runs every hour by default. Force a tick and observe the time-to-completion in the logs:

```bash
# Trigger an immediate renewal scan via the admin endpoint
curl -s $CACERT -H "$AUTH" -X POST $SERVER/api/v1/admin/scheduler/run-now/renewal | jq .

# Tail the log and look for the matching `renewal scan complete` line
docker compose logs -f certctl-server | grep 'renewal'
```

**Baseline (15-cert demo dataset):** "renewal scan complete" within 100ms of the trigger.

For a 1000-cert inventory: under 5 seconds. The dominant cost is the per-cert profile + policy + alert-channel resolve plus the threshold-comparison math. If you're seeing > 10 seconds, profile resolution is likely doing N+1 queries.

## Baseline #4: Bulk revoke

```bash
# Bulk-revoke all certs from a (test) issuer
TIME=$(date +%s)
curl -s $CACERT -H "$AUTH" -H "$CT" -X POST $SERVER/api/v1/certificates/bulk-revoke \
  -d '{"filter":{"issuer_id":"iss-test"},"reason":"superseded"}' | jq .
echo "Bulk revoke: $(($(date +%s) - TIME))s"
```

**Baseline:** linear in cert count. For 100 certs from one issuer: under 5 seconds. For 1000 certs: under 30 seconds (dominated by per-cert audit row + per-cert CRL refresh).

## When to re-baseline

After any of:

- Postgres major-version upgrade
- Go major-version upgrade  
- Significant migration (add a column to `managed_certificates`, add an index)
- Connection pool config change
- Changing the renewal scheduler interval

Capture timing in your own loadtest-baselines log so future regressions surface against a real baseline rather than the operator's gut feeling.

## Related docs

- [`docs/contributor/ci-pipeline.md`](../contributor/ci-pipeline.md) — CI guard for performance regression
- [`docs/operator/security.md`](security.md) — rate limit tuning
- [`docs/reference/architecture.md`](../reference/architecture.md) — request path through handler → service → repository
