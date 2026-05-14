# Runbook: Prometheus bearer token for the metrics scrape endpoint

> Last reviewed: 2026-05-14

Use this when:
- You're enabling Prometheus Operator scraping via the Helm chart's
  `monitoring.serviceMonitor.enabled` toggle.
- Your Prometheus scrapes are returning 401 against
  `/api/v1/metrics/prometheus`.
- An auditor asks "how is the metrics endpoint authenticated?"

## The constraint

The certctl server exposes Prometheus metrics at
`/api/v1/metrics/prometheus`. This endpoint is **RBAC-gated on the
`metrics.read` permission** (per `internal/api/router/router.go`).
Like every other gated handler, it requires an authenticated actor
holding that permission — there is no anonymous-scrape path.

The rationale: the metrics payload includes operational counters
(cert counts by status, agent counts, issuance failure rates) that
a public-facing observer should not see. Most certctl deployments
expose a reverse proxy / load balancer to the wider network; the
auth gate on `/api/v1/metrics/prometheus` prevents an external
observer from learning operational state via the metrics endpoint
even when the proxy itself is reachable.

## What you need to set up

Three pieces:

1. **An API key with `metrics.read` permission** (and only that
   permission — least-privilege).
2. **A Kubernetes Secret** holding that API key.
3. **`monitoring.serviceMonitor.bearerTokenSecret`** in the chart's
   values pointing at the Secret.

## Step 1: Create the metrics-read role + API key

The chart's seed migration ships a `metrics-read` role-template, but
some operators want a dedicated identity per scrape source. Both
approaches work; the dedicated-identity path is below.

```bash
# 1. Bootstrap or impersonate a session with auth.role.assign +
#    auth.apikey.create permissions (admin actor is fine).

# 2. Create a role with only metrics.read.
curl -sS --cacert ./ca.crt -X POST \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  https://certctl.your-org.example/api/v1/auth/roles \
  -d '{"id":"r-prometheus-scrape","name":"Prometheus scrape","permissions":["metrics.read"]}'

# 3. Create an actor that holds the role.
curl -sS --cacert ./ca.crt -X POST \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  https://certctl.your-org.example/api/v1/auth/actors \
  -d '{"id":"actor-prometheus","name":"Prometheus scrape","roles":["r-prometheus-scrape"]}'

# 4. Mint an API key for the actor. The response includes a
#    `key_value` field that's only returned ONCE — capture it.
curl -sS --cacert ./ca.crt -X POST \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  https://certctl.your-org.example/api/v1/auth/apikeys \
  -d '{"actor_id":"actor-prometheus","name":"prometheus-scrape-token"}' \
  | tee /tmp/prom-key.json

# Extract just the secret material:
jq -r '.key_value' /tmp/prom-key.json
```

The mint endpoint returns the API key plaintext exactly once. The
server stores only a constant-time-comparable hash; if you lose the
key value, mint a new one.

## Step 2: Create the Kubernetes Secret

```bash
NAMESPACE=certctl
API_KEY=$(jq -r '.key_value' /tmp/prom-key.json)

kubectl create secret generic certctl-prometheus-key \
  -n "$NAMESPACE" \
  --from-literal=api-key="$API_KEY"
```

Now scrub the temporary file:

```bash
shred -u /tmp/prom-key.json
```

## Step 3: Wire the Secret into the chart values

In your `values.yaml` (or `--set` overrides):

```yaml
monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s
    scrapeTimeout: 10s
    bearerTokenSecret:
      name: certctl-prometheus-key
      key: api-key
```

Re-apply the chart:

```bash
helm upgrade certctl . -n "$NAMESPACE" --reuse-values
```

The rendered ServiceMonitor will now include the `bearerTokenSecret`
block. Prometheus Operator's reconciler picks it up and injects the
bearer token into the scrape request.

## Verification

```bash
# 1. Confirm the ServiceMonitor renders with the secret reference
kubectl get servicemonitor -n "$NAMESPACE" certctl-server -o yaml \
  | grep -A2 bearerTokenSecret

# Expected:
#       bearerTokenSecret:
#         name: certctl-prometheus-key
#         key: api-key

# 2. Tail the certctl-server logs for the next ~60 seconds (one
#    Prometheus scrape interval). Look for incoming GET /metrics/prometheus
#    requests authenticated successfully — no 401s.
kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/component=server \
  --tail=100 -f | grep -E "GET /api/v1/metrics/prometheus|metrics-scrape"

# 3. From the Prometheus UI's "Targets" page, the certctl-server
#    target should be UP and last-scrape-error empty. If it's
#    showing 401, the bearer token isn't reaching the request — see
#    troubleshooting below.
```

## Troubleshooting

### Prometheus target shows 401

Three possible causes:

1. **Wrong Secret name / key.** Run
   `kubectl get secret -n "$NAMESPACE" certctl-prometheus-key -o yaml`
   and confirm the `data.api-key` field exists with a base64-encoded
   non-empty value. The Secret's data field name must match the
   `bearerTokenSecret.key` value in `monitoring.serviceMonitor`.
2. **API key doesn't have `metrics.read`.** Hit the gating endpoint
   manually from inside the cluster with the same key:
   ```bash
   kubectl run --rm -it --image=curlimages/curl debug -- \
     curl -sS -H "Authorization: Bearer <API_KEY>" \
     https://certctl-server.certctl.svc.cluster.local:8443/api/v1/metrics/prometheus
   ```
   A 401 here means the role doesn't include `metrics.read`. A 403
   means the role exists but the API key isn't assigned to it.
3. **TLS verification failure (not a 401, but masquerading as one in
   Prometheus's logs).** The default ServiceMonitor template sets
   `insecureSkipVerify: true` to support demos — production deploys
   should set `tlsConfig.caFile` or `tlsConfig.ca.secret` per the
   ServiceMonitor docs.

### Prometheus target shows TLS errors

`monitoring.serviceMonitor.tlsConfig` overrides the default. Three
patterns:

```yaml
# Pattern 1: trust the system CA bundle (production behind a real CA)
tlsConfig:
  caFile: /etc/ssl/certs/ca-certificates.crt
  serverName: certctl.your-org.example

# Pattern 2: trust a CA from a Secret mounted by Prometheus Operator
tlsConfig:
  ca:
    secret:
      name: certctl-ca
      key: ca.crt
  serverName: certctl.your-org.example

# Pattern 3: skip verification (DEMO ONLY — DO NOT USE IN PRODUCTION)
tlsConfig:
  insecureSkipVerify: true
```

The certctl server's self-signed bootstrap cert (default
`server.tls.existingSecret` from the chart) presents a CN of
`certctl-server`. If your `serverName` doesn't match, the scrape
fails with `x509: certificate is valid for certctl-server, not ...`.

## Rotation

API keys are constant-time-compared, stored hashed, and never
logged. Rotation:

```bash
# 1. Mint a new key (same actor + role)
curl -sS --cacert ./ca.crt -X POST \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  https://certctl.your-org.example/api/v1/auth/apikeys \
  -d '{"actor_id":"actor-prometheus","name":"prometheus-scrape-token-v2"}' \
  | tee /tmp/prom-key-new.json

# 2. Update the Secret in place
kubectl create secret generic certctl-prometheus-key \
  -n certctl \
  --from-literal=api-key="$(jq -r '.key_value' /tmp/prom-key-new.json)" \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Wait one scrape interval; verify the next scrape uses the new key.

# 4. Revoke the old key
curl -sS --cacert ./ca.crt -X DELETE \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  https://certctl.your-org.example/api/v1/auth/apikeys/<OLD_KEY_ID>

# 5. Scrub the temp file
shred -u /tmp/prom-key-new.json
```

Prometheus Operator picks up Secret changes automatically — no
ServiceMonitor edit needed, no Prometheus restart.

## Related reading

- [`docs/operator/rbac.md`](../rbac.md) — the full RBAC primitive,
  permission catalogue, and role-assignment workflow.
- [`docs/operator/security.md`](../security.md) — the broader auth
  posture including the API key / OIDC / break-glass paths.
- [`docs/operator/auth-threat-model.md`](../auth-threat-model.md) —
  why `/api/v1/metrics/prometheus` is gated, and what an
  unauthenticated leak of metrics data would reveal.
