# Traefik Integration Walkthrough

> Last reviewed: 2026-05-05

> **Use this walkthrough when** you're already running Traefik 3.0+
> (Kubernetes or VM) and want it to ACME-issue from certctl (your
> internal CA, your private PKI, or a local sub-CA chained under an
> enterprise root) instead of Let's Encrypt. The Traefik static config
> changes are minimal; the load-bearing piece is `serversTransport.rootCAs`
> so Traefik trusts certctl's bootstrap CA on every outbound ACME call.

End-to-end recipe for issuing certs from a certctl-server deployment
through Traefik 3.0+. Target audience: operator running Traefik (in
Kubernetes or on a VM) who wants to use certctl as their ACME source
of truth instead of Let's Encrypt.

## Prereqs

- A reachable certctl-server with `CERTCTL_ACME_SERVER_ENABLED=true`
  and at least one profile whose `acme_auth_mode` is set. Profile
  setup is identical to the cert-manager walkthrough — see
  [`docs/acme-cert-manager-walkthrough.md`](./acme-cert-manager-walkthrough.md)
  Step 2.
- Traefik 3.0+ (the v2 API surface for ACME is also supported but the
  `serversTransport.rootCAs` reference below is v3-shaped).
- The certctl bootstrap CA, in PEM form, captured the same way as the
  cert-manager walkthrough Step 3.

## Step 1 — Configure Traefik static config

Traefik's ACME issuer is a `certificatesResolver` in the static config
(file or CLI flags or env vars). The relevant fields:

```yaml
# /etc/traefik/traefik.yml (or wherever your static config lives)

certificatesResolvers:
  certctl:
    acme:
      caServer: https://certctl.example.com:8443/acme/profile/prof-test/directory
      email: ops@example.com
      storage: /etc/traefik/acme-certctl.json
      httpChallenge:
        entryPoint: web
      # OR for trust_authenticated mode profiles:
      # tlsChallenge: {}

# certctl uses a self-signed bootstrap cert; Traefik needs the CA
# explicitly via serversTransport.rootCAs to call the directory URL.
serversTransports:
  default:
    rootCAs:
      - /etc/traefik/certctl-bootstrap.crt

# Apply the serversTransport globally so every outbound HTTPS call —
# including ACME directory + finalize — trusts the certctl CA.
api:
  insecure: false

entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"
```

Notes:

- `caServer` must point at the directory URL (ending in `/directory`).
- `httpChallenge.entryPoint: web` requires Traefik's `web` entryPoint
  (port 80) to be reachable from certctl-server's HTTP-01 validator.
  For `trust_authenticated` mode profiles, this is a no-op formality —
  certctl auto-resolves authzs, so the solver round-trip never happens.
- `tlsChallenge: {}` is the alternative that uses TLS-ALPN-01 (RFC 8737)
  via Traefik's `websecure` (port 443) entryPoint. Either works under
  `challenge` mode; only the default-of-`tlsChallenge` is recommended
  for `trust_authenticated` mode.

## Step 2 — Trust the certctl bootstrap CA

Two options:

### Option A — `serversTransport.rootCAs` (preferred)

```
sudo cp deploy/test/certs/ca.crt /etc/traefik/certctl-bootstrap.crt
sudo systemctl reload traefik
```

`serversTransports.default.rootCAs` (shown in Step 1 above) tells
Traefik's outbound HTTPS client to trust the supplied PEM in addition
to the system trust store. This is the right pattern for containerized
Traefik where you don't want to install OS-level trust roots.

### Option B — OS trust store

For Traefik running directly on a VM, `update-ca-certificates`-style
installation works the same way as the Caddy walkthrough Option A.
The `serversTransport.rootCAs` field is unnecessary in that case.

## Step 3 — Reference the resolver from a router

Per-router (dynamic config):

```yaml
# /etc/traefik/dynamic/example-com.yml

http:
  routers:
    example-com:
      rule: "Host(`example.com`)"
      entryPoints: [websecure]
      tls:
        certResolver: certctl
      service: example-com-backend
  services:
    example-com-backend:
      loadBalancer:
        servers:
          - url: "http://localhost:8080"
```

Or, in Kubernetes via `IngressRoute` (Traefik CRD):

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: example-com
spec:
  entryPoints: [websecure]
  routes:
    - match: Host(`example.com`)
      kind: Rule
      services:
        - name: example-com-backend
          port: 8080
  tls:
    certResolver: certctl
```

## Step 4 — Reload Traefik

```
sudo systemctl reload traefik
# OR kubectl rollout restart deployment/traefik (if you changed the static config via ConfigMap).
```

On the first request to `example.com`, Traefik hits certctl's directory
URL, registers an account, submits a new-order, and finalizes. The cert
is persisted to `/etc/traefik/acme-certctl.json` (or its in-cluster
PVC equivalent).

## Step 5 — Verify

```
curl -kvI https://example.com 2>&1 | grep -E 'subject|issuer'
# subject: CN=example.com
# issuer: CN=certctl test internal CA
```

The cert is signed by certctl's bound issuer (per the `prof-test`
profile's `issuer_id`).

On the certctl side, the audit log captures the issuance:

```
psql -c "SELECT actor, action, resource_id FROM audit_events
         WHERE actor LIKE 'acme:%' ORDER BY created_at DESC LIMIT 5;"
```

## Common failure modes

- **Traefik logs `unable to obtain ACME certificate ... x509: certificate
  signed by unknown authority`** → `serversTransport.rootCAs` is not
  pointing at the certctl bootstrap CA, OR the file was rotated and
  Traefik hasn't reloaded. Verify with
  `curl --cacert /etc/traefik/certctl-bootstrap.crt
  https://certctl.example.com:8443/acme/profile/prof-test/directory`.
- **Traefik logs `urn:ietf:params:acme:error:rateLimited`** → tune
  `CERTCTL_ACME_SERVER_RATE_LIMIT_ORDERS_PER_HOUR` on the certctl
  side, OR reduce Traefik's parallel-cert-acquisition concurrency.
- **`acme: error: 400 :: POST :: ... :: badNonce`** → clock skew or
  multi-replica certctl without sticky sessions; same fix as the
  cert-manager walkthrough.
- **Storage file `acme-certctl.json` shows persistent failures** —
  Traefik retains failed-acquisition state. After fixing the
  underlying cause, delete the storage file and reload:
  `rm /etc/traefik/acme-certctl.json && systemctl reload traefik`.

## Cleanup

```
# Remove the certResolver from any router / IngressRoute consuming it.
sudo systemctl reload traefik
# Delete the persisted ACME storage:
sudo rm /etc/traefik/acme-certctl.json
# Or in K8s: drop the resolver from the static-config ConfigMap.
```

## See also

- [`docs/acme-server.md`](./acme-server.md) — canonical reference.
- [`docs/acme-cert-manager-walkthrough.md`](./acme-cert-manager-walkthrough.md) —
  cert-manager equivalent.
- [Traefik upstream ACME docs](https://doc.traefik.io/traefik/https/acme/#caserver) —
  verify behavior pinned here against Traefik 3.0+ semantics.
