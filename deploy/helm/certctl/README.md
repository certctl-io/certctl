# certctl Helm Chart

Production-ready Helm chart for deploying [certctl](https://github.com/shankar0123/certctl) on Kubernetes. Wires up the certctl server (Deployment), PostgreSQL (StatefulSet with PVC), and the agent (DaemonSet — one per node) on a private cluster, with health probes, security contexts, and optional Ingress.

## Quick install

```bash
helm install certctl deploy/helm/certctl/ \
  --create-namespace --namespace certctl \
  --set server.auth.apiKey="$(openssl rand -base64 32)" \
  --set postgresql.auth.password="$(openssl rand -base64 24)"
```

This brings up:

- `<release>-server` Deployment (HTTPS-only on port 8443; TLS 1.3)
- `<release>-postgres` StatefulSet (PostgreSQL 16-alpine, 1 replica, 10Gi PVC by default)
- `<release>-agent` DaemonSet (polls server, generates ECDSA P-256 keys locally)
- Service objects, optional Ingress, and ServiceAccount with RBAC

See [`values.yaml`](values.yaml) for the full configuration surface — issuer settings, target connectors, scheduler intervals, notifier credentials, and resource requests/limits all live there.

## Operational notes

### Postgres password rotation — read this before changing `postgresql.auth.password`

**The trap.** `postgresql.auth.password` is bound to `pg_authid` exactly once — when the StatefulSet's PVC is provisioned and `initdb` runs. The official `postgres:16-alpine` image only runs `initdb` when `/var/lib/postgresql/data` is empty, so on every subsequent rollout the `POSTGRES_PASSWORD` env var is read into the container but **ignored** by postgres itself. The certctl-server container also picks up the new value (via the database URL helper template), so the two halves diverge: server presents the new password, postgres still expects the old one.

**Symptom.** The certctl-server pod's startup log shows:

```
failed to ping database: postgres rejected the configured credentials
(SQLSTATE 28P01 — invalid_password). If you recently rotated POSTGRES_PASSWORD ...
```

That diagnostic is emitted by `internal/repository/postgres/db.go::wrapPingError` — it points operators at the two remediation paths below.

**Remediation, non-destructive (preferred for any environment with real data):**

```bash
# 1. Rotate the password in postgres directly
kubectl -n certctl exec -it <release>-postgres-0 -- \
  psql -U certctl -c "ALTER ROLE certctl PASSWORD '<new-password>';"

# 2. Update the secret / Helm values to the same value
helm upgrade <release> deploy/helm/certctl/ \
  --reuse-values \
  --set postgresql.auth.password='<new-password>'

# 3. Bounce the certctl-server pod so it re-reads the secret
kubectl -n certctl rollout restart deployment/<release>-server
```

**Remediation, destructive (DESTROYS ALL CERTCTL DATA — only acceptable on dev/demo clusters):**

```bash
helm uninstall <release> -n certctl
kubectl -n certctl delete pvc -l \
  app.kubernetes.io/name=certctl,app.kubernetes.io/component=postgres
helm install <release> deploy/helm/certctl/ \
  --namespace certctl \
  --set postgresql.auth.password='<new-password>'
```

The PVC re-creates empty, `initdb` runs on first boot of the new postgres pod, and `pg_authid` is seeded with the new password.

**Why we don't fix this in the chart.** The env-vs-`pg_authid` divergence is intrinsic to how the upstream `postgres` image bootstraps — `initdb` is run-once-per-empty-data-dir, and there is no upstream-supported way to make subsequent boots re-seed `pg_authid` from `POSTGRES_PASSWORD`. The ergonomic answer is the runtime diagnostic plus this operational note.

**Cross-references.** Same root cause is documented for the docker-compose path in [`docs/quickstart.md`](../../../docs/quickstart.md) (Warning callout after the `cp .env.example .env` block) and in [`deploy/ENVIRONMENTS.md`](../../ENVIRONMENTS.md) (Stateful volume — first-boot password binding section). The runtime diagnostic itself lives in `internal/repository/postgres/db.go::wrapPingError` with regression coverage in `internal/repository/postgres/db_test.go`.

### Server API key rotation

Unlike the postgres password, `server.auth.apiKey` accepts a comma-separated list, so zero-downtime rotation is straightforward:

```bash
# 1. Add the new key alongside the old
helm upgrade <release> deploy/helm/certctl/ \
  --reuse-values \
  --set server.auth.apiKey='new-key,old-key'

# 2. Roll your agents / clients over to the new key

# 3. Remove the old key
helm upgrade <release> deploy/helm/certctl/ \
  --reuse-values \
  --set server.auth.apiKey='new-key'
```

### JWT / OIDC via authenticating gateway

certctl's in-process auth surface is intentionally narrow: `server.auth.type=api-key` for production deployments and `server.auth.type=none` for development. There is no in-process JWT, OIDC, mTLS, or SAML middleware. (`server.auth.type=jwt` was accepted pre-G-1 but silently routed every request through the api-key bearer middleware — silent auth downgrade. The chart now fails at `helm install`/`helm upgrade` template time via the `certctl.validateAuthType` helper if you set it. See [`../../../docs/upgrade-to-v2-jwt-removal.md`](../../../docs/upgrade-to-v2-jwt-removal.md) if you previously had this in your values.)

For deployments that need JWT/OIDC, the canonical Kubernetes-flavored shape is to put oauth2-proxy in front of the certctl Service, attach an authenticating Ingress middleware, and run certctl with `server.auth.type=none`:

```bash
# 1. Install oauth2-proxy (or any OIDC-terminating sidecar) in the same namespace
helm install oauth2-proxy oauth2-proxy/oauth2-proxy \
  --namespace certctl \
  --set config.clientID="$OIDC_CLIENT_ID" \
  --set config.clientSecret="$OIDC_CLIENT_SECRET" \
  --set config.cookieSecret="$(openssl rand -base64 32)" \
  --set config.configFile='|
    provider = "oidc"
    oidc_issuer_url = "https://your-issuer/"
    upstreams = ["http://<release>-server.certctl.svc.cluster.local:8443"]
    pass_authorization_header = true
    set_authorization_header = true
    email_domains = ["*"]
  '

# 2. Install certctl with type=none (gateway terminates auth)
helm install certctl deploy/helm/certctl/ \
  --namespace certctl \
  --set server.auth.type=none \
  --set postgresql.auth.password="$(openssl rand -base64 24)"

# 3. Attach an Ingress that routes through oauth2-proxy
#    (Traefik ForwardAuth, nginx auth_request, Envoy ext_authz, etc.)
```

Same root pattern works with Pomerium, Authelia, Caddy `forward_auth`, Apache `mod_auth_openidc`, or any service-mesh `ext_authz`. See [`../../../docs/architecture.md`](../../../docs/architecture.md) "Authenticating-gateway pattern" for the full design rationale and [`../../../docs/upgrade-to-v2-jwt-removal.md`](../../../docs/upgrade-to-v2-jwt-removal.md) for the migration walkthrough.

### TLS certificate sourcing

By default the chart provisions a self-signed cert via the same init-container pattern as the docker-compose deploy. For production, supply an operator-managed Secret (cert-manager, internal CA, etc.) — see [`docs/tls.md`](../../../docs/tls.md) for the full provisioning matrix and [`docs/upgrade-to-tls.md`](../../../docs/upgrade-to-tls.md) for upgrade-from-HTTP procedures.

## Disabling embedded postgres

If you have an existing PostgreSQL cluster, disable the embedded one and point at it directly:

```bash
helm install certctl deploy/helm/certctl/ \
  --set postgresql.enabled=false \
  --set server.databaseUrl='postgres://certctl:<pw>@my-pg-host:5432/certctl?sslmode=require'
```

The volume-trap section above does **not** apply to this configuration — your postgres operator (or cloud DB) handles password rotation, and you control `pg_authid` directly.

## Uninstall

```bash
helm uninstall <release> -n certctl
# Optional — also delete the postgres PVC (DESTROYS DATA):
kubectl -n certctl delete pvc -l \
  app.kubernetes.io/name=certctl,app.kubernetes.io/component=postgres
```

By default `helm uninstall` retains the StatefulSet's PVCs, so reinstalling with the same release name preserves the database. If you've changed `postgresql.auth.password` in your values between uninstall and reinstall, you'll hit the trap on the reinstall — apply the non-destructive remediation above, or also delete the PVC.
