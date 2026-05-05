# Upgrading past G-1 — `CERTCTL_AUTH_TYPE=jwt` removal

> **Archived 2026-05-05.** This upgrade guide applies to operators
> upgrading past the G-1 milestone (the `CERTCTL_AUTH_TYPE=jwt` removal).
> Current operators on post-G-1 releases don't need this. For the
> steady-state security posture reference, see
> [`docs/operator/security.md`](../../operator/security.md). Preserved
> here for late upgraders.

If your certctl deployment currently sets `CERTCTL_AUTH_TYPE=jwt` (or `server.auth.type=jwt` in Helm), the next certctl upgrade will fail-fast at startup with a dedicated diagnostic. This guide explains why, what to switch to, and how to keep JWT/OIDC at your edge.

For everyone else — operators running `api-key` or `none` — this upgrade is a no-op. Skip to [`to-tls-v2.2.md`](to-tls-v2.2.md) for the v2.2 HTTPS-everywhere migration if you haven't done that one yet.

## Why we removed it

Pre-G-1, the config validator at `internal/config/config.go` accepted three values for `CERTCTL_AUTH_TYPE`: `api-key`, `jwt`, and `none`. The startup log line at `cmd/server/main.go` faithfully echoed `"authentication enabled" "type"="jwt"` when an operator picked `jwt`. Reasonable people read that and concluded JWT auth was on.

It wasn't. Grep `internal/ cmd/` for `NewJWT`, `JWTMiddleware`, or `jwt.Parse` — pre-G-1, there were zero matches in production code. The auth-middleware wiring at `cmd/server/main.go:653` unconditionally called `middleware.NewAuthWithNamedKeys(namedKeys)` regardless of `cfg.Auth.Type`. So `CERTCTL_AUTH_TYPE=jwt` just routed every request through the api-key bearer middleware, comparing the incoming `Authorization: Bearer <something>` against whatever string the operator put in `CERTCTL_AUTH_SECRET`. Real JWT clients got 401 (the api-key middleware saw the JWT string as a literal token and compared bytes). Operators who treated `CERTCTL_AUTH_SECRET` as a JWT signing secret (and therefore handled it less carefully than an api-key) handed an attacker an api-key. Silent auth downgrade — a security finding masquerading as a config option.

We chose to remove the option rather than implement JWT middleware. Implementing real JWT/OIDC requires jwks vs static-secret rotation, claim mapping (which claim is the actor / the admin flag?), expiry enforcement, audience and issuer validation, key rollover semantics, and regression coverage at the same depth as the existing api-key path. That's a feature, not a fix. The audit-recommended structural fix — and the one that actually closes the hazard — is to fail loudly instead of silently downgrading.

## What changes at startup

Post-G-1, a binary started with `CERTCTL_AUTH_TYPE=jwt` exits non-zero before opening the listener:

```
Failed to load configuration: CERTCTL_AUTH_TYPE=jwt is no longer accepted
(G-1 silent auth downgrade): no JWT middleware ships with certctl. To use
JWT/OIDC, run an authenticating gateway (oauth2-proxy / Envoy ext_authz /
Traefik ForwardAuth / Pomerium) in front of certctl and set
CERTCTL_AUTH_TYPE=none on the upstream. See docs/architecture.md
"Authenticating-gateway pattern" and docs/upgrade-to-v2-jwt-removal.md
for the migration walkthrough
```

Helm operators get the same shape at `helm install` / `helm upgrade` template time: `server.auth.type=jwt` is rejected by the chart's `certctl.validateAuthType` template helper before any Kubernetes object is rendered.

The CI-side regression guard at `.github/workflows/ci.yml` blocks any future PR that re-introduces `"jwt"` as an auth-type literal in production code or spec.

## Recovery — pick one

### Option A — switch to `api-key` (you weren't actually using JWT)

If your `CERTCTL_AUTH_SECRET` was a single high-entropy token and your clients sent it as `Authorization: Bearer <token>`, you were already using api-key auth — you just had `CERTCTL_AUTH_TYPE` set to the wrong string. Flip it:

```
# .env (docker-compose)
CERTCTL_AUTH_TYPE=api-key
CERTCTL_AUTH_SECRET=<your-existing-token>
```

```
# Helm
helm upgrade <release> deploy/helm/certctl/ \
  --reuse-values \
  --set server.auth.type=api-key \
  --set server.auth.apiKey=<your-existing-token>
```

No client changes needed — the same Bearer token continues to work. The startup log will now read `"authentication enabled" "type"="api-key"`, which matches what was actually happening pre-G-1.

### Option B — front certctl with an authenticating gateway

If you genuinely need JWT, OIDC, mTLS, or SAML, run an authenticating gateway in front of certctl and let the gateway terminate the federated identity protocol. Configure certctl for `CERTCTL_AUTH_TYPE=none`:

```
CERTCTL_AUTH_TYPE=none
```

Then put an oauth2-proxy / Envoy `ext_authz` / Traefik `ForwardAuth` / Pomerium / Authelia (etc.) in the network path between operators and certctl. The gateway validates the identity and proxies the authenticated request to certctl as a same-origin call on a private network.

### Concrete walkthrough — oauth2-proxy + certctl on docker-compose

This is the simplest production-grade JWT/OIDC shape. It assumes you have an OIDC provider (Okta, Auth0, Google Workspace, Keycloak, Dex) and a registered client_id / client_secret.

```yaml
# deploy/docker-compose.gateway.yml — overlay on the base compose file
services:
  oauth2-proxy:
    image: quay.io/oauth2-proxy/oauth2-proxy:latest
    command:
      - --provider=oidc
      - --oidc-issuer-url=https://<your-issuer>/
      - --client-id=${OIDC_CLIENT_ID}
      - --client-secret=${OIDC_CLIENT_SECRET}
      - --cookie-secret=${OAUTH2_PROXY_COOKIE_SECRET}  # openssl rand -base64 32
      - --upstream=http://certctl-server:8443  # internal-network only; certctl listens on 8443
      - --http-address=0.0.0.0:4180
      - --email-domain=*
      - --pass-access-token=true
      - --pass-authorization-header=true
      - --set-authorization-header=true       # forwards a bearer token upstream
      - --skip-provider-button=true
      - --reverse-proxy=true
    ports:
      - "443:4180"
    depends_on:
      - certctl-server
    networks:
      - certctl-network

  certctl-server:
    environment:
      CERTCTL_AUTH_TYPE: none   # gateway terminates auth — see docs/upgrade-to-v2-jwt-removal.md
      # ... rest of the certctl env block unchanged
```

Operators hit `https://<your-host>/`, get redirected through the OIDC provider, land back at oauth2-proxy with a session cookie, and oauth2-proxy proxies their request to certctl on the internal Docker network. certctl itself is HTTPS-only on `:8443` (TLS 1.3, see [`tls.md`](../../operator/tls.md)) but operator browsers never see that hop directly. Bind certctl-server's `:8443` to the internal Docker network only — do NOT publish it to the host. The audit trail will record the actor as the gateway-forwarded identity if you also configure a small bearer-token-mapping shim at the gateway (most production deployments do this with a per-user api-key issued by the gateway after OIDC validation).

### Traefik ForwardAuth pattern (Kubernetes)

Same shape, kubernetes-flavored:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-forward-auth
spec:
  forwardAuth:
    address: http://oauth2-proxy.auth.svc.cluster.local:4180
    trustForwardHeader: true
    authResponseHeaders:
      - X-Auth-Request-User
      - X-Auth-Request-Email
      - Authorization
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: certctl
spec:
  routes:
    - match: Host(`certctl.example.com`)
      kind: Rule
      middlewares:
        - name: oidc-forward-auth
      services:
        - name: certctl-server
          port: 8443
```

The certctl Helm release runs with `server.auth.type=none`. The Traefik IngressRoute attaches `oidc-forward-auth` as a middleware so every request is OIDC-validated by oauth2-proxy before reaching certctl.

### Envoy `ext_authz` pattern

For service-mesh deployments (Istio, Consul, plain Envoy), the `ext_authz` filter calls out to an external authorization service per-request. Same outcome: certctl runs `CERTCTL_AUTH_TYPE=none` and Envoy + your authz service handle JWT/OIDC/mTLS at the mesh edge. See the [Envoy ext_authz docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) for the configuration surface.

## Rollback

Pre-G-1 binaries silently accepted `CERTCTL_AUTH_TYPE=jwt` and routed through the api-key middleware. Downgrading the binary is the only mechanical rollback path, and it puts you back into the silent-downgrade state — which is exactly what the G-1 audit finding is about. We don't recommend it. If something is forcing your hand, capture the operational issue you're hitting and open a GitHub issue against the certctl repo with the SHAs involved; the Authenticating-gateway pattern was specifically designed to cover the use cases that historically led operators to set `CERTCTL_AUTH_TYPE=jwt`.

There is no on-disk state that changes with this upgrade — no migrations to roll back, no encrypted config to re-encode, no certificates to re-issue. The change is entirely in the config-validation surface and the helm-chart template guard.

## Cross-references

- [`architecture.md`](../../reference/architecture.md) — "Authenticating-gateway pattern (JWT, OIDC, mTLS)" section.
- [`tls.md`](../../operator/tls.md) — TLS provisioning patterns. The gateway proxying to certctl-server still needs to trust certctl's TLS cert; same patterns apply.
- [`../deploy/helm/certctl/README.md`](../deploy/helm/certctl/README.md) — Helm-chart-flavored guidance.
- `internal/config/config.go::ValidAuthTypes` — the single source of truth for what's accepted post-G-1.
- `internal/repository/postgres/db.go::wrapPingError` — unrelated; pattern for runtime diagnostic of operator misconfiguration.
- `coverage-gap-audit-2026-04-24-v5/unified-audit.md` — the audit finding (`cat-g-jwt_silent_auth_downgrade`).
