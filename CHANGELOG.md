# Changelog

All notable changes to certctl are documented in this file. Dates use ISO 8601. Versions follow [Semantic Versioning](https://semver.org/).

## [unreleased] — 2026-04-24

### G-1: JWT silent auth downgrade — closed end-to-end

> Pre-G-1 the config validator accepted `CERTCTL_AUTH_TYPE=jwt` and the startup log faithfully echoed `"authentication enabled" "type"="jwt"`. Reasonable people read that and concluded JWT was on. It wasn't. The auth-middleware wiring at `cmd/server/main.go` unconditionally routed every request through the api-key bearer middleware regardless of `cfg.Auth.Type`. So `CERTCTL_AUTH_TYPE=jwt` quietly compared incoming `Authorization: Bearer <something>` against whatever string the operator put in `CERTCTL_AUTH_SECRET` — real JWT clients got 401, and operators who treated `CERTCTL_AUTH_SECRET` as a *signing* secret (because they thought they were configuring JWT) had effectively handed an attacker an api-key. A security finding masquerading as a config option. We chose to remove the option rather than ship JWT middleware — the audit-recommended structural fix that closes the hazard. Operators who actually need JWT/OIDC front certctl with an authenticating gateway (oauth2-proxy / Envoy `ext_authz` / Traefik `ForwardAuth` / Pomerium / Authelia) and run the upstream certctl with `CERTCTL_AUTH_TYPE=none`. The same pattern works on docker-compose and Helm.

### Breaking Changes

- **`CERTCTL_AUTH_TYPE=jwt` is no longer accepted.** Pre-G-1 the value was silently downgraded to api-key middleware. Post-G-1 the server fails at startup with a dedicated diagnostic naming the authenticating-gateway pattern. Operators with this in their env block must either switch to `api-key` (if they were de facto using api-key auth all along — same Bearer token continues to work) or switch to `none` and front certctl with an oauth2-proxy / Envoy / Traefik / Pomerium gateway. See [`docs/upgrade-to-v2-jwt-removal.md`](docs/upgrade-to-v2-jwt-removal.md).
- **Helm chart `server.auth.type=jwt` now fails at `helm install` / `helm upgrade` template time.** New `certctl.validateAuthType` template helper runs on every template that depends on `.Values.server.auth.type` (`server-deployment.yaml`, `server-configmap.yaml`, `server-secret.yaml`) and fails the render with a pointer at the gateway-fronting pattern.
- **OpenAPI spec `auth_type` enum no longer includes `jwt`.** API consumers checking `/api/v1/auth/info` against the spec will see a smaller enum.

### Removed

- Documented references to JWT in the certctl auth surface (config docblocks, middleware/health-handler comments, `.env.example`, `docs/architecture.md` middleware-stack bullet). Connector-level JWT references (Google OAuth2 service-account JWT in `internal/connector/discovery/gcpsm/`, `internal/connector/issuer/googlecas/`; step-ca's provisioner one-time-token JWT in `internal/connector/issuer/stepca/`) are unrelated and untouched — those are external-protocol uses, not certctl's own auth shape.

### Added

- **`config.AuthType` typed alias** with `AuthTypeAPIKey` / `AuthTypeNone` exported constants. Single source of truth for the allowed set across the validator, the runtime defense-in-depth switch in `main.go`, and the helm chart's `validateAuthType` helper.
- **`config.ValidAuthTypes()`** helper returning the complete allowed set; pinned by a property test (`TestValidAuthTypesDoesNotContainJWT`) that fails the build if `"jwt"` is ever re-added to the slice.
- **Defense-in-depth runtime guard** in `cmd/server/main.go` immediately after `config.Load()` — a `switch config.AuthType(cfg.Auth.Type)` that exits 1 if the validator was bypassed (test harness, alt config loader, env-var rebinding).
- **`certctl.validateAuthType` Helm template helper** mirroring the existing `certctl.tls.required` pattern. Fails template render on any `server.auth.type` outside `{api-key, none}`.
- **`docs/architecture.md` "Authenticating-gateway pattern (JWT, OIDC, mTLS)"** section explaining the design rationale for the narrow in-process auth surface and listing oauth2-proxy / Envoy `ext_authz` / Traefik `ForwardAuth` / Pomerium / Authelia / Caddy `forward_auth` / Apache `mod_auth_openidc` / nginx `auth_request` as the standard fronting options.
- **`docs/upgrade-to-v2-jwt-removal.md`** migration guide. Same shape as `docs/upgrade-to-tls.md`. Walks through the dedicated startup error, both recovery paths (`api-key` vs gateway-fronting), a complete docker-compose oauth2-proxy walkthrough, Traefik ForwardAuth and Envoy `ext_authz` patterns, and rollback posture.
- **`deploy/helm/certctl/README.md`** "JWT / OIDC via authenticating gateway" section with a Kubernetes-flavored oauth2-proxy + certctl walkthrough.
- **CI regression guardrail** in `.github/workflows/ci.yml` (`Forbidden auth-type literal regression guard (G-1)`) — grep-fails the build if `"jwt"` appears as an auth-type literal in production code or spec. Connector packages exempt (legitimate external-protocol uses).
- **Negative test coverage** in `internal/config/config_test.go`: `TestValidate_JWTAuth_RejectedDedicated` (two table rows pinning that the dedicated G-1 error fires regardless of whether `Secret` is set), `TestValidAuthTypesDoesNotContainJWT` (property-level guard), `TestValidAuthTypesIsExactly_APIKey_None` (allowed-set contract), `TestValidate_GenericInvalidAuthType` (pins that other invalid values still surface the generic invalid-auth-type error, so the dedicated G-1 path doesn't accidentally swallow non-jwt typos).

### Changed

- `internal/api/middleware/middleware.go::AuthConfig.Type` field comment now references the typed `config.AuthType` constants instead of an inline string enumeration.
- `internal/api/handler/health.go::HealthHandler.AuthType` field comment same treatment.
- `internal/api/handler/health_test.go` — the prior `TestAuthInfo_ReturnsAuthType_JWT` (which asserted the handler echoed `"jwt"`, baking the silent-downgrade lie into the regression suite) is removed; the pre-existing `TestAuthInfo_ReturnsAuthType_APIKey` continues to cover the api-key happy path.
- Auth-disabled startup log in `main.go` now points operators at the authenticating-gateway pattern explicitly.

### U-2: Dockerfile HEALTHCHECK protocol mismatch — closed end-to-end

> Pre-U-2 the published `ghcr.io/shankar0123/certctl-server` image shipped with `HEALTHCHECK CMD curl -f http://localhost:8443/health`. The server has been HTTPS-only since the v2.2 HTTPS-Everywhere milestone (`cmd/server/main.go::ListenAndServeTLS`, no plaintext fallback, TLS 1.3 pinned), so the probe failed every interval and Docker marked the container `unhealthy` indefinitely. Operators inside docker-compose / Helm / the example stacks were unaffected — compose overrides the HEALTHCHECK with `--cacert + https://`, Helm uses explicit `httpGet` probes that ignore Docker's HEALTHCHECK, and every example compose file overrides with `curl -sfk https://localhost:8443/health`. But anyone running bare `docker run` / Docker Swarm / Nomad / ECS — exactly the "I just pulled the published image" path — saw permanent `unhealthy` status and (depending on orchestrator policy) a restart-loop. Recon for U-2 also surfaced two adjacent bugs from the same v2.2 milestone gap: the Helm chart's `readinessProbe.httpGet.path` pointed at `/readyz`, a route the server doesn't register (only `/health` and `/ready` are wired and bypass the auth middleware), so K8s readiness probes were getting 404/auth-rejection and pods stayed `NotReady`; and the agent image had no HEALTHCHECK at all (the compose override called `pgrep -f certctl-agent` against an image that didn't ship `procps` — latent always-fail). All three are closed in this commit.

### Fixed

- **`Dockerfile` HEALTHCHECK now speaks HTTPS.** Bare `docker run` / Swarm / Nomad / ECS users no longer see `unhealthy` forever. The probe uses `curl -fsk https://localhost:8443/health` — `-k` (insecure) is acceptable because the probe is localhost-to-localhost: the same process serving the cert is being probed; the probe never traverses a network. Compose / Helm / examples already perform full cert-chain validation and are unaffected.
- **Helm `server.readinessProbe.httpGet.path` corrected from `/readyz` to `/ready`.** The `/readyz` path was never registered as a no-auth route (see `internal/api/router/router.go:81` and `cmd/server/main.go:920`), so K8s readiness probes received 401 (api-key auth rejection) or 404 (when auth was disabled). Pods previously failed to report Ready under most realistic Helm deployments. Liveness probe path (`/health`) was already correct and is unchanged.
- **`docs/connectors.md` curl examples** (15 sites) updated from `http://localhost:8443/...` to `https://localhost:8443/...` with a one-time `--cacert "$CA"` extraction note matching the existing pattern in `docs/quickstart.md`. Pre-U-2 these examples silently failed against the HTTPS listener.

### Added

- **`Dockerfile.agent` HEALTHCHECK** — `pgrep -f certctl-agent` process-presence check (the agent has no HTTP listener; presence is the right primitive). Bare-`docker run` agents now report health-status the same way compose-managed ones do. Also adds `procps` to the runtime image so `pgrep` is actually available — pre-U-2 the docker-compose override at `deploy/docker-compose.yml:173` called `pgrep -f certctl-agent` against an image that lacked it (latent always-fail; container was reported unhealthy in compose too, just rarely noticed because nothing acted on the signal).
- **`deploy/test/healthcheck_test.go`** (`//go:build integration`) — image-level integration tests. `TestPublishedServerImage_HealthcheckSpecUsesHTTPS` builds the server image, inspects `Config.Healthcheck.Test` via `docker inspect`, and asserts the array contains `https://localhost:8443/health` and `-k`, and does NOT contain `http://localhost:8443/health` (negative regression contract). `TestPublishedAgentImage_HealthcheckSpecExists` builds the agent image and asserts the HEALTHCHECK uses `pgrep` against `certctl-agent`. Both tests `t.Skip` cleanly when docker isn't available (sandbox / CI without docker-in-docker). A third runtime test (`TestPublishedServerImage_HealthcheckTransitionsToHealthy`) is a `t.Skip` placeholder until the harness wires a sidecar postgres for image-level smoke — documented honestly so the next refactor adopts it instead of rediscovering the gap.
- **CI regression guardrail** in `.github/workflows/ci.yml` (`Forbidden plaintext HEALTHCHECK regression guard (U-2)`) — grep-fails the build if any `Dockerfile*` carries `HEALTHCHECK.*http://` or `curl -f http://localhost:8443/health`. Comments exempt; the `docs/upgrade-to-tls.md:182` post-cutover invariant string (which deliberately documents the expected-failure shape) is out of the guardrail's scope because the guardrail only scans Dockerfiles.

### Changed

- `Dockerfile` final-stage HEALTHCHECK lines now carry a long-form docblock explaining the `-k` design choice, the published-image vs compose vs Helm vs examples coverage matrix, and cross-references to the audit closure + the integration test.
- `Dockerfile.agent` runtime stage adds `procps` to the apk install so the new HEALTHCHECK and the existing compose override both have a working `pgrep`.
- `deploy/helm/certctl/values.yaml` server probes block now carries an explanatory comment naming the registered probe routes (`/health`, `/ready`) and the U-2 closure rationale for the `/readyz` → `/ready` correction.

## [2.2.0] — 2026-04-19

### HTTPS Everywhere — The Irony

> certctl manages other teams' certificates. Until v2.2, it didn't terminate TLS on its own control plane. We treated the server as an internal service sitting behind whatever TLS-terminating infrastructure the operator already owned — reverse proxies, Kubernetes Ingress controllers, service mesh sidecars. Working through an EST coverage-gap audit surfaced this as a credibility problem we wanted to fix head-on: a cert-lifecycle product should ship with HTTPS by default. This release flips that. Self-signed bootstrap for docker-compose demos, operator-supplied Secret for Helm (with optional cert-manager integration), and a one-step cutover with no backward-compat bridge. Out-of-date agents will fail at the TLS handshake layer on upgrade; the upgrade guide walks operators through the roll.

### Breaking Changes

- **HTTPS-only control plane. The plaintext HTTP listener is gone.** There is no `CERTCTL_TLS_ENABLED=false` escape hatch and no `:8080` fallback. Operators who were running certctl behind their own TLS terminator must either (a) continue doing so and let the downstream TLS terminator talk to certctl's HTTPS listener, or (b) bring their own cert/key and terminate on certctl directly. Either path requires config changes — see `docs/upgrade-to-tls.md` for a one-step cutover.
- **Agents reject `CERTCTL_SERVER_URL=http://...` at startup.** This is a pre-flight config validation failure with a fail-loud diagnostic pointing at `docs/upgrade-to-tls.md`. Not a TCP-refused, not a TLS-handshake-error — the agent will not even attempt the network call. Every agent deployment must be reconfigured before upgrading the server.
- **CLI and MCP clients require `https://` URLs.** Same pre-flight rejection of plaintext schemes.
- **TLS 1.2 is not supported. TLS 1.3 only.** The server's `tls.Config.MinVersion` is pinned to `tls.VersionTLS13`. Any client still negotiating TLS 1.2 will fail at the handshake. Modern curl, Go stdlib, browsers, and Kubernetes tooling all default to 1.3-capable; legacy clients may need an upgrade.
- **Helm chart requires a TLS source.** `helm install` without one of `server.tls.existingSecret`, `server.tls.certManager.enabled`, or (for eval only) `server.tls.selfSigned.enabled` fails at template time with a diagnostic pointing at `docs/tls.md`. There is no default-to-plaintext path.

### Added

- **Self-signed bootstrap for Docker Compose demos.** A `certctl-tls-init` init container runs before the server on first boot, generates a SAN-valid self-signed cert into `deploy/test/certs/`, and exits. The server mounts the resulting cert/key. Every curl in the demo stack pins against `./deploy/test/certs/ca.crt` with `--cacert`.
- **Helm chart TLS provisioning — three modes.** Operator-supplied Secret (`server.tls.existingSecret`), cert-manager integration (`server.tls.certManager.enabled` with issuer selection), or self-signed (`server.tls.selfSigned.enabled` — eval only, not supported for production). Chart templates enforce exactly one is active.
- **Hot-reload of TLS cert/key on `SIGHUP`.** Overwrite the cert/key on disk, send `SIGHUP` to the server PID, watch the `slog.Info("tls.reload", ...)` log line, and new TLS connections use the new cert. Failure during reload is logged and does not crash the server; the previous cert remains in use.
- **Agent CA-bundle env vars.** `CERTCTL_SERVER_CA_BUNDLE_PATH` points at a PEM file the agent's HTTP client will trust. `CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY` disables verification (development only — the agent logs a loud warning at startup). `install-agent.sh` writes both as commented template lines into the generated `agent.env`.
- **Integration test suite runs over HTTPS.** `go test -tags=integration ./deploy/test/...` stands up the full Compose stack, extracts the self-signed CA bundle, and exercises every certctl API over `https://localhost:8443`. All 34 subtests green.
- **`docs/tls.md`** — cert provisioning patterns: bring-your-own Secret, cert-manager, self-signed bootstrap, SAN requirements, rotation workflows, SIGHUP reload semantics, troubleshooting.
- **`docs/upgrade-to-tls.md`** — one-step cutover guide for existing v2.1 operators. Walks through the agent fleet roll, Helm upgrade sequencing, downgrade-is-not-supported warnings, and cert-provisioning decision tree.

### Changed

- `cmd/server/main.go` now calls `http.Server.ListenAndServeTLS(certFile, keyFile)`. The plaintext `ListenAndServe` code path is deleted — `grep -rn "ListenAndServe[^T]" cmd/ internal/` returns zero hits.
- All documentation curls (`docs/testing-guide.md`, `docs/quickstart.md`, `deploy/helm/INSTALLATION.md`, `deploy/helm/DEPLOYMENT_GUIDE.md`, `deploy/ENVIRONMENTS.md`, `docs/openapi.md`, migration guides, example READMEs) use `https://localhost:8443` and `--cacert` against the demo stack's bundle.
- OpenAPI spec (`api/openapi.yaml`) `servers` blocks default to `https://localhost:8443`.

### Security

- TLS 1.3 pinned via `tls.Config.MinVersion = tls.VersionTLS13`.
- Plaintext HTTP listener removed entirely — no port 8080, no `Upgrade-Insecure-Requests`, no HSTS-required redirect dance. There is only one port: 8443, TLS 1.3.
- `grep -rn "http://" cmd/ internal/` returns zero hits outside test fixtures and the agent-side URL-scheme rejection error message.

### Upgrade Notes

Read `docs/upgrade-to-tls.md` before upgrading. The short version:

1. Pick a TLS source — bring-your-own cert, cert-manager, or self-signed bootstrap.
2. Upgrade the server with TLS configured. First boot over HTTPS.
3. Roll the agent fleet: set `CERTCTL_SERVER_URL=https://...` and, if using a private CA, `CERTCTL_SERVER_CA_BUNDLE_PATH`. Old agents will fail loud at startup — expected.
4. Roll CLI/MCP clients the same way.

There is no backward-compat bridge. There is no dual-listener mode. The cutover is one step.
