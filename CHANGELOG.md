# Changelog

All notable changes to certctl are documented in this file. Dates use ISO 8601. Versions follow [Semantic Versioning](https://semver.org/).

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
