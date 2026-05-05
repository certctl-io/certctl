# TLS on the Control Plane

> Last reviewed: 2026-05-05

certctl's control plane is HTTPS-only as of v2.2. There is no plaintext `http://` listener, no `auto` mode, no dual-listener bridge, no TLS 1.2 escape hatch. The server refuses to start without a cert+key pair, the agent/CLI/MCP clients reject `http://` URLs at startup, and the Helm chart refuses to render without either an operator-supplied Secret or a cert-manager Certificate CR.

This doc covers four cert provisioning patterns, SIGHUP-based cert rotation, and the client-side CA-trust configuration agents and the CLI need to talk to the server. If you are upgrading from a pre-HTTPS release and want the step-by-step cutover procedure, read [`upgrade-to-tls.md`](../archive/upgrades/to-tls-v2.2.md) first and come back here for reference.

## What you get

The server binds TLS 1.3 only with an explicit curve preference of `[X25519, P-256]`. TLS 1.3 cipher suites are non-negotiable (all three mandatory suites — AES-128-GCM-SHA256, AES-256-GCM-SHA384, CHACHA20-POLY1305-SHA256 — are always offered), so there is no `CipherSuites` knob to misconfigure. No TLS 1.2 fallback is available.

Two env vars are required on the server:

- `CERTCTL_SERVER_TLS_CERT_PATH` — filesystem path to the PEM-encoded server certificate
- `CERTCTL_SERVER_TLS_KEY_PATH` — filesystem path to the PEM-encoded private key that signs the cert

Both paths are read during a fail-loud preflight in `cmd/server/main.go` (see `preflightServerTLS` in `cmd/server/tls.go`). If either is unset, unreadable, or the cert+key pair does not round-trip through `tls.LoadX509KeyPair`, the process refuses to start and emits a diagnostic pointing back at this doc. The rationale lives in §3 of the HTTPS-Everywhere milestone: a cert-lifecycle product should not silently bind plaintext.

## Pattern 1 — Self-signed bootstrap for docker-compose demos

This is the default for the `deploy/docker-compose.yml` stack. It exists so `docker compose up -d --build` just works on a laptop without the operator standing up a CA first. It is not appropriate for any non-demo environment.

An init container named `certctl-tls-init` runs once before the server starts. It uses the `alpine/openssl` image and generates an ECDSA-P256 self-signed cert (SHA-256 signature):

```
openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:P-256 \
  -nodes \
  -keyout /etc/certctl/tls/server.key \
  -out   /etc/certctl/tls/server.crt \
  -days 3650 \
  -subj "/CN=certctl-server" \
  -addext "subjectAltName=DNS:certctl-server,DNS:localhost,IP:127.0.0.1,IP:::1"
```

**Why ECDSA-P256 and not ed25519.** The pre-v2.0.48 demo bootstrap used ed25519 (small keys, fast signatures). Apple's TLS stack — Safari Network Framework and the macOS-bundled LibreSSL 3.3.6 `/usr/bin/curl` — does not advertise ed25519 in the ClientHello `signature_algorithms` extension for server certs, so an ed25519 server cert was rejected at handshake with `tls: peer doesn't support any of the certificate's signature algorithms` on the server side (and the generic TLS handshake error on the client side). Homebrew OpenSSL 3.x, Chrome, Firefox, and Linux curl all accepted ed25519 — Apple was the outlier. ECDSA-P256 with SHA-256 is universally supported, so the demo bootstrap uses it by default. To pick up the new algorithm on an existing demo install, tear the volume down and rebuild: `docker compose -f deploy/docker-compose.yml down -v && docker compose -f deploy/docker-compose.yml up -d --build`. **Helm and operator-supplied-Secret users (Patterns 2 and 3) are unaffected** — they bring their own cert, and `cmd/server/tls.go` is algorithm-agnostic (TLS 1.3 with curve preference `[X25519, P-256]` for key exchange — no constraint on the server cert's signature algorithm).

The cert, its matching key, and a copy of the cert published as `ca.crt` land in a named volume (`certs`) mounted at `/etc/certctl/tls/` in the server container (read-only) and the agent container (read-only). The bootstrap is idempotent — if `server.crt`, `server.key`, and `ca.crt` are already present on the volume, the init container logs `TLS cert already present at …` and exits cleanly.

Single-cert design. CN is `certctl-server` to match the Docker-network hostname. The SAN list is `[certctl-server, localhost, 127.0.0.1, ::1]`, which covers both container-internal agent→server traffic and operator browser/curl access to `https://localhost:8443`. There is no separate intermediate/root chain — the server cert and the CA bundle are the same PEM. This is the whole point of a demo bootstrap.

To force regeneration (rotate the demo cert), tear the volume down: `docker compose down -v`. The next `up` re-runs the init container.

The server's Docker healthcheck and the agent both verify against `/etc/certctl/tls/ca.crt`; no `-k` / `InsecureSkipVerify` anywhere in the default stack.

## Pattern 2 — Operator-supplied `kubernetes.io/tls` Secret (Helm)

This is the default path for Helm installs. The operator provisions a Secret of type `kubernetes.io/tls` holding `tls.crt` + `tls.key` (and optionally `ca.crt` for mounting a CA bundle to clients in the same cluster) from whatever source they already trust — their internal CA, a manually-issued cert, step-ca, AWS ACM PCA exported to PEM, or the output of the self-signed bootstrap pattern above copied into a cluster Secret.

```
kubectl create secret tls certctl-server-tls \
  --cert=server.crt \
  --key=server.key \
  --namespace certctl
```

Then:

```
helm install certctl deploy/helm/certctl \
  --namespace certctl \
  --set server.tls.existingSecret=certctl-server-tls
```

The Secret is mounted read-only at `/etc/certctl/tls/` in the server pod. The `CERTCTL_SERVER_TLS_CERT_PATH` and `CERTCTL_SERVER_TLS_KEY_PATH` env vars are wired to `tls.crt` and `tls.key` keys inside that mount. If `ca.crt` is absent from the Secret, clients that need a CA bundle should use `tls.crt` as the bundle (self-signed case) or mount a separate ConfigMap with the root chain (operator-CA case).

If the operator sets neither `server.tls.existingSecret` nor `server.tls.certManager.enabled=true`, `helm template` / `helm install` fails at render-time with a diagnostic pointing at this doc. The guard is implemented in `deploy/helm/certctl/templates/_helpers.tpl` under the `certctl.tls.required` helper. This is deliberate: the HTTPS-only server would crash-loop on an empty path, so we fail earlier at Helm-render time.

## Pattern 3 — cert-manager `Certificate` CR (Helm, opt-in)

For clusters that already run cert-manager, the chart can provision a `Certificate` CR that writes into the Secret the server pod reads from. This is opt-in — the default is `server.tls.certManager.enabled: false` — because not every cluster has cert-manager installed, and we refuse to ship a chart that silently depends on an external controller.

```
helm install certctl deploy/helm/certctl \
  --namespace certctl \
  --set server.tls.certManager.enabled=true \
  --set server.tls.certManager.issuerRef.name=my-cluster-issuer \
  --set server.tls.certManager.issuerRef.kind=ClusterIssuer
```

The rendered `Certificate` (see `deploy/helm/certctl/templates/server-certificate.yaml`) writes `tls.crt` + `tls.key` + `ca.crt` into the Secret named by `server.tls.certManager.secretName` (defaults to `<fullname>-tls`). The server pod reads from that same Secret; the agent DaemonSet mounts the same Secret as its CA bundle source.

cert-manager handles rotation. certctl-server handles in-place reload — see the SIGHUP section below.

The chart enforces that if `server.tls.certManager.enabled=true`, `server.tls.certManager.issuerRef.name` must also be set. An empty `issuerRef.name` makes `helm template` fail with a diagnostic naming the missing flag.

## Pattern 4 — Manually-issued from an internal CA

For operators running neither Helm nor docker-compose (bare-metal / custom orchestration), the server just needs two files on disk pointed at by `CERTCTL_SERVER_TLS_CERT_PATH` and `CERTCTL_SERVER_TLS_KEY_PATH`. Issue the cert from your internal CA with:

- CN matching the hostname your agents and operators use to dial the server (e.g., `certctl.prod.example.com`)
- SAN list covering every hostname and IP that appears in `CERTCTL_SERVER_URL` values across your agent fleet
- Key usage: digital signature + key encipherment
- Extended key usage: server auth

Store the key with mode `0600` and owner matching the UID the server runs as (`1000` in our shipped Dockerfile). The server process reads both files during `preflightServerTLS` at startup and again on every SIGHUP.

The full CA chain that signed the server cert should be distributed to agents, CLI operators, and MCP clients as their `CERTCTL_SERVER_CA_BUNDLE_PATH` — see the client section below.

## SIGHUP cert rotation

The server wraps its cert+key pair in a `*certHolder` (see `cmd/server/tls.go`) that guards the loaded `*tls.Certificate` under a `sync.Mutex`. The `*tls.Config` wires `GetCertificate` to the holder, so every new inbound TLS handshake reads whatever cert the holder currently has.

Send `SIGHUP` to the server PID and the holder re-reads both files from disk. On success, the next new connection uses the new cert; in-flight requests finish on the previous cert. A log line goes out:

```
TLS cert reloaded via SIGHUP cert_path=/etc/certctl/tls/server.crt key_path=/etc/certctl/tls/server.key
```

On failure (missing file, malformed PEM, key does not sign cert), the old cert is retained and an error logs:

```
TLS cert reload failed; continuing with previous cert cert_path=… key_path=… error=…
```

This is deliberately fail-safe on reload (as opposed to fail-loud on startup). A cert-manager renewal race, a partially-copied file, a typo in a rotation script — none of those should crash a running server and drop every agent connection. The operator sees the error in logs, fixes the underlying issue, and sends another `SIGHUP`.

Pair with cert-manager, certbot `--post-hook`, or any rotation tool that can fire a signal. For docker-compose, `docker compose kill -s HUP certctl-server` works. For Kubernetes, reload is typically handled by cert-manager updating the Secret and the mounted file changing on the next kubelet sync — no explicit SIGHUP needed if the volume mount is `subPath`-free.

Startup is a different story. If the cert is missing or malformed at process start, the server exits non-zero rather than binding plaintext or attempting a retry loop. That's the HTTPS-only contract.

## Client-side TLS: agents, CLI, MCP

Everything that talks to the server enforces HTTPS on the URL.

### Agent

`CERTCTL_SERVER_URL` must be `https://…`. `http://`, bare hostnames, `ftp://`, `ws://`, and empty strings are rejected at startup by `validateHTTPSScheme` in `cmd/agent/main.go` with a diagnostic pointing at `upgrade-to-tls.md`. There is no warning-and-proceed path.

Two additional env vars control how the agent verifies the server cert:

- `CERTCTL_SERVER_CA_BUNDLE_PATH` — filesystem path to a PEM-encoded CA bundle that signed the server cert. Loaded into `*tls.Config.RootCAs` on the agent's HTTP client. If unset, the agent falls back to the OS system trust store.
- `CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY` — defaults to `false`. Setting it to `true` skips verification entirely. **Dev-only escape hatch.** The agent logs a prominent warning at startup (`TLS certificate verification is disabled … never enable this in production`). Use this only when dialing a demo server whose cert you haven't bothered to mount into the agent container.

Equivalent CLI flags: `--ca-bundle <path>` and `--insecure-skip-verify`.

If both the CA bundle and `InsecureSkipVerify=true` are set, `InsecureSkipVerify` wins — it's the whole point of the flag. Don't do this in production.

### CLI (`certctl-cli`)

Same contract as the agent:

- `CERTCTL_SERVER_URL` defaults to `https://` scheme; `http://` rejected at startup
- `--ca-bundle <path>` flag or `CERTCTL_SERVER_CA_BUNDLE_PATH` env var — CA bundle for server cert verification
- `--insecure` flag or `CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY=true` — skip verification (dev only)
- Error diagnostic on empty URL explicitly mentions both `--server` and `CERTCTL_SERVER_URL` so operators see the right knob to turn

The CLI shares the URL-scheme validation with the agent; the test pins in `cmd/cli/main_test.go:TestValidateHTTPSScheme` cover the full rejection matrix.

### MCP server (`certctl-mcp-server`)

Same three controls as CLI, env-var-driven only (no flags — MCP runs as a stdio subprocess and inherits env from the launching LLM client):

- `CERTCTL_SERVER_URL` must start with `https://`
- `CERTCTL_SERVER_CA_BUNDLE_PATH` optional CA bundle
- `CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY` optional skip

Claude Desktop / other MCP client configs should set all three in the tool's env block.

## Troubleshooting: fail-loud preflight errors

Every preflight failure message ends with `(see docs/tls.md)` so this doc is the first hit when an operator searches. Common failures:

**`CERTCTL_SERVER_TLS_CERT_PATH is empty: HTTPS-only control plane refuses to start`**
Set the env var. For docker-compose this is already set to `/etc/certctl/tls/server.crt` in the shipped compose file — if you're seeing this, check the `certctl-tls-init` service logs to see why the init container didn't populate the volume. For Helm, check that `server.tls.existingSecret` or `server.tls.certManager.enabled=true` is set.

**`TLS cert file "…" unreadable: …`**
The cert path is set but `os.Stat` failed. Check filesystem permissions — the server runs as UID 1000 in our shipped Dockerfile; the cert needs to be readable by that UID. Typos in the path also land here.

**`TLS cert/key pair invalid (cert="…" key="…"): …`**
Both files exist but `tls.LoadX509KeyPair` refused them. Typical causes: the private key does not sign the certificate, the key is encrypted with a passphrase (not supported — remove the passphrase with `openssl pkey` before mounting), or one of the two is DER-encoded instead of PEM. Re-issue the pair from the same CA call and re-mount.

**Client side: `tls: failed to verify certificate: x509: certificate signed by unknown authority`**
The client did not trust the CA that signed the server cert. Either mount the CA bundle via `CERTCTL_SERVER_CA_BUNDLE_PATH`, add the CA to the system trust store on the client host, or (dev only) set `CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY=true`.

**Client side: `tls: first record does not look like a TLS handshake`**
The client is speaking plaintext HTTP to an HTTPS server (or vice-versa). Check that `CERTCTL_SERVER_URL` starts with `https://`. If you are upgrading from a pre-v2.2 release and your agents are old, they will surface this error until you roll the DaemonSet — see [`upgrade-to-tls.md`](../archive/upgrades/to-tls-v2.2.md).

## InsecureSkipVerify justifications (Audit L-001)

`crypto/tls.Config.InsecureSkipVerify` short-circuits standard certificate
chain validation. Each production use site below has a justification —
the shape is "this code path is fundamentally pre-trust or
trust-from-context, and chain validation in the stdlib path is not the
right tool". Test-only sites are not enumerated here.

The CI grep guard `Forbidden bare InsecureSkipVerify regression guard
(L-001)` in `.github/workflows/ci.yml` fails the build if any new
`InsecureSkipVerify: true` lands in a non-test file without a
`//nolint:gosec` comment carrying a justification — adding a new entry
to this table is the right way to extend the surface.

| Site (file:line) | Trigger | Justification |
|---|---|---|
| `cmd/agent/main.go:59,125,136,1259,1262` | `--insecure-skip-verify` CLI flag | Dev escape hatch; docs/tls.md and the agent install script direct operators to use a real CA bundle in production. The server emits a startup WARN when set. |
| `cmd/agent/verify.go:70,78` | TLS deployment verification probe | The agent is verifying that its own freshly-deployed cert is being served. The chain may be self-signed or signed by an upstream the agent host doesn't trust; what matters is the leaf-cert match against what the agent just deployed. The verifier compares the served leaf bytes to the expected leaf, not the chain. |
| `internal/tlsprobe/probe.go:33,47,54` | Network scanner / discovery probe | Discovery's job is to find every cert on the network, including expired, self-signed, and not-yet-deployed certs. Validating the chain would silently skip the broken-cert results that are precisely what operators want to know about. |
| `internal/mcp/client.go:35` | MCP CLI `--insecure` flag | Dev escape hatch for local-only MCP testing against a self-signed control plane. |
| `internal/cli/client.go:39` | `certctl --insecure` flag | Same shape as the agent flag — local dev only. |
| `internal/connector/target/f5/f5.go:128` | F5 BIG-IP iControl REST | F5 default install ships with a self-signed cert; operators who haven't replaced it use `config.Insecure`. The connector logs this on every dial and the operator-facing config docs this. |
| `internal/connector/issuer/acme/acme.go:146` | Pebble (ACME test server) | Hard-coded for tests that drive against Pebble locally. Pebble issues self-signed; verifying the chain would defeat the purpose. |
| `internal/service/network_scan.go:460` | Network scanner probe | Same rationale as `tlsprobe/probe.go` above — discovery surfaces broken certs by design. |
| `internal/api/acme/validators.go` (TLS-ALPN-01 validator) | RFC 8737 §3 TLS-ALPN-01 challenge validation | RFC 8737 mandates this: the responding TLS server presents a self-signed cert with the proof embedded in the `id-pe-acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31). The chain is intentionally NOT validated — the proof is in the extension's SHA-256 of the key authorization, not the cert chain. Validating the chain would defeat the purpose: clients running TLS-ALPN-01 self-sign their challenge cert specifically because they don't have a trusted cert yet (that's what they're trying to obtain via ACME). The validator additionally checks that ALPN negotiated `acme-tls/1` and that the cert's `id-pe-acmeIdentifier` extension value is exactly SHA-256 of the expected key authorization. SSRF posture: the validator runs `validation.IsReservedIPForDial` against the resolved IP before the dial, refusing any private-IP target — same posture as the HTTP-01 validator. |

**What is NOT covered by this list:** `*_test.go` files use
`InsecureSkipVerify` freely against `httptest.Server` instances; that's a
test-fixture pattern, not a production trust decision. The grep guard
ignores `_test.go`.

## Related docs

- [`upgrade-to-tls.md`](../archive/upgrades/to-tls-v2.2.md) — one-step cutover from pre-HTTPS releases
- [`quickstart.md`](../getting-started/quickstart.md) — docker-compose walkthrough with HTTPS examples
- [`test-env.md`](../contributor/test-environment.md) — integration test environment (also HTTPS-only)
- [`security.md`](security.md) — overall security posture, OCSP Must-Staple guidance, encryption-at-rest spec
- Milestone spec: `prompts/https-everywhere-milestone.md` (authoritative source for locked decisions)
