# Upgrading to HTTPS-Everywhere (v2.2)

certctl's control plane is HTTPS-only as of v2.2. There is no `http` mode, no `auto` mode, no dual-listener bind, no N-release migration window. The cutover is a single step. Out-of-date agents that still point at `http://…` fail at the TCP/TLS handshake layer on first connect after the upgrade and stay `Offline` in the dashboard until their env block is updated and the fleet is rolled.

This doc walks operators through the cutover for the two shipped deployment topologies — docker-compose and Helm — and documents the failure modes and rollback posture explicitly.

For the deep-dive on cert provisioning patterns, SIGHUP cert reload, and client-side CA-trust configuration, read [`tls.md`](tls.md). This doc is the narrow "how do I upgrade" procedure.

## Preconditions

Before you start, confirm:

- **Shell access** to the server host and every agent host. The cutover requires you to restart the server and update every agent's env block.
- **A cert+key source** for the server. Pick one:
  - An internal CA that can issue a server cert (CN + SAN list covering every hostname / IP agents dial).
  - A `cert-manager` install in the target Kubernetes cluster, plus a `ClusterIssuer` or `Issuer` you're willing to reference.
  - Willingness to use the self-signed bootstrap that the shipped `deploy/docker-compose.yml` generates automatically. This is the right choice for dev and demo; it is the wrong choice for production.
- **A maintenance window.** Out-of-date agents break at the TLS handshake and stay offline until rolled. Schedule the upgrade so the agent fleet can be updated in the same window as the server.
- **Backups.** This is a one-way door (see the Rollback section below). Snapshot your PostgreSQL database before `docker compose down` or `helm upgrade`.

There is no schema migration tied to this release; the only at-rest state that changes is the `certs` named volume (docker-compose) or the `tls.crt`/`tls.key` Secret (Helm).

## Procedure — docker-compose operators

The shipped `deploy/docker-compose.yml` includes a `certctl-tls-init` init container that self-signs an ed25519 cert on first boot and drops `server.crt`, `server.key`, and `ca.crt` into a named volume mounted read-only at `/etc/certctl/tls/` on the server and agent containers. No manual cert provisioning is required for the default stack.

1. **Pull the HTTPS-everywhere release.** From the repo root:

   ```
   git pull
   ```

   Confirm you're on a tag or `master` that contains the `certctl-tls-init` service in `deploy/docker-compose.yml`. Grep for it: `grep certctl-tls-init deploy/docker-compose.yml` should hit.

2. **Stop the old plaintext cluster.**

   ```
   docker compose -f deploy/docker-compose.yml down
   ```

   Do not pass `-v`; keeping the PostgreSQL volume preserves your cert inventory, audit trail, and job history across the upgrade.

3. **Bring the cluster back up with the HTTPS build.**

   ```
   docker compose -f deploy/docker-compose.yml up -d --build
   ```

   The `certctl-tls-init` service runs once, generates the self-signed cert into the `certs` volume, and exits with code 0. The server container waits for `certctl-tls-init` via `depends_on: { condition: service_completed_successfully }` and only starts once the cert material is on disk. The server's Docker healthcheck now uses `curl --cacert /etc/certctl/tls/ca.crt -f https://localhost:8443/health`, so the container only becomes healthy once the HTTPS listener is up and serving the bundled cert correctly.

4. **Verify the HTTPS endpoint from the host.**

   ```
   curl --cacert $(docker compose -f deploy/docker-compose.yml exec -T certctl-server cat /etc/certctl/tls/ca.crt) https://localhost:8443/health
   ```

   Expect `{"status":"ok"}` with HTTP 200. If you get a TLS verification error, the CA bundle wasn't read correctly — re-run the `exec -T` command and pipe the output directly into `--cacert @-` or save it to a local file first. If you get `connection refused`, the server never finished startup — check `docker compose logs certctl-server` for a fail-loud preflight diagnostic pointing at `docs/tls.md`.

5. **Confirm the bundled agent reconnects.** Agents inside the compose stack pick up the new URL (`CERTCTL_SERVER_URL=https://certctl-server:8443`) and the bundled CA (`CERTCTL_SERVER_CA_BUNDLE_PATH=/etc/certctl/tls/ca.crt`) from their env block automatically — no per-agent change needed. Tail the agent log:

   ```
   docker compose -f deploy/docker-compose.yml logs -f certctl-agent
   ```

   You should see `heartbeat sent` within 30 seconds. In the dashboard (`https://localhost:8443`), the agent should show as `Online`.

**External agents** running outside the compose network (e.g., the `install-agent.sh`-installed systemd service on a separate host) need their env block updated manually before the cutover — see the Agent env block section below.

## Procedure — Helm operators

The Helm chart does not self-sign. It refuses to render (`helm template` exits non-zero) unless you configure one of two cert sources: an operator-supplied Secret, or a cert-manager `Certificate` CR. See [`tls.md`](tls.md) for the full pattern catalog.

1. **Provision cert material.** Pick one of:

   - **Operator-supplied Secret.** Issue a cert from your internal CA (or any other source) and load it into a `kubernetes.io/tls` Secret in the certctl namespace:

     ```
     kubectl create secret tls certctl-server-tls \
       --cert=server.crt --key=server.key \
       --namespace certctl
     ```

   - **cert-manager.** Set `server.tls.certManager.enabled=true` on the upgrade and reference an existing `ClusterIssuer` or `Issuer`:

     ```
     --set server.tls.certManager.enabled=true
     --set server.tls.certManager.issuerRef.name=my-cluster-issuer
     --set server.tls.certManager.issuerRef.kind=ClusterIssuer
     ```

2. **Upgrade the release.**

   ```
   helm upgrade certctl deploy/helm/certctl \
     --namespace certctl \
     --set server.tls.existingSecret=certctl-server-tls
   ```

   (Or the `certManager` variant.) If you omit both `server.tls.existingSecret` and `server.tls.certManager.enabled`, the chart fails at render time with a diagnostic pointing at `docs/tls.md`. That guard exists precisely so you catch the missing config at `helm upgrade` time, not at pod-crash-loop time.

3. **Verify the HTTPS endpoint from inside the cluster.** Port-forward and curl with the CA bundle:

   ```
   kubectl port-forward -n certctl svc/certctl-server 8443:8443 &
   kubectl get secret -n certctl certctl-server-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > /tmp/certctl-ca.crt
   curl --cacert /tmp/certctl-ca.crt https://localhost:8443/health
   ```

   Expect `{"status":"ok"}`. If the Secret does not contain a `ca.crt` key (operator-supplied Secrets often don't), use `tls.crt` as the bundle instead — for a self-signed cert the two files are identical, and for a cert chained to an internal CA you should separately distribute the root CA bundle via ConfigMap or mounted file.

4. **Update every agent manifest.** Agents outside this Helm release (or in a separately-managed DaemonSet) need their env block updated:

   ```
   - name: CERTCTL_SERVER_URL
     value: "https://certctl-server.certctl.svc.cluster.local:8443"
   - name: CERTCTL_SERVER_CA_BUNDLE_PATH
     value: "/etc/certctl/tls/ca.crt"
   ```

   Mount the server's Secret (or a separate CA-bundle Secret / ConfigMap) at `/etc/certctl/tls/` as a read-only volume. If you bundle the agent via the shipped Helm chart's DaemonSet, the wiring is already done — set `agent.enabled=true` and the chart mounts the same Secret.

5. **Roll the agent DaemonSet.**

   ```
   kubectl rollout restart ds/certctl-agent -n certctl
   kubectl rollout status ds/certctl-agent -n certctl
   ```

   Every agent pod restarts with the new URL + CA bundle and reconnects on HTTPS. The dashboard shows agents flip from `Offline` to `Online` as pods finish rolling.

## Agent env block — external hosts

Agents installed on bare-metal or VM hosts via `install-agent.sh` (systemd on Linux, launchd on macOS) read config from `/etc/certctl/agent.env` (Linux) or `~/Library/Application Support/certctl/agent.env` (macOS). On cutover, append or update:

```
CERTCTL_SERVER_URL=https://certctl.example.com:8443
CERTCTL_SERVER_CA_BUNDLE_PATH=/etc/certctl/tls/ca.crt
# CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY=false    # Dev only. Never set to true in production.
```

Distribute the CA bundle (the same `ca.crt` the server holds, or the root chain if you issued the server cert from an intermediate) to every agent host. The path under `CERTCTL_SERVER_CA_BUNDLE_PATH` must be readable by the UID the agent service runs as.

Restart the service after editing:

- Linux: `systemctl restart certctl-agent`
- macOS: `launchctl kickstart -k system/com.certctl.agent`

The agent refuses to start on an `http://` URL and exits with a pre-flight diagnostic that names this doc. That rejection happens before any network call — no spurious half-connected state.

## Failure mode

Out-of-date agents still configured with `CERTCTL_SERVER_URL=http://…` fail on first reconnect after the cutover. The failure surfaces as one of:

- `dial tcp …: connect: connection refused` — the server is no longer listening on a plaintext port. The new release binds only a TLS listener; attempting a plaintext `connect()` gets refused at the kernel level because nothing holds the socket.
- `tls: first record does not look like a TLS handshake` — depending on timing and proxy layers (e.g., a load balancer that accepts the TCP connection before forwarding), the client may negotiate TCP, send an HTTP request line, and have the server's TLS stack reject it.

Agents in this state surface as `Offline` in the dashboard. They stay offline until their env block is updated and the service restarts. There is no graceful 400-with-migration-URL response because there is no HTTP listener to serve one from — the entire plaintext call path is removed by design.

If you see an unexpected agent stay `Offline` past the cutover window, SSH to the host and check the agent log. On a systemd host:

```
journalctl -u certctl-agent -n 100
```

Look for `URL scheme "http" is not supported: HTTPS-only control plane refuses to start (see docs/upgrade-to-tls.md)`. That's the pre-flight rejection. Update `CERTCTL_SERVER_URL`, restart the service, and the agent reconnects.

## Rollback

**There is no rollback window.** The upgrade is a one-way door. The rationale lives in §3.7 of `prompts/https-everywhere-milestone.md`: a cert-lifecycle product that bridges back to plaintext after committing to HTTPS is advertising that its own security posture is negotiable.

If you need to revert, you have two options:

1. **Stay on the pre-HTTPS release.** Do not upgrade until you are ready to run HTTPS on the control plane. Pin your `docker-compose.yml` or `helm upgrade` command to the last pre-v2.2 tag.
2. **Rollback the release.** `helm rollback certctl <previous-revision>` or `git checkout <previous-tag> && docker compose up -d --build`. This rolls back the server, the compose topology, and the Helm chart in lockstep. Your PostgreSQL volume — cert inventory, audit trail, jobs — survives the rollback; nothing in this milestone changes the database schema.

Option 2 drops you back to the plaintext world. It should be treated as an emergency measure, not a supported migration path.

## After the cutover

Once every agent is `Online`, confirm a few invariants:

- `curl -sS -o /dev/null -w "%{http_code}\n" http://localhost:8443/health` returns `000` with `Connection refused` (no HTTP listener). Plaintext is gone.
- `openssl s_client -connect localhost:8443 -tls1_2 </dev/null` fails the handshake. TLS 1.2 is rejected.
- `openssl s_client -connect localhost:8443 -tls1_3 </dev/null` succeeds and prints the server's SAN list. TLS 1.3 is live.
- A cert rotation test: overwrite the server cert on disk, `kill -HUP` the server PID, confirm the new cert serves on the next `openssl s_client -connect … -showcerts` without a process restart. See the SIGHUP section in [`tls.md`](tls.md).

Update your runbooks. Every `http://certctl.example.com` URL in internal documentation, monitoring config, and on-call playbooks should become `https://certctl.example.com` plus a CA-trust note.

## Related docs

- [`tls.md`](tls.md) — cert provisioning patterns, SIGHUP rotation, troubleshooting
- [`quickstart.md`](quickstart.md) — docker-compose walkthrough (post-HTTPS)
- [`test-env.md`](test-env.md) — integration test environment (HTTPS-only)
- Milestone spec: `prompts/https-everywhere-milestone.md`
