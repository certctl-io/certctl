# Deployment Atomicity, Post-Deploy Verification, and Rollback

> Deploy-hardening I master bundle (v2.X.0). Operator + integrator
> reference for the atomic-write + post-deploy TLS verify +
> rollback pipeline that closes the procurement-checklist gap with
> commercial competitors (Venafi, DigiCert Certificate Manager,
> Sectigo).

## 1. Overview

Before deploy-hardening I, certctl's target connectors used
duplicated `os.WriteFile` flows. A failure mid-deploy could leave
a target with a renewed cert but no chain (or vice versa); a
reload-fail produced a half-deployed state that required manual
rollback; a wrong-vhost cert was silent until users reported it.

Deploy-hardening I closes three procurement-checklist gaps in
a single shared primitive:

| Gap | Pre-bundle | Post-bundle |
|---|---|---|
| **Atomic deploy with rollback** | F5 only (transactional API) | All 13 connectors via `deploy.Apply` |
| **Post-deploy TLS verification** | None | NGINX/Apache/HAProxy/Traefik/Caddy/Envoy/Postfix all do TLS handshake + SHA-256 fingerprint compare; fail → rollback |
| **Vendor-specific deployment recipes** | Light docs | (Bundle II — `cowork/deploy-hardening-ii-prompt.md`) |

This document describes the operator-visible surface. The Go-level
contract lives at `internal/deploy/doc.go`.

## 2. The atomic-write primitive — `Plan` / `Apply`

`internal/deploy.Apply(ctx, plan)` is the load-bearing entry
point. Connectors build a `Plan` describing one or more files +
their PreCommit (validate) and PostCommit (reload) hooks; Apply
executes them all-or-nothing.

```go
plan := deploy.Plan{
    Files: []deploy.File{
        {Path: "/etc/nginx/certs/cert.pem", Bytes: certPEM, Mode: 0644},
        {Path: "/etc/nginx/certs/chain.pem", Bytes: chainPEM, Mode: 0644},
        {Path: "/etc/nginx/certs/key.pem",   Bytes: keyPEM,   Mode: 0640},
    },
    PreCommit: func(ctx context.Context, tempPaths map[string]string) error {
        // Run `nginx -t` against the staged config — bytes already
        // written to <path>.certctl-tmp.<unix-nanos>.
        return runValidate(ctx, "nginx -t")
    },
    PostCommit: func(ctx context.Context) error {
        return runReload(ctx, "nginx -s reload")
    },
}
res, err := deploy.Apply(ctx, plan)
```

Apply's algorithm:

1. Per-file mutex acquired (sync.Map; coarse-grained per-path
   serialization).
2. SHA-256 idempotency short-circuit. If every File's destination
   already matches, return `Result.SkippedAsIdempotent=true`
   without firing PreCommit/PostCommit.
3. Pre-deploy backup: copy each existing destination to
   `<path>.certctl-bak.<unix-nanos>`.
4. Write each File's bytes to `<path>.certctl-tmp.<unix-nanos>`
   in the destination directory (same-filesystem rename).
5. Apply ownership (chown + chmod) to each temp file BEFORE
   rename so the swap is atomic with the right perms.
6. Call `PreCommit(ctx, tempPaths)`. On error: clean up temps;
   return `ErrValidateFailed`.
7. `os.Rename` each temp → final. POSIX guarantees atomic.
8. Call `PostCommit(ctx)`. On error: restore each backup; re-call
   PostCommit. If second PostCommit also fails: return
   `ErrRollbackFailed` (operator-actionable).
9. Janitor: prune backups beyond `Plan.BackupRetention`
   (default 3, -1 to disable).

## 3. Per-connector atomic contract

| Connector | PreCommit (validate) | PostCommit (reload) | Post-deploy verify | Quirks |
|---|---|---|---|---|
| nginx | `nginx -t` | `nginx -s reload` | TLS handshake to `host:443` | Default key mode 0640 (worker reads via group) |
| apache | `apachectl configtest` | `apachectl graceful` | TLS handshake | Default key mode 0600; per-distro user (apache2/apache/httpd) |
| haproxy | `haproxy -c -f <cfg>` | `systemctl reload haproxy` | TLS handshake | Combined PEM (cert+chain+key in one file); default mode 0600 |
| traefik | (none — file watcher) | (none — file watcher auto-reloads) | TLS handshake | atomic-write only; ValidateOnly returns sentinel |
| caddy (file mode) | (none) | (none — file watcher) | TLS handshake | atomic-write replaces os.WriteFile |
| caddy (api mode) | Probe admin /config/ | POST /load (already atomic at admin server) | (admin server confirms) | ValidateOnly real impl probes admin API |
| envoy | (none — SDS file watcher) | (none — SDS file watcher) | TLS handshake | atomic-write replaces os.WriteFile |
| postfix | `postfix check` | `postfix reload` | TLS handshake to port 25 | Chain appended to cert if no ChainPath |
| dovecot | `doveconf -n` | `doveadm reload` | TLS handshake to port 993 | Same code path as postfix |
| f5 | (Authenticate probe) | (Transactional commit) | TLS handshake to VS | Already transactional; rollback automatic via failed commit |
| iis | (Get-WebSite probe) | (PowerShell cert install) | TLS handshake | Already explicit pre-deploy backup + post-rollback re-import |
| ssh | (Connect probe) | (SCP upload + remote chmod) | `tls.Dial` to remote TLS port | Pre-deploy SCP backup of remote files |
| wincertstore | (Get-ChildItem Cert:\) | (Import-PfxCertificate) | (admin probe) | Get-ChildItem snapshot for rollback |
| javakeystore | (`keytool -list`) | (`keytool -importkeystore`) | (admin probe) | keytool snapshot; rollback via `keytool -delete` + re-import |
| k8ssecret | (GetSecret RBAC probe) | (Update Secret) | SHA-256 verify of returned Secret | Atomic at API server; kubelet sync polled via `Pod.Status.ContainerStatuses` |

## 4. Post-deploy TLS verification

Frozen decision 0.3 (deploy-hardening I): post-deploy verify is
**ON by default** when the operator configures
`PostDeployVerify.Endpoint`. Per-target opt-out via
`PostDeployVerify.Enabled = false`.

The connector-side flow:

```go
// After Apply returns successfully, the connector dials the
// configured endpoint, pulls the leaf cert SHA-256, and compares.
res := tlsprobe.ProbeTLS(ctx, "nginx-test:443", 10*time.Second)
if res.Fingerprint != certPEMToFingerprint(deployedCertPEM) {
    // Mismatch — wrong vhost, NGINX serving cached cert,
    // load-balanced target hit a different pod, etc.
    rollbackToBackups(ctx, applyResult.BackupPaths)
    emitAlert("post-deploy verify SHA-256 mismatch")
}
```

Retry with backoff (default 3 attempts, 2s exponential) defends
against load-balanced targets where the verify might hit a
different pod that hasn't picked up the new cert yet:

```yaml
post_deploy_verify:
  enabled: true
  endpoint: "nginx.svc.cluster.local:443"
  timeout: 10s
post_deploy_verify_attempts: 3
post_deploy_verify_backoff: 2s
```

## 5. Rollback semantics

Rollback fires automatically on three triggers:

1. **PostCommit (reload) fails** → Apply restores backups + retries
   reload. Returns `ErrReloadFailed` on success (degraded
   no-op) or `ErrRollbackFailed` if the second reload also fails.
2. **Post-deploy verify fails** → Connector manually triggers
   rollback (Apply already returned successfully). Backups are
   restored + reload is invoked again. Same escalation path on
   second failure.
3. **Mid-loop rename fails** (rare; only with cross-filesystem
   misuse) → Apply rolls back the renames that already
   succeeded.

`ErrRollbackFailed` is operator-actionable. The destination is in
a known-bad state; operators must either:
- Restore from `Result.BackupPaths` manually + run `<reload command>`
- Push a fresh known-good cert via the next deploy cycle

The `certctl_deploy_rollback_total{outcome="also_failed"}` metric
is the alert target.

## 6. ValidateOnly — dry-run mode

`target.Connector.ValidateOnly(ctx, request)` runs the validate
step without touching the live cert. Connectors that can't
dry-run (Traefik / Envoy / Caddy file mode) return
`target.ErrValidateOnlyNotSupported`.

| Connector | ValidateOnly |
|---|---|
| nginx | `nginx -t` |
| apache | `apachectl configtest` |
| haproxy | `haproxy -c -f <cfg>` |
| postfix/dovecot | `postfix check` / `doveconf -n` |
| caddy (api) | GET /config/ probe |
| caddy (file) / traefik / envoy | `ErrValidateOnlyNotSupported` |
| f5 | `client.Authenticate()` probe |
| iis | `Get-WebSite -Name <SiteName>` |
| ssh | `client.Connect()` probe |
| wincertstore | `Get-ChildItem Cert:\<loc>\<store>` |
| javakeystore | `keytool -list -keystore <path>` |
| k8ssecret | `client.GetSecret()` RBAC probe |

Operators preview a deploy via the agent's `--dry-run` flag (or
the equivalent CLI invocation).

## 7. File ownership + mode preservation

The single most common silent-failure mode pre-bundle: agent runs
as root, calls `os.WriteFile(path, bytes, 0600)`, locks NGINX out
of the existing nginx:nginx 0640 key file.

Per frozen decision 0.7, `deploy.Apply` resolves ownership via
this precedence:

1. Explicit `File.Mode` / `File.Owner` / `File.Group` (per-target
   config) → use as given.
2. Existing destination file → preserve its `chown` + `chmod`.
3. `Plan.Defaults.Mode` / `.Owner` / `.Group` → use as fallback
   for new files.
4. Nothing set → `os.WriteFile` default (0644) for new files;
   preserved for existing.

Per-connector defaults (cross-distro, fall back to no-chown if
no candidate user exists):

| Connector | Default user | Default group | Default cert mode | Default key mode |
|---|---|---|---|---|
| nginx | nginx → www-data | nginx → www-data | 0644 | 0640 |
| apache | apache → www-data → httpd | same | 0644 | 0600 |
| haproxy | haproxy | haproxy | n/a (combined PEM) | 0600 |
| postfix | postfix → dovecot → _postfix | same | 0644 | 0600 |
| traefik | (none) | (none) | 0644 | 0600 |
| envoy | (none) | (none) | 0644 | 0600 |
| caddy | (none) | (none) | 0644 | 0600 |

## 8. Per-target deploy mutex

Phase 2 of the master bundle: the agent (`cmd/agent/main.go`)
serializes concurrent deploys to the same target ID via a
`sync.Map[targetID]*sync.Mutex`. Granularity per frozen decision
0.5: one mutex per target, NOT per (target, cert).

Cert deploy throughput is operator-grade tens-per-minute. Coarse
serialization is fine and simplifies reasoning about reload-side
race windows.

## 9. Idempotency via SHA-256

Every `deploy.Apply` short-circuits when all File destinations
already match SHA-256 of the new bytes. PreCommit + PostCommit do
not fire; backups are not created; the result reports
`SkippedAsIdempotent = true`.

Defends against agent-restart retry storms that would otherwise
hammer targets with no-op reloads. Operator-visible signal:
`certctl_deploy_idempotent_skip_total{target_type="..."}`.

## 10. Troubleshooting matrix

| Symptom | Root cause | Operator action |
|---|---|---|
| `ErrValidateFailed: nginx -t failed` | Validate command rejected the staged config | Read PreCommit's wrapped error for the nginx stderr; fix config |
| `ErrReloadFailed: nginx -s reload failed; rolled back` | Reload command failed; rollback succeeded; serving the OLD cert | Investigate why reload failed; re-deploy when fixed |
| `ErrRollbackFailed` | Reload AND rollback both failed; in known-bad state | Restore from `Result.BackupPaths` manually; run reload command directly; check disk space + ownership |
| `post-deploy TLS verify SHA-256 mismatch` | New cert deployed but a different cert is being served (cached, wrong vhost, stale pod in load balancer) | Check NGINX SSL session cache TTL; verify SNI; bump verify retries via `PostDeployVerifyAttempts` |
| `chown ... permission denied` (in agent log) | Non-root agent OR target user doesn't exist on host | Verify agent runs as root in production; check distro user (Debian: www-data, RHEL: nginx) |
| Backups accumulating in cert dir | BackupRetention misconfigured | Set `BackupRetention: 3` (default) or higher on per-target config |
| File world-readable after deploy | Default mode 0644 applied to new key file | Set explicit `KeyFileMode: 0640` (NGINX) or `KeyFileMode: 0600` (Apache) |

## 11. V3-Pro deferrals

Out of scope for the V2-free deploy-hardening I bundle:

- **Multi-region deployment coordination** — orchestration of N
  data-center deploys with operator approval gates per stage.
- **Cert-pinning verification against mobile-app pin manifests**.
- **SOC 2 evidence-report generator** — auto-export of the
  deploy audit trail in the format SOC 2 auditors expect.
- **Customer-paid validation matrices** — vendor-version certified
  quirks (e.g. "tested on F5 v15.1 + v17.0 + v17.5"). See
  `cowork/deploy-hardening-ii-prompt.md` for the per-vendor
  edge-case audit + integration test sidecars.

## 12. Per-connector quick reference

Paste-able config snippets for the most-used connectors. Full
field reference at `docs/connectors.md`.

### NGINX

```yaml
target_type: nginx
target_config:
  cert_path: /etc/nginx/certs/cert.pem
  chain_path: /etc/nginx/certs/chain.pem
  key_path: /etc/nginx/certs/key.pem
  reload_command: "nginx -s reload"
  validate_command: "nginx -t"
  cert_file_mode: 0644
  key_file_mode: 0640
  post_deploy_verify:
    enabled: true
    endpoint: "nginx.example.com:443"
    timeout: 10s
  backup_retention: 3
```

### HAProxy

```yaml
target_type: haproxy
target_config:
  pem_path: /etc/haproxy/certs/cert.pem
  reload_command: "systemctl reload haproxy"
  validate_command: "haproxy -c -f /etc/haproxy/haproxy.cfg"
  pem_file_mode: 0600
  post_deploy_verify:
    enabled: true
    endpoint: "haproxy.example.com:443"
```

### Traefik (file watcher; no reload command)

```yaml
target_type: traefik
target_config:
  cert_dir: /etc/traefik/certs
  cert_file: cert.pem
  key_file: key.pem
  post_deploy_verify:
    enabled: true
    endpoint: "traefik.example.com:443"
```

See per-connector tests at
`internal/connector/target/<name>/<name>_atomic_test.go` for the
full failure-mode matrix each connector handles.
