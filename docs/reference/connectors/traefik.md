# Traefik Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the Traefik target connector.
> For the connector-development context (interface contract,
> registry, atomic deploy primitive shared across all targets), see
> the [connector index](index.md).

## Overview

The Traefik connector uses Traefik's **file provider** — it writes
certificate and key files to a watched directory, and Traefik
automatically picks up the changes without any explicit reload
command. This is the simplest deployment model in the catalog:
write the files, Traefik does the rest.

Implementation lives at `internal/connector/target/traefik/`.

## When to use this connector

Use the Traefik connector when:

- Traefik fronts your services with the file provider configured
  (`providers.file.directory` in Traefik's static config).
- You want a no-reload deployment path — Traefik picks up file
  changes automatically.

Look elsewhere when:

- You're running Traefik with its built-in ACME client. Either
  point Traefik at certctl's ACME server (see
  [migration/acme-from-traefik.md](../../migration/acme-from-traefik.md))
  or let certctl-issued certs flow through this file-provider
  connector — but don't run both.
- Traefik is not exposed (e.g. behind another reverse proxy that
  terminates TLS); the front-most TLS terminator is what wants
  the cert.

## Configuration

```json
{
  "cert_dir": "/etc/traefik/certs",
  "cert_file": "site.crt",
  "key_file": "site.key"
}
```

The `cert_dir` is the directory Traefik is configured to watch
via its file provider. The connector writes `cert_file` and
`key_file` into this directory with appropriate permissions
(0644 for the cert, 0600 for the key). Traefik's file watcher
detects the change and reloads the TLS configuration
automatically.

## Deploy contract

Every cert deploy follows the Bundle I `deploy.Apply(ctx, plan)`
flow:

1. Idempotency check on cert + key bytes.
2. Pre-deploy backup of existing files.
3. Atomic write of cert + key to temp paths.
4. Atomic rename of temp paths to final cert / key paths.
5. **No reload command** — Traefik's file watcher handles it.
6. Post-deploy TLS verify when configured (dials the endpoint;
   pulls leaf cert SHA-256; compares).

The validate / reload / rollback semantics that NGINX and HAProxy
depend on don't apply here — Traefik's file watcher is the
"reload"; if Traefik fails to load the new file, that's a Traefik
problem visible in Traefik's logs, and the previous cert remains
served until Traefik retries.

## Operator playbook

### File watcher latency

Traefik's file watcher polls the directory; the cert may take a
few seconds to be picked up after the atomic rename. Post-deploy
verify with `PostDeployVerifyAttempts: 5` and a small backoff
covers this comfortably.

### Multi-router deployments

Traefik routes traffic by hostname, and the file provider can
expose multiple certs in the same directory. Configure one
certctl target per cert (one `cert_file` + `key_file` pair per
hostname); they all land in the same watched directory and
Traefik picks them up.

### Mixing file provider with ACME

If Traefik is also running its own ACME client, both can write to
the same `certificatesResolvers` config but with different
storage backends. Best practice: don't mix. Pick one source of
truth — either Traefik's ACME or certctl-supplied files — and
delete the other config block from `traefik.yml`.

## Related docs

- [Connector index](index.md) — interface contract, registry, deploy primitive
- [NGINX](nginx.md) — explicit-reload deploy contract counterpart
- [Migration: point Traefik at certctl's ACME](../../migration/acme-from-traefik.md) — alternative pattern when Traefik should pull rather than have certctl push
