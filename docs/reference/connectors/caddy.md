# Caddy Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the Caddy target connector. For
> the connector-development context (interface contract, registry,
> atomic deploy primitive shared across all targets), see the
> [connector index](index.md).

## Overview

The Caddy connector supports two deployment modes:

- **API mode (recommended).** Posts the certificate directly to
  Caddy's admin API for zero-downtime hot reload.
- **File mode (fallback).** Writes cert and key files to disk,
  relying on Caddy's built-in file watcher or a manual reload.

Implementation lives at `internal/connector/target/caddy/`.

## When to use this connector

Use the Caddy connector when:

- Caddy fronts your services and you want certctl-managed certs
  rather than letting Caddy run its own ACME client.
- You want zero-downtime hot reload via Caddy's admin API.

Look elsewhere when:

- You'd rather Caddy keep running its own ACME client — point it
  at certctl's ACME server (see
  [migration/acme-from-caddy.md](../../migration/acme-from-caddy.md))
  for the cleanest pattern.

## Configuration

```json
{
  "mode": "api",
  "admin_api": "http://localhost:2019",
  "cert_dir": "/etc/caddy/certs",
  "cert_file": "site.crt",
  "key_file": "site.key"
}
```

When `mode` is `"api"`, the connector posts the certificate to
the admin API endpoint. When `mode` is `"file"`, it writes files
to `cert_dir` (same pattern as Traefik). The `admin_api` field is
ignored in file mode.

## Mode trade-offs

### API mode

- Zero-downtime hot reload via `POST /load` or
  certificate-specific endpoints.
- Requires Caddy's admin API to be enabled and reachable from the
  deployment agent.
- Best fit for production deployments where Caddy is configured
  with an admin endpoint.

### File mode

- Writes cert and key files to `cert_dir`; Caddy picks them up
  via its file watcher or on next config reload.
- Use when the admin API isn't available or when Caddy is
  configured to read certificates from disk.
- Behaviorally equivalent to the [Traefik](traefik.md) connector.

## Deploy contract

API mode bypasses the Bundle I file-write deploy primitive and
talks directly to the Caddy admin API. File mode follows the
standard atomic-write + verify path (idempotency check → backup
→ atomic write → optional reload → post-deploy TLS verify).

## Operator playbook

### Admin API exposure

Caddy's admin API is an unauthenticated control surface by
default. In API mode, ensure the admin API is bound to a
loopback or trusted network — exposing it to the public would
let anyone reload Caddy's config. Run the agent on the same host
as Caddy and use `http://localhost:2019` for the safest posture.

### Falling back to file mode

If the admin API is intermittently unreachable, switch the
target's `mode` to `file` via `PUT /api/v1/targets/{id}`. The
deploy still lands; reload behaviour is whatever the operator's
Caddy config does with file changes.

## Related docs

- [Connector index](index.md) — interface contract, registry, deploy primitive
- [Traefik](traefik.md) — comparable file-provider target
- [Migration: point Caddy at certctl's ACME](../../migration/acme-from-caddy.md) — alternative pattern when Caddy should keep its ACME client
