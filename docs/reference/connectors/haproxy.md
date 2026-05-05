# HAProxy Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the HAProxy target connector.
> For the connector-development context (interface contract,
> registry, atomic deploy primitive shared across all targets), see
> the [connector index](index.md).

## Overview

HAProxy differs from NGINX and Apache in one important way: it
expects all TLS material in a **single combined PEM file** —
certificate, intermediate chain, and private key concatenated. The
connector builds this combined file, writes it with 0600
permissions (since it contains the private key), optionally
validates the HAProxy configuration, and reloads.

Implementation lives at `internal/connector/target/haproxy/`.

## When to use this connector

Use the HAProxy connector when:

- HAProxy fronts your applications and you want certctl to
  rotate the cert + chain + key in place atomically without
  hand-rolling the combined-PEM build.
- You want validate-before-reload behaviour to keep a bad config
  from taking down the load balancer mid-rotation.

Look elsewhere when:

- You're running HAProxy Enterprise's hot-cert-update API path —
  the connector currently uses the file-write-and-reload model;
  the API path is on the V3-Pro roadmap.
- You're not running HAProxy directly but a managed load balancer
  (AWS ALB, Azure Application Gateway). Use the cloud-native
  target connector for that platform instead.

## Configuration

```json
{
  "pem_path": "/etc/haproxy/certs/site.pem",
  "reload_command": "systemctl reload haproxy",
  "validate_command": "haproxy -c -f /etc/haproxy/haproxy.cfg"
}
```

The combined PEM is built in this order: server certificate,
intermediate / chain certificates, private key.

The `validate_command` is optional — if omitted, the connector
skips config validation and goes straight to reload. Keeping it
on is the production-recommended posture.

## Deploy contract

Every cert deploy follows the Bundle I `deploy.Apply(ctx, plan)`
flow:

1. **Idempotency check** — SHA-256 over the combined PEM bytes;
   skip if the destination already matches.
2. **Pre-deploy backup** — copy existing PEM to
   `<pem_path>.certctl-bak.<unix-nanos>`.
3. **Atomic write** — temp-file + chown + atomic rename.
4. **PreCommit (validate)** — runs `haproxy -c -f
   /etc/haproxy/haproxy.cfg`. Failure aborts; no live cert
   touched.
5. **Atomic rename** — temp → final.
6. **PostCommit (reload)** — runs `systemctl reload haproxy` (or
   the operator's override).
7. **Post-deploy TLS verify** — dials the configured endpoint
   when configured; pulls leaf cert SHA-256; compares against
   deployed bytes. Mismatch triggers automatic rollback.

## Operator playbook

### Old cert served via session resumption

HAProxy keeps TLS sessions alive for the configured
`tune.ssl.lifetime` (default 1h). Resumed clients see the OLD
cert until their session expires. Post-deploy verify in certctl
returns the NEW cert from a fresh handshake; warm clients see the
OLD cert until session expiration.

### Multi-frontend deployments

When HAProxy serves multiple frontends with different certs,
configure **one target per frontend's cert** in the certctl
control plane. Each gets its own `pem_path`. The reload command
is shared (HAProxy reloads all frontends together), so the
deploys can land in any order; the final reload picks them all up.

### `crt-list` directories

If your HAProxy config uses a `crt-list` directory rather than a
single PEM, set `pem_path` to a file inside the directory and let
HAProxy enumerate it on reload. The connector treats `pem_path`
as a single file regardless of HAProxy's directory semantics.

## Related docs

- [Connector index](index.md) — interface contract, registry, deploy primitive
- [NGINX](nginx.md) — separate-file deploy contract counterpart
- [Apache](apache.md) — separate-file deploy contract with `apachectl configtest`
- [Migration: ACME from HAProxy](../../migration/acme-from-caddy.md) — pattern for pointing edge proxies at certctl's ACME server (Caddy walkthrough; HAProxy ACME plumbing is similar)
