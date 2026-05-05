# Envoy Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the Envoy target connector. For
> the connector-development context (interface contract, registry,
> atomic deploy primitive shared across all targets), see the
> [connector index](index.md).

## Overview

The Envoy connector uses **file-based certificate delivery** — it
writes certificate and key files to a directory that Envoy watches
via its SDS (Secret Discovery Service) file-based configuration or
static `filename` references in the bootstrap config. When files
change, Envoy automatically picks up the new certificates without
requiring a reload command.

Implementation lives at `internal/connector/target/envoy/`.

## When to use this connector

Use the Envoy connector when:

- Envoy fronts your services (standalone, as part of a service
  mesh, or as an API gateway like Emissary or Gloo).
- You want certctl to drive cert rotation and let Envoy's file
  SDS handle the rolling reload across worker threads.

Look elsewhere when:

- You're running an Envoy-based service mesh (Istio, Consul
  Connect) — those meshes have their own cert distribution
  pipelines, and integrating certctl at the mesh layer is a
  different design than this connector covers.
- You're using Envoy's xDS/gRPC SDS path (not file-based SDS) —
  the gRPC SDS-server connector is on the V3-Pro roadmap.

## Configuration

```json
{
  "cert_dir": "/etc/envoy/certs",
  "cert_filename": "cert.pem",
  "key_filename": "key.pem",
  "chain_filename": "chain.pem",
  "sds_config": true
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `cert_dir` | string | (required) | Directory where Envoy watches for certificate files |
| `cert_filename` | string | `cert.pem` | Filename for the certificate (leaf + chain unless `chain_filename` is set) |
| `key_filename` | string | `key.pem` | Filename for the private key |
| `chain_filename` | string | (empty) | If set, chain is written to a separate file instead of appended to the cert |
| `sds_config` | bool | `false` | If true, writes an `sds.json` file for Envoy's file-based SDS provider |

## SDS mode (recommended for production)

When `sds_config` is `true`, the connector writes an SDS JSON
file (`{cert_dir}/sds.json`) containing a `tls_certificate`
resource that points to the cert and key file paths. Envoy's
file-based SDS (`path_config_source`) watches this file for
changes, providing automatic hot-reload of certificates without
restarting worker threads.

This is the recommended approach for production Envoy deployments
using dynamic TLS configuration.

## Static-bootstrap mode

When `sds_config` is `false` (the default), the connector simply
writes cert and key files. Use this mode when Envoy's bootstrap
config references the cert / key files directly via static
`filename` fields in the TLS context.

In this mode Envoy still picks up file changes via its filesystem
watcher, but the operator should verify the bootstrap config sets
`watched_directory` (or equivalent) on each `tls_certificate`
entry — without it, the cert is loaded once at startup and
subsequent file changes are ignored.

## Deploy contract

Standard atomic-write + post-deploy verify (file-based deploy
primitive shared across all file-deploy connectors). When SDS
mode is on, the SDS JSON file is updated last so Envoy sees the
cert / key on disk before the SDS resource pointer changes.

## Operator playbook

### Hot-reload across worker threads

Envoy's file SDS path triggers a per-worker-thread reload as each
worker re-reads the SDS file. In-flight TLS connections on each
worker continue with the OLD cert until they close; new
connections after the reload pick up the NEW cert.

### Service mesh interactions

If you're running Istio or Consul Connect, the mesh's own cert
distribution pipeline (citadel / SDS server) is the system of
record for sidecar certs. Don't point this connector at sidecar
cert paths — point it at standalone Envoy gateways or API edges
that aren't sidecar-managed.

## Related docs

- [Connector index](index.md) — interface contract, registry, deploy primitive
- [NGINX](nginx.md) — explicit-reload-command counterpart
- [Traefik](traefik.md) — file-watcher counterpart with simpler semantics
