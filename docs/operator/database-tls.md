# Database TLS — Postgres Transport Encryption

> Last reviewed: 2026-05-05

**Audit reference:** Bundle B / M-018. CWE-319 (Cleartext transmission of sensitive information).

certctl talks to Postgres over a single connection-string URL controlled by the
`CERTCTL_DATABASE_URL` env var. The `sslmode` query parameter on that URL
selects the transport-encryption posture. Pre-Bundle-B all the bundled
deployment artifacts (Helm chart, docker-compose) hard-coded `sslmode=disable`.
Bundle B exposes that as an operator-facing knob with a documented default and
explicit opt-in / opt-out paths for the four real-world deployment shapes.

## Quick reference

| Deployment shape                               | Default `sslmode` | When to change |
|------------------------------------------------|--------------------|----------------|
| Helm chart, bundled Postgres, in-cluster       | `disable`          | When the cluster does not provide pod-network encryption (CNI without WireGuard / IPSec) and the workload handles sensitive data. |
| Helm chart, external Postgres (RDS / Cloud SQL / Azure DB) | not auto-set | **Always** set to `verify-full` and provide the cloud provider's server CA bundle. |
| docker-compose, bundled Postgres on docker bridge | `disable`        | Demo/dev only; not a deployment shape we expect operators to harden. |
| docker-compose / k8s with external Postgres    | not auto-set       | **Always** set `CERTCTL_DATABASE_URL` to a connection string with `sslmode=verify-full`. |

`sslmode` values come from `lib/pq` (the underlying driver). The full set is:
`disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`.
`verify-ca` is the floor for sensitive-data transport; `verify-full`
is the floor for systems exposed to spoofing risk (it adds hostname
validation against the server cert's CN/SAN).

## Helm chart (Bundle B)

Bundle B adds two values under `postgresql.tls`:

```yaml
postgresql:
  tls:
    mode: disable          # disable | require | verify-ca | verify-full
    caSecretRef: ""        # Secret with ca.crt key (required for verify-ca / verify-full)
```

The chart pipes `postgresql.tls.mode` into the `?sslmode=` parameter of the
generated `CERTCTL_DATABASE_URL` (see `templates/_helpers.tpl::certctl.databaseURL`).
For external Postgres, set `postgresql.enabled: false` and override
`server.env.CERTCTL_DATABASE_URL` directly with the full connection string —
the operator authoring an external-DB values file owns the entire URL.

### Example: external RDS with verify-full

```yaml
postgresql:
  enabled: false   # Disable bundled Postgres

server:
  env:
    CERTCTL_DATABASE_URL: |
      postgres://certctl:STRONGPW@my-db.cabc12345.us-east-1.rds.amazonaws.com:5432/certctl?sslmode=verify-full

# Provide the AWS RDS root CA bundle as a secret + mount.
# AWS publishes per-region root certs at https://truststore.pki.rds.amazonaws.com/
extraVolumes:
  - name: rds-ca
    secret:
      secretName: rds-ca-bundle  # kubectl create secret generic rds-ca-bundle --from-file=ca.crt=...

extraVolumeMounts:
  - name: rds-ca
    mountPath: /etc/postgresql-ca
    readOnly: true

# lib/pq honors PGSSLROOTCERT for the verify-{ca,full} CA bundle path.
server:
  env:
    PGSSLROOTCERT: /etc/postgresql-ca/ca.crt
```

## docker-compose (development / demo)

The bundled `deploy/docker-compose.yml` keeps `sslmode=disable` as the default
because the Postgres container shares the docker bridge network with the certctl
server and the compose file is not a production deployment artifact. To opt in:

```bash
export CERTCTL_DATABASE_URL='postgres://certctl:certctl@postgres:5432/certctl?sslmode=verify-full'
docker compose up
```

## Verification

For any non-`disable` mode, confirm the connection actually negotiated TLS:

```bash
# From inside the certctl-server container or any host with psql + the same URL:
psql "$CERTCTL_DATABASE_URL" -c "SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();"

# Expected output for verify-full: ssl=t, version=TLSv1.3 (or TLSv1.2), cipher=...
```

If `ssl=f` appears, the connection silently fell back to plaintext — investigate
the cert chain or sslmode value before treating the deployment as PCI-compliant.

## What this does NOT cover

* **Postgres-to-Postgres replication** — if you run a replica, replica-primary
  TLS is configured via the Postgres server itself (`pg_hba.conf` +
  `ssl=on`); it is independent of certctl's `CERTCTL_DATABASE_URL`.
* **Backup transport** — `pg_dump` / `pg_basebackup` honor the same `sslmode`
  parameter when invoked with the URL form, but the bundled chart's backup
  story (if any) is operator-owned.
* **Encryption at rest** — `sslmode` is a transport concern only. Disk
  encryption is the cloud provider's storage layer (RDS, EBS, etc.) or the
  operator's Postgres TDE / disk LUKS / etc.

## Reverting

If `sslmode=verify-full` causes connection failures (most common: missing CA
bundle, wrong hostname), drop temporarily to `sslmode=require` to confirm TLS
is at least negotiated, then add the CA bundle and ratchet back up. Never
revert to `sslmode=disable` on a system carrying real cert metadata —
audit_events alone contains enough operator/issuer/target identity to justify
TLS in any scoped environment.
