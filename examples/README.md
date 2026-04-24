# Deployment Examples

Five turnkey docker-compose scenarios that show certctl deployed against real CA backends and target shapes. Each subdirectory is self-contained — pick the one closest to your stack and have it running in minutes.

| Example | Stack | What it shows |
|---------|-------|---------------|
| [`acme-nginx/`](acme-nginx/acme-nginx.md) | Let's Encrypt + NGINX (HTTP-01) | The default public-CA path: ACME-issued certs deployed to NGINX. |
| [`acme-wildcard-dns01/`](acme-wildcard-dns01/acme-wildcard-dns01.md) | Let's Encrypt wildcard (DNS-01) | Wildcard certificates via DNS-01 with pluggable DNS hooks. |
| [`private-ca-traefik/`](private-ca-traefik/private-ca-traefik.md) | Local CA + Traefik | Internal-only certs from a private CA, deployed to Traefik. |
| [`step-ca-haproxy/`](step-ca-haproxy/step-ca-haproxy.md) | Smallstep step-ca + HAProxy | Self-hosted CA with HAProxy as the deployment target. |
| [`multi-issuer/`](multi-issuer/multi-issuer.md) | Let's Encrypt + Local CA | Public + private certs side-by-side from a single dashboard. |

## Common operational notes

These notes apply to **every** example. They're called out here so the per-example walkthroughs stay focused on the issuer/target wiring instead of repeating ops boilerplate.

### Postgres password rotation — first-boot binding trap (U-1)

Every example file uses `${DB_PASSWORD:-certctl-dev-password}` as the postgres password env var, with the data directory persisted via a named volume. The `postgres:16-alpine` image runs `initdb` exactly once — when `/var/lib/postgresql/data` is empty — and that's the only time `POSTGRES_PASSWORD` is written into `pg_authid`. If you boot once with the default and then change `DB_PASSWORD` (in your shell, in a `.env` file, or in a wrapper script), the certctl-server container picks up the new value but the postgres container continues to authenticate against the old one. The server fails its startup `db.Ping()` with `pq: password authentication failed for user "certctl"` (SQLSTATE 28P01).

The certctl-server emits guidance pointing at the fix when this fires (see `internal/repository/postgres/db.go::wrapPingError`). The two remediation paths:

- **Destructive — wipes all certctl data, only acceptable on demo/test setups:**
  ```bash
  docker compose -f examples/<example>/docker-compose.yml down -v
  docker compose -f examples/<example>/docker-compose.yml up -d --build
  ```
- **Non-destructive — preserves data, rotates `pg_authid` in place:**
  ```bash
  docker compose -f examples/<example>/docker-compose.yml exec postgres \
    psql -U certctl -c "ALTER ROLE certctl PASSWORD '<new>';"
  # Then redeploy with DB_PASSWORD set to <new> in your shell or .env
  ```

The cleanest practice for a fresh demo: set `DB_PASSWORD` once in your shell **before** the very first `docker compose up`, and don't change it during the demo's lifetime. If you must rotate, use the non-destructive path.

Same root cause and remediation pattern is documented for the canonical quickstart in [`../docs/quickstart.md`](../docs/quickstart.md), the production compose surface in [`../deploy/ENVIRONMENTS.md`](../deploy/ENVIRONMENTS.md), and the Helm chart in [`../deploy/helm/certctl/README.md`](../deploy/helm/certctl/README.md).

### TLS for the certctl control plane

Every example boots certctl with HTTPS-only on port 8443 (TLS 1.3 pinned, no plaintext listener as of v2.2). The shipped `certctl-tls-init` init container generates a self-signed ECDSA-P256 cert on first boot — fine for the example demos, **never** acceptable for a public deployment. For production, swap the init container for cert-manager, an operator-supplied Secret, or your internal CA — see [`../docs/tls.md`](../docs/tls.md) for the full pattern matrix.

### Tearing down

To stop services but **keep** the postgres volume (so you can pick up where you left off):
```bash
docker compose -f examples/<example>/docker-compose.yml down
```

To stop services **and** wipe all data (clean slate for the next run):
```bash
docker compose -f examples/<example>/docker-compose.yml down -v
```

Note that `down -v` is the only canonical way to recover from the postgres-password trap when the non-destructive `ALTER ROLE` route is unavailable (e.g., you've forgotten the original password).
