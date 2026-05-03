# certctl Docker Compose Environments

This guide walks through every Docker Compose file in the `deploy/` directory. Each section explains what the environment does, when to use it, every service and environment variable, and the commands to run it. If you've never used Docker before, start with the [Prerequisites](#prerequisites) section. If you're experienced, skip to the environment you need.

## Contents

1. [Prerequisites](#prerequisites)
2. [How Docker Compose Works (30-Second Version)](#how-docker-compose-works)
3. [Base Environment (docker-compose.yml)](#base-environment)
4. [Demo Overlay (docker-compose.demo.yml)](#demo-overlay)
5. [Development Overlay (docker-compose.dev.yml)](#development-overlay)
6. [Test Environment (docker-compose.test.yml)](#test-environment)
7. [Environment Variable Reference](#environment-variable-reference)
8. [Common Operations](#common-operations)

---

## Prerequisites

You need two things: **Docker** (the container runtime) and **Docker Compose** (an orchestration tool that ships with Docker Desktop).

On macOS:
```bash
brew install --cask docker
```

On Linux (Ubuntu/Debian):
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

Verify the install:
```bash
docker --version        # Docker Engine 24+ recommended
docker compose version  # Docker Compose v2+ required (note: no hyphen)
```

**What Docker actually does:** Docker packages an application and all its dependencies (OS libraries, runtimes, config files) into an isolated unit called a container. When you run `docker compose up`, Docker reads a YAML file that describes multiple containers, creates a private network between them, and starts everything in the right order. Each container sees only its own filesystem and network unless you explicitly share volumes or ports.

**Why this matters for certctl:** Instead of installing PostgreSQL, building Go binaries, configuring the agent, and wiring everything together by hand, one command gives you the complete platform. Each compose file targets a different use case.

---

## How Docker Compose Works

A compose file defines **services** (containers), **networks** (how they talk to each other), and **volumes** (persistent storage). The key concepts:

**Services** are named containers. `certctl-server` is the API and web dashboard. `postgres` is the database. `certctl-agent` polls the server for certificate work.

**Depends_on + healthchecks** control startup order. The server won't start until PostgreSQL reports healthy. The agent won't start until the server reports healthy. This prevents connection errors during boot.

**Volumes** persist data across restarts. `postgres_data` keeps your database between `docker compose down` and `docker compose up`. Adding `-v` to `down` deletes volumes for a clean slate.

**Overlay files** let you layer changes. Running `docker compose -f base.yml -f overlay.yml up` merges both files. The overlay can add services, change environment variables, or mount extra volumes without editing the base.

**Port mapping** (`"8443:8443"`) maps host port (left) to container port (right). After startup, `https://localhost:8443` on your machine reaches the certctl server inside its container (HTTPS-only as of v2.2; the `certctl-tls-init` init container bootstraps a self-signed cert into `deploy/test/certs/`).

---

## Base Environment

**File:** `docker-compose.yml`
**When to use:** Production deployments, first-time setup, or any time you want a clean dashboard with the onboarding wizard.

### What it runs

Three services on a private bridge network:

| Service | Image | Purpose | Ports |
|---------|-------|---------|-------|
| `postgres` | `postgres:16-alpine` | Database. Stores certificates, agents, jobs, audit trail, policies, discovery results. | 5432 |
| `certctl-server` | Built from `Dockerfile` | API server + web dashboard + background scheduler. | 8443 |
| `certctl-agent` | Built from `Dockerfile.agent` | Polls server for work, generates keys, deploys certificates, discovers existing certs. | none |

### Starting it

```bash
git clone https://github.com/certctl-io/certctl.git
cd certctl
docker compose -f deploy/docker-compose.yml up -d --build
```

`--build` compiles the Go server and agent from source, including the React frontend. Without it, Docker may reuse a stale image from a previous build.

`-d` runs in detached mode (background). Omit it to see logs in your terminal.

Wait about 30 seconds, then verify:
```bash
docker compose -f deploy/docker-compose.yml ps
# All three services should show "Up (healthy)"

curl --cacert ./deploy/test/certs/ca.crt https://localhost:8443/health
# {"status":"healthy"}
```

The control plane is HTTPS-only as of v2.2. The `certctl-tls-init` init container bootstraps a self-signed cert into `deploy/test/certs/` on first boot; pin it with `--cacert` (as above) or pass `-k` for one-off smoke tests (never in production).

Open **https://localhost:8443** in your browser. You'll see the onboarding wizard guiding you through: connecting a CA, deploying an agent, and adding your first certificate. Your browser will flag the self-signed cert as untrusted — accept the warning for local evaluation, or import `deploy/test/certs/ca.crt` into your OS trust store to make the warning go away.

### Service-by-service walkthrough

#### PostgreSQL

```yaml
postgres:
  image: postgres:16-alpine
  environment:
    POSTGRES_DB: certctl
    POSTGRES_USER: certctl
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-certctl}
```

Alpine-based PostgreSQL 16. The `${POSTGRES_PASSWORD:-certctl}` syntax means: use the `POSTGRES_PASSWORD` environment variable from your shell if set, otherwise default to `certctl`. For production, create a `.env` file:

```bash
echo 'POSTGRES_PASSWORD=your-secure-password-here' > deploy/.env
```

The `volumes` section mounts 10 migration files into PostgreSQL's init directory (`/docker-entrypoint-initdb.d/`). PostgreSQL runs these SQL files in alphabetical order on first boot only. They create the schema (tables, indexes, constraints) and seed the base data (default issuer, default policy). If the `postgres_data` volume already exists with an initialized database, these scripts are skipped entirely.

**Expert note:** The numbered prefix pattern (`001_`, `002_`, ..., `020_`) ensures deterministic execution order. All migrations use `IF NOT EXISTS` and `ON CONFLICT DO NOTHING` for idempotency, so re-running them against an existing database is safe.

**Stateful volume — first-boot password binding (U-1).** The same "first boot only" semantics that govern migration scripts also govern `POSTGRES_PASSWORD`. The official `postgres` image runs `initdb` exactly once — when `/var/lib/postgresql/data` is empty — and that pass is the only time `POSTGRES_PASSWORD` is written into `pg_authid`. On every subsequent boot, the postgres container ignores the env var and authenticates against whatever password was baked into the data directory on the original `up`. Editing `POSTGRES_PASSWORD` in `.env` after a successful first boot therefore only updates the **certctl-server** container's `CERTCTL_DATABASE_URL` — postgres still expects the previous password, and the server fails to ping with `pq: password authentication failed for user "certctl"` (SQLSTATE 28P01). The certctl-server container surfaces this case explicitly: when SQLSTATE 28P01 fires at startup, the wrap text in `internal/repository/postgres/db.go::wrapPingError` points operators at the two remediation paths — destructive volume teardown via `docker compose -f deploy/docker-compose.yml down -v && up -d --build`, or non-destructive in-place rotation via `docker compose -f deploy/docker-compose.yml exec postgres psql -U certctl -c "ALTER ROLE certctl PASSWORD '<new>';"` followed by a server restart with the matching `POSTGRES_PASSWORD`. Use the destructive path on the demo / first-time setup; use the non-destructive path on any environment that holds data you want to keep.

#### certctl Server

```yaml
certctl-server:
  depends_on:
    postgres:
      condition: service_healthy
  environment:
    CERTCTL_DATABASE_URL: postgres://certctl:${POSTGRES_PASSWORD:-certctl}@postgres:5432/certctl?sslmode=disable
    CERTCTL_SERVER_HOST: 0.0.0.0
    CERTCTL_SERVER_PORT: 8443
    CERTCTL_LOG_LEVEL: info
    CERTCTL_AUTH_TYPE: none
    CERTCTL_KEYGEN_MODE: server
    CERTCTL_NETWORK_SCAN_ENABLED: "true"
    CERTCTL_CONFIG_ENCRYPTION_KEY: ${CERTCTL_CONFIG_ENCRYPTION_KEY:-change-me-32-char-encryption-key}
```

The server is the control plane. It serves the REST API, the React dashboard, runs 7 background scheduler loops (renewal, job processing, health checks, notifications, short-lived cert expiry, network scanning, digest emails), and manages the issuer/target registry.

Key environment variables explained:

- `CERTCTL_DATABASE_URL` references the `postgres` service by hostname. Docker's internal DNS resolves `postgres` to the container's IP on the bridge network. `sslmode=disable` is appropriate because traffic stays on the private Docker network.
- `CERTCTL_AUTH_TYPE: none` disables API key authentication so you can explore immediately. For production, set `api-key` and configure `CERTCTL_AUTH_SECRET`.
- `CERTCTL_KEYGEN_MODE: server` means the server generates private keys. This is convenient for demos but insecure for production. In production, set `agent` so keys are generated on agent machines and never transmitted.
- `CERTCTL_CONFIG_ENCRYPTION_KEY` enables AES-256-GCM encryption for issuer and target configurations stored in the database (credentials, API keys). Without this, the dynamic configuration GUI (adding issuers/targets from the dashboard) won't encrypt sensitive fields. For production, generate a strong random key.
- `CERTCTL_NETWORK_SCAN_ENABLED` activates the scheduler loop that probes TLS endpoints on your network to discover certificates you might not be managing.

**Expert note:** The healthcheck hits `GET /health` every 10 seconds with 5 retries. The `depends_on: condition: service_healthy` on the agent means Docker holds agent startup until this check passes. Resource limits (`cpus: '1.0'`, `memory: 512M`) prevent the server from consuming unbounded resources in shared environments.

#### certctl Agent

```yaml
certctl-agent:
  depends_on:
    certctl-server:
      condition: service_healthy
  environment:
    CERTCTL_SERVER_URL: http://certctl-server:8443
    CERTCTL_API_KEY: ${CERTCTL_API_KEY:-change-me-in-production}
    CERTCTL_AGENT_NAME: docker-agent
    CERTCTL_LOG_LEVEL: info
    CERTCTL_DISCOVERY_DIRS: /var/lib/certctl/keys
  volumes:
    - agent_keys:/var/lib/certctl/keys
```

The agent is a lightweight Go binary that polls the server for pending work (certificate deployments, CSR generation requests), executes that work locally, and reports results back. It also scans configured directories for existing certificates (filesystem discovery).

- `CERTCTL_SERVER_URL` uses the Docker internal hostname `certctl-server`. This resolves inside the Docker network only.
- `CERTCTL_DISCOVERY_DIRS` tells the agent which directories to scan for existing certificates. The agent walks these directories recursively, parses PEM and DER files, and reports findings to the server for triage.
- The `agent_keys` volume persists private keys generated by the agent across container restarts. Without this volume, keys would be lost when the container stops.

**Expert note:** The agent's healthcheck uses `pgrep` because the agent doesn't expose an HTTP endpoint. The `restart: unless-stopped` policy means Docker automatically restarts the agent on crashes but respects manual `docker compose stop` commands.

### Stopping and cleaning up

```bash
# Stop containers but keep data
docker compose -f deploy/docker-compose.yml down

# Stop and delete all data (database, keys, volumes)
docker compose -f deploy/docker-compose.yml down -v
```

---

## Demo Overlay

**File:** `docker-compose.demo.yml`
**When to use:** Demos, screenshots, stakeholder presentations, or any time you want a populated dashboard on first boot.

### What it adds

One line: mounts `seed_demo.sql` into PostgreSQL's init directory. This 667-line SQL file inserts 180 days of simulated operational history: teams, owners, certificates across multiple issuers, agents on different platforms, jobs with realistic timestamps, discovery scan results, audit events, policies, and profiles.

### Starting it

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.demo.yml up -d --build
```

The `-f` flags are ordered: base first, overlay second. Docker merges them. The demo overlay adds the seed_demo.sql volume mount to the `postgres` service defined in the base file.

### What you see

The dashboard shows pre-populated charts: expiration heatmap with upcoming renewals, status distribution across Active/Expiring/Expired/Failed states, 30-day job trends, and issuance rates. The sidebar pages (Certificates, Agents, Discovery, Jobs, etc.) all have data to explore.

### Resetting demo data

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.demo.yml down -v
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.demo.yml up -d --build
```

The `down -v` deletes the `postgres_data` volume. On next boot, PostgreSQL re-runs all init scripts including the demo seed, giving you a clean starting point.

**Expert note:** The demo overlay is a pure data layer, not a configuration change. The server, agent, and their environment variables remain identical to the base. This means any behavior you see in the demo is exactly what the base environment produces once you populate data through normal operations.

---

## Development Overlay

**File:** `docker-compose.dev.yml`
**When to use:** When you're contributing to certctl and need debug logging, database inspection, or a debugger attached to the server process.

### What it adds

| Addition | Purpose |
|----------|---------|
| Debug-level logging on server and agent | See every HTTP request, scheduler tick, and connector operation |
| PgAdmin on port 5050 | Visual database browser for inspecting tables, running queries |
| Delve debugger port 40000 | Attach a Go debugger to the running server process |

### Starting it

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.dev.yml up --build
```

Omit `-d` during development so you see logs streaming in your terminal.

### Using PgAdmin

Open **http://localhost:5050** in your browser. PgAdmin is pre-configured in desktop mode (no login required). To connect to the certctl database:

1. Right-click "Servers" in the left panel, choose "Register" > "Server"
2. Name: `certctl`
3. Connection tab: Host = `postgres`, Port = `5432`, Username = `certctl`, Password = `certctl` (or whatever you set in `.env`)

From there you can browse all 19 tables, inspect certificate records, view audit events, check the scheduler's job queue, and run arbitrary SQL.

### Using the Delve debugger

Port 40000 is exposed for remote debugging. To use it, you'd need to modify the Dockerfile to build with debug symbols and start the server under Delve:

```bash
# In Dockerfile, replace the CMD with:
CMD ["dlv", "--listen=:40000", "--headless=true", "--api-version=2", "exec", "/app/server"]
```

Then attach from your IDE (VS Code, GoLand) using remote debug configuration pointing to `localhost:40000`.

### Hot reload

The dev overlay includes commented-out volume mounts for source code directories. Uncomment them and install [air](https://github.com/cosmtrek/air) to get automatic recompilation on file changes:

```bash
go install github.com/cosmtrek/air@latest
```

**Expert note:** The `builds: context: ..` in the dev overlay overrides the base service's image reference, forcing a local build from the repository root. This means changes to your Go source code are compiled fresh on each `docker compose up --build`.

---

## Test Environment

**File:** `docker-compose.test.yml`
**When to use:** Integration testing against real CA backends. This is a standalone environment (not an overlay) with 7 containers on a static-IP subnet.

### What it runs

| Service | IP | Purpose |
|---------|----|---------|
| `postgres` | 10.30.50.2 | Database (clean, no demo data) |
| `pebble-challtestsrv` | 10.30.50.3 | DNS/HTTP challenge test server for Pebble |
| `pebble` | 10.30.50.4 | ACME test server (simulates Let's Encrypt) |
| `step-ca` | 10.30.50.5 | Private CA (Smallstep, JWK provisioner) |
| `certctl-server` | 10.30.50.6 | Control plane with all issuers configured |
| `nginx` | 10.30.50.7 | TLS target server for deployment testing |
| `certctl-agent` | 10.30.50.8 | Agent with NGINX volume + discovery |

### Why static IPs?

Pebble (the ACME test server) validates HTTP-01 challenges by connecting to the challenge URL. It resolves domain names via `pebble-challtestsrv`, which is configured to return `10.30.50.6` (the certctl server) for all lookups. Without static IPs, container IPs would be assigned randomly on each boot, breaking the challenge validation chain.

The `/24` subnet (10.30.50.0/24) provides 254 usable addresses, far more than needed but standard practice for test networks.

### Starting it

```bash
docker compose -f deploy/docker-compose.test.yml up --build
```

Wait for all health checks to pass (about 60 seconds for step-ca's first-run bootstrap). Then:

```bash
# Dashboard with auth enabled (HTTPS-only as of v2.2; browser will warn on the self-signed cert —
# accept the warning or trust `deploy/test/certs/ca.crt` in your OS keychain)
open https://localhost:8443
# API key: test-key-2026

# NGINX serving a self-signed placeholder
curl -k https://localhost:8444
```

### What's different from the base

The test environment is configured for production-like behavior:

- **API key auth enabled** (`CERTCTL_AUTH_TYPE: api-key`, `CERTCTL_AUTH_SECRET: test-key-2026`). Every API request needs `Authorization: Bearer test-key-2026`.
- **Agent-side key generation** (`CERTCTL_KEYGEN_MODE: agent`). The agent generates ECDSA P-256 keys locally and submits only the CSR to the server. Private keys never leave the agent container.
- **Three real issuers configured:**
  - **Local CA** (self-signed) for instant issuance testing
  - **ACME via Pebble** for Let's Encrypt-compatible flow testing (HTTP-01 challenges validated through the challenge test server)
  - **step-ca** for private CA testing with JWK provisioner authentication
- **EST server enabled** (`CERTCTL_EST_ENABLED: "true"`) for RFC 7030 enrollment testing
- **Post-deployment verification enabled** (`CERTCTL_VERIFY_DEPLOYMENT: "true"`) so the agent probes NGINX after deploying a cert and confirms the TLS fingerprint matches
- **Dynamic config encryption enabled** (`CERTCTL_CONFIG_ENCRYPTION_KEY`) so issuer/target configs added through the GUI are encrypted at rest
- **TLS trust bootstrapping:** The server runs a `setup-trust.sh` entrypoint that fetches Pebble's root CA from its management API and copies step-ca's root cert from a shared volume, then runs `update-ca-certificates` before starting the server binary. This is necessary because both CAs use self-signed roots that aren't in Alpine's default trust store.

### Running the Go integration tests

The test environment is designed to support the Go integration test suite at `deploy/test/integration_test.go`:

```bash
# Start the environment
docker compose -f deploy/docker-compose.test.yml up --build -d

# Wait for health checks
sleep 30

# Run integration tests (from repo root)
go test -tags integration -v ./deploy/test/...
```

The integration tests exercise 12 phases: health, agent heartbeat, Local CA issuance, ACME issuance, renewal, step-ca issuance, revocation + CRL + OCSP, EST enrollment, S/MIME issuance, discovery, network scan, and deployment verification. PostgreSQL port 5432 is exposed so the test binary can query the database directly for assertions.

See [docs/test-env.md](../docs/test-env.md) for the full walkthrough and manual QA procedures.

### Stopping and cleaning up

```bash
# Stop but keep data (volumes persist)
docker compose -f deploy/docker-compose.test.yml down

# Full reset (delete step-ca bootstrap, database, agent keys, NGINX certs)
docker compose -f deploy/docker-compose.test.yml down -v
```

**Expert note:** The step-ca container auto-bootstraps on first run: generates a root CA, creates a JWK provisioner named "admin" with password "password123", and writes everything to the `stepca_data` volume. Subsequent starts reuse this volume. If you `down -v`, the next boot generates a new root CA, which means all previously issued step-ca certs become untrusted.

---

## Environment Variable Reference

Every `CERTCTL_*` environment variable is read by the server's `internal/config/config.go` via `os.Getenv`. If the prefix is missing, the variable is silently ignored.

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_DATABASE_URL` | (required) | PostgreSQL connection string |
| `CERTCTL_SERVER_HOST` | `0.0.0.0` | Listen address |
| `CERTCTL_SERVER_PORT` | `8443` | Listen port |
| `CERTCTL_LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `CERTCTL_AUTH_TYPE` | `api-key` | Auth mode: `api-key` or `none` |
| `CERTCTL_AUTH_SECRET` | (none) | API key(s), comma-separated for rotation |
| `CERTCTL_KEYGEN_MODE` | `agent` | Key generation: `agent` (production) or `server` (demo) |
| `CERTCTL_CONFIG_ENCRYPTION_KEY` | (none) | AES-256-GCM key for encrypting issuer/target configs in DB |
| `CERTCTL_NETWORK_SCAN_ENABLED` | `false` | Enable network TLS scanning scheduler loop |
| `CERTCTL_NETWORK_SCAN_INTERVAL` | `6h` | How often the network scanner runs |
| `CERTCTL_MAX_BODY_SIZE` | `1048576` | Max request body size in bytes (1MB) |
| `CERTCTL_CORS_ORIGINS` | (empty) | Allowed CORS origins, comma-separated. Empty = deny all cross-origin |
| `CERTCTL_RATE_LIMIT_RPS` | `10` | Requests per second per client |
| `CERTCTL_RATE_LIMIT_BURST` | `20` | Burst allowance above RPS |

### Agent

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SERVER_URL` | (required) | Server API URL |
| `CERTCTL_API_KEY` | (none) | API key for authenticating with server |
| `CERTCTL_AGENT_NAME` | (hostname) | Display name in dashboard |
| `CERTCTL_AGENT_ID` | (auto-generated) | Stable agent identifier |
| `CERTCTL_KEYGEN_MODE` | `agent` | Must match server setting |
| `CERTCTL_LOG_LEVEL` | `info` | Log verbosity |
| `CERTCTL_KEY_DIR` | `/var/lib/certctl/keys` | Directory for private key storage (0600 perms) |
| `CERTCTL_DISCOVERY_DIRS` | (none) | Comma-separated paths to scan for existing certs |

### Issuers (Server)

| Variable | Description |
|----------|-------------|
| `CERTCTL_ACME_DIRECTORY_URL` | ACME CA directory (e.g., Let's Encrypt, Pebble) |
| `CERTCTL_ACME_EMAIL` | ACME account email |
| `CERTCTL_ACME_CHALLENGE_TYPE` | `http-01`, `dns-01`, or `dns-persist-01` |
| `CERTCTL_ACME_INSECURE` | Skip TLS verification for ACME CA (test only) |
| `CERTCTL_ACME_EAB_KID` / `CERTCTL_ACME_EAB_HMAC` | External Account Binding for ZeroSSL, Google Trust Services |
| `CERTCTL_ACME_ARI_ENABLED` | Enable RFC 9773 Renewal Information |
| `CERTCTL_ACME_PROFILE` | ACME profile (`tlsserver`, `shortlived`) |
| `CERTCTL_STEPCA_URL` | step-ca server URL |
| `CERTCTL_STEPCA_ROOT_CERT` | Path to step-ca root CA cert |
| `CERTCTL_STEPCA_PROVISIONER` | Provisioner name |
| `CERTCTL_STEPCA_PASSWORD` | Provisioner password |
| `CERTCTL_STEPCA_KEY_PATH` | Path to provisioner key |
| `CERTCTL_CA_CERT_PATH` / `CERTCTL_CA_KEY_PATH` | Sub-CA mode: load CA cert+key from disk |
| `CERTCTL_VAULT_ADDR` | Vault server address |
| `CERTCTL_VAULT_TOKEN` | Vault auth token |
| `CERTCTL_VAULT_MOUNT` | PKI secrets engine mount (default: `pki`) |
| `CERTCTL_VAULT_ROLE` | PKI role name |
| `CERTCTL_DIGICERT_API_KEY` | DigiCert CertCentral API key |
| `CERTCTL_DIGICERT_ORG_ID` | DigiCert organization ID |
| `CERTCTL_SECTIGO_CUSTOMER_URI` / `_LOGIN` / `_PASSWORD` | Sectigo SCM auth |
| `CERTCTL_GOOGLE_CAS_PROJECT` / `_LOCATION` / `_CA_POOL` / `_CREDENTIALS` | Google CAS config |

### EST Server

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_EST_ENABLED` | `false` | Enable RFC 7030 EST endpoints |
| `CERTCTL_EST_ISSUER_ID` | `iss-local` | Which issuer processes EST enrollments |
| `CERTCTL_EST_PROFILE_ID` | (none) | Optional profile constraint |

### Post-Deployment Verification

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_VERIFY_DEPLOYMENT` | `false` | Agent probes TLS after deploying |
| `CERTCTL_VERIFY_TIMEOUT` | `10s` | TLS probe timeout |
| `CERTCTL_VERIFY_DELAY` | `2s` | Wait before probing (let service reload) |

### Notifications

| Variable | Description |
|----------|-------------|
| `CERTCTL_SMTP_HOST` / `_PORT` / `_USERNAME` / `_PASSWORD` / `_FROM_ADDRESS` / `_USE_TLS` | SMTP email |
| `CERTCTL_SLACK_WEBHOOK_URL` / `_CHANNEL` / `_USERNAME` | Slack notifications |
| `CERTCTL_TEAMS_WEBHOOK_URL` | Microsoft Teams |
| `CERTCTL_PAGERDUTY_ROUTING_KEY` / `_SEVERITY` | PagerDuty alerts |
| `CERTCTL_OPSGENIE_API_KEY` / `_PRIORITY` | OpsGenie alerts |
| `CERTCTL_DIGEST_ENABLED` / `_INTERVAL` / `_RECIPIENTS` | Scheduled digest email |

---

## Common Operations

### Viewing logs

```bash
# All services
docker compose -f deploy/docker-compose.yml logs -f

# Single service
docker compose -f deploy/docker-compose.yml logs -f certctl-server

# Last 100 lines
docker compose -f deploy/docker-compose.yml logs --tail 100 certctl-server
```

### Rebuilding after code changes

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```

Docker only rebuilds images that have changed source files. The `--build` flag is essential after editing Go code or frontend files.

### Connecting to the database directly

```bash
docker exec -it certctl-postgres psql -U certctl -d certctl
```

Useful queries:
```sql
-- Certificate inventory
SELECT id, common_name, status, expires_at FROM managed_certificates ORDER BY expires_at;

-- Recent jobs
SELECT id, type, status, certificate_id, created_at FROM jobs ORDER BY created_at DESC LIMIT 20;

-- Audit trail
SELECT event_type, actor, resource_id, created_at FROM audit_events ORDER BY created_at DESC LIMIT 20;

-- Issuer configurations (encrypted_config is AES-256-GCM)
SELECT id, type, source, enabled, test_status FROM issuers;
```

### Checking container resource usage

```bash
docker stats --no-stream
```

### Upgrading

```bash
git pull
docker compose -f deploy/docker-compose.yml up -d --build
```

Migrations are idempotent (`IF NOT EXISTS`), so upgrading to a version with new schema changes is safe. PostgreSQL only runs init scripts on first boot of a fresh volume, so new migrations in an upgrade require running them manually:

```bash
docker exec -i certctl-postgres psql -U certctl -d certctl < migrations/000011_new_feature.up.sql
```

Or, for a clean upgrade: `down -v` and `up --build` (loses existing data).
