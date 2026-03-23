# certctl — Self-Hosted Certificate Lifecycle Platform

TLS certificate lifespans are shrinking. The CA/Browser Forum passed [Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) unanimously in April 2025, setting a phased reduction: **200 days** by March 2026, **100 days** by March 2027, and **47 days** by March 2029. Manual certificate management is no longer viable at any scale.

certctl is a self-hosted platform for **end-to-end certificate lifecycle automation** — from issuance through renewal to deployment — with zero human intervention. Track every certificate in your organization, automatically renew them before they expire, and deploy them to your servers without touching a terminal. Private keys never leave your infrastructure.

[![License](https://img.shields.io/badge/license-BSL%201.1-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/shankar0123/certctl)](https://goreportcard.com/report/github.com/shankar0123/certctl)
![Status: v1.0.0](https://img.shields.io/badge/status-v1.0.0-brightgreen)

## What It Does

certctl gives you a single pane of glass for every TLS certificate in your organization. The **web dashboard** shows your full certificate inventory — what's healthy, what's expiring, what's already expired, and who owns each one. The **REST API** (76 endpoints under `/api/v1/`) lets you automate everything. **Agents** deployed on your infrastructure generate private keys locally and submit CSRs — private keys never leave your servers. The background scheduler watches expiration dates and triggers renewals automatically — when certificate lifespans drop to 47 days, certctl handles the constant rotation without human involvement.

```mermaid
flowchart LR
    subgraph "Control Plane"
        API["REST API + Dashboard\n:8443"]
        PG[("PostgreSQL")]
    end

    subgraph "Your Infrastructure"
        A1["Agent"] --> T1["NGINX"]
        A2["Agent"] --> T2["Apache / HAProxy"]
        A3["Agent"] --> T3["F5 · IIS"]
    end

    API --> PG
    A1 & A2 & A3 -->|"CSR + status\n(no private keys)"| API
    API -->|"Signed certs"| A1 & A2 & A3
    API -->|"Issue/Renew"| CA["Certificate Authorities\nLocal CA · ACME"]
```

### Screenshots

| | |
|---|---|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Certificates](docs/screenshots/certificates.png) |
| **Dashboard** — certificate stats, expiry timeline, recent jobs | **Certificates** — full inventory with status, environment, owner filters |
| ![Agents](docs/screenshots/agents.png) | ![Jobs](docs/screenshots/jobs.png) |
| **Agents** — fleet health, hostname, heartbeat tracking | **Jobs** — issuance, renewal, deployment job queue |
| ![Notifications](docs/screenshots/notifications.png) | ![Policies](docs/screenshots/policies.png) |
| **Notifications** — threshold alerts grouped by certificate | **Policies** — enforcement rules with enable/disable and delete |
| ![Issuers](docs/screenshots/issuers.png) | ![Targets](docs/screenshots/targets.png) |
| **Issuers** — CA connectors with test connectivity | **Targets** — deployment targets (NGINX, Apache, HAProxy, F5, IIS) |
| ![Audit Trail](docs/screenshots/audit-trail.png) | |
| **Audit Trail** — immutable log of every action | |

## Quick Start

### Docker Compose (Recommended)

```bash
git clone https://github.com/shankar0123/certctl.git
cd certctl
docker compose -f deploy/docker-compose.yml up -d --build
```

Wait ~30 seconds, then open **http://localhost:8443** in your browser.

The dashboard comes pre-loaded with 15 demo certificates, 5 agents, policy rules, audit events, and notifications — a realistic snapshot of a certificate inventory so you can explore immediately.

Verify the API:
```bash
curl http://localhost:8443/health
# {"status":"healthy"}

curl -s http://localhost:8443/api/v1/certificates | jq '.total'
# 15
```

### Manual Build

```bash
# Prerequisites: Go 1.22+, PostgreSQL 16+
go mod download
make build

# Set up database
export CERTCTL_DATABASE_URL="postgres://certctl:certctl@localhost:5432/certctl?sslmode=disable"
export CERTCTL_AUTH_TYPE=none
make migrate-up

# Start server
./bin/server

# Start agent (separate terminal)
export CERTCTL_SERVER_URL=http://localhost:8443
export CERTCTL_API_KEY=change-me-in-production
export CERTCTL_AGENT_NAME=local-agent
export CERTCTL_AGENT_ID=agent-local-01
./bin/agent --agent-id=agent-local-01
```

## Documentation

| Guide | Description |
|-------|-------------|
| [Concepts](docs/concepts.md) | TLS certificates explained from scratch — for beginners who know nothing about certs |
| [Quick Start](docs/quickstart.md) | Get running in 5 minutes with accurate API examples |
| [Demo Walkthrough](docs/demo-guide.md) | 5-7 minute guided stakeholder presentation |
| [Advanced Demo](docs/demo-advanced.md) | Issue a certificate end-to-end with technical deep-dives |
| [Architecture](docs/architecture.md) | System design, data flow diagrams, security model |
| [Connectors](docs/connectors.md) | Build custom issuer, target, and notifier connectors |

## Architecture

```mermaid
flowchart TB
    subgraph "Control Plane (certctl-server)"
        DASH["Web Dashboard\nReact SPA"]
        API["REST API\nGo 1.22 net/http"]
        SVC["Service Layer"]
        REPO["Repository Layer\ndatabase/sql + lib/pq"]
        SCHED["Scheduler\nRenewal · Jobs · Health · Notifications"]
    end

    subgraph "Data Store"
        PG[("PostgreSQL 16\n18 tables\nTEXT primary keys")]
    end

    subgraph "Agents"
        AG["certctl-agent\nKey generation · CSR · Deployment"]
    end

    DASH --> API
    API --> SVC --> REPO --> PG
    SCHED --> SVC
    AG -->|"Heartbeat + CSR"| API
    API -->|"Cert + Chain"| AG
```

### Key Design Decisions

- **Private keys isolated from the control plane.** Agents generate ECDSA P-256 keys locally and submit CSRs (public key only). The server signs the CSR and returns the certificate — private keys never touch the control plane. Server-side keygen is available via `CERTCTL_KEYGEN_MODE=server` for demo/development only.
- **TEXT primary keys, not UUIDs.** IDs are human-readable prefixed strings (`mc-api-prod`, `t-platform`, `o-alice`) so you can identify resource types at a glance in logs and queries.
- **Handler → Service → Repository layering.** Handlers define their own service interfaces for clean dependency inversion. No global service singletons.
- **Idempotent migrations.** All schema uses `IF NOT EXISTS` and seed data uses `ON CONFLICT (id) DO NOTHING`, safe for repeated execution.

### Database Schema

| Table | Purpose |
|-------|---------|
| `managed_certificates` | Certificate records with metadata, status, expiry, tags |
| `certificate_versions` | Historical versions with PEM chains and CSRs |
| `renewal_policies` | Renewal window, auto-renew settings, retry config, alert thresholds |
| `issuers` | CA configurations (Local CA, ACME, etc.) |
| `deployment_targets` | Target systems (NGINX, F5, IIS) with agent assignments |
| `agents` | Registered agents with heartbeat tracking, OS/arch/IP metadata |
| `jobs` | Issuance, renewal, deployment, and validation jobs |
| `teams` | Organizational groups for certificate ownership |
| `owners` | Individual owners with email for notifications |
| `policy_rules` | Enforcement rules (allowed issuers, environments, metadata) |
| `policy_violations` | Flagged non-compliance with severity levels |
| `audit_events` | Immutable action log (append-only, no update/delete) |
| `notification_events` | Email and webhook notification records |
| `certificate_target_mappings` | Many-to-many cert ↔ target relationships |
| `certificate_profiles` | Named enrollment profiles with allowed key types, max TTL, crypto constraints |
| `agent_groups` | Dynamic device grouping by OS, architecture, IP CIDR, version |
| `agent_group_members` | Manual include/exclude membership for agent groups |
| `certificate_revocations` | Revocation records with RFC 5280 reason codes, serial numbers, issuer notification status |

## Configuration

All server environment variables use the `CERTCTL_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SERVER_HOST` | `127.0.0.1` | Server bind address |
| `CERTCTL_SERVER_PORT` | `8080` | Server listen port |
| `CERTCTL_DATABASE_URL` | `postgres://localhost/certctl` | PostgreSQL connection string |
| `CERTCTL_DATABASE_MAX_CONNS` | `25` | Connection pool size |
| `CERTCTL_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `CERTCTL_LOG_FORMAT` | `json` | Log format: `json` or `text` |
| `CERTCTL_AUTH_TYPE` | `api-key` | Auth mode: `api-key`, `jwt`, or `none` |
| `CERTCTL_AUTH_SECRET` | — | Required for `api-key` and `jwt` auth types |
| `CERTCTL_KEYGEN_MODE` | `agent` | Key generation mode: `agent` (production) or `server` (demo only) |
| `CERTCTL_ACME_DIRECTORY_URL` | — | ACME directory URL (e.g., Let's Encrypt staging) |
| `CERTCTL_ACME_EMAIL` | — | Contact email for ACME account registration |
| `CERTCTL_ACME_CHALLENGE_TYPE` | — | ACME challenge type: `http-01` (default) or `dns-01` |
| `CERTCTL_CA_CERT_PATH` | — | Path to CA certificate for sub-CA mode |
| `CERTCTL_CA_KEY_PATH` | — | Path to CA private key for sub-CA mode |
| `CERTCTL_STEPCA_URL` | — | step-ca server URL |
| `CERTCTL_STEPCA_PROVISIONER` | — | step-ca JWK provisioner name |

Agent environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SERVER_URL` | `http://localhost:8080` | Control plane URL |
| `CERTCTL_API_KEY` | — | Agent API key |
| `CERTCTL_AGENT_NAME` | `certctl-agent` | Agent display name |
| `CERTCTL_AGENT_ID` | — | Registered agent ID (required) |
| `CERTCTL_KEY_DIR` | `/var/lib/certctl/keys` | Directory for storing private keys (agent keygen mode) |

Docker Compose overrides these for the demo stack (see `deploy/docker-compose.yml`): port `8443`, auth type `none`, database pointing to the postgres container.

## API Overview

All endpoints are under `/api/v1/` and return JSON. List endpoints support pagination (`?page=1&per_page=50`).

### Certificates
```
GET    /api/v1/certificates              List (filter: status, environment, owner_id, team_id)
POST   /api/v1/certificates              Create
GET    /api/v1/certificates/{id}          Get
PUT    /api/v1/certificates/{id}          Update
DELETE /api/v1/certificates/{id}          Archive (soft delete)
GET    /api/v1/certificates/{id}/versions Version history
POST   /api/v1/certificates/{id}/renew    Trigger renewal → 202 Accepted
POST   /api/v1/certificates/{id}/deploy   Trigger deployment → 202 Accepted
POST   /api/v1/certificates/{id}/revoke   Revoke with RFC 5280 reason code
GET    /api/v1/crl                        Certificate Revocation List (JSON)
GET    /api/v1/crl/{issuer_id}            DER-encoded X.509 CRL
GET    /api/v1/ocsp/{issuer_id}/{serial}  OCSP responder (good/revoked/unknown)
```

### Agents
```
GET    /api/v1/agents                     List
POST   /api/v1/agents                     Register
GET    /api/v1/agents/{id}                Get
POST   /api/v1/agents/{id}/heartbeat      Record heartbeat
POST   /api/v1/agents/{id}/csr            Submit CSR for issuance
GET    /api/v1/agents/{id}/certificates/{certId}  Retrieve signed certificate
GET    /api/v1/agents/{id}/work            Poll for pending deployment jobs
POST   /api/v1/agents/{id}/jobs/{jobId}/status  Report job completion/failure
```

### Infrastructure
```
GET    /api/v1/issuers                    List issuers
POST   /api/v1/issuers                    Create
GET    /api/v1/issuers/{id}               Get
PUT    /api/v1/issuers/{id}               Update
DELETE /api/v1/issuers/{id}               Delete
POST   /api/v1/issuers/{id}/test          Test connectivity

GET    /api/v1/targets                    List deployment targets
POST   /api/v1/targets                    Create
GET    /api/v1/targets/{id}               Get
PUT    /api/v1/targets/{id}               Update
DELETE /api/v1/targets/{id}               Delete
```

### Organization
```
GET    /api/v1/teams                      List teams
POST   /api/v1/teams                      Create
GET    /api/v1/teams/{id}                 Get
PUT    /api/v1/teams/{id}                 Update
DELETE /api/v1/teams/{id}                 Delete
GET    /api/v1/owners                     List owners
POST   /api/v1/owners                     Create
GET    /api/v1/owners/{id}                Get
PUT    /api/v1/owners/{id}                Update
DELETE /api/v1/owners/{id}                Delete
```

### Operations
```
GET    /api/v1/jobs                       List (filter: status, type)
GET    /api/v1/jobs/{id}                  Get
POST   /api/v1/jobs/{id}/cancel           Cancel
POST   /api/v1/jobs/{id}/approve          Approve (interactive renewal)
POST   /api/v1/jobs/{id}/reject           Reject (interactive renewal)

GET    /api/v1/policies                   List policy rules
POST   /api/v1/policies                   Create
GET    /api/v1/policies/{id}              Get
PUT    /api/v1/policies/{id}              Update (enable/disable)
DELETE /api/v1/policies/{id}              Delete
GET    /api/v1/policies/{id}/violations   List violations for rule

GET    /api/v1/profiles                   List certificate profiles
POST   /api/v1/profiles                   Create
GET    /api/v1/profiles/{id}              Get
PUT    /api/v1/profiles/{id}              Update
DELETE /api/v1/profiles/{id}              Delete

GET    /api/v1/agent-groups               List agent groups
POST   /api/v1/agent-groups               Create
GET    /api/v1/agent-groups/{id}          Get
PUT    /api/v1/agent-groups/{id}          Update
DELETE /api/v1/agent-groups/{id}          Delete
GET    /api/v1/agent-groups/{id}/members  List members

GET    /api/v1/audit                      Query audit trail
GET    /api/v1/audit/{id}                 Get audit event
GET    /api/v1/notifications              List notifications
GET    /api/v1/notifications/{id}         Get notification
POST   /api/v1/notifications/{id}/read    Mark as read
```

### Observability
```
GET    /api/v1/stats/summary              Dashboard summary (totals, expiring, agents, jobs)
GET    /api/v1/stats/certificates-by-status  Certificate counts grouped by status
GET    /api/v1/stats/expiration-timeline   Expiration buckets (?days=30)
GET    /api/v1/stats/job-trends            Job success/failure over time (?days=7)
GET    /api/v1/stats/issuance-rate         Certificate issuance rate (?days=7)
GET    /api/v1/metrics                     JSON metrics (gauges, counters, uptime)
```

### Auth
```
GET    /api/v1/auth/info                  Auth mode info (no auth required)
GET    /api/v1/auth/check                 Validate credentials
```

### Health
```
GET    /health                            Server health check
GET    /ready                             Readiness check
```

## Supported Integrations

### Certificate Issuers
| Issuer | Status | Type |
|--------|--------|------|
| Local CA (self-signed + sub-CA) | Implemented | `GenericCA` |
| ACME v2 (Let's Encrypt, Sectigo) | Implemented (HTTP-01 + DNS-01) | `ACME` |
| step-ca | Implemented | `StepCA` |
| OpenSSL / Custom CA | Planned | — |
| Vault PKI | Planned | — |
| DigiCert | Planned | — |

**Note:** ADCS integration is handled via the Local CA's sub-CA mode — certctl operates as a subordinate CA with its signing certificate issued by ADCS.

### Deployment Targets
| Target | Status | Type |
|--------|--------|------|
| NGINX | Implemented | `NGINX` |
| Apache httpd | Implemented | `Apache` |
| HAProxy | Implemented | `HAProxy` |
| F5 BIG-IP | Interface only | `F5` |
| Microsoft IIS | Interface only | `IIS` |
| Kubernetes Secrets | Planned | — |

### Notifiers
| Notifier | Status | Type |
|----------|--------|------|
| Email (SMTP) | Implemented | `Email` |
| Webhooks | Implemented | `Webhook` |
| Slack | Planned | — |

## Development

```bash
# Install dev tools (golangci-lint, migrate CLI, air)
make install-tools

# Run tests
make test

# Run with coverage
make test-coverage

# Lint
make lint

# Format
make fmt
```

### Docker Compose

```bash
make docker-up          # Start stack (server + postgres + agent)
make docker-down        # Stop stack
make docker-logs-server # Server logs
make docker-logs-agent  # Agent logs
make docker-clean       # Stop + remove volumes
```

## Security

### Private Key Management
- **Agent keygen mode (default)**: Agents generate ECDSA P-256 keys locally and store them with 0600 permissions in `CERTCTL_KEY_DIR` (default `/var/lib/certctl/keys`). Only the CSR (public key) is sent to the control plane. Private keys never leave agent infrastructure.
- **Server keygen mode (demo only)**: Set `CERTCTL_KEYGEN_MODE=server` for development/demo with Local CA. The control plane generates RSA-2048 keys server-side. A log warning is emitted at startup.

### Authentication
- Agent-to-server: API key (registered at agent creation)
- API key and JWT auth types supported; `none` for demo/development
- Auth type and secret configured via `CERTCTL_AUTH_TYPE` and `CERTCTL_AUTH_SECRET`

### Audit Trail
- Immutable append-only log in PostgreSQL (`audit_events` table)
- Every lifecycle action attributed to an actor with timestamp and resource reference
- No update or delete operations on audit records
- V2 extends to log every API call (method, path, actor, response status, latency)

## Roadmap

### V1 (v1.0.0 released)
All nine development milestones (M1–M9) are complete. The backend covers the full certificate lifecycle: Local CA and ACME v2 issuers, NGINX/Apache/HAProxy/F5/IIS target connectors, threshold-based expiration alerting, agent-side ECDSA P-256 key generation, API auth with rate limiting, and a React dashboard with 19 pages wired to the real API. The CI pipeline runs build, vet, test with coverage gates (service layer 30%+, handler layer 50%+), frontend type checking, Vitest test suite, and Vite production build on every push. 744+ tests total: ~520 Go test functions + ~138 subtests across service, handler, integration, connector, and domain layers, plus 86 frontend Vitest tests covering all API client endpoints, stats/metrics endpoints, utilities, and M13 operations. Docker images are published to GitHub Container Registry on every version tag via the release workflow.

### V2: Operational Maturity
- **M10: Agent Metadata + Targets** ✅ — agents report OS, architecture, IP, hostname, version via heartbeat; Apache httpd and HAProxy target connectors
- **M11: Crypto Policy + Profiles + Ownership** ✅ — certificate profiles (named enrollment profiles with allowed key types, max TTL, crypto constraints), certificate ownership tracking (owners + teams + notification routing), dynamic agent groups (OS/arch/IP CIDR/version matching), interactive renewal approval (AwaitingApproval state)
- **M12: Sub-CA + DNS-01 + step-ca** ✅ — Local CA sub-CA mode (enterprise root chain with RSA/ECDSA/PKCS#8), ACME DNS-01 challenges (script-based DNS hooks for any provider, wildcard cert support), step-ca issuer connector (native /sign API with JWK provisioner auth)
- **M15a: Core Revocation** ✅ — revocation API with all RFC 5280 reason codes, JSON CRL endpoint, webhook + email revocation notifications, best-effort issuer notification, `certificate_revocations` table with idempotent recording, 48 new tests
- **M15b: OCSP + Revocation GUI** ✅ — embedded OCSP responder (GET /api/v1/ocsp/{issuer_id}/{serial}), DER-encoded X.509 CRL (GET /api/v1/crl/{issuer_id}), short-lived cert exemption (TTL < 1h skip CRL/OCSP), revocation GUI with reason modal, ~31 new tests
- **M13: GUI Operations** ✅ — bulk cert operations (multi-select → renew, revoke, reassign owner), deployment status timeline, inline policy/profile editor, target connector configuration wizard, audit trail export (CSV/JSON), short-lived credentials dashboard view
- **M14: Observability** ✅ — dashboard charts (expiration heatmap, cert status distribution, job trends, issuance rate), agent fleet overview with OS/arch grouping, JSON metrics endpoint, stats API (5 endpoints), structured logging with request IDs, deployment rollback
- **M19: Immutable API Audit Log** — extend audit trail to log every API call (method, path, actor, status, latency), queryable via existing audit endpoint
- **M16: Operator Tooling** — CLI tool (`certctl`), Slack/Teams/PagerDuty/OpsGenie notifiers, bulk certificate import
- **M17: Additional Connectors** — OpenSSL/Custom CA issuer connector
- **M18: Integrations** — MCP server (OpenClaw/Claude/Cursor), filesystem cert discovery

### V3: Team & Enterprise
Team access controls, identity provider integration, enterprise deployment targets, compliance and risk scoring, advanced fleet operations, real-time operational views, and premium CA integrations.

### V4+: Discovery, Cloud & Scale
Discovery engine, Kubernetes integration, cloud infrastructure targets, extended CA support, and platform-scale features.

## License

Certctl is licensed under the [Business Source License 1.1](LICENSE). The source code is publicly available and free to use, modify, and self-host. The one restriction: you may not offer certctl as a managed/hosted certificate management service to third parties.

