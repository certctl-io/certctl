# certctl — Open-Source Certificate Control Plane

A self-hosted certificate lifecycle platform. Track, renew, and deploy TLS certificates across your infrastructure with a web dashboard, REST API, and agent-based architecture where private keys never leave your servers.

[![License](https://img.shields.io/badge/license-BSL%201.1-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/shankar0123/certctl)](https://goreportcard.com/report/github.com/shankar0123/certctl)
![Status: Active Development](https://img.shields.io/badge/status-active%20development-green)

## What It Does

certctl gives you a single pane of glass for every TLS certificate in your organization. The **web dashboard** shows your full certificate inventory — what's healthy, what's expiring, what's already expired, and who owns each one. The **REST API** (40+ endpoints) lets you automate everything. **Agents** deployed on your infrastructure handle certificate deployment, and key generation moves to agents in M8 so private keys never leave your servers.

```mermaid
flowchart LR
    subgraph "Control Plane"
        API["REST API + Dashboard\n:8443"]
        PG[("PostgreSQL")]
    end

    subgraph "Your Infrastructure"
        A1["Agent"] --> T1["NGINX"]
        A2["Agent"] --> T2["F5 BIG-IP"]
        A3["Agent"] --> T3["IIS"]
    end

    API --> PG
    A1 & A2 & A3 -->|"CSR + status\n(no private keys)"| API
    API -->|"Signed certs"| A1 & A2 & A3
    API -->|"Issue/Renew"| CA["Certificate Authorities\nLocal CA · ACME"]
```

## Quick Start

### Docker Compose (Recommended)

```bash
git clone https://github.com/shankar0123/certctl.git
cd certctl
docker compose -f deploy/docker-compose.yml up -d
```

Wait ~30 seconds, then open **http://localhost:8443** in your browser.

The dashboard comes pre-loaded with 14 demo certificates, 5 agents, policy rules, audit events, and notifications — a realistic snapshot of a certificate inventory so you can explore immediately.

Verify the API:
```bash
curl http://localhost:8443/health
# {"status":"healthy"}

curl -s http://localhost:8443/api/v1/certificates | jq '.total'
# 14
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
        PG[("PostgreSQL 16\n14 tables · TEXT primary keys")]
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

- **Private keys isolated from the control plane (M8 goal).** Currently, the Local CA issuer generates server-side keys for simplicity. M8 moves key generation to agents — agents generate keys locally and submit CSRs (public key only). The architecture is designed for this separation; server-side keygen will be flagged as demo-only.
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
| `agents` | Registered agents with heartbeat tracking |
| `jobs` | Issuance, renewal, deployment, and validation jobs |
| `teams` | Organizational groups for certificate ownership |
| `owners` | Individual owners with email for notifications |
| `policy_rules` | Enforcement rules (allowed issuers, environments, metadata) |
| `policy_violations` | Flagged non-compliance with severity levels |
| `audit_events` | Immutable action log (append-only, no update/delete) |
| `notification_events` | Email and webhook notification records |
| `certificate_target_mappings` | Many-to-many cert ↔ target relationships |

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
| `CERTCTL_ACME_DIRECTORY_URL` | — | ACME directory URL (e.g., Let's Encrypt staging) |
| `CERTCTL_ACME_EMAIL` | — | Contact email for ACME account registration |

Agent environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SERVER_URL` | `http://localhost:8080` | Control plane URL |
| `CERTCTL_API_KEY` | — | Agent API key |
| `CERTCTL_AGENT_NAME` | `certctl-agent` | Agent display name |
| `CERTCTL_AGENT_ID` | — | Registered agent ID (required) |

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
POST   /api/v1/issuers/{id}/test          Test connectivity

GET    /api/v1/targets                    List deployment targets
POST   /api/v1/targets                    Create
GET    /api/v1/targets/{id}               Get
```

### Organization
```
GET    /api/v1/teams                      List teams
POST   /api/v1/teams                      Create
GET    /api/v1/owners                     List owners
POST   /api/v1/owners                     Create
```

### Operations
```
GET    /api/v1/jobs                       List (filter: status, type)
GET    /api/v1/jobs/{id}                  Get
POST   /api/v1/jobs/{id}/cancel           Cancel

GET    /api/v1/policies                   List policy rules
POST   /api/v1/policies                   Create
GET    /api/v1/policies/{id}/violations   List violations for rule

GET    /api/v1/audit                      Query audit trail
GET    /api/v1/notifications              List notifications
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
| Local CA (self-signed) | Implemented | `GenericCA` |
| ACME v2 (Let's Encrypt, Sectigo) | Implemented (HTTP-01) | `ACME` |
| Vault PKI | Planned | — |
| DigiCert | Planned | — |

### Deployment Targets
| Target | Status | Type |
|--------|--------|------|
| NGINX | Implemented | `NGINX` |
| F5 BIG-IP | Implemented | `F5` |
| Microsoft IIS | Implemented | `IIS` |
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
- **V1 (Local CA)**: The control plane generates ephemeral RSA-2048 keys server-side for certificate issuance. This simplifies the initial implementation but means private keys exist on the control plane temporarily. Keys are stored in certificate version records.
- **M8+**: Private keys will be generated exclusively on agents, never sent to the control plane. Keys stored with file permissions 0600 and rotated after successful renewal.

### Authentication
- Agent-to-server: API key (registered at agent creation)
- API key and JWT auth types supported; `none` for demo/development
- Auth type and secret configured via `CERTCTL_AUTH_TYPE` and `CERTCTL_AUTH_SECRET`

### Audit Trail
- Immutable append-only log in PostgreSQL (`audit_events` table)
- Every action attributed to an actor with timestamp and resource reference
- No update or delete operations on audit records

## Roadmap

### V1 (in progress → v1.0.0)
Backend complete: end-to-end lifecycle, Local CA + ACME v2 issuers, NGINX/F5/IIS targets, threshold alerting. GUI fully wired to real API with 11 views. CI pipeline running. Remaining milestones before v1.0 tag:
- **M7: Auth + Rate Limiting** — API key auth enforced by default, token bucket rate limiting, CORS configuration, GUI login flow
- **M8: Agent-Side Key Generation** — agents generate keys locally, submit CSR only, private keys never leave infrastructure, server-side keygen flagged as demo-only
- **M9: End-to-End Test Hardening** — handler tests for all 7 files, negative-path integration tests (issuer down, malformed CSR, DB failure), scheduler and connector tests, CI coverage gates (service 70%+, handler 60%+)

### V2: Operational Maturity
- **V2.0: Operational Workflows** — renewal approval UI, bulk cert operations, deployment timeline, real-time updates (SSE/WebSocket), target config wizard
- **V2.1: Team Adoption** — OIDC/SSO, RBAC, CLI tool, Slack/Teams notifiers, bulk cert import
- **V2.2: Observability** — expiration calendar, health scores, Prometheus metrics, deployment rollback

### V3: Discovery & Visibility
Certificate discovery (passive/active scanning), unknown cert detection, triage workflows in GUI

### V4+: Platform & Scale
Kubernetes CRD, Terraform provider, multi-region, HA control plane, HSM support

## License

Certctl is licensed under the [Business Source License 1.1](LICENSE). The source code is publicly available and free to use, modify, and self-host. The one restriction: you may not offer certctl as a managed/hosted certificate management service to third parties.

On **March 14, 2033** (7 years from initial release), the license automatically converts to [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) and all restrictions are removed.

For commercial licensing inquiries, contact skreddy040@gmail.com.
