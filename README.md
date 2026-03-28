<p align="center">
  <img src="docs/screenshots/logo/certctl-logo.png" alt="certctl logo" width="450">
</p>

<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=89db181e-76e0-45cc-b9c0-790c3dfdfc73" />
<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=b9379aff-9e5c-4d01-8f2d-9e4ffa09d126" />

# certctl — Self-Hosted Certificate Lifecycle Platform

```mermaid
timeline
    title TLS Certificate Maximum Lifespan (CA/Browser Forum Ballot SC-081v3)
    2015 : 5 years
    2018 : 825 days
    2020 : 398 days
    March 2026 : 200 days
    March 2027 : 100 days
    March 2029 : 47 days
```

TLS certificate lifespans are shrinking fast. The CA/Browser Forum passed [Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) unanimously in April 2025, setting a phased reduction: **200 days** by March 2026, **100 days** by March 2027, and **47 days** by March 2029. Organizations managing dozens or hundreds of certificates can no longer rely on spreadsheets, calendar reminders, or manual renewal workflows. The math doesn't work — at 47-day lifespans, a team managing 100 certificates is processing 7+ renewals per week, every week, forever.

certctl is a self-hosted platform that automates the entire certificate lifecycle — from issuance through renewal to deployment — with zero human intervention. It works with any certificate authority, deploys to any server, and keeps private keys on your infrastructure where they belong.

[![License](https://img.shields.io/badge/license-BSL%201.1-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/shankar0123/certctl)](https://goreportcard.com/report/github.com/shankar0123/certctl)
[![GitHub Release](https://img.shields.io/github/v/release/shankar0123/certctl)](https://github.com/shankar0123/certctl/releases)

## Documentation

| Guide | Description |
|-------|-------------|
| [Why certctl?](docs/why-certctl.md) | Competitive positioning — how certctl compares to open-source and enterprise certificate management platforms |
| [Concepts](docs/concepts.md) | TLS certificates explained from scratch — for beginners who know nothing about certs |
| [Quick Start](docs/quickstart.md) | Get running in 5 minutes — dashboard, API, CLI, discovery, stakeholder demo flow |
| [Advanced Demo](docs/demo-advanced.md) | Issue a certificate end-to-end with technical deep-dives |
| [Architecture](docs/architecture.md) | System design, data flow diagrams, security model |
| [Feature Inventory](docs/features.md) | Complete reference of all V2 capabilities, API endpoints, and configuration |
| [Connectors](docs/connectors.md) | Build custom issuer, target, and notifier connectors |
| [Compliance Mapping](docs/compliance.md) | SOC 2 Type II, PCI-DSS 4.0, NIST SP 800-57 alignment guides |

> **Next release:** v2.1.0 will be tagged after the full V2 feature suite passes manual QA across all 34 sections of the [testing guide](docs/testing-guide.md). Automated CI (1,471 Go tests + 193 frontend tests) gates every commit; the manual playbook covers integration, deployment, and UX verification that unit tests can't reach.

## Why certctl Exists

Certificate lifecycle tooling today falls into two camps: expensive enterprise platforms (Venafi, Keyfactor, Sectigo) that cost six figures and take months to deploy, or single-purpose tools (cert-manager, certbot) that handle one slice of the problem. If you run a mixed infrastructure — some NGINX, some Apache, a few HAProxy nodes, maybe an F5 — and you need to manage certificates from multiple CAs, there's nothing self-hosted that covers the full lifecycle without vendor lock-in.

certctl fills that gap. It's **CA-agnostic** — the issuer connector interface means you can plug in any certificate authority: a self-signed local CA for dev, Let's Encrypt via ACME for public certs, Smallstep step-ca for your private PKI, your enterprise ADCS via sub-CA mode, or any custom CA through a shell script adapter. You're never locked to a single CA vendor, and you can run multiple issuers simultaneously for different certificate types.

It's also **target-agnostic**. Agents deploy certificates to NGINX, Apache, HAProxy, Traefik, and Caddy — all using the same pluggable connector model for any server that accepts cert files. The control plane never initiates outbound connections — agents poll for work, which means certctl works behind firewalls, across network zones, and in air-gapped environments.

For a detailed comparison with CertKit, KeyTalk, and enterprise platforms (Venafi, Keyfactor), see [Why certctl?](docs/why-certctl.md)

## What It Does

certctl gives you a single pane of glass for every TLS certificate in your organization:

- **Web dashboard** — 22 operational pages: certificate inventory, deployment timeline with TLS verification, bulk operations (renew/revoke/reassign), discovery triage, network scan management, approval workflows, audit trail with CSV/JSON export, agent fleet overview with OS/arch grouping, short-lived credential monitoring
- **REST API** — 95 endpoints under `/api/v1/` + `/.well-known/est/` for complete automation, with sparse fields, sort, cursor pagination, and time-range filters
- **Agents** — generate private keys locally (ECDSA P-256), discover existing certs on disk (PEM/DER), submit CSRs only (private keys never leave your servers)
- **Network scanner** — discovers certificates on TLS endpoints across CIDR ranges without requiring agents, concurrent scanning with configurable timeouts
- **Certificate export** — PEM (JSON or file download) and PKCS#12 formats, with audit trail; private keys never included
- **S/MIME + EKU support** — issue certificates with emailProtection, codeSigning, timeStamping, clientAuth EKUs; email SAN routing for S/MIME
- **EST server** (RFC 7030) — device and WiFi certificate enrollment via industry-standard protocol
- **Post-deployment verification** — agent-side TLS probe confirms the target serves the correct certificate by SHA-256 fingerprint match
- **Approval workflows** — require human sign-off on renewals before deployment
- **Background scheduler** — 6 automated loops: renewal checks, job processing, agent health, notifications, short-lived cert expiry, and network scanning

For the full capability breakdown — revocation infrastructure, policy engine, observability, EST enrollment, and more — see the [Feature Inventory](docs/features.md).

## Supported Integrations

### Certificate Issuers
| Issuer | Status | Type |
|--------|--------|------|
| Local CA (self-signed + sub-CA) | Implemented | `GenericCA` |
| ACME v2 (Let's Encrypt, Sectigo) | Implemented (HTTP-01 + DNS-01 + DNS-PERSIST-01) | `ACME` |
| ACME EAB (ZeroSSL, Google Trust) | Implemented (auto-fetch EAB from ZeroSSL) | `ACME` |
| step-ca | Implemented | `StepCA` |
| OpenSSL / Custom CA | Implemented | `OpenSSL` |
| Vault PKI | Future | — |
| DigiCert | Future | — |

**Note:** ADCS integration is handled via the Local CA's sub-CA mode — certctl operates as a subordinate CA with its signing certificate issued by ADCS. Any CA with a shell-accessible signing interface can be integrated today via the OpenSSL/Custom CA connector.

### Deployment Targets
| Target | Status | Type |
|--------|--------|------|
| NGINX | Implemented | `NGINX` |
| Apache httpd | Implemented | `Apache` |
| HAProxy | Implemented | `HAProxy` |
| Traefik | Implemented | `Traefik` |
| Caddy | Implemented | `Caddy` |
| F5 BIG-IP | Interface only | `F5` |
| Microsoft IIS | Interface only | `IIS` |

### Notifiers
| Notifier | Status | Type |
|----------|--------|------|
| Email (SMTP) | Implemented | `Email` |
| Webhooks | Implemented | `Webhook` |
| Slack | Implemented | `Slack` |
| Microsoft Teams | Implemented | `Teams` |
| PagerDuty | Implemented | `PagerDuty` |
| OpsGenie | Implemented | `OpsGenie` |

All connectors are pluggable — build your own by implementing the [connector interface](docs/connectors.md).

### Screenshots

<table>
<tr>
<td><a href="docs/screenshots/v2-dashboard.png"><img src="docs/screenshots/v2-dashboard.png" width="270" alt="Dashboard"></a><br><b>Dashboard</b><br><sub>Stats, expiration heatmap, renewal trends</sub></td>
<td><a href="docs/screenshots/v2-certificates.png"><img src="docs/screenshots/v2-certificates.png" width="270" alt="Certificates"></a><br><b>Certificates</b><br><sub>Inventory with status, owner, team filters</sub></td>
<td><a href="docs/screenshots/v2-agents.png"><img src="docs/screenshots/v2-agents.png" width="270" alt="Agents"></a><br><b>Agents</b><br><sub>Fleet health, OS/arch, IP, version</sub></td>
</tr>
<tr>
<td><a href="docs/screenshots/v2-fleet.png"><img src="docs/screenshots/v2-fleet.png" width="270" alt="Fleet Overview"></a><br><b>Fleet Overview</b><br><sub>OS distribution, status breakdown</sub></td>
<td><a href="docs/screenshots/v2-jobs.png"><img src="docs/screenshots/v2-jobs.png" width="270" alt="Jobs"></a><br><b>Jobs</b><br><sub>Issuance, renewal, deployment queue</sub></td>
<td><a href="docs/screenshots/v2-notifications.png"><img src="docs/screenshots/v2-notifications.png" width="270" alt="Notifications"></a><br><b>Notifications</b><br><sub>Expiration warnings, renewal results</sub></td>
</tr>
<tr>
<td><a href="docs/screenshots/v2-policies.png"><img src="docs/screenshots/v2-policies.png" width="270" alt="Policies"></a><br><b>Policies</b><br><sub>Ownership, lifetime, renewal rules</sub></td>
<td><a href="docs/screenshots/v2-profiles.png"><img src="docs/screenshots/v2-profiles.png" width="270" alt="Profiles"></a><br><b>Profiles</b><br><sub>Key types, max TTL, crypto constraints</sub></td>
<td><a href="docs/screenshots/v2-issuers.png"><img src="docs/screenshots/v2-issuers.png" width="270" alt="Issuers"></a><br><b>Issuers</b><br><sub>Local CA, ACME, step-ca connectors</sub></td>
</tr>
<tr>
<td><a href="docs/screenshots/v2-targets.png"><img src="docs/screenshots/v2-targets.png" width="270" alt="Targets"></a><br><b>Targets</b><br><sub>NGINX, Apache, HAProxy, Traefik, Caddy deployment</sub></td>
<td><a href="docs/screenshots/v2-owners.png"><img src="docs/screenshots/v2-owners.png" width="270" alt="Owners"></a><br><b>Owners</b><br><sub>Cert ownership with team assignment</sub></td>
<td><a href="docs/screenshots/v2-teams.png"><img src="docs/screenshots/v2-teams.png" width="270" alt="Teams"></a><br><b>Teams</b><br><sub>Org grouping for notification routing</sub></td>
</tr>
<tr>
<td><a href="docs/screenshots/v2-agent-groups.png"><img src="docs/screenshots/v2-agent-groups.png" width="270" alt="Agent Groups"></a><br><b>Agent Groups</b><br><sub>Dynamic grouping by OS, arch, CIDR</sub></td>
<td><a href="docs/screenshots/v2-audit-trail.png"><img src="docs/screenshots/v2-audit-trail.png" width="270" alt="Audit Trail"></a><br><b>Audit Trail</b><br><sub>Immutable log, CSV/JSON export</sub></td>
<td><a href="docs/screenshots/v2-short-lived.png"><img src="docs/screenshots/v2-short-lived.png" width="270" alt="Short-Lived"></a><br><b>Short-Lived Creds</b><br><sub>Ephemeral certs with live TTL countdown</sub></td>
</tr>
</table>

> **22 operational GUI pages** covering the full certificate lifecycle: dashboard, certificates (list + detail with EKU badges, deployment timeline, TLS verification status), agents, fleet overview, jobs (with approval workflow), notifications, policies, profiles, issuers, targets (wizard with NGINX/Apache/HAProxy/Traefik/Caddy/F5/IIS), owners, teams, agent groups, audit trail, short-lived credentials, discovery triage, and network scan management.

## Quick Start

### Docker Pull

```bash
docker pull shankar0123.docker.scarf.sh/certctl-server
docker pull shankar0123.docker.scarf.sh/certctl-agent
```

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
# Prerequisites: Go 1.25+, PostgreSQL 16+
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

## Architecture

**Control plane** (Go 1.25 net/http) → **PostgreSQL 16** (21 tables, TEXT primary keys) → **Agents** (key generation, CSR submission, cert deployment). Background scheduler runs 6 loops: renewal checks (1h), job processing (30s), agent health (2m), notifications (1m), short-lived cert expiry (30s), network scanning (6h). See [Architecture Guide](docs/architecture.md) for full system diagrams and data flow.

### Key Design Decisions

- **Private keys isolated from the control plane.** Agents generate ECDSA P-256 keys locally and submit CSRs (public key only). The server signs the CSR and returns the certificate — private keys never touch the control plane. Server-side keygen is available via `CERTCTL_KEYGEN_MODE=server` for demo/development only.
- **TEXT primary keys, not UUIDs.** IDs are human-readable prefixed strings (`mc-api-prod`, `t-platform`, `o-alice`) so you can identify resource types at a glance in logs and queries.
- **Handler → Service → Repository layering.** Handlers define their own service interfaces for clean dependency inversion. No global service singletons.
- **Idempotent migrations.** All schema uses `IF NOT EXISTS` and seed data uses `ON CONFLICT (id) DO NOTHING`, safe for repeated execution.

PostgreSQL 16 with 21 tables covering certificates, versions, policies, issuers, targets, agents, jobs, teams, owners, profiles, agent groups, revocations, discovery, network scans, and audit events. See the [Architecture Guide](docs/architecture.md) for the full schema.

## Configuration

All environment variables use the `CERTCTL_` prefix. Full reference below (39 variables across server, agent, and connector config).

### Server — Core

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SERVER_HOST` | `127.0.0.1` | Server bind address |
| `CERTCTL_SERVER_PORT` | `8080` | Server listen port (1–65535) |
| `CERTCTL_DATABASE_URL` | `postgres://localhost/certctl` | PostgreSQL connection string (required) |
| `CERTCTL_DATABASE_MAX_CONNS` | `25` | PostgreSQL connection pool size (min 1) |
| `CERTCTL_DATABASE_MIGRATIONS_PATH` | `./migrations` | Path to migration SQL files |
| `CERTCTL_MAX_BODY_SIZE` | `1048576` | Max HTTP request body in bytes (default 1MB) |
| `CERTCTL_LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `CERTCTL_LOG_FORMAT` | `json` | Log format: `json` (structured) or `text` (human-readable) |

### Server — Auth, CORS, Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_AUTH_TYPE` | `api-key` | Auth mode: `api-key`, `jwt`, or `none` (demo only) |
| `CERTCTL_AUTH_SECRET` | — | Required for `api-key` and `jwt` auth types |
| `CERTCTL_CORS_ORIGINS` | *(empty = deny all)* | Comma-separated allowed origins, or `*` for dev |
| `CERTCTL_RATE_LIMIT_ENABLED` | `true` | Enable token bucket rate limiting |
| `CERTCTL_RATE_LIMIT_RPS` | `50` | Requests per second per client |
| `CERTCTL_RATE_LIMIT_BURST` | `100` | Max burst size |
| `CERTCTL_KEYGEN_MODE` | `agent` | Key generation: `agent` (production) or `server` (demo only) |

### Server — Scheduler

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL` | `1h` | How often to check expiring certs (min 1m) |
| `CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL` | `30s` | How often to process pending jobs (min 1s) |
| `CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL` | `2m` | Agent heartbeat check frequency (min 1s) |
| `CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL` | `1m` | Notification send frequency (min 1s) |

### Server — Sub-CA Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_CA_CERT_PATH` | — | PEM-encoded CA certificate for sub-CA mode |
| `CERTCTL_CA_KEY_PATH` | — | PEM-encoded CA private key (RSA, ECDSA, PKCS#8) |

### Server — Feature Flags

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_EST_ENABLED` | `false` | Enable RFC 7030 EST enrollment endpoints |
| `CERTCTL_EST_ISSUER_ID` | `iss-local` | Which issuer processes EST enrollments |
| `CERTCTL_EST_PROFILE_ID` | — | Constrain EST to a specific certificate profile |
| `CERTCTL_NETWORK_SCAN_ENABLED` | `false` | Enable server-side TLS network scanning |
| `CERTCTL_NETWORK_SCAN_INTERVAL` | `6h` | How often scheduled scans run |
| `CERTCTL_VERIFY_DEPLOYMENT` | `true` | TLS verification after certificate deployment |
| `CERTCTL_VERIFY_TIMEOUT` | `10s` | TLS probe timeout |
| `CERTCTL_VERIFY_DELAY` | `2s` | Delay before verification probe |

### Server — Notification Connectors

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SLACK_WEBHOOK_URL` | — | Slack incoming webhook URL (enables Slack) |
| `CERTCTL_SLACK_CHANNEL` | — | Override default webhook channel |
| `CERTCTL_SLACK_USERNAME` | `certctl` | Bot display name |
| `CERTCTL_TEAMS_WEBHOOK_URL` | — | Microsoft Teams webhook URL (enables Teams) |
| `CERTCTL_PAGERDUTY_ROUTING_KEY` | — | PagerDuty Events API v2 key (enables PagerDuty) |
| `CERTCTL_PAGERDUTY_SEVERITY` | `warning` | Event severity: `info`, `warning`, `error`, `critical` |
| `CERTCTL_OPSGENIE_API_KEY` | — | OpsGenie Alert API key (enables OpsGenie) |
| `CERTCTL_OPSGENIE_PRIORITY` | `P3` | Alert priority: `P1`–`P5` |

### Agent

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SERVER_URL` | `http://localhost:8080` | Control plane URL |
| `CERTCTL_API_KEY` | — | Agent API key for authentication |
| `CERTCTL_AGENT_ID` | — | Registered agent ID (required) |
| `CERTCTL_KEY_DIR` | `/var/lib/certctl/keys` | Private key storage directory (0600 perms) |
| `CERTCTL_DISCOVERY_DIRS` | — | Directories to scan for existing certs (comma-separated) |

Docker Compose overrides for the demo stack are in `deploy/docker-compose.yml`.

## Development

```bash
# Install dev tools (golangci-lint, migrate CLI, air)
make install-tools

# Run tests
make test

# Run tests with race detection (same as CI)
go test -race ./internal/service/... ./internal/api/handler/... ./internal/api/middleware/... ./internal/scheduler/... ./internal/connector/... ./internal/domain/... ./internal/validation/...

# Run with coverage
make test-coverage

# Lint (runs golangci-lint with project config)
make lint

# Vulnerability scan
govulncheck ./...

# Format
make fmt
```

### CI Pipeline

Every push and PR runs: `go vet`, `go test -race` (race detection), `golangci-lint` (11 linters including gosec and bodyclose), `govulncheck` (dependency CVE scanning), and per-layer coverage thresholds (service 60%, handler 60%, domain 40%, middleware 50%). Frontend CI runs TypeScript type checking, Vitest tests, and Vite production build. See `.github/workflows/ci.yml` for details.

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

### CORS
- **Deny-by-default**: Empty `CERTCTL_CORS_ORIGINS` blocks all cross-origin requests. Operators must explicitly list allowed origins (comma-separated) or set `*` for development.

### Input Validation
- Shell command injection prevention on all connector scripts (strict character whitelist, no metacharacters)
- RFC 1123 domain name validation, base64url ACME token validation
- SSRF protection in network scanner (loopback, link-local, multicast, broadcast ranges filtered)

### Concurrency Safety
- Scheduler loops protected by `sync/atomic.Bool` idempotency guards — duplicate ticks are skipped
- Graceful shutdown waits up to 30 seconds for in-flight work before database close

### Audit Trail
- Immutable append-only log in PostgreSQL (`audit_events` table)
- Every lifecycle action attributed to an actor with timestamp and resource reference
- No update or delete operations on audit records
- Every API call recorded to audit trail with method, path, actor, SHA-256 body hash, response status, and latency

## API Overview

95 endpoints under `/api/v1/` + `/.well-known/est/`, all returning JSON. List endpoints support pagination, sparse field selection (`?fields=`), sort (`?sort=-notAfter`), time-range filters, and cursor-based pagination. Full request/response schemas in the [OpenAPI 3.1 spec](api/openapi.yaml).

### Key Endpoints
```
# Certificate lifecycle
GET    /api/v1/certificates              List (filter, sort, cursor, sparse fields)
POST   /api/v1/certificates/{id}/renew   Trigger renewal → 202 Accepted
POST   /api/v1/certificates/{id}/revoke  Revoke with RFC 5280 reason code
GET    /api/v1/certificates/{id}/export/pem    Export PEM (JSON or file download)
POST   /api/v1/certificates/{id}/export/pkcs12 Export PKCS#12 bundle (no private key)
GET    /api/v1/crl/{issuer_id}           DER-encoded X.509 CRL
GET    /api/v1/ocsp/{issuer_id}/{serial} OCSP responder (good/revoked/unknown)

# Agent operations
POST   /api/v1/agents/{id}/csr           Submit CSR for issuance
GET    /api/v1/agents/{id}/work          Poll for pending deployment jobs
POST   /api/v1/agents/{id}/discoveries   Submit certificate discovery scan results

# Discovery & network scanning
GET    /api/v1/discovered-certificates   List discovered certs (?agent_id, ?status)
POST   /api/v1/discovered-certificates/{id}/claim  Link to managed cert
POST   /api/v1/network-scan-targets/{id}/scan      Trigger immediate TLS scan

# Jobs & approval
POST   /api/v1/jobs/{id}/approve         Approve interactive renewal
POST   /api/v1/jobs/{id}/reject          Reject interactive renewal

# Post-deployment verification
POST   /api/v1/jobs/{id}/verify          Submit TLS verification result
GET    /api/v1/jobs/{id}/verification    Get verification status

# Observability
GET    /api/v1/metrics/prometheus         Prometheus exposition format
GET    /api/v1/stats/summary             Dashboard summary

# EST enrollment (RFC 7030)
POST   /.well-known/est/simpleenroll     Device certificate enrollment
GET    /.well-known/est/cacerts          CA certificate chain (PKCS#7)
```

Full CRUD is available for certificates, agents, issuers, targets, teams, owners, policies, profiles, agent groups, notifications, and audit events. See the [OpenAPI spec](api/openapi.yaml) or [Feature Inventory](docs/features.md) for the complete endpoint reference.

## CLI

```bash
# Install
go install github.com/shankar0123/certctl/cmd/cli@latest

# Configure
export CERTCTL_SERVER_URL=http://localhost:8443
export CERTCTL_API_KEY=your-api-key

# Certificate commands
certctl-cli certs list                    # List all certificates
certctl-cli certs get mc-api-prod         # Get certificate details
certctl-cli certs renew mc-api-prod       # Trigger renewal
certctl-cli certs revoke mc-api-prod --reason keyCompromise

# Agent and job commands
certctl-cli agents list                   # List registered agents
certctl-cli jobs list                     # List jobs
certctl-cli jobs cancel job-123           # Cancel a pending job

# Operations
certctl-cli status                        # Server health + summary stats
certctl-cli import certs.pem              # Bulk import from PEM file

# Output formats
certctl-cli certs list --format json      # JSON output (default: table)
```

## MCP Server (AI Integration)

certctl ships a standalone MCP (Model Context Protocol) server that exposes all 78 API endpoints as tools for AI assistants — Claude, Cursor, Windsurf, OpenClaw, VS Code Copilot, and any MCP-compatible client.

```bash
# Install
go install github.com/shankar0123/certctl/cmd/mcp-server@latest

# Configure
export CERTCTL_SERVER_URL=http://localhost:8443
export CERTCTL_API_KEY=your-api-key

# Run (stdio transport — add to your AI client config)
mcp-server
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "certctl": {
      "command": "mcp-server",
      "env": {
        "CERTCTL_SERVER_URL": "http://localhost:8443",
        "CERTCTL_API_KEY": "your-api-key"
      }
    }
  }
}
```

## Roadmap

### V1 (v1.0.0)
Core lifecycle management — Local CA + ACME v2 issuers, NGINX target connector, agent-side key generation, API auth + rate limiting, React dashboard, CI pipeline with coverage gates, Docker images on GHCR.

### V2: Operational Maturity

21 milestones complete, 1100+ tests. See the [Feature Inventory](docs/features.md) for details on every capability.

**What shipped (all ✅):**

- **Issuers** — Sub-CA mode (enterprise root chains), ACME DNS-01 + DNS-PERSIST-01 (wildcard certs, any DNS provider), step-ca (native /sign API), OpenSSL/Custom CA (script-based signing)
- **Revocation** — RFC 5280 reason codes, DER-encoded X.509 CRL, embedded OCSP responder, short-lived cert exemption
- **Profiles + Ownership** — certificate profiles (key types, max TTL, crypto constraints), ownership tracking (owners + teams), dynamic agent groups, interactive renewal approval
- **GUI Operations** — bulk renew/revoke/reassign, deployment timeline, inline policy editor, target wizard, audit export (CSV/JSON), short-lived credentials view
- **Discovery** — filesystem scanning (PEM/DER) + network TLS scanning (CIDR ranges), triage workflow (claim/dismiss), network scan target management
- **Observability** — Prometheus + JSON metrics, 5 stats API endpoints, dashboard charts (heatmap, trends, distribution), agent fleet overview, structured logging
- **EST Server** (RFC 7030) — device/WiFi certificate enrollment, PKCS#7 wire format, configurable issuer + profile binding
- **MCP Server** — 78 API operations as AI tools for Claude, Cursor, and any MCP-compatible client
- **CLI** — 12 subcommands (list/get/renew/revoke certs, agents, jobs, import, status), JSON/table output
- **Notifications** — Slack, Microsoft Teams, PagerDuty, OpsGenie connectors
- **API Enhancements** — sparse fields, sort, time-range filters, cursor pagination, immutable API audit logging
- **Compliance Mapping** — SOC 2 Type II, PCI-DSS 4.0, NIST SP 800-57 alignment guides

- **Post-Deployment TLS Verification** — agent-side TLS probe confirms the target is serving the correct certificate by SHA-256 fingerprint match, verification status visible in deployment timeline
- **Traefik + Caddy Targets** — Traefik (file provider, auto-reload) and Caddy (Admin API hot-reload or file-based), both in target wizard GUI
- **Certificate Export** — PEM (JSON or file download) and PKCS#12 formats, private keys never included (agent-side only), audit trail, GUI export buttons
- **S/MIME Support** — EKU-aware issuance (emailProtection, codeSigning, timeStamping), adaptive KeyUsage flags, email SAN routing, EKU badges in GUI

### V3: certctl Pro

Team access controls, identity provider integration, enterprise deployment targets, compliance and risk scoring, advanced fleet operations, event-driven architecture, advanced search, real-time operational views, and premium CA integrations.

### V4+: Cloud, Scale & Passive Discovery
Passive network discovery (TLS listener), Kubernetes integration (cert-manager external issuer, Secrets target), cloud infrastructure targets (AWS ALB/ACM, Azure Key Vault), extended CA support (Vault PKI, Google CAS, EJBCA), and platform-scale features (Terraform provider, multi-tenancy, HSM support).

## License

Certctl is licensed under the [Business Source License 1.1](LICENSE). The source code is publicly available and free to use, modify, and self-host. The one restriction: you may not offer certctl as a managed/hosted certificate management service to third parties.

For licensing inquiries: certctl@proton.me

