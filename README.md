<p align="center">
  <img src="docs/screenshots/logo/certctl-logo.png" alt="certctl logo" width="450">
</p>

<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=89db181e-76e0-45cc-b9c0-790c3dfdfc73" />
<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=b9379aff-9e5c-4d01-8f2d-9e4ffa09d126" />

# certctl — Self-Hosted Certificate Lifecycle Platform

95+ API endpoints. 21 database tables. 930+ tests. Full GUI. Ships with Docker Compose.

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
![Version: v2.0.1](https://img.shields.io/badge/version-v2.0.1-brightgreen)

## Documentation

| Guide | Description |
|-------|-------------|
| [Concepts](docs/concepts.md) | TLS certificates explained from scratch — for beginners who know nothing about certs |
| [Quick Start](docs/quickstart.md) | Get running in 5 minutes — dashboard, API, CLI, discovery, stakeholder demo flow |
| [Advanced Demo](docs/demo-advanced.md) | Issue a certificate end-to-end with technical deep-dives |
| [Architecture](docs/architecture.md) | System design, data flow diagrams, security model |
| [Connectors](docs/connectors.md) | Build custom issuer, target, and notifier connectors |
| [Compliance Mapping](docs/compliance.md) | SOC 2 Type II, PCI-DSS 4.0, NIST SP 800-57 alignment guides |
| [Manual Testing Guide](docs/testing-guide.md) | 284 tests across 25 areas — full V2 QA runbook with exact commands and pass/fail criteria |

## Contents

- [Why certctl Exists](#why-certctl-exists)
- [What It Does](#what-it-does)
- [Screenshots](#screenshots)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [MCP Server (AI Integration)](#mcp-server-ai-integration)
- [CLI](#cli)
- [API Overview](#api-overview)
- [Supported Integrations](#supported-integrations)
- [Development](#development)
- [Security](#security)
- [Roadmap](#roadmap)
- [License](#license)

## Why certctl Exists

Certificate lifecycle tooling today falls into two camps: expensive enterprise platforms (Venafi, Keyfactor, Sectigo) that cost six figures and take months to deploy, or single-purpose tools (cert-manager, certbot) that handle one slice of the problem. If you run a mixed infrastructure — some NGINX, some Apache, a few HAProxy nodes, maybe an F5 — and you need to manage certificates from multiple CAs, there's nothing self-hosted that covers the full lifecycle without vendor lock-in.

certctl fills that gap. It's **CA-agnostic** — the issuer connector interface means you can plug in any certificate authority: a self-signed local CA for dev, Let's Encrypt via ACME for public certs, Smallstep step-ca for your private PKI, your enterprise ADCS via sub-CA mode, or any custom CA through a shell script adapter. You're never locked to a single CA vendor, and you can run multiple issuers simultaneously for different certificate types.

It's also **target-agnostic**. Agents deploy certificates to NGINX, Apache, and HAProxy today, with Traefik and Caddy support coming next — all using the same pluggable connector model for any server that accepts cert files. The control plane never initiates outbound connections — agents poll for work, which means certctl works behind firewalls, across network zones, and in air-gapped environments.

## What It Does

certctl gives you a single pane of glass for every TLS certificate in your organization. The **web dashboard** shows your full certificate inventory — what's healthy, what's expiring, what's already expired, and who owns each one. The **REST API** (95 endpoints under `/api/v1/` + `/.well-known/est/`) lets you automate everything. **Agents** deployed on your infrastructure generate private keys locally, discover existing certificates on disk, and submit CSRs — private keys never leave your servers. The **network scanner** discovers certificates on TLS endpoints across your infrastructure without requiring agents. The **EST server** (RFC 7030) enables device and WiFi certificate enrollment via industry-standard Enrollment over Secure Transport. The background scheduler watches expiration dates and triggers renewals automatically — when certificate lifespans drop to 47 days, certctl handles the constant rotation without human involvement.

**Core capabilities:**

- **Full lifecycle automation** — issuance, renewal, deployment, and revocation with zero human intervention. Configurable renewal policies trigger jobs automatically based on expiration thresholds.
- **CA-agnostic issuer connectors** — Local CA (self-signed + sub-CA for enterprise root chains), ACME v2 with HTTP-01, DNS-01, and DNS-PERSIST-01 challenges (Let's Encrypt, Sectigo, any ACME-compatible CA), Smallstep step-ca (native /sign API), and OpenSSL/Custom CA (delegate to any shell script). Pluggable interface — add your own CA in one file.
- **Agent-side key generation** — agents generate ECDSA P-256 keys locally, store them with 0600 permissions, and submit only the CSR. Private keys never touch the control plane. This is the default mode, not an opt-in feature.
- **Certificate discovery** — agents scan filesystems for existing PEM/DER certificates and report findings for triage. The network scanner probes TLS endpoints across CIDR ranges to find certificates you didn't know existed.
- **Revocation infrastructure** — RFC 5280 revocation with all standard reason codes, DER-encoded X.509 CRL per issuer, embedded OCSP responder, and short-lived certificate exemption (certs under 1 hour skip CRL/OCSP).
- **Policy engine** — 5 rule types with violation tracking and severity levels. Certificate profiles enforce allowed key types, maximum TTL, and crypto constraints at enrollment time.
- **Immutable audit trail** — every action recorded to an append-only log. Every API call recorded with method, path, actor, SHA-256 body hash, response status, and latency. No update or delete on audit records.
- **Operational dashboard** — Full React GUI with certificate inventory, bulk operations (multi-select renew/revoke/reassign), deployment timeline visualization, inline policy editing, agent fleet overview, expiration heatmaps, and real-time short-lived credential tracking.
- **Observability** — JSON and Prometheus metrics endpoints, 5 stats API endpoints for dashboards, structured slog logging with request ID propagation. Compatible with Prometheus, Grafana Agent, Datadog Agent, and Victoria Metrics.
- **Notifications** — threshold-based alerting with deduplication. Routes to email, webhooks, Slack, Microsoft Teams, PagerDuty, and OpsGenie.
- **EST enrollment (RFC 7030)** — built-in Enrollment over Secure Transport server for device certificate enrollment. Supports WiFi/802.1X, MDM, and IoT use cases. PKCS#7 certs-only wire format, accepts PEM or base64-encoded DER CSRs, configurable issuer and profile binding.
- **Multi-purpose certificates** — certificate profiles support arbitrary EKU (Extended Key Usage) constraints. TLS (serverAuth/clientAuth) today, with S/MIME (emailProtection) and code signing support coming in v2.0.2.
- **AI and CLI access** — MCP server exposes all 78 API operations as tools for Claude, Cursor, and any MCP-compatible client. CLI tool with 12 subcommands for terminal workflows and scripting.

### Screenshots

<table>
<tr>
<td><a href="docs/screenshots/v2/dashboard.png"><img src="docs/screenshots/v2/dashboard.png" width="270" alt="Dashboard"></a><br><b>Dashboard</b><br><sub>Stats, expiration heatmap, renewal trends</sub></td>
<td><a href="docs/screenshots/v2/certificates.png"><img src="docs/screenshots/v2/certificates.png" width="270" alt="Certificates"></a><br><b>Certificates</b><br><sub>Inventory with status, owner, team filters</sub></td>
<td><a href="docs/screenshots/v2/agents.png"><img src="docs/screenshots/v2/agents.png" width="270" alt="Agents"></a><br><b>Agents</b><br><sub>Fleet health, OS/arch, IP, version</sub></td>
</tr>
<tr>
<td><a href="docs/screenshots/v2/fleet-overview.png"><img src="docs/screenshots/v2/fleet-overview.png" width="270" alt="Fleet Overview"></a><br><b>Fleet Overview</b><br><sub>OS distribution, status breakdown</sub></td>
<td><a href="docs/screenshots/v2/jobs.png"><img src="docs/screenshots/v2/jobs.png" width="270" alt="Jobs"></a><br><b>Jobs</b><br><sub>Issuance, renewal, deployment queue</sub></td>
<td><a href="docs/screenshots/v2/notifications.png"><img src="docs/screenshots/v2/notifications.png" width="270" alt="Notifications"></a><br><b>Notifications</b><br><sub>Expiration warnings, renewal results</sub></td>
</tr>
<tr>
<td><a href="docs/screenshots/v2/policies.png"><img src="docs/screenshots/v2/policies.png" width="270" alt="Policies"></a><br><b>Policies</b><br><sub>Ownership, lifetime, renewal rules</sub></td>
<td><a href="docs/screenshots/v2/profiles.png"><img src="docs/screenshots/v2/profiles.png" width="270" alt="Profiles"></a><br><b>Profiles</b><br><sub>Key types, max TTL, crypto constraints</sub></td>
<td><a href="docs/screenshots/v2/issuers.png"><img src="docs/screenshots/v2/issuers.png" width="270" alt="Issuers"></a><br><b>Issuers</b><br><sub>Local CA, ACME, step-ca connectors</sub></td>
</tr>
<tr>
<td><a href="docs/screenshots/v2/targets.png"><img src="docs/screenshots/v2/targets.png" width="270" alt="Targets"></a><br><b>Targets</b><br><sub>NGINX, Apache, HAProxy deployment</sub></td>
<td><a href="docs/screenshots/v2/owners.png"><img src="docs/screenshots/v2/owners.png" width="270" alt="Owners"></a><br><b>Owners</b><br><sub>Cert ownership with team assignment</sub></td>
<td><a href="docs/screenshots/v2/teams.png"><img src="docs/screenshots/v2/teams.png" width="270" alt="Teams"></a><br><b>Teams</b><br><sub>Org grouping for notification routing</sub></td>
</tr>
<tr>
<td><a href="docs/screenshots/v2/agent-groups.png"><img src="docs/screenshots/v2/agent-groups.png" width="270" alt="Agent Groups"></a><br><b>Agent Groups</b><br><sub>Dynamic grouping by OS, arch, CIDR</sub></td>
<td><a href="docs/screenshots/v2/audit-trail.png"><img src="docs/screenshots/v2/audit-trail.png" width="270" alt="Audit Trail"></a><br><b>Audit Trail</b><br><sub>Immutable log, CSV/JSON export</sub></td>
<td><a href="docs/screenshots/v2/short-lived.png"><img src="docs/screenshots/v2/short-lived.png" width="270" alt="Short-Lived"></a><br><b>Short-Lived Creds</b><br><sub>Ephemeral certs with live TTL countdown</sub></td>
</tr>
</table>

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
| `discovered_certificates` | Filesystem and network-discovered certificates with fingerprint deduplication |
| `discovery_scans` | Discovery scan history with timestamps and agent attribution |
| `network_scan_targets` | Network scan target definitions with CIDRs, ports, schedule, and scan metrics |

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
| `CERTCTL_ACME_CHALLENGE_TYPE` | — | ACME challenge type: `http-01` (default), `dns-01`, or `dns-persist-01` |
| `CERTCTL_CA_CERT_PATH` | — | Path to CA certificate for sub-CA mode |
| `CERTCTL_CA_KEY_PATH` | — | Path to CA private key for sub-CA mode |
| `CERTCTL_CORS_ORIGINS` | — | Comma-separated allowed CORS origins (empty = same-origin, `*` = all) |
| `CERTCTL_RATE_LIMIT_ENABLED` | `true` | Enable/disable token bucket rate limiting |
| `CERTCTL_RATE_LIMIT_RPS` | `50` | Requests per second limit |
| `CERTCTL_RATE_LIMIT_BURST` | `100` | Maximum burst size for rate limiter |
| `CERTCTL_DATABASE_MIGRATIONS_PATH` | `./migrations` | Path to SQL migration files |
| `CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL` | `1h` | How often the scheduler checks for expiring certs |
| `CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL` | `30s` | How often the scheduler processes pending jobs |
| `CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL` | `2m` | How often the scheduler checks agent health |
| `CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL` | `1m` | How often the scheduler processes pending notifications |
| `CERTCTL_ACME_DNS_PRESENT_SCRIPT` | — | Script to create DNS TXT record (`_acme-challenge` for dns-01, `_validation-persist` for dns-persist-01) |
| `CERTCTL_ACME_DNS_CLEANUP_SCRIPT` | — | Script to remove DNS-01 `_acme-challenge` TXT record (not used by dns-persist-01) |
| `CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN` | — | CA issuer domain for dns-persist-01 (e.g., `letsencrypt.org`) |
| `CERTCTL_STEPCA_URL` | — | step-ca server URL |
| `CERTCTL_STEPCA_PROVISIONER` | — | step-ca JWK provisioner name |
| `CERTCTL_STEPCA_KEY_PATH` | — | Path to step-ca provisioner private key (JWK JSON) |
| `CERTCTL_STEPCA_PASSWORD` | — | step-ca provisioner key password |
| `CERTCTL_OPENSSL_SIGN_SCRIPT` | — | Script for OpenSSL/Custom CA certificate signing |
| `CERTCTL_OPENSSL_REVOKE_SCRIPT` | — | Script for OpenSSL/Custom CA certificate revocation |
| `CERTCTL_OPENSSL_CRL_SCRIPT` | — | Script for OpenSSL/Custom CA CRL generation |
| `CERTCTL_OPENSSL_TIMEOUT_SECONDS` | `30` | Timeout for OpenSSL script execution |
| `CERTCTL_NETWORK_SCAN_ENABLED` | `false` | Enable server-side network certificate discovery (TLS scanning) |
| `CERTCTL_NETWORK_SCAN_INTERVAL` | `6h` | How often the scheduler runs network scans |
| `CERTCTL_EST_ENABLED` | `false` | Enable EST (RFC 7030) enrollment endpoints under /.well-known/est/ |
| `CERTCTL_EST_ISSUER_ID` | `iss-local` | Issuer connector ID used for EST certificate enrollment |
| `CERTCTL_EST_PROFILE_ID` | — | Optional certificate profile ID to constrain EST enrollments |
| `CERTCTL_SLACK_WEBHOOK_URL` | — | Slack incoming webhook URL for notifications |
| `CERTCTL_TEAMS_WEBHOOK_URL` | — | Microsoft Teams incoming webhook URL |
| `CERTCTL_PAGERDUTY_ROUTING_KEY` | — | PagerDuty Events API v2 routing key |
| `CERTCTL_OPSGENIE_API_KEY` | — | OpsGenie Alert API key |

Agent environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SERVER_URL` | `http://localhost:8080` | Control plane URL |
| `CERTCTL_API_KEY` | — | Agent API key |
| `CERTCTL_AGENT_NAME` | `certctl-agent` | Agent display name |
| `CERTCTL_AGENT_ID` | — | Registered agent ID (required) |
| `CERTCTL_KEY_DIR` | `/var/lib/certctl/keys` | Directory for storing private keys (agent keygen mode) |
| `CERTCTL_DISCOVERY_DIRS` | — | Comma-separated directories to scan for existing certificates (e.g., `/etc/nginx/certs,/etc/ssl/certs`) |

Docker Compose overrides these for the demo stack (see `deploy/docker-compose.yml`): port `8443`, auth type `none`, database pointing to the postgres container.

## MCP Server (AI Integration)

certctl ships a standalone MCP (Model Context Protocol) server that exposes all 78 API endpoints as tools for AI assistants — Claude, Cursor, Windsurf, OpenClaw, VS Code Copilot, and any MCP-compatible client.

```bash
# Install
go install github.com/shankar0123/certctl/cmd/mcp-server@latest

# Configure
export CERTCTL_SERVER_URL=http://localhost:8443   # certctl API endpoint
export CERTCTL_API_KEY=your-api-key               # optional if auth disabled

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

78 tools organized by resource: certificates (9), CRL/OCSP (3), issuers (6), targets (5), agents (8), jobs (5), policies (6), profiles (5), teams (5), owners (5), agent groups (6), audit (2), notifications (3), stats (5), metrics (1), health (4).

## CLI

certctl ships a command-line tool for terminal-based certificate management workflows.

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
certctl-cli agents get ag-web-prod        # Get agent details
certctl-cli jobs list                     # List jobs
certctl-cli jobs get job-123              # Get job details
certctl-cli jobs cancel job-123           # Cancel a pending job

# Operations
certctl-cli status                        # Server health + summary stats
certctl-cli import certs.pem              # Bulk import from PEM file
certctl-cli version                       # Show CLI version

# Output formats
certctl-cli certs list --format json      # JSON output (default: table)
```

## API Overview

All endpoints are under `/api/v1/` and return JSON. List endpoints support pagination (`?page=1&per_page=50`). Full request/response schemas are available in the [OpenAPI 3.1 spec](api/openapi.yaml).

### Certificates
```
GET    /api/v1/certificates              List (filter, sort, cursor, sparse fields)
POST   /api/v1/certificates              Create
GET    /api/v1/certificates/{id}          Get
PUT    /api/v1/certificates/{id}          Update
DELETE /api/v1/certificates/{id}          Archive (soft delete)
GET    /api/v1/certificates/{id}/versions Version history
GET    /api/v1/certificates/{id}/deployments  List deployment targets
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
POST   /api/v1/agents/{id}/discoveries    Submit certificate discovery scan results
```

### Certificate Discovery
```
GET    /api/v1/discovered-certificates    List discovered certificates (?agent_id, ?status)
GET    /api/v1/discovered-certificates/{id}  Get discovery detail
POST   /api/v1/discovered-certificates/{id}/claim  Link discovered cert to managed cert
POST   /api/v1/discovered-certificates/{id}/dismiss  Dismiss discovery
GET    /api/v1/discovery-scans            List discovery scan history
GET    /api/v1/discovery-summary          Aggregated discovery status (new, claimed, dismissed counts)
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
GET    /api/v1/metrics/prometheus          Prometheus exposition format (text/plain)
```

### Network Discovery
```
GET    /api/v1/network-scan-targets       List scan targets
POST   /api/v1/network-scan-targets       Create scan target (CIDRs, ports, schedule)
GET    /api/v1/network-scan-targets/{id}  Get scan target
PUT    /api/v1/network-scan-targets/{id}  Update scan target
DELETE /api/v1/network-scan-targets/{id}  Delete scan target
POST   /api/v1/network-scan-targets/{id}/scan  Trigger immediate scan
```

### Auth
```
GET    /api/v1/auth/info                  Auth mode info (no auth required)
GET    /api/v1/auth/check                 Validate credentials
```

### EST Enrollment (RFC 7030)
```
GET    /.well-known/est/cacerts           CA certificate chain (PKCS#7 certs-only)
POST   /.well-known/est/simpleenroll      Simple enrollment (PEM or base64-DER CSR)
POST   /.well-known/est/simplereenroll    Simple re-enrollment (certificate renewal)
GET    /.well-known/est/csrattrs          CSR attributes request
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
| ACME v2 (Let's Encrypt, Sectigo) | Implemented (HTTP-01 + DNS-01 + DNS-PERSIST-01) | `ACME` |
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
| Traefik | Planned (v2.1.x) | `Traefik` |
| Caddy | Planned (v2.1.x) | `Caddy` |
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
- Every API call recorded to audit trail with method, path, actor, SHA-256 body hash, response status, and latency (M19)

## Roadmap

### V1 (v1.0.0 released)
All nine development milestones (M1–M9) are complete. The backend covers the full certificate lifecycle: Local CA and ACME v2 issuers, NGINX/Apache/HAProxy/F5/IIS target connectors, threshold-based expiration alerting, agent-side ECDSA P-256 key generation, API auth with rate limiting, and a full React dashboard wired to the real API. The CI pipeline runs build, vet, test with coverage gates (service layer 30%+, handler layer 50%+), frontend type checking, Vitest test suite, and Vite production build on every push. Docker images are published to GitHub Container Registry on every version tag via the release workflow.

### V2: Operational Maturity
- **M10: Agent Metadata + Targets** ✅ — agents report OS, architecture, IP, hostname, version via heartbeat; Apache httpd and HAProxy target connectors
- **M11: Crypto Policy + Profiles + Ownership** ✅ — certificate profiles (named enrollment profiles with allowed key types, max TTL, crypto constraints), certificate ownership tracking (owners + teams + notification routing), dynamic agent groups (OS/arch/IP CIDR/version matching), interactive renewal approval (AwaitingApproval state)
- **M12: Sub-CA + DNS-01 + step-ca** ✅ — Local CA sub-CA mode (enterprise root chain with RSA/ECDSA/PKCS#8), ACME DNS-01 challenges (script-based DNS hooks for any provider, wildcard cert support), ACME DNS-PERSIST-01 challenges (standing TXT record, no per-renewal DNS updates, auto-fallback to dns-01), step-ca issuer connector (native /sign API with JWK provisioner auth)
- **M15a: Core Revocation** ✅ — revocation API with all RFC 5280 reason codes, JSON CRL endpoint, webhook + email revocation notifications, best-effort issuer notification, `certificate_revocations` table with idempotent recording, 48 new tests
- **M15b: OCSP + Revocation GUI** ✅ — embedded OCSP responder (GET /api/v1/ocsp/{issuer_id}/{serial}), DER-encoded X.509 CRL (GET /api/v1/crl/{issuer_id}), short-lived cert exemption (TTL < 1h skip CRL/OCSP), revocation GUI with reason modal, ~31 new tests
- **M13: GUI Operations** ✅ — bulk cert operations (multi-select → renew, revoke, reassign owner), deployment status timeline, inline policy/profile editor, target connector configuration wizard, audit trail export (CSV/JSON), short-lived credentials dashboard view
- **M14: Observability** ✅ — dashboard charts (expiration heatmap, cert status distribution, job trends, issuance rate), agent fleet overview with OS/arch grouping, JSON metrics endpoint, stats API (5 endpoints), structured logging with request IDs, deployment rollback
- **M18a: MCP Server** ✅ (V2.1) — AI-native integration, all 78 REST API endpoints exposed as MCP tools for Claude, Cursor, OpenClaw, and any MCP-compatible client
- **M19: Immutable API Audit Log** ✅ — every API call recorded to immutable audit trail (method, path, actor, SHA-256 body hash, status, latency), async recording via goroutine, configurable path exclusions
- **M16a: Notifier Connectors** ✅ — Slack (incoming webhook), Microsoft Teams (MessageCard), PagerDuty (Events API v2), OpsGenie (Alert API v2) — config-driven enablement via env vars
- **M17: Additional Connectors** ✅ — OpenSSL/Custom CA issuer connector (script-based signing with configurable timeout)
- **M16b: CLI + Bulk Import** ✅ — `certctl-cli` with 12 subcommands (certs list/get/renew/revoke, agents list/get, jobs list/get/cancel, import, status, version), stdlib-only, JSON/table output
- **M20: Enhanced Query API** ✅ — sparse field selection (`?fields=`), sort with direction (`?sort=-notAfter`), time-range filters (`expires_before`, `created_after`, etc.), cursor-based pagination (`?cursor=&page_size=`), `GET /certificates/{id}/deployments`, additional filters (`agent_id`, `profile_id`)
- **M18b: Filesystem Cert Discovery** ✅ — agents scan configured directories (PEM/DER), report findings to control plane, deduplication by SHA-256 fingerprint, claim/dismiss/triage workflow via API
- **M21: Network Cert Discovery** ✅ — server-side active TLS scanning of CIDR ranges and ports, concurrent probing (50 goroutines), CIDR expansion with /20 safety cap, sentinel agent pattern for discovery pipeline reuse, CRUD API for scan targets, scheduler integration (6h default)
- **M22: Prometheus Metrics** ✅ — `GET /api/v1/metrics/prometheus` returns Prometheus exposition format (`text/plain; version=0.0.4`), 11 metrics with `certctl_` prefix, compatible with Prometheus, Grafana Agent, Datadog Agent, Victoria Metrics
- **M23: EST Server (RFC 7030)** ✅ — Enrollment over Secure Transport for device/WiFi certificate enrollment, 4 endpoints under /.well-known/est/, PKCS#7 certs-only wire format, base64-encoded DER CSR input, configurable issuer + profile binding, audit trail, 28 new tests
- **Compliance Mapping** ✅ — SOC 2 Type II, PCI-DSS 4.0, NIST SP 800-57 capability mapping documentation
- **M24: S/MIME Certificate Support** (Planned — v2.0.2) — wire profile EKU constraints through the issuance pipeline so certctl can issue S/MIME (emailProtection), code signing, and custom EKU certificates, not just TLS
- **M25: Traefik + Caddy Targets** (Planned — v2.1.x) — Traefik (file provider, auto-reload on filesystem change) and Caddy (Admin API, hot-reload) deployment target connectors
- **M26: Certificate Export** (Planned — v2.1.x) — single-certificate download in PFX/PKCS12, DER, and PEM formats with optional chain inclusion, GUI download button on certificate detail page

### V3: certctl Pro

Team access controls, identity provider integration, enterprise deployment targets, compliance and risk scoring, advanced fleet operations, event-driven architecture, advanced search, real-time operational views, and premium CA integrations.

### V4+: Cloud, Scale & Passive Discovery
Passive network discovery (TLS listener), Kubernetes integration (cert-manager external issuer, Secrets target), cloud infrastructure targets (AWS ALB/ACM, Azure Key Vault), extended CA support (Vault PKI, Google CAS, EJBCA), and platform-scale features (Terraform provider, multi-tenancy, HSM support).

## License

Certctl is licensed under the [Business Source License 1.1](LICENSE). The source code is publicly available and free to use, modify, and self-host. The one restriction: you may not offer certctl as a managed/hosted certificate management service to third parties.

