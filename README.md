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
![Version: v2.0.5](https://img.shields.io/badge/version-v2.0.5-brightgreen)

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

## Contents

- [Why certctl Exists](#why-certctl-exists) · [What It Does](#what-it-does) · [Screenshots](#screenshots) · [Quick Start](#quick-start) · [Architecture](#architecture)
- [Configuration](#configuration) · [MCP Server](#mcp-server-ai-integration) · [CLI](#cli) · [API Overview](#api-overview) · [Integrations](#supported-integrations)
- [Development](#development) · [Security](#security) · [Roadmap](#roadmap) · [License](#license)

## Why certctl Exists

Certificate lifecycle tooling today falls into two camps: expensive enterprise platforms (Venafi, Keyfactor, Sectigo) that cost six figures and take months to deploy, or single-purpose tools (cert-manager, certbot) that handle one slice of the problem. If you run a mixed infrastructure — some NGINX, some Apache, a few HAProxy nodes, maybe an F5 — and you need to manage certificates from multiple CAs, there's nothing self-hosted that covers the full lifecycle without vendor lock-in.

certctl fills that gap. It's **CA-agnostic** — the issuer connector interface means you can plug in any certificate authority: a self-signed local CA for dev, Let's Encrypt via ACME for public certs, Smallstep step-ca for your private PKI, your enterprise ADCS via sub-CA mode, or any custom CA through a shell script adapter. You're never locked to a single CA vendor, and you can run multiple issuers simultaneously for different certificate types.

It's also **target-agnostic**. Agents deploy certificates to NGINX, Apache, and HAProxy today, with Traefik and Caddy support coming next — all using the same pluggable connector model for any server that accepts cert files. The control plane never initiates outbound connections — agents poll for work, which means certctl works behind firewalls, across network zones, and in air-gapped environments.

### How It Compares

| | **certctl** | **CertKit** | **CertWarden** | **Certimate** | **CZERTAINLY** | **KeyTalk** | **cert-manager** |
|---|---|---|---|---|---|---|---|
| **License** | BSL 1.1 → Apache 2.0 | Proprietary (agent OSS) | MIT | MIT | MIT + commercial | Proprietary | Apache 2.0 |
| **Self-hosted** | Yes | No (SaaS) | Yes | Yes | Yes (K8s required) | On-prem or cloud | Yes (K8s only) |
| **CA support** | ACME, step-ca, Local CA, OpenSSL, EST | ACME only | ACME only | ACME (5+ CAs) | Multi-CA (connectors) | Multi-CA | ACME, Venafi, Vault |
| **Agent deployment** | Yes (default) | Yes | No (API pull) | No | Via connectors | Yes | N/A (K8s) |
| **Private key isolation** | Yes (agent-side) | Yes (Keystore, paid) | No | No | Varies | Yes | K8s Secrets |
| **Server targets** | NGINX, Apache, HAProxy | NGINX, Apache, HAProxy, IIS + more | None | 110+ (cloud/CDN-focused) | Via connectors | Undocumented | K8s-native |
| **Policy engine** | Yes (5 rule types) | No | No | No | RA profiles | Undocumented | No |
| **Certificate discovery** | Yes (filesystem + network) | No | No | No | Yes (connectors) | Undocumented | No |
| **Audit trail** | Yes (immutable, every API call) | Planned | No | No | Yes | Yes | No |
| **CRL / OCSP** | Yes | No | No | No | Yes | Undocumented | No |
| **API coverage** | 95 endpoints | REST API | Minimal | REST API | REST API | REST API | K8s CRDs |
| **AI integration (MCP)** | Yes (78 tools) | No | No | No | No | No | No |
| **Free tier** | Unlimited | 3 certificates | Unlimited | Unlimited | Unlimited | None | Unlimited |

certctl occupies a distinct position: full lifecycle automation with agent-based key isolation, multi-CA support, network discovery, and revocation infrastructure — self-hosted on any Linux server, no Kubernetes required. Enterprise platforms (Venafi, Keyfactor, Sectigo) offer broader ecosystems at $75K-$250K+/yr. For a detailed comparison, see [Why certctl?](docs/why-certctl.md)

## What It Does

certctl gives you a single pane of glass for every TLS certificate in your organization:

- **Web dashboard** — full certificate inventory with status, ownership, expiration heatmaps, and bulk operations
- **REST API** — 95 endpoints under `/api/v1/` + `/.well-known/est/` for complete automation
- **Agents** — generate private keys locally, discover existing certs on disk, submit CSRs (private keys never leave your servers)
- **Network scanner** — discovers certificates on TLS endpoints across CIDR ranges without requiring agents
- **EST server** (RFC 7030) — device and WiFi certificate enrollment via industry-standard protocol
- **Approval workflows** — require human sign-off on renewals before deployment
- **Background scheduler** — watches expiration dates and triggers renewals automatically, handling constant rotation at 47-day lifespans without human involvement

**Core capabilities:**

- **Full lifecycle automation** — issuance, renewal, deployment, and revocation with zero human intervention. Configurable renewal policies trigger jobs automatically based on expiration thresholds.
- **CA-agnostic issuer connectors** — Local CA (self-signed + sub-CA for enterprise root chains), ACME v2 with HTTP-01, DNS-01, and DNS-PERSIST-01 challenges (Let's Encrypt, ZeroSSL, Sectigo, Google Trust Services, any ACME-compatible CA), External Account Binding (EAB) for CAs that require it (auto-fetched for ZeroSSL), Smallstep step-ca (native /sign API), and OpenSSL/Custom CA (delegate to any shell script). Pluggable interface — add your own CA in one file.
- **Agent-side key generation** — agents generate ECDSA P-256 keys locally, store them with 0600 permissions, and submit only the CSR. Private keys never touch the control plane. This is the default mode, not an opt-in feature.
- **Certificate discovery** — agents scan filesystems for existing PEM/DER certificates and report findings for triage. The network scanner probes TLS endpoints across CIDR ranges to find certificates you didn't know existed.
- **Revocation infrastructure** — RFC 5280 revocation with all standard reason codes, DER-encoded X.509 CRL per issuer, embedded OCSP responder, and short-lived certificate exemption (certs under 1 hour skip CRL/OCSP).
- **Policy engine** — 5 rule types with violation tracking and severity levels. Certificate profiles enforce allowed key types, maximum TTL, and crypto constraints at enrollment time.
- **Immutable audit trail** — every action recorded to an append-only log. Every API call recorded with method, path, actor, SHA-256 body hash, response status, and latency. No update or delete on audit records.
- **Operational dashboard** — Full React GUI with certificate inventory, bulk operations (multi-select renew/revoke/reassign), deployment timeline visualization, inline policy editing, agent fleet overview, expiration heatmaps, real-time short-lived credential tracking, discovery triage workflow, network scan management, and interactive approval/rejection flow.
- **Observability** — JSON and Prometheus metrics endpoints, 5 stats API endpoints for dashboards, structured slog logging with request ID propagation. Compatible with Prometheus, Grafana Agent, Datadog Agent, and Victoria Metrics.
- **Notifications** — threshold-based alerting with deduplication. Routes to email, webhooks, Slack, Microsoft Teams, PagerDuty, and OpsGenie.
- **EST enrollment (RFC 7030)** — built-in Enrollment over Secure Transport server for device certificate enrollment. Supports WiFi/802.1X, MDM, and IoT use cases. PKCS#7 certs-only wire format, accepts PEM or base64-encoded DER CSRs, configurable issuer and profile binding.
- **Multi-purpose certificates** — certificate profiles support arbitrary EKU (Extended Key Usage) constraints. TLS (serverAuth/clientAuth) today, with S/MIME (emailProtection) and code signing support coming in v2.0.2.
- **AI and CLI access** — MCP server exposes all 78 API operations as tools for Claude, Cursor, and any MCP-compatible client. CLI tool with 12 subcommands for terminal workflows and scripting.

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
<td><a href="docs/screenshots/v2-targets.png"><img src="docs/screenshots/v2-targets.png" width="270" alt="Targets"></a><br><b>Targets</b><br><sub>NGINX, Apache, HAProxy deployment</sub></td>
<td><a href="docs/screenshots/v2-owners.png"><img src="docs/screenshots/v2-owners.png" width="270" alt="Owners"></a><br><b>Owners</b><br><sub>Cert ownership with team assignment</sub></td>
<td><a href="docs/screenshots/v2-teams.png"><img src="docs/screenshots/v2-teams.png" width="270" alt="Teams"></a><br><b>Teams</b><br><sub>Org grouping for notification routing</sub></td>
</tr>
<tr>
<td><a href="docs/screenshots/v2-agent-groups.png"><img src="docs/screenshots/v2-agent-groups.png" width="270" alt="Agent Groups"></a><br><b>Agent Groups</b><br><sub>Dynamic grouping by OS, arch, CIDR</sub></td>
<td><a href="docs/screenshots/v2-audit-trail.png"><img src="docs/screenshots/v2-audit-trail.png" width="270" alt="Audit Trail"></a><br><b>Audit Trail</b><br><sub>Immutable log, CSV/JSON export</sub></td>
<td><a href="docs/screenshots/v2-short-lived.png"><img src="docs/screenshots/v2-short-lived.png" width="270" alt="Short-Lived"></a><br><b>Short-Lived Creds</b><br><sub>Ephemeral certs with live TTL countdown</sub></td>
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

All environment variables use the `CERTCTL_` prefix. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_DATABASE_URL` | `postgres://localhost/certctl` | PostgreSQL connection string |
| `CERTCTL_AUTH_TYPE` | `api-key` | Auth mode: `api-key`, `jwt`, or `none` |
| `CERTCTL_AUTH_SECRET` | — | Required for `api-key` and `jwt` auth types |
| `CERTCTL_KEYGEN_MODE` | `agent` | Key generation: `agent` (production) or `server` (demo only) |
| `CERTCTL_SERVER_PORT` | `8080` | Server listen port |
| `CERTCTL_ACME_DIRECTORY_URL` | — | ACME directory URL (e.g., Let's Encrypt) |
| `CERTCTL_ACME_EMAIL` | — | Contact email for ACME account registration |

Agent settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SERVER_URL` | `http://localhost:8080` | Control plane URL |
| `CERTCTL_API_KEY` | — | Agent API key |
| `CERTCTL_AGENT_ID` | — | Registered agent ID (required) |
| `CERTCTL_KEY_DIR` | `/var/lib/certctl/keys` | Private key storage directory |
| `CERTCTL_DISCOVERY_DIRS` | — | Directories to scan for existing certs (comma-separated) |

For the full configuration reference — including ACME DNS challenges, sub-CA mode, step-ca, OpenSSL/Custom CA, EST enrollment, network scanning, notification connectors (Slack, Teams, PagerDuty, OpsGenie), scheduler intervals, CORS, and rate limiting — see the [Feature Inventory](docs/features.md). Docker Compose overrides for the demo stack are in `deploy/docker-compose.yml`.

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

95 endpoints under `/api/v1/` + `/.well-known/est/`, all returning JSON. List endpoints support pagination, sparse field selection (`?fields=`), sort (`?sort=-notAfter`), time-range filters, and cursor-based pagination. Full request/response schemas in the [OpenAPI 3.1 spec](api/openapi.yaml).

### Key Endpoints
```
# Certificate lifecycle
GET    /api/v1/certificates              List (filter, sort, cursor, sparse fields)
POST   /api/v1/certificates/{id}/renew   Trigger renewal → 202 Accepted
POST   /api/v1/certificates/{id}/revoke  Revoke with RFC 5280 reason code
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

# Observability
GET    /api/v1/metrics/prometheus         Prometheus exposition format
GET    /api/v1/stats/summary             Dashboard summary

# EST enrollment (RFC 7030)
POST   /.well-known/est/simpleenroll     Device certificate enrollment
GET    /.well-known/est/cacerts          CA certificate chain (PKCS#7)
```

Full CRUD is available for certificates, agents, issuers, targets, teams, owners, policies, profiles, agent groups, notifications, and audit events. See the [OpenAPI spec](api/openapi.yaml) or [Feature Inventory](docs/features.md) for the complete endpoint reference.

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
- Every API call recorded to audit trail with method, path, actor, SHA-256 body hash, response status, and latency

## Roadmap

### V1 (v1.0.0)
Core lifecycle management — Local CA + ACME v2 issuers, NGINX target connector, agent-side key generation, API auth + rate limiting, React dashboard, CI pipeline with coverage gates, Docker images on GHCR.

### V2: Operational Maturity

18 milestones complete, 950+ tests. See the [Feature Inventory](docs/features.md) for details on every capability.

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

**Coming next:**

- **Post-Deployment TLS Verification** (v2.0.6) — agent-side TLS probe confirms the target is serving the correct certificate by SHA-256 fingerprint match
- **Traefik + Caddy Targets** (v2.1.x) — Traefik (file provider, auto-reload) and Caddy (Admin API, hot-reload)
- **Certificate Export** (v2.1.x) — single-cert download in PFX/PKCS12, DER, and PEM formats
- **S/MIME Support** (v2.2.x) — profile EKU constraints for S/MIME (emailProtection), code signing, and custom EKUs

### V3: certctl Pro

Team access controls, identity provider integration, enterprise deployment targets, compliance and risk scoring, advanced fleet operations, event-driven architecture, advanced search, real-time operational views, and premium CA integrations.

### V4+: Cloud, Scale & Passive Discovery
Passive network discovery (TLS listener), Kubernetes integration (cert-manager external issuer, Secrets target), cloud infrastructure targets (AWS ALB/ACM, Azure Key Vault), extended CA support (Vault PKI, Google CAS, EJBCA), and platform-scale features (Terraform provider, multi-tenancy, HSM support).

## License

Certctl is licensed under the [Business Source License 1.1](LICENSE). The source code is publicly available and free to use, modify, and self-host. The one restriction: you may not offer certctl as a managed/hosted certificate management service to third parties.

