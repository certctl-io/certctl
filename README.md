<p align="center">
  <img src="docs/screenshots/logo/certctl-logo.png" alt="certctl logo" width="450">
</p>

<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=89db181e-76e0-45cc-b9c0-790c3dfdfc73" />
<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=b9379aff-9e5c-4d01-8f2d-9e4ffa09d126" />

# certctl — Self-Hosted Certificate Lifecycle Platform

[![License](https://img.shields.io/badge/license-BSL%201.1-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/shankar0123/certctl)](https://goreportcard.com/report/github.com/shankar0123/certctl)
[![GitHub Release](https://img.shields.io/github/v/release/shankar0123/certctl)](https://github.com/shankar0123/certctl/releases)
[![GitHub Stars](https://img.shields.io/github/stars/shankar0123/certctl?style=flat&logo=github)](https://github.com/shankar0123/certctl/stargazers)

TLS certificate lifespans are shrinking fast. The CA/Browser Forum passed [Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) unanimously in April 2025, setting a phased reduction: **200 days** by March 2026, **100 days** by March 2027, and **47 days** by March 2029. Organizations managing dozens or hundreds of certificates can no longer rely on spreadsheets, calendar reminders, or manual renewal workflows. The math doesn't work — at 47-day lifespans, a team managing 100 certificates is processing 7+ renewals per week, every week, forever.

certctl is a self-hosted platform that automates the entire certificate lifecycle — from issuance through renewal to deployment — with zero human intervention. It works with any certificate authority, deploys to any server, and keeps private keys on your infrastructure where they belong. It's free, self-hosted, and covers the same lifecycle that enterprise platforms charge $100K+/year for.

```mermaid
gantt
    title TLS Certificate Maximum Lifespan — CA/Browser Forum Ballot SC-081v3
    dateFormat YYYY-MM-DD
    axisFormat
    todayMarker off
    section 2015
        5 years (1825 days)    :done, 2020-01-01, 1825d
    section 2018
        825 days               :done, 2020-01-01, 825d
    section 2020
        398 days               :active, 2020-01-01, 398d
    section 2026
        200 days               :crit, 2020-01-01, 200d
    section 2027
        100 days               :crit, 2020-01-01, 100d
    section 2029
        47 days                :crit, 2020-01-01, 47d
```

## Documentation

| Guide | Description |
|-------|-------------|
| [Why certctl?](docs/why-certctl.md) | How certctl compares to ACME clients, agent-based SaaS, and enterprise platforms |
| [Concepts](docs/concepts.md) | TLS certificates explained from scratch — for beginners who know nothing about certs |
| [Quick Start](docs/quickstart.md) | 5-minute setup — dashboard, API, CLI, discovery, stakeholder demo flow |
| [Docker Compose Environments](deploy/ENVIRONMENTS.md) | Service-by-service walkthrough of all 4 compose files, env var reference |
| [Deployment Examples](docs/examples.md) | 5 turnkey scenarios (ACME+NGINX, wildcard DNS-01, private CA, step-ca, multi-issuer) with migration guides |
| [Advanced Demo](docs/demo-advanced.md) | Issue a certificate end-to-end with technical deep-dives |
| [Architecture](docs/architecture.md) | System design, data flow diagrams, security model |
| [Feature Inventory](docs/features.md) | Complete reference of all capabilities, API endpoints, and configuration |
| [Connector Reference](docs/connectors.md) | Configuration for all issuer, target, and notifier connectors |
| [MCP Server](docs/mcp.md) | AI integration via Model Context Protocol — setup, available tools, examples |
| [OpenAPI 3.1 Spec](docs/openapi.md) | API reference guide with endpoint overview ([raw spec](api/openapi.yaml)) |
| [Compliance Mapping](docs/compliance.md) | SOC 2 Type II, PCI-DSS 4.0, NIST SP 800-57 alignment guides |
| [Migrate from certbot](docs/migrate-from-certbot.md) | Step-by-step migration from certbot cron jobs to certctl |
| [Migrate from acme.sh](docs/migrate-from-acmesh.md) | Migration guide for acme.sh users, DNS hook compatibility |
| [certctl for cert-manager users](docs/certctl-for-cert-manager-users.md) | How certctl complements cert-manager for mixed infrastructure |
| [Test Environment](docs/test-env.md) | Docker Compose test environment with real CA backends |
| [Testing Guide](docs/testing-guide.md) | Comprehensive test procedures, smoke tests, and release sign-off checklist |

> **Actively maintained — shipping weekly.** Found something? [Open a GitHub issue](https://github.com/shankar0123/certctl/issues) — issues get triaged same-day. CI runs the full test suite with race detection, static analysis, and vulnerability scanning on every commit.

**Ready to try it?** Jump to the [Quick Start](#quick-start) — you'll have a running dashboard in under 5 minutes.

## Why certctl Exists

Certificate lifecycle tooling today falls into two camps: expensive enterprise platforms (Venafi, Keyfactor, Sectigo) that cost six figures and take months to deploy, or single-purpose tools (cert-manager, certbot) that handle one slice of the problem. If you run a mixed infrastructure — some NGINX, some Apache, a few HAProxy nodes, IIS on Windows, maybe an F5 — and you need to manage certificates from multiple CAs, there's nothing self-hosted that covers the full lifecycle without vendor lock-in.

certctl fills that gap. It's **CA-agnostic** — plug in any certificate authority: Let's Encrypt via ACME, Smallstep step-ca, HashiCorp Vault PKI, DigiCert CertCentral, Sectigo SCM, Google Cloud CAS, AWS ACM Private CA, your enterprise ADCS via sub-CA mode, or any custom CA through a shell script adapter. Run multiple issuers simultaneously for different certificate types.

It's **target-agnostic**. Agents deploy certificates to NGINX, Apache, HAProxy, Traefik, Caddy, Envoy, Postfix, Dovecot, IIS (local PowerShell or remote WinRM), F5 BIG-IP (proxy agent), Windows Certificate Store, Java Keystores, Kubernetes Secrets, and any Linux/Unix server via SSH/SFTP — all using the same pluggable connector model. The control plane never initiates outbound connections — agents poll for work, which means certctl works behind firewalls, across network zones, and in air-gapped environments.

For a detailed comparison with other competitors and enterprise platforms, see [Why certctl?](docs/why-certctl.md)

## Who Is This For

**Platform engineering and DevOps teams** managing 10–500+ certificates across mixed infrastructure who need automated renewal, deployment, and a single dashboard for visibility. If you're currently running certbot cron jobs, manually renewing certs, or stitching together scripts — certctl replaces all of that.

**Security and compliance teams** who need an immutable audit trail, certificate ownership tracking, policy enforcement, and evidence for SOC 2, PCI-DSS 4.0, or NIST SP 800-57 audits. certctl ships with [compliance mapping documentation](docs/compliance.md) for all three frameworks.

**Small teams without enterprise budgets** who need the lifecycle automation that Venafi and Keyfactor provide but can't justify six-figure licensing for a 50-server environment.

## What It Does

- **Certificates renew and deploy themselves.** The scheduler monitors expiration, creates renewal jobs, issues certificates through your CA, and deploys them to target servers — all without human intervention. ACME ARI (RFC 9773) lets your CA tell certctl exactly when to renew. Ready for 45-day and 6-day certificate lifetimes (SC-081v3 and Let's Encrypt shortlived profiles). ACME certificate profile selection (`tlsserver`, `shortlived`) supported.

- **You see everything in one place.** 26-page operational dashboard shows every certificate across every server: status, ownership, expiration timeline, deployment history with rollback, discovery triage, network scan management, and real-time agent fleet health. Bulk operations (renew, revoke, reassign) work across selections. Short-lived credential dashboard with live TTL countdown.

- **Private keys never leave your servers.** Agents generate ECDSA P-256 keys locally and submit only the CSR. The control plane never touches private keys. Post-deployment TLS verification confirms the right certificate is actually being served by comparing SHA-256 fingerprints against the live TLS endpoint.

- **Configure everything from the dashboard.** Issuers and targets are configured through the GUI — no env var editing or server restarts. AES-256-GCM encrypted credential storage. Test connection before saving. First-run onboarding wizard guides you through connecting a CA, deploying an agent, and issuing your first certificate.

- **Discover what you don't know about.** Agents scan filesystems for existing PEM/DER certificates. The network scanner probes TLS endpoints across CIDR ranges without requiring agents. Both feed into a triage workflow where you claim, dismiss, or import discovered certificates.

- **Enforce policy and control access.** Certificate profiles constrain allowed key types, maximum TTL, and required EKUs. Interactive approval workflows pause renewal jobs for human review. Ownership tracking routes notifications to the right team. Agent groups match devices by OS, architecture, IP CIDR, and version.

- **Everything is auditable.** Immutable append-only audit trail records every lifecycle action, every API call (with actor attribution, SHA-256 body hash, latency), and every approval decision. Certificate digest emails deliver daily briefings. Prometheus metrics endpoint for Grafana dashboards.

- **Standards-based enrollment protocols.** EST server (RFC 7030) for device and WiFi certificate enrollment. SCEP server (RFC 8894) for MDM platforms and network device enrollment. Both share a common PKCS#7 package and delegate to any configured issuer connector. S/MIME certificate issuance with email protection EKU for end-to-end encrypted email.

- **Full revocation infrastructure.** DER-encoded X.509 CRL per issuer, signed by the issuing CA. Embedded OCSP responder with good/revoked/unknown status. RFC 5280 reason codes. Short-lived certificates (profile TTL < 1 hour) automatically exempt from CRL/OCSP — expiry is sufficient revocation.

- **Certificate export.** Download certificates in PEM (JSON or file) and PKCS#12 formats. Private keys are never included — they live on agents only. Every export is recorded in the audit trail.

- **Multiple interfaces for different workflows.** REST API (111 routes) for automation, CLI (12 commands) for scripting, MCP server (80 tools) for AI assistants (Claude, Cursor, Windsurf), Helm chart for Kubernetes, and the web dashboard for day-to-day operations.

- **Notification routing.** Slack, Microsoft Teams, PagerDuty, OpsGenie, email (SMTP), and webhooks. Notifications route by certificate owner email. Scheduled certificate digest emails with HTML template, stats grid, and expiring certs table.

For the full capability breakdown, see the [Feature Inventory](docs/features.md).

## Supported Integrations

### Certificate Issuers

| Issuer | Type | Notes |
|--------|------|-------|
| Local CA (self-signed + sub-CA) | `GenericCA` | Sub-CA mode chains to enterprise root (ADCS, etc.) |
| ACME v2 (Let's Encrypt, ZeroSSL, etc.) | `ACME` | HTTP-01, DNS-01, DNS-PERSIST-01 challenges. EAB auto-fetch from ZeroSSL. Profile selection (`tlsserver`, `shortlived`). |
| step-ca (Smallstep) | `StepCA` | JWK provisioner auth, issuance + renewal + revocation |
| OpenSSL / Custom CA | `OpenSSL` | Shell script adapter — any CA with a CLI |
| HashiCorp Vault PKI | `VaultPKI` | Token auth, synchronous issuance, CRL/OCSP delegated to Vault |
| DigiCert CertCentral | `DigiCert` | Async order model, OV/EV support, PEM bundle parsing |
| Sectigo SCM | `Sectigo` | 3-header auth, DV/OV/EV, collect-not-ready graceful handling |
| Google Cloud CAS | `GoogleCAS` | OAuth2 service account, synchronous issuance, CA pool selection |
| AWS ACM Private CA | `AWSACMPCA` | Synchronous issuance, configurable signing algorithm/template ARN |

**Note:** ADCS integration is handled via the Local CA's sub-CA mode — certctl operates as a subordinate CA with its signing certificate issued by ADCS. Any CA with a shell-accessible signing interface can be integrated via the OpenSSL/Custom CA connector.

### Deployment Targets

| Target | Type | Notes |
|--------|------|-------|
| NGINX | `NGINX` | File write, config validation, reload |
| Apache httpd | `Apache` | Separate cert/chain/key files, configtest, graceful reload |
| HAProxy | `HAProxy` | Combined PEM file, validate, reload |
| Traefik | `Traefik` | File provider deployment, auto-reload via filesystem watch |
| Caddy | `Caddy` | Dual-mode: admin API hot-reload or file-based |
| Envoy | `Envoy` | File-based with optional SDS JSON config |
| Postfix | `Postfix` | Mail server TLS, pairs with S/MIME support |
| Dovecot | `Dovecot` | Mail server TLS, pairs with S/MIME support |
| Microsoft IIS | `IIS` | Local PowerShell or remote WinRM, PEM→PFX, SNI support |
| F5 BIG-IP | `F5` | iControl REST via proxy agent, transaction-based atomic updates |
| SSH (Agentless) | `SSH` | SFTP cert/key deployment to any Linux/Unix server |
| Windows Certificate Store | `WinCertStore` | PowerShell Import-PfxCertificate, configurable store/location |
| Java Keystore | `JavaKeystore` | PEM→PKCS#12→keytool pipeline, JKS and PKCS12 formats |
| Kubernetes Secrets | `KubernetesSecrets` | `kubernetes.io/tls` Secrets, in-cluster or kubeconfig auth |

### Enrollment Protocols

| Protocol | Standard | Use Case |
|----------|----------|----------|
| EST (Enrollment over Secure Transport) | RFC 7030 | Device enrollment, WiFi/802.1X, IoT |
| SCEP (Simple Certificate Enrollment Protocol) | RFC 8894 | MDM platforms (Jamf, Intune), network devices |
| ACME v2 | RFC 8555 | Public CA automated issuance (Let's Encrypt, ZeroSSL) |
| ACME ARI (Renewal Information) | RFC 9773 | CA-directed renewal timing — the CA tells you when to renew |

### Standards & Revocation

| Capability | Standard | Notes |
|------------|----------|-------|
| DER-encoded X.509 CRL | RFC 5280 | Per-issuer, signed by issuing CA, 24h validity |
| Embedded OCSP responder | RFC 6960 | Good/revoked/unknown status per issuer |
| S/MIME certificates | RFC 8551 | Email protection EKU, adaptive KeyUsage flags |
| Certificate export | — | PEM (JSON/file) and PKCS#12 formats |
| ACME DNS-PERSIST-01 | IETF draft | Standing validation record, no per-renewal DNS updates |

### Notifiers

| Notifier | Type |
|----------|------|
| Email (SMTP) | `Email` |
| Webhooks | `Webhook` |
| Slack | `Slack` |
| Microsoft Teams | `Teams` |
| PagerDuty | `PagerDuty` |
| OpsGenie | `OpsGenie` |

All connectors are pluggable — build your own by implementing the [connector interface](docs/connectors.md).

### Screenshots

<table>
<tr>
<td><a href="docs/screenshots/v2-dashboard.png"><img src="docs/screenshots/v2-dashboard.png" width="400" alt="Dashboard"></a><br><b>Dashboard</b><br><sub>Stats, expiration heatmap, renewal trends, issuance rate</sub></td>
<td><a href="docs/screenshots/v2-certificates.png"><img src="docs/screenshots/v2-certificates.png" width="400" alt="Certificates"></a><br><b>Certificates</b><br><sub>Inventory with bulk ops, status filters, owner/team columns</sub></td>
</tr>
<tr>
<td><a href="docs/screenshots/v2-issuers.png"><img src="docs/screenshots/v2-issuers.png" width="400" alt="Issuers"></a><br><b>Issuers</b><br><sub>Catalog with 10 CA types, GUI config, test connection</sub></td>
<td><a href="docs/screenshots/v2-jobs.png"><img src="docs/screenshots/v2-jobs.png" width="400" alt="Jobs"></a><br><b>Jobs</b><br><sub>Issuance, renewal, deployment queue with approval workflow</sub></td>
</tr>
</table>

**[See all screenshots →](docs/screenshots/)**

## Quick Start

### Docker Compose (Recommended)

```bash
git clone https://github.com/shankar0123/certctl.git
cd certctl
docker compose -f deploy/docker-compose.yml up -d --build
```

Wait ~30 seconds, then open **http://localhost:8443** in your browser. The onboarding wizard walks you through connecting a CA, deploying an agent, and issuing your first certificate.

**Want a pre-populated demo instead?** Add the demo override to see 32 certificates across 10 issuers, 8 agents, and 180 days of realistic history:

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.demo.yml up -d --build
```

The `deploy/` directory has four compose files: `docker-compose.yml` (base platform), `docker-compose.demo.yml` (demo data overlay), `docker-compose.dev.yml` (PgAdmin + debug logging), and `docker-compose.test.yml` (standalone integration tests with real CA backends). See the [Docker Compose Environments Guide](deploy/ENVIRONMENTS.md) for a service-by-service walkthrough, or the [Quick Start](docs/quickstart.md#docker-compose-environments) for a summary.

```bash
curl http://localhost:8443/health
# {"status":"healthy"}
```

### Agent Install (One-Liner)

```bash
curl -sSL https://raw.githubusercontent.com/shankar0123/certctl/master/install-agent.sh | bash
```

Detects your OS and architecture, downloads the binary, configures systemd (Linux) or launchd (macOS), and starts the agent. See [install-agent.sh](install-agent.sh) for details.

### Helm Chart (Kubernetes)

```bash
helm install certctl deploy/helm/certctl/ \
  --set server.apiKey=your-api-key \
  --set postgres.password=your-db-password
```

Production-ready chart with Server Deployment, PostgreSQL StatefulSet, Agent DaemonSet, health probes, security contexts (non-root, read-only rootfs), and optional Ingress. See [values.yaml](deploy/helm/certctl/values.yaml) for all configuration options.

### Docker Pull

```bash
docker pull shankar0123.docker.scarf.sh/certctl-server
docker pull shankar0123.docker.scarf.sh/certctl-agent
```

## Examples

Pick the scenario closest to your setup and have it running in 2 minutes.

| Example | Scenario |
|---------|----------|
| [`examples/acme-nginx/`](examples/acme-nginx/) | Let's Encrypt + NGINX, HTTP-01 challenges |
| [`examples/acme-wildcard-dns01/`](examples/acme-wildcard-dns01/) | Wildcard certs via DNS-01 (Cloudflare hook included) |
| [`examples/private-ca-traefik/`](examples/private-ca-traefik/) | Local CA (self-signed or sub-CA) + Traefik file provider |
| [`examples/step-ca-haproxy/`](examples/step-ca-haproxy/) | Smallstep step-ca + HAProxy combined PEM |
| [`examples/multi-issuer/`](examples/multi-issuer/) | ACME for public + Local CA for internal, one dashboard |

Each directory contains a `docker-compose.yml` and a `README.md` explaining the scenario, prerequisites, and customization.

## Architecture

**Control plane** (Go 1.25 net/http) → **PostgreSQL 16** (21 tables, TEXT primary keys) → **Agents** (key generation, CSR submission, cert deployment, TLS verification). For Windows servers without a local agent, a proxy agent in the same network zone handles deployment via WinRM. Background scheduler runs 7 loops: renewal checks with ARI integration (1h), job processing (30s), agent health (2m), notifications (1m), short-lived cert expiry (30s), network scanning (6h), certificate digest (24h). See [Architecture Guide](docs/architecture.md) for full system diagrams and data flow.

### Key Design Decisions

- **Private keys isolated from the control plane.** Agents generate ECDSA P-256 keys locally and submit CSRs (public key only). The server signs the CSR and returns the certificate — private keys never touch the control plane. Server-side keygen is available via `CERTCTL_KEYGEN_MODE=server` for demo/development only.
- **TEXT primary keys, not UUIDs.** IDs are human-readable prefixed strings (`mc-api-prod`, `t-platform`, `o-alice`) so you can identify resource types at a glance in logs and queries.
- **Handler → Service → Repository layering.** Handlers define their own service interfaces for clean dependency inversion. No global service singletons.
- **Idempotent migrations.** All schema uses `IF NOT EXISTS` and seed data uses `ON CONFLICT (id) DO NOTHING`, safe for repeated execution.
- **Pull-only deployment model.** The server never initiates outbound connections. Agents poll for work. Proxy agents handle network appliances (F5, IIS via WinRM) and agentless servers (SSH/SFTP).
- **Dynamic configuration.** Issuers and targets can be configured via GUI with AES-256-GCM encrypted credential storage. Env var backward compatibility preserved — env-configured connectors seed the database on first boot.

## CLI

```bash
# Install
go install github.com/shankar0123/certctl/cmd/cli@latest

# Configure
export CERTCTL_SERVER_URL=http://localhost:8443
export CERTCTL_API_KEY=your-api-key

# Usage
certctl-cli certs list                    # List all certificates
certctl-cli certs renew mc-api-prod       # Trigger renewal
certctl-cli certs revoke mc-api-prod --reason keyCompromise
certctl-cli agents list                   # List registered agents
certctl-cli jobs list                     # List jobs
certctl-cli status                        # Server health + summary stats
certctl-cli import certs.pem              # Bulk import from PEM file
certctl-cli certs list --format json      # JSON output (default: table)
```

## MCP Server (AI Integration)

certctl ships a standalone MCP (Model Context Protocol) server that exposes all 80 API endpoints as tools for AI assistants — Claude, Cursor, Windsurf, OpenClaw, VS Code Copilot, and any MCP-compatible client.

```bash
# Install and run
go install github.com/shankar0123/certctl/cmd/mcp-server@latest
export CERTCTL_SERVER_URL=http://localhost:8443
export CERTCTL_API_KEY=your-api-key
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

## Security

certctl is designed with a security-first architecture. Agents generate ECDSA P-256 keys locally — private keys never touch the control plane. API key auth is enforced by default with SHA-256 hashing and constant-time comparison. CORS is deny-by-default. All connector scripts are validated against shell injection. The network scanner filters reserved IP ranges (SSRF protection). Scheduler loops use atomic idempotency guards. Every API call is recorded to an immutable audit trail with actor attribution, SHA-256 body hash, and latency tracking. Issuer and target credentials are encrypted at rest with AES-256-GCM. See the [Architecture Guide](docs/architecture.md) for the full security model.

## Development

```bash
make build              # Build server + agent binaries
make test               # Run tests
make lint               # golangci-lint (11 linters)
govulncheck ./...       # Vulnerability scan
make docker-up          # Start Docker Compose stack
```

CI runs on every push: `go vet`, `go test -race`, `golangci-lint`, `govulncheck`, and per-layer coverage thresholds (service 55%, handler 60%, domain 40%, middleware 30%). Frontend CI runs TypeScript type checking, Vitest tests, and Vite production build. 1,668 Go test functions with 625+ subtests, plus frontend test suite.

## Roadmap

### V1 (v1.0.0) — Shipped
Core lifecycle management — Local CA + ACME v2 issuers, NGINX target connector, agent-side key generation, API auth + rate limiting, React dashboard, CI pipeline with coverage gates, Docker images on GHCR.

### V2: Operational Maturity — Shipped
30+ milestones shipping enterprise-grade features for free. Sub-CA mode, ACME DNS-01/DNS-PERSIST-01/EAB/ARI (RFC 9773)/profile selection, step-ca, Vault PKI, DigiCert CertCentral, Sectigo SCM, Google CAS, AWS ACM PCA, OpenSSL/Custom CA issuers. NGINX, Apache, HAProxy, Traefik, Caddy, Envoy, Postfix, Dovecot, IIS (WinRM), F5 BIG-IP, SSH, Windows Certificate Store, Java Keystore, Kubernetes Secrets targets. EST server (RFC 7030) and SCEP server (RFC 8894) enrollment protocols. RFC 5280 revocation with DER CRL + embedded OCSP responder. Certificate profiles, ownership tracking, team assignment, agent groups, interactive approval workflows. Filesystem and network certificate discovery with triage GUI. Dynamic issuer/target configuration via GUI with AES-256-GCM encrypted storage. First-run onboarding wizard. Post-deployment TLS verification. Certificate export (PEM/PKCS#12). S/MIME support. Prometheus metrics. Scheduled certificate digest emails. Slack, Teams, PagerDuty, OpsGenie, SMTP notifications. MCP server (80 tools), CLI (12 commands), Helm chart. Compliance mapping (SOC 2, PCI-DSS 4.0, NIST SP 800-57). 5 turnkey deployment examples. Agent install script. Migration guides from certbot, acme.sh, and cert-manager. See the [Feature Inventory](docs/features.md) for details.

### V3: certctl Pro
Team access controls and identity provider integration. Role-based access control with profile-gating. Event-driven architecture with real-time operational views. Advanced search, compliance scoring, bulk fleet operations.

### V4+: Cloud & Scale
Continuous TLS health monitoring, cloud secret manager discovery, Kubernetes cert-manager external issuer, cloud infrastructure targets, extended CA support, and platform-scale features.

## License

Certctl is licensed under the [Business Source License 1.1](LICENSE). The source code is publicly available and free to use, modify, and self-host. The one restriction: you may not use certctl's certificate management functionality as part of a commercial offering to third parties, whether hosted, managed, embedded, bundled, or integrated. The BSL 1.1 license converts automatically to Apache 2.0 on March 14, 2033.

For licensing inquiries: certctl@proton.me

---

If certctl solves a problem you have, [star the repo](https://github.com/shankar0123/certctl) to help others find it. Questions, bugs, or feature requests — [open an issue](https://github.com/shankar0123/certctl/issues).
