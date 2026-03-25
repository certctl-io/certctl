# Quick Start Guide

Certificate lifespans are dropping to **47 days by 2029**. At that cadence, a team managing 100 certificates is processing 7+ renewals per week — every week, forever. Manual processes break. certctl automates the entire lifecycle: issuance, renewal, deployment, revocation, and audit — with zero human intervention.

This guide gets you running in 5 minutes and walks you through everything certctl does.

New to certificates? Read the [Concepts Guide](concepts.md) first — it explains TLS, CAs, and private keys in plain language.

## Prerequisites

You need **Docker** and **Docker Compose** installed. That's it.

On macOS:
```bash
brew install --cask docker
```

On Linux, follow the official Docker install guide for your distribution.

## Start Everything

```bash
git clone https://github.com/shankar0123/certctl.git
cd certctl
docker compose -f deploy/docker-compose.yml up -d --build
```

The `--build` flag builds the server image including the React frontend. Without it, Docker may use a stale cached image.

**For production deployments**, copy `deploy/.env.example` to `deploy/.env` and customize the credentials:
```bash
cp deploy/.env.example deploy/.env
# Edit deploy/.env to set secure POSTGRES_PASSWORD and CERTCTL_API_KEY values
docker compose -f deploy/docker-compose.yml up -d --build
```

Wait about 30 seconds for PostgreSQL to initialize, then verify:

```bash
docker compose -f deploy/docker-compose.yml ps
```

You should see:
```
NAME                 STATUS
certctl-postgres     Up (healthy)
certctl-server       Up (healthy)
certctl-agent        Up
```

```bash
curl http://localhost:8443/health
```
```json
{"status":"healthy"}
```

## Open the Dashboard

Open **http://localhost:8443** in your browser.

The dashboard comes pre-loaded with 15 demo certificates across multiple teams, environments, and statuses — expiring certs, expired certs, active certs, failed renewals. A realistic snapshot of what certificate management looks like in a real organization.

### What you're looking at

The main dashboard shows total certificates, how many are expiring soon, how many have expired, the renewal success rate, and four charts: an **expiration heatmap** (90-day weekly buckets), **renewal success rate trends** (30-day line chart), **certificate status distribution** (donut chart), and **issuance rate** (30-day bar chart).

Explore the sidebar: Certificates, Agents, Policies, Jobs, Audit Trail, Notifications, Profiles, Teams, Owners, Agent Groups, Fleet Overview, Short-Lived Credentials, Discovery.

### Scenarios to walk through

**"We're about to have an outage"** — Filter certificates by status → Expiring. You'll see `auth-production` (12 days), `cdn-production` (8 days), and `mail-production` (5 days). At 47-day lifespans, this is every other week. certctl catches these automatically and triggers renewal before they expire.

**"A renewal failed"** — Look at `vpn-production` — status: Failed. Click it to see the audit trail showing the ACME challenge failure after 3 retry attempts. The system sent a webhook notification to the ops channel. No one had to notice manually.

**"Who owns this cert?"** — Click any certificate. Owner, team, environment, tags. Clear accountability. Notifications route to the owner's email automatically.

**"Can I revoke a compromised cert?"** — Click any active certificate, then "Revoke." A modal with RFC 5280 reason codes (Key Compromise, Superseded, Cessation of Operation). After revocation, CRL and OCSP are served automatically — clients stop trusting the cert immediately.

**"What about certificates already in production?"** — Click "Discovered Certificates." Agents scan local filesystems for existing certs. The server probes TLS endpoints on configured CIDR ranges. Both feed into a triage workflow: claim unmanaged certs to bring them under automation, or dismiss them.

**"Show me the agent fleet"** — Click "Agents." Four agents online, one offline. Click "Fleet Overview" for OS/architecture grouping, version distribution, and per-platform listing. Agents generate ECDSA P-256 keys locally — private keys never leave your infrastructure.

**"What about bulk operations?"** — On the Certificates page, select multiple certificates with checkboxes. A bulk action bar appears: trigger renewal, revoke with reason codes, or reassign ownership — all with progress tracking. At 47-day lifespans with hundreds of certs, bulk operations aren't optional.

**"Short-lived credentials?"** — Click "Short-Lived" in the sidebar. Live countdown timers for certificates with TTL under 1 hour. Auto-refresh every 10 seconds. These are for service-to-service auth where rapid expiry replaces revocation.

## Explore the API

Everything you see in the dashboard is backed by the REST API. All endpoints live under `/api/v1/` and return JSON.

### Core operations

```bash
# List all certificates
curl -s http://localhost:8443/api/v1/certificates | jq .

# Filter by status
curl -s "http://localhost:8443/api/v1/certificates?status=Expiring" | jq .

# Filter by environment
curl -s "http://localhost:8443/api/v1/certificates?environment=production" | jq .

# Get a specific certificate
curl -s http://localhost:8443/api/v1/certificates/mc-api-prod | jq .

# Get deployment targets for a certificate
curl -s http://localhost:8443/api/v1/certificates/mc-api-prod/deployments | jq .

# List agents
curl -s http://localhost:8443/api/v1/agents | jq .

# Check agent pending work
curl -s http://localhost:8443/api/v1/agents/agent-nginx-prod/work | jq .

# View audit trail
curl -s http://localhost:8443/api/v1/audit | jq .

# View policies and violations
curl -s http://localhost:8443/api/v1/policies | jq .
curl -s http://localhost:8443/api/v1/policies/pr-require-owner/violations | jq .

# Notifications
curl -s http://localhost:8443/api/v1/notifications | jq .

# Profiles and agent groups
curl -s http://localhost:8443/api/v1/profiles | jq .
curl -s http://localhost:8443/api/v1/agent-groups | jq .
```

### Sorting, filtering, and pagination

```bash
# Sort by expiration date (ascending)
curl -s "http://localhost:8443/api/v1/certificates?sort=notAfter" | jq .

# Sort descending (prefix with -)
curl -s "http://localhost:8443/api/v1/certificates?sort=-createdAt" | jq .

# Time-range filters (RFC3339)
curl -s "http://localhost:8443/api/v1/certificates?expires_before=2026-05-01T00:00:00Z" | jq .
curl -s "http://localhost:8443/api/v1/certificates?created_after=2026-03-01T00:00:00Z" | jq .

# Sparse fields — request only what you need
curl -s "http://localhost:8443/api/v1/certificates?fields=id,common_name,status,expires_at" | jq .

# Cursor pagination — efficient for large inventories
curl -s "http://localhost:8443/api/v1/certificates?page_size=5" | jq '{next_cursor: .next_cursor, count: (.data | length)}'
curl -s "http://localhost:8443/api/v1/certificates?cursor=<next_cursor_value>&page_size=5" | jq .
```

Supported sort fields: `notAfter`, `expiresAt`, `createdAt`, `updatedAt`, `commonName`, `name`, `status`, `environment`.

### Stats and metrics

```bash
# Dashboard summary
curl -s http://localhost:8443/api/v1/stats/summary | jq .

# Certificates by status
curl -s http://localhost:8443/api/v1/stats/certificates-by-status | jq .

# Expiration timeline (next 90 days)
curl -s "http://localhost:8443/api/v1/stats/expiration-timeline?days=90" | jq .

# Job trends (last 30 days)
curl -s "http://localhost:8443/api/v1/stats/job-trends?days=30" | jq .

# JSON metrics
curl -s http://localhost:8443/api/v1/metrics | jq .

# Prometheus format (for Prometheus, Grafana Agent, Datadog)
curl -s http://localhost:8443/api/v1/metrics/prometheus
```

## Create Your First Certificate

Create a certificate record that certctl will track, renew, and deploy automatically.

```bash
curl -s -X POST http://localhost:8443/api/v1/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My First Certificate",
    "common_name": "myapp.example.com",
    "sans": ["myapp.example.com", "www.myapp.example.com"],
    "environment": "staging",
    "owner_id": "o-alice",
    "team_id": "t-platform",
    "issuer_id": "iss-local",
    "renewal_policy_id": "rp-default",
    "status": "Pending",
    "tags": {"purpose": "quickstart-demo"}
  }' | jq .
```

Save the certificate ID (or provide your own `id` in the request body, e.g. `"id": "mc-my-first"`):
```bash
CERT_ID="<paste the id from the response>"
```

Trigger renewal:
```bash
curl -s -X POST http://localhost:8443/api/v1/certificates/$CERT_ID/renew | jq .
```

Check the result:
```bash
curl -s http://localhost:8443/api/v1/certificates/$CERT_ID | jq .
```

Refresh the dashboard at http://localhost:8443 — your new certificate appears in the inventory.

### Revoke a certificate

When a private key is compromised or a service is decommissioned:

```bash
curl -s -X POST http://localhost:8443/api/v1/certificates/$CERT_ID/revoke \
  -H "Content-Type: application/json" \
  -d '{"reason": "superseded"}' | jq .
```

Supported RFC 5280 reason codes: `unspecified`, `keyCompromise`, `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn`.

Confirm via CRL:
```bash
curl -s http://localhost:8443/api/v1/crl | jq .
```

### Interactive approval workflow

For high-value certificates where you want human oversight:

```bash
# Approve a pending job
curl -s -X POST http://localhost:8443/api/v1/jobs/JOB_ID/approve \
  -H "Content-Type: application/json" \
  -d '{"reason": "Approved for production deployment"}' | jq .

# Reject a pending job
curl -s -X POST http://localhost:8443/api/v1/jobs/JOB_ID/reject \
  -H "Content-Type: application/json" \
  -d '{"reason": "Key type does not meet compliance requirements"}' | jq .
```

## Certificate Discovery

Find certificates already running in your infrastructure — ones you didn't issue through certctl.

### Filesystem discovery (agent-based)

```bash
# Configure agent to scan directories
export CERTCTL_DISCOVERY_DIRS="/etc/nginx/certs,/etc/ssl/certs,/var/lib/certs"
# Agent scans on startup + every 6 hours
```

### Network discovery (agentless)

```bash
# Enable network scanning
export CERTCTL_NETWORK_SCAN_ENABLED=true

# Create a scan target
curl -s -X POST http://localhost:8443/api/v1/network-scan-targets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Internal Network",
    "cidrs": ["10.0.1.0/24"],
    "ports": [443, 8443],
    "enabled": true,
    "scan_interval_hours": 6,
    "timeout_ms": 5000
  }' | jq .

# Trigger an immediate scan
curl -s -X POST http://localhost:8443/api/v1/network-scan-targets/nst-internal-network/scan | jq .
```

### Triage discovered certificates

```bash
# List discovered certs
curl -s "http://localhost:8443/api/v1/discovered-certificates?agent_id=agent-nginx-prod" | jq .

# Summary counts
curl -s http://localhost:8443/api/v1/discovery-summary | jq .

# Claim a discovered cert (bring under management)
curl -s -X POST "http://localhost:8443/api/v1/discovered-certificates/DISCOVERY_ID/claim" \
  -H "Content-Type: application/json" \
  -d '{"managed_certificate_id": "mc-api-prod"}' | jq .
```

## CLI Tool

```bash
cd cmd/cli && go build -o certctl-cli .

export CERTCTL_SERVER_URL="http://localhost:8443"
export CERTCTL_API_KEY="test-key-123"

./certctl-cli certs list               # List certificates
./certctl-cli certs get mc-api-prod    # Certificate details
./certctl-cli certs renew mc-api-prod  # Trigger renewal
./certctl-cli certs revoke mc-api-prod --reason keyCompromise
./certctl-cli agents list              # List agents
./certctl-cli jobs list                # List jobs
./certctl-cli import /path/to/certs.pem  # Bulk import
./certctl-cli status                   # Health + stats
```

## MCP Server (AI Integration)

```bash
cd cmd/mcp-server && go build -o mcp-server .

export CERTCTL_SERVER_URL="http://localhost:8443"
export CERTCTL_API_KEY="test-key-123"

./mcp-server
```

Exposes all 78 API endpoints as MCP tools via stdio transport. Ask Claude: "What certificates are expiring in the next 30 days?", "Revoke the payments cert due to key compromise", "Show me the audit trail."

## Demo Data Reference

| Resource | Count | Examples |
|----------|-------|---------|
| Teams | 5 | Platform, Security, Payments, Frontend, Data |
| Owners | 5 | Alice, Bob, Carol, Dave, Eve |
| Issuers | 4 | Local Dev CA, Let's Encrypt Staging, step-ca Internal, DigiCert (disabled) |
| Agents | 5 | nginx-prod, nginx-staging, f5-prod, iis-prod, data-agent |
| Targets | 5 | NGINX (prod/staging/data), F5 LB, IIS |
| Certificates | 15 | Various statuses: Active, Expiring, Expired, Failed, Wildcard |
| Policies | 4 | Required owner, allowed environments, max lifetime, min renewal window |
| Profiles | 3 | Default TLS, Short-Lived, High-Security |
| Agent Groups | 5 | Linux agents, ARM agents, Production subnet, etc. |

## Dashboard Demo Mode

The dashboard works without a backend for screenshots and presentations:

```bash
cd web && npm install && npm run dev
# Dashboard at http://localhost:5173
```

When the API is unreachable, the dashboard loads realistic mock data with a "Demo Mode" badge.

## Presenting to Stakeholders

A suggested 5-minute flow:

1. **Dashboard** — "Certificate inventory at a glance. Real-time charts show expiration trends and renewal health."
2. **Expiring certs** — "These three would have caused outages. At 47-day lifespans, this happens every other week."
3. **Certificate detail** — "Full lifecycle: who owns it, where it's deployed, deployment timeline, version history with rollback."
4. **Revocation** — "One click revokes with an RFC 5280 reason code. CRL and OCSP served automatically."
5. **Failed renewal** — "System tried 3 times, then alerted the team via Slack, Teams, PagerDuty, or OpsGenie."
6. **Agent fleet** — "Agents handle key generation locally (ECDSA P-256). Private keys never leave your infrastructure."
7. **Discovery** — "Agents scan filesystems, server probes TLS endpoints. We find what you're not managing yet."
8. **Bulk operations** — "Select multiple certs, renew or revoke in bulk. At 47-day lifespans with hundreds of certs, this is essential."
9. **Audit trail** — "Every action recorded. Export to CSV/JSON for compliance."
10. **CLI + MCP** — "Terminal users get `certctl-cli`. AI assistants get MCP integration. Everything is API-first."

## Tear Down

```bash
docker compose -f deploy/docker-compose.yml down -v
```

The `-v` flag removes the PostgreSQL data volume for a clean slate.

## What's Next

- **[Advanced Demo](demo-advanced.md)** — Issue a real certificate via the Local CA end-to-end
- **[Architecture](architecture.md)** — How the control plane, agents, and connectors work together
- **[Connector Guide](connectors.md)** — Build custom connectors for your infrastructure
- **[Concepts Guide](concepts.md)** — TLS certificates, CAs, and private keys explained from scratch
