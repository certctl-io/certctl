# Quick Start Guide

Certificate lifespans are dropping to **47 days by 2029**. At that cadence, a team managing 100 certificates is processing 7+ renewals per week — every week, forever. Manual processes break. certctl automates the entire lifecycle: issuance, renewal, deployment, revocation, and audit — with zero human intervention.

This guide gets you running in 5 minutes and walks you through everything certctl does.

New to certificates? Read the [Concepts Guide](concepts.md) first — it explains TLS, CAs, and private keys in plain language.

## Contents

1. [Prerequisites](#prerequisites)
2. [Start Everything](#start-everything)
3. [Open the Dashboard](#open-the-dashboard)
4. [Explore the API](#explore-the-api)
   - [Core operations](#core-operations)
   - [Sorting, filtering, and pagination](#sorting-filtering-and-pagination)
   - [Stats and metrics](#stats-and-metrics)
5. [Create Your First Certificate](#create-your-first-certificate)
   - [Revoke a certificate](#revoke-a-certificate)
   - [Interactive approval workflow](#interactive-approval-workflow)
6. [Certificate Discovery](#certificate-discovery)
   - [Filesystem discovery (agent-based)](#filesystem-discovery-agent-based)
   - [Network discovery (agentless)](#network-discovery-agentless)
   - [Triage discovered certificates](#triage-discovered-certificates)
7. [CLI Tool](#cli-tool)
8. [MCP Server (AI Integration)](#mcp-server-ai-integration)
9. [Demo Data Reference](#demo-data-reference)
10. [Dashboard Demo Mode](#dashboard-demo-mode)
11. [Presenting to Stakeholders](#presenting-to-stakeholders)
12. [Tear Down](#tear-down)
13. [What's Next](#whats-next)

## Prerequisites

You need **Docker** and **Docker Compose** installed. That's it.

On macOS:
```bash
brew install --cask docker
```

On Linux, follow the official Docker install guide for your distribution.

## Start Everything

### Docker Compose (Quick Start)

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

> **Warning:** Edit `POSTGRES_PASSWORD` *before* the very first `docker compose up`. Postgres seeds the password into its data directory only on first boot of an empty volume — after that, the password is baked into `pg_authid` and the env var is ignored. If you boot once with the default and later change `POSTGRES_PASSWORD` in `.env`, the certctl-server container picks up the new value but postgres still authenticates against the old one, and the server logs `pq: password authentication failed for user "certctl"` (SQLSTATE 28P01). Two ways out: tear down the volume with `docker compose -f deploy/docker-compose.yml down -v` (this **deletes all data**) and bring up fresh, or rotate non-destructively with `docker compose -f deploy/docker-compose.yml exec postgres psql -U certctl -c "ALTER ROLE certctl PASSWORD '<new>';"` and then restart certctl-server with the matching `POSTGRES_PASSWORD`.

### Docker Compose Environments

The `deploy/` directory contains four compose files for different use cases:

| File | Purpose | How to run |
|------|---------|------------|
| `docker-compose.yml` | **Base platform.** PostgreSQL + certctl server + agent. Clean dashboard with onboarding wizard — use this for production or first-time setup. | `docker compose -f deploy/docker-compose.yml up --build` |
| `docker-compose.demo.yml` | **Demo data override.** Layers 180 days of realistic seed data (15 certs, 5 agents, multiple issuers) onto the base. Dashboard charts and tables look populated on first boot. | `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.demo.yml up --build` |
| `docker-compose.dev.yml` | **Development override.** Adds PgAdmin (port 5050), debug-level logging, and a Delve debugger port (40000) for the server. | `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.dev.yml up --build` |
| `docker-compose.test.yml` | **Integration test environment.** 7 containers on a static-IP subnet: PostgreSQL, certctl server+agent, step-ca, Pebble ACME server, challenge test server, and NGINX. Runs the full issuance→deployment→verification flow against real CA backends. Standalone — does not combine with the base file. | `docker compose -f deploy/docker-compose.test.yml up --build` |

Override files are layered onto the base with multiple `-f` flags. The test environment is self-contained and runs independently. To reset any environment's data, add `down -v` to remove volumes.

For a deep dive into every service, environment variable, and networking decision, see the [Docker Compose Environments Guide](../deploy/ENVIRONMENTS.md).

### Kubernetes with Helm

For production deployments on Kubernetes, use the Helm chart:

```bash
helm install certctl deploy/helm/certctl/ \
  --create-namespace --namespace certctl \
  --set server.auth.apiKey="your-secure-api-key" \
  --set postgresql.auth.password="your-db-password" \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host="certctl.example.com" \
  --set ingress.hosts[0].tls=true
```

The chart includes: server Deployment (with configurable replicas, health probes, security context), PostgreSQL StatefulSet with persistent volumes, agent DaemonSet (one agent per infrastructure node), optional Ingress with TLS, and ServiceAccount with RBAC. All certctl configuration options are exposed in `values.yaml` — customize issuer settings, target connectors, scheduler intervals, and notifier credentials there.

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

The control plane is HTTPS-only as of v2.2. The `certctl-tls-init` init container in the shipped `deploy/docker-compose.yml` self-signs a cert on first boot and drops it into a named volume. Extract the CA bundle once and reuse it for every API call in this guide:

```bash
export CA=/tmp/certctl-ca.crt
docker compose -f deploy/docker-compose.yml exec -T certctl-server \
  cat /etc/certctl/tls/ca.crt > "$CA"

curl --cacert "$CA" https://localhost:8443/health
```
```json
{"status":"healthy"}
```

If you're bringing your own cert (internal CA, cert-manager, operator-supplied Secret), see [`docs/tls.md`](tls.md) for the full provisioning matrix. If you're cutting over an existing install, see [`docs/upgrade-to-tls.md`](upgrade-to-tls.md) for the failure modes (out-of-date `http://…` agents fail at the TLS handshake) and the one-step procedure.

## Open the Dashboard

Open **https://localhost:8443** in your browser. Your browser will warn about the self-signed cert — that's expected for the demo bootstrap. Trust the CA bundle you just exported, or click through the warning.

> **Note:** The Docker Compose demo runs with authentication disabled (`CERTCTL_AUTH_TYPE=none`) so you can explore immediately. For production, set `CERTCTL_AUTH_TYPE=api-key` and `CERTCTL_AUTH_SECRET=<your-secret>` in your environment, then pass `Authorization: Bearer <your-secret>` on all API requests. The dashboard will prompt for your API key on first load.
>
> **Key rotation:** `CERTCTL_AUTH_SECRET` accepts comma-separated keys (e.g., `CERTCTL_AUTH_SECRET=new-key,old-key`). Both keys are valid simultaneously, enabling zero-downtime rotation: add the new key, roll clients over, then remove the old key.

The dashboard comes pre-loaded with 35 demo certificates across 5 issuers, 8 agents, and 90 days of job history — expiring certs, expired certs, active certs, failed renewals, revocations, discovery scans, and approval workflows. A realistic snapshot of what certificate management looks like in a real organization.

### What you're looking at

The main dashboard shows total certificates, how many are expiring soon, how many have expired, the renewal success rate, and four charts: an **expiration heatmap** (90-day weekly buckets), **renewal success rate trends** (30-day line chart), **certificate status distribution** (donut chart), and **issuance rate** (30-day bar chart).

Explore the sidebar: Certificates, Agents, Policies, Jobs, Audit Trail, Notifications, Profiles, Teams, Owners, Agent Groups, Fleet Overview, Short-Lived Credentials, Discovery, and Network Scans.

### Scenarios to walk through

**"We're about to have an outage"** — Filter certificates by status → Expiring. You'll see `auth-production` (12 days), `cdn-production` (8 days), and `mail-production` (5 days). At 47-day lifespans, this is every other week. certctl catches these automatically and triggers renewal before they expire.

**"A renewal failed"** — Look at `vpn-production` — status: Failed. Click it to see the audit trail showing the ACME challenge failure after 3 retry attempts. The system sent a webhook notification to the ops channel. No one had to notice manually.

**"Who owns this cert?"** — Click any certificate. Owner, team, environment, tags. Clear accountability. Notifications route to the owner's email automatically.

**"Can I revoke a compromised cert?"** — Click any active certificate, then "Revoke." A modal with RFC 5280 reason codes (Key Compromise, Superseded, Cessation of Operation). After revocation, CRL and OCSP are served automatically — clients stop trusting the cert immediately.

**"What about certificates already in production?"** — Click "Discovery" in the sidebar. The demo comes pre-loaded with 9 discovered certificates — some found by agents scanning filesystems, some found by the server probing TLS endpoints on the network. You'll see Unmanaged certs waiting for triage (including an expired printer cert and an expiring switch management cert), certs already linked to managed inventory, and one that was dismissed. Claim unmanaged certs to bring them under automation, or dismiss them. Click "Network Scans" to see the 3 configured scan targets with recent scan results.

**"I need to approve a renewal before it proceeds"** — Click "Jobs" in the sidebar. You'll see an amber banner: "2 jobs awaiting approval." These are renewal jobs for `auth-production` and `payments-production` that require human sign-off before proceeding. Click Approve or Reject with a reason — the decision is recorded in the audit trail.

**"Show me the agent fleet"** — Click "Agents." Eight agents across Linux, macOS, and Windows platforms—most online, showing OS, architecture, IP, and version metadata. A ninth entry (server-scanner) is the sentinel agent used for network certificate discovery. Click "Fleet Overview" for OS/architecture grouping, version distribution, and per-platform listing. Agents generate ECDSA P-256 keys locally — private keys never leave your infrastructure.

**"What about bulk operations?"** — On the Certificates page, select multiple certificates with checkboxes. A bulk action bar appears: trigger renewal, revoke with reason codes, or reassign ownership — all with progress tracking. At 47-day lifespans with hundreds of certs, bulk operations aren't optional.

**"Short-lived credentials?"** — Click "Short-Lived" in the sidebar. Live countdown timers for certificates with TTL under 1 hour. Auto-refresh every 10 seconds. These are for service-to-service auth where rapid expiry replaces revocation.

## Explore the API

Everything you see in the dashboard is backed by the REST API. All endpoints live under `/api/v1/` and return JSON.

### Core operations

Every request below uses `--cacert "$CA"` to pin the self-signed CA bundle extracted above. In production, point `$CA` at your internal CA root or the bundle you distributed to the fleet.

```bash
# List all certificates
curl --cacert "$CA" -s https://localhost:8443/api/v1/certificates | jq .

# Filter by status
curl --cacert "$CA" -s "https://localhost:8443/api/v1/certificates?status=Expiring" | jq .

# Filter by environment
curl --cacert "$CA" -s "https://localhost:8443/api/v1/certificates?environment=production" | jq .

# Get a specific certificate
curl --cacert "$CA" -s https://localhost:8443/api/v1/certificates/mc-api-prod | jq .

# Get deployment targets for a certificate
curl --cacert "$CA" -s https://localhost:8443/api/v1/certificates/mc-api-prod/deployments | jq .

# List agents
curl --cacert "$CA" -s https://localhost:8443/api/v1/agents | jq .

# Check agent pending work
curl --cacert "$CA" -s https://localhost:8443/api/v1/agents/ag-web-prod/work | jq .

# View audit trail
curl --cacert "$CA" -s https://localhost:8443/api/v1/audit | jq .

# View policies and violations
curl --cacert "$CA" -s https://localhost:8443/api/v1/policies | jq .
curl --cacert "$CA" -s https://localhost:8443/api/v1/policies/pr-require-owner/violations | jq .

# Notifications
curl --cacert "$CA" -s https://localhost:8443/api/v1/notifications | jq .

# Profiles and agent groups
curl --cacert "$CA" -s https://localhost:8443/api/v1/profiles | jq .
curl --cacert "$CA" -s https://localhost:8443/api/v1/agent-groups | jq .
```

### Sorting, filtering, and pagination

```bash
# Sort by expiration date (ascending)
curl --cacert "$CA" -s "https://localhost:8443/api/v1/certificates?sort=notAfter" | jq .

# Sort descending (prefix with -)
curl --cacert "$CA" -s "https://localhost:8443/api/v1/certificates?sort=-createdAt" | jq .

# Time-range filters (RFC3339)
curl --cacert "$CA" -s "https://localhost:8443/api/v1/certificates?expires_before=2026-05-01T00:00:00Z" | jq .
curl --cacert "$CA" -s "https://localhost:8443/api/v1/certificates?created_after=2026-03-01T00:00:00Z" | jq .

# Sparse fields — request only what you need
curl --cacert "$CA" -s "https://localhost:8443/api/v1/certificates?fields=id,common_name,status,expires_at" | jq .

# Cursor pagination — efficient for large inventories
curl --cacert "$CA" -s "https://localhost:8443/api/v1/certificates?page_size=5" | jq '{next_cursor: .next_cursor, count: (.data | length)}'
curl --cacert "$CA" -s "https://localhost:8443/api/v1/certificates?cursor=<next_cursor_value>&page_size=5" | jq .
```

Supported sort fields: `notAfter`, `expiresAt`, `createdAt`, `updatedAt`, `commonName`, `name`, `status`, `environment`.

### Stats and metrics

```bash
# Dashboard summary
curl --cacert "$CA" -s https://localhost:8443/api/v1/stats/summary | jq .

# Certificates by status
curl --cacert "$CA" -s https://localhost:8443/api/v1/stats/certificates-by-status | jq .

# Expiration timeline (next 90 days)
curl --cacert "$CA" -s "https://localhost:8443/api/v1/stats/expiration-timeline?days=90" | jq .

# Job trends (last 30 days)
curl --cacert "$CA" -s "https://localhost:8443/api/v1/stats/job-trends?days=30" | jq .

# JSON metrics
curl --cacert "$CA" -s https://localhost:8443/api/v1/metrics | jq .

# Prometheus format (for Prometheus, Grafana Agent, Datadog)
curl --cacert "$CA" -s https://localhost:8443/api/v1/metrics/prometheus
```

## Create Your First Certificate

Create a certificate record that certctl will track, renew, and deploy automatically.

```bash
curl --cacert "$CA" -s -X POST https://localhost:8443/api/v1/certificates \
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
curl --cacert "$CA" -s -X POST https://localhost:8443/api/v1/certificates/$CERT_ID/renew | jq .
```

Check the result:
```bash
curl --cacert "$CA" -s https://localhost:8443/api/v1/certificates/$CERT_ID | jq .
```

Refresh the dashboard at https://localhost:8443 — your new certificate appears in the inventory.

### Revoke a certificate

When a private key is compromised or a service is decommissioned:

```bash
curl --cacert "$CA" -s -X POST https://localhost:8443/api/v1/certificates/$CERT_ID/revoke \
  -H "Content-Type: application/json" \
  -d '{"reason": "superseded"}' | jq .
```

Supported RFC 5280 reason codes: `unspecified`, `keyCompromise`, `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn`.

Confirm via the unauthenticated DER CRL (RFC 5280 §5, RFC 8615):
```bash
# Fetch the CRL without any API key — relying parties shouldn't need one.
# The CRL path is unauthenticated, but it's still served over TLS.
curl --cacert "$CA" -s https://localhost:8443/.well-known/pki/crl/iss-local -o /tmp/crl.der
openssl crl -inform der -in /tmp/crl.der -noout -text | head -40
```

### Interactive approval workflow

For high-value certificates where you want human oversight. The demo includes 2 pre-seeded jobs in `AwaitingApproval` status (for `auth-production` and `payments-production`). Open **Jobs** in the sidebar and you'll see the amber "Pending Approval" banner immediately.

```bash
# List jobs awaiting approval (demo includes 2)
curl --cacert "$CA" -s "https://localhost:8443/api/v1/jobs?status=AwaitingApproval" | jq '.data[] | {id, certificate_id, status}'

# Approve a pending job
curl --cacert "$CA" -s -X POST https://localhost:8443/api/v1/jobs/JOB_ID/approve \
  -H "Content-Type: application/json" \
  -d '{"reason": "Approved for production deployment"}' | jq .

# Reject a pending job
curl --cacert "$CA" -s -X POST https://localhost:8443/api/v1/jobs/JOB_ID/reject \
  -H "Content-Type: application/json" \
  -d '{"reason": "Key type does not meet compliance requirements"}' | jq .
```

## Certificate Discovery

Find certificates already running in your infrastructure — ones you didn't issue through certctl.

The demo environment comes pre-loaded with 9 discovered certificates (from agent filesystem scans and server-side network scans), 3 network scan targets, and recent scan history. Open **Discovery** and **Network Scans** in the sidebar to see the triage workflow immediately.

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
curl --cacert "$CA" -s -X POST https://localhost:8443/api/v1/network-scan-targets \
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
curl --cacert "$CA" -s -X POST https://localhost:8443/api/v1/network-scan-targets/nst-internal-network/scan | jq .
```

### Triage discovered certificates

```bash
# List discovered certs
curl --cacert "$CA" -s "https://localhost:8443/api/v1/discovered-certificates?agent_id=agent-nginx-prod" | jq .

# Summary counts
curl --cacert "$CA" -s https://localhost:8443/api/v1/discovery-summary | jq .

# Claim a discovered cert (bring under management)
curl --cacert "$CA" -s -X POST "https://localhost:8443/api/v1/discovered-certificates/DISCOVERY_ID/claim" \
  -H "Content-Type: application/json" \
  -d '{"managed_certificate_id": "mc-api-prod"}' | jq .
```

## CLI Tool

```bash
cd cmd/cli && go build -o certctl-cli .

export CERTCTL_SERVER_URL="https://localhost:8443"
export CERTCTL_API_KEY="test-key-123"
export CERTCTL_SERVER_CA_BUNDLE_PATH="$CA"   # or pass --ca-bundle; --insecure for dev self-signed

./certctl-cli certs list               # List certificates
./certctl-cli certs get mc-api-prod    # Certificate details
./certctl-cli certs renew mc-api-prod  # Trigger renewal
./certctl-cli certs revoke mc-api-prod --reason keyCompromise
./certctl-cli agents list              # List agents
./certctl-cli jobs list                # List jobs
./certctl-cli import /path/to/certs.pem  # Bulk import
./certctl-cli status                   # Health + stats
```

## Scheduled Certificate Digest Emails

Enable automatic HTML digest emails with certificate stats, expiration timeline, and job health:

```bash
# Set SMTP configuration
export CERTCTL_SMTP_HOST=smtp.gmail.com
export CERTCTL_SMTP_PORT=587
export CERTCTL_SMTP_USERNAME=admin@example.com
export CERTCTL_SMTP_PASSWORD=your-app-password
export CERTCTL_SMTP_FROM_ADDRESS=certctl@example.com
export CERTCTL_SMTP_USE_TLS=true

# Enable digest and set recipients
export CERTCTL_DIGEST_ENABLED=true
export CERTCTL_DIGEST_INTERVAL=24h
export CERTCTL_DIGEST_RECIPIENTS=ops@example.com,security@example.com
```

Preview the digest HTML before enabling scheduled delivery:
```bash
curl --cacert "$CA" https://localhost:8443/api/v1/digest/preview | jq '.html' | grep -o '<html>' # Shows HTML is ready

# Trigger a digest send immediately (outside of schedule)
curl --cacert "$CA" -X POST https://localhost:8443/api/v1/digest/send
```

If no recipients are configured (`CERTCTL_DIGEST_RECIPIENTS` empty), the digest falls back to certificate owner emails. Digests include total certificates, expiring soon, expired, active agents, completed/failed jobs (30-day summary), and a table of expiring certs color-coded by urgency (7/14/30 days).

## MCP Server (AI Integration)

```bash
cd cmd/mcp-server && go build -o mcp-server .

export CERTCTL_SERVER_URL="https://localhost:8443"
export CERTCTL_API_KEY="test-key-123"
export CERTCTL_SERVER_CA_BUNDLE_PATH="$CA"   # MCP is env-vars-only; no CLI flags

./mcp-server
```

Exposes the full REST API via MCP over stdio transport. Ask Claude: "What certificates are expiring in the next 30 days?", "Revoke the payments cert due to key compromise", "Show me the audit trail."

## Demo Data Reference

| Resource | Count | Examples |
|----------|-------|---------|
| Teams | 6 | Platform, Security, Payments, Frontend, Data, DevOps |
| Owners | 6 | Alice, Bob, Carol, Dave, Eve, Frank |
| Issuers | 5 | Local Dev CA, Let's Encrypt Staging, step-ca Internal, ZeroSSL (EAB), Custom OpenSSL CA |
| Agents | 9 | 8 real agents (linux/darwin/windows, amd64/arm64) + server-scanner (network discovery) |
| Targets | 8 | NGINX prod, NGINX staging, NGINX data, HAProxy, Apache, IIS, Traefik, Caddy |
| Certificates | 35 | Active, Expiring, Expired, Failed, Revoked, RenewalInProgress, Wildcard, S/MIME |
| Jobs | 50+ | 90 days of issuance, renewal, deployment jobs + 2 AwaitingApproval |
| Discovered Certs | 12 | Unmanaged (filesystem + network), Managed (linked), Dismissed |
| Discovery Scans | 8 | Historical + recent agent filesystem scans + network TLS scans |
| Network Scan Targets | 4 | DC1 Web Servers, DC2 Application Tier, DMZ Public Endpoints, Edge Locations |
| Audit Events | 55+ | 90 days of lifecycle events (issuance, renewal, deployment, revocation, discovery) |
| Policies | 4 | Required owner, allowed environments, max lifetime, min renewal window |
| Profiles | 5 | Standard TLS, Internal mTLS, Short-Lived, High Security, S/MIME Email |
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

**Ready to deploy with your stack?** The [Deployment Examples](examples.md) page has 5 turnkey docker-compose scenarios — pick the one closest to your setup and have it running in minutes. It also covers migration paths from Certbot, acme.sh, and cert-manager.

- **[Deployment Examples](examples.md)** — ACME+NGINX, wildcard DNS-01, private CA+Traefik, step-ca+HAProxy, multi-issuer
- **[Advanced Demo](demo-advanced.md)** — Issue a real certificate via the Local CA end-to-end
- **[Architecture](architecture.md)** — How the control plane, agents, and connectors work together
- **[Connector Reference](connectors.md)** — Configuration for all 7 issuers and 10 targets
- **[Concepts Guide](concepts.md)** — TLS certificates, CAs, and private keys explained from scratch
