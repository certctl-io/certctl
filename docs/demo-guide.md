# certctl Demo Guide

A 5-10 minute guided walkthrough of certctl's dashboard and API. Perfect for stakeholder presentations and team demos.

New to certificates? Read the [Concepts Guide](concepts.md) first. Want a hands-on demo where you issue certificates yourself? See the [Advanced Demo](demo-advanced.md).

## Quick Start

```bash
git clone https://github.com/shankar0123/certctl.git
cd certctl
docker compose -f deploy/docker-compose.yml up -d --build
```

Wait ~30 seconds for PostgreSQL to initialize and the server to start, then open:

**http://localhost:8443**

You'll see the dashboard pre-loaded with 15 demo certificates across multiple teams, environments, and statuses — including expiring, expired, active, failed, wildcard, and in-progress renewals.

## What You'll See

### Dashboard Overview
The main dashboard shows at a glance:
- **Total certificates** managed across your infrastructure
- **Expiring soon** — certificates within 30 days of expiration (yellow/red)
- **Expired** — certificates past their expiration date
- **Active** — healthy certificates with time remaining
- **Renewal success rate** — percentage of automated renewals that succeeded

Below the stats, interactive charts provide deeper visibility: an **expiration heatmap** (90-day weekly buckets), **renewal success rate trends** (30-day line chart), **certificate status distribution** (donut chart), and **issuance rate** (30-day bar chart).

### Certificates View
Click "Certificates" in the sidebar to see the full inventory:
- Search by name or domain
- Filter by status (Active, Expiring, Expired, Failed) or environment (Production, Staging)
- Sort by any column
- Click any row to see full details: metadata, version history, deployment targets, and audit trail

### Demo Scenarios to Walk Through

**1. "We're about to have an outage"**
Filter by status → Expiring. You'll see `auth-production` (12 days), `cdn-production` (8 days), and `mail-production` (5 days). These are real alerts the platform would catch automatically.

**2. "A renewal failed"**
Look at `vpn-production` — status: Failed. Click it to see the audit trail showing the ACME challenge failure after 3 retry attempts. The system sent a webhook notification to the ops channel.

**3. "Who owns this cert?"**
Click any certificate to see the owner, team, environment, and tags. Every cert has clear accountability.

**4. "What happened to the legacy app?"**
Filter by status → Expired. `legacy-app` expired 3 days ago, `old-api-v1` expired 15 days ago. Both have policy violations flagged.

**5. "Show me the agent fleet"**
Click "Agents" in the sidebar. Four agents are online, one (`iis-prod-agent`) went offline 3 hours ago — you'd want to investigate that.

**6. "What policies are enforced?"**
Click "Policies" to see the active rules: required owner metadata, allowed environments, max certificate lifetime, minimum renewal window. Check the violations list to see which certs are non-compliant.

**7. "Can I revoke a compromised cert?"**
Click any active certificate, then click the "Revoke" button. A modal appears with RFC 5280 reason codes (Key Compromise, Superseded, Cessation of Operation, etc.). After revocation, the cert shows a revocation banner with the reason and timestamp.

**8. "Show me short-lived credentials"**
Click "Short-Lived" in the sidebar. This view shows certificates with TTL under 1 hour — live countdown timers, auto-refresh every 10 seconds, and profile-based filtering. These are for service-to-service auth where rapid expiry replaces revocation.

**9. "What about bulk operations?"**
On the Certificates page, select multiple certificates using the checkboxes. A bulk action bar appears with options to trigger renewal, revoke (with reason codes), or reassign ownership — all with progress tracking.

**10. "How do I see the deployment history?"**
Click any certificate, then scroll to the deployment timeline. A visual 4-step timeline shows the lifecycle: Requested → Issued → Deploying → Active. Previous versions show a rollback button.

**11. "What about certificates already running in production?"**
Enable discovery on agents by setting `CERTCTL_DISCOVERY_DIRS` to directories containing certificates (e.g., `/etc/nginx/certs`). Agents scan on startup and every 6 hours, report findings to the control plane. Click "Discovered Certificates" to see what agents found — claim unmanaged certs to bring them under certctl's management, or dismiss them.

## API Walkthrough

The dashboard is backed by a real REST API. Try these while the demo is running:

```bash
# List all certificates
curl -s http://localhost:8443/api/v1/certificates | jq .

# Get expiring certs
curl -s "http://localhost:8443/api/v1/certificates?status=expiring" | jq .

# Get a specific certificate
curl -s http://localhost:8443/api/v1/certificates/mc-api-prod | jq .

# List agents
curl -s http://localhost:8443/api/v1/agents | jq .

# View audit trail
curl -s http://localhost:8443/api/v1/audit | jq .

# View policy violations (replace POLICY_ID with a real policy ID, e.g. pr-require-owner)
curl -s http://localhost:8443/api/v1/policies/pr-require-owner/violations | jq .

# Check system health
curl -s http://localhost:8443/health | jq .

# Dashboard stats
curl -s http://localhost:8443/api/v1/stats/summary | jq .

# System metrics (cert totals, agent counts, job stats)
curl -s http://localhost:8443/api/v1/metrics | jq .

# Certificate profiles
curl -s http://localhost:8443/api/v1/profiles | jq .

# Agent groups
curl -s http://localhost:8443/api/v1/agent-groups | jq .

# Revoke a certificate
curl -s -X POST http://localhost:8443/api/v1/certificates/mc-api-prod/revoke \
  -H "Content-Type: application/json" \
  -d '{"reason": "superseded"}' | jq .

# List discovered certificates
curl -s http://localhost:8443/api/v1/discovered-certificates | jq .

# Discovery summary (counts by status)
curl -s http://localhost:8443/api/v1/discovery-summary | jq .
```

## Demo Without Docker

The dashboard includes a **Demo Mode** that works without any backend. Build and serve the frontend with Vite:

```bash
cd web
npm install
npm run dev
# Dashboard available at http://localhost:5173
```

When the API is unreachable, the dashboard automatically loads realistic mock data and shows a subtle "Demo Mode" badge. This is perfect for screenshots, presentations, or quick demos without any infrastructure.

## Teardown

```bash
docker compose -f deploy/docker-compose.yml down -v
```

The `-v` flag removes the PostgreSQL data volume so you get a clean slate next time.

## Presenting to Stakeholders

If you're demoing to a team or customer, here's a suggested flow:

1. **Start with the dashboard** — "This is your certificate inventory at a glance, with real-time charts showing expiration trends and renewal health"
2. **Show the expiring certs** — "These three would have caused outages without this platform"
3. **Click into auth-production** — "Here's the full lifecycle: who owns it, where it's deployed, deployment timeline, when it was last renewed"
4. **Show revocation** — "If a key is compromised, one click revokes the cert with an RFC 5280 reason code. CRL and OCSP are served automatically"
5. **Show the failed VPN cert** — "The system tried 3 times, then alerted the team via Slack, Teams, PagerDuty, or OpsGenie"
6. **Show agents and fleet overview** — "Agents run on your infrastructure, handle key generation locally. Fleet view shows OS, architecture, and version distribution"
7. **Show profiles** — "Certificate profiles enforce crypto constraints — key types, max TTL, compliance requirements"
8. **Show policies** — "Guardrails prevent teams from going outside approved scope"
9. **Show bulk operations** — "Select multiple certs, trigger renewal or revoke in bulk with progress tracking"
10. **Show certificate discovery** — "Agents scan your infrastructure for existing certificates you're not managing yet. We automatically deduplicate by fingerprint, show you what we found, and let you claim them or dismiss them"
11. **Show the API** — "Everything you see here is API-first. We also have a CLI tool and an MCP server for AI assistant integration"

The whole walkthrough takes 5-10 minutes.

## Next Steps

- **[Advanced Demo](demo-advanced.md)** — Go hands-on: create a team, issue a certificate via API, trigger renewal, and watch it appear in the dashboard
- **[Concepts Guide](concepts.md)** — Understand TLS certificates, CAs, and private keys from scratch
- **[Architecture](architecture.md)** — Deep dive into the control plane, agent model, and connector architecture
