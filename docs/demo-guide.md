# certctl Demo Guide

A 5-7 minute guided walkthrough of certctl's dashboard and API. Perfect for stakeholder presentations and team demos.

New to certificates? Read the [Concepts Guide](concepts.md) first. Want a hands-on demo where you issue certificates yourself? See the [Advanced Demo](demo-advanced.md).

## Quick Start

```bash
git clone https://github.com/shankar0123/certctl.git
cd certctl
docker compose -f deploy/docker-compose.yml up -d
```

Wait ~30 seconds for PostgreSQL to initialize and the server to start, then open:

**http://localhost:8443**

You'll see the dashboard pre-loaded with 14 demo certificates across multiple teams, environments, and statuses — including expiring, expired, active, failed, and in-progress renewals.

## What You'll See

### Dashboard Overview
The main dashboard shows at a glance:
- **Total certificates** managed across your infrastructure
- **Expiring soon** — certificates within 30 days of expiration (yellow/red)
- **Expired** — certificates past their expiration date
- **Active** — healthy certificates with time remaining
- **Renewal success rate** — percentage of automated renewals that succeeded

Below the stats, you'll see an **expiry timeline** showing how many certs expire in each time bucket (7/14/30/60/90 days), and a **recent activity feed** with the latest audit events.

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

1. **Start with the dashboard** — "This is your certificate inventory at a glance"
2. **Show the expiring certs** — "These three would have caused outages without this platform"
3. **Click into auth-production** — "Here's the full lifecycle: who owns it, where it's deployed, when it was last renewed"
4. **Show the failed VPN cert** — "The system tried 3 times, then alerted the team via webhook"
5. **Show agents** — "Agents run on your infrastructure, handle key generation locally, and report back"
6. **Show policies** — "Guardrails prevent teams from going outside approved scope"
7. **Show the API** — "Everything you see here is API-first, so you can automate on top of it"

The whole walkthrough takes 5-7 minutes.

## Next Steps

- **[Advanced Demo](demo-advanced.md)** — Go hands-on: create a team, issue a certificate via API, trigger renewal, and watch it appear in the dashboard
- **[Concepts Guide](concepts.md)** — Understand TLS certificates, CAs, and private keys from scratch
- **[Architecture](architecture.md)** — Deep dive into the control plane, agent model, and connector architecture
