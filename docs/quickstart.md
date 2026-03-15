# Quick Start Guide

Get certctl running locally and managing certificates in under 5 minutes.

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
docker compose -f deploy/docker-compose.yml up -d
```

Wait about 30 seconds for PostgreSQL to initialize and the server to boot. Check that everything is healthy:

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

Verify the server responds:
```bash
curl http://localhost:8443/health
```
```json
{"status":"healthy"}
```

## Open the Dashboard

Open **http://localhost:8443** in your browser.

The dashboard comes pre-loaded with 14 demo certificates across multiple teams, environments, and statuses. You'll see expiring certs, expired certs, active certs, failed renewals — a realistic snapshot of what a certificate inventory looks like in a real organization.

Explore the sidebar: Certificates, Agents, Policies, Jobs, Audit Trail, Notifications. Everything you see in the dashboard is backed by the REST API.

## Explore the API

The dashboard reads from the same REST API you can call directly. All endpoints live under `/api/v1/` and return JSON.

### List all certificates

```bash
curl -s http://localhost:8443/api/v1/certificates | jq .
```

The response has this shape:
```json
{
  "data": [
    {
      "id": "mc-api-prod",
      "name": "API Production",
      "common_name": "api.example.com",
      "sans": ["api.example.com", "api-v2.example.com"],
      "environment": "production",
      "owner_id": "o-alice",
      "team_id": "t-platform",
      "issuer_id": "iss-local",
      "status": "Active",
      "expires_at": "2026-05-28T00:00:00Z",
      "tags": {"service": "api-gateway", "tier": "critical"},
      "created_at": "2026-03-14T00:00:00Z",
      "updated_at": "2026-03-14T00:00:00Z"
    }
  ],
  "total": 14,
  "page": 1,
  "per_page": 50
}
```

### Filter by status

```bash
# Get only expiring certificates
curl -s "http://localhost:8443/api/v1/certificates?status=Expiring" | jq .

# Get only production certificates
curl -s "http://localhost:8443/api/v1/certificates?environment=production" | jq .
```

### Get a specific certificate

```bash
curl -s http://localhost:8443/api/v1/certificates/mc-api-prod | jq .
```

### List agents

```bash
curl -s http://localhost:8443/api/v1/agents | jq .
```

### Check agent pending work

```bash
# Replace with an actual agent ID from the list above
curl -s http://localhost:8443/api/v1/agents/agent-nginx-prod/work | jq .
```

### View audit trail

```bash
curl -s http://localhost:8443/api/v1/audit | jq .
```

### View policy rules

```bash
curl -s http://localhost:8443/api/v1/policies | jq .
```

### View notifications

```bash
curl -s http://localhost:8443/api/v1/notifications | jq .
```

## Create Your First Certificate

Let's create a new managed certificate from scratch using the API. This will create a certificate record that certctl will track, renew, and deploy.

### Step 1: Create a certificate

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

The server returns the created certificate with an auto-generated ID:
```json
{
  "id": "a1b2c3d4-...",
  "name": "My First Certificate",
  "common_name": "myapp.example.com",
  "status": "Pending",
  "created_at": "2026-03-14T..."
}
```

Save the certificate ID:
```bash
CERT_ID="<paste the id from the response>"
```

### Step 2: Trigger renewal

```bash
curl -s -X POST http://localhost:8443/api/v1/certificates/$CERT_ID/renew | jq .
```

This creates a renewal job that will be processed by the scheduler.

### Step 3: Check the certificate

```bash
curl -s http://localhost:8443/api/v1/certificates/$CERT_ID | jq .
```

### Step 4: Check the audit trail

```bash
curl -s http://localhost:8443/api/v1/audit | jq '.data[0:3]'
```

Refresh the dashboard at http://localhost:8443 — your new certificate appears in the inventory.

## Understanding the Demo Data

The demo comes pre-loaded with realistic data so you can explore certctl's features immediately:

| Resource | Count | Examples |
|----------|-------|---------|
| Teams | 5 | Platform, Security, Payments, Frontend, Data |
| Owners | 5 | Alice, Bob, Carol, Dave, Eve |
| Issuers | 3 | Local Dev CA, Let's Encrypt Staging, DigiCert |
| Agents | 5 | nginx-prod, nginx-staging, f5-prod, iis-prod, data-agent |
| Targets | 5 | NGINX (prod/staging/data), F5 LB, IIS |
| Certificates | 14 | Various statuses: Active, Expiring, Expired, Failed |
| Policies | 4 | Required owner, allowed environments, max lifetime, min renewal window |

Certificates have varied statuses so you can see what each state looks like in the dashboard: healthy certs with 45+ days remaining, certs about to expire (5-12 days), certs that already expired, and a failed renewal.

## Tear Down

```bash
docker compose -f deploy/docker-compose.yml down -v
```

The `-v` flag removes the PostgreSQL data volume so you get a clean slate next time.

## What's Next

- **[Advanced Demo](demo-advanced.md)** — Issue a real certificate via the Local CA and watch it appear in the dashboard
- **[Demo Walkthrough](demo-guide.md)** — Guided 5-minute stakeholder presentation
- **[Architecture](architecture.md)** — How the control plane, agents, and connectors work together
- **[Connector Guide](connectors.md)** — Build custom connectors for your infrastructure
