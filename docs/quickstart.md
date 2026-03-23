# Quick Start Guide

Get certctl running locally and managing certificates in under 5 minutes. With TLS certificate lifespans dropping to 47 days by 2029, automated lifecycle management isn't optional — it's infrastructure. This guide gets you hands-on with certctl's automation loop: tracking, renewing, and deploying certificates without manual intervention.

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

The `--build` flag is important — it builds the server image including the React frontend. Without it, Docker may use a stale cached image that doesn't include the dashboard.

**For production deployments**, copy `deploy/.env.example` to `deploy/.env` and customize the credentials:
```bash
cp deploy/.env.example deploy/.env
# Edit deploy/.env to set secure POSTGRES_PASSWORD and CERTCTL_API_KEY values
docker compose -f deploy/docker-compose.yml up -d --build
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

The dashboard comes pre-loaded with 15 demo certificates across multiple teams, environments, and statuses. You'll see expiring certs, expired certs, active certs, failed renewals — a realistic snapshot of what a certificate inventory looks like in a real organization.

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
  "total": 15,
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

The server returns the created certificate. Since we didn't include an `id` field, the server auto-generates one using the name and a timestamp:
```json
{
  "id": "My First Certificate-1710403200000000000",
  "name": "My First Certificate",
  "common_name": "myapp.example.com",
  "status": "Pending",
  "created_at": "2026-03-14T..."
}
```

Save the certificate ID (or provide your own `id` in the request body, e.g. `"id": "mc-my-first"`):
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

### Step 5: Revoke a certificate

If a certificate's private key is compromised or the service is decommissioned, revoke it:

```bash
curl -s -X POST http://localhost:8443/api/v1/certificates/$CERT_ID/revoke \
  -H "Content-Type: application/json" \
  -d '{"reason": "superseded"}' | jq .
```

Supported RFC 5280 reason codes: `unspecified`, `keyCompromise`, `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn`. If you omit the reason, it defaults to `unspecified`.

Check the CRL to confirm:

```bash
curl -s http://localhost:8443/api/v1/crl | jq .
```

## Understanding the Demo Data

The demo comes pre-loaded with realistic data so you can explore certctl's features immediately:

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

Certificates have varied statuses so you can see what each state looks like in the dashboard: healthy certs with 45+ days remaining, certs about to expire (5-12 days), certs that already expired, and a failed renewal.

## Advanced API Features

### Sorting and filtering

```bash
# Sort certificates by expiration date (ascending)
curl -s "http://localhost:8443/api/v1/certificates?sort=notAfter" | jq .

# Sort descending (prefix with -)
curl -s "http://localhost:8443/api/v1/certificates?sort=-createdAt" | jq .

# Time-range filters (RFC3339 format)
curl -s "http://localhost:8443/api/v1/certificates?expires_before=2026-05-01T00:00:00Z" | jq .
curl -s "http://localhost:8443/api/v1/certificates?created_after=2026-03-01T00:00:00Z" | jq .
```

Supported sort fields: `notAfter`, `expiresAt`, `createdAt`, `updatedAt`, `commonName`, `name`, `status`, `environment`.

### Sparse field selection

Request only the fields you need to reduce response size:

```bash
curl -s "http://localhost:8443/api/v1/certificates?fields=id,common_name,status,expires_at" | jq .
```

### Cursor-based pagination

For large datasets, cursor pagination is more efficient than page-based:

```bash
# First page
curl -s "http://localhost:8443/api/v1/certificates?page_size=5" | jq '{next_cursor: .next_cursor, count: (.data | length)}'

# Next page (use the next_cursor from the previous response)
curl -s "http://localhost:8443/api/v1/certificates?cursor=<next_cursor_value>&page_size=5" | jq .
```

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

# System metrics
curl -s http://localhost:8443/api/v1/metrics | jq .
```

### Certificate profiles

```bash
# List all profiles
curl -s http://localhost:8443/api/v1/profiles | jq .

# Get a specific profile
curl -s http://localhost:8443/api/v1/profiles/prof-default | jq .
```

### Certificate deployments

```bash
# View deployment targets for a certificate
curl -s http://localhost:8443/api/v1/certificates/mc-api-prod/deployments | jq .
```

### Interactive approval workflow

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
- **[CLI Reference](cli.md)** — Manage certificates from your terminal
