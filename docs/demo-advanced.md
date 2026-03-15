# Advanced Demo: Certificate Lifecycle End-to-End

This demo goes beyond browsing pre-loaded data. You'll create a team, register an owner, set up an issuer, create a certificate, trigger renewal, and watch everything appear in the dashboard in real time. By the end, you'll understand the full certificate lifecycle as certctl manages it.

**Time**: 10-15 minutes
**Prerequisites**: certctl running via Docker Compose (see [Quick Start](quickstart.md))

## Setup

Make sure certctl is running:

```bash
docker compose -f deploy/docker-compose.yml up -d
# Wait for healthy status
docker compose -f deploy/docker-compose.yml ps
```

Open **http://localhost:8443** in your browser alongside your terminal. You'll watch changes appear in the dashboard as you make API calls.

Set up a base variable for convenience:

```bash
API="http://localhost:8443"
```

## Part 1: Build the Organization Structure

### Create a new team

```bash
curl -s -X POST $API/api/v1/teams \
  -H "Content-Type: application/json" \
  -d '{
    "id": "t-demo",
    "name": "Demo Team",
    "description": "Team created during advanced demo walkthrough"
  }' | jq .
```

### Register an owner

```bash
curl -s -X POST $API/api/v1/owners \
  -H "Content-Type: application/json" \
  -d '{
    "id": "o-demo-user",
    "name": "Demo User",
    "email": "demo@example.com",
    "team_id": "t-demo"
  }' | jq .
```

Verify both exist:

```bash
curl -s $API/api/v1/teams/t-demo | jq .
curl -s $API/api/v1/owners/o-demo-user | jq .
```

## Part 2: Configure the Issuer

The demo ships with a Local CA issuer (`iss-local`) that can sign certificates immediately — no external CA needed. Let's verify it's available:

```bash
curl -s $API/api/v1/issuers/iss-local | jq .
```

You should see:
```json
{
  "id": "iss-local",
  "name": "Local Dev CA",
  "type": "GenericCA",
  "enabled": true
}
```

This Local CA generates real X.509 certificates using Go's `crypto/x509` library. The certificates are self-signed (not trusted by browsers in production), but structurally identical to production certificates — they have serial numbers, validity periods, SANs, key usage extensions, and a proper certificate chain.

## Part 3: Create a Managed Certificate

Now the main event. Let's create a certificate for a fictional internal API:

```bash
curl -s -X POST $API/api/v1/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "id": "mc-demo-api",
    "name": "Demo API Certificate",
    "common_name": "demo-api.internal.example.com",
    "sans": ["demo-api.internal.example.com", "demo-api-v2.internal.example.com"],
    "environment": "staging",
    "owner_id": "o-demo-user",
    "team_id": "t-demo",
    "issuer_id": "iss-local",
    "renewal_policy_id": "rp-default",
    "status": "Pending",
    "tags": {
      "service": "demo-api",
      "created_by": "advanced-demo",
      "tier": "internal"
    }
  }' | jq .
```

**Check the dashboard now.** Click "Certificates" in the sidebar. You'll see your new "Demo API Certificate" with status "Pending" alongside the pre-loaded demo certificates. Click on it to see the full details: owner, team, environment, tags, and timeline.

### Verify via API

```bash
curl -s $API/api/v1/certificates/mc-demo-api | jq '{id, name, common_name, status, environment, owner_id, team_id}'
```

## Part 4: Trigger Certificate Renewal

In production, the scheduler automatically triggers renewal when certificates approach expiry. For this demo, we'll trigger it manually:

```bash
curl -s -X POST $API/api/v1/certificates/mc-demo-api/renew | jq .
```

Expected response:
```json
{
  "status": "renewal_triggered"
}
```

This creates a renewal job. Check the jobs list:

```bash
curl -s "$API/api/v1/jobs" | jq '.data[] | select(.certificate_id == "mc-demo-api") | {id, type, status, certificate_id}'
```

**Check the dashboard.** Go to the "Jobs" view — you'll see the renewal job for your certificate.

## Part 5: Deploy the Certificate

Trigger deployment to see the deployment workflow:

```bash
curl -s -X POST $API/api/v1/certificates/mc-demo-api/deploy | jq .
```

Expected response:
```json
{
  "status": "deployment_triggered"
}
```

Check for deployment jobs:

```bash
curl -s "$API/api/v1/jobs" | jq '.data[] | select(.certificate_id == "mc-demo-api")'
```

## Part 6: View the Audit Trail

Every action you've taken has been recorded. Check the audit trail:

```bash
curl -s $API/api/v1/audit | jq '.data[0:5]'
```

You'll see events for certificate creation, renewal trigger, and deployment trigger — each with actor, action, resource type, and timestamp.

**Check the dashboard.** The "Audit" view shows the full timeline of all actions across the system.

## Part 7: Check Notifications

Certctl sends notifications for certificate lifecycle events. Check what notifications were generated:

```bash
curl -s $API/api/v1/notifications | jq '.data[0:5]'
```

In demo mode, notifications are marked as "sent" even without a real email/webhook backend. In production, these would go out via SMTP or HTTP webhooks.

## Part 8: Create a Second Certificate and Compare

Let's create another certificate in production to see how the dashboard handles multiple environments:

```bash
curl -s -X POST $API/api/v1/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "id": "mc-demo-payments",
    "name": "Demo Payments Gateway",
    "common_name": "payments.example.com",
    "sans": ["payments.example.com", "checkout.example.com"],
    "environment": "production",
    "owner_id": "o-demo-user",
    "team_id": "t-demo",
    "issuer_id": "iss-local",
    "renewal_policy_id": "rp-default",
    "status": "Active",
    "expires_at": "2026-04-01T00:00:00Z",
    "tags": {
      "service": "payments",
      "pci": "true",
      "tier": "critical"
    }
  }' | jq .
```

This certificate expires in about 18 days from the demo date, so it should show up as "Expiring" in the dashboard when the scheduler runs. **Refresh the dashboard** — you'll see it in the certificate list.

Now filter the dashboard by environment or status to see how the filtering works with your new certificates mixed in with the demo data.

## Part 9: Policy Violations

Let's see what happens when a certificate doesn't meet policy requirements. Check existing policy rules:

```bash
curl -s $API/api/v1/policies | jq '.data[] | {id, name, type, enabled}'
```

The demo includes rules for required owner metadata, allowed environments, maximum certificate lifetime, and minimum renewal windows. Check existing violations:

```bash
curl -s "$API/api/v1/policies/pr-max-certificate-lifetime/violations" | jq .
```

**In the dashboard**, click "Policies" in the sidebar to see all active rules and which certificates are violating them.

## Full Automated Script

Here's a single script that runs the entire demo end-to-end. Save it as `demo.sh` and run it:

```bash
#!/bin/bash
set -e

API="http://localhost:8443"
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}=== certctl Advanced Demo ===${NC}"
echo ""

# Step 1: Health check
echo -e "${YELLOW}Step 1: Checking server health...${NC}"
HEALTH=$(curl -s $API/health | jq -r '.status')
if [ "$HEALTH" != "healthy" ]; then
  echo "Server is not healthy. Run: docker compose -f deploy/docker-compose.yml up -d"
  exit 1
fi
echo -e "${GREEN}Server is healthy${NC}"
echo ""

# Step 2: Create team
echo -e "${YELLOW}Step 2: Creating demo team...${NC}"
curl -s -X POST $API/api/v1/teams \
  -H "Content-Type: application/json" \
  -d '{"id":"t-demo-auto","name":"Automated Demo Team","description":"Created by demo script"}' | jq -r '.id'
echo -e "${GREEN}Team created${NC}"
echo ""

# Step 3: Create owner
echo -e "${YELLOW}Step 3: Registering demo owner...${NC}"
curl -s -X POST $API/api/v1/owners \
  -H "Content-Type: application/json" \
  -d '{"id":"o-demo-auto","name":"Demo Script","email":"demo-script@example.com","team_id":"t-demo-auto"}' | jq -r '.id'
echo -e "${GREEN}Owner registered${NC}"
echo ""

# Step 4: Create certificate
echo -e "${YELLOW}Step 4: Creating managed certificate...${NC}"
CERT_ID="mc-demo-$(date +%s)"
curl -s -X POST $API/api/v1/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "id":"'$CERT_ID'",
    "name":"Demo Auto Certificate",
    "common_name":"auto-demo.internal.example.com",
    "sans":["auto-demo.internal.example.com"],
    "environment":"staging",
    "owner_id":"o-demo-auto",
    "team_id":"t-demo-auto",
    "issuer_id":"iss-local",
    "renewal_policy_id":"rp-default",
    "status":"Pending",
    "tags":{"created_by":"demo-script","automated":"true"}
  }' | jq '{id, name, status}'
echo -e "${GREEN}Certificate created: $CERT_ID${NC}"
echo ""

# Step 5: Trigger renewal
echo -e "${YELLOW}Step 5: Triggering certificate renewal...${NC}"
curl -s -X POST $API/api/v1/certificates/$CERT_ID/renew | jq .
echo -e "${GREEN}Renewal triggered${NC}"
echo ""

# Step 6: Trigger deployment
echo -e "${YELLOW}Step 6: Triggering certificate deployment...${NC}"
curl -s -X POST $API/api/v1/certificates/$CERT_ID/deploy | jq .
echo -e "${GREEN}Deployment triggered${NC}"
echo ""

# Step 7: Check certificate status
echo -e "${YELLOW}Step 7: Checking certificate status...${NC}"
curl -s $API/api/v1/certificates/$CERT_ID | jq '{id, name, status, common_name, environment}'
echo ""

# Step 8: Check jobs
echo -e "${YELLOW}Step 8: Checking jobs...${NC}"
curl -s "$API/api/v1/jobs" | jq "[.data[] | select(.certificate_id == \"$CERT_ID\") | {id, type, status}]"
echo ""

# Step 9: View recent audit events
echo -e "${YELLOW}Step 9: Recent audit events...${NC}"
curl -s $API/api/v1/audit | jq '.data[0:3] | .[] | {action, resource_type, resource_id, timestamp}'
echo ""

# Step 10: Summary
echo -e "${BLUE}=== Demo Complete ===${NC}"
echo ""
echo "What happened:"
echo "  1. Created a team and owner for accountability"
echo "  2. Created a managed certificate tracked by certctl"
echo "  3. Triggered renewal (would contact the Local CA in production flow)"
echo "  4. Triggered deployment (would push to NGINX/F5/IIS targets)"
echo "  5. All actions recorded in the audit trail"
echo ""
echo -e "Open ${GREEN}http://localhost:8443${NC} to see everything in the dashboard."
echo "Look for certificate: $CERT_ID"
```

Make it executable and run:

```bash
chmod +x demo.sh
./demo.sh
```

## What to Show Stakeholders

If you're using this demo to present certctl to decision-makers, here's the narrative:

1. **Start with the dashboard** — "This is your certificate inventory. Every TLS certificate across your infrastructure, in one place."
2. **Point to expiring certs** — "These certificates would have caused outages. Certctl catches them automatically."
3. **Show the cert you just created** — "I just created this via the API. It's already tracked, assigned to a team, and will be renewed automatically."
4. **Show the audit trail** — "Complete traceability. Every action, every change, every deployment — timestamped and attributed."
5. **Show policies** — "Guardrails. We enforce that every certificate has an owner, uses approved CAs, and stays within allowed environments."
6. **Show agents** — "Private keys never touch the control plane. Agents handle cryptographic operations locally on your infrastructure."
7. **Show the API** — "Everything is API-first. The dashboard is just one consumer. You can integrate with CI/CD, Terraform, or custom tooling."

## Teardown

```bash
docker compose -f deploy/docker-compose.yml down -v
```
