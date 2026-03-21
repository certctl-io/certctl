# Advanced Demo: Certificate Lifecycle End-to-End

This demo goes beyond browsing pre-loaded data. You'll create a team, register an owner, set up an issuer, create a certificate, trigger renewal, and watch everything appear in the dashboard in real time. Each step includes a technical explanation of what's happening inside certctl and why the system is designed that way.

**Time**: 15-20 minutes
**Prerequisites**: certctl running via Docker Compose (see [Quick Start](quickstart.md))

## Setup

Make sure certctl is running:

```bash
docker compose -f deploy/docker-compose.yml up -d --build
# Wait for healthy status
docker compose -f deploy/docker-compose.yml ps
```

Open **http://localhost:8443** in your browser alongside your terminal. You'll watch changes appear in the dashboard as you make API calls.

Set up a base variable for convenience:

```bash
API="http://localhost:8443"
```

## How the pieces fit together

Before we start, here's the high-level flow of what we're about to do:

```mermaid
flowchart LR
    A[Create Team\n& Owner] --> B[Verify Issuer]
    B --> C[Create\nCertificate]
    C --> D[Trigger\nRenewal]
    D --> E[Trigger\nDeployment]
    E --> F[Inspect Audit\n& Notifications]
```

Each step corresponds to a real operation that certctl would perform in production. The difference here is that we're driving each step manually via curl instead of letting the scheduler and agents handle it automatically.

---

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

**How it works:** This `POST` hits the `/api/v1/teams` endpoint, which routes through Go 1.22's `net/http` pattern-based mux to the `TeamsHandler.CreateTeam` method. The handler deserializes the JSON body into a `domain.Team` struct, calls the `TeamService.Create()` method, which delegates to the `TeamRepository.Create()` postgres implementation — executing an `INSERT INTO teams (id, name, description, created_at, updated_at) VALUES (...)`. The server returns the full team object with server-generated timestamps.

**Why teams exist:** Certificate ownership is a core design decision. In organizations with hundreds of certificates, outages happen when nobody knows who's responsible for a specific cert. Teams create accountability boundaries — when a cert expires, certctl knows exactly which team to alert. This maps to how enterprises actually operate: the platform team owns infrastructure certs, the payments team owns PCI-scoped certs, etc.

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

**How it works:** Same handler → service → repository flow. The owner is inserted into the `owners` table with a foreign key reference to the team via `team_id`. The `team_id` field isn't enforced at the database FK level in V1 (to keep migrations simple), but the service layer validates the reference.

**Why owners matter:** Owners are the individual humans accountable for certificates. When certctl sends an expiration warning notification, it needs a recipient. The owner's email becomes the notification target. This also feeds the audit trail — every action is attributed to an actor, and owners provide the human identity layer.

Verify both exist:

```bash
curl -s $API/api/v1/teams/t-demo | jq .
curl -s $API/api/v1/owners/o-demo-user | jq .
```

**How it works:** These `GET` requests use path parameters (`/api/v1/teams/{id}`) which Go 1.22's router extracts via `r.PathValue("id")`. The handler calls `service.Get(ctx, id)` which issues `SELECT * FROM teams WHERE id = $1`. If the row doesn't exist, the repository returns `nil` and the handler responds with HTTP 404.

---

## Part 2: Verify the Issuer

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

**How it works:** The issuer record was inserted during database seeding (`migrations/seed_demo.sql`). The `type` field (`GenericCA`) maps to a connector implementation. When the server starts, it registers connector instances in an `issuerRegistry` map keyed by issuer ID. When a certificate needs issuance, the service layer looks up the issuer ID in this registry to find the right connector.

**How the Local CA works internally:** The Local CA connector (`internal/connector/issuer/local/local.go`) generates a self-signed root CA certificate on first use using Go's `crypto/x509` package. The CA key pair lives in memory only — it's regenerated each time the server restarts, which means all certificates it issued become untrusted on restart (acceptable for dev/demo). When it receives an `IssuanceRequest` containing a CSR (Certificate Signing Request), it:

1. Parses the CSR using `x509.ParseCertificateRequest()`
2. Generates a random serial number via `crypto/rand`
3. Creates an `x509.Certificate` template with the CN, SANs, validity period, key usage extensions (Digital Signature, Key Encipherment), and extended key usage (TLS Server Auth)
4. Signs it with the CA's private key using `x509.CreateCertificate()`
5. Returns the PEM-encoded certificate and chain

The result is a structurally valid X.509 certificate — browsers won't trust it (no root CA in their trust store), but it exercises the exact same code paths that a production ACME or Vault issuer would.

**Why pluggable issuers:** Different organizations use different CAs. Some use Let's Encrypt (ACME protocol), some use step-ca or internal PKI (Vault), some use commercial CAs (DigiCert, Entrust, GlobalSign), and some have custom OpenSSL-based workflows. For enterprises with ADCS, certctl can operate as a sub-CA — all issued certs chain to the enterprise root. The connector interface means certctl doesn't care — it calls `IssueCertificate()` and gets back a signed cert regardless of the backend. V1 ships with Local CA (self-signed or sub-CA) and ACME (HTTP-01); step-ca, OpenSSL/custom CA are planned for V2; DigiCert, Vault PKI, Entrust, GlobalSign, Google CAS, and EJBCA are planned for V3.

```mermaid
flowchart TD
    subgraph "Issuer Connector Interface"
        A["IssueCertificate(CSR)"]
        B["RenewCertificate(CSR)"]
        C["RevokeCertificate(serial)"]
        D["GetOrderStatus(orderID)"]
    end

    A --> E["Local CA\n(self-signed or sub-CA)"]
    A --> F["ACME\n(Let's Encrypt)"]
    A --> G["step-ca\n(planned V2)"]
    A --> H["OpenSSL / Custom CA\n(planned V2)"]
    A --> J["DigiCert API\n(planned V2.3)"]
    A --> K["Vault PKI\n(planned V3)"]
    A --> L["Entrust / GlobalSign\n(planned V3)"]
    A --> M["Google CAS / EJBCA\n(planned V3)"]
```

---

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

**How it works:** The `CertificatesHandler.CreateCertificate` handler deserializes the JSON into a `domain.ManagedCertificate` struct and calls `CertificateService.Create()`. The service layer:

1. Validates required fields (`common_name`, `issuer_id`, `renewal_policy_id`)
2. Stores `sans` as a PostgreSQL `TEXT[]` array and `tags` as a `JSONB` column
3. Inserts into the `managed_certificates` table
4. Logs an audit event via `AuditService.Create()` — recording the actor, action (`certificate_created`), resource type, and resource ID
5. Returns the full certificate record with `created_at` and `updated_at` timestamps

**Why each field matters:**

| Field | Purpose |
|-------|---------|
| `id` | Human-readable TEXT primary key (not UUID). Prefixed with `mc-` by convention so you can identify resource types at a glance in logs and queries. |
| `common_name` | The primary domain this certificate covers. Maps to the CN field in the X.509 certificate. |
| `sans` | Subject Alternative Names — additional domains covered by the same certificate. Modern browsers actually check SANs, not CN, for domain validation. |
| `environment` | Organizational tag (`production`, `staging`, `development`). Used for dashboard filtering and policy enforcement (e.g., "staging certs can only use the Local CA"). |
| `issuer_id` | Links to the issuer connector that will sign this certificate. Determines which CA backend is used. |
| `renewal_policy_id` | Links to a `renewal_policies` row that defines: how many days before expiry to renew (`renewal_window_days`), whether auto-renewal is enabled (`auto_renew`), max retries, and retry interval. The default policy (`rp-default`) renews 30 days before expiry. |
| `status` | Set to `Pending` because the certificate hasn't been issued yet. The scheduler will pick it up, or you can trigger renewal manually. |
| `tags` | Arbitrary key-value metadata stored as JSONB. Useful for filtering, reporting, and integration with external systems (e.g., `"pci": "true"` for compliance scoping). |

**Check the dashboard now.** Click "Certificates" in the sidebar. You'll see your new "Demo API Certificate" with status "Pending" alongside the pre-loaded demo certificates. Click on it to see the full details.

### Verify via API

```bash
curl -s $API/api/v1/certificates/mc-demo-api | jq '{id, name, common_name, status, environment, owner_id, team_id}'
```

---

## Part 4: Trigger Certificate Renewal

In production, the scheduler automatically triggers renewal when certificates approach expiry. The scheduler's renewal loop runs every hour, queries `SELECT * FROM managed_certificates WHERE status IN ('Active', 'Expiring') AND expires_at < NOW() + interval '30 days'`, and creates renewal jobs for each match. For this demo, we'll trigger it manually:

```bash
curl -s -X POST $API/api/v1/certificates/mc-demo-api/renew | jq .
```

Expected response:
```json
{
  "status": "renewal_triggered"
}
```

**How it works:** The `TriggerRenewal` handler extracts the certificate ID from the URL path, calls `CertificateService.TriggerRenewal(ctx, id)`, which:

1. Fetches the certificate from the database to verify it exists
2. Creates a new `Job` record in the `jobs` table with `type: "Renewal"`, `status: "Pending"`, `certificate_id: "mc-demo-api"`, and `scheduled_at: now()`
3. The response returns `202 Accepted` immediately — the actual renewal happens asynchronously

The `202 Accepted` status code is deliberate. Certificate issuance can take seconds (Local CA) to minutes (ACME DNS challenges). The API doesn't block the caller — it creates a job and returns. The job processor loop (runs every 30 seconds) picks up pending jobs and executes them.

**What happens during renewal (V1 flow with Local CA):**

```mermaid
sequenceDiagram
    participant S as Scheduler
    participant DB as PostgreSQL
    participant SVC as RenewalService
    participant ISS as IssuerConnector
    participant A as Agent

    S->>DB: Query expiring certificates
    DB-->>S: [mc-demo-api: expires in 25 days]
    S->>DB: INSERT job (type=Renewal, status=Pending)

    Note over S: Job processor loop (every 30s)
    S->>DB: SELECT pending jobs
    DB-->>S: [job-123: Renewal for mc-demo-api]

    SVC->>SVC: Generate ECDSA P-256 key + CSR (server-side in demo mode)
    SVC->>ISS: IssueCertificate(commonName, sans, csrPEM)
    ISS-->>SVC: {cert_pem, chain_pem, serial, not_after}

    SVC->>DB: INSERT certificate_version (PEM chain + fingerprint)
    SVC->>DB: UPDATE managed_certificates SET status='Active'
    SVC->>DB: INSERT audit_event (certificate_renewed)
    SVC->>DB: CREATE deployment jobs for all targets

    Note over A: Agent polls GET /agents/{id}/work
    A->>SVC: GET /api/v1/agents/{id}/work
    SVC-->>A: [deployment job for mc-demo-api]
    A->>SVC: GET /api/v1/agents/{id}/certificates/{certId}
    SVC-->>A: {certificate PEM chain}
    A->>A: Deploy to target system
    A->>SVC: POST /api/v1/agents/{id}/jobs/{jobId}/status {Completed}
```

**Keygen mode note:** By default, certctl uses agent-side key generation (`CERTCTL_KEYGEN_MODE=agent`) where agents generate ECDSA P-256 keys locally and submit CSRs to the control plane — private keys never leave agent infrastructure. The Docker Compose demo stack uses server-side keygen mode (`CERTCTL_KEYGEN_MODE=server`) for simplicity, where the control plane generates keys within `RenewalService.ProcessRenewalJob`. In production, always use agent keygen mode.

Check the jobs list:

```bash
curl -s "$API/api/v1/jobs" | jq '.data[] | select(.certificate_id == "mc-demo-api") | {id, type, status, certificate_id}'
```

**Check the dashboard.** Go to the "Jobs" view — you'll see the renewal job for your certificate.

---

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

**How it works:** The `TriggerDeployment` handler optionally accepts a `target_id` in the request body. If no target is specified, it creates deployment jobs for all targets mapped to this certificate (via the `certificate_target_mappings` table). Each deployment job is independent — if NGINX succeeds but F5 fails, the NGINX deployment isn't rolled back.

The handler:
1. Looks up the certificate
2. Finds all deployment targets for this certificate (or uses the specific `target_id` if provided)
3. Creates a `Job` record for each target with `type: "Deployment"`, `target_id`, and `certificate_id`
4. Returns `202 Accepted`

**What the agent does during deployment:**

```mermaid
sequenceDiagram
    participant A as Agent
    participant TC as TargetConnector
    participant T as Target System

    A->>A: Load cert.pem + key.pem from local storage
    A->>TC: DeployCertificate(cert_pem, chain_pem, config)

    alt NGINX Target
        TC->>T: Write cert.pem to /etc/nginx/certs/
        TC->>T: Write chain.pem to /etc/nginx/certs/
        TC->>T: Run: nginx -t (validate config)
        TC->>T: Run: systemctl reload nginx
        TC-->>A: {success: true, deployed_at: "..."}
    else F5 Target (via proxy agent)
        TC->>T: iControl REST: POST /mgmt/tm/sys/crypto/cert
        TC->>T: iControl REST: PUT /mgmt/tm/ltm/virtual
        TC-->>A: {success: true, deployed_at: "..."}
    else IIS Target (agent-local)
        TC->>T: PowerShell: Import-PfxCertificate
        TC->>T: PowerShell: Set-WebBinding -SslFlags
        TC-->>A: {success: true, deployed_at: "..."}
    end

    A->>A: Report deployment status to control plane
```

The `DeploymentRequest` struct includes a `KeyPEM` field, but this field is populated by the agent from its local key store (`CERTCTL_KEY_DIR`), never from the control plane. The control plane only sends the signed certificate and CA chain (public material). The agent combines the locally-generated private key with the certificate from the control plane to create the full deployment payload. This is the architectural boundary that ensures zero private key exposure — the control plane API never transmits private keys, and the agent's key store is the sole source of key material for target deployment.

Check for deployment jobs:

```bash
curl -s "$API/api/v1/jobs" | jq '.data[] | select(.certificate_id == "mc-demo-api")'
```

### Agent Work Polling & Status Reporting

In production, agents poll for work and report results. You can simulate this manually:

```bash
# Poll for pending deployment work (as an agent)
curl -s "$API/api/v1/agents/agent-nginx-prod/work" | jq .
```

This returns pending deployment jobs assigned to the agent. The agent would then fetch the certificate, deploy it, and report back:

```bash
# Report job completion (replace JOB_ID with an actual job ID from the work response)
curl -s -X POST "$API/api/v1/agents/agent-nginx-prod/jobs/JOB_ID/status" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "Completed",
    "error": ""
  }' | jq .
```

**How it works:** The `GET /api/v1/agents/{id}/work` endpoint returns all pending deployment jobs. The agent processes each one, then calls `POST /api/v1/agents/{id}/jobs/{job_id}/status` with either `"Completed"` or `"Failed"` (with an error message). The control plane updates the job record and logs an audit event.

---

## Part 6: View the Audit Trail

Every action you've taken has been recorded. Check the audit trail:

```bash
curl -s $API/api/v1/audit | jq '.data[0:5]'
```

**How it works:** The `audit_events` table is append-only — there is no `UPDATE` or `DELETE` in the `AuditRepository` interface. This is a deliberate design decision for compliance. Every service method that mutates state calls `AuditService.Create()` with:

| Field | Source | Example |
|-------|--------|---------|
| `actor` | The authenticated user or system component | `"o-demo-user"`, `"system"`, `"agent-prod-01"` |
| `actor_type` | Category of the actor | `"User"`, `"System"`, `"Agent"` |
| `action` | What happened | `"certificate_created"`, `"renewal_triggered"`, `"deployment_completed"` |
| `resource_type` | What was affected | `"certificate"`, `"team"`, `"agent"` |
| `resource_id` | Specific resource | `"mc-demo-api"` |
| `details` | Arbitrary JSON context | `{"environment": "staging", "issuer": "iss-local"}` |
| `timestamp` | When it happened (server clock) | `"2026-03-14T10:30:00Z"` |

**Why immutable audit:** Compliance frameworks (SOC 2 Type II, PCI-DSS, ISO 27001) require tamper-evident audit logs. By making the repository interface append-only, even a compromised API server can't retroactively delete or modify audit records. In a production deployment, you'd also stream these to an external SIEM (Splunk, Datadog) for additional protection.

**Check the dashboard.** The "Audit" view shows the full timeline of all actions across the system.

---

## Part 7: Check Notifications

Certctl sends notifications for certificate lifecycle events. Check what notifications were generated:

```bash
curl -s $API/api/v1/notifications | jq '.data[0:5]'
```

**How it works:** The `NotificationService` generates notification records in the `notification_events` table whenever significant events occur — expiration warnings at configurable thresholds (30, 14, 7, 0 days by default), renewal success/failure, deployment results, and policy violations. Each notification has a `channel` (Email, Webhook) and a `recipient`.

**Threshold-Based Alerting:** Each renewal policy defines configurable alert thresholds via the `alert_thresholds_days` field (e.g., `[30, 14, 7, 0]` for the standard policy, `[14, 7, 3, 0]` for the urgent policy). The scheduler checks which thresholds each certificate has crossed and sends one notification per threshold, deduplicated so the same alert is never sent twice. Certificates are automatically transitioned to `Expiring` status when entering the alert window and `Expired` when they hit 0 days.

The notification processor loop runs every 60 seconds and processes pending notifications:

```mermaid
flowchart TD
    A[Notification Processor\nevery 60s] --> B{Pending\nnotifications?}
    B -->|Yes| C[Look up channel\nin notifierRegistry]
    C --> D{Notifier\nregistered?}
    D -->|Yes| E[Call Notifier.Send\nrecipient, subject, body]
    D -->|No| F[Mark as 'sent'\nDemo mode graceful skip]
    E --> G{Delivery\nsucceeded?}
    G -->|Yes| H[Update status → 'sent'\nRecord sent_at timestamp]
    G -->|No| I[Update status → 'failed'\nRecord error message]
    B -->|No| J[Sleep until next tick]
```

**Why graceful notifier fallback:** In demo mode, no SMTP server or webhook endpoint is configured. Rather than spamming error logs with "notifier not found" every 60 seconds (which was the original behavior — we fixed this), the service marks notifications as "sent" when no notifier is registered for the channel. This keeps the notification records visible in the dashboard without requiring external infrastructure.

---

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

**How it works:** This certificate is created with status `Active` and an explicit `expires_at` 18 days from now. The scheduler's renewal checker will flag this certificate when it runs because `expires_at - now() < 30 days` (the default renewal window in `rp-default`). It would transition the status to `Expiring`, send deduplicated threshold alerts at 30 and 14 days (since both thresholds have been crossed), and create a renewal job.

**Why `environment` matters:** The environment field isn't just metadata — it feeds the policy engine. A policy rule with type `AllowedEnvironments` can restrict which environments are valid. If someone tries to create a certificate with `environment: "yolo"`, the policy engine flags a violation. In a mature deployment, you'd enforce policies strictly: production certificates must use a trusted CA (not Local CA), staging certificates can use Let's Encrypt staging, and development certificates can use the Local CA.

**Why `pci: true` in tags:** Tags are free-form, but they enable powerful filtering and compliance scoping. A security team could query `GET /api/v1/certificates?tags.pci=true` (not implemented yet, but the JSONB column supports it) to find all PCI-scoped certificates and verify they meet compliance requirements.

**Refresh the dashboard** — you'll see the new payment gateway certificate. Try filtering by environment or status to see how both certificates appear alongside the demo data.

---

## Part 9: Policy Violations

Let's see what happens when a certificate doesn't meet policy requirements. Check existing policy rules:

```bash
curl -s $API/api/v1/policies | jq '.data[] | {id, name, type, enabled}'
```

**How it works:** Policy rules are stored in the `policy_rules` table with a `type` field that determines the enforcement logic and a `config` JSONB column with rule-specific parameters. The demo ships with four rules:

| Rule | Type | What it enforces |
|------|------|-----------------|
| `pr-require-owner` | `RequiredMetadata` | Every certificate must have an `owner_id` |
| `pr-allowed-environments` | `AllowedEnvironments` | Only `production`, `staging`, `development` are valid |
| `pr-max-certificate-lifetime` | `RenewalLeadTime` | Certificates can't exceed a maximum lifetime |
| `pr-min-renewal-window` | `RenewalLeadTime` | Certificates must be renewed at least N days before expiry |

When a certificate is created or updated, the policy service evaluates it against all enabled rules. Violations are recorded in the `policy_violations` table with a severity (`Warning`, `Error`, `Critical`) and a human-readable message.

Check existing violations:

```bash
curl -s "$API/api/v1/policies/pr-max-certificate-lifetime/violations" | jq .
```

**How it works:** This hits `GET /api/v1/policies/{id}/violations`, which queries `SELECT * FROM policy_violations WHERE rule_id = $1`. Each violation references the offending certificate and the rule it violated, creating a traceable link between the policy definition and the specific non-compliance.

**In the dashboard**, click "Policies" in the sidebar to see all active rules and which certificates are violating them.

---

## End-to-End Architecture Summary

Here's what we just walked through, mapped to the system architecture:

```mermaid
flowchart TB
    subgraph "What You Did (API Calls)"
        U1["POST /teams"] --> U2["POST /owners"]
        U2 --> U3["POST /certificates"]
        U3 --> U4["POST /certificates/{id}/renew"]
        U4 --> U5["POST /certificates/{id}/deploy"]
        U5 --> U6["GET /audit"]
    end

    subgraph "Control Plane (certctl-server)"
        API["REST API\nGo net/http"]
        SVC["Service Layer\nBusiness Logic"]
        REPO["Repository Layer\ndatabase/sql + lib/pq"]
        SCHED["Scheduler\n4 background loops"]
        CONN["Connector Registry\nIssuer + Target + Notifier"]
    end

    subgraph "Data Store"
        PG["PostgreSQL 16\n14 tables, TEXT PKs"]
    end

    subgraph "Agent (certctl-agent)"
        AGENT["Agent Process\nHeartbeat + Work Poll"]
        KEYS["Local Key Storage\nPrivate keys (0600)"]
        TC["Target Connectors\nNGINX / F5 / IIS"]
    end

    U1 & U2 & U3 & U4 & U5 & U6 --> API
    API --> SVC
    SVC --> REPO
    REPO --> PG
    SVC --> CONN
    SCHED --> SVC
    AGENT -->|"CSR + Heartbeat"| API
    API -->|"Cert + Chain (no key)"| AGENT
    AGENT --> KEYS
    AGENT --> TC
```

---

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
  echo "Server is not healthy. Run: docker compose -f deploy/docker-compose.yml up -d --build"
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

---

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
