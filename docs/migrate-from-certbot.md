# Migrating from Certbot to certctl

You have 50 Let's Encrypt certificates across 10 servers, managed by a mix of Certbot cron jobs and manual renewals. Certbot handles issuance, but you lack inventory visibility, centralized alerting, and audit trails. This guide walks you through moving to certctl while keeping your existing certificates and ACME account.

## Why Migrate

Certbot renews certs in isolation. If a renewal fails on one server, you don't know until the cert expires. certctl gives you a single pane of glass: see all certs across all servers, get alerts 30/14/7 days before expiry, track who renewed what when, and verify each deployment succeeded via TLS fingerprint validation.

## What You Keep

- Your existing Certbot ACME account key and Let's Encrypt account
- All issued certificates in `/etc/letsencrypt/live/`
- Certbot's renewal history and hooks

You will not re-issue any certificates. certctl discovers them and takes over renewal scheduling.

## Step-by-Step Migration

### 1. Deploy certctl Control Plane

Option A: Docker Compose (quickest for evaluation)
```bash
cd /opt/certctl
docker compose up -d
# Dashboard & API: http://localhost:8443
# Default API key in logs (grep CERTCTL_API_KEY docker logs certctl-server)
```

Option B: Kubernetes (Helm)
```bash
helm install certctl deploy/helm/certctl/ \
  --set auth.apiKey=YOUR_SECURE_KEY
```

### 2. Deploy Agents to Each Server

On each of your 10 servers running Certbot:

```bash
# Linux amd64 (adjust for your architecture)
curl -sSL https://github.com/shankar0123/certctl/releases/download/v2.1.0/certctl-agent-linux-amd64 \
  -o /usr/local/bin/certctl-agent
chmod +x /usr/local/bin/certctl-agent

# Create config
sudo mkdir -p /etc/certctl /var/lib/certctl/keys
sudo tee /etc/certctl/agent.env > /dev/null <<EOF
CERTCTL_SERVER_URL=http://certctl-control-plane.example.com:8443
CERTCTL_API_KEY=your-api-key-here
CERTCTL_DISCOVERY_DIRS=/etc/letsencrypt/live
CERTCTL_KEY_DIR=/var/lib/certctl/keys
EOF
sudo chmod 600 /etc/certctl/agent.env

# Start agent
sudo systemctl start certctl-agent  # if installed via script
# OR manually:
sudo certctl-agent --server https://... --api-key ... --discovery-dirs /etc/letsencrypt/live
```

The agent will scan `/etc/letsencrypt/live/` and report all discovered certificates to the control plane.

### 3. Triage Discovered Certificates

In the certctl dashboard, go to **Discovery**:
- See all discovered certs grouped by agent
- Status shows "Unmanaged" for certificates not yet claimed
- For each Certbot cert, click **Claim** and link it to managed inventory

The control plane now knows about all 50 certs and where they live.

### 4. Configure ACME Issuer

Go to **Issuers** → **+ New Issuer**:
1. Select **ACME** from the issuer type grid
2. Fill in the type-specific fields: name, directory URL (`https://acme-v02.api.letsencrypt.org/directory`), and any required config

Alternatively, configure via environment variables before starting the server:
```bash
export CERTCTL_ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
export CERTCTL_ACME_EMAIL=your-email@example.com
export CERTCTL_ACME_CHALLENGE_TYPE=http-01  # or dns-01 for wildcard certs
```

For DNS-01, also set:
```bash
export CERTCTL_ACME_DNS_PRESENT_SCRIPT=/etc/certctl/dns/present.sh
export CERTCTL_ACME_DNS_CLEANUP_SCRIPT=/etc/certctl/dns/cleanup.sh
```

certctl uses the same Let's Encrypt account; no new credentials needed.

### 5. Create Renewal Policies

Go to **Policies** → **+ New Policy** to create enforcement rules:
- Name: e.g., "ACME Renewal Policy"
- Type: `expiration_window` (to enforce renewal thresholds)
- Severity: `high`
- Config: set your renewal threshold (default: 30 days before expiry)

Renewal scheduling is driven by the certificate's assigned profile and issuer. Policies add enforcement guardrails (key algorithm requirements, expiration windows, etc.).

### 6. Disable Certbot Cron, One Server at a Time

On the first server (start with a low-traffic one):

```bash
# Stop Certbot renewal
sudo systemctl disable certbot.timer
sudo systemctl stop certbot.timer

# Or remove the cron job
sudo rm /etc/cron.d/certbot  # if managed by cron
```

Monitor that server in the certctl dashboard. Certctl will renew the cert ~30 days before expiry.

### 7. Verify First Renewal Succeeds

Wait for the renewal to trigger (or manually trigger it in **Certificates** → select cert → **Renew**). Check the dashboard:
- **Certificates** page: status transitions from `Active` to `Renewing` to `Active`
- **Jobs** page: renewal job shows `Completed` status
- **Verification** tab: TLS check confirms the new cert is deployed and live

After verifying, disable Certbot on the remaining 9 servers.

### 8. Enable Alerting

Configure notifiers via environment variables before starting the server:
```bash
# Example: Slack alerting
export CERTCTL_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
docker compose up -d

# Or email alerting
export CERTCTL_SMTP_HOST=smtp.gmail.com
export CERTCTL_SMTP_PORT=587
export CERTCTL_SMTP_USERNAME=your-email@gmail.com
export CERTCTL_SMTP_PASSWORD=your-app-password
export CERTCTL_SMTP_FROM_ADDRESS=certctl@example.com
docker compose up -d

# Other options: CERTCTL_TEAMS_WEBHOOK_URL, CERTCTL_PAGERDUTY_ROUTING_KEY, CERTCTL_OPSGENIE_API_KEY
```

Now you get 30/14/7-day warnings before any cert expires, across all 10 servers, in one place.

## What Changes

- **Renewal**: Agent polls certctl for work instead of Certbot cron triggering locally. Faster failure detection (agent heartbeat every 60 seconds vs. cron running once a day).
- **Deployment**: certctl verifies post-deployment by probing the live TLS endpoint and comparing SHA-256 fingerprints. Catches reload failures silently.
- **Audit Trail**: Every renewal, deployment, and alert is logged immutably. Answer "who renewed cert X when and why" within seconds.
- **Alerting**: Threshold-based alerts to Slack/email/webhook 30/14/7 days before expiry, not when cert expires.

## Coexistence and Rollback

During migration, certctl and Certbot can run simultaneously. The agent will discover Certbot certs even while Certbot continues renewing them. Run both for a week to build confidence.

**If you need to rollback**: Re-enable Certbot cron on any server:
```bash
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

certctl will stop renewing that cert when the policy is disabled. Certbot resumes as before. Your certificates and ACME account remain untouched.

## Next Steps

- Review the [Concepts Guide](./concepts.md) for terminology (profiles, policies, agents, jobs)
- Explore [Network Discovery](./quickstart.md#network-discovery-agentless) to find certificates you didn't know about
- Set up [Kubernetes cert-manager integration](./certctl-for-cert-manager-users.md) if you manage in-cluster certs too
