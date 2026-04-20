# Migrate from acme.sh to certctl

You use acme.sh to automate Let's Encrypt renewal across multiple servers. It works — but without centralized visibility, deployment verification, or policy enforcement.

This guide walks through moving your acme.sh workload to certctl while keeping your existing DNS provider setup.

## Why Migrate

**acme.sh strength:** Lightweight agent, works everywhere, integrates with any DNS provider via shell script hooks.

**acme.sh limitations:**
- No inventory visibility — certificates scattered across servers, no unified view of expiry dates or renewal status
- No deployment verification — cron job succeeds even if cert doesn't actually take effect on the service
- No policy enforcement — no way to require approval, audit who renewed what, or prevent misconfigurations
- No multi-server orchestration — each server manages its own renewals; no way to batch test or rollback

certctl adds a control plane that sees all your certificates, deploys with verification, enforces policy, and provides a complete audit trail. You keep the DNS-01 challenge scripts you already have.

## What You Keep

- **Existing certificates** — discovered automatically during migration, claimed in the dashboard
- **DNS provider scripts** — acme.sh's `dns_*` hooks are shell-script compatible with certctl's DNS-01 implementation
- **Same Let's Encrypt account** — ACME issuer in certctl uses the same account and email

## Migration Steps

### 1. Deploy certctl Server

Start with Docker Compose (5 minutes):

```bash
git clone https://github.com/shankar0123/certctl.git
cd certctl/deploy
docker compose up -d
```

Access the dashboard at `https://localhost:8443` with the API key from `.env`. The default compose stack ships a self-signed cert; pin with `--cacert ./deploy/test/certs/ca.crt` when calling the API from the host.

### 2. Deploy Agents

On each server running acme.sh certs, install the certctl agent:

```bash
curl -sSL https://raw.githubusercontent.com/shankar0123/certctl/master/install-agent.sh | bash
# Prompted for server URL and API key
```

Or manually:

```bash
# Download and install agent binary
wget https://github.com/shankar0123/certctl/releases/download/v2.1.0/certctl-agent-linux-amd64
chmod +x certctl-agent-linux-amd64
sudo mv certctl-agent-linux-amd64 /usr/local/bin/certctl-agent

# Create systemd unit
sudo tee /etc/systemd/system/certctl-agent.service > /dev/null <<EOF
[Unit]
Description=certctl Agent
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/certctl-agent
Environment="CERTCTL_SERVER_URL=https://certctl.internal:8443"
Environment="CERTCTL_API_KEY=your-api-key-here"
Environment="CERTCTL_DISCOVERY_DIRS=~/.acme.sh"
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now certctl-agent
```

### 3. Discover Existing acme.sh Certificates

acme.sh stores certificates in `~/.acme.sh/<domain>/` (or `/etc/acme.sh/` if installed system-wide).

When you start the agent with `CERTCTL_DISCOVERY_DIRS` pointing to those directories, it scans for existing PEM/DER certificates and reports fingerprints to the control plane. The dashboard's **Discovery** page shows what was found.

Example agent systemd service (using home directory):

```bash
Environment="CERTCTL_DISCOVERY_DIRS=/home/user/.acme.sh"
```

Or for system-wide acme.sh:

```bash
Environment="CERTCTL_DISCOVERY_DIRS=/etc/acme.sh"
```

### 4. Claim Discovered Certificates

In the **Discovery** page:
1. Review the "Unmanaged" certificates found by the agent
2. Click **Claim** on each acme.sh certificate
3. Enter the managed certificate ID to link it (e.g., `mc-api-prod`)

Once claimed, the certificate appears in the main **Certificates** page with ownership, renewal history, and deployment status.

### 5. Create an ACME Issuer

In **Issuers** → **+ New Issuer:**

1. Select **ACME** from the issuer type grid
2. Fill in the type-specific fields: name, directory URL (`https://acme-v02.api.letsencrypt.org/directory`), and config

Or configure via environment variables:
```bash
export CERTCTL_ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
export CERTCTL_ACME_EMAIL=your-email@example.com  # same as your acme.sh account
export CERTCTL_ACME_CHALLENGE_TYPE=dns-01
```

### 6. Adapt Your DNS Provider Scripts

acme.sh uses `dns_*` hooks (e.g., `dns_cloudflare`) with predictable argument patterns. certctl's DNS-01 uses the same pattern, so your scripts often work with zero changes.

**acme.sh pattern:**
```bash
# acme.sh invokes: dns_cloudflare_add "domain" "record" "value"
dns_cloudflare_add() {
  local full_domain=$1
  local record_name=$2
  local record_value=$3
  # ... DNS API call to create TXT record ...
}
```

**certctl pattern:**
```bash
# certctl invokes: /path/to/dns-present-script
# Scripts receive environment variables:
#!/bin/bash
# CERTCTL_DNS_DOMAIN — domain name (e.g., "example.com")
# CERTCTL_DNS_FQDN — full record name (e.g., "_acme-challenge.example.com")
# CERTCTL_DNS_VALUE — TXT record value (key authorization digest)
# CERTCTL_DNS_TOKEN — ACME challenge token
# Create TXT record at "${CERTCTL_DNS_FQDN}" with value "${CERTCTL_DNS_VALUE}"
```

**Example: Cloudflare DNS-01 adapter**

If you have an acme.sh Cloudflare hook, adapt it:

```bash
#!/bin/bash
# /etc/certctl/dns/cloudflare-present.sh
set -e

# certctl passes these environment variables:
# CERTCTL_DNS_DOMAIN — domain name
# CERTCTL_DNS_FQDN — full record name (e.g., "_acme-challenge.example.com")
# CERTCTL_DNS_VALUE — TXT record value
# CERTCTL_DNS_TOKEN — ACME challenge token

# Call your existing Cloudflare API (example using curl)
curl -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
  -H "X-Auth-Email: ${CF_EMAIL}" \
  -H "X-Auth-Key: ${CF_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"TXT\",\"name\":\"${CERTCTL_DNS_FQDN}\",\"content\":\"${CERTCTL_DNS_VALUE}\"}"

echo "Created ${CERTCTL_DNS_FQDN}"
```

DNS cleanup:

```bash
#!/bin/bash
# /etc/certctl/dns/cloudflare-cleanup.sh

# certctl passes these environment variables:
# CERTCTL_DNS_DOMAIN — domain name
# CERTCTL_DNS_FQDN — full record name (e.g., "_acme-challenge.example.com")
# CERTCTL_DNS_VALUE — TXT record value
# CERTCTL_DNS_TOKEN — ACME challenge token

# Query and delete the TXT record
curl -X DELETE "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${RECORD_ID}" \
  -H "X-Auth-Email: ${CF_EMAIL}" \
  -H "X-Auth-Key: ${CF_KEY}"
```

Configure the ACME issuer via environment variables:

```bash
export CERTCTL_ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
export CERTCTL_ACME_EMAIL=your-email@example.com
export CERTCTL_ACME_CHALLENGE_TYPE=dns-01
export CERTCTL_ACME_DNS_PRESENT_SCRIPT=/etc/certctl/dns/cloudflare-present.sh
export CERTCTL_ACME_DNS_CLEANUP_SCRIPT=/etc/certctl/dns/cloudflare-cleanup.sh
```

Or create the issuer through the dashboard: **Issuers** → **+ New Issuer** → select **ACME** → fill in the config fields.

### 7. Create Renewal Policies

In **Policies** → **+ New Policy:**

- **Name:** e.g., "ACME DNS-01 Policy"
- **Type:** `expiration_window` (enforces renewal thresholds)
- **Severity:** `high`
- **Config:** set your renewal window (default: 30 days before expiry)

Renewal scheduling is driven by the certificate's assigned profile and issuer. Policies add enforcement guardrails on top.

### 8. Phase Out acme.sh Cron

Once you verify renewals work via certctl (manually trigger one in the dashboard first), remove the acme.sh cron job:

```bash
# Remove acme.sh from crontab
crontab -e
# Delete the line: "0 0 * * * /home/user/.acme.sh/acme.sh --cron --home /home/user/.acme.sh"

# OR disable the cron service if installed
sudo systemctl disable acme-renew.timer
```

## DNS Script Compatibility

Most acme.sh DNS provider hooks need only minor changes:

| acme.sh | certctl |
|---------|---------|
| Called on every renewal | Called once per challenge window |
| Receives: domain, record name, record value as arguments | Receives: `CERTCTL_DNS_DOMAIN`, `CERTCTL_DNS_FQDN`, `CERTCTL_DNS_VALUE`, `CERTCTL_DNS_TOKEN` as environment variables |
| Must support multiple concurrent records | Same — cleanup removes the specific token |
| Environment variables for credentials | Same — pass via agent systemd `Environment=` or `.env` file |

**Real example:** If you use Route53, acme.sh's `dns_aws` hook submits via AWS CLI. Adapt it to use `${CERTCTL_DNS_FQDN}` and `${CERTCTL_DNS_VALUE}` environment variables instead of positional arguments, and it works with certctl's DNS-01.

## Coexistence Period

During migration, run both acme.sh and certctl in parallel:

1. Keep acme.sh cron running (low overhead, serves as fallback)
2. Configure certctl policies and test renewal on 1-2 non-critical domains
3. Monitor certctl's audit trail and deployment logs
4. Once confident, disable acme.sh cron on those domains
5. Roll out to remaining domains

This way, if certctl renewal fails, acme.sh's cron still renews the cert (you'll see duplicate renewals in the audit trail, but no gap).

## Next: DNS-PERSIST-01 (Zero-Touch Renewals)

After migrating to certctl + DNS-01, consider upgrading to **DNS-PERSIST-01**. Instead of creating/deleting DNS records on every renewal, you create one persistent TXT record at `_validation-persist.<domain>` that never changes. Let's Encrypt then validates against that standing record forever.

Benefits:
- **Zero operational overhead per renewal** — no DNS API calls during renewal
- **Auditable** — DNS record created once, visible to the team, never modified
- **Vendor-agnostic** — works with any DNS provider that supports TXT records

To enable:

```bash
export CERTCTL_ACME_CHALLENGE_TYPE=dns-persist-01
export CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN=letsencrypt.org
export CERTCTL_ACME_DNS_PRESENT_SCRIPT=/etc/certctl/dns/cloudflare-present.sh
```

certctl automatically falls back to DNS-01 if the CA doesn't support dns-persist-01 yet.

## Next Steps

- Try the [Wildcard DNS-01 example](../examples/acme-wildcard-dns01/acme-wildcard-dns01.md) — a working docker-compose with Cloudflare hooks you can adapt for your DNS provider
- See [Connector Reference](connectors.md) for advanced ACME options (EAB, ARI, custom timeouts)
- See [Discovery Guide](concepts.md#certificate-discovery) for managing discovered certificates at scale
- See all [Deployment Examples](./examples.md) for other scenarios (ACME+NGINX, private CA, step-ca, multi-issuer)
