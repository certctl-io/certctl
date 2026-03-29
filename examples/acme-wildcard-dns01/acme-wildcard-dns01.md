# ACME Wildcard DNS-01 Example

**What this does:** Issues wildcard certificates (e.g., `*.example.com`) from Let's Encrypt using DNS-01 challenge validation.

This example is ideal for:
- Issuing wildcard certificates (`*.example.com`)
- Services behind NAT, firewalls, or non-public networks
- Batch issuance of multiple domains in parallel
- Internal PKI with public DNS names
- Scenarios where you have programmatic access to your DNS provider's API

## Prerequisites

Before running this example, you need:

1. **A domain name** (e.g., `example.com`) that you control and can manage DNS records for
2. **DNS provider credentials:**
   - **Cloudflare** (example included): API token with DNS:write permission + Zone ID
   - **Route53 (AWS)**: AWS access key + secret key
   - **Azure DNS**: Azure subscription ID + credentials
   - **Other providers**: See "Adapting for Other DNS Providers" below
3. **Docker and Docker Compose** installed

## Quick Start (Cloudflare)

### Step 1: Get Cloudflare Credentials

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Select your domain (e.g., `example.com`)
3. In the sidebar, find **Zone ID** (copy this)
4. Go to **Account Settings > API Tokens**
5. Create a new token with these scopes:
   - **Zone > Zone:Read** (to list DNS records)
   - **Zone > DNS:Write** (to create/delete challenge records)
6. Copy the API token

### Step 2: Set Environment Variables

Create a `.env` file in this directory:

```bash
# .env
CLOUDFLARE_API_TOKEN=your-api-token-here
CLOUDFLARE_ZONE_ID=your-zone-id-here
ACME_EMAIL=admin@example.com
DB_PASSWORD=your-secure-db-password
```

Or export them in your shell:

```bash
export CLOUDFLARE_API_TOKEN="your-api-token-here"
export CLOUDFLARE_ZONE_ID="your-zone-id-here"
export ACME_EMAIL="admin@example.com"
export DB_PASSWORD="your-secure-db-password"
```

### Step 3: Make DNS Scripts Executable

```bash
chmod +x dns-hooks/*.sh
```

### Step 4: Start the Stack

```bash
docker compose up -d
```

This starts:
- **certctl-server** (port 8443): Control plane and ACME orchestrator
- **postgres**: Certificate metadata database
- **certctl-agent**: Certificate deployment agent

### Step 5: Access the Dashboard

Open your browser to `http://localhost:8443`

### Step 6: Create a Wildcard Certificate

1. Go to **Issuers** page
2. Verify the ACME issuer is registered
3. Go to **Certificates** > **New Certificate**
4. Fill in:
   - **Issuer:** ACME (Let's Encrypt)
   - **Common Name:** `*.example.com`
   - **Subject Alt Names:** `example.com` (to also cover the root domain)
5. Click **Request**

The renewal job will:
1. Send a request to Let's Encrypt
2. Run `dns-hooks/cloudflare-present.sh` to create `_acme-challenge.example.com` TXT record
3. Wait for Let's Encrypt to verify the TXT record
4. Issue the certificate
5. Run `dns-hooks/cloudflare-cleanup.sh` to delete the temporary TXT record

### Step 7: Monitor the Job

Go to **Jobs** page to see the renewal progress:
- **AwaitingCSR**: Agent is generating the CSR
- **Running**: ACME challenge in progress (DNS record being validated)
- **Completed**: Certificate issued and stored
- **Failed**: Check logs for errors (e.g., DNS provider API issues)

## How DNS-01 Works

The DNS-01 challenge proves you own a domain by creating a DNS TXT record:

```
_acme-challenge.example.com TXT "acme-validation-token-xxxxx"
```

Let's Encrypt then queries this TXT record. Once verified, it issues the certificate and certctl cleans up the TXT record.

**Why DNS-01 is better than HTTP-01 for wildcards:**
- HTTP-01 requires a public web server; DNS-01 works anywhere
- Wildcard certificates require DNS proof (not HTTP)
- DNS challenges can be solved for multiple domains in parallel
- No need for public IP or inbound port 80/443

## Adapting for Other DNS Providers

The example uses Cloudflare, but certctl supports **any DNS provider via pluggable shell scripts**.

### AWS Route53

Replace the `CERTCTL_ACME_DNS_PRESENT_SCRIPT` and `CERTCTL_ACME_DNS_CLEANUP_SCRIPT` in `docker-compose.yml` with:
- `./dns-hooks/route53-present.sh`
- `./dns-hooks/route53-cleanup.sh`

Example script outline (using AWS CLI):

```bash
#!/bin/bash
DOMAIN="$1"
VALIDATION_TOKEN="$2"

# Get Route53 hosted zone ID for the domain
ZONE_ID=$(aws route53 list-hosted-zones --query \
  "HostedZones[?Name=='$DOMAIN.'].Id" --output text | cut -d'/' -f3)

# Create TXT record
aws route53 change-resource-record-sets \
  --hosted-zone-id "$ZONE_ID" \
  --change-batch "{
    \"Changes\": [{
      \"Action\": \"CREATE\",
      \"ResourceRecordSet\": {
        \"Name\": \"_acme-challenge.$DOMAIN\",
        \"Type\": \"TXT\",
        \"TTL\": 120,
        \"ResourceRecords\": [{\"Value\": \"\\\"$VALIDATION_TOKEN\\\"\"}]
      }
    }]
  }"
```

### Azure DNS

```bash
#!/bin/bash
DOMAIN="$1"
VALIDATION_TOKEN="$2"

# Set Azure credentials via environment variables
# AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, AZURE_TENANT_ID, etc.

az network dns record-set txt create \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --zone-name "$DOMAIN" \
  --name "_acme-challenge" \
  --ttl 120 \
  --txt-value "$VALIDATION_TOKEN"
```

### Generic DNS Provider (using dig + TSIG)

If your DNS provider supports NSUPDATE (RFC 2136):

```bash
#!/bin/bash
DOMAIN="$1"
VALIDATION_TOKEN="$2"

nsupdate <<EOF
zone $DOMAIN
update add _acme-challenge.$DOMAIN 120 TXT "$VALIDATION_TOKEN"
send
EOF
```

### Manual DNS (for testing)

Replace scripts with no-ops during testing:

```bash
#!/bin/bash
echo "Please create: _acme-challenge.$1 TXT $2"
sleep 60  # Manual wait for you to create the record
```

## Alternative: DNS-PERSIST-01 (Standing Records)

If your DNS provider supports it, use **DNS-PERSIST-01** for zero-maintenance renewals.

Instead of creating a new TXT record for each renewal, you create one standing record once:

```
_validation-persist.example.com TXT "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/12345678"
```

Then every renewal uses the same record — no cleanup scripts needed!

To enable in `docker-compose.yml`:

```yaml
CERTCTL_ACME_CHALLENGE_TYPE: dns-persist-01
CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN: letsencrypt.org
```

Certctl will:
1. Fetch your ACME account URI
2. Create the standing `_validation-persist` record once
3. Reuse it for all future renewals (no per-renewal DNS updates)

## Security Notes

1. **API Token Scope:** Restrict Cloudflare/AWS tokens to DNS:write only (not full account access)
2. **Key Generation:** This example uses agent-side key generation (`CERTCTL_KEYGEN_MODE=agent`), which is production-standard. Private keys never leave the agent.
3. **Script Safety:** The DNS scripts run in the certctl-server container. For production:
   - Validate script inputs (already done in certctl code)
   - Log all API calls
   - Monitor for failed DNS operations
   - Use a separate proxy agent for DNS operations if needed

## Troubleshooting

### DNS record not created

Check the server logs:

```bash
docker logs certctl-server-dns01
```

Look for lines like:
- `[certctl DNS-01] Creating DNS record: _acme-challenge.example.com`
- `Error: Cloudflare API failed: ...`

**Common issues:**
- Missing or invalid `CLOUDFLARE_API_TOKEN`
- Invalid `CLOUDFLARE_ZONE_ID`
- API token doesn't have DNS:write permission
- Domain not in your Cloudflare account

### DNS propagation timeout

If the TLS negotiation fails, it might be DNS caching. Increase the wait time in the script:

```bash
sleep 30  # Increase from 10 to 30 seconds
```

### Let's Encrypt rate limits

Let's Encrypt has strict rate limits:
- 50 certificates per registered domain per week
- 5 duplicate certificates per domain per week

For testing, use the **staging directory**:

```yaml
CERTCTL_ACME_DIRECTORY_URL: https://acme-staging-v02.api.letsencrypt.org/directory
```

(Staging certs won't be trusted by browsers, but don't count against rate limits.)

### Job fails with "CSR generation timeout"

If your DNS provider is very slow, increase the timeout in the cleanup script or add a longer wait time:

```bash
sleep 60  # Wait 1 minute for DNS propagation
```

## Next Steps

1. **Monitor renewals:** Set up notifications (email, Slack, PagerDuty) for renewal events
2. **Deploy certificates:** Configure target connectors (NGINX, HAProxy, Traefik) to automatically deploy issued certs
3. **Multi-domain:** Use certificate profiles to group wildcard + subdomain certs
4. **Backup DNS scripts:** Version control your DNS provider scripts in git

## Files in This Example

- **docker-compose.yml** — Container stack definition with ACME DNS-01 configuration
- **dns-hooks/cloudflare-present.sh** — Creates `_acme-challenge` TXT record (Cloudflare)
- **dns-hooks/cloudflare-cleanup.sh** — Deletes `_acme-challenge` TXT record (Cloudflare)
- **README.md** — This file

## Additional Resources

- [certctl Documentation](../../docs/)
- [ACME Specification (RFC 8555)](https://tools.ietf.org/html/rfc8555)
- [DNS-01 Challenge Details](https://letsencrypt.org/docs/challenge-types/#dns-01)
- [DNS-PERSIST-01 (IETF Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
