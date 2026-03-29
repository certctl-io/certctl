#!/bin/bash

#
# Cloudflare DNS-01 Challenge Script (PRESENT)
#
# This script creates a DNS TXT record for ACME DNS-01 challenge validation.
# Called by certctl during the renewal process to prove domain ownership.
#
# certctl sets these environment variables before invoking this script:
#   CERTCTL_DNS_DOMAIN   - Base domain (e.g., "example.com")
#   CERTCTL_DNS_FQDN     - Full challenge FQDN (e.g., "_acme-challenge.example.com")
#   CERTCTL_DNS_VALUE    - Challenge value/token to place in the TXT record
#
# You must set these environment variables before running:
#   CLOUDFLARE_API_TOKEN - Cloudflare API token with DNS:write permission
#   CLOUDFLARE_ZONE_ID   - Cloudflare zone ID for your domain
#                          (Find at: https://dash.cloudflare.com > Select Domain > Zone ID in sidebar)
#
# Error Handling:
#   This script exits 0 on success, non-zero on failure.
#   certctl will retry the renewal if this script fails.
#

set -euo pipefail

# Get values from certctl environment variables
DOMAIN="${CERTCTL_DNS_DOMAIN:-}"
RECORD_NAME="${CERTCTL_DNS_FQDN:-}"
VALIDATION_TOKEN="${CERTCTL_DNS_VALUE:-}"

# Validate inputs
if [[ -z "$DOMAIN" || -z "$RECORD_NAME" || -z "$VALIDATION_TOKEN" ]]; then
    echo "Error: Required certctl environment variables not set (CERTCTL_DNS_DOMAIN, CERTCTL_DNS_FQDN, CERTCTL_DNS_VALUE)" >&2
    exit 1
fi

# Validate environment
if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
    echo "Error: CLOUDFLARE_API_TOKEN environment variable not set" >&2
    exit 1
fi

if [[ -z "${CLOUDFLARE_ZONE_ID:-}" ]]; then
    echo "Error: CLOUDFLARE_ZONE_ID environment variable not set" >&2
    exit 1
fi

# Validate RECORD_NAME (set by certctl above)
RECORD_TYPE="TXT"
RECORD_TTL=120  # Short TTL for challenge records (1-2 min)

# Cloudflare API endpoint
CF_API="https://api.cloudflare.com/client/v4"
CF_ZONE="$CLOUDFLARE_ZONE_ID"
CF_TOKEN="$CLOUDFLARE_API_TOKEN"

echo "[certctl DNS-01] Creating DNS record: $RECORD_NAME = $VALIDATION_TOKEN"

# Step 1: Check if record already exists (GET /zones/{zone_id}/dns_records)
# This is optional but helps with idempotency
EXISTING=$(curl -s -X GET \
  "$CF_API/zones/$CF_ZONE/dns_records?name=$RECORD_NAME&type=$RECORD_TYPE" \
  -H "Authorization: Bearer $CF_TOKEN" \
  -H "Content-Type: application/json" \
  | jq -r '.result | if length > 0 then .[0].id else "" end')

if [[ -n "$EXISTING" ]]; then
    echo "[certctl DNS-01] Record already exists (ID: $EXISTING). Updating..."
    # Update existing record
    RESPONSE=$(curl -s -X PUT \
      "$CF_API/zones/$CF_ZONE/dns_records/$EXISTING" \
      -H "Authorization: Bearer $CF_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"type\": \"$RECORD_TYPE\",
        \"name\": \"$RECORD_NAME\",
        \"content\": \"$VALIDATION_TOKEN\",
        \"ttl\": $RECORD_TTL
      }")
else
    echo "[certctl DNS-01] Creating new DNS record..."
    # Create new record
    RESPONSE=$(curl -s -X POST \
      "$CF_API/zones/$CF_ZONE/dns_records" \
      -H "Authorization: Bearer $CF_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"type\": \"$RECORD_TYPE\",
        \"name\": \"$RECORD_NAME\",
        \"content\": \"$VALIDATION_TOKEN\",
        \"ttl\": $RECORD_TTL
      }")
fi

# Check response success
SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
if [[ "$SUCCESS" != "true" ]]; then
    ERROR=$(echo "$RESPONSE" | jq -r '.errors[0].message // "Unknown error"')
    echo "Error: Cloudflare API failed: $ERROR" >&2
    exit 1
fi

RECORD_ID=$(echo "$RESPONSE" | jq -r '.result.id')
echo "[certctl DNS-01] Successfully created/updated DNS record (ID: $RECORD_ID)"
echo "[certctl DNS-01] Waiting for DNS propagation..."
sleep 10

exit 0
