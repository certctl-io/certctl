#!/bin/bash

#
# Cloudflare DNS-01 Challenge Script (CLEANUP)
#
# This script removes a DNS TXT record after ACME DNS-01 challenge validation.
# Called by certctl after certificate issuance to clean up temporary challenge records.
#
# certctl sets these environment variables before invoking this script:
#   CERTCTL_DNS_DOMAIN   - Base domain (e.g., "example.com")
#   CERTCTL_DNS_FQDN     - Full challenge FQDN (e.g., "_acme-challenge.example.com")
#   CERTCTL_DNS_VALUE    - Challenge value/token that was in the TXT record
#
# You must set these environment variables before running:
#   CLOUDFLARE_API_TOKEN - Cloudflare API token with DNS:write permission
#   CLOUDFLARE_ZONE_ID   - Cloudflare zone ID for your domain
#
# Error Handling:
#   This script exits 0 on success, non-zero on failure.
#   If cleanup fails, certctl logs the error but doesn't block renewals.
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

# Cloudflare API endpoint
CF_API="https://api.cloudflare.com/client/v4"
CF_ZONE="$CLOUDFLARE_ZONE_ID"
CF_TOKEN="$CLOUDFLARE_API_TOKEN"

echo "[certctl DNS-01] Cleaning up DNS record: $RECORD_NAME"

# Step 1: Find the record ID
RECORD_ID=$(curl -s -X GET \
  "$CF_API/zones/$CF_ZONE/dns_records?name=$RECORD_NAME&type=$RECORD_TYPE" \
  -H "Authorization: Bearer $CF_TOKEN" \
  -H "Content-Type: application/json" \
  | jq -r '.result | if length > 0 then .[0].id else "" end')

if [[ -z "$RECORD_ID" ]]; then
    echo "[certctl DNS-01] Record not found (already deleted?). Skipping cleanup."
    exit 0
fi

# Step 2: Delete the record (DELETE /zones/{zone_id}/dns_records/{record_id})
echo "[certctl DNS-01] Deleting DNS record (ID: $RECORD_ID)..."
RESPONSE=$(curl -s -X DELETE \
  "$CF_API/zones/$CF_ZONE/dns_records/$RECORD_ID" \
  -H "Authorization: Bearer $CF_TOKEN" \
  -H "Content-Type: application/json")

# Check response success
SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
if [[ "$SUCCESS" != "true" ]]; then
    ERROR=$(echo "$RESPONSE" | jq -r '.errors[0].message // "Unknown error"')
    echo "Warning: Cloudflare API failed to delete record: $ERROR" >&2
    # Don't exit 1 here — DNS cleanup is best-effort; cleanup failures shouldn't block certs
    exit 0
fi

echo "[certctl DNS-01] Successfully deleted DNS record"
exit 0
