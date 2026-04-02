#!/bin/sh
# This script runs inside the certctl-server container at startup.
# It fetches CA certificates from Pebble and step-ca, adds them to the
# system trust store, then starts the certctl server.
#
# Why: The ACME connector and step-ca connector use Go's default http.Client
# with no InsecureSkipVerify. They rely on the system trust store to verify
# TLS connections. Pebble and step-ca both use self-signed root CAs that
# aren't in Alpine's default CA bundle, so we must add them manually.
#
# This script runs as root (user: "0:0" in docker-compose) so that
# update-ca-certificates can write to /etc/ssl/certs/.

set -e

echo "=== certctl trust store setup ==="

# --- Pebble CA cert (fetched from management API) ---
# Pebble's management API serves the root CA at /roots/0.
# We use -k because we can't verify Pebble's TLS cert yet (chicken-and-egg).
echo "Fetching Pebble root CA from management API..."
PEBBLE_CA=""
for i in 1 2 3 4 5 6 7 8 9 10; do
    if PEBBLE_CA=$(curl -sk https://pebble:15000/roots/0 2>/dev/null); then
        if [ -n "$PEBBLE_CA" ]; then
            echo "$PEBBLE_CA" > /usr/local/share/ca-certificates/pebble-ca.crt
            echo "  Added: Pebble test CA"
            break
        fi
    fi
    echo "  Waiting for Pebble (attempt $i/10)..."
    sleep 2
done

if [ -z "$PEBBLE_CA" ]; then
    echo "  WARNING: Could not fetch Pebble CA. ACME issuance will fail."
fi

# --- step-ca root cert (from shared volume) ---
# The step-ca container writes its root CA to /home/step/certs/root_ca.crt.
# We mount the step-ca data volume at /stepca-data inside this container.
STEPCA_ROOT="/stepca-data/certs/root_ca.crt"
echo "Waiting for step-ca root cert..."
for i in 1 2 3 4 5 6 7 8 9 10; do
    if [ -f "$STEPCA_ROOT" ]; then
        cp "$STEPCA_ROOT" /usr/local/share/ca-certificates/step-ca-root.crt
        echo "  Added: step-ca root CA"
        break
    fi
    echo "  Waiting for step-ca root cert (attempt $i/10)..."
    sleep 2
done

if [ ! -f "$STEPCA_ROOT" ]; then
    echo "  WARNING: step-ca root cert not found at $STEPCA_ROOT"
    echo "  step-ca issuance may fail until the cert is available."
fi

# --- step-ca provisioner key (extracted from ca.json) ---
# When step-ca auto-bootstraps via DOCKER_STEPCA_INIT_* env vars, the
# encrypted provisioner key (JWE) is NOT written as a separate file.
# Instead, it's embedded in ca.json under:
#   authority.provisioners[0].encryptedKey
# We extract it here and write to /tmp so the certctl server can read it.
# The stepca_data volume is mounted :ro, so we can't write there.
STEPCA_CA_JSON="/stepca-data/config/ca.json"
STEPCA_KEY_EXTRACTED="/tmp/step-ca-provisioner-key"
echo "Extracting step-ca provisioner key from ca.json..."
for i in 1 2 3 4 5 6 7 8 9 10; do
    if [ -f "$STEPCA_CA_JSON" ]; then
        # Extract the encryptedKey value using grep+sed (no jq in Alpine base)
        # The field looks like: "encryptedKey": "eyJhbGciOi..."
        ENCRYPTED_KEY=$(grep -o '"encryptedKey":"[^"]*"' "$STEPCA_CA_JSON" | head -1 | sed 's/"encryptedKey":"//;s/"$//')
        if [ -z "$ENCRYPTED_KEY" ]; then
            # Try with spaces around colon (JSON formatting varies)
            ENCRYPTED_KEY=$(grep -o '"encryptedKey" *: *"[^"]*"' "$STEPCA_CA_JSON" | head -1 | sed 's/"encryptedKey" *: *"//;s/"$//')
        fi
        if [ -n "$ENCRYPTED_KEY" ]; then
            # Check if it's JWE compact serialization (dot-separated) or JSON serialization
            case "$ENCRYPTED_KEY" in
                \{*)
                    # Already JSON serialization — write as-is
                    echo "$ENCRYPTED_KEY" > "$STEPCA_KEY_EXTRACTED"
                    ;;
                *)
                    # JWE compact serialization: header.encrypted_key.iv.ciphertext.tag
                    # Convert to JSON serialization expected by Go decryptProvisionerKey()
                    JWE_PROTECTED=$(echo "$ENCRYPTED_KEY" | cut -d. -f1)
                    JWE_ENCKEY=$(echo "$ENCRYPTED_KEY" | cut -d. -f2)
                    JWE_IV=$(echo "$ENCRYPTED_KEY" | cut -d. -f3)
                    JWE_CT=$(echo "$ENCRYPTED_KEY" | cut -d. -f4)
                    JWE_TAG=$(echo "$ENCRYPTED_KEY" | cut -d. -f5)
                    printf '{"protected":"%s","encrypted_key":"%s","iv":"%s","ciphertext":"%s","tag":"%s"}' \
                        "$JWE_PROTECTED" "$JWE_ENCKEY" "$JWE_IV" "$JWE_CT" "$JWE_TAG" > "$STEPCA_KEY_EXTRACTED"
                    ;;
            esac
            echo "  Extracted provisioner key to $STEPCA_KEY_EXTRACTED"
            echo "  Key file size: $(wc -c < "$STEPCA_KEY_EXTRACTED") bytes"
            echo "  Key starts with: $(head -c 40 "$STEPCA_KEY_EXTRACTED")..."
            # Override the env var so the server reads from the extracted file
            export CERTCTL_STEPCA_KEY_PATH="$STEPCA_KEY_EXTRACTED"
            break
        else
            echo "  ca.json found but encryptedKey not found in it (attempt $i/10)"
        fi
    else
        echo "  Waiting for step-ca ca.json (attempt $i/10)..."
    fi
    sleep 2
done

if [ ! -f "$STEPCA_KEY_EXTRACTED" ]; then
    echo "  WARNING: Could not extract step-ca provisioner key"
    echo "  Listing /stepca-data/config/ for debugging:"
    ls -la /stepca-data/config/ 2>/dev/null || echo "  /stepca-data/config/ does not exist"
    echo "  step-ca issuance will fail."
fi

# --- Update system trust store ---
echo "Updating system CA trust store..."
update-ca-certificates 2>/dev/null || true

echo "Trust store updated."

# --- Debug: verify configuration before starting server ---
echo "=== Pre-launch verification ==="
echo "  CERTCTL_STEPCA_KEY_PATH=$CERTCTL_STEPCA_KEY_PATH"
if [ -f "$CERTCTL_STEPCA_KEY_PATH" ]; then
    echo "  step-ca key file exists ($(wc -c < "$CERTCTL_STEPCA_KEY_PATH") bytes)"
    echo "  step-ca key preview: $(head -c 60 "$CERTCTL_STEPCA_KEY_PATH")..."
else
    echo "  WARNING: step-ca key file NOT FOUND at $CERTCTL_STEPCA_KEY_PATH"
fi
echo "  CERTCTL_ACME_DIRECTORY_URL=$CERTCTL_ACME_DIRECTORY_URL"
echo "  CERTCTL_ACME_INSECURE=$CERTCTL_ACME_INSECURE"
echo "  Pebble CA cert: $(ls -la /usr/local/share/ca-certificates/pebble-ca.crt 2>/dev/null || echo 'NOT FOUND')"
echo "  step-ca root cert: $(ls -la /usr/local/share/ca-certificates/step-ca-root.crt 2>/dev/null || echo 'NOT FOUND')"
echo "  System CA count: $(ls /etc/ssl/certs/*.pem 2>/dev/null | wc -l) PEM files"
echo "=== Starting certctl server ==="
exec /app/server
