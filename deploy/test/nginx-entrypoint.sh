#!/bin/sh
# Generate a self-signed placeholder certificate so NGINX can boot
# before the certctl agent deploys a real certificate.
# Once the agent deploys, it overwrites these files and reloads NGINX.

CERT_DIR="/etc/nginx/certs"
mkdir -p "$CERT_DIR"

# Make cert directory world-writable so the certctl-agent container
# (which shares this volume) can overwrite the placeholder certs.
chmod 777 "$CERT_DIR"

if [ ! -f "$CERT_DIR/cert.pem" ]; then
    echo "Generating self-signed placeholder certificate..."
    apk add --no-cache openssl > /dev/null 2>&1
    openssl req -x509 -nodes -days 1 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$CERT_DIR/key.pem" \
        -out "$CERT_DIR/cert.pem" \
        -subj "/CN=placeholder.certctl.test" \
        2>/dev/null
    # Make placeholder certs writable by the agent container
    chmod 666 "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"
    echo "Placeholder certificate generated."
fi

# Start NGINX in foreground
exec nginx -g "daemon off;"
