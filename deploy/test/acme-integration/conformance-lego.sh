#!/usr/bin/env bash
#
# Phase 5 — lego-driven RFC 8555 conformance test. Drives a real ACME
# client (lego v4) against the certctl ACME server in trust_authenticated
# mode and exercises the full happy-path: register → new-order →
# finalize → cert download.
#
# Caller (`make acme-rfc-conformance-test`) brings up the certctl
# docker-compose stack first; this script just runs lego against it.
#
# Skips cleanly when CERTCTL_ACME_DIR is unset (the operator probably
# meant to run the make target instead of this script directly).
set -euo pipefail

if [[ -z "${CERTCTL_ACME_DIR:-}" ]]; then
  echo "CERTCTL_ACME_DIR unset — point at the certctl ACME directory URL"
  echo "  e.g. CERTCTL_ACME_DIR=https://localhost:8443/acme/profile/prof-test/directory"
  exit 1
fi

WORKDIR="$(mktemp -d -t certctl-lego-conf-XXXXXX)"
trap 'rm -rf "${WORKDIR}"' EXIT

# Skip TLS verification — the test stack uses certctl's self-signed
# bootstrap cert. Operators in production use --insecure-skip-verify=false
# and pass --tls-bundle for the real CA.
LEGO_INSECURE="--insecure-skip-verify"

# Step 1: register a fresh account.
echo "==> lego: register account"
lego --server "${CERTCTL_ACME_DIR}" \
     --email conformance@example.com \
     --domains conformance.example.com \
     --path "${WORKDIR}" \
     --accept-tos \
     ${LEGO_INSECURE} \
     register

# Step 2: issue a cert (trust_authenticated mode auto-resolves authzs).
echo "==> lego: run (issue conformance.example.com)"
lego --server "${CERTCTL_ACME_DIR}" \
     --email conformance@example.com \
     --domains conformance.example.com \
     --path "${WORKDIR}" \
     --accept-tos \
     ${LEGO_INSECURE} \
     run

# Step 3: assert the cert PEM landed.
CERT_FILE="${WORKDIR}/certificates/conformance.example.com.crt"
if [[ ! -s "${CERT_FILE}" ]]; then
  echo "FAIL: ${CERT_FILE} is missing or empty"
  exit 1
fi
openssl x509 -in "${CERT_FILE}" -noout -subject -issuer -dates
echo "PASS: lego conformance happy-path completed"
