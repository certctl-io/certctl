#!/usr/bin/env bash
#
# Phase 5 — install cert-manager 1.15.0 into the kind cluster brought
# up by kind-config.yaml. Idempotent: re-running waits for the
# existing deployment to be Ready instead of reinstalling.
#
# Called from: deploy/test/acme-integration/certmanager_test.go
# Standalone: bash deploy/test/acme-integration/cert-manager-install.sh
set -euo pipefail

CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.15.0}"
KUBECTL="${KUBECTL:-kubectl}"

echo "Installing cert-manager ${CERT_MANAGER_VERSION}..."
${KUBECTL} apply -f \
  "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"

echo "Waiting for cert-manager controller to be Ready (timeout 5m)..."
${KUBECTL} -n cert-manager wait --for=condition=Available --timeout=5m \
  deployment/cert-manager \
  deployment/cert-manager-cainjector \
  deployment/cert-manager-webhook

echo "cert-manager ${CERT_MANAGER_VERSION} ready."
