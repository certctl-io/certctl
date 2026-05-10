#!/usr/bin/env bash
# scripts/ci-guards/N-bundle-2-security-empty-preserved.sh
#
# Auth Bundle 2 / Phase 5 Category N — preserve every existing
# `security: []` opt-out in api/openapi.yaml.
#
# Pre-Bundle-2 baseline: 14 occurrences (verified via
# `grep -c 'security: \[\]' api/openapi.yaml` at the Phase 5 starting
# state). Post-Bundle-2 must be ≥ 14. Adding new `security: []`
# entries (for new public endpoints like /auth/oidc/back-channel-logout)
# is fine; reducing the count below 14 is a regression — every
# existing public endpoint MUST stay public.
#
# Why this matters: each `security: []` opt-out is an intentional
# auth-exempt declaration (health probes, public protocol endpoints,
# OIDC handshake). Removing one would silently force a Bearer-or-
# cookie requirement onto an endpoint that legitimately runs without
# certctl-issued credentials, breaking RFC-mandated unauth surfaces
# (CRL/OCSP) or the bootstrap path.
#
# This guard runs as part of `make verify` / CI.

set -e

OPENAPI_PATH="api/openapi.yaml"
PHASE5_BASELINE=14

if [ ! -f "$OPENAPI_PATH" ]; then
    echo "::error::$OPENAPI_PATH not found"
    exit 1
fi

count=$(grep -c 'security: \[\]' "$OPENAPI_PATH" || true)

if [ "$count" -lt "$PHASE5_BASELINE" ]; then
    echo "::error::Found $count 'security: []' entries in $OPENAPI_PATH; expected ≥ $PHASE5_BASELINE (Auth Bundle 2 Phase 5 baseline)."
    echo ""
    echo "Each 'security: []' is an intentional auth-exempt declaration."
    echo "Removing one silently forces a Bearer-or-cookie requirement onto"
    echo "an endpoint that legitimately runs without certctl-issued"
    echo "credentials. Restore the missing opt-out OR — if a previously-public"
    echo "endpoint genuinely should now require auth — bump PHASE5_BASELINE"
    echo "in this script with a justification in the commit message."
    exit 1
fi

echo "OK: $count 'security: []' entries in $OPENAPI_PATH (≥ $PHASE5_BASELINE baseline)."
