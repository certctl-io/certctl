#!/usr/bin/env bash
# scripts/ci-guards/H-002-bare-compose-image.sh
#
# DEPL-002 closure (Sprint 3, 2026-05-16). Companion to H-001-bare-from.sh
# (which enforces digest pins on every Dockerfile FROM): every `image:`
# line in the production-shaped compose file MUST carry an @sha256
# digest. Pre-fix `deploy/docker-compose.yml` had two floating tags
# (alpine/openssl:latest and postgres:16-alpine), so a registry-side
# tag swap could change what an operator deploys without their seeing
# the diff.
#
# Scope is intentionally narrow: only the production-shaped compose
# under deploy/. Test compose files (deploy/docker-compose.test.yml,
# deploy/test/loadtest/docker-compose.yml) and the examples/ directory
# stay free of digest pins because they're development-loop tooling
# whose floating tags are intentional (developer pulls latest, runs
# the loop, throws it away). If a finding ever escalates one of those
# files to "ships in production," extend SCAN_FILES below.

set -e

SCAN_FILES=(
  "deploy/docker-compose.yml"
)

failed=0
for f in "${SCAN_FILES[@]}"; do
  if [ ! -f "$f" ]; then
    echo "::error::H-002 misconfig: $f not found"
    failed=1
    continue
  fi
  # Match `image: something:tag` (with optional indent / quotes) that
  # does NOT contain @sha256. Strip commented lines and YAML anchors.
  BAD=$(grep -nE '^\s*image:\s+[^#@]+$' "$f" | grep -v '@sha256' || true)
  if [ -n "$BAD" ]; then
    echo "::error file=${f}::H-002 regression: compose has bare image (no @sha256 digest pin):"
    echo "$BAD"
    failed=1
  fi
done

if [ "$failed" -ne 0 ]; then
  echo ""
  echo "Pin every production-compose image to an immutable digest."
  echo "Look up current digests via:"
  echo "  curl -sS https://hub.docker.com/v2/repositories/<org>/<image>/tags/<tag> | jq -r .digest"
  exit 1
fi
echo "H-002 bare-compose-image: clean."
