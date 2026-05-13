#!/usr/bin/env bash
# scripts/ci-guards/B2-compose-base-no-demo-env.sh
#
# Bundle 2 closure (2026-05-12) — base compose must stay production-shaped.
#
# Pre-Bundle-2 the base file `deploy/docker-compose.yml` shipped with the
# demo-mode env vars baked in (CERTCTL_AUTH_TYPE=none + DEMO_MODE_ACK=true +
# KEYGEN_MODE=server + DEMO_SEED=true + literal change-me placeholder
# credentials). The README, ENVIRONMENTS.md, and operator intuition all
# said "drop the demo overlay for a clean install" — but dropping the
# overlay still produced a demo-shape stack because the demo posture
# lived in the base. The Bundle 2 closure (cowork/bundle-2-prompt.md)
# moved every demo-mode env var out of the base into the demo overlay.
#
# This guard catches any future regression that would re-introduce a
# demo-mode env var into the base file. The signals checked map 1:1 to
# the env vars the overlay now owns:
#
#   CERTCTL_AUTH_TYPE: none           — demo-mode synthetic admin
#   CERTCTL_DEMO_MODE_ACK: "true"     — the HIGH-12 bypass acknowledgment
#   CERTCTL_KEYGEN_MODE: server       — demo-only server-side keygen
#   CERTCTL_DEMO_SEED: "true"         — 180-day simulated history seeder
#   change-me-in-production           — literal placeholder API secret
#   change-me-32-char-encryption-key  — literal placeholder encryption key
#
# Per the contract documented in scripts/ci-guards/README.md:
# bare callable, no args, no env, exit 0 on clean.

set -e

GUARD_NAME="B2-compose-base-no-demo-env"
BASE="deploy/docker-compose.yml"

if [ ! -f "$BASE" ]; then
  echo "${GUARD_NAME}: ${BASE} not found — refuse to skip silently."
  exit 1
fi

# The patterns below match the literal Bundle-2-overlay-owned env values
# anywhere in the base compose file. Comments are excluded so the same
# strings can still appear in documentation-style # comments inside the
# file (which is exactly what we want — the base file still references
# the overlay's name and posture in its header).

# grep helpers: -E for ERE, -v '^\s*#' to drop YAML comments, -F to
# match literal strings (no regex meta-chars in sentinels). The base
# compose still has narrative-comment references to the overlay's
# posture (CERTCTL_AUTH_TYPE=none ... etc.) so we can't grep the file
# raw — strip comments first.

stripped=$(sed -E 's/^\s*#.*$//' "$BASE" \
            | sed -E 's/^([^#]*)#.*$/\1/')

failed=0

# Pattern 1: CERTCTL_AUTH_TYPE: none  (with the YAML "key: value" shape).
if echo "$stripped" | grep -qE '^\s*CERTCTL_AUTH_TYPE\s*:\s*none\s*$'; then
  echo "::error file=${BASE}::CERTCTL_AUTH_TYPE: none belongs in deploy/docker-compose.demo.yml (the demo overlay), not the base compose. Bundle 2 closure: the base must boot production-shaped. See cowork/bundle-2-prompt.md."
  failed=1
fi

# Pattern 2: CERTCTL_DEMO_MODE_ACK: "true"  (the HIGH-12 bypass ACK).
if echo "$stripped" | grep -qE '^\s*CERTCTL_DEMO_MODE_ACK\s*:\s*"?true"?\s*$'; then
  echo "::error file=${BASE}::CERTCTL_DEMO_MODE_ACK: \"true\" belongs in deploy/docker-compose.demo.yml. Setting it in the base disables the HIGH-12 fail-closed guard on every deploy that uses the base alone."
  failed=1
fi

# Pattern 3: CERTCTL_KEYGEN_MODE: server  (demo-only setting).
if echo "$stripped" | grep -qE '^\s*CERTCTL_KEYGEN_MODE\s*:\s*server\s*$'; then
  echo "::error file=${BASE}::CERTCTL_KEYGEN_MODE: server belongs in deploy/docker-compose.demo.yml. Production deploys must use the code default 'agent' so private keys never leave agent infrastructure."
  failed=1
fi

# Pattern 4: CERTCTL_DEMO_SEED: "true"  (180-day simulated history seeder).
if echo "$stripped" | grep -qE '^\s*CERTCTL_DEMO_SEED\s*:\s*"?true"?\s*$'; then
  echo "::error file=${BASE}::CERTCTL_DEMO_SEED: \"true\" belongs in deploy/docker-compose.demo.yml. The 180-day demo-history seeder must not run on the production-shaped base."
  failed=1
fi

# Pattern 5+6: literal change-me placeholder credentials.
# Use fgrep against the stripped (no-comment) content so the narrative
# header in deploy/docker-compose.yml can still mention the sentinels.
if echo "$stripped" | grep -qF 'change-me-in-production'; then
  echo "::error file=${BASE}::literal \"change-me-in-production\" placeholder belongs in deploy/docker-compose.demo.yml. The base compose Validate() now refuses to start with this placeholder outside demo mode."
  failed=1
fi

if echo "$stripped" | grep -qF 'change-me-32-char-encryption-key'; then
  echo "::error file=${BASE}::literal \"change-me-32-char-encryption-key\" placeholder belongs in deploy/docker-compose.demo.yml. The base compose Validate() now refuses to start with this placeholder outside demo mode."
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  echo ""
  echo "${GUARD_NAME}: FAILED — base compose has regressed into demo-mode territory."
  echo "  Move the offending env vars into deploy/docker-compose.demo.yml and"
  echo "  re-run: bash scripts/ci-guards/${GUARD_NAME}.sh"
  exit 1
fi

echo "${GUARD_NAME}: clean."
