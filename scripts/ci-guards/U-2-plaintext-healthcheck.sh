#!/usr/bin/env bash
# scripts/ci-guards/U-2-plaintext-healthcheck.sh
#
# U-2 closed cat-u-healthcheck_protocol_mismatch by switching the
# published image's HEALTHCHECK from `curl -f http://localhost:
# 8443/health` (always failed against the HTTPS-only listener) to
# `curl -fsk https://localhost:8443/health`. This script grep-fails
# the build if any Dockerfile in the repo carries the pre-U-2
# plaintext shape — either explicitly (`http://localhost:8443/
# health` in a HEALTHCHECK) or via the looser pattern of any
# HEALTHCHECK that targets `http://` against the certctl server
# port.
#
# Comment lines and the docs/archive/upgrades/to-tls-v2.2.md:182 expected-to-
# fail invariant ("plaintext is gone, expect Connection refused")
# are intentionally exempt — we DO want the upgrade-doc string
# `http://localhost:8443/health` to remain there, since it
# documents what operators should test for to confirm plaintext
# is dead. The guardrail is scoped to Dockerfile* only, so docs
# are out of its reach.
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# cat-u-healthcheck_protocol_mismatch for the closure rationale,
# or deploy/test/healthcheck_test.go for the binary-image
# contract the runtime test pins.

set -e

# Patterns that catch the actual regression shapes:
#   - HEALTHCHECK directive carrying any http:// (even if the
#     port differs, no plaintext probe should ship).
#   - The exact pre-U-2 string for grep-friendliness.
BAD=$(grep -rnEH \
    -e 'HEALTHCHECK.*http://' \
    -e 'curl[^|&;]*-f[^|&;]*http://localhost:8443/health' \
    Dockerfile Dockerfile.agent Dockerfile.* 2>/dev/null \
    | grep -vE '^\s*[^:]+:[0-9]+:\s*#' \
    || true)
if [ -n "$BAD" ]; then
  echo "::error::U-2 regression: plaintext HEALTHCHECK reappeared in a Dockerfile:"
  echo "$BAD"
  echo ""
  echo "Allowed: HTTPS HEALTHCHECK with -k (acceptable for"
  echo "localhost-to-localhost), or non-HTTP probe shapes"
  echo "(pgrep, /proc check). See Dockerfile / Dockerfile.agent"
  echo "for the post-U-2 reference shape and"
  echo "coverage-gap-audit-2026-04-24-v5/unified-audit.md"
  echo "cat-u-healthcheck_protocol_mismatch for rationale."
  exit 1
fi
echo "U-2 plaintext-healthcheck: clean."
