#!/usr/bin/env bash
# scripts/ci-guards/vendor-e2e-skip-check.sh
#
# Counts `^--- SKIP:` lines in the vendor-e2e test output and fails
# the build if any test skipped that's NOT in the allowlist at
# scripts/ci-guards/vendor-e2e-skip-allowlist.txt.
#
# Per ci-pipeline-cleanup bundle Phase 5 / frozen decision 0.6.
# requireSidecar() in deploy/test/vendor_e2e_helpers.go uses
# t.Skipf() when a sidecar isn't reachable. The collapsed
# deploy-vendor-e2e job brings up all 11 sidecars at once — if
# one fails to start, the affected tests skip silently. This
# guard catches that.
#
# Usage: bash scripts/ci-guards/vendor-e2e-skip-check.sh <test-output.log>

set -e

LOG="${1:-test-output.log}"
ALLOWLIST="scripts/ci-guards/vendor-e2e-skip-allowlist.txt"

if [ ! -f "$LOG" ]; then
  echo "::error::test output log not found: $LOG"
  exit 1
fi

if [ ! -f "$ALLOWLIST" ]; then
  echo "::error::skip allowlist not found: $ALLOWLIST"
  exit 1
fi

# Build the set of allowed-skip test names (strip comments + blanks).
allowed=$(grep -vE '^\s*(#|$)' "$ALLOWLIST" | sort -u)
allowed_count=$(echo "$allowed" | grep -c .)

# Extract skipped test names from `--- SKIP: TestName (0.00s)` style lines.
skipped=$(grep -E '^--- SKIP: ' "$LOG" | awk '{print $3}' | sort -u || true)
skipped_count=$(echo "$skipped" | grep -c . || true)

echo "Vendor-e2e skip-check:"
echo "  allowlist size: $allowed_count"
echo "  observed skips: $skipped_count"

# Find skips not in allowlist.
unexpected=$(comm -23 <(echo "$skipped") <(echo "$allowed") || true)
if [ -n "$unexpected" ]; then
  echo "::error::Unexpected test skips — a sidecar likely failed to start"
  echo "Unexpected skipped tests (not in $ALLOWLIST):"
  echo "$unexpected" | sed 's/^/  - /'
  echo ""
  echo "Either:"
  echo "  (a) Fix the sidecar / network / docker-compose issue causing the skip, OR"
  echo "  (b) If the skip is legitimate (e.g., a new Windows-only test added),"
  echo "      add the test name to $ALLOWLIST with a one-line justification comment."
  exit 1
fi

# Also flag skips beyond the allowlist count (defensive — comm -23 catches
# this already but the explicit count check makes the error message clearer).
if [ "$skipped_count" -gt "$allowed_count" ]; then
  echo "::error::Skip count $skipped_count exceeds allowlist size $allowed_count"
  exit 1
fi

echo "vendor-e2e-skip-check: clean ($skipped_count skips ≤ $allowed_count allowed)."
