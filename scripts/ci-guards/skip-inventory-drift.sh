#!/usr/bin/env bash
# scripts/ci-guards/skip-inventory-drift.sh
#
# Phase 3 TEST-M4 + ARCH-L2 closure (2026-05-13): regenerate the
# skip inventory at docs/testing/skip-inventory.md and fail the build
# if the regenerated file differs from the tracked copy. The
# inventory is the canonical acquisition-diligence artefact for "what
# tests are being skipped and why" — keeping it accurate is a CI
# contract, not a manual checklist.
#
# To fix a drift error: re-run ./scripts/skip-inventory.sh locally
# and commit the regenerated file alongside the PR that added or
# removed t.Skip sites.

set -e

EXPECTED="docs/testing/skip-inventory.md"
TMPFILE="$(mktemp -t skip-inventory.XXXXXX.md)"

trap 'rm -f "$TMPFILE"' EXIT

./scripts/skip-inventory.sh "$TMPFILE" > /dev/null

# Compare excluding the timestamp line (which legitimately drifts per-day).
if diff -q \
   <(grep -vE "^> Last reviewed:" "$EXPECTED") \
   <(grep -vE "^> Last reviewed:" "$TMPFILE") > /dev/null; then
  echo "skip-inventory-drift guard OK: docs/testing/skip-inventory.md matches the live tree"
  exit 0
fi

echo "::error::skip-inventory-drift regression: docs/testing/skip-inventory.md is stale."
echo ""
echo "The skip inventory at $EXPECTED no longer matches the live"
echo "t.Skip surface. Regenerate with:"
echo ""
echo "    ./scripts/skip-inventory.sh"
echo ""
echo "Then commit the updated docs/testing/skip-inventory.md alongside"
echo "your t.Skip changes."
echo ""
echo "Diff (- expected, + actual):"
diff <(grep -vE "^> Last reviewed:" "$EXPECTED") \
     <(grep -vE "^> Last reviewed:" "$TMPFILE") | head -50
exit 1
