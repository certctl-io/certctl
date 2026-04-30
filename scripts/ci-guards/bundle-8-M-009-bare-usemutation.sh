#!/usr/bin/env bash
# scripts/ci-guards/bundle-8-M-009-bare-usemutation.sh
#
# Audit M-009 + M-029 Pass 1 closure:
#
# Pre-Bundle-8 the codebase had 56 bare useMutation sites with
# discretionary invalidation. Bundle 8 shipped the useTrackedMutation
# wrapper (web/src/hooks/useTrackedMutation.ts) that requires every
# caller to declare `invalidates: QueryKey[] | 'noop'`. M-029 Pass 1
# then migrated all 56 sites to the wrapper across 6 batches.
#
# This guard pins the contract going forward: every useMutation call
# in src/ MUST be inside useTrackedMutation.ts (the wrapper itself
# is the only legitimate caller of useMutation). Any bare useMutation
# call elsewhere is a regression — adding a new mutation site means
# going through the wrapper so the invalidates contract is enforced
# per-site, not by a soft budget guard.
#
# If you genuinely need raw useMutation (extremely unlikely — the
# wrapper supports invalidates: 'noop' for fire-and-forget mutations),
# update this guard's exclusion list and document the carve-out.

set -e
# Test files (web/src/**/*.test.{ts,tsx}) are excluded so existing
# useMutation-mocking test patterns and the wrapper's own unit
# tests don't trip the production guard — symmetric with L-015
# and L-019 above.
BARE=$(grep -rnE '\buseMutation\(' web/src/ 2>/dev/null \
  | grep -v 'web/src/hooks/useTrackedMutation\.ts' \
  | grep -vE '\.test\.(ts|tsx)(:[0-9]+)?:' \
  || true)
if [ -n "$BARE" ]; then
  echo "::error::M-009 hard-zero regression: bare useMutation() call(s) outside the wrapper:"
  echo "$BARE"
  echo
  echo "Every mutation must go through useTrackedMutation"
  echo "(web/src/hooks/useTrackedMutation.ts) with explicit"
  echo "invalidates: QueryKey[] | 'noop'. See file header for usage."
  exit 1
fi
# Sanity counts (informational, not a gate).
TRACKED=$(grep -rcE '\buseTrackedMutation\(' web/src/ 2>/dev/null | awk -F: '{s+=$2} END{print s}')
INVALIDATIONS=$(grep -rcE 'invalidateQueries|setQueryData|removeQueries|invalidates:' web/src/ 2>/dev/null | awk -F: '{s+=$2} END{print s}')
echo "M-009 bare-usemutation: clean (wrapper-internal call + test files excluded)."
echo "M-009 informational: useTrackedMutation sites = $TRACKED; invalidation surface = $INVALIDATIONS."
