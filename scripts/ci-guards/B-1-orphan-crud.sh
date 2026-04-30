#!/usr/bin/env bash
# scripts/ci-guards/B-1-orphan-crud.sh
#
# B-1 master closed four audit findings — three orphan-update fns
# (cat-b-31ceb6aaa9f1, cat-b-7a34f893a8f9) and one orphan CRUD
# surface (cat-b-4631ca092bee, RenewalPolicy) — by wiring per-page
# Edit modals so every backend write endpoint has at least one
# GUI consumer. The fourth finding (cat-b-9b97ffb35ef7) deleted
# the dead `exportCertificatePEM` duplicate.
#
# Pre-B-1 the failure mode was: backend ships a CRUD handler,
# client.ts ships the matching `update*` / `delete*` / `create*`
# function, but no page imports it. Operators were forced to
# `psql` directly to edit team names, owner emails, agent-group
# match rules, issuer names, profile names, or any renewal-policy
# field — turning a 30-second GUI task into a 30-minute database
# excursion with audit-trail gaps.
#
# This script fails the build if any of the eight previously-orphan
# client functions loses its page consumer (i.e. a future refactor
# accidentally re-orphans them). Each fn must have ≥1 non-test
# consumer under web/src/pages/. Tests (*.test.ts(x)) and the
# client.ts definition file itself are exempt.
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# cat-b-31ceb6aaa9f1, cat-b-7a34f893a8f9, cat-b-4631ca092bee,
# cat-b-9b97ffb35ef7 for closure rationale.

set -e
ORPHAN_FNS="updateOwner updateTeam updateAgentGroup updateIssuer updateProfile createRenewalPolicy updateRenewalPolicy deleteRenewalPolicy"
FAIL=0
for fn in $ORPHAN_FNS; do
  HITS=$(grep -rE "\b${fn}\b" web/src/pages/ 2>/dev/null \
      | grep -vE '\.test\.(ts|tsx):' \
      | wc -l)
  if [ "$HITS" -eq 0 ]; then
    echo "::error::B-1 regression: client function '${fn}' has zero consumers under web/src/pages/."
    echo "  Every backend CRUD endpoint must have a GUI consumer to avoid forcing operators to psql."
    echo "  Either restore the page consumer or delete the client function in the same commit."
    FAIL=1
  fi
done
# cat-b-9b97ffb35ef7: exportCertificatePEM was deleted as a dead
# duplicate of downloadCertificatePEM. Block resurrection.
if grep -nE 'export\s+const\s+exportCertificatePEM' web/src/api/client.ts >/dev/null 2>&1; then
  echo "::error::B-1 regression: exportCertificatePEM was removed as a dead duplicate of downloadCertificatePEM."
  echo "  If a JSON variant is needed, add an explicit page consumer in the same commit."
  FAIL=1
fi
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
echo "B-1 orphan-CRUD: clean (all 8 functions have page consumers)."
