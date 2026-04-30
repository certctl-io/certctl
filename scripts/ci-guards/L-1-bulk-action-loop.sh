#!/usr/bin/env bash
# scripts/ci-guards/L-1-bulk-action-loop.sh
#
# L-1 master closed cat-l-fa0c1ac07ab5 (bulk-renew loop) and
# cat-l-8a1fb258a38a (bulk-reassign loop) by adding server-side
# bulk endpoints (POST /api/v1/certificates/bulk-renew and
# POST /api/v1/certificates/bulk-reassign) that the GUI calls
# in a single round-trip. Pre-L-1 the GUI looped per-cert
# HTTP calls — 100 selected certs = 100 round-trips × ~50–200ms
# each = a 5–20-second wedge during which the operator stares
# at a progress bar.
#
# This script grep-fails the build if either loop shape reappears
# in CertificatesPage.tsx. Patterns catch the actual pre-L-1
# shapes:
#   - `for (const id of ids) { await triggerRenewal(id) }`
#   - `for (const id of ids) { await updateCertificate(id, { owner_id }) }`
#   - `for (let i = 0; i < ids.length; i++) { await triggerRenewal(ids[i]) }`
#
# Allowed: comment lines explaining the pre-L-1 pattern in the
# docblock above each handler. Test files (_test.tsx) exempt
# so negative-pattern tests can keep working.
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# cat-l-fa0c1ac07ab5 and cat-l-8a1fb258a38a for closure
# rationale, or web/src/api/client.ts::bulkRenewCertificates
# / bulkReassignCertificates for the canonical call path.

set -e

BAD_LOOP=$(grep -nE 'for[[:space:]]*\(' web/src/pages/CertificatesPage.tsx 2>/dev/null \
    | grep -E 'await[[:space:]]+(triggerRenewal|updateCertificate)\(' \
    | grep -v '\.test\.' \
    | grep -vE '^\s*[^:]+:[0-9]+:\s*//' \
    || true)
if [ -n "$BAD_LOOP" ]; then
  echo "::error::L-1 regression: client-side bulk-action loop reappeared in CertificatesPage.tsx:"
  echo "$BAD_LOOP"
  echo ""
  echo "Use bulkRenewCertificates({ certificate_ids: [...] }) or"
  echo "bulkReassignCertificates({ certificate_ids: [...], owner_id, team_id? })"
  echo "instead of looping per-item HTTP calls. See"
  echo "coverage-gap-audit-2026-04-24-v5/unified-audit.md cat-l-* for rationale."
  exit 1
fi
echo "L-1 bulk-action-loop: clean."
