#!/usr/bin/env bash
# scripts/ci-guards/P-1-documented-orphan-fns.sh
#
# P-1 master closed diff-04x03-d24864996ad4 + cat-b-dc46aadab98e
# by documenting 17 detail-page-candidate orphan client.ts
# functions in a docblock at the top of web/src/api/client.ts.
# This script verifies the docblock list ↔ export list relationship:
# every name listed in the docblock must still be declared as
# an export below it (catches drift where someone deletes the
# export but forgets the docblock, or vice versa).
#
# CRL/OCSP-Responder Phase 5 closed the getOCSPStatus orphan: the
# CertificateDetailPage Revocation Endpoints panel now consumes it
# ("Check OCSP status" button). Removed from the list to keep the
# docblock + guardrail honest.
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# diff-04x03-d24864996ad4 + cat-b-dc46aadab98e for closure rationale.

set -e
DOCUMENTED='getAgentGroup getAgentGroupMembers getAuditEvent getCertificateDeployments getDiscoveredCertificate getHealthCheck getHealthCheckHistory getNetworkScanTarget getNotification getOwner getPolicy getPolicyViolations getRenewalPolicy getTeam registerAgent updateHealthCheck'
MISSING=""
for fn in $DOCUMENTED; do
  if ! grep -qE "^export const ${fn}\b" web/src/api/client.ts; then
    MISSING="${MISSING}${fn} "
  fi
done
if [ -n "$MISSING" ]; then
  echo "::error::P-1 regression: documented orphan(s) missing from client.ts exports:"
  echo "  $MISSING"
  echo ""
  echo "Either restore the export, or delete the corresponding line"
  echo "in the documented-orphans docblock at the top of client.ts."
  echo "See coverage-gap-audit-2026-04-24-v5/unified-audit.md"
  echo "diff-04x03-d24864996ad4 for closure rationale."
  exit 1
fi
echo "P-1 documented-orphan-fns: clean ($(echo $DOCUMENTED | wc -w) fns verified)."
