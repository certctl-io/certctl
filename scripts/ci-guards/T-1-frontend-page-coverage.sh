#!/usr/bin/env bash
# scripts/ci-guards/T-1-frontend-page-coverage.sh
#
# T-1 closure (cat-s2-c24a548076c6): pre-T-1 only 3 of 28 pages
# had Vitest coverage. T-1 lifted that to 11/28 by writing tests
# for the 8 highest-leverage pages (CertificatesPage filter +
# pagination state, the new B-1 Edit modals, the D-2 type-trim
# render sites, etc.). The remaining pages are deferred to per-
# page commits — when the next feature change touches them, the
# test gets added in the same commit. This script blocks new
# pages from landing without tests.
#
# Allowlist: pages that are explicitly deferred — listed below
# with a one-line "why deferred" justification. Each entry must
# be removed when the page gets its test.
#   - LoginPage:           static auth form, no business logic
#   - AuditPage:           read-only timeline; D-2 already trimmed
#   - ShortLivedPage:      derived view of certs already covered by CertificatesPage
#   - DigestPage:          server-rendered digest; minimal client logic
#   - ObservabilityPage:   exposes Prometheus / Grafana links only
#   - HealthMonitorPage:   wraps M-006 health check timeline; M-006 has its own tests
#   - NetworkScanPage:     wraps the network scanner UX; SSRF unit-tested in domain
#   - JobsPage:            covered transitively via AgentDetailPage
#   - JobDetailPage:       drill-down view; covered transitively via JobsPage
#   - AgentFleetPage:      bulk overview; covered transitively via AgentsPage
#   - ProfilesPage:        CRUD form; mirrors PoliciesPage shape (covered)
#   - CertificateDetailPage: drill-down view; covered transitively via CertificatesPage
#   - IssuerDetailPage:    drill-down view; covered transitively via IssuersPage
#   - IssuerHierarchyPage: Rank 8 admin-gated hierarchy render; admin gate +
#                          recursive build tested at the API + service layers
#                          (intermediate_ca_test.go + intermediate_ca_test.go
#                          handler triplet); defer Vitest until the next
#                          feature change touches the page
#   - TargetDetailPage:    drill-down view; covered transitively via TargetsPage
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# cat-s2-c24a548076c6 for closure rationale.

set -e
ALLOW='^(LoginPage|AuditPage|ShortLivedPage|DigestPage|ObservabilityPage|HealthMonitorPage|NetworkScanPage|JobsPage|JobDetailPage|AgentFleetPage|ProfilesPage|CertificateDetailPage|IssuerDetailPage|IssuerHierarchyPage|TargetDetailPage)$'
UNTESTED=""
for f in web/src/pages/*.tsx; do
  base=$(basename "$f" .tsx)
  case "$f" in *.test.tsx) continue ;; esac
  if [ -f "web/src/pages/${base}.test.tsx" ]; then continue; fi
  if echo "$base" | grep -qE "$ALLOW"; then continue; fi
  UNTESTED="${UNTESTED}${base} "
done
if [ -n "$UNTESTED" ]; then
  echo "::error::T-1 regression: page(s) without sibling .test.tsx and not on the deferred allowlist:"
  echo "  $UNTESTED"
  echo ""
  echo "Either add web/src/pages/<Page>.test.tsx (mirror NotificationsPage.test.tsx),"
  echo "or add the page to the ALLOW pattern in scripts/ci-guards/T-1-frontend-page-coverage.sh"
  echo "with a one-line 'why deferred' comment. See"
  echo "coverage-gap-audit-2026-04-24-v5/unified-audit.md cat-s2-c24a548076c6"
  echo "for closure rationale."
  exit 1
fi
ALLOWLIST_SIZE=$(echo "$ALLOW" | tr '|' '\n' | wc -l)
echo "T-1 frontend-page-coverage: clean (allowlist size: $ALLOWLIST_SIZE pages deferred)."
