#!/usr/bin/env bash
# Phase 6 closure (I18N-H2 regression gate): fail CI when a new
# `new Date(x).toLocaleString()` or `.toLocaleDateString()` ships in
# production tsx outside the canonical web/src/api/utils.ts impls.
#
# Pre-Phase-6 the codebase had 8 raw sites across 6 pages, each making
# its own locale + timezone choice. Phase 6 routed them through the
# formatDateTime / formatDate / <Timestamp> helpers in utils.ts +
# components/Timestamp.tsx. This guard prevents new raw sites from
# landing.
#
# Allowlist: web/src/api/utils.ts itself — those raw calls ARE the
# canonical implementation everyone else routes through.
#
# Tests are excluded (web/src/**/*.test.*) so test fixtures + assertions
# describing the pre-Phase-6 raw pattern don't trip the guard.
set -euo pipefail

cd "$(dirname "$0")/../../web"

OFFENDERS=$(
  grep -rnE 'new Date\([^)]*\)\.toLocaleString\(\)|new Date\([^)]*\)\.toLocaleDateString\(\)' \
    src \
    --include='*.tsx' \
    --include='*.ts' \
    --exclude='*.test.*' \
    --exclude-dir='node_modules' \
    --exclude-dir='dist' \
    2>/dev/null \
    | grep -v 'src/api/utils.ts:' \
    || true
)

if [[ -n "$OFFENDERS" ]]; then
  echo "::error::I18N-H2 regression: raw new Date(x).toLocaleString() outside web/src/api/utils.ts:"
  echo "$OFFENDERS"
  echo ""
  echo "Migrate to one of:"
  echo "  • <Timestamp iso={...} />            — for hover-shows-other-zone UX"
  echo "  • formatDateTime(iso)                 — for local-zone date+time text"
  echo "  • formatDate(iso) / formatDateUTC(iso) — for date-only text"
  echo ""
  echo "All three live in web/src/api/utils.ts / web/src/components/Timestamp.tsx."
  exit 1
fi

echo "I18N-H2 no-raw-toLocaleString: clean."
