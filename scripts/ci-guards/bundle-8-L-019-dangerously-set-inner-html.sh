#!/usr/bin/env bash
# scripts/ci-guards/bundle-8-L-019-dangerously-set-inner-html.sh
#
# Audit L-019 / CWE-79 (XSS): no PRODUCTION code may use
# dangerouslySetInnerHTML directly. At Bundle-8 close the codebase
# has 0 sites; future genuine needs MUST route through
# web/src/utils/safeHtml.ts::sanitizeHtml.
#
# Test files (web/src/**/*.test.{ts,tsx}) are explicitly excluded:
# the M-029 Pass 3 XSS-hardening test docstrings legitimately cite
# the attack vector by name to explain what the test is guarding
# against (e.g. "a careless refactor to dangerouslySetInnerHTML
# would let an attacker-controlled CSR deliver an XSS payload").
# Tests describing the threat aren't using it; the guard's intent
# is production code only.

set -e
OFFENDERS=$(grep -rnE 'dangerouslySetInnerHTML' web/src/ 2>/dev/null \
  | grep -v 'web/src/utils/safeHtml.ts' \
  | grep -vE '\.test\.(ts|tsx)(:[0-9]+)?:' \
  || true)
if [ -n "$OFFENDERS" ]; then
  echo "::error::L-019 regression: dangerouslySetInnerHTML used outside safeHtml.ts:"
  echo "$OFFENDERS"
  echo ""
  echo "Route through web/src/utils/safeHtml.ts::sanitizeHtml — see file"
  echo "header for the activation procedure (DOMPurify dependency)."
  exit 1
fi
echo "L-019 dangerously-set-inner-html: clean."
