#!/usr/bin/env bash
# scripts/ci-guards/S-1-hardcoded-source-counts.sh
#
# S-1 master closed cat-s1-9ce1cbe26876 (README + features.md
# stale numeric counts; explicit CLAUDE.md violation per
# "version-stamped numbers rot") and
# cat-s1-features_md_issuer_count_contradiction (features.md
# self-disagreed on issuer count: 9 vs 12 in the same doc).
# The fix replaced source-derived numbers in prose with
# "rebuild via <command>" patterns documented in CLAUDE.md::
# "Current-state commands". This script grep-fails the build if
# any of the previously-stale sites reintroduces a hardcoded
# count.
#
# Allowed surfaces: demo-fixture prose in README ("32
# certificates" — those are seed_demo.sql facts, not live
# source counts), historical-milestone counts in
# WORKSPACE-CHANGELOG.md, the testing-guide example phrasing
# ("README claims 8 issuer connectors but only 6 exist"),
# and any number that quotes the source command immediately
# adjacent.
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# cat-s1-9ce1cbe26876 + cat-s1-features_md_issuer_count_contradiction
# for closure rationale.

set -e
BAD=$(grep -rnE '\b[0-9]+\s+(issuer connectors?|target connectors?|notifier connectors?|discovery connectors?|MCP tools|OpenAPI operations|migrations|database tables|frontend pages|HTTP routes)\b' \
    README.md docs/ 2>/dev/null \
    | grep -vE 'WORKSPACE-CHANGELOG|seed_demo|demo override' \
    | grep -vE 'DRIFT HAZARD|Source: |Rebuild|rebuild via|grep -|wc -l|ls -d|find ' \
    | grep -vE 'README claims [0-9]+ issuer connectors but only [0-9]+ exist' \
    || true)
if [ -n "$BAD" ]; then
  echo "::error::S-1 regression: hardcoded source-count prose reappeared:"
  echo "$BAD"
  echo ""
  echo "CLAUDE.md rule: 'Numeric claims about current state rot.'"
  echo "Replace the count with the grep command from CLAUDE.md::"
  echo "'Current-state commands' (e.g. 'ls -d internal/connector/issuer/*/ | wc -l')"
  echo "or rephrase to reference the rebuild command on the same line."
  echo "See coverage-gap-audit-2026-04-24-v5/unified-audit.md"
  echo "cat-s1-9ce1cbe26876 for closure rationale."
  exit 1
fi
echo "S-1 hardcoded-source-counts: clean."
