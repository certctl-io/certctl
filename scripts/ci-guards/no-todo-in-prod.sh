#!/usr/bin/env bash
# scripts/ci-guards/no-todo-in-prod.sh
#
# Phase 3 ARCH-L4 closure (2026-05-13): production Go files
# (cmd/ + internal/, excluding *_test.go) MUST NOT carry bare
# TODO / FIXME comments. The pre-Phase-3 working tree had 5 such
# comments; this guard catches the regression mode where a future PR
# reintroduces them.
#
# Allowed patterns:
#   - `// see #<descriptor>` — track-via-descriptor for deferred work.
#     Descriptor may be a GitHub issue number (`see #123`) or a
#     greppable kebab-case identifier (`see #gcpsm-pagination`,
#     `see #bundle-2-scope-fk`). The point is that future code-search
#     for the descriptor finds the comment + every related call site.
#   - Test files (*_test.go) are exempt because TODO in tests is
#     usually documenting an unimplemented test case, not deferred
#     production code.
#
# The Phase 3 closure rewrote the 5 pre-existing TODOs:
#   - internal/repository/postgres/auth.go:220 → see #bundle-2-scope-fk
#   - internal/connector/discovery/gcpsm/gcpsm.go:547 → see #gcpsm-pagination
#   - internal/service/audit.go:244 → see #audit-pagination-count
#   - internal/service/job.go:295, 299 → see #validation-job-impl

set -e

VIOLATIONS=$(grep -rnE "TODO|FIXME" --include='*.go' cmd/ internal/ 2>/dev/null \
    | grep -v '_test\.go' \
    || true)

if [ -n "$VIOLATIONS" ]; then
  echo "::error::no-todo-in-prod regression: TODO / FIXME in production Go."
  echo ""
  echo "Production code MUST NOT carry bare TODO / FIXME comments. Use"
  echo "'// see #<descriptor>' instead — either a GitHub issue number"
  echo "(see #123) or a greppable descriptor (see #gcpsm-pagination)."
  echo ""
  echo "Violations:"
  echo "$VIOLATIONS"
  exit 1
fi

echo "no-todo-in-prod guard OK: no TODO / FIXME in production Go"
