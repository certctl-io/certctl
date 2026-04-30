#!/usr/bin/env bash
# scripts/ci-guards/S-2-strings-contains-err.sh
#
# S-2 closure (cat-s6-efc7f6f6bd50): replaced 30 brittle
# substring-match error-dispatch sites in internal/api/handler/
# with errors.Is + typed sentinels (repository.ErrNotFound,
# repository.ErrForeignKeyConstraint via the
# repository.IsForeignKeyError helper). This script grep-fails
# the build if any new strings.Contains(err.Error(), "not found")
# or strings.Contains(err.Error(), "violates foreign key")
# site appears under internal/api/handler/.
#
# Allowed: closure-comments documenting the convention (e.g.
# bulk_reassignment.go's "post-M-1 errToStatus convention"
# docblock); domain-specific substring patterns that are
# legitimately one-off ("cannot approve", "cannot reject",
# "cannot be parsed", "challenge password") — flagged as
# deferred follow-ups in the S-2 commit message.
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# cat-s6-efc7f6f6bd50 for closure rationale.

set -e
BAD=$(grep -rnE 'strings\.Contains\(err\.Error\(\),\s*"(not found|violates foreign key|RESTRICT)"' internal/api/handler/ 2>/dev/null \
    | grep -vE '^\s*[^:]+:[0-9]+:\s*//' \
    || true)
if [ -n "$BAD" ]; then
  echo "::error::S-2 regression: brittle substring-match error-dispatch reappeared:"
  echo "$BAD"
  echo ""
  echo "Use errors.Is(err, repository.ErrNotFound) for not-found dispatch,"
  echo "or repository.IsForeignKeyError(err) for FK violations."
  echo "See coverage-gap-audit-2026-04-24-v5/unified-audit.md"
  echo "cat-s6-efc7f6f6bd50 for closure rationale."
  exit 1
fi
echo "S-2 strings-contains-err: clean."
