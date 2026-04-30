#!/usr/bin/env bash
# scripts/ci-guards/H-001-bare-from.sh
#
# Bundle A / Audit H-001 (CWE-829): every FROM line in every
# Dockerfile in the repo MUST carry an @sha256:... digest pin in
# addition to the human-readable tag. A registry-side tag swap
# cannot then change what we pull. This script grep-fails the
# build if any new FROM lands without the @sha256 suffix.
#
# Companion check: digest-validity.sh (added by ci-pipeline-cleanup
# Phase 7) verifies that each digest actually resolves on its
# registry — H-001 is presence-only.

set -e
# Match any "FROM image[:tag]" that does NOT contain @sha256.
# Strip comments and blank lines defensively.
BAD=$(find . -name 'Dockerfile*' -not -path './web/node_modules/*' \
        -exec grep -HnE '^FROM\s+[^@#]+(\s+AS\s+\S+)?\s*$' {} \; || true)
if [ -n "$BAD" ]; then
  echo "::error::H-001 regression: Dockerfile has bare FROM (no @sha256 digest pin):"
  echo "$BAD"
  echo ""
  echo "Pin every FROM to an immutable digest. See the bump"
  echo "procedure in Dockerfile's header comment (Bundle A / H-001)."
  exit 1
fi
echo "H-001 bare-from: clean."
