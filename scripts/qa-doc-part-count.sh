#!/usr/bin/env bash
# scripts/qa-doc-part-count.sh
#
# Bundle P / Strengthening #6 — QA-doc Part-count drift guard.
# Forces every PR that adds a Part to docs/testing-guide.md to keep
# docs/qa-test-guide.md headline in sync.
#
# Per ci-pipeline-cleanup bundle Phase 11 / frozen decision 0.13:
# moved out of CI (was in ci.yml) — operator runs via 'make verify-docs'
# pre-tag. Protects docs-the-operator-reads, not anything the product
# depends on; CI-blocking on every push was overkill.

set -e
DOC_PARTS=$(grep -oE '49 of [0-9]+ Parts' docs/qa-test-guide.md | grep -oE '[0-9]+' | tail -1)
GUIDE_PARTS=$(grep -cE '^## Part [0-9]+:' docs/testing-guide.md)
if [ -z "$DOC_PARTS" ]; then
  echo "::error::Could not extract Part count from docs/qa-test-guide.md headline."
  echo "  Expected pattern: '49 of <N> Parts'"
  exit 1
fi
if [ "$DOC_PARTS" != "$GUIDE_PARTS" ]; then
  echo "::error::DRIFT — qa-test-guide.md headline claims $DOC_PARTS Parts; testing-guide.md has $GUIDE_PARTS Parts."
  echo "  Update docs/qa-test-guide.md to match. Bundle I patched this once;"
  echo "  Bundle P added this guard so the drift cannot recur silently."
  exit 1
fi
echo "qa-doc-part-count: clean ($DOC_PARTS == $GUIDE_PARTS)."
