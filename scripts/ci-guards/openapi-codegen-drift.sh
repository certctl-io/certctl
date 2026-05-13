#!/usr/bin/env bash
# scripts/ci-guards/openapi-codegen-drift.sh
#
# Phase 5 ARCH-M6 scaffolding (2026-05-13): block the build when
# api/openapi.yaml changes but web/src/api/generated/ wasn't
# regenerated alongside. The generated tree is git-tracked; running
# `cd web && npm run generate` regenerates from api/openapi.yaml.
#
# Guard logic:
#
#   1. If web/src/api/generated/ does NOT exist yet, do nothing.
#      This phase ships the orval.config.ts scaffolding without
#      running `npm install orval` from the sandbox (disk-full); the
#      first operator-run of `npm run generate` creates the directory
#      and the guard activates from that point forward.
#
#   2. If web/src/api/generated/ exists:
#      - Regenerate into a tmp dir using `npm run generate`
#        (requires orval to be installed locally).
#      - Diff against the tracked tree.
#      - Fail the build with a clear regenerate-command pointer.
#
# Note: this guard requires Node + npm to be available on the CI
# runner. The frontend job in ci.yml already provisions both
# (.github/workflows/ci.yml frontend-build), so wiring is mechanical.
# Run order matters: this guard must run AFTER `npm ci` in the
# frontend job so orval is in node_modules.

set -e

GENERATED_DIR="web/src/api/generated"

if [ ! -d "$GENERATED_DIR" ]; then
  echo "openapi-codegen-drift: skipped — $GENERATED_DIR does not exist yet."
  echo "  This is expected during Phase 5 scaffolding. Once the operator"
  echo "  runs 'cd web && npm install && npm run generate' for the first"
  echo "  time, the directory lands and this guard activates."
  exit 0
fi

# Tolerate the case where orval isn't installed in the local
# environment — in that case the guard is informational. The CI
# pipeline activates it once the frontend job runs `npm ci`.
if [ ! -f "web/node_modules/.bin/orval" ]; then
  echo "openapi-codegen-drift: skipped — web/node_modules/.bin/orval not present."
  echo "  Run 'cd web && npm ci' to install. CI runs npm ci before this guard."
  exit 0
fi

# Snapshot the tracked tree, regenerate into a tmpdir, diff.
TMPGEN="$(mktemp -d -t orval-drift.XXXXXX)"
trap 'rm -rf "$TMPGEN"' EXIT

# Copy the tracked tree so we can compare against a fresh regeneration.
cp -r "$GENERATED_DIR" "$TMPGEN/tracked"

# Regenerate in-place; orval honors orval.config.ts output paths.
(cd web && npm run generate --silent) >/dev/null

# Diff the tracked tree against the freshly-regenerated tree.
if diff -r --brief "$TMPGEN/tracked" "$GENERATED_DIR" >/dev/null 2>&1; then
  echo "openapi-codegen-drift: clean — generated client matches openapi.yaml"
  # Restore the tracked tree (regeneration overwrites it; restore so
  # the working tree is back to the tracked state).
  rm -rf "$GENERATED_DIR"
  cp -r "$TMPGEN/tracked" "$GENERATED_DIR"
  exit 0
fi

echo "::error::openapi-codegen-drift regression: $GENERATED_DIR is stale."
echo ""
echo "api/openapi.yaml changed but the generated client tree wasn't"
echo "regenerated alongside. Regenerate with:"
echo ""
echo "    cd web && npm run generate"
echo ""
echo "Then commit the updated $GENERATED_DIR/ alongside the openapi.yaml"
echo "change in this PR."
echo ""
echo "Diff (- tracked, + regenerated):"
diff -r "$TMPGEN/tracked" "$GENERATED_DIR" | head -80

# Restore tracked tree so the working tree isn't surprising.
rm -rf "$GENERATED_DIR"
cp -r "$TMPGEN/tracked" "$GENERATED_DIR"
exit 1
