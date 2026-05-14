#!/usr/bin/env bash
# scripts/ci-guards/no-sh-c-in-connectors.sh
#
# Phase 7 SEC-H2 closure (2026-05-14): block any future `sh -c`
# shell-exec pattern inside target connectors.
#
# Phase 7 migrated all 5 connectors (nginx, apache, haproxy, postfix,
# javakeystore) from `exec.CommandContext(ctx, "sh", "-c", command)`
# to argv-form `exec.CommandContext(ctx, argv[0], argv[1:]...)`. The
# operator's command string is split via
# internal/validation.SplitShellCommand at exec-time (which also
# re-validates against the metachar deny-list as defense-in-depth).
# Server-side validation via ValidateShellCommand happens at
# config-time and remains unchanged.
#
# This guard blocks any future regression. Add a new connector that
# legitimately needs shell features → add it to the ALLOWLIST below
# with a one-line justification + paired ValidateConfig allowlist
# regex.
#
# Pattern matches both the direct form:
#   exec.CommandContext(ctx, "sh", "-c", ...)
# and the executor-style:
#   c.executor.Execute(ctx, "sh", "-c", ...)
#
# Production code only; *_test.go files are exempt (test fixtures
# legitimately invoke /bin/sh for assertion setup).

set -e

TARGET_DIR="internal/connector/target"

if [ ! -d "$TARGET_DIR" ]; then
  echo "no-sh-c-in-connectors: skipped — $TARGET_DIR not found"
  exit 0
fi

# Allowlist of connectors permitted to use sh -c. Empty post-Phase-7.
# To add a connector here:
#   1. Document WHY argv-form doesn't work for it (typically:
#      legitimately needs pipelines, globs, or env-var substitution).
#   2. Add a paired strict-allowlist regex in ValidateShellCommand
#      so the operator's command can't be arbitrary shell.
#   3. Append the connector's package name below.
ALLOWLIST=""

# Find every production .go file under the connector tree where an
# actual exec / Execute call site invokes `"sh", "-c"`. We match
# call-site shapes, NOT comment text — the production connectors
# carry Phase-7-history comments like
#   `// exec.CommandContext(ctx, "sh", "-c", command) — the`
# explaining the pre-migration shape, and those should pass clean.
#
# The match condition: a line containing both an exec/Execute call
# AND the "sh", "-c" args. Comments mentioning the legacy shape
# don't trigger because comment lines don't contain an active
# exec call.
hits=$(grep -rnE '(exec\.Command(Context)?|\.Execute)\([^)]*"sh"[[:space:]]*,[[:space:]]*"-c"' "$TARGET_DIR" \
  --include='*.go' \
  --exclude='*_test.go' \
  | grep -vE "configcheck/configcheck\.go" \
  | grep -vE ':[[:space:]]*//' \
  || true)

if [ -z "$hits" ]; then
  echo "no-sh-c-in-connectors: clean — 0 sh -c sites in production connector code"
  exit 0
fi

# Filter out allowlisted connectors (none post-Phase-7).
unmatched="$hits"
if [ -n "$ALLOWLIST" ]; then
  unmatched=$(echo "$hits" | grep -vE "$ALLOWLIST" || true)
fi

if [ -z "$unmatched" ]; then
  echo "no-sh-c-in-connectors: clean — all sh -c sites are allowlisted"
  exit 0
fi

echo "::error::no-sh-c-in-connectors regression: production connector code invokes 'sh -c'"
echo ""
echo "Phase 7 SEC-H2 migrated all 5 connectors to argv-form exec via"
echo "validation.SplitShellCommand. Re-introducing 'sh -c' would reopen"
echo "the command-injection surface the migration closed."
echo ""
echo "Offending sites:"
echo "$unmatched"
echo ""
echo "If the new connector legitimately needs shell features, add it"
echo "to the ALLOWLIST in this script + a paired strict regex in"
echo "ValidateConfig. See the script header for the contract."
exit 1
