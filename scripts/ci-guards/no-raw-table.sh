#!/usr/bin/env bash
# Phase 9 closure (UX-M7 regression gate): fail CI when a new raw
# `<table>` ships in production tsx outside the canonical DataTable
# + Skeleton primitives.
#
# Pre-Phase-9 the codebase had 19 `<table>` sites across 16 files.
# Two of those are LEGITIMATE primitives — they ARE the chokepoint
# every list page should route through:
#   • web/src/components/DataTable.tsx — the canonical table component
#   • web/src/components/Skeleton.tsx  — the loading-shape table-shaped
#                                         skeleton
#
# The other 14 page-level raw tables stay in place during the Phase 9
# rollout (the audit prompt's "DO NOT migrate all 18 in one PR" rule).
# This guard baseline-locks the existing 14; every migration to
# DataTable drops the baseline by 1. `--strict` mode rejects any raw
# table once the backlog clears.
#
# Tests are excluded.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASELINE_FILE="$SCRIPT_DIR/no-raw-table-baseline.txt"

cd "$SCRIPT_DIR/../../web"

STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1

# Count <table tags outside DataTable.tsx + Skeleton.tsx (the
# allowlisted primitives) in production tsx (excludes tests +
# node_modules + dist).
COUNT_RAW=$(
  grep -rl '<table' src \
    --include='*.tsx' \
    --exclude='*.test.*' \
    --exclude-dir='__tests__' \
    --exclude-dir='node_modules' \
    --exclude-dir='dist' \
    2>/dev/null \
    | grep -vE '(DataTable\.tsx|Skeleton\.tsx)$' \
    | xargs -r grep -ohE '<table\b' 2>/dev/null \
    | wc -l \
    | tr -d '[:space:]'
)
COUNT_RAW=${COUNT_RAW:-0}

BASELINE=0
if [[ -f "$BASELINE_FILE" ]]; then
  BASELINE=$(cat "$BASELINE_FILE" | tr -d '[:space:]')
fi

echo "Raw <table> tags outside DataTable + Skeleton — current: $COUNT_RAW, baseline: $BASELINE"

if [[ $STRICT -eq 1 ]]; then
  if [[ $COUNT_RAW -gt 0 ]]; then
    echo "FAIL (--strict): $COUNT_RAW raw <table> tag(s) remain. Migrate to <DataTable> from web/src/components/DataTable.tsx."
    exit 1
  fi
  echo "PASS (--strict): zero raw <table> tags."
  exit 0
fi

if [[ $COUNT_RAW -gt $BASELINE ]]; then
  echo ""
  echo "FAIL: A new raw <table> tag was added ($COUNT_RAW > baseline $BASELINE)."
  echo ""
  echo "Migrate to <DataTable> from web/src/components/DataTable.tsx —"
  echo "it provides StatusBadge wiring, EmptyState slot, Skeleton loading,"
  echo "pagination, selectable rows, and the Phase 9 UX-M8 density toggle"
  echo "for free."
  echo ""
  exit 1
fi

if [[ $COUNT_RAW -lt $BASELINE ]]; then
  echo ""
  echo "PASS — and you're under baseline! Drop the baseline to lock in progress:"
  echo "  echo $COUNT_RAW > $BASELINE_FILE"
  echo ""
fi

exit 0
