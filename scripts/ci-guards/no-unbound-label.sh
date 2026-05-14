#!/usr/bin/env bash
# Phase 5 closure (UX-H4 regression gate): fail the build when a new
# <label> element ships in production tsx without htmlFor= or a wrapping
# <FormField> primitive (which auto-emits htmlFor via useId()).
#
# Pre-Phase-5: 139 <label> tags, 6 with htmlFor, 0 inputs with id —
# WCAG 1.3.1 fails on ~99% of form fields. The FormField primitive
# (web/src/components/FormField.tsx) closes new label/input pairs by
# construction; this guard prevents reintroducing unbound labels in
# untouched parts of the codebase.
#
# Grace period: during the Phase 5 migration we expect ~133 existing
# unbound labels to stay in place until each owning page migrates
# through. They live in the allowlist file alongside this script
# (no-unbound-label-exceptions.txt). Each migration deletes the
# corresponding line; when the allowlist is empty, this guard becomes
# strictly enforcing and the allowlist file should be removed.
#
# Known false-positive class: wrap-style implicit-association labels —
# `<label><input/>...</label>`. These ARE a11y-safe (browsers + screen
# readers pair the wrapped input with the label automatically — no
# htmlFor needed), but this guard's line-based regex can't tell the
# wrap pattern apart from a sibling-label-no-htmlFor bug. When such
# patterns ship, raise the baseline with a one-line explanation in
# the commit message; they're benign. Phase 6 added 2 (the timestamp-
# mode radios in AuthSettingsPage), so baseline 132 → 134.
#
# Algorithm:
#   1. Count current unbound labels (labels NOT preceded by htmlFor= on
#      the same line OR within the wrapping JSX block).
#   2. Compare against the allowlist's recorded count. If today's count
#      is HIGHER than the allowlist baseline, a new unbound label was
#      added — fail with the diff.
#   3. If today's count is LOWER, congratulate and remind to update
#      the baseline.
#
# Strict mode: pass `--strict` to fail on any unbound label, ignoring
# the allowlist. Use once the allowlist is empty.
set -euo pipefail

# Resolve script dir BEFORE cd so baseline path stays valid.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASELINE_FILE="$SCRIPT_DIR/no-unbound-label-baseline.txt"

cd "$SCRIPT_DIR/../../web"

STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1

# Count <label tags WITHOUT htmlFor= on the same line in production
# tsx (excludes tests + node_modules + dist).
COUNT_UNBOUND=$(
  grep -rohE '<label[^>]*>' src \
    --include='*.tsx' \
    --exclude='*.test.*' \
    --exclude-dir='__tests__' \
    --exclude-dir='node_modules' \
    --exclude-dir='dist' \
    2>/dev/null \
    | grep -vcE 'htmlFor='
) || true

BASELINE=0
if [[ -f "$BASELINE_FILE" ]]; then
  BASELINE=$(cat "$BASELINE_FILE" | tr -d '[:space:]')
fi

echo "Unbound <label> tags in web/src — current: $COUNT_UNBOUND, baseline: $BASELINE"

if [[ $STRICT -eq 1 ]]; then
  if [[ $COUNT_UNBOUND -gt 0 ]]; then
    echo "FAIL (--strict): $COUNT_UNBOUND unbound <label> tag(s) remain. Migrate to <FormField> or add htmlFor=."
    exit 1
  fi
  echo "PASS (--strict): zero unbound <label> tags."
  exit 0
fi

if [[ $COUNT_UNBOUND -gt $BASELINE ]]; then
  echo ""
  echo "FAIL: A new unbound <label> tag was added ($COUNT_UNBOUND > baseline $BASELINE)."
  echo ""
  echo "Wrap the new label in <FormField label='…'>{<input … />}</FormField> — the"
  echo "primitive at web/src/components/FormField.tsx auto-pairs label htmlFor with"
  echo "the child input's id via React's useId() so WCAG 1.3.1 holds by construction."
  echo ""
  echo "If a raw <label> is genuinely needed (rare: e.g. wrapping a Headless UI"
  echo "Switch where Headless UI handles the binding internally), add htmlFor=…"
  echo "explicitly. Then update the baseline:"
  echo ""
  echo "  echo $COUNT_UNBOUND > $BASELINE_FILE"
  echo ""
  exit 1
fi

if [[ $COUNT_UNBOUND -lt $BASELINE ]]; then
  echo ""
  echo "PASS — and you're under baseline! Drop the baseline to lock in progress:"
  echo "  echo $COUNT_UNBOUND > $BASELINE_FILE"
  echo ""
fi

exit 0
