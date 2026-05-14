#!/usr/bin/env bash
# scripts/ci-guards/no-bare-newticker-in-scheduler.sh
#
# Phase 6 SCALE-M5 closure (2026-05-14): block any future
# `time.NewTicker(...)` use inside internal/scheduler/scheduler.go.
#
# Phase 6 migrated all 15 scheduler-loop ticker sites from bare
# time.NewTicker(interval) to NewJitteredTicker(interval,
# DefaultSchedulerJitter) so multiple loops with the same cadence
# don't co-fire and produce hour-boundary CPU + DB spikes. A future
# refactor that re-introduces bare NewTicker would silently regress
# the spreading behavior.
#
# The guard:
#   - Greps for `time.NewTicker(` in internal/scheduler/scheduler.go
#     ONLY (the jitter helper lives in a separate file and is allowed
#     to wrap time.NewTimer internally).
#   - Fails the build on ANY match.
#
# Adding a new ticker site: use NewJitteredTicker instead. The base
# interval stays operator-configurable via the existing scheduler
# config fields; jitter is added on top.

set -e

TARGET="internal/scheduler/scheduler.go"

if [ ! -f "$TARGET" ]; then
  echo "no-bare-newticker-in-scheduler: skipped — $TARGET not found"
  exit 0
fi

hits=$(grep -cE 'time\.NewTicker\(' "$TARGET" || true)

if [ "$hits" -gt 0 ]; then
  echo "::error::no-bare-newticker-in-scheduler regression: $hits bare time.NewTicker(...) call(s) in $TARGET"
  echo ""
  echo "All scheduler-loop tickers MUST use NewJitteredTicker (Phase 6 SCALE-M5)."
  echo "Replace 'ticker := time.NewTicker(interval)' with"
  echo "        'ticker := NewJitteredTicker(interval, DefaultSchedulerJitter)'"
  echo ""
  echo "Offending lines:"
  grep -nE 'time\.NewTicker\(' "$TARGET" || true
  exit 1
fi

echo "no-bare-newticker-in-scheduler: clean — 0 bare NewTicker sites in scheduler.go"

# Belt-and-suspenders: confirm the JitteredTicker site count is
# non-trivial (regression catch where someone replaced the bare
# tickers with no-op direct-fire shims).
jitter_hits=$(grep -cE 'NewJitteredTicker\(' "$TARGET" || true)
if [ "$jitter_hits" -lt 10 ]; then
  echo "::warning::no-bare-newticker-in-scheduler: only $jitter_hits JitteredTicker sites in scheduler.go (expected ≥ 10 — Phase 6 baseline was 15)"
fi
