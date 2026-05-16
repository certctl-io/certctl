#!/usr/bin/env bash
# Copyright 2026 certctl LLC. All rights reserved.
# SPDX-License-Identifier: BUSL-1.1
#
# Acquisition-audit SCALE-007 closure (Sprint 6 ACQ, 2026-05-16).
# Per-chunk frontend bundle-size budget guard.
#
# Reads web/.size-limit.json and asserts every chunk-size pattern
# matches its committed cap (brotli-compressed, the default
# size-limit measurement mode — closest analogue to what a real
# browser downloads). A regression that bloats a chunk past its
# cap fails the build and forces an explicit operator decision —
# either fix the regression, or raise the cap in
# web/.size-limit.json with a rationale comment in the commit
# message.
#
# Contract (matches the other scripts/ci-guards/<id>.sh files):
#   - exit 0 on clean repo
#   - non-zero with `::error::` prefix on regression
#   - skips with exit 0 when the prerequisites aren't installed
#     (npm missing, web/node_modules missing, web/dist not built)
#     — CI's frontend-build job runs `npm ci` + `npx vite build`
#     BEFORE invoking this guard, so the skip path only fires in
#     local fast-loop runs where the operator hasn't built the
#     frontend yet.
#
# Local run:
#   cd web && npm ci && npm run build && cd ..
#   bash scripts/ci-guards/G-frontend-bundle-budget.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

fail() {
	echo "::error::G-frontend-bundle-budget: $*" >&2
	exit 1
}

if ! command -v npm >/dev/null 2>&1; then
	echo "G-frontend-bundle-budget: skipped — npm not on PATH."
	echo "  Install: https://nodejs.org/ (CI uses Node 22 via actions/setup-node)."
	exit 0
fi

if [ ! -f "web/.size-limit.json" ]; then
	fail "web/.size-limit.json is missing — the size-limit config is the source of truth for per-chunk budgets."
fi

if [ ! -d "web/node_modules/size-limit" ]; then
	echo "G-frontend-bundle-budget: skipped — web/node_modules/size-limit/ missing."
	echo "  Run \`cd web && npm ci\` first."
	exit 0
fi

if [ ! -d "web/dist/assets" ]; then
	echo "G-frontend-bundle-budget: skipped — web/dist/assets/ not present."
	echo "  Run \`cd web && npm run build\` first."
	exit 0
fi

echo "G-frontend-bundle-budget: checking $(ls -1 web/dist/assets/*.js 2>/dev/null | wc -l) JS chunks against web/.size-limit.json..."
cd web
if ! npm run --silent size; then
	echo "::error::G-frontend-bundle-budget: at least one chunk exceeded its budget in web/.size-limit.json. See output above for the offender."
	echo "  To fix: either reduce the chunk size (audit the imports / move code to a route-level lazy boundary / drop an unneeded dependency), or — only if the growth is intentional — raise the cap in web/.size-limit.json with a rationale comment in the commit message."
	exit 1
fi

echo "G-frontend-bundle-budget: PASS — all chunks within budget."
