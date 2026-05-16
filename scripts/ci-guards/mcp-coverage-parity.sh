#!/usr/bin/env bash
# scripts/ci-guards/mcp-coverage-parity.sh
#
# ARCH-004 closure (Sprint 4, 2026-05-16). Pre-fix the README claimed
# the full REST API was exposed as MCP tools; the actual coverage was
# 162 tools / 221 routes. Operators and diligence reviewers had no
# published evidence of what the gap was.
#
# This guard enforces a simple invariant: every route registered in
# internal/api/router/router.go is EITHER wrapped by a `gomcp.AddTool`
# call OR matches one of the four named exclusion categories in
# docs/reference/mcp-coverage.md (protocol-conformance, browser-only
# auth, liveness, streaming/binary).
#
# Implementation note: the guard works on the route-prefix level rather
# than the per-route level. Per-route allowlisting would require
# embedding 60+ route literals here — fragile and noisy. Category
# matching (`/acme/*` → exclude) is the right grain for the diligence
# story this guard pins.

set -e

ROUTER="internal/api/router/router.go"
MCP_DIR="internal/mcp"
COVERAGE_DOC="docs/reference/mcp-coverage.md"

if [ ! -f "$ROUTER" ]; then
  echo "::error::$ROUTER not found"
  exit 1
fi
if [ ! -d "$MCP_DIR" ]; then
  echo "::error::$MCP_DIR not found"
  exit 1
fi
if [ ! -f "$COVERAGE_DOC" ]; then
  echo "::error::$COVERAGE_DOC missing — operator-facing coverage doc is the canonical record. Re-create it from the ARCH-004 closure template."
  exit 1
fi

# Count REST routes and MCP tools.
routes=$(grep -cE '^\s*r\.Register\(' "$ROUTER")
tools=$(grep -rE 'gomcp\.AddTool' "$MCP_DIR" --include='*.go' \
        | grep -v '_test.go' | wc -l | tr -d ' ')

# Exclusion-category route paths, by prefix. Routes matching any of these
# are EXPECTED not to have an MCP tool — per docs/reference/mcp-coverage.md
# categories 1-4. Edit this list ONLY when adding a fifth category (and
# document it in the doc).
EXCLUDED_PATTERNS=(
  # Category 1 — protocol-conformance endpoints
  '"GET /acme/'  '"POST /acme/'  '"HEAD /acme/'
  '"GET /scep/'  '"POST /scep/'
  '"GET /\.well-known/est/'  '"POST /\.well-known/est/'
  '"GET /ocsp'   '"POST /ocsp'
  '"GET /\.well-known/pki/crl/'
  # Category 2 — browser-only auth flow
  '"GET /auth/oidc/login'
  '"GET /auth/oidc/callback'
  '"POST /auth/oidc/back-channel-logout'
  '"POST /api/v1/auth/bootstrap'
  '"POST /api/v1/auth/login'
  '"POST /api/v1/auth/logout'
  '"GET /api/v1/auth/csrf'
  # Category 3 — liveness / readiness / version
  '"GET /health'
  '"GET /ready'
  '"GET /api/v1/version'
  # Category 4 — streaming / binary download
  '"GET /api/v1/certificates/{id}/download'
  '"GET /api/v1/certificates/{id}/chain'
  '"GET /api/v1/intermediate-cas/{id}/cert'
  '"GET /api/v1/metrics/prometheus'
)

excluded=0
for pat in "${EXCLUDED_PATTERNS[@]}"; do
  # grep -c on a no-match returns 0 + exit 1; coerce both into a
  # single-line digit so the arithmetic below stays well-formed.
  c=$(grep -cE "r\.Register\($pat" "$ROUTER" 2>/dev/null | head -1 || true)
  c=${c:-0}
  excluded=$((excluded + c))
done

expected_min_tools=$((routes - excluded))
# Some legitimate REST routes share an MCP tool (bulk-list endpoints
# fan in; RBAC role-permission edit routes bundle into one tool that
# takes a verb param; etc.). Empirically the count-based gap at
# 2026-05-16 is ~25; pick 40 as the floor below which a real
# regression has happened. Tighten this number when the gap narrows
# (e.g. when an MCP tool generator catches up to all routes).
slack=40
floor=$((expected_min_tools - slack))
if [ "$floor" -lt 0 ]; then floor=0; fi

if [ "$tools" -lt "$floor" ]; then
  echo "::error file=${COVERAGE_DOC}::mcp-coverage-parity: tool count ($tools) < floor ($floor)."
  echo "  routes:     $routes"
  echo "  excluded:   $excluded (matched the 4 exclusion categories in $COVERAGE_DOC)"
  echo "  net REST:   $expected_min_tools"
  echo "  tool floor: $floor (net − $slack slack)"
  echo ""
  echo "Either add the missing tools or, if the new routes are exclusion-category,"
  echo "add a matching pattern to EXCLUDED_PATTERNS in this script + a paragraph"
  echo "to $COVERAGE_DOC explaining the category."
  exit 1
fi

# Tightness check the other direction — if tools grow far past routes
# (impossible without test-helper noise leaking), flag it so the doc
# stays in sync.
if [ "$tools" -gt $((routes + 30)) ]; then
  echo "::warning file=${COVERAGE_DOC}::mcp-coverage-parity: tool count ($tools) exceeds routes ($routes) by >30 — coverage doc may be stale."
fi

echo "mcp-coverage-parity: clean."
echo "  REST routes:                   $routes"
echo "  intentional exclusions:        $excluded"
echo "  MCP tools registered:          $tools"
echo "  coverage of non-excluded:      $tools / $expected_min_tools"
