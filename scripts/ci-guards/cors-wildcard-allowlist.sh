#!/usr/bin/env bash
# cors-wildcard-allowlist.sh — Audit 2026-05-10 CRIT-3 ratchet.
#
# middleware.CORSWildcard (formerly middleware.CORS) emits
# Access-Control-Allow-Origin: * unconditionally, ignoring the operator's
# CERTCTL_CORS_ORIGINS knob (CWE-942). It is ONLY safe to use on endpoints
# that (a) carry no credentials and (b) must be reachable from any origin
# (health probes, version probes, the GUI's pre-login auth-info probe).
#
# This guard greps for every middleware.CORSWildcard call site, extracts
# the nearest preceding r.mux.Handle("…") route string, and asserts that
# the route appears in the documented ALLOWLIST below. Adding a new
# wildcard-CORS wrap therefore requires either:
#
#   1. Adding the route to ALLOWLIST below AND documenting why in the
#      commit body, or
#   2. Switching the call site to middleware.NewCORS(reg.CorsCfg).
#
# Closes CRIT-3 of cowork/auth-bundles-audit-2026-05-10.md. See also
# internal/api/middleware/middleware.go::CORSWildcard for the doc block.

set -euo pipefail

ROUTER=internal/api/router/router.go

# Routes allowed to use middleware.CORSWildcard. Every entry must be a
# credential-free endpoint that operators expect to be reachable from any
# origin (Kubernetes probes, Prometheus, the pre-login GUI).
ALLOWLIST=(
    "GET /health"               # K8s/Docker liveness probe
    "GET /ready"                # K8s/Docker readiness probe
    "GET /api/v1/version"       # rollout probes; pre-auth
    "GET /api/v1/auth/info"     # GUI reads before login
)

if [[ ! -f "$ROUTER" ]]; then
    echo "FAIL: $ROUTER not found (run from certctl/ root)"
    exit 1
fi

# Extract every (route, wrap) pair from the router by finding each
# r.mux.Handle("ROUTE", ...) block and checking whether its wrapping list
# contains middleware.CORSWildcard.
python3 - <<PY
import re, sys

ALLOWLIST = [
    "GET /health",
    "GET /ready",
    "GET /api/v1/version",
    "GET /api/v1/auth/info",
]
allowset = set(ALLOWLIST)

with open("$ROUTER", "r") as f:
    src = f.read()

# Find every r.mux.Handle("ROUTE", middleware.Chain(... or direct chain)) block
# and check whether middleware.CORSWildcard appears within the next ~400 chars.
violations = []
seen = []
for m in re.finditer(r'r\.mux\.Handle\("([^"]+)",', src):
    route = m.group(1)
    region = src[m.end(): m.end() + 600]
    if "middleware.CORSWildcard" not in region:
        continue
    seen.append(route)
    if route not in allowset:
        violations.append(route)

if violations:
    print("FAIL: middleware.CORSWildcard call sites outside the allowlist:")
    for r in violations:
        print("  " + r)
    print()
    print("If a new wildcard-CORS endpoint is intentional, add the route to")
    print("ALLOWLIST in scripts/ci-guards/cors-wildcard-allowlist.sh AND")
    print("document why in the commit body. Otherwise switch the call site")
    print("to middleware.NewCORS(reg.CorsCfg).")
    sys.exit(1)

print(f"OK: {len(seen)} middleware.CORSWildcard call site(s); all allowlisted.")
for r in seen:
    print(f"  - {r}")
PY
