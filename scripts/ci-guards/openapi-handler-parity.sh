#!/usr/bin/env bash
# scripts/ci-guards/openapi-handler-parity.sh
#
# Verify every router.Register / r.mux.Handle call has a matching
# operationId in api/openapi.yaml, modulo documented exceptions in
# api/openapi-handler-exceptions.yaml.
#
# Per ci-pipeline-cleanup bundle Phase 9 / frozen decision 0.11.
#
# Phase 5 reconciliation (2026-05-13):
#   220 r.Register call sites in internal/api/router/router.go
#   209 unique (METHOD /path) router routes after de-duplication
#   158 operationIds in api/openapi.yaml
#    64 documented exceptions in api/openapi-handler-exceptions.yaml
#     0 unaccounted router routes — every route is in OpenAPI OR
#       in the exceptions YAML. Guard passes clean today.
#
# Of the 64 exceptions:
#   35 wire-protocol carve-outs (SCEP RFC 8894 = 8, ACME RFC 8555
#      default + per-profile = 27). These MUST stay as exceptions —
#      they're protocol contracts, not REST resources.
#   29 REST-shaped routes deferred from openapi.yaml authoring
#      (auth sessions, OIDC providers admin, breakglass admin,
#      users mgmt, runtime-config, demo-residual-cleanup, audit
#      export). Burn-down target: author the 29 OpenAPI ops over
#      the next ~2 sprints so the generated client (web/orval.config.ts)
#      covers them. Tracked under ARCH-H1 in
#      cowork/certctl-architecture-diligence-audit.html.
#
# Going forward: any new gap (in either direction) fails the build
# unless documented in the exceptions YAML.

set -e

python3 - <<'PY'
import re, sys, yaml

# Extract router routes: r.mux.Handle("METHOD /path", ...) and
# r.Register("METHOD /path", ...) — Go 1.22+ ServeMux pattern syntax.
with open('internal/api/router/router.go') as f:
    src = f.read()
routes = []
for m in re.finditer(r'r\.(?:mux\.Handle|Register)\("([A-Z]+)\s+(/[^"]*)"', src):
    routes.append((m.group(1), m.group(2)))
router_set = set(routes)

# Extract OpenAPI operations: paths × HTTP methods
with open('api/openapi.yaml') as f:
    spec = yaml.safe_load(f)
oapi_set = set()
for path, methods in (spec.get('paths') or {}).items():
    for method, op in methods.items():
        if method.upper() in ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'):
            oapi_set.add((method.upper(), path))

# Extract documented exceptions
try:
    with open('api/openapi-handler-exceptions.yaml') as f:
        exc_doc = yaml.safe_load(f)
except FileNotFoundError:
    exc_doc = {'documented_exceptions': []}
exception_set = set()
for entry in (exc_doc.get('documented_exceptions') or []):
    route_str = entry['route']
    parts = route_str.split(maxsplit=1)
    if len(parts) == 2:
        exception_set.add((parts[0], parts[1]))

# Report counts
print(f"Router routes:                  {len(router_set)}")
print(f"OpenAPI operations:             {len(oapi_set)}")
print(f"Documented exceptions:          {len(exception_set)}")
print()

fail = False

# Routes in router but NOT in openapi AND NOT in exceptions = drift
router_only_undocumented = router_set - oapi_set - exception_set
if router_only_undocumented:
    print(f"::error::OpenAPI ↔ handler drift: {len(router_only_undocumented)} router routes have no OpenAPI operationId AND are not in api/openapi-handler-exceptions.yaml:")
    for m, p in sorted(router_only_undocumented):
        print(f"  {m:6} {p}")
    print()
    print("Either:")
    print("  (a) Add the operationId to api/openapi.yaml (preferred for REST endpoints), OR")
    print("  (b) Add the route to api/openapi-handler-exceptions.yaml with a one-line `why:` justification")
    print("      (only for protocol-shaped or operational routes — health probes,")
    print("      Prometheus scrape, SCEP/EST/OCSP wire-protocol endpoints, etc.).")
    fail = True

# Routes in openapi but NOT in router = orphan operationId
oapi_only = oapi_set - router_set
if oapi_only:
    print(f"::error::OpenAPI ↔ handler drift: {len(oapi_only)} OpenAPI operations have no router registration:")
    for m, p in sorted(oapi_only):
        print(f"  {m:6} {p}")
    print()
    print("Either delete the operationId from api/openapi.yaml, OR add the missing")
    print("router registration in internal/api/router/router.go.")
    fail = True

# Exceptions that don't match any router route = stale exception
stale_exceptions = exception_set - router_set
if stale_exceptions:
    print(f"::error::Stale exceptions in api/openapi-handler-exceptions.yaml — these routes are not in the router:")
    for m, p in sorted(stale_exceptions):
        print(f"  {m:6} {p}")
    print()
    print("Remove the stale entry from api/openapi-handler-exceptions.yaml.")
    fail = True

if fail:
    sys.exit(1)
print("openapi-handler-parity: clean.")
PY
