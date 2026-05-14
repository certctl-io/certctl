#!/usr/bin/env bash
# scripts/ci-guards/openapi-handler-parity.sh
#
# Verify every router.Register / r.mux.Handle call has a matching
# operationId in api/openapi.yaml, modulo documented exceptions in
# api/openapi-handler-exceptions.yaml.
#
# Per ci-pipeline-cleanup bundle Phase 9 / frozen decision 0.11.
#
# Phase 13 Sprint 13.1 (2026-05-14) — every entry in the exceptions
# YAML now carries a required `category: wire-protocol | rest-deferred`
# field. This script reports the two buckets alongside the total. The
# rest-deferred bucket is gated by a sibling guard
# (openapi-rest-deferred-monotonic.sh) against a checked-in baseline
# at api/openapi-handler-exceptions-baseline.txt.
#
# Current state (post-Sprint-13.7 / 2026-05-14):
#   220 r.Register / r.mux.Handle call sites in internal/api/router/router.go
#   186 operationIds in api/openapi.yaml
#    36 documented exceptions (36 wire-protocol + 0 rest-deferred)
#     0 unaccounted router routes — guard passes clean today.
#
# Sprints 13.4-13.6 drove rest-deferred to zero by authoring 28 OpenAPI
# ops + deleting the corresponding exception entries. Sprint 13.7
# (this comment-block update + the inline fail-on-rest-deferred check
# at the bottom of the python block) tightens this guard's
# rest-deferred floor from "monotonic-decrease vs baseline" (the
# sibling guard openapi-rest-deferred-monotonic.sh) to a HARD
# zero-exact pin. The `category: rest-deferred` escape hatch is now
# closed for good: any future PR adding a new REST route MUST author
# its OpenAPI op or fail CI.
#
# The sibling monotonic-decrease guard stays in tree as belt-and-
# suspenders — both must hold. The monotonic guard catches baseline-
# drift accidents (e.g. an operator manually edits the baseline up
# without surfacing the rationale); this guard catches the underlying
# rest-deferred bucket re-growing at all.
#
# Going forward: any new gap (in either direction) fails the build
# unless documented in the exceptions YAML with category=wire-protocol
# (carry an RFC anchor in `why:` for review-time scrutiny).
#
# Subcommand:
#   bash scripts/ci-guards/openapi-handler-parity.sh
#     Full parity check + bucket reporting.
#   bash scripts/ci-guards/openapi-handler-parity.sh --bucket=wire-protocol
#   bash scripts/ci-guards/openapi-handler-parity.sh --bucket=rest-deferred
#     Print just the count for the named bucket (used by sibling guards
#     + Sprint 13.7's zero-exact pin). Exit 0 always; informational.

set -e

BUCKET=""
case "${1:-}" in
    --bucket=wire-protocol|--bucket=rest-deferred)
        BUCKET="${1#--bucket=}"
        ;;
    "")
        ;;
    *)
        echo "::error::unknown argument: $1"
        echo "usage: $0 [--bucket=wire-protocol|--bucket=rest-deferred]"
        exit 2
        ;;
esac

python3 - "$BUCKET" <<'PY'
import re, sys, yaml

bucket_arg = sys.argv[1] if len(sys.argv) > 1 else ""

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
bucket_counts = {'wire-protocol': 0, 'rest-deferred': 0}
missing_category = []
unknown_category = []
for entry in (exc_doc.get('documented_exceptions') or []):
    route_str = entry['route']
    parts = route_str.split(maxsplit=1)
    if len(parts) == 2:
        exception_set.add((parts[0], parts[1]))
    cat = entry.get('category')
    if cat is None:
        missing_category.append(route_str)
    elif cat in bucket_counts:
        bucket_counts[cat] += 1
    else:
        unknown_category.append((route_str, cat))

# --bucket=X subcommand: print just the count, exit 0, no other output.
if bucket_arg in bucket_counts:
    print(bucket_counts[bucket_arg])
    sys.exit(0)

# Report counts
print(f"Router routes:                  {len(router_set)}")
print(f"OpenAPI operations:             {len(oapi_set)}")
print(f"Documented exceptions:          {len(exception_set)}")
print(f"  wire-protocol:                {bucket_counts['wire-protocol']}")
print(f"  rest-deferred:                {bucket_counts['rest-deferred']}")
print()

fail = False

# Phase 13 Sprint 13.1: every entry MUST have a category. Missing or
# unknown categories fail the build — keeps the bucket math honest.
if missing_category:
    print(f"::error::api/openapi-handler-exceptions.yaml: {len(missing_category)} entries missing required `category:` field:")
    for r in missing_category:
        print(f"  {r}")
    print()
    print("Add `category: wire-protocol` (with an RFC anchor in `why:`) or")
    print("author the route's OpenAPI op (the rest-deferred bucket is now")
    print("pinned at zero — see Phase 13 Sprint 13.7 closure).")
    fail = True

if unknown_category:
    print(f"::error::api/openapi-handler-exceptions.yaml: {len(unknown_category)} entries with unknown category value (must be wire-protocol or rest-deferred):")
    for r, c in unknown_category:
        print(f"  {r}  → category: {c}")
    fail = True

# Phase 13 Sprint 13.7 — hard zero-exact pin on the rest-deferred
# bucket. ARCH-H1's substantive close requires that the bucket stay
# empty in perpetuity: any new REST route MUST land with an
# OpenAPI op. Categorizing a new exception as `category: rest-deferred`
# is no longer an escape hatch — it fails CI immediately, surfacing
# the route + suggesting the fix.
if bucket_counts['rest-deferred'] > 0:
    print(f"::error::rest-deferred bucket is non-empty ({bucket_counts['rest-deferred']} entries) — Phase 13 Sprint 13.7 closure pins this at zero.")
    print()
    print("Every entry in api/openapi-handler-exceptions.yaml with")
    print("`category: rest-deferred` represents a REST-shaped route whose")
    print("OpenAPI op was deferred. Author the OpenAPI op in api/openapi.yaml")
    print("with a request/response schema mirroring the Go handler's")
    print("projection types, then delete the exception entry.")
    print()
    print("Offending entries:")
    for entry in (exc_doc.get('documented_exceptions') or []):
        if entry.get('category') == 'rest-deferred':
            print(f"  {entry['route']}")
    fail = True

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
    print("      AND a `category: wire-protocol | rest-deferred` field (only protocol-shaped")
    print("      or operational routes — health probes, Prometheus scrape, SCEP/EST/ACME")
    print("      wire-protocol endpoints, etc. — qualify as wire-protocol).")
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
