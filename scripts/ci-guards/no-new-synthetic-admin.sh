#!/usr/bin/env bash
# Audit 2026-05-11 A-8 — no new code paths may reference actor-demo-anon
# outside the declared allowlist. The synthetic actor is a load-bearing
# demo-mode primitive but ANY new reference in production code paths is
# a candidate footgun (the original CRIT class was a fallback that
# resolved unauthenticated requests to this actor and got full admin).
#
# Adding a legitimate new reference? Add the file to ALLOWLIST below
# AND describe the reason in this header. Operators (auditors) read
# this script to understand where the synthetic admin "lives" in the
# codebase.
#
# Test files (*_test.go), /vendor/, /docs/, and CHANGELOG entries are
# excluded — they don't introduce new runtime code paths.

set -euo pipefail

# Files that legitimately reference the actor-demo-anon literal in
# source. Each entry needs a one-line rationale comment so future
# maintainers don't have to trace why it's here.
ALLOWLIST=(
    "./cmd/server/main.go"                           # HandlerRegistry comment + DemoResidual wiring
    "./cmd/server/preflight_demo_residual.go"        # A-8 detector + cleanup helpers
    "./internal/api/handler/auth.go"                 # interface docstring for ListKeys
    "./internal/api/handler/demo_residual.go"        # A-8 cleanup endpoint
    "./internal/api/router/router.go"                # routing comment for cleanup endpoint
    "./internal/auth/context.go"                     # const DemoAnonActorID source-of-truth (canonical)
    "./internal/auth/middleware.go"                  # NewDemoModeAuth — injects synthetic actor under Type=none
    "./internal/cli/auth_scope_down.go"              # interactive prompt filter
    "./internal/config/auth.go"                      # Phase 9 Sprint 5 — Auth-family validate-time guard comments + AdminKey wiring narrative (relocated from config.go in commit 51f9cf13; same references, different file)
    "./internal/config/config.go"                    # validate-time guard comments + DemoModeResidualStrict env var
    "./internal/domain/audit.go"                     # audit-event documentation comment
    "./internal/domain/auth/validate.go"             # const DemoAnonActorID mirror
    "./internal/mcp/tools_auth.go"                   # MCP tool description for ListKeys + Revoke
    "./internal/mcp/types.go"                        # MCP request-schema description
    "./internal/repository/auth.go"                  # ActorRoleRepository interface docstrings
    "./internal/service/auth/actor_role_service.go"  # reserved-actor mutation guard (CRIT-1 closure)
    "./internal/service/auth/authorizer.go"          # synthetic-actor authorization comment
    "./scripts/ci-guards/no-new-synthetic-admin.sh"  # this script itself
)

declare -A allow=()
for loc in "${ALLOWLIST[@]}"; do allow["$loc"]=1; done

violations=()
# rg/grep with -l prints filenames. We exclude test files, vendored
# code, docs (operator-facing prose), and CHANGELOG markdown.
while IFS= read -r file; do
    [ -z "$file" ] && continue
    if [ -z "${allow[$file]:-}" ]; then
        violations+=("$file")
    fi
done < <(grep -rln 'actor-demo-anon' \
    --include='*.go' --include='*.sh' . \
    2>/dev/null \
    | grep -v '_test\.go$' \
    | grep -v '^\./vendor/' \
    | grep -v '^\./docs/' \
    | grep -v '^\./CHANGELOG\.md$' \
    | sort -u)

if [ ${#violations[@]} -gt 0 ]; then
    printf 'A-8 GUARD FAIL: new actor-demo-anon reference outside the established allowlist:\n'
    printf '  %s\n' "${violations[@]}"
    printf '\n'
    printf 'If this reference is legitimate, add the file to ALLOWLIST in\n'
    printf '  scripts/ci-guards/no-new-synthetic-admin.sh\n'
    printf 'WITH a rationale comment describing why the synthetic admin\n'
    printf 'literal needs to appear there. Otherwise, route through the\n'
    printf 'public DemoAnonActorID constant or refactor the new code path\n'
    printf 'to NOT reference the synthetic actor at all (preferred).\n'
    exit 1
fi

echo "A-8 guard PASS — actor-demo-anon references confined to the declared ${#ALLOWLIST[@]}-entry allowlist."
