#!/usr/bin/env bash
# scripts/ci-guards/multi-tenant-query-coverage.sh
#
# Auth Bundle 2 / Phase 13 — multi-tenant query guard (forward-compat
# protection, ratchet-style).
#
# Goal:
#   Bundle 2 ships single-tenant only (the seeded `t-default` tenant).
#   This guard is forward-compat protection so a future Bundle 3 /
#   managed-service tenant activation can flip the multi-tenant
#   switch without finding silent tenant-data-leak bugs in shipped
#   queries.
#
# Behavior:
#   Counts every SELECT / UPDATE / DELETE FROM / INSERT INTO statement
#   in internal/repository/postgres/*.go (excluding *_test.go) that
#   targets a tenant-aware table AND lacks a `tenant_id` clause within
#   the surrounding 7-line window. Compares the count against the
#   baseline pinned in this script.
#
#   If count > baseline → FAIL (a new query was added that doesn't
#   carry tenant_id; either add the clause or — if legitimately
#   tenant-spanning — document it in the source comments AND lift the
#   baseline). The guard refuses to silently approve new violations.
#
#   If count < baseline → FAIL (improvements were made; lower the
#   baseline in this script). The guard refuses to silently let the
#   ratchet slip backward.
#
#   If count == baseline → PASS.
#
# Tenant-aware tables (10):
#   Bundle 1 (RBAC primitive, migration 000029):
#     roles, role_permissions, actor_roles
#     (permissions is global — canonical permission catalogue.)
#   Bundle 2 (OIDC + sessions + users + break-glass, migrations 34-38):
#     oidc_providers, group_role_mappings, sessions,
#     session_signing_keys, oidc_pre_login_sessions, users,
#     breakglass_credentials
#
# Why ratchet not zero:
#   The current single-tenant codebase has many Get-by-PK queries
#   (e.g. `SELECT * FROM users WHERE id = $1`) where the primary key
#   is globally unique and the lack of tenant_id is not a leak. Going
#   to zero would require either (a) adding `AND tenant_id = $N` to
#   every PK query — defense-in-depth but mechanical churn — or (b)
#   maintaining a long exception list. The ratchet captures the
#   current state as a baseline; multi-tenant activation work then has
#   to either lower the baseline (good — defense-in-depth applied) or
#   keep it constant (acceptable — single-tenant invariant intact).
#   New code that ADDS to the count without operator review is what
#   we want to catch.
#
# Run:
#   bash scripts/ci-guards/multi-tenant-query-coverage.sh

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET_DIR="${REPO_ROOT}/internal/repository/postgres"

# Baseline: number of tenant-aware queries that legitimately lack
# tenant_id today (Bundle 2 / Phase 13 close, 2026-05-10). Multi-
# tenant activation work in a future bundle should drive this number
# down; this guard makes any drift from the baseline visible at
# `make verify` time.
#
# To rebase: re-run the guard, set BASELINE_COUNT to the new value,
# include the rebase commit's SHA in the "last rebase" comment.
BASELINE_COUNT=32
# Last rebase: 2026-05-10 (Bundle 2 Phase 13 initial baseline).

if [ ! -d "$TARGET_DIR" ]; then
    echo "::error::TARGET_DIR not found: $TARGET_DIR"
    exit 1
fi

# Tenant-aware tables. Add to this list when a new tenant-scoped
# table lands. The `permissions` table is global (canonical permission
# catalogue) — NOT in this list.
TENANT_AWARE_TABLES=(
    "roles"
    "role_permissions"
    "actor_roles"
    "oidc_providers"
    "group_role_mappings"
    "sessions"
    "session_signing_keys"
    "oidc_pre_login_sessions"
    "users"
    "breakglass_credentials"
)

# Build a regex of tenant-aware table names for grep.
TABLE_REGEX="$(printf '|%s' "${TENANT_AWARE_TABLES[@]}" | sed 's/^|//')"

# Find every line in the repository directory that mentions a
# tenant-aware table in a SQL keyword context.
mapfile -t hits < <(
    grep -nE "(FROM|UPDATE|DELETE FROM|INTO)\s+(${TABLE_REGEX})" \
        "$TARGET_DIR"/*.go 2>/dev/null \
        | grep -v "_test.go:" \
        || true
)

violations=0
violation_lines=""

for hit in "${hits[@]}"; do
    file="${hit%%:*}"
    rest="${hit#*:}"
    lineno="${rest%%:*}"
    matched_line="${rest#*:}"

    # Identify which table matched.
    table=""
    for t in "${TENANT_AWARE_TABLES[@]}"; do
        if echo "$matched_line" | grep -qE "(FROM|UPDATE|DELETE FROM|INTO)\s+${t}\b"; then
            table="$t"
            break
        fi
    done
    if [ -z "$table" ]; then
        continue
    fi

    # Read a 7-line window starting at lineno.
    end_line=$((lineno + 6))
    window=$(sed -n "${lineno},${end_line}p" "$file")

    if echo "$window" | grep -q "tenant_id"; then
        continue
    fi

    violations=$((violations + 1))
    rel_file="${file#$REPO_ROOT/}"
    violation_lines="${violation_lines}    ${rel_file}:${lineno} → ${table}\n"
done

if [ "$violations" -gt "$BASELINE_COUNT" ]; then
    echo "::error::multi-tenant-query-coverage: REGRESSION — count $violations > baseline $BASELINE_COUNT"
    echo ""
    echo "A new tenant-aware query was added without tenant_id in the"
    echo "surrounding 7-line window. Either:"
    echo "  (a) Add 'AND tenant_id = \$N' to the WHERE clause."
    echo "  (b) If the query is legitimately tenant-spanning (e.g. a"
    echo "      GC sweep scoped by absolute_expires_at, or a Get-by-id"
    echo "      where id is globally unique), document the rationale"
    echo "      in a comment immediately above the query AND lift"
    echo "      BASELINE_COUNT in this script."
    echo ""
    echo "Current violations:"
    printf "%b" "$violation_lines"
    exit 1
fi

if [ "$violations" -lt "$BASELINE_COUNT" ]; then
    echo "::error::multi-tenant-query-coverage: ratchet drift — count $violations < baseline $BASELINE_COUNT"
    echo ""
    echo "The number of tenant-aware queries lacking tenant_id has"
    echo "DECREASED, which is good (defense-in-depth applied). Lower"
    echo "BASELINE_COUNT in this script from $BASELINE_COUNT to $violations."
    echo ""
    echo "The ratchet must move forward, never backward — silently"
    echo "letting the baseline drift up later would erase the win."
    exit 1
fi

echo "multi-tenant-query-coverage: PASS"
echo ""
echo "Tenant-aware tables checked: ${#TENANT_AWARE_TABLES[@]}"
echo "Tenant_id-less queries:       $violations (baseline: $BASELINE_COUNT)"
echo ""
echo "These are queries scoped by globally-unique IDs or GC sweeps;"
echo "single-tenant deployments are unaffected. Multi-tenant activation"
echo "work in a future bundle should drive the count down. Lower"
echo "BASELINE_COUNT in this script when that happens."
