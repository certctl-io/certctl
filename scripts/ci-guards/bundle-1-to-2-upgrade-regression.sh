#!/usr/bin/env bash
# scripts/ci-guards/bundle-1-to-2-upgrade-regression.sh
#
# Auth Bundle 2 / Phase 6 Bundle-1 → Bundle-2 upgrade regression.
#
# Pre-commit invariant: an existing v2.1.0 (Bundle-1-shipped) deployment
# upgraded in place to Bundle 2 must:
#
#   (a) Have all Bundle-2 migrations apply cleanly. The new migrations
#       (000034 oidc_providers, 000035 sessions, 000036 users, 000037
#       oidc_pre_login + auth.session.*/auth.oidc.* permissions) MUST
#       be additive — no DROP TABLE / ALTER COLUMN that would break a
#       Bundle-1 dump.
#
#   (b) Bundle 1's CERTCTL_BOOTSTRAP_TOKEN path keeps working for fresh
#       deployments without an admin (bootstrap.go invariant; pinned
#       by Bundle 1 Phase 6 tests).
#
#   (c) Existing minted admin's API key continues to authenticate every
#       Bundle 1 endpoint (chained-auth combinator's Bearer fallback).
#
#   (d) Existing admin's role grants in actor_roles survive the upgrade
#       (additive migrations preserve all rows).
#
#   (e) Bundled certctl-agent continues to authenticate against
#       agent-demo-1 (Bundle 1 demo path; pinned by demo-compose.yml).
#
# This guard checks the static-source invariants that protect those
# properties since spinning up a v2.1.0 dump + upgrading is sandbox-
# infeasible. Concretely:
#
#   1. Migrations 000034..000037 use `CREATE TABLE IF NOT EXISTS` (not
#      `CREATE TABLE`) so re-running against a partially-migrated DB
#      doesn't error.
#
#   2. Migrations 000034..000037 are wrapped in `BEGIN; ... COMMIT;`
#      so a partial failure rolls back cleanly.
#
#   3. NO migration in the 000034..000037 range runs `DROP TABLE` or
#      `ALTER TABLE ... DROP COLUMN` against any Bundle-1 table
#      (api_keys, audit_events, certificates, certificate_versions,
#      certificate_profiles, issuers, targets, agents, jobs, owners,
#      teams, agent_groups, notifications, roles, permissions,
#      role_permissions, actor_roles, tenants, etc.). Adding a new
#      table or extending an existing one with a NULLable column or
#      DEFAULT-valued column is fine.
#
#   4. INSERT INTO permissions / role_permissions in 000037 use
#      `ON CONFLICT (id) DO NOTHING` / equivalent so a Bundle-2 deploy
#      whose v2.1.0 baseline already has the rows doesn't duplicate
#      them.
#
# When the sandbox-feasibility constraint changes, promote this to a
# real `pg_dump` round-trip from a v2.1.0 baseline + apply migrations
# + assert the row counts on the protected Bundle-1 tables match
# pre-upgrade.

set -e

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

fail=0

PHASE2_RANGE="000034 000035 000036 000037"

# Bundle-1 tables that MUST NOT be DROPPED or have columns DROPPED in
# the Bundle-2 migration range. Adding columns or new tables is fine.
PROTECTED_TABLES=(
    api_keys audit_events certificates certificate_versions
    certificate_profiles issuers targets agents jobs owners teams
    agent_groups notifications roles permissions role_permissions
    actor_roles tenants approvals intermediate_cas
    issuance_approval_requests
)

for num in $PHASE2_RANGE; do
    upfile=$(ls migrations/${num}_*.up.sql 2>/dev/null | head -1)
    if [ -z "$upfile" ]; then
        echo "::warning::no migration ${num}_*.up.sql found; skipping invariants for this number"
        continue
    fi
    # Invariant 1: CREATE TABLE IF NOT EXISTS.
    if grep -E '^CREATE TABLE [^[:space:]]' "$upfile" | grep -v 'IF NOT EXISTS' >/dev/null; then
        echo "::error::$upfile uses 'CREATE TABLE' without 'IF NOT EXISTS' — re-running against a partially-migrated DB will fail"
        fail=1
    fi
    # Invariant 2: BEGIN ... COMMIT wrapping.
    if ! grep -q '^BEGIN;' "$upfile"; then
        echo "::error::$upfile is not wrapped in 'BEGIN;'"
        fail=1
    fi
    if ! grep -q '^COMMIT;' "$upfile"; then
        echo "::error::$upfile is not wrapped in 'COMMIT;'"
        fail=1
    fi
    # Invariant 3: no DROP TABLE / ALTER ... DROP COLUMN against
    # protected Bundle-1 tables.
    for tbl in "${PROTECTED_TABLES[@]}"; do
        if grep -qE "DROP TABLE[^[:space:]]*[[:space:]]+(IF EXISTS )?$tbl([[:space:]]|;|$)" "$upfile"; then
            echo "::error::$upfile contains DROP TABLE against protected Bundle-1 table: $tbl"
            fail=1
        fi
        if grep -qE "ALTER TABLE[[:space:]]+$tbl[[:space:]].*DROP COLUMN" "$upfile"; then
            echo "::error::$upfile contains ALTER TABLE ... DROP COLUMN against protected Bundle-1 table: $tbl"
            fail=1
        fi
    done
done

# Invariant 4: 000037 INSERTs use ON CONFLICT DO NOTHING.
upfile37=$(ls migrations/000037_*.up.sql 2>/dev/null | head -1)
if [ -n "$upfile37" ]; then
    if grep -q 'INSERT INTO permissions' "$upfile37"; then
        if ! grep -q 'ON CONFLICT.*DO NOTHING' "$upfile37"; then
            echo "::error::$upfile37 INSERT INTO permissions missing ON CONFLICT DO NOTHING"
            fail=1
        fi
    fi
    if grep -q 'INSERT INTO role_permissions' "$upfile37"; then
        if ! grep -q 'ON CONFLICT.*DO NOTHING' "$upfile37"; then
            echo "::error::$upfile37 INSERT INTO role_permissions missing ON CONFLICT DO NOTHING"
            fail=1
        fi
    fi
fi

# Invariant 5: ChainAuthSessionThenBearer's Bearer fallback MUST be
# wired in cmd/server/main.go so existing v2.1.0-minted API keys
# continue to authenticate.
if ! grep -q 'session.ChainAuthSessionThenBearer' cmd/server/main.go; then
    echo "::error::cmd/server/main.go does not wire the chained-auth combinator (Bundle-1 Bearer keys would stop authenticating)"
    fail=1
fi
if ! grep -q 'auth.NewAuthWithKeyStore(authKeyStore)' cmd/server/main.go; then
    echo "::error::cmd/server/main.go does not construct the Bundle-1 Bearer middleware"
    fail=1
fi

# Invariant 6: bootstrap path is preserved — v2.1.0 path still works
# for fresh deployments without an admin.
if ! grep -q 'bootstrapHandler' cmd/server/main.go; then
    echo "::error::cmd/server/main.go does not register the bootstrap handler — fresh-deployment bootstrap broken"
    fail=1
fi

if [ $fail -eq 0 ]; then
    echo "OK: Bundle-1 → Bundle-2 upgrade regression invariants hold."
fi
exit $fail
