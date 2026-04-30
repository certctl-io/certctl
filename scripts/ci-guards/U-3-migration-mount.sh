#!/usr/bin/env bash
# scripts/ci-guards/U-3-migration-mount.sh
#
# U-3 closed cat-u-seed_initdb_schema_drift (GitHub #10) by
# eliminating the dual-source-of-truth between
# `migrations/*.up.sql` mounted into postgres
# `/docker-entrypoint-initdb.d/` and the same files re-applied at
# runtime by `RunMigrations`. Pre-U-3 every new migration that
# the seed depended on (000013 added `policy_rules.severity`,
# 000017 renames `retry_interval_seconds`, etc.) had to be added
# by hand to the compose mount list; missing the update crashed
# initdb on first boot, postgres flagged unhealthy, and the
# whole stack failed to start from a fresh clone. Post-U-3 the
# server is the single source of truth — `RunMigrations` +
# `RunSeed` apply everything at boot.
#
# This script grep-fails the build if any compose file under
# `deploy/` re-introduces a `migrations/.*\.sql` mount into
# `/docker-entrypoint-initdb.d`. Comments are exempt so the
# post-fix rationale block in the compose files (which
# documents WHY the mounts were removed) doesn't trip the guard.
# The demo overlay's `seed_demo.sql` is the explicit exception:
# it is tolerated only when it lives behind the
# CERTCTL_DEMO_SEED env var (post-U-3 demo path) — bare initdb
# mounts are NOT tolerated. The grep matches all compose
# mount-list shapes (`-` indented, `volumes:` indented, both),
# so any future drift surfaces here before the operator hits it
# on a fresh clone.
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# cat-u-seed_initdb_schema_drift for the closure rationale, or
# internal/repository/postgres/db.go::RunSeed for the runtime
# contract.

set -e

BAD=$(grep -rnEH \
    -e 'migrations/.*\.sql:.*docker-entrypoint-initdb' \
    -e 'seed.*\.sql:.*docker-entrypoint-initdb' \
    deploy/docker-compose.yml \
    deploy/docker-compose.test.yml \
    deploy/docker-compose.demo.yml \
    2>/dev/null \
    | grep -vE '^\s*[^:]+:[0-9]+:\s*#' \
    || true)
if [ -n "$BAD" ]; then
  echo "::error::U-3 regression: migration/seed mount into postgres initdb reappeared:"
  echo "$BAD"
  echo ""
  echo "The post-U-3 contract is: postgres comes up with an empty"
  echo "schema and the server applies migrations + seed at boot via"
  echo "internal/repository/postgres.RunMigrations + RunSeed. Demo"
  echo "data lives behind CERTCTL_DEMO_SEED=true (RunDemoSeed),"
  echo "not an initdb mount. See"
  echo "coverage-gap-audit-2026-04-24-v5/unified-audit.md"
  echo "cat-u-seed_initdb_schema_drift for the closure rationale."
  exit 1
fi
echo "U-3 migration-mount: clean."
