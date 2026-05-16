#!/usr/bin/env bash
# Copyright 2026 certctl LLC. All rights reserved.
# SPDX-License-Identifier: BUSL-1.1
#
# Acquisition-audit DEPL-005 + DATA-012 closure (Sprint 4 ACQ,
# 2026-05-16). Backup/restore smoke harness — orchestrates a real
# pg_dump -Fc → DROP DATABASE → CREATE DATABASE → pg_restore loop
# around the audit_events hash chain and asserts the chain head
# round-trips byte-for-byte.
#
# This script is the body of the `.github/workflows/backup-restore.yml`
# weekly job AND the same thing an operator can run locally against a
# running Postgres to gain confidence before a real restore.
#
# Prereqs
# =======
# - psql / pg_dump / pg_restore installed and on PATH (ubuntu-latest
#   ships postgresql-client by default; on macOS use Homebrew's
#   libpq).
# - A reachable Postgres at $PGHOST:$PGPORT, plus the certctl user +
#   database created. In CI we point this at the GHA service container
#   (postgres:16-alpine, pinned to the same digest as
#   deploy/docker-compose.yml). Locally, point it wherever — the
#   script DROPs the database it connects to, so DO NOT POINT THIS
#   AT A DATABASE YOU CARE ABOUT.
# - Go 1.25+ on PATH so the smoke program can be built. (CI's
#   setup-go step handles this.)
# - jq is NOT required — JSON snapshots are compared via python3.
#
# Behavior contract
# =================
# - On success: exit 0, prints "PASS" + a summary line.
# - On any assertion failure: prints `::error::<reason>`, exits 1.
#   (The ::error:: prefix is the GitHub Actions log-annotation shape;
#    it surfaces as a red banner in the Actions run UI.)
#
# Non-goals
# =========
# - Does not exercise PITR / WAL archiving. The Sprint 4 scope is the
#   pg_dump/pg_restore path only; managed-DB PITR is the operator's
#   responsibility per docs/operator/runbooks/postgres-backup.md.
# - Does not regenerate the audit chain after restore. A "restore
#   that rewrote history" would mask exactly the bug under test.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# ----------------------------------------------------------------------
# Configuration — every knob is env-overridable so the same script
# runs unchanged in CI (where the GHA service container exposes
# 127.0.0.1:5432) and on an operator's laptop (where they may have
# Postgres on a UNIX socket or a different port).
# ----------------------------------------------------------------------
: "${PGHOST:=127.0.0.1}"
: "${PGPORT:=5432}"
: "${PGUSER:=certctl}"
: "${PGPASSWORD:=certctl}"
: "${PGDATABASE:=certctl}"
: "${SMOKE_ROWS:=24}"
: "${MIGRATIONS_PATH:=${REPO_ROOT}/migrations}"

# psql/pg_dump/pg_restore all read PG* env vars. Export so we don't
# have to spell them out on every command line.
export PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE

DB_URL="postgres://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${PGDATABASE}?sslmode=disable"

fail() {
	# GitHub Actions log annotation. The `::error::` prefix is what
	# the Actions UI uses to highlight a line in the run log.
	echo "::error::backup-restore-smoke: $*" >&2
	exit 1
}

step() { printf '\n=== %s ===\n' "$*"; }

# ----------------------------------------------------------------------
# Sanity preflight
# ----------------------------------------------------------------------
step "preflight"
command -v psql       >/dev/null || fail "psql not on PATH (install postgresql-client)"
command -v pg_dump    >/dev/null || fail "pg_dump not on PATH"
command -v pg_restore >/dev/null || fail "pg_restore not on PATH"
command -v go         >/dev/null || fail "go not on PATH (need Go to build the smoke program)"
command -v python3    >/dev/null || fail "python3 not on PATH (used for JSON diff)"
test -d "${MIGRATIONS_PATH}" || fail "migrations dir not found: ${MIGRATIONS_PATH}"

# Wait for Postgres readiness up to 60s. pg_isready returns 0 when
# the server is accepting connections, so the loop is the canonical
# CI-friendly "wait for the service container" pattern.
step "waiting for postgres at ${PGHOST}:${PGPORT}"
for _ in $(seq 1 60); do
	if pg_isready -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" -d "${PGDATABASE}" -q; then
		break
	fi
	sleep 1
done
pg_isready -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" -d "${PGDATABASE}" -q \
	|| fail "postgres not ready after 60s at ${PGHOST}:${PGPORT}"

# Wipe any prior state in the target DB. A previous failed run could
# have left rows behind; the smoke contract is "starts from clean."
step "wiping ${PGDATABASE} schema (DROP SCHEMA public CASCADE; CREATE SCHEMA public)"
psql -v ON_ERROR_STOP=1 -c 'DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO PUBLIC;'

# ----------------------------------------------------------------------
# Build the smoke program. We use `go run` to avoid leaving a binary
# behind; the migrations + workload are quick so the per-invocation
# compile cost is negligible.
# ----------------------------------------------------------------------
step "building smoke program"
cd "${REPO_ROOT}"
go build -o "${WORKDIR}/smoke" ./deploy/test/backupsmoke

# ----------------------------------------------------------------------
# Phase 1 — workload: migrate, insert rows, snapshot chain head.
# ----------------------------------------------------------------------
step "phase 1 — workload (${SMOKE_ROWS} audit_events rows)"
"${WORKDIR}/smoke" \
	--mode=workload \
	--db-url="${DB_URL}" \
	--migrations-path="${MIGRATIONS_PATH}" \
	--rows="${SMOKE_ROWS}" \
	| tee "${WORKDIR}/pre.json"

# ----------------------------------------------------------------------
# Phase 2 — backup. Canonical pg_dump shape per
# deploy/helm/certctl/templates/backup-cronjob.yaml: --format=custom,
# --no-owner, --no-acl. --no-owner / --no-acl keep the dump portable
# across Postgres installations with different role layouts (the
# audit-trail hash chain is data, not ACL state).
# ----------------------------------------------------------------------
step "phase 2 — pg_dump -Fc"
pg_dump --format=custom --no-owner --no-acl --dbname="${PGDATABASE}" --file="${WORKDIR}/backup.dump"
test -s "${WORKDIR}/backup.dump" || fail "pg_dump produced an empty file"

# ----------------------------------------------------------------------
# Phase 3 — wipe. The fresh-schema approach is the closest analogue
# to "operator nuked the wrong volume." DROP DATABASE would require
# connecting to a different DB and reconnect dance; DROP SCHEMA
# achieves the same "no rows, no schema, no functions" end state
# inside the existing connection and is restore-compatible (pg_dump
# -Fc bundles the schema in the dump, so pg_restore recreates it).
# ----------------------------------------------------------------------
step "phase 3 — drop schema (simulating data-loss event)"
psql -v ON_ERROR_STOP=1 -c 'DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO PUBLIC;'

# Sanity: confirm audit_events is actually gone before restore. A
# regression here (e.g. DROP SCHEMA silently no-op) would let the
# verifier "succeed" by reading the original rows, making the test
# false-pass.
PRE_RESTORE_TABLES=$(psql -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'")
if [ "${PRE_RESTORE_TABLES}" -ne 0 ]; then
	fail "post-DROP SCHEMA, expected 0 public tables; saw ${PRE_RESTORE_TABLES}"
fi

# ----------------------------------------------------------------------
# Phase 4 — restore.
# ----------------------------------------------------------------------
step "phase 4 — pg_restore"
pg_restore --dbname="${PGDATABASE}" --no-owner --no-acl --exit-on-error "${WORKDIR}/backup.dump"

# ----------------------------------------------------------------------
# Phase 5 — verify: re-snapshot, run audit_events_verify_chain().
# ----------------------------------------------------------------------
step "phase 5 — verify (audit_events_verify_chain() + snapshot)"
"${WORKDIR}/smoke" \
	--mode=verify \
	--db-url="${DB_URL}" \
	| tee "${WORKDIR}/post.json"

# ----------------------------------------------------------------------
# Phase 6 — assert.
#
#   pre.row_count       == post.row_count
#   pre.chain_head_hash == post.chain_head_hash   (BYTE-EXACT)
#   post.first_break_id == ""                     (verifier clean)
#   post.verifier_walked == pre.row_count         (every row walked)
#
# Use python3 rather than jq so the script runs unchanged on macOS
# without an extra Homebrew install.
# ----------------------------------------------------------------------
step "phase 6 — assertions"
python3 - <<'PY' "${WORKDIR}/pre.json" "${WORKDIR}/post.json"
import json, sys

pre  = json.load(open(sys.argv[1]))
post = json.load(open(sys.argv[2]))

def bail(msg):
    print(f"::error::backup-restore-smoke: {msg}", file=sys.stderr)
    sys.exit(1)

if pre["row_count"] != post["row_count"]:
    bail(f"row_count mismatch: pre={pre['row_count']} post={post['row_count']}")

if pre["chain_head_hash"] != post["chain_head_hash"]:
    bail(
        "chain_head_hash mismatch — pg_dump/pg_restore did NOT round-trip the "
        "audit_events hash chain byte-for-byte. "
        f"pre={pre['chain_head_hash']} post={post['chain_head_hash']}"
    )

if post.get("first_break_id", "") != "":
    bail(
        "audit_events_verify_chain() reports a break post-restore at id="
        f"{post['first_break_id']} pos={post.get('first_break_pos', '?')} — "
        "the chain is no longer self-consistent after the restore."
    )

if post.get("verifier_walked", -1) != pre["row_count"]:
    bail(
        f"verifier_walked={post.get('verifier_walked')} != pre.row_count="
        f"{pre['row_count']} — verifier short-circuited or read stale rows."
    )

print(
    f"PASS  rows={pre['row_count']}  "
    f"chain_head={pre['chain_head_hash'][:16]}…  "
    f"verifier=clean"
)
PY
