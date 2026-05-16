-- Sprint 6 COMP-001-HASH closure (2026-05-16). audit_events grows a
-- per-row hash chain so a compliance superuser (or anyone who escapes
-- to the role that bypasses the migration 000018 WORM trigger — backup
-- restore, retention purges, breach-recovery operators) can no longer
-- rewrite history undetectably. The WORM trigger is tamper-prevention;
-- the hash chain adds tamper-evidence (HIPAA §164.312(b) /
-- FedRAMP AU-9 / NIST 800-53 AU-10).
--
-- Wire shape:
--
--   1. audit_chain_head: single-row sentinel table holding the
--      most-recent row_hash. The INSERT trigger SELECTs it FOR UPDATE
--      to serialize chain mutation under concurrent inserts (without
--      the row-lock, two parallel INSERTs could read the same prev_hash
--      and produce a forked chain). Single-row design + FOR UPDATE makes
--      the lock granularity 1 row; the trigger releases it on commit.
--   2. audit_events.prev_hash / row_hash: NEW columns.
--   3. audit_events_compute_hash_chain(): BEFORE-INSERT trigger function
--      that reads + advances the sentinel, computes the canonical
--      sha256, and writes both columns on NEW.
--   4. audit_events_verify_chain(): on-demand verifier that walks the
--      chain in (timestamp ASC, id ASC) order and returns the first
--      tamper position. The scheduler's auditChainVerifyLoop calls this
--      every CERTCTL_AUDIT_CHAIN_VERIFY_INTERVAL (default 6h) and
--      emits the certctl_audit_chain_break_detected counter on a
--      non-NULL return. operator-facing how-to:
--      docs/operator/audit-chain.md (added in the next commit).
--
-- WORM-trigger interaction: migration 000018 installs
--   audit_events_worm_trigger BEFORE UPDATE OR DELETE
-- so backfill UPDATEs on the existing rows would be rejected. We
-- DISABLE the trigger inside this migration's transaction, backfill,
-- ENABLE the trigger before COMMIT. The DISABLE is scoped to this
-- session only (per Postgres docs on ALTER TABLE ... DISABLE TRIGGER
-- via pg_trigger.tgenabled). Migrations run under their own session,
-- so concurrent inserts from a running server (extremely unlikely —
-- the migrate-then-start contract is the deploy norm) would observe
-- the trigger temporarily disabled. Mitigation: migrations run before
-- the server boots in CERTCTL_MIGRATIONS_VIA_HOOK=true mode; the
-- in-process migrate.Up at boot also runs before HTTP handlers are
-- registered. So the "concurrent insert during backfill" window is
-- effectively zero.
--
-- Determinism: timestamp::text in Postgres serializes with the session
-- timezone, which would make the hash session-dependent. We coerce to
-- UTC + ISO-8601-microseconds via `to_char(... AT TIME ZONE 'UTC', ...)`
-- so the same row produces the same hash everywhere. Other fields are
-- string-typed or JSONB (JSONB's ::text canonicalizes key order +
-- whitespace, so it's stable across servers).
--
-- Idempotent: ADD COLUMN IF NOT EXISTS, CREATE TABLE IF NOT EXISTS,
-- DROP TRIGGER IF EXISTS + CREATE TRIGGER, CREATE OR REPLACE FUNCTION.
-- The backfill DO block guards with WHERE row_hash IS NULL.

BEGIN;

-- pgcrypto for digest(). Postgres ships it as a contrib extension;
-- the postgres:16-alpine image used in deploy/docker-compose*.yml
-- has it available.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Single-row sentinel — id = 1 always. row_hash is the most-recent
-- hash; '' means "no rows yet, genesis".
CREATE TABLE IF NOT EXISTS audit_chain_head (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    row_hash   TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO audit_chain_head (id, row_hash, updated_at)
    VALUES (1, '', NOW())
    ON CONFLICT (id) DO NOTHING;

-- Schema growth on audit_events. Both columns nullable initially so
-- the backfill loop below can populate them; row_hash becomes NOT NULL
-- after backfill, prev_hash stays nullable (genesis row has NULL).
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS prev_hash TEXT,
    ADD COLUMN IF NOT EXISTS row_hash  TEXT;

-- Helper: canonical serialization of an audit_events row for hashing.
-- Centralized in a function so the trigger and the verifier compute
-- byte-identical inputs. UTC + microsecond-precision ISO-8601 keeps
-- the output session-timezone-independent.
CREATE OR REPLACE FUNCTION audit_events_canonical_payload(
    p_prev_hash     TEXT,
    p_id            TEXT,
    p_actor         TEXT,
    p_actor_type    TEXT,
    p_action        TEXT,
    p_resource_type TEXT,
    p_resource_id   TEXT,
    p_details       JSONB,
    p_timestamp     TIMESTAMPTZ,
    p_event_category TEXT
) RETURNS TEXT AS $$
BEGIN
    RETURN COALESCE(p_prev_hash, '')      || '|' ||
           p_id                            || '|' ||
           p_actor                         || '|' ||
           p_actor_type                    || '|' ||
           p_action                        || '|' ||
           p_resource_type                 || '|' ||
           p_resource_id                   || '|' ||
           COALESCE(p_details::text, '')   || '|' ||
           to_char(p_timestamp AT TIME ZONE 'UTC',
                   'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || '|' ||
           COALESCE(p_event_category, '');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- BEFORE-INSERT trigger function: read sentinel FOR UPDATE, compute
-- hash, write both columns + advance the sentinel.
CREATE OR REPLACE FUNCTION audit_events_compute_hash_chain()
RETURNS TRIGGER AS $$
DECLARE
    head_hash TEXT;
BEGIN
    SELECT row_hash INTO head_hash
        FROM audit_chain_head
        WHERE id = 1
        FOR UPDATE;

    IF head_hash IS NULL OR head_hash = '' THEN
        NEW.prev_hash := NULL;
    ELSE
        NEW.prev_hash := head_hash;
    END IF;

    NEW.row_hash := encode(
        digest(
            audit_events_canonical_payload(
                NEW.prev_hash,
                NEW.id,
                NEW.actor,
                NEW.actor_type,
                NEW.action,
                NEW.resource_type,
                NEW.resource_id,
                NEW.details,
                NEW.timestamp,
                NEW.event_category
            ),
            'sha256'
        ),
        'hex'
    );

    UPDATE audit_chain_head
        SET row_hash = NEW.row_hash, updated_at = NOW()
        WHERE id = 1;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_hash_chain_trigger ON audit_events;
CREATE TRIGGER audit_events_hash_chain_trigger
    BEFORE INSERT ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION audit_events_compute_hash_chain();

-- Backfill existing rows. The migration 000018 WORM trigger blocks
-- UPDATE; disable it for the duration of the backfill transaction.
-- ALTER TABLE ... DISABLE TRIGGER takes ACCESS EXCLUSIVE; the
-- migration session holds it until COMMIT.
ALTER TABLE audit_events DISABLE TRIGGER audit_events_worm_trigger;

DO $$
DECLARE
    r          RECORD;
    cur_hash   TEXT := '';
    prev       TEXT;
    new_hash   TEXT;
BEGIN
    FOR r IN
        SELECT id, actor, actor_type, action, resource_type, resource_id,
               details, timestamp, event_category
        FROM audit_events
        WHERE row_hash IS NULL
        ORDER BY timestamp ASC, id ASC
    LOOP
        IF cur_hash = '' THEN
            prev := NULL;
        ELSE
            prev := cur_hash;
        END IF;

        new_hash := encode(
            digest(
                audit_events_canonical_payload(
                    prev, r.id, r.actor, r.actor_type, r.action,
                    r.resource_type, r.resource_id, r.details,
                    r.timestamp, r.event_category
                ),
                'sha256'
            ),
            'hex'
        );

        UPDATE audit_events
            SET prev_hash = prev, row_hash = new_hash
            WHERE id = r.id;

        cur_hash := new_hash;
    END LOOP;

    -- Sync the sentinel to the post-backfill tail so the next live
    -- INSERT chains onto the existing tail (not onto '' / genesis).
    UPDATE audit_chain_head SET row_hash = cur_hash, updated_at = NOW()
        WHERE id = 1;
END$$;

ALTER TABLE audit_events ENABLE TRIGGER audit_events_worm_trigger;

-- Now that every row has a row_hash, enforce NOT NULL. prev_hash stays
-- nullable so the genesis row remains representable.
ALTER TABLE audit_events
    ALTER COLUMN row_hash SET NOT NULL;

-- On-demand verifier. Returns:
--   first_break_id  TEXT  — NULL if chain verifies end-to-end.
--   first_break_pos INT   — 0-indexed row position of the first break.
--   row_count       INT   — total rows walked.
-- The scheduler's auditChainVerifyLoop calls this every tick.
CREATE OR REPLACE FUNCTION audit_events_verify_chain(
    OUT first_break_id  TEXT,
    OUT first_break_pos INT,
    OUT row_count       INT
) AS $$
DECLARE
    r           RECORD;
    expected    TEXT := '';
    computed    TEXT;
    pos         INT := 0;
BEGIN
    first_break_id  := NULL;
    first_break_pos := -1;
    row_count       := 0;

    FOR r IN
        SELECT id, actor, actor_type, action, resource_type, resource_id,
               details, timestamp, event_category, prev_hash, row_hash
        FROM audit_events
        ORDER BY timestamp ASC, id ASC
    LOOP
        -- prev_hash on this row must equal the running expected hash
        -- (NULL on the very first row, otherwise the previous row's
        -- row_hash). Mismatch = chain break.
        IF (pos = 0 AND r.prev_hash IS NOT NULL)
           OR (pos > 0 AND r.prev_hash IS DISTINCT FROM expected) THEN
            first_break_id  := r.id;
            first_break_pos := pos;
            row_count       := pos + 1;
            RETURN;
        END IF;

        computed := encode(
            digest(
                audit_events_canonical_payload(
                    r.prev_hash, r.id, r.actor, r.actor_type, r.action,
                    r.resource_type, r.resource_id, r.details,
                    r.timestamp, r.event_category
                ),
                'sha256'
            ),
            'hex'
        );

        IF computed IS DISTINCT FROM r.row_hash THEN
            first_break_id  := r.id;
            first_break_pos := pos;
            row_count       := pos + 1;
            RETURN;
        END IF;

        expected := r.row_hash;
        pos := pos + 1;
    END LOOP;

    row_count := pos;
END;
$$ LANGUAGE plpgsql STABLE;

COMMIT;
