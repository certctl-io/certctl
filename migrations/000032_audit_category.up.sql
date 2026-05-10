-- Bundle 1 Phase 8 — categorize audit events.
--
-- Why: post-Phase-1 the auditor role holds only audit.read +
-- audit.export. Without a category column the auditor surface
-- co-mingles cert-lifecycle events with auth-config mutations and
-- config edits, which makes a "show me only the auth changes from
-- last week" query impossible. Phase 8 adds the column + enum CHECK
-- constraint + index so auditors can filter to the slice they care
-- about.
--
-- Storage rules:
--
--   - cert_lifecycle (default): cert.issue, cert.renew, cert.revoke,
--     cert.bulk_revoke, deployment.*, agent.heartbeat, etc.
--     Existing rows backfill here.
--   - auth: every auth.role.* / auth.key.* / auth.bootstrap.* event,
--     plus the day-0 bootstrap.consume action from Phase 6.
--   - config: issuer config edits, target config edits, settings
--     mutations. Distinct from cert_lifecycle so a regulator can
--     review "who changed the issuer wiring" separately from "who
--     issued certs".
--
-- WORM trigger continues to enforce append-only at the DB layer
-- (migration 000018). The ALTER TABLE itself is DDL, not DML, so
-- it's not blocked by the trigger.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS, ADD CONSTRAINT IF NOT EXISTS
-- (Postgres 15+; uses DO blocks for older versions). The migration
-- runner re-applies safely if the migration was partially completed.

BEGIN;

ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS event_category TEXT NOT NULL DEFAULT 'cert_lifecycle';

-- CHECK constraint (idempotent via DO block; ADD CONSTRAINT IF NOT
-- EXISTS is Postgres 15+ only).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'audit_events_event_category_check'
    ) THEN
        ALTER TABLE audit_events
            ADD CONSTRAINT audit_events_event_category_check
            CHECK (event_category IN ('cert_lifecycle', 'auth', 'config'));
    END IF;
END$$;

-- Index for the auditor-filter query path. Single-column btree
-- because event_category is low-cardinality (3 values today); the
-- planner can still bitmap-scan with a small index.
CREATE INDEX IF NOT EXISTS idx_audit_events_event_category
    ON audit_events(event_category);

-- Composite index for the most common auditor query: "auth events
-- from last 7 days, newest first". The (category, timestamp DESC)
-- shape lets the planner serve LIMIT-20 dashboards without sorting.
CREATE INDEX IF NOT EXISTS idx_audit_events_category_timestamp
    ON audit_events(event_category, timestamp DESC);

COMMIT;
