-- Bundle 1 Phase 8 down: drop the event_category column + indexes.
-- Destructive — auditor-filter queries stop working after this runs.
BEGIN;
DROP INDEX IF EXISTS idx_audit_events_category_timestamp;
DROP INDEX IF EXISTS idx_audit_events_event_category;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_category_check;
ALTER TABLE audit_events DROP COLUMN IF EXISTS event_category;
COMMIT;
