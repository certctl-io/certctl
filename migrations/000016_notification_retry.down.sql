-- Rollback for migration 000016 (I-005 notification retry + DLQ).
-- Drops the retry-sweep partial index first, then the three columns added to
-- notification_events. No status-rewriting: rows that were promoted to 'dead'
-- during retry exhaustion remain in that status (rollback is opt-in, and
-- clobbering terminal states on rollback would erase the audit trail of which
-- alerts were never delivered).

DROP INDEX IF EXISTS idx_notification_events_retry_sweep;

ALTER TABLE notification_events DROP COLUMN IF EXISTS last_error;
ALTER TABLE notification_events DROP COLUMN IF EXISTS next_retry_at;
ALTER TABLE notification_events DROP COLUMN IF EXISTS retry_count;
