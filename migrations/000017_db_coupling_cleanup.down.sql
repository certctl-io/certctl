-- Migration 000017 (down): reverse the U-3 bundle.
--
-- Operators almost certainly never need this — each block in the up
-- migration was a strict improvement (column-name truth, dead-schema
-- removal, missing-column add). The down migration exists for
-- documentation and disaster-recovery completeness only.
--
-- Idempotent: each block uses the standard IF EXISTS / IF NOT EXISTS
-- guards plus a DO $$ guard on the rename to handle re-application.
-- Reverses the up migration's blocks in reverse order.

-- (3) Re-add the orphan health_check columns at their original defaults.
--
-- Note: re-adding does NOT restore the auto-health-check feature —
-- that code was never written. The column values revert to the
-- DEFAULT FALSE / 300 baseline that operators saw pre-U-3.
ALTER TABLE network_scan_targets
    ADD COLUMN IF NOT EXISTS health_check_enabled BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS health_check_interval_seconds INTEGER DEFAULT 300;

-- (2) Drop the notification_events.created_at column.
--
-- This re-introduces the cat-o-notification_created_at_dead_field bug
-- (Go field with no DB column → API serializes 0001-01-01). Only roll
-- back if you've also rolled back the Go-side INSERT path that sets
-- created_at, otherwise INSERTs will fail with "column created_at does
-- not exist".
ALTER TABLE notification_events
    DROP COLUMN IF EXISTS created_at;

-- (1) Rename the renewal_policies column back to the misleading name.
--
-- Re-introduces cat-o-retry_interval_unit_mismatch. Operators running
-- raw SQL revert to the 60x confusion. No data conversion (values are
-- still seconds; the column label lies again).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'renewal_policies'
          AND column_name = 'retry_interval_seconds'
    ) THEN
        ALTER TABLE renewal_policies
            RENAME COLUMN retry_interval_seconds TO retry_interval_minutes;
    END IF;
END $$;
