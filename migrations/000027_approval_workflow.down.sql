-- 000027_approval_workflow.down.sql — reverse of the up migration.
-- Drops the issuance_approval_requests table and the
-- requires_approval column from certificate_profiles. Idempotent:
-- IF EXISTS on every drop.

DROP INDEX IF EXISTS idx_approval_pending_age;
DROP INDEX IF EXISTS idx_approval_certificate;
DROP INDEX IF EXISTS idx_approval_state;
DROP INDEX IF EXISTS idx_approval_pending_per_job;

DROP TABLE IF EXISTS issuance_approval_requests;

ALTER TABLE certificate_profiles
    DROP COLUMN IF EXISTS requires_approval;
