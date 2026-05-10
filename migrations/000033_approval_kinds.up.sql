-- Bundle 1 Phase 9 — approval kinds (Decision 9, option a).
--
-- Closes the flip-flop loophole: an admin can NO LONGER flip a
-- profile's RequiresApproval=false → mutate → flip back. Profile
-- edits to a profile that has (or would have) RequiresApproval=true
-- now route through ApprovalService just like cert issuance.
--
-- Schema changes:
--
--   1. New `approval_kind` column (cert_issuance | profile_edit).
--      Default cert_issuance preserves back-compat for every existing
--      row created by Phase 7 of the 2026-05-03 deep-research bundle.
--
--   2. `certificate_id` and `job_id` become nullable so profile-edit
--      approvals (no associated cert / job) can share the table.
--      The CHECK constraint below pins per-kind nullability so
--      cert_issuance rows must have both, profile_edit rows must
--      have neither and instead carry payload.
--
--   3. New `payload` JSONB column captures the pending profile diff
--      for profile_edit approvals. The approver's POST
--      /v1/approvals/{id}/approve triggers the diff to be applied
--      against the live profile row.
--
-- Idempotent throughout via IF NOT EXISTS / DO blocks.

BEGIN;

ALTER TABLE issuance_approval_requests
    ADD COLUMN IF NOT EXISTS approval_kind TEXT NOT NULL DEFAULT 'cert_issuance';

ALTER TABLE issuance_approval_requests
    ADD COLUMN IF NOT EXISTS payload JSONB;

-- Drop NOT NULL on cert_id + job_id so profile_edit rows can omit
-- both. The CHECK below restores per-kind invariants. Idempotent
-- via DO block (Postgres doesn't expose ALTER COLUMN ... IF NOT
-- NULL natively).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'issuance_approval_requests'
                 AND column_name = 'certificate_id'
                 AND is_nullable = 'NO') THEN
        ALTER TABLE issuance_approval_requests
            ALTER COLUMN certificate_id DROP NOT NULL;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'issuance_approval_requests'
                 AND column_name = 'job_id'
                 AND is_nullable = 'NO') THEN
        ALTER TABLE issuance_approval_requests
            ALTER COLUMN job_id DROP NOT NULL;
    END IF;
END$$;

-- Per-kind invariant. cert_issuance rows must have cert_id + job_id.
-- profile_edit rows must have payload (the pending diff).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'approval_kind_consistency') THEN
        ALTER TABLE issuance_approval_requests
            ADD CONSTRAINT approval_kind_consistency CHECK (
                (approval_kind = 'cert_issuance'
                 AND certificate_id IS NOT NULL AND job_id IS NOT NULL)
                OR (approval_kind = 'profile_edit'
                    AND payload IS NOT NULL)
            );
    END IF;
END$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'approval_kind_check') THEN
        ALTER TABLE issuance_approval_requests
            ADD CONSTRAINT approval_kind_check CHECK (
                approval_kind IN ('cert_issuance', 'profile_edit')
            );
    END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_approval_kind
    ON issuance_approval_requests(approval_kind);

COMMIT;
