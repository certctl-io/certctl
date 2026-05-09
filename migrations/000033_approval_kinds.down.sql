-- Bundle 1 Phase 9 down: drop the kind/payload columns + constraints.
-- Destructive — any pending profile-edit approval rows are lost.
BEGIN;
DROP INDEX IF EXISTS idx_approval_kind;
ALTER TABLE issuance_approval_requests DROP CONSTRAINT IF EXISTS approval_kind_consistency;
ALTER TABLE issuance_approval_requests DROP CONSTRAINT IF EXISTS approval_kind_check;
ALTER TABLE issuance_approval_requests DROP COLUMN IF EXISTS payload;
ALTER TABLE issuance_approval_requests DROP COLUMN IF EXISTS approval_kind;
-- Down-migration intentionally does NOT restore NOT NULL on cert_id
-- and job_id even though the up-migration relaxed them — old data
-- might already include profile_edit rows that violate it.
COMMIT;
