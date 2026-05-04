-- 000027_approval_workflow.up.sql
-- Rank 7 of the 2026-05-03 deep-research deliverable
-- (cowork/deep-research-results-2026-05-03.md Part 5). Two-person
-- integrity / four-eyes principle for compliance-tier certificate
-- issuance. CertificateProfile.RequiresApproval gates the renewal-
-- loop entry; issuance_approval_requests captures the per-job
-- decision with full audit trail.
--
-- All operations use IF NOT EXISTS / IF EXISTS so the migration is
-- idempotent — safe to re-run on every certctl-server boot per the
-- "Idempotent migrations" architecture decision in CLAUDE.md.
--
-- Existing scaffolding REUSED (not redefined here):
--   - JobStatusAwaitingApproval enum value (internal/domain/job.go).
--   - JobRepository.ListTimedOutAwaitingJobs (postgres reaper query).
--   - Config.Scheduler.AwaitingApprovalTimeout (env-mapped, default
--     168h via CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT).
--
-- The lifecycle states are pinned at the schema level via a CHECK
-- constraint matching internal/domain/approval.go::ApprovalState.

ALTER TABLE certificate_profiles
    ADD COLUMN IF NOT EXISTS requires_approval BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS issuance_approval_requests (
    id              TEXT PRIMARY KEY,
    certificate_id  TEXT NOT NULL REFERENCES managed_certificates(id) ON DELETE CASCADE,
    job_id          TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    profile_id      TEXT NOT NULL REFERENCES certificate_profiles(id) ON DELETE RESTRICT,
    requested_by    TEXT NOT NULL,
    state           VARCHAR(20) NOT NULL DEFAULT 'pending',
    decided_by      TEXT,
    decided_at      TIMESTAMPTZ,
    decision_note   TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT approval_state_check CHECK (
        state IN ('pending', 'approved', 'rejected', 'expired')
    ),
    CONSTRAINT approval_decision_consistency CHECK (
        (state = 'pending' AND decided_by IS NULL AND decided_at IS NULL)
        OR (state IN ('approved', 'rejected', 'expired') AND decided_at IS NOT NULL)
    )
);

-- Partial-unique index: at most one PENDING approval request per job
-- ID. Creates / re-creates idempotently. Terminal-state rows
-- (approved / rejected / expired) are not constrained — operators
-- can audit-trail multiple decisions over a job's lifetime, though
-- in practice each job creates exactly one ApprovalRequest at
-- AwaitingApproval entry and never recreates it.
CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_pending_per_job
    ON issuance_approval_requests(job_id)
    WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS idx_approval_state
    ON issuance_approval_requests(state);

CREATE INDEX IF NOT EXISTS idx_approval_certificate
    ON issuance_approval_requests(certificate_id);

CREATE INDEX IF NOT EXISTS idx_approval_pending_age
    ON issuance_approval_requests(created_at)
    WHERE state = 'pending';
