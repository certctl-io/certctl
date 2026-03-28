-- Drop verification-related columns from jobs table
ALTER TABLE jobs
DROP COLUMN IF EXISTS verification_status,
DROP COLUMN IF EXISTS verified_at,
DROP COLUMN IF EXISTS verification_fingerprint,
DROP COLUMN IF EXISTS verification_error;

-- Drop verification indexes
DROP INDEX IF EXISTS idx_jobs_verification_status;
DROP INDEX IF EXISTS idx_jobs_verified_at;
