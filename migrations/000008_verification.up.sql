-- Add verification fields to jobs table for post-deployment TLS verification
ALTER TABLE jobs
ADD COLUMN IF NOT EXISTS verification_status TEXT DEFAULT 'pending',
ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS verification_fingerprint TEXT,
ADD COLUMN IF NOT EXISTS verification_error TEXT;

-- Index on verification_status for queries filtering by status
CREATE INDEX IF NOT EXISTS idx_jobs_verification_status ON jobs(verification_status);

-- Index on verified_at for temporal queries
CREATE INDEX IF NOT EXISTS idx_jobs_verified_at ON jobs(verified_at);
