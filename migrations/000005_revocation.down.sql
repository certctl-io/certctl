-- Rollback Migration 000005: Revocation Infrastructure

DROP TABLE IF EXISTS certificate_revocations;

ALTER TABLE managed_certificates DROP COLUMN IF EXISTS revoked_at;
ALTER TABLE managed_certificates DROP COLUMN IF EXISTS revocation_reason;
