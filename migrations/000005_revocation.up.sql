-- Migration 000005: Revocation Infrastructure
-- Adds revocation tracking to managed_certificates and a dedicated revocations table for CRL generation.

-- Add revocation columns to managed_certificates
ALTER TABLE managed_certificates ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE managed_certificates ADD COLUMN IF NOT EXISTS revocation_reason VARCHAR(50);

-- Certificate revocations table for CRL generation
-- Each row represents a revoked certificate version (by serial number).
-- This is the authoritative source for CRL content.
CREATE TABLE IF NOT EXISTS certificate_revocations (
    id TEXT PRIMARY KEY,
    certificate_id TEXT NOT NULL REFERENCES managed_certificates(id),
    serial_number TEXT NOT NULL,
    reason VARCHAR(50) NOT NULL DEFAULT 'unspecified',
    revoked_by TEXT NOT NULL,           -- actor who initiated revocation
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    issuer_id TEXT REFERENCES issuers(id),
    issuer_notified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for CRL generation (all revoked certs, ordered by revocation time)
CREATE INDEX IF NOT EXISTS idx_certificate_revocations_revoked_at ON certificate_revocations(revoked_at);

-- Index for looking up revocations by certificate
CREATE INDEX IF NOT EXISTS idx_certificate_revocations_cert_id ON certificate_revocations(certificate_id);

-- Index for looking up revocations by serial (OCSP lookup, future M15b)
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_revocations_serial ON certificate_revocations(serial_number);

-- Add revocation notification type
-- (NotificationType is enforced in Go code, not DB constraints, so no ALTER needed)
