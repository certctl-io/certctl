-- Migration 000012: Scope Revocation Uniqueness to (issuer_id, serial_number)
--
-- RFC 5280 §5.2.3 defines certificate serial number uniqueness per issuing CA.
-- The prior global-unique index on `certificate_revocations.serial_number` was
-- too strict: certctl supports multiple issuer connectors (Local CA, Vault,
-- DigiCert, Sectigo, Google CAS, AWS ACM PCA, step-ca, Entrust, GlobalSign,
-- EJBCA, ACME, OpenSSL), and different CAs legitimately issue distinct certs
-- that share a serial-number value. Under the old index, recording a
-- revocation for such a collision silently dropped via ON CONFLICT DO NOTHING.
--
-- This migration scopes uniqueness to the (issuer_id, serial_number) pair,
-- which matches RFC 5280 and the revocation-recording call site's intent
-- (see RevocationSvc.RevokeCertificateWithActor, which already populates
-- IssuerID at Create time).
--
-- Duplicate detection: if any row pairs exist with identical (issuer_id,
-- serial_number), the unique-index creation will fail — this is intentional.
-- Operators must resolve duplicates manually before re-running the migration.

-- Drop the overly broad global-serial unique index.
DROP INDEX IF EXISTS idx_certificate_revocations_serial;

-- Recreate uniqueness scoped to (issuer_id, serial_number) per RFC 5280 §5.2.3.
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_revocations_issuer_serial
    ON certificate_revocations(issuer_id, serial_number);

-- Preserve fast serial-only lookup for OCSP/CRL paths that search within a
-- known issuer scope. Non-unique — uniqueness is enforced by the composite
-- index above.
CREATE INDEX IF NOT EXISTS idx_certificate_revocations_serial_lookup
    ON certificate_revocations(serial_number);
