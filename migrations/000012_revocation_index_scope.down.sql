-- Rollback Migration 000012: Restore global-serial uniqueness.
--
-- Reverts to the pre-000012 behavior: uniqueness on `serial_number` alone.
-- Operators must ensure no duplicate serial_numbers exist across different
-- issuers before rolling back, otherwise the unique-index creation will fail.

DROP INDEX IF EXISTS idx_certificate_revocations_serial_lookup;

DROP INDEX IF EXISTS idx_certificate_revocations_issuer_serial;

CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_revocations_serial
    ON certificate_revocations(serial_number);
