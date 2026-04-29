-- EST RFC 7030 hardening master bundle Phase 6.1 rollback.
ALTER TABLE certificate_profiles DROP COLUMN IF EXISTS required_csr_attributes;
ALTER TABLE certificate_profiles DROP COLUMN IF EXISTS must_staple;
