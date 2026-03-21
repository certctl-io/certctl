-- Rollback: remove certificate profiles and associated columns

ALTER TABLE certificate_versions DROP COLUMN IF EXISTS key_algorithm;
ALTER TABLE certificate_versions DROP COLUMN IF EXISTS key_size;

ALTER TABLE renewal_policies DROP COLUMN IF EXISTS certificate_profile_id;

DROP INDEX IF EXISTS idx_managed_certificates_profile_id;
ALTER TABLE managed_certificates DROP COLUMN IF EXISTS certificate_profile_id;

DROP INDEX IF EXISTS idx_certificate_profiles_name;
DROP INDEX IF EXISTS idx_certificate_profiles_enabled;
DROP TABLE IF EXISTS certificate_profiles;
