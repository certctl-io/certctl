-- Reverse of 000025_acme_server.up.sql.
--
-- Drops in reverse-dependency order: challenges → authzs → orders →
-- nonces → accounts (FKs cascade upward), then strips the per-profile
-- acme_auth_mode column from certificate_profiles.

DROP INDEX IF EXISTS idx_acme_challenges_authz;
DROP TABLE IF EXISTS acme_challenges;

DROP INDEX IF EXISTS idx_acme_authz_status;
DROP INDEX IF EXISTS idx_acme_authz_order;
DROP TABLE IF EXISTS acme_authorizations;

DROP INDEX IF EXISTS idx_acme_orders_expires;
DROP INDEX IF EXISTS idx_acme_orders_status;
DROP INDEX IF EXISTS idx_acme_orders_account;
DROP TABLE IF EXISTS acme_orders;

DROP INDEX IF EXISTS idx_acme_nonces_expires;
DROP TABLE IF EXISTS acme_nonces;

DROP INDEX IF EXISTS idx_acme_accounts_status;
DROP INDEX IF EXISTS idx_acme_accounts_jwk_thumb;
DROP TABLE IF EXISTS acme_accounts;

ALTER TABLE certificate_profiles
    DROP CONSTRAINT IF EXISTS certificate_profiles_acme_auth_mode_chk;
ALTER TABLE certificate_profiles
    DROP COLUMN IF EXISTS acme_auth_mode;
