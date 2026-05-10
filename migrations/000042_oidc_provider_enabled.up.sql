-- =============================================================================
-- 2026-05-10 Audit / MED-9 closure
-- =============================================================================
--
-- OIDCProvider.enabled toggle. Pre-fix, the only way to take a provider
-- offline was to DELETE the row, which breaks active users that reference
-- it via user_oidc_provider FKs (and any session that minted under the
-- provider stays orphaned). Post-fix, operators flip enabled=false to
-- keep the row + group mappings + user records intact while suppressing
-- the provider from the LoginPage and rejecting new HandleAuthRequest
-- attempts with ErrProviderDisabled.
--
-- Default true — existing rows pre-migration are all considered enabled
-- so this migration is a no-op for the active set.
-- =============================================================================

ALTER TABLE oidc_providers
    ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE;
