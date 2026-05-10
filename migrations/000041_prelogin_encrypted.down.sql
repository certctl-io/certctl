-- =============================================================================
-- Rollback for 000041_prelogin_encrypted.up.sql.
--
-- Drops the {state,nonce,pkce_verifier}_enc columns and re-adds the NOT NULL
-- constraint on the plaintext columns. Safe because no in-flight rows persist
-- past the 10-minute TTL — the GC sweep removes legacy rows quickly.
-- =============================================================================

ALTER TABLE oidc_pre_login_sessions
    DROP COLUMN IF EXISTS state_enc,
    DROP COLUMN IF EXISTS nonce_enc,
    DROP COLUMN IF EXISTS pkce_verifier_enc;

-- Re-applying NOT NULL would fail if there are any rows missing the plaintext;
-- truncate the table to remove any stragglers (only handshake-state, safe).
TRUNCATE TABLE oidc_pre_login_sessions;

ALTER TABLE oidc_pre_login_sessions
    ALTER COLUMN state          SET NOT NULL,
    ALTER COLUMN nonce          SET NOT NULL,
    ALTER COLUMN pkce_verifier  SET NOT NULL;
