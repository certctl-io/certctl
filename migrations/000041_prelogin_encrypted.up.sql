-- =============================================================================
-- 2026-05-10 Audit / HIGH-5 closure
-- =============================================================================
--
-- Pre-login rows in oidc_pre_login_sessions used to persist OIDC state, nonce,
-- and the PKCE verifier as plaintext columns. An operator restoring a backup
-- to a debug environment without redacting handshake-table data leaked every
-- in-flight verifier; combined with a separately-leaked authorization code
-- (e.g. logged at a misconfigured TLS terminator), the attacker could exchange
-- code + verifier directly. RFC 7636 §7 requires verifier confidentiality.
--
-- This migration adds {state,nonce,pkce_verifier}_enc BYTEA columns alongside
-- the existing plaintext columns. The new repository write path emits only the
-- encrypted columns (via internal/crypto.EncryptIfKeySet, v3 blob format —
-- magic(0x03) || salt(16) || nonce(12) || ciphertext+tag, AES-256-GCM with
-- per-row salt + nonce). The existing plaintext columns are made nullable so
-- the new write path doesn't have to populate them; in-flight handshakes from
-- pre-deploy code paths still consume the legacy plaintext columns until the
-- 10-minute absolute TTL expires every legacy row.
--
-- A follow-up migration (queued for v2.1.1) drops the plaintext columns once
-- the rolling deploy completes. We do NOT bundle the DROP into 000041 because
-- in-flight handshakes during deploy would break.
--
-- The encryption key reuses CERTCTL_CONFIG_ENCRYPTION_KEY — the same passphrase
-- already protecting OIDC client secrets, session signing keys, and other
-- secret-bearing rows. No new env var.
-- =============================================================================

ALTER TABLE oidc_pre_login_sessions
    ADD COLUMN IF NOT EXISTS state_enc          BYTEA,
    ADD COLUMN IF NOT EXISTS nonce_enc          BYTEA,
    ADD COLUMN IF NOT EXISTS pkce_verifier_enc  BYTEA;

ALTER TABLE oidc_pre_login_sessions
    ALTER COLUMN state          DROP NOT NULL,
    ALTER COLUMN nonce          DROP NOT NULL,
    ALTER COLUMN pkce_verifier  DROP NOT NULL;
