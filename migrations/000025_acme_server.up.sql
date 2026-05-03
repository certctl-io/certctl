-- ACME Server (RFC 8555 + RFC 9773 ARI) — Phase 1a foundation.
--
-- Adds the per-profile auth-mode column on certificate_profiles plus
-- the 5 ACME state tables (accounts, orders, authorizations, challenges,
-- nonces). Phase 1a actively uses only `acme_nonces`; Phase 1b consumes
-- `acme_accounts`; Phases 2-4 consume the rest. All five tables ship
-- in this migration so the schema is stable from day one.
--
-- Per the architecture decision documented in docs/acme-server.md,
-- auth_mode is per-profile (NOT a server-wide env var). One certctl-server
-- can serve `trust_authenticated` for an internal-PKI profile AND
-- `challenge` for a public-trust-style profile simultaneously.
--
-- Idempotent (IF NOT EXISTS / IF EXISTS) per certctl architecture
-- decision; safe to re-run.

-- 1. Add per-profile auth_mode to certificate_profiles.
--    'trust_authenticated' (default) — JWS-authenticated client trusted
--    to issue for any identifier the profile policy allows; no per-
--    identifier ownership proof. The most common certctl use case.
--    'challenge' — full HTTP-01 + DNS-01 + TLS-ALPN-01 validation per
--    RFC 8555 §8. For public-trust-style PKI.
ALTER TABLE certificate_profiles
    ADD COLUMN IF NOT EXISTS acme_auth_mode TEXT NOT NULL DEFAULT 'trust_authenticated';

-- Constraint name pinned so the .down.sql can drop it deterministically.
-- Wrapped in DO block so re-running the migration on a database that
-- already has the constraint doesn't fail.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'certificate_profiles_acme_auth_mode_chk'
    ) THEN
        ALTER TABLE certificate_profiles
            ADD CONSTRAINT certificate_profiles_acme_auth_mode_chk
            CHECK (acme_auth_mode IN ('trust_authenticated', 'challenge'));
    END IF;
END $$;

-- 2. acme_accounts — RFC 8555 §7.1.2.
--    account_id is 'acme-acc-' + base32-encoded random per certctl's
--    human-readable-prefix convention. jwk_thumbprint is RFC 7638
--    SHA-256 thumbprint of the canonicalized JWK; the (profile_id,
--    jwk_thumbprint) UNIQUE constraint enforces "one account per
--    keypair per profile" — RFC 8555 §7.3.1 idempotent semantics.
--
--    Phase 1a creates the table; Phase 1b adds CRUD methods.
CREATE TABLE IF NOT EXISTS acme_accounts (
    account_id     TEXT PRIMARY KEY,
    jwk_thumbprint TEXT NOT NULL,
    jwk_pem        TEXT NOT NULL,
    contact        TEXT[],
    status         TEXT NOT NULL,
    profile_id     TEXT NOT NULL,
    owner_id       TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (profile_id) REFERENCES certificate_profiles(id),
    FOREIGN KEY (owner_id) REFERENCES owners(id),
    UNIQUE (profile_id, jwk_thumbprint)
);
CREATE INDEX IF NOT EXISTS idx_acme_accounts_jwk_thumb ON acme_accounts(profile_id, jwk_thumbprint);
CREATE INDEX IF NOT EXISTS idx_acme_accounts_status ON acme_accounts(status) WHERE status = 'valid';

-- 3. acme_orders — RFC 8555 §7.1.3.
--    identifiers stored as JSONB to keep the DNS-name list simple
--    (ACME currently has only the dns identifier type in scope; future
--    types like ip can extend without schema migration).
--    error stored as JSONB (RFC 7807 Problem+JSON shape on failure).
--    certificate_id FKs into managed_certificates so the existing cert
--    pipeline owns the leaf data.
CREATE TABLE IF NOT EXISTS acme_orders (
    order_id       TEXT PRIMARY KEY,
    account_id     TEXT NOT NULL,
    identifiers    JSONB NOT NULL,
    status         TEXT NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    not_before     TIMESTAMPTZ,
    not_after      TIMESTAMPTZ,
    error          JSONB,
    csr_pem        TEXT,
    certificate_id TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (account_id) REFERENCES acme_accounts(account_id),
    FOREIGN KEY (certificate_id) REFERENCES managed_certificates(id)
);
CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_id);
CREATE INDEX IF NOT EXISTS idx_acme_orders_status ON acme_orders(status) WHERE status IN ('pending', 'ready', 'processing');
CREATE INDEX IF NOT EXISTS idx_acme_orders_expires ON acme_orders(expires_at);

-- 4. acme_authorizations — RFC 8555 §7.1.4.
CREATE TABLE IF NOT EXISTS acme_authorizations (
    authz_id       TEXT PRIMARY KEY,
    order_id       TEXT NOT NULL,
    identifier     JSONB NOT NULL,
    status         TEXT NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    wildcard       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (order_id) REFERENCES acme_orders(order_id)
);
CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_id);
CREATE INDEX IF NOT EXISTS idx_acme_authz_status ON acme_authorizations(status) WHERE status IN ('pending', 'processing');

-- 5. acme_challenges — RFC 8555 §8.
CREATE TABLE IF NOT EXISTS acme_challenges (
    challenge_id   TEXT PRIMARY KEY,
    authz_id       TEXT NOT NULL,
    type           TEXT NOT NULL,
    status         TEXT NOT NULL,
    token          TEXT NOT NULL,
    validated_at   TIMESTAMPTZ,
    error          JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (authz_id) REFERENCES acme_authorizations(authz_id)
);
CREATE INDEX IF NOT EXISTS idx_acme_challenges_authz ON acme_challenges(authz_id);

-- 6. acme_nonces — RFC 8555 §6.5.
--    Nonces are short-lived (TTL default 5m, configurable via
--    CERTCTL_ACME_SERVER_NONCE_TTL). DB-backed (NOT in-memory) so
--    they survive server restart — replay protection only works if the
--    server-side store outlasts the client's nonce caching window.
--    Phase 5 adds a scheduler-loop GC sweep; Phase 1a inserts but does
--    not yet GC.
CREATE TABLE IF NOT EXISTS acme_nonces (
    nonce      TEXT PRIMARY KEY,
    issued_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_acme_nonces_expires ON acme_nonces(expires_at) WHERE used = FALSE;
