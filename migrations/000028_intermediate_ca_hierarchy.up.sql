-- 000028_intermediate_ca_hierarchy.up.sql
-- Rank 8: first-class N-level CA hierarchy management. Closes the
-- FedRAMP / financial-services / OT-network "policy CA in the middle"
-- deployment shape. intermediate_cas captures every non-root CA in
-- the hierarchy with a self-referential parent_ca_id FK; issuers.
-- hierarchy_mode toggles the new code-path behind a flag.
--
-- All operations use IF NOT EXISTS / IF EXISTS so the migration is
-- idempotent — safe to re-run on every certctl-server boot per the
-- "Idempotent migrations" architecture decision in CLAUDE.md.
--
-- Defense in depth: NEVER persist CA private key bytes. The
-- key_driver_id column is a reference (filesystem path / KMS key ID
-- / HSM slot) to the signer.Driver instance that owns the key.

ALTER TABLE issuers
    ADD COLUMN IF NOT EXISTS hierarchy_mode VARCHAR(20) NOT NULL DEFAULT 'single';

CREATE TABLE IF NOT EXISTS intermediate_cas (
    id                  TEXT PRIMARY KEY,
    owning_issuer_id    TEXT NOT NULL REFERENCES issuers(id) ON DELETE RESTRICT,
    parent_ca_id        TEXT REFERENCES intermediate_cas(id) ON DELETE RESTRICT,
    name                TEXT NOT NULL,
    subject             TEXT NOT NULL,
    state               VARCHAR(20) NOT NULL DEFAULT 'active',
    cert_pem            TEXT NOT NULL,
    key_driver_id       TEXT NOT NULL,
    not_before          TIMESTAMPTZ NOT NULL,
    not_after           TIMESTAMPTZ NOT NULL,
    path_len_constraint INT,
    name_constraints    JSONB NOT NULL DEFAULT '[]'::jsonb,
    ocsp_responder_url  TEXT,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT intermediate_ca_state_check CHECK (
        state IN ('active', 'retiring', 'retired')
    ),
    CONSTRAINT intermediate_ca_validity_check CHECK (
        not_after > not_before
    ),
    CONSTRAINT intermediate_ca_no_self_parent CHECK (
        parent_ca_id IS NULL OR parent_ca_id <> id
    )
);

-- Partial-unique: at most one ACTIVE root per issuer. A root is a row
-- with parent_ca_id IS NULL (it has no parent in the hierarchy);
-- multiple retired roots can coexist for audit history.
CREATE UNIQUE INDEX IF NOT EXISTS idx_intermediate_ca_active_root_per_issuer
    ON intermediate_cas(owning_issuer_id)
    WHERE parent_ca_id IS NULL AND state = 'active';

CREATE UNIQUE INDEX IF NOT EXISTS idx_intermediate_ca_unique_name_per_issuer
    ON intermediate_cas(owning_issuer_id, name);

CREATE INDEX IF NOT EXISTS idx_intermediate_ca_owning_issuer
    ON intermediate_cas(owning_issuer_id);

CREATE INDEX IF NOT EXISTS idx_intermediate_ca_parent
    ON intermediate_cas(parent_ca_id);

CREATE INDEX IF NOT EXISTS idx_intermediate_ca_state
    ON intermediate_cas(state);

CREATE INDEX IF NOT EXISTS idx_intermediate_ca_expiring
    ON intermediate_cas(not_after) WHERE state = 'active';
