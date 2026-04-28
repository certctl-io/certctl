-- 000020_ocsp_responder.up.sql
--
-- Per-issuer OCSP responder cert + key tracking. Phase 2 of the
-- CRL/OCSP responder bundle.
--
-- WHY: RFC 6960 §2.6 + §4.2.2.2 strongly recommend that OCSP
-- responses be signed by a dedicated "OCSP responder cert" issued by
-- the CA, NOT by the CA's own private key. Signing OCSP with the CA
-- key directly means every relying-party OCSP fetch triggers a CA-key
-- signing operation — a problem when the CA key lives on an HSM
-- (every OCSP poll = HSM op = HSM-rate-limit risk + audit-volume
-- pressure) and a security smell otherwise (broader exposure surface
-- for the CA private key).
--
-- This table tracks one responder cert per issuer. The bootstrap
-- happens on first OCSP request (or at server startup if the row
-- doesn't exist) and rotates automatically when the responder cert
-- enters its 7-day-before-expiry window.
--
-- The responder cert MUST carry the id-pkix-ocsp-nocheck extension
-- (RFC 6960 §4.2.2.2.1) so OCSP clients don't recursively check the
-- responder cert's own revocation status.
--
-- Idempotent. Schema design: composite PK (issuer_id, cert_serial)
-- would let us track historical responder certs across rotations,
-- but operators don't need the history — only the current cert is
-- ever queried. PK on issuer_id alone, replace-on-rotate via UPSERT.

CREATE TABLE IF NOT EXISTS ocsp_responders (
    issuer_id    TEXT PRIMARY KEY REFERENCES issuers(id) ON DELETE CASCADE,
    cert_pem     TEXT NOT NULL,                -- PEM-encoded responder cert
    cert_serial  TEXT NOT NULL,                -- hex serial for ops grep / audit
    key_path     TEXT NOT NULL,                -- filesystem path to the responder key (FileDriver) or driver-specific ref
    key_alg      TEXT NOT NULL,                -- 'ECDSA-P256', 'RSA-2048', ... matches signer.Algorithm enum
    not_before   TIMESTAMPTZ NOT NULL,
    not_after    TIMESTAMPTZ NOT NULL,
    rotated_from TEXT,                         -- previous cert_serial when rotation happens (NULL on first bootstrap)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lets the rotation scheduler quickly find responders whose cert is
-- entering the 7-day-before-expiry window.
CREATE INDEX IF NOT EXISTS idx_ocsp_responders_not_after ON ocsp_responders(not_after);
