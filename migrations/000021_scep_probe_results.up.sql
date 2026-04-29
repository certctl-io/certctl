-- Migration 000021: SCEP probe results (Phase 11.5 of the SCEP RFC 8894
-- + Intune master bundle).
--
-- The control plane's network scanner can probe an SCEP server URL
-- (RFC 8894 §3.5.1 GetCACaps + GetCACert) and persist a structured
-- posture snapshot per run. Operators use this for:
--   1. Pre-migration assessment — point the probe at an existing
--      EJBCA / NDES SCEP server to see what capabilities it advertises
--      (RFC 8894 / AES / POST / Renewal / SHA-256 / SHA-512) and what
--      the CA cert looks like (subject, issuer, expiry, algorithm).
--   2. Compliance posture audits — periodic probes against the
--      operator's own SCEP servers to flag drift.
--
-- The probe deliberately does NOT POST a CSR — capability-only.
-- Standalone CLI for this same probe is explicitly out of scope for
-- this bundle; the GUI surface inside certctl is the only consumer
-- of this table at this time.

CREATE TABLE IF NOT EXISTS scep_probe_results (
    id                       TEXT PRIMARY KEY,
    target_url               TEXT NOT NULL,
    reachable                BOOLEAN NOT NULL,
    advertised_caps          TEXT[] NOT NULL DEFAULT '{}',
    supports_rfc8894         BOOLEAN NOT NULL DEFAULT FALSE,
    supports_aes             BOOLEAN NOT NULL DEFAULT FALSE,
    supports_post_operation  BOOLEAN NOT NULL DEFAULT FALSE,
    supports_renewal         BOOLEAN NOT NULL DEFAULT FALSE,
    supports_sha256          BOOLEAN NOT NULL DEFAULT FALSE,
    supports_sha512          BOOLEAN NOT NULL DEFAULT FALSE,
    ca_cert_subject          TEXT,
    ca_cert_issuer           TEXT,
    ca_cert_not_before       TIMESTAMPTZ,
    ca_cert_not_after        TIMESTAMPTZ,
    ca_cert_expired          BOOLEAN NOT NULL DEFAULT FALSE,
    ca_cert_algorithm        TEXT,
    ca_cert_chain_length     INTEGER NOT NULL DEFAULT 0,
    probed_at                TIMESTAMPTZ NOT NULL,
    probe_duration_ms        BIGINT NOT NULL DEFAULT 0,
    error                    TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The two query patterns the GUI uses:
--   - "show me the most recent N probes across any URL" → probed_at DESC
--   - "show me the probe history for this URL" → target_url + probed_at DESC
CREATE INDEX IF NOT EXISTS idx_scep_probe_results_probed_at
    ON scep_probe_results(probed_at DESC);
CREATE INDEX IF NOT EXISTS idx_scep_probe_results_target_url
    ON scep_probe_results(target_url, probed_at DESC);
