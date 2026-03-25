-- Migration 000006: Filesystem Certificate Discovery
-- Agents scan configured directories for existing certificates and report to the control plane.
-- The control plane deduplicates by SHA-256 fingerprint and stores discovery metadata.

-- Discovery scans track each scan run by an agent
CREATE TABLE IF NOT EXISTS discovery_scans (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    directories TEXT[] NOT NULL,
    certificates_found INTEGER NOT NULL DEFAULT 0,
    certificates_new INTEGER NOT NULL DEFAULT 0,
    errors_count INTEGER NOT NULL DEFAULT 0,
    scan_duration_ms INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_discovery_scans_agent_id ON discovery_scans(agent_id);
CREATE INDEX IF NOT EXISTS idx_discovery_scans_started_at ON discovery_scans(started_at DESC);

-- Discovered certificates store certs found on agent filesystems
CREATE TABLE IF NOT EXISTS discovered_certificates (
    id TEXT PRIMARY KEY,
    fingerprint_sha256 TEXT NOT NULL,
    common_name TEXT NOT NULL DEFAULT '',
    sans TEXT[] DEFAULT '{}',
    serial_number TEXT NOT NULL DEFAULT '',
    issuer_dn TEXT NOT NULL DEFAULT '',
    subject_dn TEXT NOT NULL DEFAULT '',
    not_before TIMESTAMPTZ,
    not_after TIMESTAMPTZ,
    key_algorithm TEXT NOT NULL DEFAULT '',
    key_size INTEGER NOT NULL DEFAULT 0,
    is_ca BOOLEAN NOT NULL DEFAULT FALSE,
    pem_data TEXT NOT NULL DEFAULT '',
    source_path TEXT NOT NULL DEFAULT '',
    source_format TEXT NOT NULL DEFAULT 'PEM',
    agent_id TEXT NOT NULL REFERENCES agents(id),
    discovery_scan_id TEXT REFERENCES discovery_scans(id),
    managed_certificate_id TEXT REFERENCES managed_certificates(id),
    status TEXT NOT NULL DEFAULT 'Unmanaged',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dismissed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique constraint: same fingerprint on same agent at same path
CREATE UNIQUE INDEX IF NOT EXISTS idx_discovered_certs_fingerprint_agent_path
    ON discovered_certificates(fingerprint_sha256, agent_id, source_path);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_discovered_certs_agent_id ON discovered_certificates(agent_id);
CREATE INDEX IF NOT EXISTS idx_discovered_certs_status ON discovered_certificates(status);
CREATE INDEX IF NOT EXISTS idx_discovered_certs_fingerprint ON discovered_certificates(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_discovered_certs_not_after ON discovered_certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_discovered_certs_managed_id ON discovered_certificates(managed_certificate_id)
    WHERE managed_certificate_id IS NOT NULL;
