-- Migration 000007: Network Discovery (Active TLS Scanning)
-- The control plane actively scans network endpoints for TLS certificates.
-- Results feed into the existing discovery pipeline (discovered_certificates table).

-- Network scan targets define CIDR ranges and ports to probe for TLS certificates
CREATE TABLE IF NOT EXISTS network_scan_targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    cidrs TEXT[] NOT NULL DEFAULT '{}',
    ports INTEGER[] NOT NULL DEFAULT '{443}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    scan_interval_hours INTEGER NOT NULL DEFAULT 6,
    timeout_ms INTEGER NOT NULL DEFAULT 5000,
    last_scan_at TIMESTAMPTZ,
    last_scan_duration_ms INTEGER,
    last_scan_certs_found INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_network_scan_targets_enabled ON network_scan_targets(enabled) WHERE enabled = TRUE;
