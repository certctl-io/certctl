-- M48: Continuous TLS Health Monitoring

-- Add health check columns to network_scan_targets
ALTER TABLE network_scan_targets ADD COLUMN IF NOT EXISTS health_check_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE network_scan_targets ADD COLUMN IF NOT EXISTS health_check_interval_seconds INTEGER DEFAULT 300;

-- Endpoint health checks
CREATE TABLE IF NOT EXISTS endpoint_health_checks (
    id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    certificate_id TEXT REFERENCES managed_certificates(id),
    network_scan_target_id TEXT REFERENCES network_scan_targets(id),
    expected_fingerprint TEXT NOT NULL DEFAULT '',
    observed_fingerprint TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unknown',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    response_time_ms INTEGER NOT NULL DEFAULT 0,
    tls_version TEXT NOT NULL DEFAULT '',
    cipher_suite TEXT NOT NULL DEFAULT '',
    cert_subject TEXT NOT NULL DEFAULT '',
    cert_issuer TEXT NOT NULL DEFAULT '',
    cert_expiry TIMESTAMPTZ,
    last_checked_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    last_transition_at TIMESTAMPTZ,
    failure_reason TEXT NOT NULL DEFAULT '',
    degraded_threshold INTEGER NOT NULL DEFAULT 2,
    down_threshold INTEGER NOT NULL DEFAULT 5,
    check_interval_seconds INTEGER NOT NULL DEFAULT 300,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by TEXT NOT NULL DEFAULT '',
    acknowledged_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_health_checks_status ON endpoint_health_checks(status);
CREATE INDEX IF NOT EXISTS idx_health_checks_endpoint ON endpoint_health_checks(endpoint);
CREATE INDEX IF NOT EXISTS idx_health_checks_enabled ON endpoint_health_checks(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_health_checks_certificate ON endpoint_health_checks(certificate_id) WHERE certificate_id IS NOT NULL;

-- Endpoint health check history (per-probe records)
CREATE TABLE IF NOT EXISTS endpoint_health_history (
    id TEXT PRIMARY KEY,
    health_check_id TEXT NOT NULL REFERENCES endpoint_health_checks(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    response_time_ms INTEGER NOT NULL DEFAULT 0,
    fingerprint TEXT NOT NULL DEFAULT '',
    failure_reason TEXT NOT NULL DEFAULT '',
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_health_history_check_time ON endpoint_health_history(health_check_id, checked_at DESC);
