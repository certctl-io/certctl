-- M48: Continuous TLS Health Monitoring - rollback

DROP TABLE IF EXISTS endpoint_health_history;
DROP TABLE IF EXISTS endpoint_health_checks;
ALTER TABLE network_scan_targets DROP COLUMN IF EXISTS health_check_enabled;
ALTER TABLE network_scan_targets DROP COLUMN IF EXISTS health_check_interval_seconds;
