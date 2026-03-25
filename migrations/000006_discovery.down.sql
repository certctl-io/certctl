-- Rollback Migration 000006: Filesystem Certificate Discovery
DROP TABLE IF EXISTS discovered_certificates;
DROP TABLE IF EXISTS discovery_scans;
