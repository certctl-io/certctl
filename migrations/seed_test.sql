-- =============================================================================
-- certctl Test Environment — Seed Data
-- =============================================================================
--
-- Pre-populates the database with the minimum objects needed to test the full
-- certificate lifecycle against real CA backends (Pebble, step-ca, Local CA).
--
-- Load order (handled by Docker entrypoint filename sorting):
--   001_schema.sql → ... → 008_verification.sql → 010_seed.sql → 015_seed_test.sql
--
-- All IDs use a "test-" prefix so they're easy to spot in the dashboard.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Team
-- ---------------------------------------------------------------------------
INSERT INTO teams (id, name, description)
VALUES (
  'team-test-ops',
  'Test Operations',
  'Operations team for certctl testing environment'
) ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Owner (references team)
-- ---------------------------------------------------------------------------
INSERT INTO owners (id, name, email, team_id)
VALUES (
  'owner-test-admin',
  'Test Admin',
  'admin@certctl-test.local',
  'team-test-ops'
) ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Agent — must exist before the agent binary sends its first heartbeat
-- ---------------------------------------------------------------------------
-- The agent binary (certctl-agent container) connects with:
--   CERTCTL_AGENT_ID=agent-test-01
--   CERTCTL_AGENT_NAME=test-agent-01
-- The heartbeat handler does a GET by ID — if the agent doesn't exist, it 404s.
-- api_key_hash is SHA-256 of "test-agent-key-2026" (not used for auth, just stored).
INSERT INTO agents (id, name, hostname, status, registered_at, api_key_hash, os, architecture, ip_address, version)
VALUES (
  'agent-test-01',
  'test-agent-01',
  'certctl-test-agent',
  'online',
  NOW(),
  'cad819dee454889f686d678f691e5084e58ba149762eae2fda4d0bd2abaceefa',
  'linux',
  'amd64',
  '10.30.50.8',
  'test'
) ON CONFLICT (id) DO NOTHING;

-- The network scanner uses "server-scanner" as a virtual agent.
-- It gets auto-created by the server code, but seed it here to avoid races.
INSERT INTO agents (id, name, hostname, status, registered_at, api_key_hash)
VALUES (
  'server-scanner',
  'server-scanner',
  'certctl-server',
  'online',
  NOW(),
  'no-key'
) ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Issuers — one row per CA backend in the test environment
-- ---------------------------------------------------------------------------
-- These are metadata records the dashboard reads. The actual CA connections
-- are configured via env vars on the server container.

-- Local CA (self-signed, always available)
INSERT INTO issuers (id, name, type, config, enabled)
VALUES (
  'iss-local',
  'Local CA (Self-Signed)',
  'local',
  '{"mode": "self-signed", "description": "Built-in self-signed CA for testing"}'::jsonb,
  true
) ON CONFLICT (id) DO NOTHING;

-- ACME via Pebble (simulates Let''s Encrypt)
INSERT INTO issuers (id, name, type, config, enabled)
VALUES (
  'iss-acme-staging',
  'ACME (Pebble Test CA)',
  'acme',
  '{"directory_url": "https://pebble:14000/dir", "email": "test@certctl.dev", "challenge_type": "http-01", "description": "Pebble ACME test server simulating Lets Encrypt"}'::jsonb,
  true
) ON CONFLICT (id) DO NOTHING;

-- step-ca (Smallstep private CA)
INSERT INTO issuers (id, name, type, config, enabled)
VALUES (
  'iss-stepca',
  'step-ca (Private CA)',
  'stepca',
  '{"url": "https://step-ca:9000", "provisioner": "admin", "description": "Smallstep private CA with JWK provisioner"}'::jsonb,
  true
) ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Certificate Profile — TLS server certs, 90-day max
-- ---------------------------------------------------------------------------
INSERT INTO certificate_profiles (id, name, description, max_ttl_seconds, allowed_ekus, allowed_key_algorithms)
VALUES (
  'prof-test-tls',
  'Test TLS Server',
  'Standard TLS server certificate profile for testing',
  7776000,  -- 90 days
  '["serverAuth"]'::jsonb,
  '[{"algorithm": "ECDSA", "min_size": 256}, {"algorithm": "RSA", "min_size": 2048}]'::jsonb
) ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Deployment Target — NGINX (references agent-test-01)
-- ---------------------------------------------------------------------------
-- The agent deploys certs to NGINX via the shared nginx_certs volume.
INSERT INTO deployment_targets (id, name, type, agent_id, config, enabled)
VALUES (
  'target-test-nginx',
  'Test NGINX',
  'NGINX',
  'agent-test-01',
  '{"cert_path": "/nginx-certs/cert.pem", "key_path": "/nginx-certs/key.pem", "chain_path": "/nginx-certs/chain.pem", "reload_command": "true", "validate_command": "true"}'::jsonb,
  true
) ON CONFLICT (id) DO NOTHING;
