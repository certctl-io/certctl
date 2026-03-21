-- =============================================================================
-- Demo Seed Data for certctl
-- Run after schema migration to populate a realistic demo environment
-- =============================================================================

-- Teams
INSERT INTO teams (id, name, description, created_at, updated_at) VALUES
  ('t-platform',  'Platform Engineering', 'Core infrastructure and platform services', NOW(), NOW()),
  ('t-security',  'Security Operations',  'Security tooling and compliance',          NOW(), NOW()),
  ('t-payments',  'Payments',             'Payment processing services',              NOW(), NOW()),
  ('t-frontend',  'Frontend',             'Web and mobile applications',              NOW(), NOW()),
  ('t-data',      'Data Engineering',     'Data pipelines and analytics',             NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Owners
INSERT INTO owners (id, name, email, team_id, created_at, updated_at) VALUES
  ('o-alice',   'Alice Chen',      'alice@example.com',    't-platform',  NOW(), NOW()),
  ('o-bob',     'Bob Martinez',    'bob@example.com',      't-security',  NOW(), NOW()),
  ('o-carol',   'Carol Williams',  'carol@example.com',    't-payments',  NOW(), NOW()),
  ('o-dave',    'Dave Kim',        'dave@example.com',     't-frontend',  NOW(), NOW()),
  ('o-eve',     'Eve Johnson',     'eve@example.com',      't-data',      NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Renewal Policies
INSERT INTO renewal_policies (id, name, renewal_window_days, auto_renew, max_retries, retry_interval_minutes, alert_thresholds_days, created_at, updated_at) VALUES
  ('rp-standard', 'Standard 30-day', 30, true,  3, 60,  '[30, 14, 7, 0]'::jsonb,  NOW(), NOW()),
  ('rp-urgent',   'Urgent 14-day',   14, true,  5, 30,  '[14, 7, 3, 0]'::jsonb,   NOW(), NOW()),
  ('rp-manual',   'Manual Only',     30, false, 0, 0,   '[30, 14, 7, 0]'::jsonb,  NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Issuers
INSERT INTO issuers (id, name, type, config, enabled, created_at, updated_at) VALUES
  ('iss-local',    'Local Dev CA',          'local',      '{"ca_common_name": "CertCtl Demo CA", "validity_days": 90}', true,  NOW(), NOW()),
  ('iss-acme-le',  'Let''s Encrypt Staging', 'acme',      '{"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory", "email": "admin@example.com"}', true,  NOW(), NOW()),
  ('iss-digicert', 'DigiCert (disabled)',    'generic_ca', '{"api_url": "https://api.digicert.com", "api_key": "REDACTED"}', false, NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Agents
INSERT INTO agents (id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash, os, architecture, ip_address, version) VALUES
  ('ag-web-prod',    'web-prod-agent',    'web-prod-01.internal',    'online',  NOW() - INTERVAL '30 seconds',  NOW() - INTERVAL '90 days', 'demo_hash_1', 'linux', 'amd64', '10.0.1.10', '1.0.0'),
  ('ag-web-staging', 'web-staging-agent', 'web-stg-01.internal',    'online',  NOW() - INTERVAL '45 seconds',  NOW() - INTERVAL '60 days', 'demo_hash_2', 'linux', 'amd64', '10.0.2.20', '1.0.0'),
  ('ag-lb-prod',     'lb-prod-agent',     'f5-prod-01.internal',    'online',  NOW() - INTERVAL '15 seconds',  NOW() - INTERVAL '120 days', 'demo_hash_3', 'linux', 'amd64', '10.0.1.50', '1.0.0'),
  ('ag-iis-prod',    'iis-prod-agent',    'iis-prod-01.internal',   'offline', NOW() - INTERVAL '3 hours',     NOW() - INTERVAL '30 days', 'demo_hash_4', 'windows', 'amd64', '10.0.3.15', '1.0.0'),
  ('ag-data-prod',   'data-prod-agent',   'data-prod-01.internal',  'online',  NOW() - INTERVAL '20 seconds',  NOW() - INTERVAL '45 days', 'demo_hash_5', 'linux', 'arm64', '10.0.4.30', '1.0.0')
ON CONFLICT (id) DO NOTHING;

-- Deployment Targets
INSERT INTO deployment_targets (id, name, type, agent_id, config, enabled, created_at, updated_at) VALUES
  ('tgt-nginx-prod',    'NGINX Production',    'nginx', 'ag-web-prod',    '{"cert_path": "/etc/nginx/ssl/cert.pem", "key_path": "/etc/nginx/ssl/key.pem", "reload_command": "nginx -s reload"}', true,  NOW(), NOW()),
  ('tgt-nginx-staging', 'NGINX Staging',       'nginx', 'ag-web-staging', '{"cert_path": "/etc/nginx/ssl/cert.pem", "key_path": "/etc/nginx/ssl/key.pem", "reload_command": "nginx -s reload"}', true,  NOW(), NOW()),
  ('tgt-f5-prod',       'F5 BIG-IP Production','f5',    'ag-lb-prod',    '{"host": "f5-prod-01.internal", "partition": "Common", "ssl_profile": "clientssl"}', true,  NOW(), NOW()),
  ('tgt-iis-prod',      'IIS Production',      'iis',   'ag-iis-prod',   '{"site_name": "Default Web Site", "binding_info": "*:443:"}', true,  NOW(), NOW()),
  ('tgt-nginx-data',    'NGINX Data Services', 'nginx', 'ag-data-prod',  '{"cert_path": "/etc/nginx/ssl/cert.pem", "key_path": "/etc/nginx/ssl/key.pem", "reload_command": "nginx -s reload"}', true,  NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Certificate Profiles
INSERT INTO certificate_profiles (id, name, description, allowed_key_algorithms, max_ttl_seconds, allowed_ekus, required_san_patterns, spiffe_uri_pattern, allow_short_lived, enabled, created_at, updated_at) VALUES
  ('prof-standard-tls', 'Standard TLS',
   'Default profile for web-facing TLS certificates. Requires ECDSA P-256+ or RSA 2048+.',
   '[{"algorithm": "ECDSA", "min_size": 256}, {"algorithm": "RSA", "min_size": 2048}]'::jsonb,
   7776000, -- 90 days
   '["serverAuth"]'::jsonb,
   '[]'::jsonb,
   '', false, true, NOW(), NOW()),

  ('prof-internal-mtls', 'Internal mTLS',
   'Mutual TLS profile for internal service-to-service communication.',
   '[{"algorithm": "ECDSA", "min_size": 256}]'::jsonb,
   2592000, -- 30 days
   '["serverAuth", "clientAuth"]'::jsonb,
   '[".*\\.internal\\.example\\.com$"]'::jsonb,
   '', false, true, NOW(), NOW()),

  ('prof-short-lived', 'Short-Lived Credential',
   'Ephemeral certificates for CI/CD pipelines and container workloads. TTL under 1 hour, expiry = revocation.',
   '[{"algorithm": "ECDSA", "min_size": 256}]'::jsonb,
   300, -- 5 minutes
   '["serverAuth", "clientAuth"]'::jsonb,
   '[]'::jsonb,
   'spiffe://example.com/workload/*',
   true, true, NOW(), NOW()),

  ('prof-high-security', 'High Security',
   'For PCI-DSS and compliance-sensitive workloads. RSA 4096+ or ECDSA P-384+ only.',
   '[{"algorithm": "ECDSA", "min_size": 384}, {"algorithm": "RSA", "min_size": 4096}]'::jsonb,
   4060800, -- 47 days (Ballot SC-081v3 target)
   '["serverAuth"]'::jsonb,
   '[".*\\.example\\.com$"]'::jsonb,
   '', false, true, NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Managed Certificates — varied statuses and expiry dates for realistic dashboard
INSERT INTO managed_certificates (id, name, common_name, sans, environment, owner_id, team_id, issuer_id, renewal_policy_id, status, expires_at, tags, last_renewal_at, last_deployment_at, created_at, updated_at) VALUES
  -- Active, healthy certs
  ('mc-api-prod',      'api-production',       'api.example.com',       ARRAY['api.example.com', 'api-v2.example.com'],                 'production',  'o-alice', 't-platform', 'iss-local', 'rp-standard', 'active',              NOW() + INTERVAL '75 days',  '{"service": "api-gateway", "tier": "critical"}',   NOW() - INTERVAL '15 days', NOW() - INTERVAL '15 days', NOW() - INTERVAL '180 days', NOW()),
  ('mc-web-prod',      'web-production',       'www.example.com',       ARRAY['www.example.com', 'example.com'],                        'production',  'o-dave',  't-frontend', 'iss-local', 'rp-standard', 'active',              NOW() + INTERVAL '60 days',  '{"service": "web-app", "tier": "critical"}',       NOW() - INTERVAL '30 days', NOW() - INTERVAL '30 days', NOW() - INTERVAL '365 days', NOW()),
  ('mc-pay-prod',      'payments-production',  'pay.example.com',       ARRAY['pay.example.com', 'checkout.example.com'],               'production',  'o-carol', 't-payments', 'iss-local', 'rp-urgent',   'active',              NOW() + INTERVAL '45 days',  '{"service": "payments", "tier": "critical", "pci": "true"}', NOW() - INTERVAL '45 days', NOW() - INTERVAL '45 days', NOW() - INTERVAL '200 days', NOW()),
  ('mc-dash-prod',     'dashboard-production', 'dashboard.example.com', ARRAY['dashboard.example.com'],                                 'production',  'o-dave',  't-frontend', 'iss-local', 'rp-standard', 'active',              NOW() + INTERVAL '82 days',  '{"service": "dashboard", "tier": "high"}',         NOW() - INTERVAL '8 days',  NOW() - INTERVAL '8 days',  NOW() - INTERVAL '100 days', NOW()),
  ('mc-data-prod',     'data-api-production',  'data.example.com',      ARRAY['data.example.com', 'analytics.example.com'],             'production',  'o-eve',   't-data',     'iss-local', 'rp-standard', 'active',              NOW() + INTERVAL '55 days',  '{"service": "data-api", "tier": "high"}',          NOW() - INTERVAL '35 days', NOW() - INTERVAL '35 days', NOW() - INTERVAL '150 days', NOW()),

  -- Expiring soon (< 30 days)
  ('mc-auth-prod',     'auth-production',      'auth.example.com',      ARRAY['auth.example.com', 'login.example.com', 'sso.example.com'], 'production', 'o-bob', 't-security', 'iss-local', 'rp-urgent', 'expiring',            NOW() + INTERVAL '12 days',  '{"service": "auth", "tier": "critical"}',          NOW() - INTERVAL '78 days', NOW() - INTERVAL '78 days', NOW() - INTERVAL '300 days', NOW()),
  ('mc-cdn-prod',      'cdn-production',       'cdn.example.com',       ARRAY['cdn.example.com', 'static.example.com'],                 'production',  'o-alice', 't-platform', 'iss-local', 'rp-standard', 'expiring',            NOW() + INTERVAL '8 days',   '{"service": "cdn", "tier": "high"}',               NOW() - INTERVAL '82 days', NOW() - INTERVAL '82 days', NOW() - INTERVAL '250 days', NOW()),
  ('mc-mail-prod',     'mail-production',      'mail.example.com',      ARRAY['mail.example.com', 'smtp.example.com'],                  'production',  'o-bob',   't-security', 'iss-local', 'rp-standard', 'expiring',            NOW() + INTERVAL '5 days',   '{"service": "email", "tier": "medium"}',           NOW() - INTERVAL '85 days', NOW() - INTERVAL '85 days', NOW() - INTERVAL '400 days', NOW()),

  -- Expired
  ('mc-legacy-prod',   'legacy-app',           'legacy.example.com',    ARRAY['legacy.example.com'],                                    'production',  'o-alice', 't-platform', 'iss-local', 'rp-manual',   'expired',             NOW() - INTERVAL '3 days',   '{"service": "legacy", "tier": "low", "decom": "planned"}', NOW() - INTERVAL '93 days', NOW() - INTERVAL '93 days', NOW() - INTERVAL '500 days', NOW()),
  ('mc-old-api',       'old-api-v1',           'api-v1.example.com',    ARRAY['api-v1.example.com'],                                    'production',  'o-alice', 't-platform', 'iss-local', 'rp-manual',   'expired',             NOW() - INTERVAL '15 days',  '{"service": "api-v1", "tier": "low", "deprecated": "true"}', NULL, NULL, NOW() - INTERVAL '600 days', NOW()),

  -- Staging certs
  ('mc-api-stg',       'api-staging',          'api.staging.example.com', ARRAY['api.staging.example.com'],                             'staging',     'o-alice', 't-platform', 'iss-local', 'rp-standard', 'active',              NOW() + INTERVAL '65 days',  '{"service": "api-gateway", "tier": "low"}',        NOW() - INTERVAL '25 days', NOW() - INTERVAL '25 days', NOW() - INTERVAL '120 days', NOW()),
  ('mc-web-stg',       'web-staging',          'www.staging.example.com', ARRAY['www.staging.example.com', 'staging.example.com'],      'staging',     'o-dave',  't-frontend', 'iss-local', 'rp-standard', 'active',              NOW() + INTERVAL '70 days',  '{"service": "web-app", "tier": "low"}',            NOW() - INTERVAL '20 days', NOW() - INTERVAL '20 days', NOW() - INTERVAL '100 days', NOW()),

  -- Renewal in progress
  ('mc-grafana-prod',  'grafana-production',   'grafana.example.com',   ARRAY['grafana.example.com', 'metrics.example.com'],            'production',  'o-eve',   't-data',     'iss-local', 'rp-standard', 'renewal_in_progress', NOW() + INTERVAL '3 days',   '{"service": "monitoring", "tier": "high"}',        NOW() - INTERVAL '87 days', NOW() - INTERVAL '87 days', NOW() - INTERVAL '180 days', NOW()),

  -- Failed
  ('mc-vpn-prod',      'vpn-production',       'vpn.example.com',       ARRAY['vpn.example.com'],                                      'production',  'o-bob',   't-security', 'iss-acme-le', 'rp-urgent', 'failed',              NOW() + INTERVAL '1 day',    '{"service": "vpn", "tier": "critical"}',           NULL, NULL, NOW() - INTERVAL '90 days', NOW()),

  -- Wildcard
  ('mc-wildcard-prod', 'wildcard-production',  '*.example.com',         ARRAY['*.example.com', 'example.com'],                          'production',  'o-alice', 't-platform', 'iss-local', 'rp-standard', 'active',              NOW() + INTERVAL '50 days',  '{"service": "wildcard", "tier": "critical"}',      NOW() - INTERVAL '40 days', NOW() - INTERVAL '40 days', NOW() - INTERVAL '365 days', NOW())
ON CONFLICT (id) DO NOTHING;

-- Certificate-Target Mappings
INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES
  ('mc-api-prod',      'tgt-nginx-prod'),
  ('mc-api-prod',      'tgt-f5-prod'),
  ('mc-web-prod',      'tgt-nginx-prod'),
  ('mc-web-prod',      'tgt-f5-prod'),
  ('mc-pay-prod',      'tgt-nginx-prod'),
  ('mc-pay-prod',      'tgt-f5-prod'),
  ('mc-dash-prod',     'tgt-nginx-prod'),
  ('mc-data-prod',     'tgt-nginx-data'),
  ('mc-auth-prod',     'tgt-nginx-prod'),
  ('mc-auth-prod',     'tgt-f5-prod'),
  ('mc-cdn-prod',      'tgt-f5-prod'),
  ('mc-mail-prod',     'tgt-nginx-prod'),
  ('mc-legacy-prod',   'tgt-iis-prod'),
  ('mc-api-stg',       'tgt-nginx-staging'),
  ('mc-web-stg',       'tgt-nginx-staging'),
  ('mc-grafana-prod',  'tgt-nginx-data'),
  ('mc-vpn-prod',      'tgt-f5-prod'),
  ('mc-wildcard-prod', 'tgt-nginx-prod'),
  ('mc-wildcard-prod', 'tgt-f5-prod'),
  ('mc-wildcard-prod', 'tgt-nginx-staging')
ON CONFLICT DO NOTHING;

-- Certificate Versions (latest version for each active cert)
INSERT INTO certificate_versions (id, certificate_id, serial_number, not_before, not_after, fingerprint_sha256, pem_chain, csr_pem, created_at) VALUES
  ('cv-api-1',     'mc-api-prod',      '0A:1B:2C:3D:4E:5F:00:01', NOW() - INTERVAL '15 days', NOW() + INTERVAL '75 days',  'sha256:ab12cd34ef56', '-----BEGIN CERTIFICATE-----\nMIIDemoAPI...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '15 days'),
  ('cv-web-1',     'mc-web-prod',      '0A:1B:2C:3D:4E:5F:00:02', NOW() - INTERVAL '30 days', NOW() + INTERVAL '60 days',  'sha256:cd34ef56ab12', '-----BEGIN CERTIFICATE-----\nMIIDemoWeb...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '30 days'),
  ('cv-pay-1',     'mc-pay-prod',      '0A:1B:2C:3D:4E:5F:00:03', NOW() - INTERVAL '45 days', NOW() + INTERVAL '45 days',  'sha256:ef56ab12cd34', '-----BEGIN CERTIFICATE-----\nMIIDemoPay...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '45 days'),
  ('cv-auth-1',    'mc-auth-prod',     '0A:1B:2C:3D:4E:5F:00:04', NOW() - INTERVAL '78 days', NOW() + INTERVAL '12 days',  'sha256:1234abcdef56', '-----BEGIN CERTIFICATE-----\nMIIDemoAuth...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '78 days'),
  ('cv-wild-1',    'mc-wildcard-prod', '0A:1B:2C:3D:4E:5F:00:05', NOW() - INTERVAL '40 days', NOW() + INTERVAL '50 days',  'sha256:5678abcdef12', '-----BEGIN CERTIFICATE-----\nMIIDemoWild...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '40 days')
ON CONFLICT (id) DO NOTHING;

-- Recent Audit Events
INSERT INTO audit_events (id, actor, actor_type, action, resource_type, resource_id, details, timestamp) VALUES
  ('audit-demo-01', 'alice@example.com', 'user',   'certificate.renewed',   'certificate', 'mc-api-prod',      '{"issuer": "local", "serial": "0A:1B:2C:3D:4E:5F:00:01"}', NOW() - INTERVAL '15 days'),
  ('audit-demo-02', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-api-prod',      '{"target": "tgt-nginx-prod", "status": "success"}',         NOW() - INTERVAL '15 days' + INTERVAL '5 minutes'),
  ('audit-demo-03', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-api-prod',      '{"target": "tgt-f5-prod", "status": "success"}',            NOW() - INTERVAL '15 days' + INTERVAL '8 minutes'),
  ('audit-demo-04', 'dave@example.com',  'user',   'certificate.renewed',   'certificate', 'mc-web-prod',      '{"issuer": "local", "serial": "0A:1B:2C:3D:4E:5F:00:02"}', NOW() - INTERVAL '30 days'),
  ('audit-demo-05', 'carol@example.com', 'user',   'certificate.created',   'certificate', 'mc-pay-prod',      '{"common_name": "pay.example.com"}',                        NOW() - INTERVAL '200 days'),
  ('audit-demo-06', 'system',            'system', 'renewal.started',       'certificate', 'mc-grafana-prod',  '{"reason": "expiring_in_3_days"}',                          NOW() - INTERVAL '2 hours'),
  ('audit-demo-07', 'system',            'system', 'renewal.failed',        'certificate', 'mc-vpn-prod',      '{"error": "ACME challenge failed: DNS timeout", "attempt": 3}', NOW() - INTERVAL '1 hour'),
  ('audit-demo-08', 'system',            'system', 'expiration.warning',    'certificate', 'mc-auth-prod',     '{"days_until_expiry": 12}',                                 NOW() - INTERVAL '30 minutes'),
  ('audit-demo-09', 'system',            'system', 'expiration.warning',    'certificate', 'mc-cdn-prod',      '{"days_until_expiry": 8}',                                  NOW() - INTERVAL '25 minutes'),
  ('audit-demo-10', 'system',            'system', 'expiration.warning',    'certificate', 'mc-mail-prod',     '{"days_until_expiry": 5}',                                  NOW() - INTERVAL '20 minutes'),
  ('audit-demo-11', 'bob@example.com',   'user',   'agent.registered',      'agent',       'ag-iis-prod',      '{"hostname": "iis-prod-01.internal"}',                      NOW() - INTERVAL '30 days'),
  ('audit-demo-12', 'system',            'system', 'agent.offline',         'agent',       'ag-iis-prod',      '{"last_heartbeat": "3 hours ago"}',                         NOW() - INTERVAL '3 hours'),
  ('audit-demo-13', 'alice@example.com', 'user',   'policy.violation',      'certificate', 'mc-legacy-prod',   '{"rule": "max-certificate-lifetime", "message": "Certificate expired"}', NOW() - INTERVAL '3 days'),
  ('audit-demo-14', 'bob@example.com',   'user',   'issuer.configured',     'issuer',      'iss-local',        '{"type": "local", "ca_common_name": "CertCtl Demo CA"}',    NOW() - INTERVAL '90 days'),
  ('audit-demo-15', 'alice@example.com', 'user',   'target.configured',     'target',      'tgt-nginx-prod',   '{"type": "nginx", "agent": "ag-web-prod"}',                 NOW() - INTERVAL '90 days')
ON CONFLICT (id) DO NOTHING;

-- Policy Violations (reference policy rules by their IDs from seed.sql)
INSERT INTO policy_violations (id, certificate_id, rule_id, message, severity, created_at) VALUES
  ('pv-demo-01', 'mc-legacy-prod', 'pr-max-certificate-lifetime', 'Certificate has expired and exceeds maximum lifetime policy', 'critical', NOW() - INTERVAL '3 days'),
  ('pv-demo-02', 'mc-old-api',     'pr-max-certificate-lifetime', 'Certificate expired 15 days ago',                            'critical', NOW() - INTERVAL '15 days'),
  ('pv-demo-03', 'mc-vpn-prod',    'pr-min-renewal-window',       'Renewal failed within minimum renewal window',               'error',    NOW() - INTERVAL '1 hour'),
  ('pv-demo-04', 'mc-mail-prod',   'pr-min-renewal-window',       'Certificate expiring in 5 days, below 14-day minimum window','warning',  NOW() - INTERVAL '20 minutes')
ON CONFLICT (id) DO NOTHING;

-- Notification Events
INSERT INTO notification_events (id, type, certificate_id, channel, recipient, message, sent_at, status, error) VALUES
  ('ne-demo-01', 'expiration_warning',  'mc-auth-prod',     'email',   'bob@example.com',     'Certificate auth-production expires in 12 days',         NOW() - INTERVAL '30 minutes', 'sent',   NULL),
  ('ne-demo-02', 'expiration_warning',  'mc-cdn-prod',      'email',   'alice@example.com',   'Certificate cdn-production expires in 8 days',           NOW() - INTERVAL '25 minutes', 'sent',   NULL),
  ('ne-demo-03', 'expiration_warning',  'mc-mail-prod',     'email',   'bob@example.com',     'Certificate mail-production expires in 5 days',          NOW() - INTERVAL '20 minutes', 'sent',   NULL),
  ('ne-demo-04', 'renewal_failure',     'mc-vpn-prod',      'webhook', 'https://hooks.example.com/certctl', 'Renewal failed for vpn-production after 3 attempts', NOW() - INTERVAL '1 hour', 'sent', NULL),
  ('ne-demo-05', 'renewal_success',     'mc-api-prod',      'email',   'alice@example.com',   'Certificate api-production renewed successfully',        NOW() - INTERVAL '15 days',    'sent',   NULL),
  ('ne-demo-06', 'deployment_success',  'mc-api-prod',      'webhook', 'https://hooks.example.com/certctl', 'Certificate api-production deployed to NGINX Production', NOW() - INTERVAL '15 days', 'sent', NULL)
ON CONFLICT (id) DO NOTHING;
