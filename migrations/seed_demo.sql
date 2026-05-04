-- =============================================================================
-- Demo Seed Data for certctl v2.0.14
-- Run after schema migration to populate a realistic demo environment.
-- Simulates 90 days of certificate lifecycle activity so the dashboard
-- looks like a system that has been running in production for months.
-- =============================================================================

-- ============================================================
-- 1. Organizations: Teams & Owners
-- ============================================================
INSERT INTO teams (id, name, description, created_at, updated_at) VALUES
  ('t-platform',  'Platform Engineering', 'Core infrastructure and platform services', NOW() - INTERVAL '180 days', NOW() - INTERVAL '180 days'),
  ('t-security',  'Security Operations',  'Security tooling and compliance',          NOW() - INTERVAL '180 days', NOW() - INTERVAL '180 days'),
  ('t-payments',  'Payments',             'Payment processing services',              NOW() - INTERVAL '150 days', NOW() - INTERVAL '150 days'),
  ('t-frontend',  'Frontend',             'Web and mobile applications',              NOW() - INTERVAL '150 days', NOW() - INTERVAL '150 days'),
  ('t-data',      'Data Engineering',     'Data pipelines and analytics',             NOW() - INTERVAL '120 days', NOW() - INTERVAL '120 days'),
  ('t-devops',    'DevOps',               'CI/CD and release engineering',            NOW() - INTERVAL '90 days',  NOW() - INTERVAL '90 days')
ON CONFLICT (id) DO NOTHING;

INSERT INTO owners (id, name, email, team_id, created_at, updated_at) VALUES
  ('o-alice',   'Alice Chen',      'alice@example.com',    't-platform',  NOW() - INTERVAL '180 days', NOW() - INTERVAL '180 days'),
  ('o-bob',     'Bob Martinez',    'bob@example.com',      't-security',  NOW() - INTERVAL '180 days', NOW() - INTERVAL '180 days'),
  ('o-carol',   'Carol Williams',  'carol@example.com',    't-payments',  NOW() - INTERVAL '150 days', NOW() - INTERVAL '150 days'),
  ('o-dave',    'Dave Kim',        'dave@example.com',     't-frontend',  NOW() - INTERVAL '150 days', NOW() - INTERVAL '150 days'),
  ('o-eve',     'Eve Johnson',     'eve@example.com',      't-data',      NOW() - INTERVAL '120 days', NOW() - INTERVAL '120 days'),
  ('o-frank',   'Frank Torres',    'frank@example.com',    't-devops',    NOW() - INTERVAL '90 days',  NOW() - INTERVAL '90 days')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 2. Policies
-- ============================================================
INSERT INTO renewal_policies (id, name, renewal_window_days, auto_renew, max_retries, retry_interval_seconds, alert_thresholds_days, created_at, updated_at) VALUES
  ('rp-standard', 'Standard 30-day', 30, true,  3, 60,  '[30, 14, 7, 0]'::jsonb,  NOW() - INTERVAL '180 days', NOW() - INTERVAL '180 days'),
  ('rp-urgent',   'Urgent 14-day',   14, true,  5, 30,  '[14, 7, 3, 0]'::jsonb,   NOW() - INTERVAL '180 days', NOW() - INTERVAL '180 days'),
  ('rp-manual',   'Manual Only',     30, false, 0, 0,   '[30, 14, 7, 0]'::jsonb,  NOW() - INTERVAL '180 days', NOW() - INTERVAL '180 days')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 3. Issuers
-- ============================================================
INSERT INTO issuers (id, name, type, config, enabled, created_at, updated_at) VALUES
  ('iss-local',    'Local Dev CA',           'GenericCA',   '{"ca_common_name": "CertCtl Demo CA", "validity_days": 90}', true,  NOW() - INTERVAL '180 days', NOW() - INTERVAL '180 days'),
  ('iss-acme-le',  'Let''s Encrypt Staging', 'ACME',        '{"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory", "email": "admin@example.com", "challenge_type": "http-01"}', true,  NOW() - INTERVAL '150 days', NOW() - INTERVAL '150 days'),
  ('iss-stepca',   'step-ca Internal',       'StepCA',      '{"ca_url": "https://ca.internal:9000", "provisioner_name": "certctl", "validity_days": 90}', true, NOW() - INTERVAL '120 days', NOW() - INTERVAL '120 days'),
  ('iss-acme-zs',  'ZeroSSL (EAB)',          'ACME',        '{"directory_url": "https://acme.zerossl.com/v2/DV90", "email": "admin@example.com", "challenge_type": "http-01"}', true,  NOW() - INTERVAL '60 days', NOW() - INTERVAL '60 days'),
  ('iss-openssl',  'Custom OpenSSL CA',      'OpenSSL',     '{"sign_script": "/opt/ca/sign.sh", "timeout_seconds": 30}', false, NOW() - INTERVAL '30 days', NOW() - INTERVAL '30 days'),
  ('iss-vault',    'HashiCorp Vault PKI',   'VaultPKI',    '{"addr": "https://vault.internal:8200", "mount": "pki", "role": "web-certs", "ttl": "8760h"}', true, NOW() - INTERVAL '20 days', NOW() - INTERVAL '20 days'),
  ('iss-digicert', 'DigiCert CertCentral',  'DigiCert',    '{"base_url": "https://www.digicert.com/services/v2", "product_type": "ssl_basic"}', true, NOW() - INTERVAL '15 days', NOW() - INTERVAL '15 days'),
  ('iss-sectigo',  'Sectigo SCM',           'Sectigo',     '{"base_url": "https://cert-manager.com/api", "cert_type": 423, "term": 365}', true, NOW() - INTERVAL '10 days', NOW() - INTERVAL '10 days'),
  ('iss-googlecas','Google CAS',            'GoogleCAS',   '{"project": "demo-project", "location": "us-central1", "ca_pool": "demo-pool"}', false, NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days'),
  ('iss-awsacmpca','AWS ACM Private CA',    'AWSACMPCA',   '{"region": "us-east-1", "ca_arn": "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/demo", "signing_algorithm": "SHA256WITHRSA", "validity_days": 365}', false, NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days'),
  ('iss-entrust',  'Entrust CA',            'Entrust',     '{"api_url": "https://api.managed.entrust.com/v1/", "ca_id": "demo-ca-id"}', false, NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days'),
  ('iss-globalsign','GlobalSign Atlas',      'GlobalSign',  '{"api_url": "https://emea.api.hvca.globalsign.com:8443/v2/"}', false, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),
  ('iss-ejbca',    'EJBCA Enterprise',       'EJBCA',       '{"api_url": "https://ejbca.internal:8443/ejbca/ejbca-rest-api/v1", "auth_mode": "mtls", "ca_name": "DemoCA"}', false, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 4. Agents (8 agents across multiple platforms)
-- ============================================================
INSERT INTO agents (id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash, os, architecture, ip_address, version) VALUES
  ('ag-web-prod',    'web-prod-agent',    'web-prod-01.internal',    'Online',  NOW() - INTERVAL '30 seconds',  NOW() - INTERVAL '120 days', 'demo_hash_1', 'linux',   'amd64', '10.0.1.10', '2.0.14'),
  ('ag-web-staging', 'web-staging-agent', 'web-stg-01.internal',    'Online',  NOW() - INTERVAL '45 seconds',  NOW() - INTERVAL '90 days',  'demo_hash_2', 'linux',   'amd64', '10.0.2.20', '2.0.14'),
  ('ag-lb-prod',     'lb-prod-agent',     'lb-prod-01.internal',    'Online',  NOW() - INTERVAL '15 seconds',  NOW() - INTERVAL '150 days', 'demo_hash_3', 'linux',   'amd64', '10.0.1.50', '2.0.14'),
  ('ag-iis-prod',    'iis-prod-agent',    'iis-prod-01.internal',   'Offline', NOW() - INTERVAL '3 hours',     NOW() - INTERVAL '60 days',  'demo_hash_4', 'windows', 'amd64', '10.0.3.15', '2.0.12'),
  ('ag-data-prod',   'data-prod-agent',   'data-prod-01.internal',  'Online',  NOW() - INTERVAL '20 seconds',  NOW() - INTERVAL '90 days',  'demo_hash_5', 'linux',   'arm64', '10.0.4.30', '2.0.14'),
  ('ag-edge-01',     'edge-eu-agent',     'edge-eu-01.internal',    'Online',  NOW() - INTERVAL '50 seconds',  NOW() - INTERVAL '45 days',  'demo_hash_6', 'linux',   'arm64', '10.0.5.10', '2.0.14'),
  ('ag-k8s-prod',    'k8s-prod-agent',    'k8s-node-01.internal',   'Online',  NOW() - INTERVAL '10 seconds',  NOW() - INTERVAL '30 days',  'demo_hash_7', 'linux',   'amd64', '10.0.6.10', '2.0.14'),
  ('ag-mac-dev',     'mac-dev-agent',     'dev-mac-01.internal',    'Online',  NOW() - INTERVAL '60 seconds',  NOW() - INTERVAL '15 days',  'demo_hash_8', 'darwin',  'arm64', '10.0.7.5',  '2.0.14')
ON CONFLICT (id) DO NOTHING;

-- Sentinel agent for network-discovered certificates
INSERT INTO agents (id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash, os, architecture, ip_address, version) VALUES
  ('server-scanner', 'Network Scanner (Server-Side)', 'certctl-server', 'Online', NOW(), NOW() - INTERVAL '90 days', 'sentinel_no_auth', 'linux', 'amd64', '127.0.0.1', '2.0.14')
ON CONFLICT (id) DO NOTHING;

-- Sentinel agents for cloud discovery sources (M50)
INSERT INTO agents (id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash, os, architecture, ip_address, version) VALUES
  ('cloud-aws-sm',   'AWS Secrets Manager Discovery',  'certctl-server', 'Online', NOW(), NOW() - INTERVAL '90 days', 'sentinel_no_auth', 'linux', 'amd64', '127.0.0.1', '2.1.0'),
  ('cloud-azure-kv', 'Azure Key Vault Discovery',      'certctl-server', 'Online', NOW(), NOW() - INTERVAL '90 days', 'sentinel_no_auth', 'linux', 'amd64', '127.0.0.1', '2.1.0'),
  ('cloud-gcp-sm',   'GCP Secret Manager Discovery',   'certctl-server', 'Online', NOW(), NOW() - INTERVAL '90 days', 'sentinel_no_auth', 'linux', 'amd64', '127.0.0.1', '2.1.0')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 5. Deployment Targets (8 targets across multiple connector types)
-- ============================================================
INSERT INTO deployment_targets (id, name, type, agent_id, config, enabled, created_at, updated_at) VALUES
  ('tgt-nginx-prod',    'NGINX Production',     'NGINX',    'ag-web-prod',    '{"cert_path": "/etc/nginx/ssl/cert.pem", "key_path": "/etc/nginx/ssl/key.pem", "reload_command": "nginx -s reload"}', true,  NOW() - INTERVAL '120 days', NOW()),
  ('tgt-nginx-staging', 'NGINX Staging',        'NGINX',    'ag-web-staging', '{"cert_path": "/etc/nginx/ssl/cert.pem", "key_path": "/etc/nginx/ssl/key.pem", "reload_command": "nginx -s reload"}', true,  NOW() - INTERVAL '90 days',  NOW()),
  ('tgt-haproxy-prod',  'HAProxy Production',   'HAProxy',  'ag-lb-prod',    '{"combined_pem_path": "/etc/haproxy/ssl/site.pem", "reload_command": "systemctl reload haproxy"}', true,  NOW() - INTERVAL '150 days', NOW()),
  ('tgt-apache-prod',   'Apache Production',    'Apache',   'ag-web-prod',   '{"cert_path": "/etc/httpd/ssl/cert.pem", "key_path": "/etc/httpd/ssl/key.pem", "chain_path": "/etc/httpd/ssl/chain.pem", "reload_command": "apachectl graceful"}', true, NOW() - INTERVAL '100 days', NOW()),
  ('tgt-iis-prod',      'IIS Production',       'IIS',      'ag-iis-prod',   '{"site_name": "Default Web Site", "binding_info": "*:443:"}', true,  NOW() - INTERVAL '60 days', NOW()),
  ('tgt-traefik-prod',  'Traefik Production',   'Traefik',  'ag-k8s-prod',   '{"watch_dir": "/etc/traefik/dynamic/certs"}', true, NOW() - INTERVAL '30 days', NOW()),
  ('tgt-caddy-prod',    'Caddy Production',     'Caddy',    'ag-edge-01',    '{"mode": "api", "admin_url": "http://localhost:2019"}', true, NOW() - INTERVAL '45 days', NOW()),
  ('tgt-nginx-data',    'NGINX Data Services',  'NGINX',    'ag-data-prod',  '{"cert_path": "/etc/nginx/ssl/cert.pem", "key_path": "/etc/nginx/ssl/key.pem", "reload_command": "nginx -s reload"}', true,  NOW() - INTERVAL '90 days', NOW()),
  -- Rank 5 cloud target seed rows (2026-05-03 deep-research deliverable).
  -- AWS ACM and Azure Key Vault demo targets so QA can exercise the wiring
  -- end-to-end without standing up a real cloud account.
  ('tgt-aws-acm-prod',  'AWS ACM Production',    'AWSACM',         'ag-server',      '{"region": "us-east-1", "tags": {"env": "production", "app": "api-gateway"}}', true, NOW() - INTERVAL '7 days', NOW()),
  ('tgt-azure-kv-prod', 'Azure KeyVault Prod',   'AzureKeyVault',  'ag-server',      '{"vault_url": "https://prod-vault.vault.azure.net", "certificate_name": "api-prod", "credential_mode": "managed_identity", "tags": {"env": "production"}}', true, NOW() - INTERVAL '7 days', NOW())
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 6. Certificate Profiles
-- ============================================================
INSERT INTO certificate_profiles (id, name, description, allowed_key_algorithms, max_ttl_seconds, allowed_ekus, required_san_patterns, spiffe_uri_pattern, allow_short_lived, enabled, created_at, updated_at) VALUES
  ('prof-standard-tls', 'Standard TLS',
   'Default profile for web-facing TLS certificates. Requires ECDSA P-256+ or RSA 2048+.',
   '[{"algorithm": "ECDSA", "min_size": 256}, {"algorithm": "RSA", "min_size": 2048}]'::jsonb,
   7776000, -- 90 days
   '["serverAuth"]'::jsonb,
   '[]'::jsonb,
   '', false, true, NOW() - INTERVAL '180 days', NOW()),

  ('prof-internal-mtls', 'Internal mTLS',
   'Mutual TLS profile for internal service-to-service communication.',
   '[{"algorithm": "ECDSA", "min_size": 256}]'::jsonb,
   2592000, -- 30 days
   '["serverAuth", "clientAuth"]'::jsonb,
   '[".*\\.internal\\.example\\.com$"]'::jsonb,
   '', false, true, NOW() - INTERVAL '150 days', NOW()),

  ('prof-short-lived', 'Short-Lived Credential',
   'Ephemeral certificates for CI/CD pipelines and container workloads. TTL under 1 hour, expiry = revocation.',
   '[{"algorithm": "ECDSA", "min_size": 256}]'::jsonb,
   300, -- 5 minutes
   '["serverAuth", "clientAuth"]'::jsonb,
   '[]'::jsonb,
   'spiffe://example.com/workload/*',
   true, true, NOW() - INTERVAL '120 days', NOW()),

  ('prof-high-security', 'High Security',
   'For PCI-DSS and compliance-sensitive workloads. RSA 4096+ or ECDSA P-384+ only.',
   '[{"algorithm": "ECDSA", "min_size": 384}, {"algorithm": "RSA", "min_size": 4096}]'::jsonb,
   4060800, -- 47 days (Ballot SC-081v3 target)
   '["serverAuth"]'::jsonb,
   '[".*\\.example\\.com$"]'::jsonb,
   '', false, true, NOW() - INTERVAL '90 days', NOW()),

  ('prof-smime', 'S/MIME Email',
   'S/MIME certificate profile for email signing and encryption. Requires emailProtection EKU.',
   '[{"algorithm": "ECDSA", "min_size": 256}, {"algorithm": "RSA", "min_size": 2048}]'::jsonb,
   31536000, -- 365 days
   '["emailProtection"]'::jsonb,
   '[]'::jsonb,
   '', false, true, NOW() - INTERVAL '60 days', NOW())
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 7. Managed Certificates (32 certs across multiple issuers and environments)
-- ============================================================
INSERT INTO managed_certificates (id, name, common_name, sans, environment, owner_id, team_id, issuer_id, renewal_policy_id, status, expires_at, tags, last_renewal_at, last_deployment_at, created_at, updated_at) VALUES
  -- ---- Active, healthy production certs (Local CA) ----
  ('mc-api-prod',      'api-production',       'api.example.com',       ARRAY['api.example.com', 'api-v2.example.com'],                 'production',  'o-alice', 't-platform', 'iss-local', 'rp-standard', 'Active',   NOW() + INTERVAL '75 days',  '{"service": "api-gateway", "tier": "critical"}',   NOW() - INTERVAL '15 days', NOW() - INTERVAL '15 days', NOW() - INTERVAL '180 days', NOW()),
  ('mc-web-prod',      'web-production',       'www.example.com',       ARRAY['www.example.com', 'example.com'],                        'production',  'o-dave',  't-frontend', 'iss-local', 'rp-standard', 'Active',   NOW() + INTERVAL '60 days',  '{"service": "web-app", "tier": "critical"}',       NOW() - INTERVAL '30 days', NOW() - INTERVAL '30 days', NOW() - INTERVAL '365 days', NOW()),
  ('mc-pay-prod',      'payments-production',  'pay.example.com',       ARRAY['pay.example.com', 'checkout.example.com'],               'production',  'o-carol', 't-payments', 'iss-local', 'rp-urgent',   'Active',   NOW() + INTERVAL '40 days',  '{"service": "payments", "tier": "critical", "pci": "true"}', NOW() - INTERVAL '50 days', NOW() - INTERVAL '50 days', NOW() - INTERVAL '200 days', NOW()),
  ('mc-dash-prod',     'dashboard-production', 'dashboard.example.com', ARRAY['dashboard.example.com'],                                 'production',  'o-dave',  't-frontend', 'iss-local', 'rp-standard', 'Active',   NOW() + INTERVAL '82 days',  '{"service": "dashboard", "tier": "high"}',         NOW() - INTERVAL '8 days',  NOW() - INTERVAL '8 days',  NOW() - INTERVAL '100 days', NOW()),
  ('mc-data-prod',     'data-api-production',  'data.example.com',      ARRAY['data.example.com', 'analytics.example.com'],             'production',  'o-eve',   't-data',     'iss-local', 'rp-standard', 'Active',   NOW() + INTERVAL '55 days',  '{"service": "data-api", "tier": "high"}',          NOW() - INTERVAL '35 days', NOW() - INTERVAL '35 days', NOW() - INTERVAL '150 days', NOW()),
  ('mc-search-prod',   'search-production',    'search.example.com',    ARRAY['search.example.com', 'es.example.com'],                  'production',  'o-eve',   't-data',     'iss-local', 'rp-standard', 'Active',   NOW() + INTERVAL '68 days',  '{"service": "search", "tier": "high"}',            NOW() - INTERVAL '22 days', NOW() - INTERVAL '22 days', NOW() - INTERVAL '130 days', NOW()),
  ('mc-admin-prod',    'admin-production',     'admin.example.com',     ARRAY['admin.example.com'],                                     'production',  'o-bob',   't-security', 'iss-local', 'rp-urgent',   'Active',   NOW() + INTERVAL '35 days',  '{"service": "admin-panel", "tier": "critical"}',   NOW() - INTERVAL '55 days', NOW() - INTERVAL '55 days', NOW() - INTERVAL '200 days', NOW()),

  -- ---- Active certs via ACME (Let's Encrypt) ----
  ('mc-blog-prod',     'blog-production',      'blog.example.com',      ARRAY['blog.example.com'],                                      'production',  'o-dave',  't-frontend', 'iss-acme-le', 'rp-standard', 'Active', NOW() + INTERVAL '52 days',  '{"service": "blog", "tier": "medium"}',            NOW() - INTERVAL '38 days', NOW() - INTERVAL '38 days', NOW() - INTERVAL '160 days', NOW()),
  ('mc-docs-prod',     'docs-production',      'docs.example.com',      ARRAY['docs.example.com', 'help.example.com'],                  'production',  'o-dave',  't-frontend', 'iss-acme-le', 'rp-standard', 'Active', NOW() + INTERVAL '47 days',  '{"service": "docs", "tier": "medium"}',            NOW() - INTERVAL '43 days', NOW() - INTERVAL '43 days', NOW() - INTERVAL '140 days', NOW()),
  ('mc-status-prod',   'status-production',    'status.example.com',    ARRAY['status.example.com'],                                    'production',  'o-frank', 't-devops',   'iss-acme-le', 'rp-standard', 'Active', NOW() + INTERVAL '71 days',  '{"service": "status-page", "tier": "high"}',       NOW() - INTERVAL '19 days', NOW() - INTERVAL '19 days', NOW() - INTERVAL '80 days',  NOW()),

  -- ---- Active certs via step-ca (internal services) ----
  ('mc-grpc-prod',     'grpc-internal',        'grpc.internal.example.com', ARRAY['grpc.internal.example.com'],                         'production',  'o-alice', 't-platform', 'iss-stepca', 'rp-standard', 'Active',  NOW() + INTERVAL '58 days',  '{"service": "grpc-gateway", "tier": "high"}',      NOW() - INTERVAL '32 days', NOW() - INTERVAL '32 days', NOW() - INTERVAL '100 days', NOW()),
  ('mc-vault-prod',    'vault-internal',       'vault.internal.example.com', ARRAY['vault.internal.example.com'],                       'production',  'o-bob',   't-security', 'iss-stepca', 'rp-urgent',   'Active',  NOW() + INTERVAL '35 days',  '{"service": "vault", "tier": "critical"}',         NOW() - INTERVAL '65 days', NOW() - INTERVAL '65 days', NOW() - INTERVAL '120 days', NOW()),
  ('mc-consul-prod',   'consul-internal',      'consul.internal.example.com', ARRAY['consul.internal.example.com'],                     'production',  'o-alice', 't-platform', 'iss-stepca', 'rp-standard', 'Active',  NOW() + INTERVAL '63 days',  '{"service": "consul", "tier": "high"}',            NOW() - INTERVAL '27 days', NOW() - INTERVAL '27 days', NOW() - INTERVAL '90 days',  NOW()),

  -- ---- Active certs via ZeroSSL ----
  ('mc-shop-prod',     'shop-production',      'shop.example.com',      ARRAY['shop.example.com', 'store.example.com'],                 'production',  'o-carol', 't-payments', 'iss-acme-zs', 'rp-urgent',  'Active',  NOW() + INTERVAL '44 days',  '{"service": "shop", "tier": "critical", "pci": "true"}', NOW() - INTERVAL '46 days', NOW() - INTERVAL '46 days', NOW() - INTERVAL '60 days', NOW()),

  -- ---- Expiring soon ----
  -- NOTE: expires_at is set > 31 days to stay outside the scheduler's 31-day renewal query window.
  -- The scheduler runs CheckExpiringCertificates on boot with a 31-day lookahead; certs inside that
  -- window get renewal jobs created automatically. By placing these at 32-38 days, the status stays
  -- frozen as seeded while still being within the 30-day alert threshold range shown on the dashboard.
  ('mc-auth-prod',     'auth-production',      'auth.example.com',      ARRAY['auth.example.com', 'login.example.com', 'sso.example.com'], 'production', 'o-bob', 't-security', 'iss-local', 'rp-urgent', 'Expiring', NOW() + INTERVAL '32 days',  '{"service": "auth", "tier": "critical"}',          NOW() - INTERVAL '78 days', NOW() - INTERVAL '78 days', NOW() - INTERVAL '300 days', NOW()),
  ('mc-cdn-prod',      'cdn-production',       'cdn.example.com',       ARRAY['cdn.example.com', 'static.example.com'],                 'production',  'o-alice', 't-platform', 'iss-local', 'rp-standard', 'Expiring', NOW() + INTERVAL '34 days',  '{"service": "cdn", "tier": "high"}',               NOW() - INTERVAL '82 days', NOW() - INTERVAL '82 days', NOW() - INTERVAL '250 days', NOW()),
  ('mc-mail-prod',     'mail-production',      'mail.example.com',      ARRAY['mail.example.com', 'smtp.example.com'],                  'production',  'o-bob',   't-security', 'iss-local', 'rp-standard', 'Expiring', NOW() + INTERVAL '33 days',  '{"service": "email", "tier": "medium"}',           NOW() - INTERVAL '85 days', NOW() - INTERVAL '85 days', NOW() - INTERVAL '400 days', NOW()),
  ('mc-ci-prod',       'ci-production',        'ci.example.com',        ARRAY['ci.example.com', 'jenkins.example.com'],                 'production',  'o-frank', 't-devops',   'iss-acme-le', 'rp-standard', 'Expiring', NOW() + INTERVAL '38 days', '{"service": "ci", "tier": "high"}',                NOW() - INTERVAL '72 days', NOW() - INTERVAL '72 days', NOW() - INTERVAL '100 days', NOW()),

  -- ---- Expired ----
  ('mc-legacy-prod',   'legacy-app',           'legacy.example.com',    ARRAY['legacy.example.com'],                                    'production',  'o-alice', 't-platform', 'iss-local', 'rp-manual',   'Expired',  NOW() - INTERVAL '3 days',   '{"service": "legacy", "tier": "low", "decom": "planned"}', NOW() - INTERVAL '93 days', NOW() - INTERVAL '93 days', NOW() - INTERVAL '500 days', NOW()),
  ('mc-old-api',       'old-api-v1',           'api-v1.example.com',    ARRAY['api-v1.example.com'],                                    'production',  'o-alice', 't-platform', 'iss-local', 'rp-manual',   'Expired',  NOW() - INTERVAL '15 days',  '{"service": "api-v1", "tier": "low", "deprecated": "true"}', NULL, NULL, NOW() - INTERVAL '600 days', NOW()),
  ('mc-wiki-prod',     'wiki-production',      'wiki.example.com',      ARRAY['wiki.example.com'],                                      'production',  'o-dave',  't-frontend', 'iss-acme-le', 'rp-manual', 'Expired',  NOW() - INTERVAL '7 days',   '{"service": "wiki", "tier": "low"}',               NOW() - INTERVAL '97 days', NOW() - INTERVAL '97 days', NOW() - INTERVAL '300 days', NOW()),

  -- ---- Staging certs ----
  ('mc-api-stg',       'api-staging',          'api.staging.example.com', ARRAY['api.staging.example.com'],                             'staging',     'o-alice', 't-platform', 'iss-local', 'rp-standard', 'Active',   NOW() + INTERVAL '65 days',  '{"service": "api-gateway", "tier": "low"}',        NOW() - INTERVAL '25 days', NOW() - INTERVAL '25 days', NOW() - INTERVAL '120 days', NOW()),
  ('mc-web-stg',       'web-staging',          'www.staging.example.com', ARRAY['www.staging.example.com', 'staging.example.com'],      'staging',     'o-dave',  't-frontend', 'iss-local', 'rp-standard', 'Active',   NOW() + INTERVAL '70 days',  '{"service": "web-app", "tier": "low"}',            NOW() - INTERVAL '20 days', NOW() - INTERVAL '20 days', NOW() - INTERVAL '100 days', NOW()),
  ('mc-pay-stg',       'payments-staging',     'pay.staging.example.com', ARRAY['pay.staging.example.com'],                             'staging',     'o-carol', 't-payments', 'iss-local', 'rp-standard', 'Active',   NOW() + INTERVAL '72 days',  '{"service": "payments", "tier": "low"}',           NOW() - INTERVAL '18 days', NOW() - INTERVAL '18 days', NOW() - INTERVAL '80 days',  NOW()),

  -- ---- Development certs ----
  ('mc-api-dev',       'api-development',      'api.dev.example.com',   ARRAY['api.dev.example.com'],                                   'development', 'o-alice', 't-platform', 'iss-local', 'rp-standard', 'Active',   NOW() + INTERVAL '85 days',  '{"service": "api-gateway", "tier": "low"}',        NOW() - INTERVAL '5 days',  NOW() - INTERVAL '5 days',  NOW() - INTERVAL '45 days',  NOW()),

  -- ---- Renewal in progress ----
  -- NOTE: expires_at set > 31 days to keep outside scheduler's renewal query window
  ('mc-grafana-prod',  'grafana-production',   'grafana.example.com',   ARRAY['grafana.example.com', 'metrics.example.com'],            'production',  'o-eve',   't-data',     'iss-local', 'rp-standard', 'RenewalInProgress', NOW() + INTERVAL '33 days',  '{"service": "monitoring", "tier": "high"}',  NOW() - INTERVAL '87 days', NOW() - INTERVAL '87 days', NOW() - INTERVAL '180 days', NOW()),

  -- ---- Failed ----
  -- NOTE: expires_at set > 31 days; scheduler code fix also skips Failed certs from auto-renewal
  ('mc-vpn-prod',      'vpn-production',       'vpn.example.com',       ARRAY['vpn.example.com'],                                      'production',  'o-bob',   't-security', 'iss-acme-le', 'rp-urgent', 'Failed',   NOW() + INTERVAL '32 days',  '{"service": "vpn", "tier": "critical"}',           NULL, NULL, NOW() - INTERVAL '90 days', NOW()),

  -- ---- Wildcard ----
  ('mc-wildcard-prod', 'wildcard-production',  '*.example.com',         ARRAY['*.example.com', 'example.com'],                          'production',  'o-alice', 't-platform', 'iss-acme-le', 'rp-standard', 'Active', NOW() + INTERVAL '50 days',  '{"service": "wildcard", "tier": "critical"}',      NOW() - INTERVAL '40 days', NOW() - INTERVAL '40 days', NOW() - INTERVAL '365 days', NOW()),

  -- ---- Revoked ----
  ('mc-compromised',   'compromised-cert',     'old-service.example.com', ARRAY['old-service.example.com'],                             'production',  'o-bob',   't-security', 'iss-local', 'rp-standard', 'Revoked',  NOW() + INTERVAL '45 days',  '{"service": "decommissioned", "tier": "low"}',     NOW() - INTERVAL '60 days', NOW() - INTERVAL '60 days', NOW() - INTERVAL '120 days', NOW()),

  -- ---- Edge/CDN certs (Traefik + Caddy targets) ----
  ('mc-edge-eu',       'edge-eu-production',   'eu.cdn.example.com',    ARRAY['eu.cdn.example.com', 'eu-assets.example.com'],           'production',  'o-alice', 't-platform', 'iss-acme-le', 'rp-standard', 'Active', NOW() + INTERVAL '61 days',  '{"service": "cdn-eu", "tier": "high", "region": "eu-west-1"}', NOW() - INTERVAL '29 days', NOW() - INTERVAL '29 days', NOW() - INTERVAL '45 days', NOW()),
  ('mc-k8s-ingress',   'k8s-ingress',          'ingress.example.com',   ARRAY['ingress.example.com', 'app.example.com'],                'production',  'o-frank', 't-devops',   'iss-acme-le', 'rp-standard', 'Active', NOW() + INTERVAL '56 days',  '{"service": "k8s-ingress", "tier": "critical"}',   NOW() - INTERVAL '34 days', NOW() - INTERVAL '34 days', NOW() - INTERVAL '30 days', NOW()),

  -- ---- S/MIME cert ----
  ('mc-smime-bob',     'bob-email-signing',    'bob@example.com',       ARRAY['bob@example.com'],                                       'production',  'o-bob',   't-security', 'iss-local', 'rp-standard', 'Active',   NOW() + INTERVAL '300 days', '{"type": "smime", "tier": "medium"}',              NOW() - INTERVAL '65 days', NULL, NOW() - INTERVAL '65 days', NOW())
ON CONFLICT (id) DO NOTHING;

-- Mark revoked cert
UPDATE managed_certificates SET revoked_at = NOW() - INTERVAL '14 days', revocation_reason = 'keyCompromise' WHERE id = 'mc-compromised';

-- ============================================================
-- 8. Certificate-Target Mappings
-- ============================================================
INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES
  ('mc-api-prod',      'tgt-nginx-prod'),
  ('mc-api-prod',      'tgt-haproxy-prod'),
  ('mc-web-prod',      'tgt-nginx-prod'),
  ('mc-web-prod',      'tgt-haproxy-prod'),
  ('mc-pay-prod',      'tgt-nginx-prod'),
  ('mc-pay-prod',      'tgt-haproxy-prod'),
  ('mc-dash-prod',     'tgt-nginx-prod'),
  ('mc-data-prod',     'tgt-nginx-data'),
  ('mc-auth-prod',     'tgt-nginx-prod'),
  ('mc-auth-prod',     'tgt-haproxy-prod'),
  ('mc-cdn-prod',      'tgt-haproxy-prod'),
  ('mc-mail-prod',     'tgt-nginx-prod'),
  ('mc-legacy-prod',   'tgt-iis-prod'),
  ('mc-blog-prod',     'tgt-nginx-prod'),
  ('mc-docs-prod',     'tgt-nginx-prod'),
  ('mc-status-prod',   'tgt-nginx-prod'),
  ('mc-grpc-prod',     'tgt-nginx-prod'),
  ('mc-vault-prod',    'tgt-nginx-prod'),
  ('mc-search-prod',   'tgt-nginx-data'),
  ('mc-admin-prod',    'tgt-nginx-prod'),
  ('mc-shop-prod',     'tgt-nginx-prod'),
  ('mc-shop-prod',     'tgt-haproxy-prod'),
  ('mc-ci-prod',       'tgt-nginx-prod'),
  ('mc-edge-eu',       'tgt-caddy-prod'),
  ('mc-k8s-ingress',   'tgt-traefik-prod'),
  ('mc-api-stg',       'tgt-nginx-staging'),
  ('mc-web-stg',       'tgt-nginx-staging'),
  ('mc-pay-stg',       'tgt-nginx-staging'),
  ('mc-grafana-prod',  'tgt-nginx-data'),
  ('mc-vpn-prod',      'tgt-haproxy-prod'),
  ('mc-wildcard-prod', 'tgt-nginx-prod'),
  ('mc-wildcard-prod', 'tgt-haproxy-prod'),
  ('mc-wildcard-prod', 'tgt-nginx-staging'),
  ('mc-compromised',   'tgt-nginx-prod')
ON CONFLICT DO NOTHING;

-- ============================================================
-- 9. Certificate Versions (latest version for active/expiring certs)
-- ============================================================
INSERT INTO certificate_versions (id, certificate_id, serial_number, not_before, not_after, fingerprint_sha256, pem_chain, csr_pem, created_at) VALUES
  ('cv-api-v3',    'mc-api-prod',      '0A:1B:2C:3D:4E:5F:00:01', NOW() - INTERVAL '15 days', NOW() + INTERVAL '75 days',  'sha256:ab12cd34ef5600', '-----BEGIN CERTIFICATE-----\nMIIDemoAPI...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '15 days'),
  ('cv-api-v2',    'mc-api-prod',      '0A:1B:2C:3D:4E:5F:AA:01', NOW() - INTERVAL '105 days', NOW() - INTERVAL '15 days', 'sha256:ab12cd34ef5601', '-----BEGIN CERTIFICATE-----\nMIIDemoAPIv2...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '105 days'),
  ('cv-web-v2',    'mc-web-prod',      '0A:1B:2C:3D:4E:5F:00:02', NOW() - INTERVAL '30 days', NOW() + INTERVAL '60 days',  'sha256:cd34ef56ab1200', '-----BEGIN CERTIFICATE-----\nMIIDemoWeb...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '30 days'),
  ('cv-pay-v4',    'mc-pay-prod',      '0A:1B:2C:3D:4E:5F:00:03', NOW() - INTERVAL '50 days', NOW() + INTERVAL '40 days',  'sha256:ef56ab12cd3400', '-----BEGIN CERTIFICATE-----\nMIIDemoPay...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '50 days'),
  ('cv-auth-v5',   'mc-auth-prod',     '0A:1B:2C:3D:4E:5F:00:04', NOW() - INTERVAL '78 days', NOW() + INTERVAL '12 days',  'sha256:1234abcdef5600', '-----BEGIN CERTIFICATE-----\nMIIDemoAuth...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '78 days'),
  ('cv-wild-v3',   'mc-wildcard-prod', '0A:1B:2C:3D:4E:5F:00:05', NOW() - INTERVAL '40 days', NOW() + INTERVAL '50 days',  'sha256:5678abcdef1200', '-----BEGIN CERTIFICATE-----\nMIIDemoWild...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '40 days'),
  ('cv-dash-v2',   'mc-dash-prod',     '0A:1B:2C:3D:4E:5F:00:06', NOW() - INTERVAL '8 days',  NOW() + INTERVAL '82 days',  'sha256:dash12345600', '-----BEGIN CERTIFICATE-----\nMIIDemoDash...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '8 days'),
  ('cv-data-v3',   'mc-data-prod',     '0A:1B:2C:3D:4E:5F:00:07', NOW() - INTERVAL '35 days', NOW() + INTERVAL '55 days',  'sha256:data12345600', '-----BEGIN CERTIFICATE-----\nMIIDemoData...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '35 days'),
  ('cv-blog-v2',   'mc-blog-prod',     '0A:1B:2C:3D:4E:5F:00:08', NOW() - INTERVAL '38 days', NOW() + INTERVAL '52 days',  'sha256:blog12345600', '-----BEGIN CERTIFICATE-----\nMIIDemoBlog...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '38 days'),
  ('cv-grpc-v2',   'mc-grpc-prod',     '0A:1B:2C:3D:4E:5F:00:09', NOW() - INTERVAL '32 days', NOW() + INTERVAL '58 days',  'sha256:grpc12345600', '-----BEGIN CERTIFICATE-----\nMIIDemoGRPC...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '32 days'),
  ('cv-shop-v1',   'mc-shop-prod',     '0A:1B:2C:3D:4E:5F:00:10', NOW() - INTERVAL '46 days', NOW() + INTERVAL '44 days',  'sha256:shop12345600', '-----BEGIN CERTIFICATE-----\nMIIDemoShop...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '46 days'),
  ('cv-edge-v1',   'mc-edge-eu',       '0A:1B:2C:3D:4E:5F:00:11', NOW() - INTERVAL '29 days', NOW() + INTERVAL '61 days',  'sha256:edge12345600', '-----BEGIN CERTIFICATE-----\nMIIDemoEdge...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '29 days'),
  ('cv-k8s-v1',    'mc-k8s-ingress',   '0A:1B:2C:3D:4E:5F:00:12', NOW() - INTERVAL '34 days', NOW() + INTERVAL '56 days',  'sha256:k8si12345600', '-----BEGIN CERTIFICATE-----\nMIIDemoK8s...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '34 days'),
  ('cv-vpn-v2',    'mc-vpn-prod',      '0A:1B:2C:3D:4E:5F:00:13', NOW() - INTERVAL '90 days', NOW() + INTERVAL '1 day',    'sha256:vpn012345600', '-----BEGIN CERTIFICATE-----\nMIIDemoVPN...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '90 days'),
  ('cv-compro-v1', 'mc-compromised',   '0A:1B:2C:3D:4E:5F:00:14', NOW() - INTERVAL '60 days', NOW() + INTERVAL '30 days',  'sha256:comp12345600', '-----BEGIN CERTIFICATE-----\nMIIDemoComp...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '60 days'),
  ('cv-smime-v1',  'mc-smime-bob',     '0A:1B:2C:3D:4E:5F:00:15', NOW() - INTERVAL '65 days', NOW() + INTERVAL '300 days', 'sha256:smime1234560', '-----BEGIN CERTIFICATE-----\nMIIDemoSMIME...\n-----END CERTIFICATE-----', NULL, NOW() - INTERVAL '65 days')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 10. Certificate Revocations
-- ============================================================
INSERT INTO certificate_revocations (id, certificate_id, serial_number, reason, revoked_by, revoked_at, issuer_id, issuer_notified, created_at) VALUES
  ('cr-compro-01', 'mc-compromised', '0A:1B:2C:3D:4E:5F:00:14', 'keyCompromise', 'bob@example.com', NOW() - INTERVAL '14 days', 'iss-local', true, NOW() - INTERVAL '14 days')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 11. Jobs — 90 days of realistic job history
-- Simulates weekly renewal cycles, deployment chains, and some failures
-- ============================================================
INSERT INTO jobs (id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts, last_error, scheduled_at, started_at, completed_at, created_at, verification_status) VALUES
  -- ---- Week 1 (90 days ago): Initial issuances ----
  ('job-iss-001', 'issuance',   'mc-api-prod',     NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '90 days',  NOW() - INTERVAL '90 days',  NOW() - INTERVAL '90 days' + INTERVAL '10 seconds', NOW() - INTERVAL '90 days', 'success'),
  ('job-dep-001', 'deployment', 'mc-api-prod',     'tgt-nginx-prod',   'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '90 days',  NOW() - INTERVAL '90 days' + INTERVAL '15 seconds', NOW() - INTERVAL '90 days' + INTERVAL '25 seconds', NOW() - INTERVAL '90 days', 'success'),

  -- ---- Week 3 (77 days ago): Renewal cycle ----
  ('job-ren-010', 'renewal',    'mc-web-prod',     NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '77 days',  NOW() - INTERVAL '77 days',  NOW() - INTERVAL '77 days' + INTERVAL '12 seconds', NOW() - INTERVAL '77 days', 'success'),
  ('job-dep-010', 'deployment', 'mc-web-prod',     'tgt-nginx-prod',   'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '77 days',  NOW() - INTERVAL '77 days' + INTERVAL '15 seconds', NOW() - INTERVAL '77 days' + INTERVAL '22 seconds', NOW() - INTERVAL '77 days', 'success'),
  ('job-dep-011', 'deployment', 'mc-web-prod',     'tgt-haproxy-prod', 'ag-lb-prod',     'Completed', 1, 3, NULL, NOW() - INTERVAL '77 days',  NOW() - INTERVAL '77 days' + INTERVAL '15 seconds', NOW() - INTERVAL '77 days' + INTERVAL '24 seconds', NOW() - INTERVAL '77 days', 'success'),

  -- ---- Week 5 (63 days ago): step-ca renewals ----
  ('job-ren-020', 'renewal',    'mc-grpc-prod',    NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '63 days',  NOW() - INTERVAL '63 days',  NOW() - INTERVAL '63 days' + INTERVAL '8 seconds',  NOW() - INTERVAL '63 days', 'success'),
  ('job-dep-020', 'deployment', 'mc-grpc-prod',    'tgt-nginx-prod',   'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '63 days',  NOW() - INTERVAL '63 days' + INTERVAL '10 seconds', NOW() - INTERVAL '63 days' + INTERVAL '18 seconds', NOW() - INTERVAL '63 days', 'success'),

  -- ---- Week 6 (56 days ago): Failed renewal attempt ----
  ('job-ren-030', 'renewal',    'mc-vpn-prod',     NULL,               'ag-lb-prod',     'Failed',    3, 3, 'ACME challenge failed: DNS timeout after 30s', NOW() - INTERVAL '56 days', NOW() - INTERVAL '56 days', NOW() - INTERVAL '56 days' + INTERVAL '35 seconds', NOW() - INTERVAL '56 days', NULL),

  -- ---- Week 7 (50 days ago): Payments renewal ----
  ('job-ren-040', 'renewal',    'mc-pay-prod',     NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '50 days',  NOW() - INTERVAL '50 days',  NOW() - INTERVAL '50 days' + INTERVAL '11 seconds', NOW() - INTERVAL '50 days', 'success'),
  ('job-dep-040', 'deployment', 'mc-pay-prod',     'tgt-nginx-prod',   'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '50 days',  NOW() - INTERVAL '50 days' + INTERVAL '14 seconds', NOW() - INTERVAL '50 days' + INTERVAL '22 seconds', NOW() - INTERVAL '50 days', 'success'),
  ('job-dep-041', 'deployment', 'mc-pay-prod',     'tgt-haproxy-prod', 'ag-lb-prod',     'Completed', 1, 3, NULL, NOW() - INTERVAL '50 days',  NOW() - INTERVAL '50 days' + INTERVAL '14 seconds', NOW() - INTERVAL '50 days' + INTERVAL '25 seconds', NOW() - INTERVAL '50 days', 'success'),

  -- ---- Week 8 (46 days ago): ZeroSSL issuance ----
  ('job-iss-050', 'issuance',   'mc-shop-prod',    NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '46 days',  NOW() - INTERVAL '46 days',  NOW() - INTERVAL '46 days' + INTERVAL '18 seconds', NOW() - INTERVAL '46 days', 'success'),
  ('job-dep-050', 'deployment', 'mc-shop-prod',    'tgt-nginx-prod',   'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '46 days',  NOW() - INTERVAL '46 days' + INTERVAL '20 seconds', NOW() - INTERVAL '46 days' + INTERVAL '28 seconds', NOW() - INTERVAL '46 days', 'success'),

  -- ---- Week 9 (43 days ago): Docs renewal (ACME) ----
  ('job-ren-060', 'renewal',    'mc-docs-prod',    NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '43 days',  NOW() - INTERVAL '43 days',  NOW() - INTERVAL '43 days' + INTERVAL '15 seconds', NOW() - INTERVAL '43 days', 'success'),
  ('job-dep-060', 'deployment', 'mc-docs-prod',    'tgt-nginx-prod',   'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '43 days',  NOW() - INTERVAL '43 days' + INTERVAL '18 seconds', NOW() - INTERVAL '43 days' + INTERVAL '26 seconds', NOW() - INTERVAL '43 days', 'success'),

  -- ---- Week 10 (40 days ago): Wildcard renewal (DNS-01) ----
  ('job-ren-070', 'renewal',    'mc-wildcard-prod', NULL,              'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '40 days',  NOW() - INTERVAL '40 days',  NOW() - INTERVAL '40 days' + INTERVAL '45 seconds', NOW() - INTERVAL '40 days', 'success'),
  ('job-dep-070', 'deployment', 'mc-wildcard-prod', 'tgt-nginx-prod',  'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '40 days',  NOW() - INTERVAL '40 days' + INTERVAL '48 seconds', NOW() - INTERVAL '40 days' + INTERVAL '55 seconds', NOW() - INTERVAL '40 days', 'success'),

  -- ---- Week 11 (38 days ago): Blog renewal ----
  ('job-ren-075', 'renewal',    'mc-blog-prod',    NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '38 days',  NOW() - INTERVAL '38 days',  NOW() - INTERVAL '38 days' + INTERVAL '14 seconds', NOW() - INTERVAL '38 days', 'success'),
  ('job-dep-075', 'deployment', 'mc-blog-prod',    'tgt-nginx-prod',   'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '38 days',  NOW() - INTERVAL '38 days' + INTERVAL '16 seconds', NOW() - INTERVAL '38 days' + INTERVAL '24 seconds', NOW() - INTERVAL '38 days', 'success'),

  -- ---- Week 11 (35 days ago): Data API renewal ----
  ('job-ren-080', 'renewal',    'mc-data-prod',    NULL,               'ag-data-prod',   'Completed', 1, 3, NULL, NOW() - INTERVAL '35 days',  NOW() - INTERVAL '35 days',  NOW() - INTERVAL '35 days' + INTERVAL '9 seconds',  NOW() - INTERVAL '35 days', 'success'),
  ('job-dep-080', 'deployment', 'mc-data-prod',    'tgt-nginx-data',   'ag-data-prod',   'Completed', 1, 3, NULL, NOW() - INTERVAL '35 days',  NOW() - INTERVAL '35 days' + INTERVAL '12 seconds', NOW() - INTERVAL '35 days' + INTERVAL '19 seconds', NOW() - INTERVAL '35 days', 'success'),

  -- ---- Week 12 (34 days ago): K8s ingress issuance ----
  ('job-iss-085', 'issuance',   'mc-k8s-ingress',  NULL,              'ag-k8s-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '34 days',  NOW() - INTERVAL '34 days',  NOW() - INTERVAL '34 days' + INTERVAL '16 seconds', NOW() - INTERVAL '34 days', 'success'),
  ('job-dep-085', 'deployment', 'mc-k8s-ingress',  'tgt-traefik-prod','ag-k8s-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '34 days',  NOW() - INTERVAL '34 days' + INTERVAL '18 seconds', NOW() - INTERVAL '34 days' + INTERVAL '24 seconds', NOW() - INTERVAL '34 days', 'success'),

  -- ---- Week 12 (30 days ago): Web prod renewal ----
  ('job-ren-090', 'renewal',    'mc-web-prod',     NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '30 days',  NOW() - INTERVAL '30 days',  NOW() - INTERVAL '30 days' + INTERVAL '11 seconds', NOW() - INTERVAL '30 days', 'success'),
  ('job-dep-090', 'deployment', 'mc-web-prod',     'tgt-nginx-prod',   'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '30 days',  NOW() - INTERVAL '30 days' + INTERVAL '14 seconds', NOW() - INTERVAL '30 days' + INTERVAL '21 seconds', NOW() - INTERVAL '30 days', 'success'),
  ('job-dep-091', 'deployment', 'mc-web-prod',     'tgt-haproxy-prod', 'ag-lb-prod',     'Completed', 1, 3, NULL, NOW() - INTERVAL '30 days',  NOW() - INTERVAL '30 days' + INTERVAL '14 seconds', NOW() - INTERVAL '30 days' + INTERVAL '23 seconds', NOW() - INTERVAL '30 days', 'success'),

  -- ---- Week 13 (29 days ago): Edge EU issuance ----
  ('job-iss-093', 'issuance',   'mc-edge-eu',      NULL,              'ag-edge-01',     'Completed', 1, 3, NULL, NOW() - INTERVAL '29 days',  NOW() - INTERVAL '29 days',  NOW() - INTERVAL '29 days' + INTERVAL '13 seconds', NOW() - INTERVAL '29 days', 'success'),
  ('job-dep-093', 'deployment', 'mc-edge-eu',      'tgt-caddy-prod',  'ag-edge-01',     'Completed', 1, 3, NULL, NOW() - INTERVAL '29 days',  NOW() - INTERVAL '29 days' + INTERVAL '15 seconds', NOW() - INTERVAL '29 days' + INTERVAL '20 seconds', NOW() - INTERVAL '29 days', 'success'),

  -- ---- Week 13 (27 days ago): Consul renewal ----
  ('job-ren-095', 'renewal',    'mc-consul-prod',  NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '27 days',  NOW() - INTERVAL '27 days',  NOW() - INTERVAL '27 days' + INTERVAL '9 seconds',  NOW() - INTERVAL '27 days', 'success'),

  -- ---- Week 14 (22 days ago): Search renewal ----
  ('job-ren-100', 'renewal',    'mc-search-prod',  NULL,               'ag-data-prod',   'Completed', 1, 3, NULL, NOW() - INTERVAL '22 days',  NOW() - INTERVAL '22 days',  NOW() - INTERVAL '22 days' + INTERVAL '10 seconds', NOW() - INTERVAL '22 days', 'success'),
  ('job-dep-100', 'deployment', 'mc-search-prod',  'tgt-nginx-data',   'ag-data-prod',   'Completed', 1, 3, NULL, NOW() - INTERVAL '22 days',  NOW() - INTERVAL '22 days' + INTERVAL '13 seconds', NOW() - INTERVAL '22 days' + INTERVAL '20 seconds', NOW() - INTERVAL '22 days', 'success'),

  -- ---- Week 14 (19 days ago): Status page renewal ----
  ('job-ren-105', 'renewal',    'mc-status-prod',  NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '19 days',  NOW() - INTERVAL '19 days',  NOW() - INTERVAL '19 days' + INTERVAL '12 seconds', NOW() - INTERVAL '19 days', 'success'),
  ('job-dep-105', 'deployment', 'mc-status-prod',  'tgt-nginx-prod',   'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '19 days',  NOW() - INTERVAL '19 days' + INTERVAL '15 seconds', NOW() - INTERVAL '19 days' + INTERVAL '22 seconds', NOW() - INTERVAL '19 days', 'success'),

  -- ---- Week 15 (15 days ago): API prod renewal ----
  ('job-ren-110', 'renewal',    'mc-api-prod',     NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '15 days',  NOW() - INTERVAL '15 days',  NOW() - INTERVAL '15 days' + INTERVAL '10 seconds', NOW() - INTERVAL '15 days', 'success'),
  ('job-dep-110', 'deployment', 'mc-api-prod',     'tgt-nginx-prod',   'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '15 days',  NOW() - INTERVAL '15 days' + INTERVAL '13 seconds', NOW() - INTERVAL '15 days' + INTERVAL '20 seconds', NOW() - INTERVAL '15 days', 'success'),
  ('job-dep-111', 'deployment', 'mc-api-prod',     'tgt-haproxy-prod', 'ag-lb-prod',     'Completed', 1, 3, NULL, NOW() - INTERVAL '15 days',  NOW() - INTERVAL '15 days' + INTERVAL '13 seconds', NOW() - INTERVAL '15 days' + INTERVAL '22 seconds', NOW() - INTERVAL '15 days', 'success'),

  -- ---- Revocation job (14 days ago) ----
  ('job-rev-120', 'validation', 'mc-compromised',  NULL,               'ag-web-prod',    'Completed', 1, 1, NULL, NOW() - INTERVAL '14 days',  NOW() - INTERVAL '14 days',  NOW() - INTERVAL '14 days' + INTERVAL '2 seconds',  NOW() - INTERVAL '14 days', NULL),

  -- ---- Week 16 (8 days ago): Dashboard renewal ----
  ('job-ren-130', 'renewal',    'mc-dash-prod',    NULL,               'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '8 days',   NOW() - INTERVAL '8 days',   NOW() - INTERVAL '8 days' + INTERVAL '9 seconds',   NOW() - INTERVAL '8 days', 'success'),
  ('job-dep-130', 'deployment', 'mc-dash-prod',    'tgt-nginx-prod',   'ag-web-prod',    'Completed', 1, 3, NULL, NOW() - INTERVAL '8 days',   NOW() - INTERVAL '8 days' + INTERVAL '11 seconds',  NOW() - INTERVAL '8 days' + INTERVAL '18 seconds',  NOW() - INTERVAL '8 days', 'success'),

  -- ---- Failed VPN renewal retries (recent) ----
  ('job-ren-140', 'renewal',    'mc-vpn-prod',     NULL,               'ag-lb-prod',     'Failed',    3, 3, 'ACME HTTP-01 challenge: connection refused on port 80', NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days' + INTERVAL '32 seconds', NOW() - INTERVAL '3 days', NULL),

  -- ---- Grafana renewal in progress ----
  ('job-ren-150', 'renewal',    'mc-grafana-prod', NULL,               'ag-data-prod',   'Running',   1, 3, NULL, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '2 hours', NULL, NOW() - INTERVAL '2 hours', NULL),

  -- ---- Awaiting approval ----
  ('job-approval-01', 'renewal', 'mc-auth-prod',   NULL,               'ag-web-prod',    'AwaitingApproval', 0, 3, NULL, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour', NULL, NOW() - INTERVAL '1 hour', NULL),
  ('job-approval-02', 'renewal', 'mc-pay-prod',    NULL,               'ag-web-prod',    'AwaitingApproval', 0, 3, NULL, NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '30 minutes', NULL, NOW() - INTERVAL '30 minutes', NULL),

  -- ---- Development API issuance (5 days ago) ----
  ('job-iss-160', 'issuance',   'mc-api-dev',      NULL,               'ag-mac-dev',     'Completed', 1, 3, NULL, NOW() - INTERVAL '5 days',   NOW() - INTERVAL '5 days',   NOW() - INTERVAL '5 days' + INTERVAL '6 seconds',   NOW() - INTERVAL '5 days', 'skipped')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 12. Audit Events — 90 days of activity
-- ============================================================
INSERT INTO audit_events (id, actor, actor_type, action, resource_type, resource_id, details, timestamp) VALUES
  -- System bootstrap (90 days ago)
  ('audit-001', 'alice@example.com', 'user',   'issuer.configured',     'issuer',      'iss-local',      '{"type": "local", "ca_common_name": "CertCtl Demo CA"}',    NOW() - INTERVAL '180 days'),
  ('audit-002', 'alice@example.com', 'user',   'issuer.configured',     'issuer',      'iss-acme-le',    '{"type": "acme", "directory": "letsencrypt-staging"}',       NOW() - INTERVAL '150 days'),
  ('audit-003', 'bob@example.com',   'user',   'issuer.configured',     'issuer',      'iss-stepca',     '{"type": "stepca", "ca_url": "ca.internal:9000"}',          NOW() - INTERVAL '120 days'),
  ('audit-004', 'alice@example.com', 'user',   'target.configured',     'target',      'tgt-nginx-prod', '{"type": "nginx", "agent": "ag-web-prod"}',                 NOW() - INTERVAL '120 days'),
  ('audit-005', 'system',            'system', 'agent.registered',      'agent',       'ag-web-prod',    '{"hostname": "web-prod-01.internal", "os": "linux"}',       NOW() - INTERVAL '120 days'),
  ('audit-006', 'system',            'system', 'agent.registered',      'agent',       'ag-lb-prod',     '{"hostname": "lb-prod-01.internal", "os": "linux"}',        NOW() - INTERVAL '150 days'),

  -- Issuances (90-60 days ago)
  ('audit-010', 'system',            'system', 'certificate.issued',    'certificate', 'mc-api-prod',    '{"issuer": "iss-local", "serial": "0A:1B:2C:3D:4E:5F:00:01"}', NOW() - INTERVAL '90 days'),
  ('audit-011', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-api-prod',    '{"target": "tgt-nginx-prod", "status": "success"}',         NOW() - INTERVAL '90 days' + INTERVAL '25 seconds'),
  ('audit-012', 'system',            'system', 'certificate.issued',    'certificate', 'mc-pay-prod',    '{"issuer": "iss-local", "serial": "0A:1B:2C:3D:4E:5F:00:03"}', NOW() - INTERVAL '85 days'),
  ('audit-013', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-pay-prod',    '{"target": "tgt-nginx-prod", "status": "success"}',         NOW() - INTERVAL '85 days' + INTERVAL '22 seconds'),
  ('audit-014', 'system',            'system', 'certificate.issued',    'certificate', 'mc-web-prod',    '{"issuer": "iss-local", "serial": "0A:1B:2C:3D:4E:5F:00:02"}', NOW() - INTERVAL '77 days'),
  ('audit-015', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-web-prod',    '{"target": "tgt-nginx-prod", "status": "success"}',         NOW() - INTERVAL '77 days' + INTERVAL '22 seconds'),
  ('audit-016', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-web-prod',    '{"target": "tgt-haproxy-prod", "status": "success"}',       NOW() - INTERVAL '77 days' + INTERVAL '24 seconds'),

  -- step-ca renewals
  ('audit-020', 'system',            'system', 'certificate.renewed',   'certificate', 'mc-grpc-prod',   '{"issuer": "iss-stepca", "serial": "0A:1B:2C:3D:4E:5F:00:09"}', NOW() - INTERVAL '63 days'),
  ('audit-021', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-grpc-prod',   '{"target": "tgt-nginx-prod", "status": "success"}',         NOW() - INTERVAL '63 days' + INTERVAL '18 seconds'),

  -- Failed VPN renewal
  ('audit-025', 'system',            'system', 'renewal.failed',        'certificate', 'mc-vpn-prod',    '{"error": "ACME challenge failed: DNS timeout", "attempt": 3}', NOW() - INTERVAL '56 days'),

  -- Payments renewal
  ('audit-030', 'system',            'system', 'certificate.renewed',   'certificate', 'mc-pay-prod',    '{"issuer": "iss-local", "serial": "0A:1B:2C:3D:4E:5F:00:03"}', NOW() - INTERVAL '50 days'),
  ('audit-031', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-pay-prod',    '{"target": "tgt-nginx-prod", "status": "success"}',         NOW() - INTERVAL '50 days' + INTERVAL '22 seconds'),
  ('audit-032', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-pay-prod',    '{"target": "tgt-haproxy-prod", "status": "success"}',       NOW() - INTERVAL '50 days' + INTERVAL '25 seconds'),

  -- ZeroSSL issuance
  ('audit-035', 'carol@example.com', 'user',   'certificate.created',   'certificate', 'mc-shop-prod',   '{"common_name": "shop.example.com", "issuer": "iss-acme-zs"}', NOW() - INTERVAL '46 days'),
  ('audit-036', 'system',            'system', 'certificate.issued',    'certificate', 'mc-shop-prod',   '{"issuer": "iss-acme-zs", "serial": "0A:1B:2C:3D:4E:5F:00:10"}', NOW() - INTERVAL '46 days'),
  ('audit-037', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-shop-prod',   '{"target": "tgt-nginx-prod", "status": "success"}',         NOW() - INTERVAL '46 days' + INTERVAL '28 seconds'),

  -- Wildcard renewal
  ('audit-040', 'system',            'system', 'certificate.renewed',   'certificate', 'mc-wildcard-prod', '{"issuer": "iss-acme-le", "challenge": "dns-01"}',        NOW() - INTERVAL '40 days'),
  ('audit-041', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-wildcard-prod', '{"target": "tgt-nginx-prod", "status": "success"}',       NOW() - INTERVAL '40 days' + INTERVAL '55 seconds'),

  -- K8s ingress + Traefik
  ('audit-045', 'frank@example.com', 'user',   'certificate.created',   'certificate', 'mc-k8s-ingress', '{"common_name": "ingress.example.com"}',                   NOW() - INTERVAL '34 days'),
  ('audit-046', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-k8s-ingress', '{"target": "tgt-traefik-prod", "status": "success"}',       NOW() - INTERVAL '34 days' + INTERVAL '24 seconds'),

  -- Edge EU + Caddy
  ('audit-048', 'alice@example.com', 'user',   'certificate.created',   'certificate', 'mc-edge-eu',     '{"common_name": "eu.cdn.example.com"}',                    NOW() - INTERVAL '29 days'),
  ('audit-049', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-edge-eu',     '{"target": "tgt-caddy-prod", "status": "success"}',         NOW() - INTERVAL '29 days' + INTERVAL '20 seconds'),

  -- API prod renewal (15 days ago)
  ('audit-050', 'system',            'system', 'certificate.renewed',   'certificate', 'mc-api-prod',    '{"issuer": "iss-local", "serial": "0A:1B:2C:3D:4E:5F:00:01"}', NOW() - INTERVAL '15 days'),
  ('audit-051', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-api-prod',    '{"target": "tgt-nginx-prod", "status": "success"}',         NOW() - INTERVAL '15 days' + INTERVAL '20 seconds'),
  ('audit-052', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-api-prod',    '{"target": "tgt-haproxy-prod", "status": "success"}',       NOW() - INTERVAL '15 days' + INTERVAL '22 seconds'),

  -- Revocation (14 days ago)
  ('audit-055', 'bob@example.com',   'user',   'certificate.revoked',   'certificate', 'mc-compromised', '{"reason": "keyCompromise", "serial": "0A:1B:2C:3D:4E:5F:00:14"}', NOW() - INTERVAL '14 days'),

  -- Dashboard renewal (8 days ago)
  ('audit-060', 'system',            'system', 'certificate.renewed',   'certificate', 'mc-dash-prod',   '{"issuer": "iss-local"}',                                   NOW() - INTERVAL '8 days'),
  ('audit-061', 'system',            'system', 'certificate.deployed',  'certificate', 'mc-dash-prod',   '{"target": "tgt-nginx-prod", "status": "success"}',         NOW() - INTERVAL '8 days' + INTERVAL '18 seconds'),

  -- Expiration warnings (recent)
  ('audit-070', 'system',            'system', 'expiration.warning',    'certificate', 'mc-auth-prod',   '{"days_until_expiry": 12}',                                 NOW() - INTERVAL '30 minutes'),
  ('audit-071', 'system',            'system', 'expiration.warning',    'certificate', 'mc-cdn-prod',    '{"days_until_expiry": 8}',                                  NOW() - INTERVAL '25 minutes'),
  ('audit-072', 'system',            'system', 'expiration.warning',    'certificate', 'mc-mail-prod',   '{"days_until_expiry": 5}',                                  NOW() - INTERVAL '20 minutes'),
  ('audit-073', 'system',            'system', 'expiration.warning',    'certificate', 'mc-ci-prod',     '{"days_until_expiry": 18}',                                 NOW() - INTERVAL '15 minutes'),

  -- Recent failed VPN retry
  ('audit-075', 'system',            'system', 'renewal.failed',        'certificate', 'mc-vpn-prod',    '{"error": "ACME HTTP-01 challenge: connection refused", "attempt": 3}', NOW() - INTERVAL '3 days'),

  -- Grafana renewal started
  ('audit-080', 'system',            'system', 'renewal.started',       'certificate', 'mc-grafana-prod', '{"reason": "expiring_in_3_days"}',                          NOW() - INTERVAL '2 hours'),

  -- Agent events
  ('audit-085', 'system',            'system', 'agent.registered',      'agent',       'ag-edge-01',     '{"hostname": "edge-eu-01.internal", "os": "linux"}',        NOW() - INTERVAL '45 days'),
  ('audit-086', 'system',            'system', 'agent.registered',      'agent',       'ag-k8s-prod',    '{"hostname": "k8s-node-01.internal", "os": "linux"}',       NOW() - INTERVAL '30 days'),
  ('audit-087', 'system',            'system', 'agent.registered',      'agent',       'ag-mac-dev',     '{"hostname": "dev-mac-01.internal", "os": "darwin"}',       NOW() - INTERVAL '15 days'),
  ('audit-088', 'bob@example.com',   'user',   'agent.registered',      'agent',       'ag-iis-prod',    '{"hostname": "iis-prod-01.internal", "os": "windows"}',     NOW() - INTERVAL '60 days'),
  ('audit-089', 'system',            'system', 'agent.offline',         'agent',       'ag-iis-prod',    '{"last_heartbeat": "3 hours ago"}',                         NOW() - INTERVAL '3 hours'),

  -- Discovery events
  ('audit-090', 'system',            'system', 'discovery_scan_completed', 'agent',    'ag-web-prod',    '{"certs_found": 4, "certs_new": 2, "dirs": ["/etc/nginx/ssl"]}', NOW() - INTERVAL '3 hours'),
  ('audit-091', 'system',            'system', 'discovery_scan_completed', 'agent',    'ag-data-prod',   '{"certs_found": 3, "certs_new": 1, "dirs": ["/etc/nginx/ssl"]}', NOW() - INTERVAL '2 hours'),
  ('audit-092', 'system',            'system', 'discovery_scan_completed', 'agent',    'server-scanner', '{"certs_found": 5, "certs_new": 5, "scan_type": "network"}',     NOW() - INTERVAL '1 hour'),

  -- Policy violations
  ('audit-095', 'alice@example.com', 'user',   'policy.violation',      'certificate', 'mc-legacy-prod', '{"rule": "max-certificate-lifetime", "message": "Certificate expired"}', NOW() - INTERVAL '3 days'),
  ('audit-096', 'system',            'system', 'policy.violation',      'certificate', 'mc-old-api',     '{"rule": "max-certificate-lifetime", "message": "Certificate expired 15 days ago"}', NOW() - INTERVAL '15 days'),

  -- API audit middleware events (sampled — these accumulate fast)
  ('audit-100', 'alice@example.com', 'user',   'api.call',              'api',         'GET /api/v1/certificates', '{"status": 200, "latency_ms": 12}',                NOW() - INTERVAL '2 hours'),
  ('audit-101', 'bob@example.com',   'user',   'api.call',              'api',         'GET /api/v1/agents',       '{"status": 200, "latency_ms": 8}',                 NOW() - INTERVAL '1 hour'),
  ('audit-102', 'anonymous',         'system', 'api.call',              'api',         'GET /api/v1/auth/info',    '{"status": 200, "latency_ms": 1}',                 NOW() - INTERVAL '30 minutes')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 13. Policy Violations
-- ============================================================
-- D-008: severity values rewritten to TitleCase canonicals (Warning/Error/Critical).
-- Pre-D-008 these rows used lowercase strings ('critical', 'error', 'warning'). Those
-- values were silently tolerated by the pre-D-008 engine, which hardcoded 'Warning'
-- on every new violation regardless of the triggering rule's severity. D-008 rewires
-- evaluateRule to copy rule.Severity into the violation AND migration 000014 adds a
-- CHECK constraint enforcing the TitleCase allowlist at the DB level. Both paths now
-- round-trip correctly against these demo rows.
INSERT INTO policy_violations (id, certificate_id, rule_id, message, severity, created_at) VALUES
  ('pv-001', 'mc-legacy-prod', 'pr-max-certificate-lifetime', 'Certificate has expired and exceeds maximum lifetime policy', 'Critical', NOW() - INTERVAL '3 days'),
  ('pv-002', 'mc-old-api',     'pr-max-certificate-lifetime', 'Certificate expired 15 days ago',                            'Critical', NOW() - INTERVAL '15 days'),
  ('pv-003', 'mc-vpn-prod',    'pr-min-renewal-window',       'Renewal failed within minimum renewal window',               'Error',    NOW() - INTERVAL '3 days'),
  ('pv-004', 'mc-mail-prod',   'pr-min-renewal-window',       'Certificate expiring in 5 days, below 14-day minimum window','Warning',  NOW() - INTERVAL '20 minutes'),
  ('pv-005', 'mc-wiki-prod',   'pr-max-certificate-lifetime', 'Certificate expired 7 days ago',                             'Critical', NOW() - INTERVAL '7 days'),
  ('pv-006', 'mc-compromised', 'pr-min-renewal-window',       'Certificate revoked due to key compromise',                  'Critical', NOW() - INTERVAL '14 days')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 14. Notification Events
-- ============================================================
INSERT INTO notification_events (id, type, certificate_id, channel, recipient, message, sent_at, status, error) VALUES
  -- Expiration warnings
  ('ne-001', 'expiration_warning',  'mc-auth-prod',     'email',   'bob@example.com',     'Certificate auth-production expires in 12 days',         NOW() - INTERVAL '30 minutes', 'sent',   NULL),
  ('ne-002', 'expiration_warning',  'mc-cdn-prod',      'email',   'alice@example.com',   'Certificate cdn-production expires in 8 days',           NOW() - INTERVAL '25 minutes', 'sent',   NULL),
  ('ne-003', 'expiration_warning',  'mc-mail-prod',     'email',   'bob@example.com',     'Certificate mail-production expires in 5 days',          NOW() - INTERVAL '20 minutes', 'sent',   NULL),
  ('ne-004', 'expiration_warning',  'mc-ci-prod',       'email',   'frank@example.com',   'Certificate ci-production expires in 18 days',           NOW() - INTERVAL '15 minutes', 'sent',   NULL),

  -- Renewal success/failure
  ('ne-010', 'renewal_success',     'mc-api-prod',      'email',   'alice@example.com',   'Certificate api-production renewed successfully',        NOW() - INTERVAL '15 days',    'sent',   NULL),
  ('ne-011', 'renewal_success',     'mc-web-prod',      'email',   'dave@example.com',    'Certificate web-production renewed successfully',        NOW() - INTERVAL '30 days',    'sent',   NULL),
  ('ne-012', 'renewal_success',     'mc-pay-prod',      'email',   'carol@example.com',   'Certificate payments-production renewed successfully',   NOW() - INTERVAL '50 days',    'sent',   NULL),
  ('ne-013', 'renewal_failure',     'mc-vpn-prod',      'webhook', 'https://hooks.example.com/certctl', 'Renewal failed for vpn-production after 3 attempts', NOW() - INTERVAL '3 days', 'sent', NULL),
  ('ne-014', 'renewal_failure',     'mc-vpn-prod',      'email',   'bob@example.com',     'Renewal failed for vpn-production after 3 attempts',    NOW() - INTERVAL '3 days',     'sent',   NULL),

  -- Deployment success
  ('ne-020', 'deployment_success',  'mc-api-prod',      'webhook', 'https://hooks.example.com/certctl', 'Certificate api-production deployed to NGINX Production', NOW() - INTERVAL '15 days', 'sent', NULL),
  ('ne-021', 'deployment_success',  'mc-dash-prod',     'email',   'dave@example.com',    'Certificate dashboard-production deployed successfully', NOW() - INTERVAL '8 days',     'sent',   NULL),
  ('ne-022', 'deployment_success',  'mc-k8s-ingress',   'email',   'frank@example.com',   'Certificate k8s-ingress deployed to Traefik',           NOW() - INTERVAL '34 days',    'sent',   NULL),

  -- Revocation notification
  ('ne-030', 'revocation',          'mc-compromised',   'email',   'bob@example.com',     'Certificate old-service.example.com revoked: keyCompromise', NOW() - INTERVAL '14 days', 'sent', NULL),

  -- Slack notifications (recent)
  ('ne-040', 'expiration_warning',  'mc-auth-prod',     'slack',   '#ops-alerts',         'Certificate auth-production expires in 12 days',         NOW() - INTERVAL '30 minutes', 'sent',   NULL),
  ('ne-041', 'renewal_failure',     'mc-vpn-prod',      'slack',   '#ops-alerts',         'Renewal failed: vpn-production (ACME HTTP-01 refused)',  NOW() - INTERVAL '3 days',     'sent',   NULL)
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 15. Agent Groups
-- ============================================================
INSERT INTO agent_groups (id, name, description, match_os, match_architecture, match_ip_cidr, match_version, enabled, created_at, updated_at) VALUES
  ('ag-linux-prod',   'Linux Production',    'All Linux agents in production',          'linux',   '',       '',              '',      true,  NOW() - INTERVAL '90 days', NOW()),
  ('ag-linux-amd64',  'Linux AMD64',         'Linux agents on x86_64 architecture',     'linux',   'amd64', '',              '',      true,  NOW() - INTERVAL '90 days', NOW()),
  ('ag-windows',      'Windows Agents',      'All Windows-based agents',                'windows', '',       '',              '',      true,  NOW() - INTERVAL '60 days', NOW()),
  ('ag-datacenter-a', 'Datacenter A',        'Agents in 10.0.1.0/24 subnet',           '',        '',       '10.0.1.0/24',  '',      true,  NOW() - INTERVAL '90 days', NOW()),
  ('ag-arm64',        'ARM64 Agents',        'Agents on ARM architecture',              '',        'arm64',  '',              '',      true,  NOW() - INTERVAL '45 days', NOW()),
  ('ag-manual',       'Manual Group',        'Manually managed agent group',            '',        '',       '',              '',      false, NOW() - INTERVAL '30 days', NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO agent_group_members (agent_group_id, agent_id, membership_type, created_at) VALUES
  ('ag-manual', 'ag-web-prod',    'include', NOW() - INTERVAL '30 days'),
  ('ag-manual', 'ag-web-staging', 'include', NOW() - INTERVAL '30 days'),
  ('ag-manual', 'ag-iis-prod',    'exclude', NOW() - INTERVAL '30 days')
ON CONFLICT (agent_group_id, agent_id) DO NOTHING;

-- ============================================================
-- 16. Network Scan Targets
-- ============================================================
INSERT INTO network_scan_targets (id, name, cidrs, ports, enabled, scan_interval_hours, timeout_ms, created_at, updated_at) VALUES
  ('nst-dc1-web',    'DC1 Web Servers',      '{10.0.1.0/24}',              '{443,8443}',      true,  6,  5000, NOW() - INTERVAL '60 days', NOW()),
  ('nst-dc2-apps',   'DC2 Application Tier', '{10.0.2.0/24,10.0.3.0/24}', '{443}',           true,  6,  5000, NOW() - INTERVAL '60 days', NOW()),
  ('nst-dmz',        'DMZ Public Endpoints', '{192.168.100.0/24}',         '{443,8443,9443}', true,  12, 3000, NOW() - INTERVAL '45 days', NOW()),
  ('nst-edge',       'Edge Locations',       '{10.0.5.0/24,10.0.6.0/24}', '{443}',           true,  6,  5000, NOW() - INTERVAL '30 days', NOW())
ON CONFLICT (id) DO NOTHING;

UPDATE network_scan_targets SET
  last_scan_at = NOW() - INTERVAL '1 hour',
  last_scan_duration_ms = 4500,
  last_scan_certs_found = 5
WHERE id = 'nst-dc1-web';

UPDATE network_scan_targets SET
  last_scan_at = NOW() - INTERVAL '2 hours',
  last_scan_duration_ms = 8200,
  last_scan_certs_found = 2
WHERE id = 'nst-dc2-apps';

UPDATE network_scan_targets SET
  last_scan_at = NOW() - INTERVAL '6 hours',
  last_scan_duration_ms = 3100,
  last_scan_certs_found = 3
WHERE id = 'nst-dmz';

-- ============================================================
-- 17. Discovery Scans (backdated over 90 days)
-- ============================================================
INSERT INTO discovery_scans (id, agent_id, directories, certificates_found, certificates_new, errors_count, scan_duration_ms, started_at, completed_at) VALUES
  -- Historical scans
  ('ds-web-hist-01',   'ag-web-prod',    '{/etc/nginx/ssl,/etc/pki/tls/certs}', 3, 3, 0, 1100, NOW() - INTERVAL '60 days', NOW() - INTERVAL '60 days' + INTERVAL '1 second'),
  ('ds-web-hist-02',   'ag-web-prod',    '{/etc/nginx/ssl,/etc/pki/tls/certs}', 4, 1, 0, 1200, NOW() - INTERVAL '30 days', NOW() - INTERVAL '30 days' + INTERVAL '1 second'),
  ('ds-data-hist-01',  'ag-data-prod',   '{/etc/nginx/ssl,/opt/certs}',         2, 2, 0, 850,  NOW() - INTERVAL '45 days', NOW() - INTERVAL '45 days' + INTERVAL '1 second'),
  -- Recent scans
  ('ds-web-prod-01',   'ag-web-prod',    '{/etc/nginx/ssl,/etc/pki/tls/certs}', 4, 0, 0, 1250, NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours' + INTERVAL '1 second'),
  ('ds-data-prod-01',  'ag-data-prod',   '{/etc/nginx/ssl,/opt/certs}',         3, 0, 0, 980,  NOW() - INTERVAL '2 hours', NOW() - INTERVAL '2 hours' + INTERVAL '1 second'),
  ('ds-edge-prod-01',  'ag-edge-01',     '{/etc/caddy/certs}',                  1, 0, 0, 420,  NOW() - INTERVAL '4 hours', NOW() - INTERVAL '4 hours' + INTERVAL '1 second'),
  -- Network scans
  ('ds-net-hist-01',   'server-scanner', '{network-scan}',                       3, 3, 0, 12500, NOW() - INTERVAL '7 days',  NOW() - INTERVAL '7 days' + INTERVAL '12 seconds'),
  ('ds-net-prod-01',   'server-scanner', '{network-scan}',                       5, 2, 1, 15200, NOW() - INTERVAL '1 hour',  NOW() - INTERVAL '1 hour' + INTERVAL '15 seconds')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 18. Discovered Certificates
-- ============================================================
INSERT INTO discovered_certificates (id, fingerprint_sha256, common_name, sans, serial_number, issuer_dn, subject_dn, not_before, not_after, key_algorithm, key_size, is_ca, pem_data, source_path, source_format, agent_id, discovery_scan_id, managed_certificate_id, status, first_seen_at, last_seen_at) VALUES
  -- Unmanaged: found on filesystem, not yet claimed
  ('dc-unmanaged-01', 'sha256:f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
   'internal-service.example.com', ARRAY['internal-service.example.com', 'internal-svc.local'],
   '1A:2B:3C:4D:5E:6F:00:11', 'CN=Example Internal CA,O=Example Corp',
   'CN=internal-service.example.com,O=Example Corp', NOW() - INTERVAL '200 days', NOW() + INTERVAL '20 days',
   'RSA', 2048, false, '', '/etc/pki/tls/certs/internal-svc.pem', 'PEM',
   'ag-web-prod', 'ds-web-prod-01', NULL, 'Unmanaged',
   NOW() - INTERVAL '60 days', NOW() - INTERVAL '3 hours'),

  ('dc-unmanaged-02', 'sha256:a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0',
   'monitoring.internal.example.com', ARRAY['monitoring.internal.example.com', 'prometheus.internal.example.com'],
   '2B:3C:4D:5E:6F:7A:00:22', 'CN=Let''s Encrypt Authority X3,O=Let''s Encrypt',
   'CN=monitoring.internal.example.com', NOW() - INTERVAL '60 days', NOW() + INTERVAL '30 days',
   'ECDSA', 256, false, '', '/opt/certs/monitoring.pem', 'PEM',
   'ag-data-prod', 'ds-data-prod-01', NULL, 'Unmanaged',
   NOW() - INTERVAL '45 days', NOW() - INTERVAL '2 hours'),

  ('dc-unmanaged-03', 'sha256:1122334455667788990011223344556677889900',
   'db-replication.example.com', ARRAY['db-replication.example.com'],
   '3C:4D:5E:6F:7A:8B:00:33', 'CN=Example Internal CA,O=Example Corp',
   'CN=db-replication.example.com,O=Example Corp', NOW() - INTERVAL '300 days', NOW() - INTERVAL '10 days',
   'RSA', 4096, false, '', '/etc/pki/tls/certs/db-repl.pem', 'PEM',
   'ag-web-prod', 'ds-web-prod-01', NULL, 'Unmanaged',
   NOW() - INTERVAL '60 days', NOW() - INTERVAL '3 hours'),

  ('dc-unmanaged-04', 'sha256:aabb001122334455667788990011223344aabb00',
   'redis-tls.internal.example.com', ARRAY['redis-tls.internal.example.com'],
   '4D:5E:6F:7A:8B:9C:00:44', 'CN=Example Internal CA,O=Example Corp',
   'CN=redis-tls.internal.example.com,O=Example Corp', NOW() - INTERVAL '90 days', NOW() + INTERVAL '60 days',
   'ECDSA', 256, false, '', '/opt/certs/redis-tls.pem', 'PEM',
   'ag-data-prod', 'ds-data-prod-01', NULL, 'Unmanaged',
   NOW() - INTERVAL '45 days', NOW() - INTERVAL '2 hours'),

  -- Managed: already linked to managed certificates
  ('dc-managed-01', 'sha256:ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12',
   'api.example.com', ARRAY['api.example.com', 'api-v2.example.com'],
   '0A:1B:2C:3D:4E:5F:00:01', 'CN=CertCtl Demo CA',
   'CN=api.example.com', NOW() - INTERVAL '15 days', NOW() + INTERVAL '75 days',
   'ECDSA', 256, false, '', '/etc/nginx/ssl/cert.pem', 'PEM',
   'ag-web-prod', 'ds-web-prod-01', 'mc-api-prod', 'Managed',
   NOW() - INTERVAL '60 days', NOW() - INTERVAL '3 hours'),

  ('dc-managed-02', 'sha256:cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34',
   'data.example.com', ARRAY['data.example.com', 'analytics.example.com'],
   '0A:1B:2C:3D:4E:5F:00:07', 'CN=CertCtl Demo CA',
   'CN=data.example.com', NOW() - INTERVAL '35 days', NOW() + INTERVAL '55 days',
   'ECDSA', 256, false, '', '/etc/nginx/ssl/cert.pem', 'PEM',
   'ag-data-prod', 'ds-data-prod-01', 'mc-data-prod', 'Managed',
   NOW() - INTERVAL '45 days', NOW() - INTERVAL '2 hours'),

  -- Dismissed: triaged and explicitly ignored
  ('dc-dismissed-01', 'sha256:9988776655443322110099887766554433221100',
   'test-selfsigned.local', ARRAY['test-selfsigned.local', 'localhost'],
   '00:00:00:00:00:00:FF:01', 'CN=test-selfsigned.local',
   'CN=test-selfsigned.local', NOW() - INTERVAL '365 days', NOW() + INTERVAL '365 days',
   'RSA', 2048, false, '', '/etc/pki/tls/certs/test.pem', 'PEM',
   'ag-web-prod', 'ds-web-hist-01', NULL, 'Dismissed',
   NOW() - INTERVAL '60 days', NOW() - INTERVAL '3 hours'),

  -- Network-discovered certs (from server-scanner sentinel agent)
  ('dc-network-01', 'sha256:net1aabbccdd11223344556677889900aabbccdd',
   'switch-mgmt.example.com', ARRAY['switch-mgmt.example.com'],
   '5E:6F:7A:8B:9C:0D:00:44', 'CN=Example Network CA,O=Example Corp',
   'CN=switch-mgmt.example.com,O=Example Corp', NOW() - INTERVAL '180 days', NOW() + INTERVAL '5 days',
   'RSA', 2048, false, '', '10.0.1.50:443', 'TLS',
   'server-scanner', 'ds-net-prod-01', NULL, 'Unmanaged',
   NOW() - INTERVAL '7 days', NOW() - INTERVAL '1 hour'),

  ('dc-network-02', 'sha256:net2eeff00112233445566778899aabbccddeeff',
   'printer.example.com', ARRAY['printer.example.com'],
   '6F:7A:8B:9C:0D:1E:00:55', 'CN=printer.example.com',
   'CN=printer.example.com', NOW() - INTERVAL '400 days', NOW() - INTERVAL '30 days',
   'RSA', 1024, false, '', '10.0.2.100:443', 'TLS',
   'server-scanner', 'ds-net-prod-01', NULL, 'Unmanaged',
   NOW() - INTERVAL '7 days', NOW() - INTERVAL '1 hour'),

  ('dc-network-03', 'sha256:net3001122334455667788990011223344556677',
   'vpn-appliance.example.com', ARRAY['vpn-appliance.example.com', '10.0.1.1'],
   '7A:8B:9C:0D:1E:2F:00:66', 'CN=Fortinet CA,O=Fortinet',
   'CN=vpn-appliance.example.com', NOW() - INTERVAL '90 days', NOW() + INTERVAL '275 days',
   'RSA', 2048, false, '', '10.0.1.1:443', 'TLS',
   'server-scanner', 'ds-net-prod-01', NULL, 'Unmanaged',
   NOW() - INTERVAL '7 days', NOW() - INTERVAL '1 hour'),

  ('dc-network-04', 'sha256:net400112233445566778899001122334455aabb',
   'ilo-server-rack3.example.com', ARRAY['ilo-server-rack3.example.com'],
   '8B:9C:0D:1E:2F:3A:00:77', 'CN=iLO Default Issuer',
   'CN=ilo-server-rack3.example.com', NOW() - INTERVAL '730 days', NOW() - INTERVAL '365 days',
   'RSA', 2048, false, '', '10.0.1.80:443', 'TLS',
   'server-scanner', 'ds-net-prod-01', NULL, 'Unmanaged',
   NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour'),

  ('dc-network-05', 'sha256:net500aabbccdd11223344556677889900112233',
   'nas-backup.example.com', ARRAY['nas-backup.example.com'],
   '9C:0D:1E:2F:3A:4B:00:88', 'CN=Synology Inc CA,O=Synology Inc.',
   'CN=nas-backup.example.com', NOW() - INTERVAL '180 days', NOW() + INTERVAL '180 days',
   'RSA', 2048, false, '', '10.0.1.90:5001', 'TLS',
   'server-scanner', 'ds-net-prod-01', NULL, 'Unmanaged',
   NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour')
ON CONFLICT (id) DO NOTHING;
