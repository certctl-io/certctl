-- Create initial schema for certificate control plane
-- IDs are TEXT to support application-generated prefixed IDs (e.g., "team-123", "cert-456")

-- Table: teams
CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_teams_name ON teams(name);

-- Table: owners
CREATE TABLE IF NOT EXISTS owners (
  id TEXT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_owners_email ON owners(email);
CREATE INDEX IF NOT EXISTS idx_owners_team_id ON owners(team_id);

-- Table: renewal_policies
CREATE TABLE IF NOT EXISTS renewal_policies (
  id TEXT PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  renewal_window_days INT NOT NULL,
  auto_renew BOOLEAN NOT NULL DEFAULT true,
  max_retries INT NOT NULL DEFAULT 3,
  retry_interval_minutes INT NOT NULL DEFAULT 60,
  alert_thresholds_days JSONB NOT NULL DEFAULT '[30, 14, 7, 0]',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_renewal_policies_name ON renewal_policies(name);

-- Table: issuers
CREATE TABLE IF NOT EXISTS issuers (
  id TEXT PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  type VARCHAR(255) NOT NULL,
  config JSONB,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_issuers_name ON issuers(name);
CREATE INDEX IF NOT EXISTS idx_issuers_enabled ON issuers(enabled);

-- Table: agents
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  hostname VARCHAR(255) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'offline',
  last_heartbeat_at TIMESTAMPTZ,
  registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  api_key_hash VARCHAR(255) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents(hostname);
CREATE INDEX IF NOT EXISTS idx_agents_last_heartbeat_at ON agents(last_heartbeat_at);

-- Table: managed_certificates
CREATE TABLE IF NOT EXISTS managed_certificates (
  id TEXT PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  common_name VARCHAR(255) NOT NULL,
  sans TEXT[] DEFAULT ARRAY[]::TEXT[],
  environment VARCHAR(50),
  owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE RESTRICT,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  issuer_id TEXT NOT NULL REFERENCES issuers(id) ON DELETE RESTRICT,
  renewal_policy_id TEXT NOT NULL REFERENCES renewal_policies(id) ON DELETE RESTRICT,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  expires_at TIMESTAMPTZ,
  tags JSONB NOT NULL DEFAULT '{}',
  last_renewal_at TIMESTAMPTZ,
  last_deployment_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_managed_certificates_status ON managed_certificates(status);
CREATE INDEX IF NOT EXISTS idx_managed_certificates_expires_at ON managed_certificates(expires_at);
CREATE INDEX IF NOT EXISTS idx_managed_certificates_owner_id ON managed_certificates(owner_id);
CREATE INDEX IF NOT EXISTS idx_managed_certificates_team_id ON managed_certificates(team_id);
CREATE INDEX IF NOT EXISTS idx_managed_certificates_issuer_id ON managed_certificates(issuer_id);
CREATE INDEX IF NOT EXISTS idx_managed_certificates_name ON managed_certificates(name);

-- Table: deployment_targets
CREATE TABLE IF NOT EXISTS deployment_targets (
  id TEXT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  type VARCHAR(255) NOT NULL,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  config JSONB,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deployment_targets_agent_id ON deployment_targets(agent_id);
CREATE INDEX IF NOT EXISTS idx_deployment_targets_enabled ON deployment_targets(enabled);
CREATE INDEX IF NOT EXISTS idx_deployment_targets_name ON deployment_targets(name);

-- Table: certificate_target_mappings
CREATE TABLE IF NOT EXISTS certificate_target_mappings (
  certificate_id TEXT NOT NULL REFERENCES managed_certificates(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES deployment_targets(id) ON DELETE CASCADE,
  PRIMARY KEY (certificate_id, target_id)
);

CREATE INDEX IF NOT EXISTS idx_certificate_target_mappings_target_id ON certificate_target_mappings(target_id);

-- Table: certificate_versions
CREATE TABLE IF NOT EXISTS certificate_versions (
  id TEXT PRIMARY KEY,
  certificate_id TEXT NOT NULL REFERENCES managed_certificates(id) ON DELETE CASCADE,
  serial_number VARCHAR(255) NOT NULL,
  not_before TIMESTAMPTZ NOT NULL,
  not_after TIMESTAMPTZ NOT NULL,
  fingerprint_sha256 VARCHAR(255) NOT NULL UNIQUE,
  pem_chain TEXT NOT NULL,
  csr_pem TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_certificate_versions_certificate_id ON certificate_versions(certificate_id);
CREATE INDEX IF NOT EXISTS idx_certificate_versions_fingerprint ON certificate_versions(fingerprint_sha256);

-- Table: jobs
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  type VARCHAR(255) NOT NULL,
  certificate_id TEXT REFERENCES managed_certificates(id) ON DELETE CASCADE,
  target_id TEXT REFERENCES deployment_targets(id) ON DELETE SET NULL,
  agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 3,
  last_error TEXT,
  deployment_result JSONB,
  scheduled_at TIMESTAMPTZ,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_certificate_id ON jobs(certificate_id);
CREATE INDEX IF NOT EXISTS idx_jobs_scheduled_at ON jobs(scheduled_at);
CREATE INDEX IF NOT EXISTS idx_jobs_agent_id ON jobs(agent_id);

-- Table: policy_rules
CREATE TABLE IF NOT EXISTS policy_rules (
  id TEXT PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  type VARCHAR(255) NOT NULL,
  config JSONB NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_rules_name ON policy_rules(name);
CREATE INDEX IF NOT EXISTS idx_policy_rules_enabled ON policy_rules(enabled);

-- Table: policy_violations
CREATE TABLE IF NOT EXISTS policy_violations (
  id TEXT PRIMARY KEY,
  certificate_id TEXT NOT NULL REFERENCES managed_certificates(id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL REFERENCES policy_rules(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  severity VARCHAR(50) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_violations_certificate_id ON policy_violations(certificate_id);
CREATE INDEX IF NOT EXISTS idx_policy_violations_rule_id ON policy_violations(rule_id);
CREATE INDEX IF NOT EXISTS idx_policy_violations_severity ON policy_violations(severity);

-- Table: audit_events
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor VARCHAR(255) NOT NULL,
  actor_type VARCHAR(50) NOT NULL,
  action VARCHAR(255) NOT NULL,
  resource_type VARCHAR(255) NOT NULL,
  resource_id VARCHAR(255) NOT NULL,
  details JSONB,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_resource_type_id ON audit_events(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);

-- Table: notification_events
CREATE TABLE IF NOT EXISTS notification_events (
  id TEXT PRIMARY KEY,
  type VARCHAR(255) NOT NULL,
  certificate_id TEXT REFERENCES managed_certificates(id) ON DELETE CASCADE,
  channel VARCHAR(255) NOT NULL,
  recipient VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  sent_at TIMESTAMPTZ,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  error TEXT
);

CREATE INDEX IF NOT EXISTS idx_notification_events_certificate_id ON notification_events(certificate_id);
CREATE INDEX IF NOT EXISTS idx_notification_events_status ON notification_events(status);
CREATE INDEX IF NOT EXISTS idx_notification_events_type ON notification_events(type);
