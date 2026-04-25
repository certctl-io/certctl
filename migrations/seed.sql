-- Seed data for certificate control plane

-- Default renewal policy
INSERT INTO renewal_policies (id, name, renewal_window_days, auto_renew, max_retries, retry_interval_seconds, alert_thresholds_days)
VALUES (
  'rp-default',
  'default',
  30,
  true,
  3,
  60,
  '[30, 14, 7, 0]'::jsonb
) ON CONFLICT (id) DO NOTHING;

-- Policy rules: Require owner assignment, bound environments, cap lifetime,
-- and enforce a renewal lead-time.
--
-- Severity is differentiated per rule (D-006) and the types are now the
-- TitleCase canonicals the engine actually recognizes (D-008). Pre-D-008 the
-- types were lowercase strings (`ownership`, `environment`, `lifetime`,
-- `renewal_window`) that the engine silently dropped through to its
-- default-case error path — the rules looked alive in the GUI but did not
-- enforce anything. The backend CHECK constraint (migration 000013) enforces
-- the TitleCase severity allowlist Warning/Error/Critical. Configs are also
-- reshaped to match the D-008 per-arm schemas so the rules actually exercise
-- the config-consuming paths instead of falling back to the missing-field
-- placeholders.
INSERT INTO policy_rules (id, name, type, config, enabled, severity)
VALUES (
  'pr-require-owner',
  'require-owner',
  'RequiredMetadata',
  '{"required_keys": ["owner"]}'::jsonb,
  true,
  'Warning'
) ON CONFLICT (id) DO NOTHING;

-- Policy rules: Allowed environments
INSERT INTO policy_rules (id, name, type, config, enabled, severity)
VALUES (
  'pr-allowed-environments',
  'allowed-environments',
  'AllowedEnvironments',
  '{"allowed": ["production", "staging", "development"]}'::jsonb,
  true,
  'Error'
) ON CONFLICT (id) DO NOTHING;

-- Policy rules: Maximum certificate lifetime
INSERT INTO policy_rules (id, name, type, config, enabled, severity)
VALUES (
  'pr-max-certificate-lifetime',
  'max-certificate-lifetime',
  'CertificateLifetime',
  '{"max_days": 90}'::jsonb,
  true,
  'Critical'
) ON CONFLICT (id) DO NOTHING;

-- Policy rules: Minimum renewal window (renew at least 14 days before expiry)
INSERT INTO policy_rules (id, name, type, config, enabled, severity)
VALUES (
  'pr-min-renewal-window',
  'min-renewal-window',
  'RenewalLeadTime',
  '{"lead_time_days": 14}'::jsonb,
  true,
  'Warning'
) ON CONFLICT (id) DO NOTHING;
