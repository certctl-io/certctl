-- Seed data for certificate control plane

-- Default renewal policy
INSERT INTO renewal_policies (id, name, renewal_window_days, auto_renew, max_retries, retry_interval_minutes, alert_thresholds_days)
VALUES (
  'rp-default',
  'default',
  30,
  true,
  3,
  60,
  '[30, 14, 7, 0]'::jsonb
) ON CONFLICT (id) DO NOTHING;

-- Policy rules: Require owner assignment
-- Severity differentiated per rule to demonstrate the field means something
-- (D-006). The backend CHECK constraint (migration 000013) enforces the
-- TitleCase allowlist Warning/Error/Critical. Type-value drift
-- (ownership/environment/lifetime/renewal_window vs. the engine's TitleCase
-- canonicals) is tracked separately in d/D-008 and intentionally left
-- unchanged in this commit.
INSERT INTO policy_rules (id, name, type, config, enabled, severity)
VALUES (
  'pr-require-owner',
  'require-owner',
  'ownership',
  '{"requirement": "owner_id must be set"}'::jsonb,
  true,
  'Warning'
) ON CONFLICT (id) DO NOTHING;

-- Policy rules: Allowed environments
INSERT INTO policy_rules (id, name, type, config, enabled, severity)
VALUES (
  'pr-allowed-environments',
  'allowed-environments',
  'environment',
  '{"allowed": ["production", "staging", "development"]}'::jsonb,
  true,
  'Error'
) ON CONFLICT (id) DO NOTHING;

-- Policy rules: Maximum certificate lifetime
INSERT INTO policy_rules (id, name, type, config, enabled, severity)
VALUES (
  'pr-max-certificate-lifetime',
  'max-certificate-lifetime',
  'lifetime',
  '{"max_days": 90}'::jsonb,
  true,
  'Critical'
) ON CONFLICT (id) DO NOTHING;

-- Policy rules: Minimum renewal window
INSERT INTO policy_rules (id, name, type, config, enabled, severity)
VALUES (
  'pr-min-renewal-window',
  'min-renewal-window',
  'renewal_window',
  '{"min_days": 14}'::jsonb,
  true,
  'Warning'
) ON CONFLICT (id) DO NOTHING;
