-- Rollback initial schema - drop tables in reverse dependency order

DROP TABLE IF EXISTS notification_events;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS policy_violations;
DROP TABLE IF EXISTS policy_rules;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS certificate_versions;
DROP TABLE IF EXISTS certificate_target_mappings;
DROP TABLE IF EXISTS deployment_targets;
DROP TABLE IF EXISTS managed_certificates;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS issuers;
DROP TABLE IF EXISTS renewal_policies;
DROP TABLE IF EXISTS owners;
DROP TABLE IF EXISTS teams;

DROP EXTENSION IF EXISTS "uuid-ossp";
