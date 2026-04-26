-- Bundle-6 / Audit M-017 / HIPAA §164.312(b) (audit controls):
--
-- audit_events is append-only at the database layer. The application
-- role cannot UPDATE or DELETE rows. Compliance superusers (legal hold,
-- retention purges) use a separate role provisioned out-of-band that
-- bypasses this trigger; see docs/compliance.md for the operator
-- pattern.
--
-- Pre-Bundle-6 enforcement was app-layer only (no DELETE/UPDATE method
-- on AuditService). A buggy migration script, a manual psql session, or
-- an attacker with the app role's DB credentials could rewrite history.
-- This trigger is the load-bearing defence; the REVOKE below is
-- defence-in-depth.

CREATE OR REPLACE FUNCTION audit_events_block_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (Bundle-6 / M-017 / HIPAA §164.312(b))'
        USING ERRCODE = 'check_violation',
              HINT = 'Use a compliance superuser role for legitimate retention operations.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_worm_trigger ON audit_events;
CREATE TRIGGER audit_events_worm_trigger
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION audit_events_block_modification();

-- Defence-in-depth: revoke UPDATE + DELETE from the app role too.
-- The role is conventionally `certctl` (matches docker-compose POSTGRES_USER
-- and Helm values.yaml postgresql.username). If the role doesn't exist
-- (test fixtures, single-superuser setups), the DO block is a no-op so
-- the migration stays idempotent across all environments.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'certctl') THEN
        REVOKE UPDATE, DELETE ON audit_events FROM certctl;
    END IF;
END $$;
