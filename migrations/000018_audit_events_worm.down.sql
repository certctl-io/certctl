-- Bundle-6 / Audit M-017: down migration drops the WORM trigger and
-- restores writability for dev resets. Production environments should
-- never need this — the only use case is a clean teardown of a dev DB
-- before re-applying migrations from scratch.

DROP TRIGGER IF EXISTS audit_events_worm_trigger ON audit_events;
DROP FUNCTION IF EXISTS audit_events_block_modification();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'certctl') THEN
        GRANT UPDATE, DELETE ON audit_events TO certctl;
    END IF;
END $$;
