-- Sprint 6 COMP-001-HASH rollback.
--
-- Order of operations:
--   1. Drop the BEFORE-INSERT trigger so subsequent inserts don't try
--      to populate the columns we're about to drop.
--   2. Drop the trigger function + verifier function + canonical
--      payload helper.
--   3. Drop the columns + sentinel table.
--   4. Leave pgcrypto installed — other future migrations may rely on
--      it; uninstall risk is asymmetric with retention benefit.

BEGIN;

DROP TRIGGER IF EXISTS audit_events_hash_chain_trigger ON audit_events;
DROP FUNCTION  IF EXISTS audit_events_compute_hash_chain();
DROP FUNCTION  IF EXISTS audit_events_verify_chain();
DROP FUNCTION  IF EXISTS audit_events_canonical_payload(
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, TIMESTAMPTZ, TEXT
);

ALTER TABLE audit_events
    DROP COLUMN IF EXISTS prev_hash,
    DROP COLUMN IF EXISTS row_hash;

DROP TABLE IF EXISTS audit_chain_head;

COMMIT;
