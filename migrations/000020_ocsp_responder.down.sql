-- 000020_ocsp_responder.down.sql — reverses 000020_ocsp_responder.up.sql.

DROP INDEX IF EXISTS idx_ocsp_responders_not_after;
DROP TABLE IF EXISTS ocsp_responders;
