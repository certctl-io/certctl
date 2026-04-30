-- EST RFC 7030 hardening master bundle Phase 11.1.
--
-- Add `source` TEXT column to managed_certificates so the bulk-revoke
-- handler can filter by provenance (EST / SCEP / API / Agent /
-- legacy-empty). Empty value preserves v2.X.0 behavior — existing
-- rows scan as Source="" + the bulk-revoke filter treats empty as
-- "any source", so no existing call path sees a behavior change.
--
-- New EST issuances (Phases 5 + 11 of this bundle) stamp Source="EST";
-- new SCEP issuances continue to land with Source="" until a follow-up
-- bundle wires the stamp at the SCEP service layer.
--
-- An index would only pay off when bulk-revoke is called frequently
-- AND the table is large; both prerequisites are unlikely at GA, so
-- defer the index to a follow-up if observability flags slow filter
-- queries in production.

ALTER TABLE managed_certificates
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT '';
