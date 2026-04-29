-- EST RFC 7030 hardening master bundle Phase 6.1.
--
-- Add `required_csr_attributes` JSONB column to certificate_profiles so the
-- EST `csrattrs` endpoint (RFC 7030 §4.5) can return a profile-derived OID
-- list to enrolling clients. Clients use the response as a hint for which
-- attributes / EKUs to include in their PKCS#10 CSR — example: the
-- IoT-bootstrap profile might require `serialNumber` (OID 2.5.4.5) so the
-- device serial appears in the issued cert's Subject DN.
--
-- Defaults to `[]` for back-compat (existing profiles see no behavior change;
-- their EST csrattrs response stays the legacy 204-No-Content).
--
-- Also lands `must_staple` as a real column. The 5.6 follow-up wired
-- CertificateProfile.MustStaple all the way through the issuer/service
-- layer but the postgres repo never grew the column — every existing
-- deploy implicitly has must_staple=false because the field couldn't be
-- persisted. The column is added with default false so existing profiles
-- behave identically; operators flipping must_staple via the API now
-- actually round-trip to disk.
--
-- Both columns ship in the same migration to keep the schema-history
-- contiguous; rolling back drops both.

ALTER TABLE certificate_profiles
    ADD COLUMN IF NOT EXISTS required_csr_attributes JSONB NOT NULL DEFAULT '[]';

ALTER TABLE certificate_profiles
    ADD COLUMN IF NOT EXISTS must_staple BOOLEAN NOT NULL DEFAULT false;

-- Index isn't necessary — required_csr_attributes is read on every EST
-- csrattrs request but only at the per-profile granularity (always a
-- direct PK lookup); must_staple is a per-issuance bool with no query
-- pattern that benefits from indexing.
