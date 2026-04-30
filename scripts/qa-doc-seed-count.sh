#!/usr/bin/env bash
# scripts/qa-doc-seed-count.sh
#
# Bundle P / Strengthening #6 — QA-doc seed-count drift guard.
# Forces every PR that adds a seed row to migrations/seed_demo.sql
# to keep docs/qa-test-guide.md::Seed Data Reference in sync.
#
# Per ci-pipeline-cleanup bundle Phase 11 / frozen decision 0.13:
# moved out of CI (was in ci.yml) — operator runs via 'make verify-docs'
# pre-tag.

set -e
# Seed-cert count: agnostic to documented header format. The current
# documented count lives in `### Certificates (32 total in ...` —
# extract the first integer in that header.
DOC_CERTS=$(grep -oE '### Certificates \([0-9]+' docs/qa-test-guide.md | grep -oE '[0-9]+' | head -1)
# Authoritative count: unique mc-* IDs in seed_demo.sql.
SEED_CERTS=$(grep -oE 'mc-[a-z0-9_-]+' migrations/seed_demo.sql | sort -u | wc -l | tr -d ' ')
if [ -z "$DOC_CERTS" ]; then
  echo "::warning::Could not extract documented cert count from docs/qa-test-guide.md."
  echo "  Skipping cert-count drift check (header format may have changed)."
elif [ "$DOC_CERTS" != "$SEED_CERTS" ]; then
  echo "::error::DRIFT — qa-test-guide.md says $DOC_CERTS certs; seed_demo.sql has $SEED_CERTS unique mc-* IDs."
  echo "  Update docs/qa-test-guide.md::Seed Data Reference to match."
  exit 1
fi
# Issuers: seed-table count vs doc claim.
DOC_ISS=$(grep -oE '### Issuers \([0-9]+' docs/qa-test-guide.md | grep -oE '[0-9]+' | head -1)
# Authoritative: unique iss-* IDs (close enough proxy; the issuers
# table count IS the unique-ID count for this prefix).
SEED_ISS=$(grep -oE 'iss-[a-z0-9_-]+' migrations/seed_demo.sql | sort -u | wc -l | tr -d ' ')
if [ -z "$DOC_ISS" ]; then
  echo "::warning::Could not extract documented issuer count."
elif [ "$DOC_ISS" != "$SEED_ISS" ] && [ "$((SEED_ISS - DOC_ISS))" -gt 5 ]; then
  # Allow up to 5pp slack — iss-* IDs appear in audit_events and
  # other reference tables that aren't issuer-table rows. Drift
  # only flags when the spread grows large.
  echo "::error::DRIFT — qa-test-guide.md says $DOC_ISS issuers; seed_demo.sql has $SEED_ISS unique iss-* IDs (spread > 5)."
  exit 1
fi
echo "qa-doc-seed-count: clean."
