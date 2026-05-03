#!/usr/bin/env bash
# scripts/ci-guards/G-3-env-docs-drift.sh
#
# G-3 master closed cat-g-163dae19bc59 (docs-only env vars
# phantom in features.md), cat-g-b8f8f8796159 (6 config-only
# env vars never documented), and cat-g-renewal_check_interval_rename_drift
# (features.md still advertised the pre-rename
# CERTCTL_RENEWAL_CHECK_INTERVAL after it was renamed to
# CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL). This script runs
# `comm -23` both ways between the env vars defined in Go
# source (config.go + cmd/agent + deploy/test fixtures + ACME
# DNS-01 script env exports) and the env vars mentioned in
# README + docs/ + deploy/helm/.
#
# Allowlist: env vars that are documented as integration-
# surface contracts (script env exports for ACME DNS-01,
# OpenSSL CA scripts, StepCA per-issuer-config-blob fields,
# Webhook per-notifier-config-blob fields, ACME EAB, audit
# exclusion, demo-stack overrides) but not consumed directly
# by config.go. Each entry below has a one-line justification
# — if you add a new entry, add the justification too.
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# cat-g-* for closure rationale.

set -e
# Defined: config.go + agent + cli + mcp-server + server cmds + test fixtures + ACME DNS export
{
  grep -nE '"CERTCTL_[A-Z_]+"' internal/config/config.go | sed -E 's/.*"(CERTCTL_[A-Z_]+)".*/\1/'
  grep -rhoE '"CERTCTL_[A-Z_]+"' cmd/agent/*.go cmd/cli/*.go cmd/mcp-server/*.go cmd/server/*.go 2>/dev/null | sed -E 's/"(CERTCTL_[A-Z_]+)"/\1/'
  grep -rhoE 'CERTCTL_[A-Z_]+' deploy/test/qa_test.go internal/connector/issuer/acme/dns.go 2>/dev/null
} | grep -E '^CERTCTL_' | sort -u > /tmp/g3-defined.txt
# Documented: README + docs + helm
grep -rhoE '\bCERTCTL_[A-Z_]+\b' README.md docs/ deploy/helm/ 2>/dev/null | sort -u > /tmp/g3-docs.txt
# Allowlist of env vars documented as external integration contracts.
# Each entry justifies itself in one line; if you add to this list,
# add the justification.
ALLOWED='^(
CERTCTL_OPENSSL_SIGN_SCRIPT|
CERTCTL_OPENSSL_REVOKE_SCRIPT|
CERTCTL_OPENSSL_CRL_SCRIPT|
CERTCTL_OPENSSL_TIMEOUT_SECONDS|
CERTCTL_STEPCA_URL|
CERTCTL_STEPCA_FINGERPRINT|
CERTCTL_STEPCA_PROVISIONER|
CERTCTL_STEPCA_PROVISIONER_NAME|
CERTCTL_STEPCA_PROVISIONER_KEY|
CERTCTL_STEPCA_PROVISIONER_JWK|
CERTCTL_STEPCA_PROVISIONER_PASSWORD|
CERTCTL_STEPCA_PASSWORD|
CERTCTL_STEPCA_KEY_PATH|
CERTCTL_STEPCA_ROOT_CA|
CERTCTL_WEBHOOK_URL|
CERTCTL_WEBHOOK_SECRET|
CERTCTL_ACME_EAB_KID|
CERTCTL_ACME_EAB_HMAC|
CERTCTL_ACME_DNS_PROPAGATION_WAIT|
CERTCTL_AUDIT_EXCLUDE_PATHS|
CERTCTL_TLS_|
CERTCTL_TLS_INSECURE_SKIP_VERIFY|
CERTCTL_SCEP_|
CERTCTL_SERVER_CA_BUNDLE_PATH|
CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY|
CERTCTL_QA_[A-Z_]+|
CERTCTL_ACME_|
CERTCTL_ACME_SERVER_
)$'
# ^ The CERTCTL_OPENSSL_* / CERTCTL_STEPCA_* / CERTCTL_WEBHOOK_* /
# CERTCTL_ACME_EAB_* / CERTCTL_ACME_DNS_PROPAGATION_WAIT /
# CERTCTL_AUDIT_EXCLUDE_PATHS / CERTCTL_TLS_* / CERTCTL_SERVER_* /
# CERTCTL_QA_* sets are documented integration-surface contracts
# (script invocations, per-issuer config-blob field names,
# per-notifier config-blob field names, demo-stack overrides,
# test fixtures) — not server-side env vars in config.go.
#
# CERTCTL_ACME_ + CERTCTL_ACME_SERVER_ are bare-prefix forms
# operator docs use to describe namespace separation between the
# consumer-side ACMEConfig (full names like CERTCTL_ACME_DIRECTORY_URL
# defined in config.go) and the ACME server's CERTCTL_ACME_SERVER_*
# prefix (full names like CERTCTL_ACME_SERVER_ENABLED defined in
# config.go::ACMEServerConfig). The bare prefixes themselves are
# never read by config.go — they're only doc prose — so they
# allowlist alongside the existing CERTCTL_SCEP_ + CERTCTL_TLS_
# bare-prefix entries.
# The audit's "37 docs-only" count over-flagged these; the
# closure narrows the gate to the specific drift sites
# (renewal-interval rename + 6 config-only) and allowlists
# the documented external contracts here.
ALLOWED_FLAT=$(echo "$ALLOWED" | tr -d '\n ')
DOCS_ONLY=$(comm -13 /tmp/g3-defined.txt /tmp/g3-docs.txt | grep -vE "$ALLOWED_FLAT" || true)
CONFIG_ONLY=$(comm -23 /tmp/g3-defined.txt /tmp/g3-docs.txt || true)
if [ -n "$DOCS_ONLY" ]; then
  echo "::error::G-3 regression: env var(s) mentioned in docs but not defined in Go source AND not in the documented integration-surface allowlist:"
  echo "$DOCS_ONLY"
  echo ""
  echo "Either delete from docs (phantom/typo) or add to config.go,"
  echo "or add to the ALLOWED list with a one-line justification."
  exit 1
fi
if [ -n "$CONFIG_ONLY" ]; then
  echo "::error::G-3 regression: env var(s) defined in Go source but never documented:"
  echo "$CONFIG_ONLY"
  echo ""
  echo "Add an entry to docs/features.md (or another canonical doc) so operators can find it."
  exit 1
fi
echo "G-3 env-docs-drift: clean."
