#!/usr/bin/env bash
# scripts/ci-guards/G-2-api-key-hash-json.sh
#
# G-2 closed cat-s5-apikey_leak by tagging Agent.APIKeyHash
# `json:"-"` and adding a defense-in-depth Agent.MarshalJSON that
# zeroes the field on the marshal-time copy. This script grep-fails
# the build if `api_key_hash` reappears in any of the *additive*
# JSON-emitting surfaces: a Go struct json tag in internal/domain/,
# an OpenAPI Agent schema property, a TypeScript field declaration
# in web/src/, or an enum-list / discriminator in handler
# production code.
#
# Repository, migration, seed, service, integration-test, and
# unit-test files are exempt — those are server-internal use
# sites (the DB column stays, the in-memory struct field stays,
# the auth-lookup path stays). Comment lines are exempt so the
# G-2 closure rationale can stay in the source.
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# cat-s5-apikey_leak for the closure rationale, or
# internal/domain/connector.go::Agent::MarshalJSON for the
# redaction enforcement.

set -e

# Scoped patterns that indicate api_key_hash being added back
# to a JSON-emitting surface. Each catches a regression shape
# that pre-G-2 actually shipped or that a future refactor
# could plausibly introduce:
#   - Go struct tag:           `json:"api_key_hash"`
#   - Frontend interface:      api_key_hash[?]: string
#   - OpenAPI schema property: api_key_hash:   (column-aligned)
#   - YAML enum / array:       - api_key_hash
BAD=$(grep -rnEH \
    -e 'json:"api_key_hash[",]' \
    -e '^\s*api_key_hash\??\s*:' \
    -e '^\s*-\s*api_key_hash\s*$' \
    internal/domain/ \
    internal/api/ \
    cmd/ \
    api/openapi.yaml \
    web/src/ \
    2>/dev/null \
    | grep -v '_test.go' \
    | grep -vE '^\s*[^:]+:[0-9]+:\s*(//|#)' \
    || true)
if [ -n "$BAD" ]; then
  echo "::error::G-2 regression: api_key_hash reappeared in a JSON-emitting surface:"
  echo "$BAD"
  echo ""
  echo "Allowed surface for api_key_hash literals: comment lines,"
  echo "the database column (migrations/), the in-memory struct"
  echo "field tagged \`json:\"-\"\`, and the repository / service"
  echo "use sites. See internal/domain/connector.go::Agent and"
  echo "coverage-gap-audit-2026-04-24-v5/unified-audit.md"
  echo "cat-s5-apikey_leak for the closure rationale."
  exit 1
fi
echo "G-2 api-key-hash-json: clean."
