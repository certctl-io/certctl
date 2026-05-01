#!/usr/bin/env bash
# scripts/ci-guards/H-1-encryption-key-min-length.sh
#
# H-1 master commit 6cb4414 ("feat(security): bodyLimit on noAuth +
# security headers + encryption-key validation (H-1 master)") added
# internal/config/config.go's minEncryptionKeyLength = 32 byte floor
# and 5 unit-test cases at internal/config/config_test.go for it.
#
# The closure was incomplete: it didn't enforce the floor against
# the literal values certctl's own deploy/docker-compose*.yml files
# pass via `CERTCTL_CONFIG_ENCRYPTION_KEY: <literal>`. Pre-Phase-5
# (ci-pipeline-cleanup matrix collapse) the test stack didn't fully
# exercise the validator at boot, so the gap was silent. Once the
# collapsed deploy-vendor-e2e job started actually booting the
# certctl-test-server, deploy/docker-compose.test.yml's 29-byte
# `test-encryption-key-32chars!!` (the name claimed 32 but the
# author miscounted: 4+1+10+1+3+1+2+5+2 = 29) failed the validator
# at startup and the whole job started failing with
# `dependency failed to start: container certctl-test-server is
# unhealthy` — without an obvious cause until the diagnostic-dump
# step in commit 69266c8 made it visible.
#
# This guard closes the recurrence path: every literal value
# CERTCTL_CONFIG_ENCRYPTION_KEY in any deploy/docker-compose*.yml
# is checked against the 32-byte floor at PR time. `${VAR:-...}`
# expansions where `...` is not a literal are skipped (they're
# operator-supplied; runtime validation handles them). Default
# values inside `${VAR:-default}` ARE checked — if the operator
# never sets the env var, the default takes effect.
#
# Per the contract documented in scripts/ci-guards/README.md:
# bare callable, no args, no env, exit 0 on clean.

set -e

GUARD_NAME="H-1-encryption-key-min-length"
MIN_BYTES=32
ENV_VAR="CERTCTL_CONFIG_ENCRYPTION_KEY"

# Find every literal value in any deploy/docker-compose*.yml.
# Matches lines of the form (with optional leading whitespace):
#
#   CERTCTL_CONFIG_ENCRYPTION_KEY: <value>
#   CERTCTL_CONFIG_ENCRYPTION_KEY: ${VAR:-<default>}
#   CERTCTL_CONFIG_ENCRYPTION_KEY: ${VAR}      # operator-supplied; skip
#
# The validator runs against whatever the runtime sees — if the env
# expansion ${VAR:-default} resolves to `default`, that's what the
# server validates against. So `default` IS a literal we should check.
# A bare ${VAR} with no default is a runtime contract — skip.

failed=0
while IFS= read -r line; do
  file=$(echo "$line" | cut -d: -f1)
  lineno=$(echo "$line" | cut -d: -f2)
  raw=$(echo "$line" | cut -d: -f3-)

  # Strip leading whitespace and the env-var name + colon.
  value=$(echo "$raw" | sed -E "s/^\s*${ENV_VAR}\s*:\s*//")
  # Strip any trailing inline comment + surrounding whitespace.
  value=$(echo "$value" | sed -E 's/\s+#.*$//' | sed -E 's/\s+$//')

  # Three cases:
  #   1. Pure literal: `value`
  #   2. Env expansion with default: `${SOMEVAR:-default}`
  #   3. Env expansion without default: `${SOMEVAR}` — skip
  case "$value" in
    '${'*':-'*'}')
      # Extract the default between :- and the closing }.
      default=$(echo "$value" | sed -E 's/.*:-(.*)\}.*/\1/')
      check="$default"
      kind="default of ${value}"
      ;;
    '${'*'}')
      # Bare env reference, no default — operator-supplied at runtime.
      continue
      ;;
    *)
      check="$value"
      kind="literal"
      ;;
  esac

  byte_len=${#check}
  if [ "$byte_len" -lt "$MIN_BYTES" ]; then
    echo "::error file=${file},line=${lineno}::${ENV_VAR} ${kind} is ${byte_len} bytes (minimum ${MIN_BYTES}). H-1 closure (config.go:1974) rejects values <32 at server boot. Generate a replacement with: openssl rand -base64 32"
    failed=1
  fi
done < <(grep -nE "^\s*${ENV_VAR}\s*:" deploy/docker-compose*.yml 2>/dev/null || true)

if [ "$failed" -ne 0 ]; then
  echo ""
  echo "${GUARD_NAME}: FAILED — at least one ${ENV_VAR} literal violates the 32-byte floor."
  exit 1
fi

echo "${GUARD_NAME}: clean."
