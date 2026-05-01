#!/usr/bin/env bash
# scripts/ci-guards/test-compose-scep-coherence.sh
#
# Enforces that deploy/docker-compose.test.yml's SCEP profile config
# stays coherent with the rest of the test infrastructure: if SCEP is
# enabled in test compose, then there MUST be a CI job that exercises
# the SCEP integration test, AND the supporting fixture files must
# actually exist on disk (not just be documented in the fixtures README).
#
# Background. The 2026-04-29 SCEP RFC 8894 + Intune master bundle
# Phase I added an `e2eintune` SCEP profile to docker-compose.test.yml
# expecting deploy/test/scep_intune_e2e_test.go to exercise it. The
# test exists (//go:build integration) but was never wired into any
# CI job, AND the supporting fixtures (ra.crt + ra.key +
# intune_trust_anchor.pem) were documented in deploy/test/fixtures/
# README.md but never committed. Pre-Phase-5 (ci-pipeline-cleanup
# matrix collapse) the test stack didn't fully boot the certctl-server,
# so the gap was hidden. Post-collapse the boot validator at
# config.go::Validate() fired with CWE-306 (empty CHALLENGE_PASSWORD)
# and blocked deploy-vendor-e2e.
#
# That bundle's CI commit (this guard's predecessor commit) dropped the
# SCEP env vars + the fixtures volume mount from compose. This guard
# stops the same drift from ever recurring silently. To re-enable SCEP
# in test compose:
#
#   1. Restore the SCEP env vars (CERTCTL_SCEP_ENABLED=true +
#      CERTCTL_SCEP_PROFILES + per-profile CHALLENGE_PASSWORD + ...).
#   2. Restore the volume mount `./test/fixtures:/etc/certctl/scep:ro`.
#   3. Commit the supporting fixtures (ra.crt, ra.key,
#      intune_trust_anchor.pem) per deploy/test/fixtures/README.md.
#   4. Add a CI job that runs `go test -tags integration -run 'SCEPIntune'`
#      against the same compose stack — without it, the SCEP plumbing
#      in test compose is paying maintenance cost for zero benefit.
#
# All four must move together. This guard refuses any partial state.
#
# Per the contract documented in scripts/ci-guards/README.md:
# bare callable, no args, no env, exit 0 on clean.

set -e

GUARD_NAME="test-compose-scep-coherence"
COMPOSE_FILE="deploy/docker-compose.test.yml"
CI_FILE=".github/workflows/ci.yml"
FIXTURES_DIR="deploy/test/fixtures"

failed=0

# Phase 1: is SCEP enabled in test compose? Match `CERTCTL_SCEP_ENABLED:`
# followed by an optional quote then `true`.
if grep -qE '^\s*CERTCTL_SCEP_ENABLED:\s*"?true"?\s*$' "$COMPOSE_FILE"; then
  echo "Detected CERTCTL_SCEP_ENABLED=true in $COMPOSE_FILE"

  # Phase 2: is there a CI job that runs the SCEP integration test?
  # Match either an explicit selector (-run 'SCEPIntune' or similar) or
  # a direct reference to scep_intune_e2e_test.go.
  if ! grep -qE "scep_intune|SCEPIntune|SCEPProfile.*E2E|-run.*[Ss]cep" "$CI_FILE"; then
    echo "::error file=${CI_FILE}::CERTCTL_SCEP_ENABLED=true in ${COMPOSE_FILE} but no CI job runs the SCEP integration test. Add a job that invokes 'go test -tags integration -run SCEPIntune' against the same compose stack, OR remove the SCEP env vars from compose."
    failed=1
  fi

  # Phase 3: are the required fixture files present?
  for f in ra.crt ra.key intune_trust_anchor.pem; do
    if [ ! -f "${FIXTURES_DIR}/${f}" ]; then
      echo "::error file=${COMPOSE_FILE}::CERTCTL_SCEP_ENABLED=true in ${COMPOSE_FILE} but required SCEP fixture is missing: ${FIXTURES_DIR}/${f}. See ${FIXTURES_DIR}/README.md for the regeneration recipe."
      failed=1
    fi
  done

  # Phase 4: is the volume mount present? Without it, the cert/key
  # paths inside the container resolve to nothing.
  if ! grep -qE '^\s*-\s+\./test/fixtures:/etc/certctl/scep:ro\s*$' "$COMPOSE_FILE"; then
    echo "::error file=${COMPOSE_FILE}::CERTCTL_SCEP_ENABLED=true but the './test/fixtures:/etc/certctl/scep:ro' volume mount is missing. SCEP profile would have no fixture access."
    failed=1
  fi
fi

if [ "$failed" -ne 0 ]; then
  echo ""
  echo "${GUARD_NAME}: FAILED — SCEP test config is incoherent across compose, CI workflow, and fixtures."
  exit 1
fi

echo "${GUARD_NAME}: clean."
