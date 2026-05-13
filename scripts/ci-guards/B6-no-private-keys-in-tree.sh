#!/usr/bin/env bash
# scripts/ci-guards/B6-no-private-keys-in-tree.sh
#
# Bundle 6 closure (R4 / RT-L1): a real EC P-256 private key
# (cmd/agent/mc-001.key) lived in the working tree as a leftover from a
# 2025-era agent dev run. `.gitignore` line 49 (`cmd/agent/*.key`)
# meant it never reached `git ls-files`, but the file was still on
# every operator's workstation and on every CI runner's checkout, so
# `find . -name '*.key'` and any future overzealous `git add` could
# have surfaced it.
#
# This guard catches the same class of mistake from the OTHER
# direction: it scans every TRACKED file (i.e. files already in git,
# what an external acquirer's clone sees) for PEM private-key blocks
# and fails the build if any of them contain real key material outside
# the known-good test-fixture set.
#
# Allowlist rationale:
# - *_test.go files generate ephemeral keys for hermetic tests. They
#   never carry real production material — the keys are RSA/ECDSA pairs
#   minted by the test setup at runtime, then embedded as PEM so test
#   fixtures stay self-contained. Buyer review can confirm by grepping
#   for `GenerateKey(` / `crypto/rand` nearby.
# - examples/*.md sample walkthroughs deliberately include throwaway
#   keys so the operator can paste-and-run.
# - internal/scep/intune/testdata/*.pem are CERTIFICATES (no private
#   key block) — verified at write time but excluded here as a belt-
#   and-suspenders precaution.
#
# If a new file legitimately needs a sample PEM private key (e.g. a
# new connector's test fixture), add it to the allowlist below with a
# short rationale comment. Real production material — Local CA keys,
# agent keys, OIDC client secrets, session signing keys — NEVER
# appears in a checked-in file.

set -e

BAD=$(git ls-files -z \
    | xargs -0 grep -lE 'BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY' 2>/dev/null \
    | grep -vE '_test\.go$' \
    | grep -vE '^examples/' \
    | grep -vE '^internal/scep/intune/testdata/' \
    || true)

if [ -n "$BAD" ]; then
  echo "::error::B6 regression: PEM private-key block found in tracked non-test file(s):"
  echo "$BAD"
  echo ""
  echo "Real private-key material MUST NOT be checked into the repo."
  echo "If this is a legitimate sample fixture, add the path to the"
  echo "allowlist in scripts/ci-guards/B6-no-private-keys-in-tree.sh"
  echo "with a rationale comment, and verify the key is throwaway."
  echo ""
  echo "If this is leftover dev/demo material (the original Bundle 6"
  echo "trigger was cmd/agent/mc-001.key from an agent test run),"
  echo "delete the file and add the file pattern to .gitignore so it"
  echo "stops landing in working trees."
  exit 1
fi

echo "B6 guard OK: no PEM private-key blocks in tracked non-test files"
