#!/usr/bin/env bash
# scripts/ci-guards/test-naming-convention.sh
#
# Bundle Q / I-001-extended (2026-04-27): hard-fail. Catches tests
# Go itself would silently skip — `func TestX...` where the first
# letter after `Test` is lowercase. Go's testing runner requires
# uppercase to register the test (^Test[A-Z]); lowercase tests
# don't run, which is a real bug a CI guard should catch.
#
# The original audit's `Test<Func>_<Scenario>_<ExpectedResult>`
# triple-token prescription was relaxed: single-function pin
# tests like `TestNewAgent` or `TestSplitPEMChain` are valid Go
# convention, with internal scenarios expressed via t.Run subtests.
# Requiring the underscore-Scenario-Result triple repo-wide would
# mean renaming 167 legitimate tests for no observable behavior
# change.

set -e
INVALID=$(grep -rnE '^func Test[a-z]' --include='*_test.go' . \
  | grep -v '_test.go.bak' \
  || true)
if [ -n "$INVALID" ]; then
  echo "::error::Test-naming convention regression: tests Go would silently skip (lowercase after 'Test'):"
  echo "$INVALID"
  echo "Rename to start with an uppercase letter — Go's test runner only matches ^Test[A-Z]."
  exit 1
fi
echo "test-naming-convention: clean (no Go-invalid test names found)."
