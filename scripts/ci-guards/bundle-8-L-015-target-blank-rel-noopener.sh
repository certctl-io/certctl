#!/usr/bin/env bash
# scripts/ci-guards/bundle-8-L-015-target-blank-rel-noopener.sh
#
# Audit L-015 / CWE-1022 (reverse-tabnabbing): every <a target="_blank">
# MUST carry rel="noopener noreferrer" so a malicious page at the
# target URL cannot navigate the opener window via window.opener.
# At Bundle-8 close all 3 sites in the codebase already comply —
# this guard prevents regression. The ExternalLink component
# (web/src/components/ExternalLink.tsx) is the recommended way to
# add new external links.
#
# Test files (web/src/**/*.test.{ts,tsx}) are excluded so test
# docstrings or fixture data describing the attack vector by
# name don't trip the guard — symmetric with the L-019 guard.

set -e
OFFENDERS=$(grep -rnE 'target=["'"'"']?_blank["'"'"']?' web/src/ 2>/dev/null \
  | grep -v 'noopener noreferrer' \
  | grep -v 'web/src/components/ExternalLink.tsx' \
  | grep -vE '\.test\.(ts|tsx)(:[0-9]+)?:' \
  || true)
if [ -n "$OFFENDERS" ]; then
  echo "::error::L-015 regression: target=\"_blank\" without rel=\"noopener noreferrer\":"
  echo "$OFFENDERS"
  echo ""
  echo "Either add rel=\"noopener noreferrer\" inline,"
  echo "or migrate to <ExternalLink> from web/src/components/ExternalLink.tsx."
  exit 1
fi
echo "L-015 target-blank-rel-noopener: clean."
