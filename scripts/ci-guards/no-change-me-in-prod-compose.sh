#!/usr/bin/env bash
# scripts/ci-guards/no-change-me-in-prod-compose.sh
#
# Phase 2 DEPL-M2 closure (2026-05-13): the demo Compose overlay
# (`deploy/docker-compose.demo.yml`) intentionally ships placeholder
# `change-me-*` credentials (CERTCTL_AUTH_SECRET=change-me-in-production,
# CERTCTL_CONFIG_ENCRYPTION_KEY=change-me-32-char-encryption-key, etc.)
# behind the DemoModeAck=true exemption in Validate(). The runtime
# fail-closed guards in internal/config/config.go::Validate (Bundle 2
# 2026-05-12) refuse to start when those strings reach a non-demo
# config, so the runtime path is protected.
#
# This guard catches the SAME class of mistake one layer earlier — at
# CI / PR-review time, before the change reaches any operator's
# workstation. Specifically: any non-demo compose file (base
# `docker-compose.yml`, `docker-compose.dev.yml`, or any operator-
# authored overlay that doesn't carry the `.demo.yml` suffix) must
# never contain a `change-me-` literal.
#
# This is belt-and-suspenders alongside the runtime guard: a
# placeholder leaking into the base compose surfaces here BEFORE any
# operator's `docker compose up` triggers the fail-closed boot.
#
# Allowlist: deploy/docker-compose.demo.yml — the demo overlay
# legitimately ships the placeholder strings as documented defaults.

set -e

# Scan every tracked compose file under deploy/ except the demo overlay.
# Exclude comment lines (starting with optional whitespace then `#`) so
# documentation discussing the placeholder pattern doesn't trip the guard.
# The remaining matches are actual YAML key=value or env: lines.
VIOLATIONS=$(git ls-files 'deploy/*compose*.yml' 'deploy/*compose*.yaml' \
    | grep -v 'docker-compose\.demo\.yml$' \
    | xargs grep -nE 'change-me-' 2>/dev/null \
    | grep -vE ':\s*#' \
    || true)

if [ -n "$VIOLATIONS" ]; then
  echo "::error::DEPL-M2 regression: 'change-me-' placeholder credential leaked into a non-demo compose file."
  echo ""
  echo "Placeholder credentials are exempt only in deploy/docker-compose.demo.yml"
  echo "(the demo overlay sets DemoModeAck=true at runtime, which unlocks them via"
  echo "Validate()'s Bundle 2 fail-closed guards). Production / dev / staging compose"
  echo "files must use real values."
  echo ""
  echo "Violations:"
  echo "$VIOLATIONS"
  echo ""
  echo "Fix: either move the offending compose to the .demo.yml overlay, or replace"
  echo "the placeholder with an env-var interpolation (\${CERTCTL_AUTH_SECRET:?required})"
  echo "that fails compose-up cleanly when the operator forgot to set it."
  exit 1
fi

echo "no-change-me-in-prod-compose guard OK: no 'change-me-' placeholders in non-demo compose files"
