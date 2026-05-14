#!/usr/bin/env bash
# scripts/ci-guards/helm-templates-lint.sh
#
# Phase 4 closure (2026-05-14): Helm chart lint + template-render gate.
#
# Runs `helm lint` against the chart and `helm template` against four
# representative value combinations to catch:
#   - Syntax errors in any chart template
#   - Schema-violation in values.yaml
#   - Missing required values uncovered by the opt-in toggles
#     (backup, monitoring.prometheusRules, migrations.viaHook)
#   - Render errors when new templates are added without updating
#     this guard's coverage matrix
#
# The opt-in templates added in Phase 4 (backup-cronjob.yaml,
# prometheusrules.yaml, migration-job.yaml) default OFF; without
# explicit coverage in the guard's matrix they would never render in
# CI and silent breakage could ship.

set -euo pipefail

CHART_DIR="deploy/helm/certctl"

if [ ! -d "$CHART_DIR" ]; then
  echo "helm-templates-lint: skipped — $CHART_DIR not found (running outside repo root?)"
  exit 0
fi

if ! command -v helm >/dev/null 2>&1; then
  echo "helm-templates-lint: skipped — helm not on PATH."
  echo "  Install: https://helm.sh/docs/intro/install/"
  exit 0
fi

echo "helm-templates-lint: running helm lint"
helm lint "$CHART_DIR" >/dev/null

# Minimal valid value set to satisfy chart preflight validators
# (server.tls.existingSecret, server.auth.apiKey, postgresql.auth.password).
# These are NOT real secrets — they're just non-empty strings to
# make the chart render in lint mode.
BASE_VALUES=(
  --set "server.tls.existingSecret=lint-test-tls"
  --set "server.auth.apiKey=lint-test-apikey"
  --set "postgresql.auth.password=lint-test-pgpass"
)

render_and_check() {
  local label="$1"
  shift
  local out
  out="$(helm template "$CHART_DIR" "${BASE_VALUES[@]}" "$@" 2>&1)" || {
    echo "helm-templates-lint: FAIL — template render error for '$label'"
    echo "$out" | tail -20
    return 1
  }
  echo "helm-templates-lint: OK — '$label'"
}

# Matrix:
#  1. Defaults (no Phase 4 opt-ins) — confirms the chart still
#     renders cleanly when every Phase 4 feature is off.
#  2. backup.enabled=true (PVC sink) — confirms backup-cronjob renders.
#  3. backup.enabled=true + sink=s3 — confirms S3 sink branch renders.
#  4. monitoring.prometheusRules.enabled=true — confirms PrometheusRule renders.
#  5. migrations.viaHook=true — confirms migration-job hook renders.
#  6. All Phase 4 opt-ins on simultaneously — confirms no template
#     interaction breaks the others.
render_and_check "defaults"
render_and_check "backup.enabled (pvc)" \
  --set "backup.enabled=true"
render_and_check "backup.enabled (s3)" \
  --set "backup.enabled=true" \
  --set "backup.sink=s3" \
  --set "backup.s3.bucket=lint-test-bucket"
render_and_check "monitoring.prometheusRules.enabled" \
  --set "monitoring.enabled=true" \
  --set "monitoring.prometheusRules.enabled=true"
render_and_check "migrations.viaHook" \
  --set "migrations.viaHook=true"
render_and_check "all phase 4 opt-ins" \
  --set "backup.enabled=true" \
  --set "monitoring.enabled=true" \
  --set "monitoring.prometheusRules.enabled=true" \
  --set "migrations.viaHook=true"

echo "helm-templates-lint: all matrix combinations rendered cleanly"
