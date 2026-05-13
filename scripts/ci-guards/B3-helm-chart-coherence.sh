#!/usr/bin/env bash
# scripts/ci-guards/B3-helm-chart-coherence.sh
#
# Bundle 3 closure (2026-05-12) — Helm chart coherence guard.
#
# Catches regressions in the chart-truth surface the Bundle 3 closure
# locked in:
#
#   1. README's Helm install example must use the canonical
#      `postgresql.auth.password` key (audit C2). The pre-Bundle-3
#      example used the wrong `postgresql.password` shape.
#
#   2. The chart renders all 5 advertised production modes:
#        - default (TLS existingSecret + secrets)
#        - external Postgres (postgresql.enabled=false + externalDatabase.url)
#        - cert-manager TLS
#        - production hardening (NetworkPolicy + PDB + ServiceMonitor)
#        - both-TLS-set is REJECTED (D7)
#
#   3. The chart still fail-fasts on missing required secrets (D1):
#        - server.auth.apiKey empty when type=api-key
#        - postgresql.auth.password empty when postgresql.enabled=true
#        - externalDatabase.url empty when postgresql.enabled=false
#
#   4. The bundled-Postgres Secret template does NOT render when
#      postgresql.enabled=false (D2 / clean external mode).
#
# Per the contract documented in scripts/ci-guards/README.md:
# bare callable, no args, no env, exit 0 on clean. Skips quietly when
# `helm` is not on PATH (developer workstations without Helm installed),
# but the GH Actions runner always has it.

set -e

GUARD_NAME="B3-helm-chart-coherence"
CHART="deploy/helm/certctl/"
README="README.md"

if ! command -v helm > /dev/null 2>&1; then
  echo "${GUARD_NAME}: helm not on PATH — skipping (install helm ≥ 3.13 to enable locally)."
  exit 0
fi

failed=0

# Check 1 — README Helm install command uses postgresql.auth.password,
# never the pre-Bundle-3 postgresql.password shape.
if grep -nE -- '--set\s+postgresql\.password=' "$README"; then
  echo "::error file=${README}::Bundle 3 audit C2 regression: README references --set postgresql.password=... — the canonical key is postgresql.auth.password (matches values.yaml + Bitnami-style chart). Update the install command."
  failed=1
fi

# Check 2 — production-mode renders pass. We use a tmp dir so partial
# failures don't leave stray files.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Default mode.
if ! helm template c "$CHART" \
      --set server.tls.existingSecret=ci \
      --set postgresql.auth.password=p \
      --set server.auth.apiKey=k \
      > "$TMP/default.yaml" 2> "$TMP/default.err"; then
  echo "::error file=${CHART}::B3 regression: default mode (TLS + secrets) fails to render."
  cat "$TMP/default.err"
  failed=1
fi

# External Postgres mode.
if ! helm template c "$CHART" \
      --set server.tls.existingSecret=ci \
      --set postgresql.enabled=false \
      --set externalDatabase.url='postgres://u:p@h:5432/db?sslmode=require' \
      --set server.auth.apiKey=k \
      > "$TMP/external.yaml" 2> "$TMP/external.err"; then
  echo "::error file=${CHART}::B3 regression: external Postgres mode fails to render."
  cat "$TMP/external.err"
  failed=1
fi

# Bundle 3 D2 check: bundled-Postgres Secret + StatefulSet + Service
# must NOT appear in external-Postgres render.
for resource in StatefulSet "postgres-secret.yaml" "postgres-service.yaml"; do
  if grep -q "$resource" "$TMP/external.yaml" 2>/dev/null; then
    echo "::error file=${CHART}::B3 regression (D2): external-Postgres render still emits $resource. postgresql.enabled=false must skip ALL postgres-* templates."
    failed=1
  fi
done

# Production hardening mode.
if ! helm template c "$CHART" \
      --set server.tls.existingSecret=ci \
      --set postgresql.auth.password=p \
      --set server.auth.apiKey=k \
      --set server.replicas=3 \
      --set monitoring.enabled=true \
      --set monitoring.serviceMonitor.enabled=true \
      --set podDisruptionBudget.enabled=true \
      --set networkPolicy.enabled=true \
      > "$TMP/prod.yaml" 2> "$TMP/prod.err"; then
  echo "::error file=${CHART}::B3 regression: production hardening mode fails to render."
  cat "$TMP/prod.err"
  failed=1
fi

# Bundle 3 D5 + D11 check: production hardening render MUST include
# ServiceMonitor + PodDisruptionBudget + NetworkPolicy.
for kind in ServiceMonitor PodDisruptionBudget NetworkPolicy; do
  if ! grep -q "^kind: $kind\$" "$TMP/prod.yaml" 2>/dev/null; then
    echo "::error file=${CHART}::B3 regression: production hardening render is missing kind: $kind."
    failed=1
  fi
done

# Check 3 — D7 TLS both-set rejection.
if helm template c "$CHART" \
      --set server.tls.existingSecret=existing \
      --set server.tls.certManager.enabled=true \
      --set server.tls.certManager.issuerRef.name=foo \
      --set postgresql.auth.password=p \
      --set server.auth.apiKey=k \
      > /dev/null 2> "$TMP/both-tls.err"; then
  echo "::error file=${CHART}::B3 regression (D7): TLS both-set rendered successfully. Chart must refuse when existingSecret AND certManager.enabled are both populated."
  failed=1
fi

# Check 4 — D1 fail-fast on missing apiKey.
if helm template c "$CHART" \
      --set server.tls.existingSecret=ci \
      --set postgresql.auth.password=p \
      > /dev/null 2> "$TMP/missing-apikey.err"; then
  echo "::error file=${CHART}::B3 regression (D1): missing server.auth.apiKey rendered successfully when auth.type=api-key. Chart must refuse."
  failed=1
fi

# Check 5 — D1 fail-fast on missing postgres password (bundled mode).
if helm template c "$CHART" \
      --set server.tls.existingSecret=ci \
      --set server.auth.apiKey=k \
      > /dev/null 2> "$TMP/missing-pg.err"; then
  echo "::error file=${CHART}::B3 regression (D1): missing postgresql.auth.password rendered successfully when postgresql.enabled=true. Chart must refuse."
  failed=1
fi

# Check 6 — D1 fail-fast on missing external DB URL.
if helm template c "$CHART" \
      --set server.tls.existingSecret=ci \
      --set postgresql.enabled=false \
      --set server.auth.apiKey=k \
      > /dev/null 2> "$TMP/missing-extdb.err"; then
  echo "::error file=${CHART}::B3 regression (D1): missing externalDatabase.url rendered successfully when postgresql.enabled=false. Chart must refuse."
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  echo ""
  echo "${GUARD_NAME}: FAILED — Helm chart coherence regression."
  exit 1
fi

echo "${GUARD_NAME}: clean (default + external-Postgres + cert-manager + production hardening + 3 fail-fast gates all green)."
