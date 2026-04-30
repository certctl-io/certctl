#!/usr/bin/env bash
# scripts/ci-guards/D-1-D-2-statusbadge-phantom.sh
#
# D-1 master closed cat-d-359e92c20cbf (Agent: 'Stale' dead key,
# 'Degraded' missing), cat-d-9f4c8e4a91f1 (Notification: 'dead'
# missing), cat-d-1447e04732e7 (Cert: 'PendingIssuance' dead
# key), cat-f-cert_detail_page_key_render_fallback (render-site
# uses cert.X directly), and cat-f-ae0d06b6588f (Certificate
# TS phantom fields). This script grep-fails the build if either
# half of the closure is reverted:
#
#   1. The dead StatusBadge keys ('Stale' for Agent, 'PendingIssuance'
#      for Cert) reappearing as map literals, OR
#   2. The five phantom Certificate TS fields (serial_number,
#      fingerprint_sha256, key_algorithm, key_size, issued_at)
#      reappearing on the `Certificate` interface in types.ts
#      (CertificateVersion legitimately carries them and is
#      explicitly excluded by the awk pre-filter below).
#
# Comments are exempt so the closure prose in StatusBadge.tsx +
# types.ts can stay. Test files are exempt so negative tests
# asserting the dead keys fall through to neutral keep working.
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# cat-d-* / cat-f-* for the closure rationale, or
# web/src/components/StatusBadge.test.tsx for the live
# enum-coverage contract.

set -e

BAD_BADGE=$(grep -nE "^\s*(Stale|PendingIssuance)\s*:\s*'badge-" \
    web/src/components/StatusBadge.tsx 2>/dev/null \
    | grep -v '\.test\.' \
    | grep -vE '^\s*[^:]+:[0-9]+:\s*//' \
    || true)
if [ -n "$BAD_BADGE" ]; then
  echo "::error::D-1 regression: dead StatusBadge key reappeared:"
  echo "$BAD_BADGE"
  echo ""
  echo "Allowed surface: comment lines naming the removed key in"
  echo "the file's preamble. The Go-side AgentStatus values are"
  echo "Online/Offline/Degraded (no Stale); CertificateStatus values"
  echo "are Pending/Active/... (no PendingIssuance). See"
  echo "web/src/components/StatusBadge.test.tsx for the contract."
  exit 1
fi

# Certificate TS phantom-field check. Scoped to the
# `export interface Certificate {` block in web/src/api/types.ts
# — CertificateVersion legitimately declares these fields and
# must NOT trip the guardrail. The awk window opens on the
# exact `Certificate {` header (not `CertificateVersion {`,
# not `CertificateProfile {`) and closes at the first `}`,
# then the grep matches a phantom-field declaration anywhere
# in that window.
BAD_TS=$(awk '
  /^export interface Certificate \{/ { flag=1; next }
  flag && /^\}/                     { flag=0 }
  flag                              { print FILENAME":"NR":"$0 }
' web/src/api/types.ts \
  | grep -E '\b(serial_number|fingerprint_sha256|key_algorithm|key_size|issued_at)\??\s*:' \
  || true)
if [ -n "$BAD_TS" ]; then
  echo "::error::D-1 regression: Certificate TS interface re-added a phantom field:"
  echo "$BAD_TS"
  echo ""
  echo "These fields live on CertificateVersion, not ManagedCertificate."
  echo "The Go-side ManagedCertificate has never carried them; the"
  echo "TS optional declarations were silently undefined on every"
  echo "list response. Render-site consumers (e.g. CertificateDetailPage)"
  echo "use latestVersion?.field as the canonical access path."
  echo "See coverage-gap-audit-2026-04-24-v5/unified-audit.md"
  echo "cat-f-ae0d06b6588f for the closure rationale."
  exit 1
fi

# D-2 master closed five diff-05x06-* type-drift findings:
# Agent (5 phantoms), Issuer (1 phantom), Notification (1 phantom)
# — TRIM half. The Target (2 missing fields) and DiscoveredCertificate
# (1 missing field) — ADD half is pinned by the literal-construction
# blocks in web/src/api/types.test.ts, not a CI grep. The phantom-
# trim regression vector is an awk-windowed grep per interface
# mirroring the D-1 Certificate check above.
#
# See coverage-gap-audit-2026-04-24-v5/unified-audit.md
# diff-05x06-7cdf4e78ae24 (Agent), diff-05x06-97fab8783a5c (Issuer),
# diff-05x06-caba9eb3620e (Notification) for the closure rationale.

# D-2 Agent phantom-field check. The grep matches `last_heartbeat`
# but NOT `last_heartbeat_at` (the legitimate Go-emitted field) —
# the `\b...\b` boundaries plus the `grep -v 'last_heartbeat_at'`
# filter handle that.
BAD_AGENT=$(awk '
  /^export interface Agent \{/ { flag=1; next }
  flag && /^\}/                 { flag=0 }
  flag                          { print FILENAME":"NR":"$0 }
' web/src/api/types.ts \
  | grep -E '\b(last_heartbeat|capabilities|tags|created_at|updated_at)\??\s*:' \
  | grep -v 'last_heartbeat_at' \
  || true)
if [ -n "$BAD_AGENT" ]; then
  echo "::error::D-2 regression: Agent TS interface re-added a phantom field:"
  echo "$BAD_AGENT"
  echo ""
  echo "The Go-side internal/domain/connector.go::Agent emits exactly:"
  echo "id, name, hostname, status, last_heartbeat_at?, registered_at,"
  echo "os, architecture, ip_address, version, retired_at?, retired_reason?."
  echo "The five fields blocked by this guard (last_heartbeat,"
  echo "capabilities, tags, created_at, updated_at) were TS phantoms"
  echo "the Go struct never emitted. See unified-audit.md"
  echo "diff-05x06-7cdf4e78ae24 for closure rationale."
  exit 1
fi

# D-2 Issuer phantom-field check.
BAD_ISSUER=$(awk '
  /^export interface Issuer \{/ { flag=1; next }
  flag && /^\}/                  { flag=0 }
  flag                           { print FILENAME":"NR":"$0 }
' web/src/api/types.ts \
  | grep -E '\bstatus\??\s*:' \
  || true)
if [ -n "$BAD_ISSUER" ]; then
  echo "::error::D-2 regression: Issuer TS interface re-added a phantom 'status' field:"
  echo "$BAD_ISSUER"
  echo ""
  echo "The Go-side internal/domain/connector.go::Issuer has no 'status'"
  echo "field — only 'enabled' (bool). Render sites derive the displayed"
  echo "status from 'enabled' at the call site (see"
  echo "web/src/pages/IssuersPage.tsx::issuerStatus). See unified-audit.md"
  echo "diff-05x06-97fab8783a5c for closure rationale."
  exit 1
fi

# D-2 Notification phantom-field check.
BAD_NOTIF=$(awk '
  /^export interface Notification \{/ { flag=1; next }
  flag && /^\}/                        { flag=0 }
  flag                                 { print FILENAME":"NR":"$0 }
' web/src/api/types.ts \
  | grep -E '\bsubject\??\s*:' \
  || true)
if [ -n "$BAD_NOTIF" ]; then
  echo "::error::D-2 regression: Notification TS interface re-added a phantom 'subject' field:"
  echo "$BAD_NOTIF"
  echo ""
  echo "The Go-side internal/domain/notification.go::NotificationEvent"
  echo "has no 'subject' field — only 'message'. Pre-D-2 the consumer"
  echo "at NotificationsPage.tsx had a dead '|| n.subject' fallback"
  echo "that always fell through. See unified-audit.md"
  echo "diff-05x06-caba9eb3620e for closure rationale."
  exit 1
fi
echo "D-1 + D-2 statusbadge-phantom: clean."
