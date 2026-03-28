# certctl Test Suite Audit & Manual Testing Guide

Last updated: March 28, 2026

This document covers the automated test suite inventory, identified gaps, and a complete manual testing guide for v2.1 release validation.

## Contents

1. [Automated Test Suite Inventory](#automated-test-suite-inventory)
2. [Test Gap Analysis](#test-gap-analysis)
3. [Manual Testing Guide](#manual-testing-guide)
4. [Pre-Release Checklist](#pre-release-checklist)

---

## Automated Test Suite Inventory

### Summary

| Layer | Test Files | Test Functions | Subtests | Coverage Target | Notes |
|-------|-----------|---------------|----------|-----------------|-------|
| Service | 12 | ~120 | ~185 | 60% (CI gate) | Best-covered layer |
| Handler | 12 | ~140 | ~145 | 60% (CI gate) | Near-complete endpoint coverage |
| Domain | 3 | ~16 | ~12 | 40% (CI gate) | Only revocation, discovery, verification tested |
| Middleware | 2 | ~14 | ~10 | 50% (CI gate) | Audit + CORS tested |
| Integration | 2 | ~15 | ~25 | — | Lifecycle + negative paths |
| Connector (Issuer) | 4 | ~41 | — | — | Local CA, ACME DNS, step-ca, OpenSSL |
| Connector (Target) | 2 | ~12 | — | — | Traefik, Caddy |
| Connector (Notifier) | 4 | ~20 | — | — | Slack, Teams, PagerDuty, OpsGenie |
| Validation | 2 | ~10 | ~80 | — | command.go + fuzz tests |
| Scheduler | 1 | ~5 | — | — | Startup/shutdown only |
| CLI | 1 | ~14 | — | — | All 10 subcommands |
| Repository | 2 | ~24 | ~50 | — | testcontainers-go, skipped in CI |
| Agent | 1 | ~5 | — | — | verify.go only |
| Frontend (API) | 1 | 89 | — | — | 96% API function coverage |
| Frontend (Utils) | 1 | 18 | — | — | 100% utility coverage |
| **Total** | **~50** | **~835+** | **~200+** | — | **1100+ total test points** |

### CI Pipeline

Every push runs (`.github/workflows/ci.yml`):

- `go vet ./...`
- `golangci-lint` (11 linters including gosec, bodyclose, errcheck)
- `govulncheck` (dependency CVE scanning)
- `go test -race` (race detection across service, handler, middleware, scheduler, connector, domain, validation)
- `go test -cover` with per-layer thresholds (service 55%, handler 60%, domain 40%, middleware 30%)
- Frontend: `tsc --noEmit`, `vitest run`, `vite build`

### What's Well-Tested

**Service layer** — renewal flows (server + agent keygen modes), revocation (all 8 RFC 5280 reasons), CRL/OCSP generation, discovery (process report, claim, dismiss, summary), network scan (CIDR expansion, validation, CRUD), stats (5 aggregations), EST enrollment (GetCACerts, SimpleEnroll/ReEnroll, CSRAttrs), export (PEM split, PKCS#12 encoding), verification (record/get results), issuer adapter (issue, renew, revoke with EKU forwarding).

**Handler layer** — all 12 resource handlers tested with success paths, 404/400/405/500 error paths, input validation (required fields, type checks, JSON parsing), query parameter parsing (pagination, filters, sort, cursor, sparse fields). CRUD endpoints, revocation, CRL, OCSP, EST, export, verification handlers all covered.

**Connectors** — Local CA (self-signed, sub-CA with RSA/ECDSA, renewal, config validation), ACME DNS solver (present, cleanup, DNS-PERSIST-01), step-ca (issue, renew, revoke via mock HTTP), OpenSSL (config validation, script execution, timeout), Traefik (file write, directory validation), Caddy (API mode, file mode, config validation), all 4 notifiers (webhook payloads, HTTP errors, auth headers, config defaults).

**Validation** — shell injection prevention with 80+ adversarial patterns (fuzz tests), domain validation, ACME token validation.

**Frontend** — 107 Vitest tests: all API client functions (certificates, agents, jobs, policies, profiles, owners, teams, agent groups, discovery, network scans, stats, metrics, export, health), utility functions (date formatting, time-ago, expiry color), both happy path and some error scenarios.

---

## Test Gap Analysis

### P0 — Critical Gaps (Production Risk)

**1. No tests for `service/deployment.go`** — deployment orchestration (creating deployment jobs, target resolution, deployment execution) is completely untested. This is the core path that actually puts certificates onto servers.
- Missing: `CreateDeploymentJobs`, `ProcessDeploymentJob`, target connector dispatch
- Risk: silent deployment failures, wrong cert deployed to wrong target
- Effort: 15-20 test functions, 1-2 days

**2. Agent binary (`cmd/agent/main.go`) largely untested** — only `verify.go` has tests. The agent's registration, heartbeat loop, work polling, CSR generation, discovery scanning, and deployment execution have no automated tests.
- Missing: heartbeat error handling, CSR generation edge cases, deployment with local keys, discovery scan error paths
- Risk: agent fails silently in production, key material handling bugs
- Effort: significant — needs mock control plane HTTP server, 3-5 days
- Mitigation: the manual testing guide below covers these flows

**3. `service/target.go` untested** — target CRUD operations (Create, List, Get, Update, Delete) have service-layer tests missing.
- Risk: target configuration errors not caught
- Effort: 8-10 test functions, 0.5 days

**4. Scheduler loop execution untested** — `scheduler_test.go` only tests startup and graceful shutdown. The 6 actual loops (renewal check, job processing, health check, notifications, short-lived expiry, network scanning) are not tested for correct execution behavior.
- Risk: scheduler silently stops processing without detection
- Effort: complex — needs time manipulation and mock services, 2-3 days

### P1 — High-Priority Gaps

**5. `CompleteAgentCSRRenewal()` not tested** — this is the critical path where agent-submitted CSRs are signed by the issuer. EKU resolution from profiles, deployment job creation after signing, and CSR validation are all untested at the service layer.
- Effort: 5-8 test functions, 1 day

**6. `ExpireShortLivedCertificates()` not tested** — scheduler operation that marks short-lived certs as expired. No test coverage.
- Effort: 3-4 test functions, 0.5 days

**7. Domain models mostly untested** — only `revocation.go`, `discovery.go`, and `verification.go` have test files. Missing: `job.go` (state machine transitions), `certificate.go` (status validation), `agent_group.go` (MatchesAgent criteria), `notification.go`, `policy.go`.
- Effort: 20-30 test functions across 5 files, 2-3 days

**8. Handler gaps** — `UpdateAgentGroup`, `UpdateIssuer`, `GetNetworkScanTarget`, `UpdateNetworkScanTarget` are untested handler methods.
- Effort: ~12 test functions, 0.5 days

### P2 — Medium-Priority Gaps

**9. Frontend: zero component/page render tests** — no React component tests exist. All 22 pages and 8 shared components are untested for rendering, user interaction, modal behavior, and form validation.
- Risk: UI regressions go undetected
- Effort: significant — needs React Testing Library setup, 3-5 days for core pages

**10. Frontend: weak error handling tests** — only 13 of 78 API functions have error scenario tests. Missing: 404 errors, network timeouts, 429 rate limiting, malformed JSON responses.
- Effort: 1-2 days

**11. Context cancellation / timeout tests** — no service or handler tests verify correct behavior when contexts are cancelled or time out. Long-running operations (network scan, EST enrollment) should gracefully handle cancellation.
- Effort: 1-2 days

**12. Concurrent operation tests** — two simultaneous revocations of the same certificate, concurrent discovery reports from multiple agents, parallel deployment jobs. Race detector catches some of this but not logic bugs.
- Effort: 1-2 days

### Docker Compose Bug Found During Audit

**`migrations/000008_verification.up.sql` is NOT mounted in `deploy/docker-compose.yml`**. The verification migration exists on disk but the Docker Compose file only mounts migrations 000001-000007. This means the demo environment is missing the `verification_status`, `verified_at`, `verification_fingerprint`, and `verification_error` columns on the jobs table.

Fix: add to docker-compose.yml:
```yaml
- ../migrations/000008_verification.up.sql:/docker-entrypoint-initdb.d/008_verification.sql
```

---

## Manual Testing Guide

This guide covers end-to-end manual validation of all certctl features against the Docker Compose demo environment. Use this for v2.1 release validation.

### Setup

```bash
# Clean start (removes old data)
docker compose -f deploy/docker-compose.yml down -v
docker compose -f deploy/docker-compose.yml up -d --build

# Wait for healthy
docker compose -f deploy/docker-compose.yml ps
# All three services should show "Up (healthy)" or "Up"

# Verify
curl -s http://localhost:8443/health | jq .
# {"status":"healthy"}
```

### 1. Dashboard & Navigation

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 1.1 | Dashboard loads | Open http://localhost:8443 | Stats cards show (total certs, expiring, expired, agents). 4 charts render (heatmap, trends, distribution, issuance rate) |
| 1.2 | Sidebar navigation | Click each sidebar item | All 16 nav items load without errors: Dashboard, Certificates, Agents, Fleet Overview, Jobs, Notifications, Policies, Profiles, Issuers, Targets, Owners, Teams, Agent Groups, Audit Trail, Short-Lived, Discovery, Network Scans |
| 1.3 | Auth disabled notice | Check for login prompt | No login screen (demo runs with `CERTCTL_AUTH_TYPE=none`) |

### 2. Certificate Lifecycle

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 2.1 | List certificates | Certificates page | 15 demo certificates with status badges, names, expiry dates |
| 2.2 | Certificate detail | Click any certificate | Detail page shows: Certificate Details card, Lifecycle card, Lifecycle Timeline (4 steps), Policy & Profile editor, Version History, Tags |
| 2.3 | Trigger renewal | Click "Trigger Renewal" on `mc-api-prod` | Success banner. Jobs page shows new Renewal job |
| 2.4 | Trigger deployment | Click "Deploy" → select a target → "Deploy" | Success banner. Jobs page shows new Deployment job |
| 2.5 | Revoke certificate | Click "Revoke" on an active cert → select "Key Compromise" → confirm | Red revocation banner appears on cert detail. Status changes to "Revoked" |
| 2.6 | Archive certificate | Click "Archive" → confirm | Redirect to certificates list. Cert no longer shows (or shows as Archived) |
| 2.7 | Export PEM | Click "Export PEM" on cert detail | Browser downloads a .pem file. File contains valid PEM certificate |
| 2.8 | Export PKCS#12 | Click "Export PKCS#12" → enter password → download | Browser downloads a .p12 file |
| 2.9 | Deployment timeline | View cert detail for a cert with deployment jobs | Timeline shows: Requested (green) → Issued (green) → Deploying (status) → Active |
| 2.10 | Version history | View cert detail with multiple versions | Version list with "Current" badge on latest. Rollback button on previous versions |
| 2.11 | Inline policy editor | Click "Edit" on Policy & Profile card → change policy → Save | Policy updates. Card shows new values |

### 3. Bulk Operations

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 3.1 | Multi-select | On Certificates page, check 3 certificates | Bulk action bar appears with count |
| 3.2 | Bulk renew | Select 3 certs → "Renew Selected" | Progress bar. 3 renewal jobs created |
| 3.3 | Bulk revoke | Select 2 certs → "Revoke Selected" → choose reason → confirm | Progress bar. Both certs revoked |
| 3.4 | Bulk reassign | Select 2 certs → "Reassign Owner" → enter new owner ID → confirm | Owner updated on both certificates |
| 3.5 | Select all | Click header checkbox | All visible certs selected |

### 4. Agent & Fleet

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 4.1 | Agent list | Agents page | 5 demo agents with status (Online/Offline), OS, Architecture, IP |
| 4.2 | Agent detail | Click an agent | System Information card (OS, arch, IP, version), recent jobs, capabilities |
| 4.3 | Fleet overview | Fleet Overview page | OS distribution chart, architecture chart, version breakdown, per-platform agent listing |
| 4.4 | Agent heartbeat | Check docker-agent status | `docker-agent` shows recent heartbeat timestamp, status Online |

### 5. Jobs & Approval Workflows

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 5.1 | Job list | Jobs page | Jobs with status badges. Type and status filters work |
| 5.2 | Pending approval banner | Jobs page (if AwaitingApproval jobs exist) | Amber banner: "N jobs awaiting approval" with "Show only" link |
| 5.3 | Approve renewal | Click "Approve" on an AwaitingApproval job | Job status changes to Pending or Running |
| 5.4 | Reject renewal | Click "Reject" → enter reason → confirm | Job status changes to Cancelled. Reason recorded |
| 5.5 | Cancel job | Click "Cancel" on a Pending/Running job | Job status changes to Cancelled |
| 5.6 | Status filter | Select "AwaitingApproval" from status dropdown | Only AwaitingApproval jobs shown |
| 5.7 | Type filter | Select "Deployment" from type dropdown | Only Deployment jobs shown |

### 6. Discovery & Network Scanning

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 6.1 | Discovery page | Discovery nav item | Summary stats bar (Unmanaged/Managed/Dismissed counts), certificate table |
| 6.2 | Claim cert | Click "Claim" on an unmanaged cert → enter managed cert ID → confirm | Status changes to Managed |
| 6.3 | Dismiss cert | Click "Dismiss" on an unmanaged cert | Status changes to Dismissed |
| 6.4 | Discovery filters | Filter by status (Unmanaged) | Only unmanaged certs shown |
| 6.5 | Scan history | Expand scan history panel | List of past scans with timestamps, cert counts |
| 6.6 | Network scan list | Network Scans page | Demo scan targets with CIDRs, ports, intervals |
| 6.7 | Create scan target | Click "+ New Target" → fill form → create | New target appears in list |
| 6.8 | Trigger scan | Click "Scan Now" on a target | Scan triggered (may timeout in demo if targets unreachable — that's OK) |
| 6.9 | Delete scan target | Click "Delete" on a target → confirm | Target removed from list |

### 7. Target Connector Wizard

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 7.1 | Open wizard | Targets page → "+ New Target" | 3-step wizard opens: Select Type → Configure → Review |
| 7.2 | NGINX type | Select NGINX → Next | Config fields: Certificate Path*, Key Path*, Chain Path, Reload Command |
| 7.3 | Apache type | Select Apache → Next | Config fields: Certificate Path*, Key Path*, Chain Path, Reload Command |
| 7.4 | HAProxy type | Select HAProxy → Next | Config fields: Combined PEM Path*, Reload Command, Validate Command |
| 7.5 | Traefik type | Select Traefik → Next | Config fields: Certificate Directory*, Certificate Filename, Key Filename |
| 7.6 | Caddy type | Select Caddy → Next | Config fields: Deployment Mode*, Admin API URL, Certificate Directory, Certificate Filename, Key Filename |
| 7.7 | F5 BIG-IP type | Select F5 BIG-IP → Next | Config fields: Management IP*, Partition, Proxy Agent ID |
| 7.8 | IIS type | Select IIS → Next | Config fields: IIS Site Name*, Binding IP, Binding Port, Certificate Store |
| 7.9 | Review & create | Fill required fields → Review → Create Target | Target appears in list with correct type and config |
| 7.10 | Validation | Leave required fields empty → try to proceed | "Next" / "Review" button disabled |

### 8. Policies, Profiles & Ownership

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 8.1 | Policy list | Policies page | 5 demo policies with severity bar |
| 8.2 | Create policy | Create a new policy with name, type, severity, config | Policy appears in list |
| 8.3 | Profile list | Profiles page | Demo profiles with allowed key types, max TTL, EKUs |
| 8.4 | S/MIME profile | Check `prof-smime` profile | Shows `emailProtection` EKU, 365-day max TTL |
| 8.5 | Owner list | Owners page | Demo owners with email and team assignment |
| 8.6 | Team list | Teams page | Demo teams |
| 8.7 | Agent groups | Agent Groups page | Demo groups with dynamic criteria badges (OS, arch, CIDR, version) |

### 9. Observability

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 9.1 | Audit trail | Audit Trail page | Events with actor, action, resource, timestamp. Time range filter works |
| 9.2 | Audit export CSV | Click "Export CSV" | Downloads .csv file with filtered audit events |
| 9.3 | Audit export JSON | Click "Export JSON" | Downloads .json file with filtered audit events |
| 9.4 | Short-lived creds | Short-Lived page | Filtered view of certs with TTL < 1 hour. Live countdown timers |
| 9.5 | Notifications | Notifications page | Grouped by certificate. Read/unread state. Mark as read works |
| 9.6 | JSON metrics | `curl http://localhost:8443/api/v1/metrics \| jq .` | Returns gauges (cert totals, agent counts), counters (jobs), uptime |
| 9.7 | Prometheus metrics | `curl http://localhost:8443/api/v1/metrics/prometheus` | Returns text/plain with `certctl_` prefixed metrics, `# HELP` and `# TYPE` lines |
| 9.8 | Stats summary | `curl http://localhost:8443/api/v1/stats/summary \| jq .` | Returns total_certificates, expiring, expired, agent counts, job counts |

### 10. API Endpoints (curl)

Run these against the demo environment to verify the API layer:

```bash
# Health
curl -s http://localhost:8443/health | jq .

# Certificate CRUD
curl -s http://localhost:8443/api/v1/certificates | jq '.total'
curl -s http://localhost:8443/api/v1/certificates/mc-api-prod | jq '.common_name'
curl -s "http://localhost:8443/api/v1/certificates?status=Active&sort=-notAfter&fields=id,common_name,status,expires_at" | jq .
curl -s "http://localhost:8443/api/v1/certificates?page_size=3" | jq '.next_cursor'
curl -s "http://localhost:8443/api/v1/certificates?expires_before=2026-05-01T00:00:00Z" | jq '.total'

# Certificate deployments
curl -s http://localhost:8443/api/v1/certificates/mc-api-prod/deployments | jq .

# Renewal
curl -s -X POST http://localhost:8443/api/v1/certificates/mc-api-prod/renew | jq .

# Revocation
curl -s -X POST http://localhost:8443/api/v1/certificates/mc-internal-staging/revoke \
  -H "Content-Type: application/json" \
  -d '{"reason": "superseded"}' | jq .

# CRL (JSON)
curl -s http://localhost:8443/api/v1/crl | jq .

# Export PEM
curl -s http://localhost:8443/api/v1/certificates/mc-api-prod/export/pem | jq .
curl -s "http://localhost:8443/api/v1/certificates/mc-api-prod/export/pem?download=true" -o cert.pem

# Export PKCS#12
curl -s -X POST http://localhost:8443/api/v1/certificates/mc-api-prod/export/pkcs12 \
  -H "Content-Type: application/json" \
  -d '{"password": "test123"}' -o cert.p12

# Agents
curl -s http://localhost:8443/api/v1/agents | jq '.total'
curl -s http://localhost:8443/api/v1/agents/ag-web-prod | jq '.os, .architecture, .ip_address'
curl -s http://localhost:8443/api/v1/agents/ag-web-prod/work | jq .

# Jobs
curl -s http://localhost:8443/api/v1/jobs | jq '.total'
curl -s "http://localhost:8443/api/v1/jobs?status=AwaitingApproval" | jq '.total'

# Approval
curl -s -X POST http://localhost:8443/api/v1/jobs/JOB_ID_HERE/approve | jq .
curl -s -X POST http://localhost:8443/api/v1/jobs/JOB_ID_HERE/reject \
  -H "Content-Type: application/json" \
  -d '{"reason": "Not approved for this window"}' | jq .

# Discovery
curl -s http://localhost:8443/api/v1/discovered-certificates | jq '.total'
curl -s http://localhost:8443/api/v1/discovery-summary | jq .
curl -s http://localhost:8443/api/v1/discovery-scans | jq '.total'

# Network scan targets
curl -s http://localhost:8443/api/v1/network-scan-targets | jq '.total'
curl -s -X POST http://localhost:8443/api/v1/network-scan-targets \
  -H "Content-Type: application/json" \
  -d '{"name": "test-scan", "cidrs": ["192.168.1.0/24"], "ports": [443, 8443]}' | jq .

# Policies, profiles, teams, owners, agent groups
curl -s http://localhost:8443/api/v1/policies | jq '.total'
curl -s http://localhost:8443/api/v1/profiles | jq '.data[] | {id, name, allowed_ekus}'
curl -s http://localhost:8443/api/v1/teams | jq '.total'
curl -s http://localhost:8443/api/v1/owners | jq '.total'
curl -s http://localhost:8443/api/v1/agent-groups | jq '.total'

# Stats
curl -s http://localhost:8443/api/v1/stats/summary | jq .
curl -s http://localhost:8443/api/v1/stats/certificates-by-status | jq .
curl -s "http://localhost:8443/api/v1/stats/expiration-timeline?days=90" | jq .
curl -s "http://localhost:8443/api/v1/stats/job-trends?days=30" | jq .
curl -s "http://localhost:8443/api/v1/stats/issuance-rate?days=30" | jq .

# Metrics
curl -s http://localhost:8443/api/v1/metrics | jq .
curl -s http://localhost:8443/api/v1/metrics/prometheus

# Audit
curl -s http://localhost:8443/api/v1/audit | jq '.total'
curl -s "http://localhost:8443/api/v1/audit?resource_type=certificate&action=revoke" | jq .

# Notifications
curl -s http://localhost:8443/api/v1/notifications | jq '.total'

# Issuers and targets
curl -s http://localhost:8443/api/v1/issuers | jq '.data[] | {id, name, type}'
curl -s http://localhost:8443/api/v1/targets | jq '.data[] | {id, name, type, hostname}'
```

### 11. EST Server (RFC 7030)

EST requires `CERTCTL_EST_ENABLED=true` in the server environment. Add it to docker-compose and restart:

```bash
# Get CA certs (PKCS#7)
curl -s http://localhost:8443/.well-known/est/cacerts

# Get CSR attributes
curl -s http://localhost:8443/.well-known/est/csrattrs

# Simple enroll (requires a valid CSR in base64 DER or PEM format)
# Generate a test CSR:
openssl req -new -newkey rsa:2048 -nodes -keyout /tmp/test.key -subj "/CN=test.example.com" | \
  base64 -w0 | \
  curl -s -X POST http://localhost:8443/.well-known/est/simpleenroll \
    -H "Content-Type: application/pkcs10" \
    -d @-
```

### 12. CLI Tool

```bash
# Build CLI (requires Go)
go build -o certctl-cli ./cmd/cli/

# Configure
export CERTCTL_SERVER_URL=http://localhost:8443

# Test all subcommands
./certctl-cli health
./certctl-cli metrics
./certctl-cli certs list
./certctl-cli certs list --format json
./certctl-cli certs get mc-api-prod
./certctl-cli certs renew mc-api-prod
./certctl-cli certs revoke mc-internal-staging --reason superseded
./certctl-cli agents list
./certctl-cli jobs list

# Bulk import
echo "-----BEGIN CERTIFICATE-----
... (paste a valid PEM cert) ...
-----END CERTIFICATE-----" > /tmp/test-import.pem
./certctl-cli import /tmp/test-import.pem
```

### 13. Auth Flow (requires restart with auth enabled)

```bash
# Restart with auth
docker compose -f deploy/docker-compose.yml down
CERTCTL_AUTH_TYPE=api-key CERTCTL_AUTH_SECRET=test-secret-key \
  docker compose -f deploy/docker-compose.yml up -d --build

# API should reject without key
curl -s http://localhost:8443/api/v1/certificates
# 401 Unauthorized

# API works with key
curl -s -H "Authorization: Bearer test-secret-key" http://localhost:8443/api/v1/certificates | jq '.total'

# GUI should show login screen
# Open http://localhost:8443 — enter "test-secret-key" — dashboard loads
# Logout button in sidebar should clear auth and redirect to login
```

---

## Pre-Release Checklist

### Automated (CI must pass)

- [ ] `go vet ./...` — no issues
- [ ] `golangci-lint run ./...` — no issues
- [ ] `govulncheck ./...` — no known vulnerabilities
- [ ] `go test -race` — no race conditions detected
- [ ] Coverage thresholds met (service 55%+, handler 60%+, domain 40%+, middleware 30%+)
- [ ] `npx tsc --noEmit` — no TypeScript errors
- [ ] `npx vitest run` — all frontend tests pass (107+)
- [ ] `npx vite build` — production build succeeds

### Manual (v2.1 release gate)

- [ ] Docker Compose starts cleanly from scratch (`down -v` then `up --build`)
- [ ] All 16 sidebar navigation items load without console errors
- [ ] Dashboard charts render with demo data
- [ ] Certificate CRUD: list, detail, renew, deploy, revoke, archive all work
- [ ] Bulk operations: multi-select, bulk renew, bulk revoke with progress bars
- [ ] Export: PEM download and PKCS#12 download both produce valid files
- [ ] Target wizard: all 7 target types show correct config fields (NGINX, Apache, HAProxy, Traefik, Caddy, F5, IIS)
- [ ] Deployment timeline shows correct step progression
- [ ] Jobs page: status/type filters, approval workflow (approve/reject with reason)
- [ ] Discovery page: summary stats, claim/dismiss, scan history
- [ ] Network scans: CRUD, trigger scan
- [ ] Audit trail: time range filter, CSV export, JSON export
- [ ] Prometheus endpoint returns valid exposition format
- [ ] CLI: `health`, `certs list`, `certs get`, `agents list` all return data
- [ ] Auth flow: login screen appears with auth enabled, API rejects without key

### Known Limitations

- EST enrollment requires `CERTCTL_EST_ENABLED=true` (off by default in demo)
- Network scans will timeout scanning demo CIDRs (no real hosts) — this is expected
- Agent keygen mode is `server` in demo (production uses `agent` for key isolation)
- OCSP/CRL endpoints require the Local CA to have been used for issuance (demo uses seeded certs, not issued via Local CA — OCSP/CRL may return empty results)
- Post-deployment TLS verification requires a real TLS endpoint to probe — not testable in basic demo setup
- Verification migration (000008) needs to be added to docker-compose.yml for full feature availability

---

## Prioritized Test Backlog

For the engineering team to close gaps over the next 2-3 sprints:

**Sprint 1 (1 week):**
1. Fix docker-compose migration gap (000008_verification)
2. Add `service/deployment_test.go` — 15 tests for deployment orchestration
3. Add `service/target_test.go` — 8 tests for target CRUD
4. Add missing handler tests: UpdateAgentGroup, UpdateIssuer, Get/UpdateNetworkScanTarget

**Sprint 2 (1 week):**
5. Add `CompleteAgentCSRRenewal` service tests — 8 tests
6. Add `ExpireShortLivedCertificates` service tests — 4 tests
7. Add domain model tests for `job.go`, `certificate.go`, `agent_group.go` — 20 tests
8. Frontend: add error scenario tests for API client (404, 429, timeout) — 15 tests

**Sprint 3 (1-2 weeks):**
9. Expand scheduler tests — test loop execution with mocked time
10. Add agent binary tests — mock HTTP control plane, test heartbeat + CSR + deploy flows
11. Frontend: add React component tests for LoginPage, CertificateDetailPage, TargetsPage wizard
12. Context cancellation tests for long-running service operations
