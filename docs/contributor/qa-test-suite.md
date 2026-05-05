# QA Test Suite Guide (`qa_test.go`)

> Last reviewed: 2026-05-05

> **Audience:** Anyone running release QA for certctl — whether you're a first-time contributor or the maintainer cutting a release tag.
>
> **Self-contained.** Through 2026-05-04 this doc was a companion to a separate `docs/testing-guide.md` (the *what* to test) — that companion was pruned during the Phase 5 docs overhaul (its content dispersed across the audience-organized doc tree). The Part-by-Part Coverage Map below is now the canonical inventory of QA Parts.

---

## Test Suite Health (regenerate via `make qa-stats`)

> Snapshot at HEAD. Re-run `make qa-stats` to refresh; the QA-doc seed-count drift guard (`.github/workflows/ci.yml::QA-doc seed-count drift guard`) catches out-of-date cert / issuer counts on every PR. The Part-count drift guard retired in the 2026-05-04 docs overhaul Phase 5 (testing-guide.md was pruned; Part counts are now tracked inside `qa_test.go` itself, not against an external doc). **Last regenerated: 2026-04-27 (Bundle P).**

| Metric | Value | Target | Status |
|---|---|---|---|
| Backend test files | 221 | n/a | ℹ |
| Backend `Test*` functions | 2,454 | n/a | ℹ |
| Backend `t.Run` subtests | 778 | n/a | ℹ |
| Frontend test files | 38 | n/a | ℹ |
| Fuzz targets | 11 | ≥10 (one per hand-rolled parser) | ✓ |
| `t.Skip` sites | 60 | each carries valid rationale (Bundle O audit) | ✓ |
| `qa_test.go` Part_* subtests | 53 | covers 49 of 56 historical QA Parts directly + Parts 15–17 indirectly via Parts 42–46 | ✓ |
| Existential cluster line cov (post-Bundle-J + L.B + Bundle 0.7) | acme 55.6%, stepca 90.4%, local-issuer ≥86%, crypto ≥85% | ≥95% | △ ACME below; tracked in `coverage-matrix.md` |
| Mutation kill rate (Existential) | unmeasured (operator-runnable per Strengthening #5) | ≥90% | ⚠ |
| Race detector clean (`-count=10`) | partial (`-count=3` clean per Phase 0) | 0 races | ⚠ |

## What Is This File?

`deploy/test/qa_test.go` is a single Go test file (~1700 lines) that automates the historical QA Part inventory (preserved in the Part-by-Part Coverage Map below) against a running certctl Docker Compose demo stack. It replaces the legacy `qa-smoke-test.sh` bash script.

It covers **49 of 56 Parts** of the testing guide as automation; the remaining 7 are
either manual-only by design or pending QA-suite coverage:

- **49 `Part_*` automation wrappers**, **~159 leaf subtests** — API calls, database queries, source file checks, performance benchmarks
- **11 fully skipped Parts** — with documented reasons (external CAs, Windows, browser-only, etc.) — see "What This Test Does NOT Cover" below
- **4 Parts NOT YET AUTOMATED** — Parts 23 (S/MIME & EKU), 24 (OCSP/CRL), 55 (Agent Soft-Retirement), 56 (Notification Retry & Dead-Letter) — must be tested manually until QA-suite automation lands; the Part-by-Part Coverage Map below describes the surface area each Part covers
- **Manual-only flows** in addition: GUI flows, scheduler timing, Docker log inspection — must be done by a human (Coverage Map below describes each)

## Architecture

```mermaid
flowchart LR
    QA["qa_test.go (//go:build qa)<br/><br/>TestQA(t *testing.T)<br/>├─ Part01_Infra<br/>├─ Part02_Auth<br/>├─ Part03_CertCRUD<br/>├─ ...<br/>└─ Part52_HelmChart"]
    subgraph Stack["certctl demo stack<br/>docker-compose.yml + docker-compose.demo.yml"]
        Server["certctl-server :8443"]
        Postgres["postgres :5432"]
        Agents["certctl-agent (×N)<br/>↑ seed_demo.sql provisions 12 agent rows<br/>(1 active, 2 retired, 9 reserved/sentinel)<br/>for the soft-retire / FSM coverage Parts 55–56 exercise"]
    end
    QA --> Stack
```

> **Multi-agent demo stack (Bundle Q / L-004 closure).** The demo
> stack runs a single live `certctl-agent` container by default but
> the database is seeded with 12 agent rows (`migrations/seed_demo.sql`,
> grep `mc-* | ag-*` IDs). The "(×N)" notation reflects the seed-data
> reality: Parts 04 (Agents Listing), 05 (Agent Heartbeats), 55
> (Agent Soft-Retirement), and FSM coverage tables in
> `coverage-audit-2026-04-27/tables/fsm-coverage.md` exercise the full
> multi-agent population, not the one live container. Operators
> running the QA suite in a parallel-agent topology should set
> `AGENT_COUNT=N` in compose-override and re-derive the seed counts
> via `make qa-stats`.

Key design choices:

- **Build tag:** `//go:build qa` — never runs during `go test ./...` or CI. Only runs when explicitly requested.
- **Package:** `integration_test` — same package as `integration_test.go` (which uses `//go:build integration` for the test stack). They coexist but never run together.
- **Zero internal imports:** Uses only stdlib + `lib/pq` (from `go.mod`). All API interactions are plain HTTP. All JSON is decoded into lightweight local structs (`qaCert`, `qaJob`, etc.) — not the internal domain types.
- **Self-cleaning:** Tests that create data use `t.Cleanup()` to delete it afterward. The seed data is not modified.

## Prerequisites

1. **Docker Compose demo stack running:**
   ```bash
   cd deploy
   docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d
   ```
   Wait ~15 seconds for health checks to pass.

2. **Go 1.22+** installed (the project uses Go 1.25 in `go.mod`, but 1.22+ works for running tests).

3. **PostgreSQL port exposed** — the demo stack exposes port 5432 for database verification tests (table counts, schema checks).

4. **Repository checkout** — source file verification tests (`fileExists`, `fileContains`) read files relative to `qaRepoDir` (default: `../..` from `deploy/test/`).

## Running the Tests

### Full suite
```bash
cd deploy/test
go test -tags qa -v -timeout 10m ./...
```

### Single Part
```bash
go test -tags qa -v -run TestQA/Part03 ./...
```

### Single subtest
```bash
go test -tags qa -v -run TestQA/Part03_CertCRUD/Create_Minimal ./...
```

### With custom environment
```bash
CERTCTL_QA_SERVER_URL=https://staging.internal:8443 \
CERTCTL_QA_API_KEY=my-staging-key \
CERTCTL_QA_DB_URL=postgres://certctl:secret@db.internal:5432/certctl?sslmode=require \
CERTCTL_QA_REPO_DIR=/path/to/certctl \
go test -tags qa -v -timeout 10m ./...
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CERTCTL_QA_SERVER_URL` | `https://localhost:8443` | certctl server URL (HTTPS-only as of v2.2) |
| `CERTCTL_QA_API_KEY` | `change-me-in-production` | API key for Bearer auth |
| `CERTCTL_QA_DB_URL` | `postgres://certctl:certctl@localhost:5432/certctl?sslmode=disable` | PostgreSQL connection string |
| `CERTCTL_QA_REPO_DIR` | `../..` | Path to certctl repo root (for source file checks) |
| `CERTCTL_QA_CA_BUNDLE` | `./certs/ca.crt` | PEM CA bundle pinned for TLS verification. The demo stack's `certctl-tls-init` container writes here. |
| `CERTCTL_QA_INSECURE` | `false` | Set to `"true"` to skip TLS verification (e.g. before the init container finishes). Never use outside the demo harness. |

## Part-by-Part Coverage Map

This table shows what each Part tests and what's left for manual verification.

| Part | Testing Guide Section | Automated Subtests | What's Automated | What's Manual |
|------|----------------------|-------------------|-----------------|--------------|
| 1 | Infrastructure & Deployment | 8 | Table count, health/ready endpoints, seed data counts (certs, agents, issuers, targets, policies) | Docker container health, log inspection, volume mounts |
| 2 | Authentication & Security | 4 | No-auth 401, bad-key 401, health-no-auth 200, no private keys in API | CORS preflight, rate limiting (429 + Retry-After), TLS config |
| 3 | Certificate Lifecycle | 10 | Create (minimal + full), get, 404, list pagination, status/issuer filters, sparse fields, update, archive | Deployment trigger, version history, certificate detail UI |
| 4 | Renewal Workflow | 3 | Trigger renewal, 404 on nonexistent, agent work endpoint | AwaitingCSR flow, agent key generation, full issuance cycle |
| 5 | Revocation | 5 | Revoke (default reason), already-revoked, nonexistent, invalid reason, CRL JSON | DER CRL, OCSP responder, revocation notifications |
| 6 | Policies & Profiles | 6 | Policy CRUD (create/delete), invalid type 400, profile CRUD, list | Policy violation detection, profile enforcement on CSR |
| 7 | Ownership & Teams | 4 | Team CRUD, owner CRUD, agent groups list | Owner notification routing, dynamic group matching |
| 8 | Job System | 2 | List jobs, 404 on nonexistent | Job state transitions, approval workflow, cancellation |
| 9 | Issuer Connectors | 4 | List, get detail, create (GenericCA), missing name 400 | Test connection, issuer-specific issuance flow |
| 10 | Sub-CA Mode | SKIP | — | Requires CA cert+key on disk |
| 11 | ACME ARI | SKIP | — | Requires ARI-capable CA |
| 12 | Vault PKI | SKIP | — | Requires live Vault server |
| 13 | DigiCert | SKIP | — | Requires DigiCert sandbox |
| 14 | Target Connectors | 3 | List, create NGINX target, delete 204 | Deploy to real target, validate deployment |
| 15–17 | Apache/HAProxy, Traefik/Caddy, IIS | — | (Covered by source checks in Parts 42–46) | Requires real services or Windows |
| 18 | Agent Operations | 3 | Heartbeat (register), metadata check, auto-create on heartbeat | Agent binary behavior, key storage, discovery scan |
| 19 | Agent Work Routing | 1 | Empty work for agent with no targets | Scoped job assignment, multi-target fan-out |
| 20 | Post-Deployment Verification | 1 | 404 on nonexistent job verification | TLS probing, fingerprint comparison |
| 21 | EST Server | 2 | CACerts (200 + content-type), CSRAttrs (200/204) | simpleenroll with CSR, simplereenroll, PKCS#7 parsing |
| 22 | Certificate Export | 3 | PEM export, PKCS#12 export, 404 on nonexistent | Download mode, file content validation |
| 23 | S/MIME & EKU Support | 0 (NOT AUTOMATED) | — | S/MIME profile creation; EKU enforcement on issuance; SMIMECapabilities extension presence in issued cert; rejection of profile-violating EKU on CSR. Test manually — see the Coverage Map row |
| 24 | OCSP Responder & DER CRL | 0 (NOT AUTOMATED) | — | OCSP request/response (RFC 6960), DER CRL generation, status (Good/Revoked/Unknown), Must-Staple coordination. Test manually — see the Coverage Map row |
| 25 | Certificate Discovery | 5 | List discovered, summary, list scan targets, create target, invalid CIDR 400 | Agent filesystem scan, claim/dismiss workflow |
| 26 | Enhanced Query API | 4 | Sort descending, cursor pagination, time-range filter, invalid sort field | Field projection correctness, cursor token cycling |
| 27 | Request Body Size Limits | 1 | 2MB body rejected (413/400) | Exact limit boundary (1MB) |
| 28 | CLI | SKIP | — | Requires compiled `certctl-cli` binary |
| 29 | MCP Server | SKIP | — | Requires compiled `mcp-server` binary + stdio |
| 30 | Observability | 7 | Dashboard summary, certs by status, expiration timeline, job trends, issuance rate, JSON metrics (uptime + gauges), Prometheus (content-type + 4 metric names) | Chart rendering (GUI), Grafana import |
| 31 | Notifications | 2 | List, 404 on nonexistent | Notification content, mark-read, email/Slack delivery |
| 32 | Audit Trail | 3 | List events (≥10), PUT immutability, DELETE immutability | Actor attribution, body hash, time range filters |
| 33 | Background Scheduler | SKIP | — | Timing-dependent; verify via Docker logs |
| 34 | Structured Logging | SKIP | — | Requires Docker log inspection |
| 35 | GUI Testing | SKIP | — | Requires browser |
| 36–37 | Issuer Catalog, Frontend Audit | SKIP | — | Requires browser |
| 38 | Error Handling | 5 | Malformed JSON, missing required field, method not allowed, UTF-8 CN, empty body | Stack trace suppression, error response format |
| 39 | Performance | 5 | List certs < 200ms, stats < 500ms, metrics < 200ms, Prometheus < 300ms, audit < 500ms | Load testing, concurrent request handling |
| 40 | Documentation | 8 | README, quickstart, architecture, connectors, compliance exist; migration guides exist; 8 issuer types in docs; 11 target types in docs | Content accuracy, link validity |
| 41 | Regression | 3 | DELETE 204, per_page max fallback, network scan target seed count | `errors.Is(errors.New())` anti-pattern source scan |
| 42 | Envoy Target | 5 | Domain type, connector file, test file, OpenAPI, agent dispatch | Envoy deployment test, SDS config |
| 43 | Postfix/Dovecot | 3 | Domain types (Postfix + Dovecot), connector file, OpenAPI | Mail server deployment test |
| 44 | SSH Target | 4 | Domain type, connector file, agent dispatch (`sshconn`), OpenAPI | SSH deployment test (requires target host) |
| 45 | Windows Certificate Store | 3 | Domain type, connector file, shared certutil package | Windows deployment (requires Windows) |
| 46 | Java Keystore | 3 | Domain type, connector file, OpenAPI | JKS deployment (requires keytool) |
| 47 | Certificate Digest Email | 3 | Preview endpoint (200/503), service file, adapter file | SMTP delivery, HTML template rendering |
| 48 | Dynamic Issuer Config | 4 | Crypto package exists, create ACME issuer via API, config redaction check, migration exists | Test connection flow, registry rebuild |
| 49 | Dynamic Target Config | 2 | Create NGINX target via API, migration exists | Test connection via agent heartbeat |
| 50 | Onboarding Wizard | 2 | Wizard component exists, docker-compose split (clean vs demo) | Wizard UI flow, step completion |
| 51 | ACME Profile Selection | 3 | Profile module exists, frontend config, RFC 9702→9773 renumber check | Profile-aware issuance against real CA |
| 52 | Helm Chart | 5 | Chart.yaml, values.yaml, 4 templates exist, securityContext, health probes | `helm template` rendering, `helm install` |
| 53 | Kubernetes Secrets Target Connector (M47) | 18 | Config validation (namespace DNS-1123, secret name DNS subdomain, label keys, required fields), deployment (create/update Secret, chain concatenation, error propagation), validation (serial comparison, not-found, empty cert) | GUI target wizard KubernetesSecrets fields (namespace, secret_name, labels, kubeconfig_path), Helm RBAC toggle, TargetDetailPage type label |
| 54 | AWS ACM Private CA Issuer Connector (M47) | 23 | Config validation (region, CA ARN regex, signing algorithm whitelist, validity_days, defaults), issuance (full flow, empty CSR, errors), renewal (reuses issuance), revocation (reason mapping, default, errors), GetOrderStatus completed, GetCACertPEM (success/chain/error), GetRenewalInfo nil | GUI issuer wizard AWSACMPCA fields (region, ca_arn, signing_algorithm, validity_days, template_arn), seed data visibility, create issuer flow |
| 55 | Agent Soft-Retirement (I-004) | 0 (NOT AUTOMATED) | — | Soft-retire vs hard-retire; force flag; reason capture; foreign-key cascade behavior on retired-agent cert ownership; reactivation. Test manually — see the Coverage Map row |
| 56 | Notification Retry & Dead-Letter Queue (I-005) | 0 (NOT AUTOMATED) | — | Retry loop with exponential backoff, dead-letter transition after N retries, requeue endpoint (`POST /api/v1/notifications/{id}/requeue`), idempotency on retry. Test manually — see the Coverage Map row |

**Totals (verified 2026-04-27):** 49 `Part_*` automation wrappers, ~159 leaf subtests, 11 fully
skipped Parts, 4 Parts not yet automated (23, 24, 55, 56), and an unspecified count of manual-only
flows (GUI, scheduler timing, Docker log inspection). Run `grep -cE 't\.Run\("Part[0-9]+_' deploy/test/qa_test.go` to count Part_* automation wrappers
and `grep -cE 't\.Run\("Part[0-9]+_' deploy/test/qa_test.go` to re-verify.

## Coverage by Risk Class

A buyer's QA lead reading this doc wants "where are the existential bugs caught?" — Bundle P / Strengthening #1 surfaces that view directly. The table below classifies each Part by risk class so reviewers can answer the existential-coverage question in one glance.

| Risk class | Description | Parts in scope | Automation status |
|---|---|---|---|
| **Existential** (Critical paths — bugs would compromise CA, leak keys, mis-issue, bypass revocation) | Crypto, PKCS#7, local-issuer, OCSP/CRL, agent keygen, CSR validation | 5 (Revocation), 21 (EST), 23 (S/MIME EKU), 24 (OCSP/CRL), 47 (Digest with cert content), 53 (K8s Secrets), 54 (AWS PCA) | 5/7 automated; Parts 23 + 24 pending (Bundle I Skip stubs in `qa_test.go`; manual playbook in the Coverage Map below) |
| **High** (FSM corruption, credential leak, authn/z weakening) | Renewal, jobs, agents, issuers, deployment, scheduler | 4, 7, 8, 9, 18, 19, 20, 22, 25, 28, 29, 32, 33, 48, 49, 55, 56 | 14/17 automated; CLI / MCP / scheduler-loop are inherently SKIP (require compiled binaries / Docker logs); Parts 55 + 56 pending |
| **Medium** (Operational pain or silent data drift) | Targets, notifiers, observability, error handling, performance, regression | 14, 15-17, 30, 31, 38, 39, 40, 41, 42, 43, 44, 45, 46 | 14/14 automated (15-17 indirect via Parts 42–46) |
| **Low** (Hygiene) | Documentation, docs verification | 40 (Documentation), 50 (Onboarding) | 2/2 automated |
| **Frontend** (XSS, render correctness, mutation contracts) | GUI testing | 35, 36-37 | 0/3 automated in this suite (Vitest covers separately under `web/`); this doc punts to manual + Vitest |
| **Compliance** (PCI / SOC2 / HIPAA-relevant) | Audit trail, body-size limits, request limits, Helm chart deploy posture | 27, 32, 51, 52 | 4/4 automated |

This is the table acquisition reviewers screenshot for their report. When a new Part_* subtest lands in `qa_test.go`, classify it here.

## Test Categories

The automated tests fall into four categories:

### 1. API Integration Tests (majority)
Make real HTTP requests to the running server and verify status codes, response structure, and JSON field values. Examples:
- `POST /api/v1/certificates` with valid payload → 201
- `GET /api/v1/certificates?status=Active` → all returned certs have `status: "Active"`
- `DELETE /api/v1/certificates/mc-qa-full` → 204

### 2. Database Verification Tests
Connect directly to PostgreSQL and verify schema state:
- Table count ≥ 19 (from migrations 000001–000010)
- Useful for catching migration regressions

### 3. Source File Verification Tests
Read files from the repo checkout and verify structure:
- Domain types exist in `internal/domain/connector.go` (e.g., `TargetTypeEnvoy`)
- Connector implementations exist (e.g., `internal/connector/target/envoy/envoy.go`)
- Documentation contains expected content (all issuer/target types listed)
- No stale RFC 9702 references (replaced by RFC 9773)

### 4. Performance Spot Checks
Timed API requests with threshold assertions:
- `GET /api/v1/certificates?per_page=15` < 200ms
- `GET /api/v1/stats/summary` < 500ms
- `GET /api/v1/metrics/prometheus` < 300ms

## What This Test Does NOT Cover

These gaps must be filled by manual testing — see each Coverage Map row for surface-area description:

### Not Yet Automated (Parts 23, 24, 55, 56)

These historical QA Parts are listed in the Coverage Map below but have no `Part_*` automation
in `qa_test.go` yet. They are operator-runnable from the manual playbook; QA-suite
automation should land before the next acquisition-grade release.

- **Part 23: S/MIME & EKU Support** — profile-driven EKU enforcement; SMIMECapabilities extension
- **Part 24: OCSP Responder & DER CRL** — OCSP request/response correctness, CRL generation, Must-Staple coordination
- **Part 55: Agent Soft-Retirement (I-004)** — soft vs hard retire, FK cascade, reactivation
- **Part 56: Notification Retry & Dead-Letter Queue (I-005)** — retry semantics, dead-letter transition, requeue

### External CA Integrations (Parts 10–13)
- **Sub-CA mode** — requires CA cert+key files on disk
- **ACME ARI** — requires a CA that supports RFC 9773 Renewal Information
- **Vault PKI** — requires a running HashiCorp Vault instance
- **DigiCert / Sectigo / Google CAS** — requires sandbox API credentials

### Browser/GUI Testing (Parts 35–37, 50)
- Dashboard chart rendering (Recharts)
- Onboarding wizard step-by-step flow
- Issuer catalog card layout and create wizard
- Bulk operations UI (multi-select, progress bars)
- Discovery triage workflow

### Real Deployment Testing (Parts 15–17)
- NGINX/Apache/HAProxy file write + reload
- Traefik/Caddy file provider or API reload
- IIS PowerShell/WinRM (requires Windows)
- F5 BIG-IP iControl REST (requires appliance or mock)
- SSH agentless deployment (requires target host)

### Agent Binary Behavior (Parts 18, 28–29)
- Agent-side ECDSA key generation and CSR submission
- Agent filesystem discovery scan
- CLI tool (`certctl-cli`) — all 10 subcommands
- MCP server (`mcp-server`) — stdio transport

### Timing-Dependent Tests (Parts 33–34)
- Background scheduler loop execution (renewal, jobs, health, notifications, digest, network scan)
- Structured logging format verification (requires Docker log parsing)

## How This Relates to `integration_test.go`

Both files live in `deploy/test/` in the same Go package (`integration_test`):

| | `qa_test.go` | `integration_test.go` |
|---|---|---|
| **Build tag** | `//go:build qa` | `//go:build integration` |
| **Target stack** | Demo (`docker-compose.yml` + `docker-compose.demo.yml`) | Test (`docker-compose.test.yml`) |
| **Port** | 8443 | Different (test stack config) |
| **Seed data** | `seed_demo.sql` (32 certs, 12 agents, 13 issuers, 8 targets, realistic history) | Minimal (created by tests) |
| **CA backends** | Local CA only (demo mode) | Pebble ACME, step-ca, NGINX |
| **Purpose** | Release QA — broad coverage, spot checks | Functional — end-to-end issuance, renewal, revocation against real CAs |
| **Run frequency** | Before each release tag | CI on every PR |

They are complementary. Integration tests prove the machinery works. QA tests prove the product works at release quality.

## Seed Data Reference

The QA tests depend on `migrations/seed_demo.sql`. Key IDs used:

### Certificates (32 total in `managed_certificates`)

The full canonical list is generated by:
```
sed -n '/^INSERT INTO managed_certificates/,/^;/p' migrations/seed_demo.sql \
  | grep -oE "^\s*\('mc-[a-z0-9_-]+" | sed -E "s/^\s*\('//" | sort -u
```

Hand-listing is unsustainable as the seed grows; tests reference IDs by lookup, not by enumeration.
Sample IDs: `mc-api-prod`, `mc-web-prod`, `mc-pay-prod`, `mc-compromised`, `mc-smime-bob`, `mc-edge-eu`, `mc-k8s-ingress`, `mc-wildcard-prod`. See `migrations/seed_demo.sql:147` onward.

### Agents (12 total in `agents` table)

8 named workload agents + 1 server-side sentinel + 3 cloud-discovery sentinels:

- **Workload agents:** `ag-web-prod`, `ag-web-staging`, `ag-lb-prod`, `ag-iis-prod`, `ag-data-prod`, `ag-edge-01`, `ag-k8s-prod`, `ag-mac-dev`
- **Server-side sentinel:** `server-scanner`
- **Cloud-discovery sentinels:** `cloud-aws-sm`, `cloud-azure-kv`, `cloud-gcp-sm`

Full list via:
```
sed -n '/^INSERT INTO agents/,/^;/p' migrations/seed_demo.sql \
  | grep -oE "^\s*\('[a-z][a-z0-9_-]+" | sed -E "s/^\s*\('//"
```

(The `agent_groups` table also contains entries with `ag-*` IDs — `ag-linux-prod`, `ag-windows`, `ag-datacenter-a`, `ag-arm64`, `ag-manual` — but those are *group* IDs, not agents. Don't confuse the two.)

### Issuers (13 total)

`iss-local`, `iss-acme-le`, `iss-stepca`, `iss-acme-zs`, `iss-openssl`, `iss-vault`, `iss-digicert`, `iss-sectigo`, `iss-googlecas`, `iss-awsacmpca`, `iss-entrust`, `iss-globalsign`, `iss-ejbca`.

Full list via:
```
sed -n '/^INSERT INTO issuers/,/^;/p' migrations/seed_demo.sql \
  | grep -oE "^\s*\('iss-[a-z0-9_-]+" | sed -E "s/^\s*\('//"
```

### Targets (8 total in `deployment_targets`)
`tgt-nginx-prod`, `tgt-nginx-staging`, `tgt-haproxy-prod`, `tgt-apache-prod`, `tgt-iis-prod`, `tgt-traefik-prod`, `tgt-caddy-prod`, `tgt-nginx-data`

### Network Scan Targets (4 total in `network_scan_targets`)
`nst-dc1-web`, `nst-dc2-apps`, `nst-dmz`, `nst-edge`

**Maintenance note:** when adding new seed rows, also update this section, OR remove the
per-table counts and rely on the `sed | grep` commands so the doc stops drifting on every
seed-data change. A CI guard that fails when the doc count diverges from the seed file is
proposed in `coverage-audit-2026-04-27/tables/qa-doc-strengthening.md` (Strengthening #6).

## Troubleshooting

### "Server unreachable" on startup
The test pings `GET /health` before running anything. If this fails:
```bash
# Check if the stack is running
docker compose -f docker-compose.yml -f docker-compose.demo.yml ps

# Check server logs
docker compose -f docker-compose.yml -f docker-compose.demo.yml logs certctl-server

# Check if the port is exposed (self-signed cert — pin CA bundle)
curl --cacert ./deploy/test/certs/ca.crt -s https://localhost:8443/health
```

### "connect to QA DB" failure
The database tests connect directly to PostgreSQL. Ensure port 5432 is exposed:
```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml port postgres 5432
```

### Performance tests flaking
The performance thresholds (200ms, 300ms, 500ms) assume a local Docker stack. On slow CI runners or remote Docker hosts, increase the thresholds or skip Part 39:
```bash
go test -tags qa -v -run 'TestQA/Part(?!39)' ./...
```

### Source file checks failing
The `fileExists` and `fileContains` helpers read from `CERTCTL_QA_REPO_DIR` (default `../..`). If running from a non-standard location:
```bash
CERTCTL_QA_REPO_DIR=/absolute/path/to/certctl go test -tags qa -v ./...
```

## Release Day Sign-Off Matrix

Before tagging a release, the QA-on-call engineer signs off on each row. This matrix replaces the previous ad-hoc release checklist and ties test execution directly to release approval. Acquisition-grade releases have this kind of matrix; the doc previously didn't.

| Sign-off | Evidence | Owner | Result | Date |
|---|---|---|---|---|
| `make verify` clean on master | CI run URL | Eng-on-call | ☐ | |
| `go test -tags qa ./deploy/test/...` ≥ 95% pass rate (skips counted as pass) | Test output | QA-on-call | ☐ | |
| `go test -race -count=10 ./internal/...` 0 races | `tool-output/race-x10.txt` | QA-on-call | ☐ | |
| Coverage ≥ thresholds in `ci.yml` (service / handler / crypto / local-issuer / acme / stepca / mcp) | `tool-output/cover-summary.txt` | QA-on-call | ☐ | |
| Helm chart `helm lint && helm template` clean | `tool-output/helm.txt` | DevOps-on-call | ☐ | |
| All `t.Skip` sites have current rationales (see Bundle O audit; CI guard catches new orphans) | `make qa-stats` t.Skip count | QA-on-call | ☐ | |
| Frontend: Vitest run clean; per-page coverage ≥ 70% | `web/tool-output/vitest.txt` | Frontend-on-call | ☐ | |
| Manual Parts 23, 24, 55, 56 executed (or explicit defer with rationale) | This sheet | QA-on-call | ☐ | |
| Demo stack `docker compose up -d --build` smoke (`/health` 200, `/ready` 200) | curl receipt | QA-on-call | ☐ | |
| `govulncheck ./...` clean (or deferred-call advisories tracked in `gap-backlog`) | `tool-output/govulncheck.json` | Security-on-call | ☐ | |
| QA-doc drift guards green (Part-count + cert-count) | CI run URL | QA-on-call | ☐ | |
| FSM transition coverage tables (`coverage-audit-2026-04-27/tables/fsm-coverage.md`) — Existential FSMs ≥80% legal + 100% illegal | This sheet | QA-on-call | ☐ | |

**Sign-off owner:** ______________________ &nbsp;&nbsp;**Date:** ______ &nbsp;&nbsp;**Tag:** v__.__.__

## Mutation Testing Targets & Kill Rate

Mutation testing exposes which assertions are actually load-bearing — tests can pass against broken code if mutations survive, which is a coverage trap. The audit's Phase 0 attempted to run `go-mutesting` on the Existential cluster but was blocked by a Go 1.25 / arm64 incompatibility in `osutil@v1.6.1` (uses `syscall.Dup2` which is undefined on linux/arm64). The operator-runnable workaround uses a fork that targets `unix.Dup3` instead.

| Package | Risk class | Target kill rate | Last measured | Tool |
|---|---|---|---|---|
| `internal/crypto` | Existential | ≥90% | unmeasured (sandbox-blocked, operator-runnable) | go-mutesting |
| `internal/pkcs7` | Existential | ≥90% | unmeasured | go-mutesting |
| `internal/connector/issuer/local` | Existential | ≥90% | unmeasured | go-mutesting |
| `internal/connector/issuer/acme` | Existential | ≥80% (catch-up; failure-mode coverage 55.6% per Bundle J) | unmeasured | go-mutesting |
| `internal/connector/issuer/stepca` | Existential | ≥85% (post-Bundle-L.B coverage at 90.4%) | unmeasured | go-mutesting |
| `internal/api/middleware` | High | ≥80% | unmeasured | go-mutesting |
| `internal/validation` | Existential (CWE-78 / CWE-113 boundary) | ≥90% | unmeasured | go-mutesting |
| `web/src/utils/safeHtml.ts` | Frontend (XSS gate) | ≥90% | unmeasured | Stryker |

### Operator command (per package)

```bash
# Use the avito-tech fork that supports linux/arm64 + Go 1.25.
go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest

mkdir -p tool-output
$(go env GOPATH)/bin/go-mutesting --debug ./internal/crypto/... \
  > tool-output/mutation-crypto.txt 2>&1
grep -oE 'mutation score is [0-9.]+' tool-output/mutation-crypto.txt | tail -1
```

**Acceptance:** ≥80% (Existential) / ≥70% (High). Anything below is a Medium finding; triage entries go in `coverage-audit-2026-04-27/gap-backlog.md`. This subsection moves mutation testing from "future work" to "documented release gate."

## Adding New Tests

When a new feature ships:

1. **Add a Part section** in `qa_test.go` following the numbering convention in the Coverage Map below
2. **API tests**: use `c.get()`, `c.post()`, `c.bodyStr()`, `c.getJSON()`, `c.timedGet()`
3. **Source checks**: use `fileExists(t, "relative/path")` and `fileContains(t, "path", "substring")`
4. **DB checks**: use `openQADB(t)` and `db.queryInt(t, "SELECT ...")`
5. **Cleanup**: always use `t.Cleanup()` for data created during tests
6. **Skip if external**: use `t.Skip("Requires X — manual test")` with a clear reason

## Version History

- **v1.3** (April 2026, post-Bundle-P) — QA Doc Strengthening shipped. New top-of-doc Test Suite Health dashboard (regenerated via `make qa-stats`). New Coverage by Risk Class table after the Coverage Map. New Release Day Sign-Off Matrix and Mutation Testing Targets sections. CI seed-count + Part-count drift guards land in `.github/workflows/ci.yml` so future doc drift fails CI. Bundle P closes M-007 / M-010 / M-011 / M-012 (structural strengthening) + M-008 (Mutation Testing Targets).
- **v1.2** (April 2026, post-coverage-audit) — Documented Parts 55–56 (I-004 Agent Soft-Retirement, I-005 Notification Retry & Dead-Letter) and surfaced Parts 23–24 (S/MIME & EKU; OCSP/CRL) as not-yet-automated. 56 Parts total in `testing-guide.md`; 49 live `Part_*` automation wrappers in `qa_test.go` + 4 new `Skip` stubs for Parts 23/24/55/56 = 53 wrappers (Parts 15–17 remain covered by source-checks in Parts 42–46). Reconciled seed-data section to actual `seed_demo.sql` counts (12 agents, 13 issuers; certs were already accurate at 32). Bundle I of the 2026-04-27 coverage-audit closure plan.
- **v1.1** (April 2026) — Added Parts 53–54 (M47: Kubernetes Secrets target + AWS ACM PCA issuer). 54 Parts total, ~164 automated subtests.
- **v1.0** (April 2026) — Initial release covering all 52 Parts of testing-guide.md v2.1. Replaces `qa-smoke-test.sh`.
