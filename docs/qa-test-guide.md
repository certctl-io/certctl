# QA Test Suite Guide (`qa_test.go`)

> **Audience:** Anyone running release QA for certctl — whether you're a first-time contributor or the maintainer cutting a release tag.
>
> **Companion to:** `docs/testing-guide.md` (the *what* to test). This document explains the *how* — the automated test file, what it covers, what it skips, and how to fill the gaps manually.

---

## What Is This File?

`deploy/test/qa_test.go` is a single Go test file (~1700 lines) that automates as much of `docs/testing-guide.md` as possible against a running certctl Docker Compose demo stack. It replaces the legacy `qa-smoke-test.sh` bash script.

It covers **all 54 Parts** of the testing guide:

- **~164 automated subtests** — API calls, database queries, source file checks, performance benchmarks
- **11 skipped Parts** — with documented reasons (external CAs, Windows, browser-only, etc.)
- **Remaining ~282 manual tests** — GUI flows, scheduler timing, Docker log inspection — must be done by a human following `docs/testing-guide.md`

## Architecture

```
┌────────────────────────┐     ┌──────────────────────────┐
│  qa_test.go            │────▶│  certctl demo stack      │
│  (//go:build qa)       │     │  docker-compose.yml +    │
│                        │     │  docker-compose.demo.yml │
│  TestQA(t *testing.T)  │     │                          │
│   ├─ Part01_Infra      │     │  ┌─ certctl-server :8443 │
│   ├─ Part02_Auth       │     │  ├─ postgres :5432       │
│   ├─ Part03_CertCRUD   │     │  └─ certctl-agent        │
│   ├─ ...               │     └──────────────────────────┘
│   └─ Part52_HelmChart  │
└────────────────────────┘
```

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

**Totals:** ~164 automated subtests, 11 fully skipped Parts, ~282 manual tests remaining.

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

These gaps must be filled by manual testing per `docs/testing-guide.md`:

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
| **Seed data** | `seed_demo.sql` (32 certs, 8 agents, realistic history) | Minimal (created by tests) |
| **CA backends** | Local CA only (demo mode) | Pebble ACME, step-ca, NGINX |
| **Purpose** | Release QA — broad coverage, spot checks | Functional — end-to-end issuance, renewal, revocation against real CAs |
| **Run frequency** | Before each release tag | CI on every PR |

They are complementary. Integration tests prove the machinery works. QA tests prove the product works at release quality.

## Seed Data Reference

The QA tests depend on `migrations/seed_demo.sql`. Key IDs used:

### Certificates (32 total)
`mc-api-prod`, `mc-web-prod`, `mc-pay-prod`, `mc-dash-prod`, `mc-data-prod`, `mc-search-prod`, `mc-admin-prod`, `mc-blog-prod`, `mc-docs-prod`, `mc-status-prod`, `mc-grpc-prod`, `mc-vault-prod`, `mc-consul-prod`, `mc-shop-prod`, `mc-auth-prod`, `mc-cdn-prod`, `mc-mail-prod`, `mc-ci-prod`, `mc-legacy-prod`, `mc-old-api`, `mc-wiki-prod`, `mc-api-stg`, `mc-web-stg`, `mc-pay-stg`, `mc-api-dev`, `mc-grafana-prod`, `mc-vpn-prod`, `mc-wildcard-prod`, `mc-compromised`, `mc-edge-eu`, `mc-k8s-ingress`, `mc-smime-bob`

### Agents (9 total)
`ag-web-prod`, `ag-web-staging`, `ag-lb-prod`, `ag-iis-prod`, `ag-data-prod`, `ag-edge-01`, `ag-k8s-prod`, `ag-mac-dev`, `server-scanner` (sentinel)

### Issuers (9 total)
`iss-local`, `iss-acme-le`, `iss-stepca`, `iss-acme-zs`, `iss-openssl`, `iss-vault`, `iss-digicert`, `iss-sectigo`, `iss-googlecas`

### Targets (8 total)
`tgt-nginx-prod`, `tgt-nginx-staging`, `tgt-haproxy-prod`, `tgt-apache-prod`, `tgt-iis-prod`, `tgt-traefik-prod`, `tgt-caddy-prod`, `tgt-nginx-data`

### Network Scan Targets (4 total)
`nst-dc1-web`, `nst-dc2-apps`, `nst-dmz`, `nst-edge`

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

## Adding New Tests

When a new feature ships:

1. **Add a Part section** in `qa_test.go` following the numbering in `docs/testing-guide.md`
2. **API tests**: use `c.get()`, `c.post()`, `c.bodyStr()`, `c.getJSON()`, `c.timedGet()`
3. **Source checks**: use `fileExists(t, "relative/path")` and `fileContains(t, "path", "substring")`
4. **DB checks**: use `openQADB(t)` and `db.queryInt(t, "SELECT ...")`
5. **Cleanup**: always use `t.Cleanup()` for data created during tests
6. **Skip if external**: use `t.Skip("Requires X — manual test")` with a clear reason

## Version History

- **v1.0** (April 2026) — Initial release covering all 52 Parts of testing-guide.md v2.1. Replaces `qa-smoke-test.sh`.
- **v1.1** (April 2026) — Added Parts 53–54 (M47: Kubernetes Secrets target + AWS ACM PCA issuer). 54 Parts total, ~164 automated subtests.
