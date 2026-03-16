You are my long-term copilot for building certctl — a self-hosted certificate lifecycle platform. Help me design, document, and evolve the project across versions while preserving a small, understandable core, strong architecture, modular connectors, safe automation, good security, and excellent documentation for both beginners and experts. Be structured, opinionated, and practical. Challenge scope creep, separate core platform concerns from integrations, and recommend the smallest useful implementation before expanding. Always think in terms of maintainability, extensibility, observability, auditability, and clear product/engineering tradeoffs.

## Project Status (Last Updated: March 16, 2026)

### What's Built and Working
- [x] Go 1.22 server with net/http stdlib routing, slog logging, handler->service->repository layering
- [x] PostgreSQL 16 schema (14 tables, TEXT primary keys, idempotent migrations)
- [x] REST API — 55 endpoints under /api/v1/ with pagination, filtering, async actions
- [x] Web dashboard — Vite + React 18 + TypeScript + TanStack Query, 11 views wired to real API, dark theme
- [x] Agent binary — heartbeat, work polling, cert fetch, CSR generation, job status reporting (real HTTP calls)
- [x] Local CA issuer connector — crypto/x509, in-memory CA, self-signed certs
- [x] Issuer connector wired end-to-end — Local CA registered in server, adapter bridging connector<->service layers
- [x] Renewal job processor — dual-mode keygen: agent mode (AwaitingCSR) or server mode (server-side RSA key + CSR)
- [x] Issuance job processor — reuses renewal flow (same mechanics for Local CA)
- [x] Agent CSR signing — SubmitCSR forwards to issuer connector, stores signed cert version
- [x] Agent work API — GET /agents/{id}/work returns pending deployment + AwaitingCSR jobs with cert details
- [x] Agent job status API — POST /agents/{id}/jobs/{job_id}/status for agent feedback
- [x] NGINX target connector — file write, config validation, reload
- [x] F5 BIG-IP target connector — REST API integration
- [x] IIS target connector — WinRM integration
- [x] Expiration threshold alerting — configurable per-policy thresholds (default 30/14/7/0 days), deduplication, auto status transitions (Expiring/Expired)
- [x] Email + Webhook notifier interfaces
- [x] Policy engine — 4 rule types, violation tracking, severity levels
- [x] Immutable audit trail — append-only, no update/delete
- [x] Job system — 4 types (Issuance, Renewal, Deployment, Validation), 6 states (Pending, AwaitingCSR, Running, Completed, Failed, Cancelled)
- [x] Background scheduler — 4 loops (renewal 1h, jobs 30s, health 2m, notifications 1m)
- [x] Docker Compose deployment — server + postgres + agent, health checks, seed data
- [x] Demo mode — 14 certs, 5 agents, 5 targets, policies, audit events, notifications
- [x] Documentation — concepts guide, quickstart, advanced demo, architecture, connectors
- [x] BSL 1.1 license — 7-year conversion to Apache 2.0 (March 2033)
- [x] Test suite — 220+ tests: Go backend (170+ across service, handler, integration, connector layers) + frontend (53 Vitest tests for API client and utilities)
- [x] Input validation — centralized validators for common name, CSR PEM, policy type/severity, string length
- [x] GitHub Actions CI — parallel Go (build, vet, test+coverage+gates) and Frontend (tsc, vitest, vite build) jobs
- [x] API key auth enforced by default — SHA-256 hashed keys, constant-time comparison, Bearer token middleware
- [x] Token bucket rate limiting — configurable RPS/burst, 429 responses with Retry-After header
- [x] Configurable CORS — per-origin allowlist or wildcard, preflight caching
- [x] GUI auth flow — login screen, auth context, 401 auto-redirect, logout button
- [x] Agent-side key generation — ECDSA P-256 keygen on agent, CSR-only submission, private keys never leave agent
- [x] Dual keygen mode — `CERTCTL_KEYGEN_MODE=agent` (default, production) or `server` (demo only with log warning)
- [x] AwaitingCSR job state — renewal/issuance jobs pause for agent CSR submission in agent keygen mode
- [x] Agent local key storage — keys written to `CERTCTL_KEY_DIR` (default /var/lib/certctl/keys) with 0600 permissions

### What's NOT Wired Up Yet (Pre-v1.0 Gaps)
- [ ] **README screenshots**: Screenshots of actual dashboard in README
- [ ] **Tagged Docker images**: Publish v1.0.0 images
- [x] **Frontend tests**: 53 Vitest tests (API client coverage, utility functions) with CI integration

---

## Completed Milestones

### M1: End-to-End Lifecycle ✅
Wire the complete flow: scheduler -> job -> CSR -> issuer -> cert version -> deploy -> status -> audit -> notification.

### M1.1: Agent-Side Deployment ✅
Work endpoint enriched with target type + config, agent instantiates connectors and calls DeployCertificate.

### M2: ACME Integration ✅
Full ACME v2 protocol implementation using golang.org/x/crypto/acme with HTTP-01 challenge solving.

### M3: Expiration Alerting ✅
Configurable alert_thresholds_days JSONB column on renewal_policies, threshold-aware alerting with deduplication, auto status transitions.

### M4: Test Coverage ✅
120 tests: service layer unit tests (8 files), handler tests (2 files + utils), end-to-end integration test.

### M5: Hardening + GUI Foundation ✅
Fixed nginx.go format string errors, added centralized input validation (validation.go), migrated from single-file SPA to Vite + React 18 + TypeScript + TanStack Query v5 + Tailwind CSS 3. Componentized 7 views with real API wiring, loading/error/empty states. Server serves `web/dist/` with SPA fallback.

### M6: Functional GUI + CI ✅
All views wired to real API: agent detail page with heartbeat status + capabilities + recent jobs, audit trail with time range/actor/resource filters, notifications with grouped-by-cert view + read/unread state + mark-read mutations, policies with severity summary bar + config preview, new issuers and targets list views. GitHub Actions CI with parallel Go (build, vet, test+coverage) and Frontend (tsc, vite build) jobs. Makefile updated with test-cover and frontend-build targets.

### M7: Auth + Rate Limiting ✅
API key auth middleware with SHA-256 hashing and constant-time comparison. `CERTCTL_AUTH_TYPE=api-key` enforced by default; `none` requires explicit opt-in with log warning. Token bucket rate limiter (configurable via `CERTCTL_RATE_LIMIT_RPS` / `CERTCTL_RATE_LIMIT_BURST`). Configurable CORS via `CERTCTL_CORS_ORIGINS`. GUI: login page with API key entry, AuthProvider context, automatic 401 redirect, logout button in sidebar. Auth info endpoint (`GET /api/v1/auth/info`) served without auth so GUI can detect auth mode. Auth check endpoint (`GET /api/v1/auth/check`) validates credentials.

---

## V1 Roadmap: Ship a Functional Product

The principle: **every backend feature ships with its corresponding GUI surface.** The GUI is where ops teams spend 80% of their time — it must be an operational tool, not a demo viewer.

### M8: Agent-Side Key Generation ✅ COMPLETE
**Goal**: Private keys never leave agent infrastructure. Crypto architecture gate for v1.0.

**Implemented:**
- `CERTCTL_KEYGEN_MODE` config: `agent` (default) or `server` (demo only)
- `AwaitingCSR` job state: renewal/issuance jobs pause for agent to generate key + submit CSR
- Agent generates ECDSA P-256 key pairs locally (crypto/ecdsa + crypto/elliptic)
- Agent stores private keys to disk (`CERTCTL_KEY_DIR`, default `/var/lib/certctl/keys`) with 0600 permissions
- Agent creates CSR with common name + SANs from work response, submits via `POST /agents/{id}/csr`
- Server signs agent-submitted CSR via `CompleteAgentCSRRenewal`, stores cert version with CSR (not private key)
- Work endpoint enriched: AwaitingCSR jobs include `common_name` and `sans` so agent knows what CSR to generate
- Deployment jobs read local private key from key store for target connector deployment
- `DeploymentRequest` struct extended with `KeyPEM` field for agent-provided keys
- Server-side keygen retained for `CERTCTL_KEYGEN_MODE=server` with explicit log warning
- Docker Compose demo uses `CERTCTL_KEYGEN_MODE=server` for backward compatibility

**Files created:**
(none — all changes to existing files)

**Files modified:**
- `internal/domain/job.go` — Added `JobStatusAwaitingCSR`, `CommonName`/`SANs` fields to `WorkItem`
- `internal/config/config.go` — Added `KeygenConfig` struct and `CERTCTL_KEYGEN_MODE` env var
- `internal/service/renewal.go` — Added `keygenMode` field, split `ProcessRenewalJob` into `processRenewalAgentKeygen` and `processRenewalServerKeygen`, added `CompleteAgentCSRRenewal`, `GetAwaitingCSRJobs`, `createDeploymentJobs`
- `internal/service/agent.go` — Added `renewalService` dependency, updated `SubmitCSR` to handle AwaitingCSR flow, updated `GetPendingWork` to return AwaitingCSR jobs, updated `GetWorkWithTargets` to enrich with cert details
- `internal/connector/target/interface.go` — Added `KeyPEM` field to `DeploymentRequest`
- `cmd/server/main.go` — Passes `keygenMode` to `NewRenewalService`, passes `renewalService` to `NewAgentService`, added keygen mode log line
- `cmd/agent/main.go` — Added crypto imports, `KeyDir` config, `executeCSRJob` method (ECDSA P-256 keygen + CSR creation + submission), deployment reads local key, added `--key-dir` flag / `CERTCTL_KEY_DIR` env var
- `deploy/docker-compose.yml` — Added `CERTCTL_KEYGEN_MODE=server` for demo
- `internal/service/renewal_test.go` — Updated all `NewRenewalService` calls with `keygenMode` param
- `internal/service/job_test.go` — Updated `NewRenewalService` call with `keygenMode` param
- `internal/integration/lifecycle_test.go` — Updated `NewRenewalService` and `NewAgentService` calls

### M9: End-to-End Test Hardening ✅
**Goal**: Comprehensive test coverage across all layers as the final quality gate before v1.0.

**Handler test expansion (all 7 handler files covered):**
- ✅ Jobs handler tests — list with filters, get, cancel, method not allowed, empty ID, service errors
- ✅ Notifications handler tests — list with pagination, get, mark-read, method not allowed, service errors
- ✅ Policies handler tests — full CRUD, violations endpoint, validation (missing name/type, invalid type, invalid JSON)
- ✅ Issuers handler tests — list, get, create, delete, test connection, validation (missing name/type, name too long)
- ✅ Targets handler tests — list, get, create, update, delete, validation (missing name/type, name too long, invalid JSON)

**Negative-path integration tests:**
- ✅ Nonexistent resource lookups (certificate, agent, job) — verify 404 responses
- ✅ Invalid request bodies (malformed JSON, missing required fields, invalid policy type)
- ✅ Invalid CSR submission (non-PEM garbage data)
- ✅ Heartbeat for nonexistent agent
- ✅ Method not allowed on list endpoints
- ✅ Empty list responses (verify 200 with total=0)
- ✅ Trigger renewal on nonexistent certificate
- ✅ Expired certificate lifecycle (create expired cert, verify retrieval, test renewal trigger)

**Deferred to future milestone (not blocking v1.0):**
- Deployment job with unreachable target (requires mock target infrastructure)
- Scheduler loop unit tests: renewal checker, job processor, health checker, notification processor (time-dependent, tested manually during development)

**CI coverage enforcement:**
- ✅ Coverage threshold check in CI (fail if service layer <30%, handler layer <50%)
- ✅ Connector tests included in CI coverage (`./internal/connector/issuer/local/...`)

**Files created:**
- `internal/api/handler/job_handler_test.go` — 14 tests for jobs handler
- `internal/api/handler/notification_handler_test.go` — 11 tests for notifications handler
- `internal/api/handler/policy_handler_test.go` — 15 tests for policies handler (CRUD + violations + validation)
- `internal/api/handler/issuer_handler_test.go` — 15 tests for issuers handler (CRUD + test connection + validation)
- `internal/api/handler/target_handler_test.go` — 14 tests for targets handler (CRUD + validation)
- `internal/integration/negative_test.go` — 12 negative-path subtests + expired cert lifecycle test

**Files modified:**
- `.github/workflows/ci.yml` — Added coverage threshold check step, added `./internal/connector/issuer/local/...` to test path

**Deliverables**: All 7 handler files tested, negative-path integration suite, CI coverage gates.

### v1.0.0 Release
**Gate criteria** — all must be true:
- [x] All M5–M8 deliverables complete
- [x] M9 deliverables complete (test hardening)
- [ ] CI green with coverage gates passing (service 30%+, handler 50%+)
- [ ] GUI functional against real API (no demo mode fallback needed)
- [x] Agent-side keygen working (ECDSA P-256, AwaitingCSR flow)
- [x] API auth enforced by default
- [x] Negative-path integration tests passing
- [ ] README screenshots of actual dashboard
- [ ] Tagged Docker images published
- [ ] No known panics or unhandled error paths

---

## V2 Roadmap: Operational Maturity

### V2.0: Operational Workflows (GUI-first)
**Goal**: Transform the GUI from a viewer into an operational tool.

- Interactive renewal approval for non-auto-renew policies (approve/reject with reason)
- Bulk certificate operations (multi-select -> trigger renewal, change policy, reassign owner)
- Deployment status timeline showing each lifecycle step visually (requested -> issued -> deploying -> active)
- Certificate detail: inline policy editor with threshold configuration
- Target connector configuration wizard (add NGINX target, enter config, test connectivity)
- Audit trail export (CSV/JSON) with applied filters
- Real-time updates via SSE/WebSocket for job status changes (no polling)

### V2.1: Team Adoption
**Goal**: Enable multi-user team environments.

- OIDC/SSO authentication (Okta, Azure AD, Google)
- Role-based access control (admin, operator, viewer)
- CLI tool (`certctl`) for terminal-based workflows (list certs, trigger renewal, check agent status)
- Slack/Teams notifier connectors
- Bulk import of existing certificates from PEM files or network scans

### V2.2: Observability + Polish
**Goal**: Give operators confidence in the system itself.

- Dashboard charts: expiration calendar/heatmap, renewal success rate trends, cert count over time
- Certificate health score (composite of: days to expiry, policy compliance, deployment status)
- Agent fleet overview with environment grouping
- Prometheus metrics endpoint (`/metrics`) for control plane monitoring
- Structured logging improvements (request IDs, trace context)
- Deployment rollback support

---

## V3 Roadmap: Discovery & Visibility

- Passive certificate discovery (network listener for TLS handshakes)
- Active scanning (port scan -> TLS probe -> cert extraction)
- Network scan import (Nmap, Qualys, etc.)
- Unknown/unmanaged certificate detection with ownership recommendation
- Discovery results triage workflow in GUI (claim, assign, ignore)
- Alerting rule builder with preview in GUI

---

## V4+ Roadmap: Platform & Scale

- Kubernetes CRD for certificate management
- Terraform provider
- Multi-region deployment with control plane federation
- HA control plane with etcd backend
- Advanced scheduling policies (maintenance windows, blackout periods)
- Certificate pinning validation
- Hardware security module (HSM) support for CA key storage
- Backup/restore tooling for PostgreSQL data lifecycle
- API versioning strategy for breaking changes

---

## Architecture Decisions

- **Go 1.22 net/http** — stdlib routing, no external framework (Chi, Gin, Echo)
- **database/sql + lib/pq** — no ORM, raw SQL for clarity and control
- **TEXT primary keys** — human-readable prefixed IDs (mc-api-prod, t-platform, o-alice), not UUIDs
- **Handler->Service->Repository** — handlers define their own service interfaces (dependency inversion)
- **Idempotent migrations** — IF NOT EXISTS + ON CONFLICT for safe repeated execution
- **Agent-based key management** — v1.0: agents generate keys, submit CSR only. Local CA demo mode retains server-side keygen with explicit flag.
- **Connector interfaces** — pluggable issuers (IssuerConnector), targets (TargetConnector), notifiers (Notifier)
- **IssuerConnectorAdapter** — bridges connector-layer `issuer.Connector` with service-layer `service.IssuerConnector` to maintain dependency inversion
- **BSL 1.1 license** — source-available, prevents competing managed services, converts to Apache 2.0 in 2033
- **Vite + React + TypeScript** — (M5+) proper frontend build pipeline replacing single-file SPA. TanStack Query for server state.
- **GUI parallel-tracked with backend** — every backend feature ships with its corresponding GUI surface. No GUI debt accumulation.

## Key File Locations
- Server entry: `cmd/server/main.go`
- Agent entry: `cmd/agent/main.go`
- Config: `internal/config/config.go`
- Domain models: `internal/domain/`
- API handlers: `internal/api/handler/`
- Router: `internal/api/router/router.go`
- Services: `internal/service/`
- Issuer adapter: `internal/service/issuer_adapter.go`
- Repositories: `internal/repository/postgres/`
- Issuer connectors: `internal/connector/issuer/`
- Target connectors: `internal/connector/target/`
- Notifier connectors: `internal/connector/notifier/`
- Scheduler: `internal/scheduler/scheduler.go`
- Schema: `migrations/000001_initial_schema.up.sql`
- Seed data: `migrations/seed.sql`, `migrations/seed_demo.sql`
- Dashboard: `web/src/` (Vite + React + TypeScript), built to `web/dist/`
- CI: `.github/workflows/ci.yml`
- Docker: `deploy/docker-compose.yml`, `Dockerfile`, `Dockerfile.agent`
- Docs: `docs/`
- Tests: `internal/service/*_test.go`, `internal/api/handler/*_test.go`, `internal/integration/lifecycle_test.go`
