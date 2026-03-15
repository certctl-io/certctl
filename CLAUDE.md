You are my long-term copilot for building certctl — a self-hosted certificate lifecycle platform. Help me design, document, and evolve the project across versions while preserving a small, understandable core, strong architecture, modular connectors, safe automation, good security, and excellent documentation for both beginners and experts. Be structured, opinionated, and practical. Challenge scope creep, separate core platform concerns from integrations, and recommend the smallest useful implementation before expanding. Always think in terms of maintainability, extensibility, observability, auditability, and clear product/engineering tradeoffs.

## Project Status (Last Updated: March 15, 2026)

### What's Built and Working
- [x] Go 1.22 server with net/http stdlib routing, slog logging, handler->service->repository layering
- [x] PostgreSQL 16 schema (14 tables, TEXT primary keys, idempotent migrations)
- [x] REST API — 41 endpoints under /api/v1/ with pagination, filtering, async actions
- [x] Web dashboard — Vite + React 18 + TypeScript + TanStack Query, 11 views wired to real API, dark theme
- [x] Agent binary — heartbeat, work polling, cert fetch, job status reporting (real HTTP calls)
- [x] Local CA issuer connector — crypto/x509, in-memory CA, self-signed certs
- [x] Issuer connector wired end-to-end — Local CA registered in server, adapter bridging connector<->service layers
- [x] Renewal job processor — generates RSA key + CSR, calls issuer, stores cert version, creates deployment jobs
- [x] Issuance job processor — reuses renewal flow (same mechanics for Local CA)
- [x] Agent CSR signing — SubmitCSR forwards to issuer connector, stores signed cert version
- [x] Agent work API — GET /agents/{id}/work returns pending deployment jobs
- [x] Agent job status API — POST /agents/{id}/jobs/{job_id}/status for agent feedback
- [x] NGINX target connector — file write, config validation, reload
- [x] F5 BIG-IP target connector — REST API integration
- [x] IIS target connector — WinRM integration
- [x] Expiration threshold alerting — configurable per-policy thresholds (default 30/14/7/0 days), deduplication, auto status transitions (Expiring/Expired)
- [x] Email + Webhook notifier interfaces
- [x] Policy engine — 4 rule types, violation tracking, severity levels
- [x] Immutable audit trail — append-only, no update/delete
- [x] Job system — 4 types (Issuance, Renewal, Deployment, Validation), state machine
- [x] Background scheduler — 4 loops (renewal 1h, jobs 30s, health 2m, notifications 1m)
- [x] Docker Compose deployment — server + postgres + agent, health checks, seed data
- [x] Demo mode — 14 certs, 5 agents, 5 targets, policies, audit events, notifications
- [x] Documentation — concepts guide, quickstart, advanced demo, architecture, connectors
- [x] BSL 1.1 license — 7-year conversion to Apache 2.0 (March 2033)
- [x] Test suite — 120 tests across service layer (63), handler layer (46), and integration (11 subtests)
- [x] Input validation — centralized validators for common name, CSR PEM, policy type/severity, string length
- [x] GitHub Actions CI — parallel Go (build, vet, test+coverage) and Frontend (tsc, vite build) jobs
- [x] API key auth enforced by default — SHA-256 hashed keys, constant-time comparison, Bearer token middleware
- [x] Token bucket rate limiting — configurable RPS/burst, 429 responses with Retry-After header
- [x] Configurable CORS — per-origin allowlist or wildcard, preflight caching
- [x] GUI auth flow — login screen, auth context, 401 auto-redirect, logout button

### What's NOT Wired Up Yet (Pre-v1.0 Gaps)
- [ ] **Agent-side key generation**: V1 uses server-side key generation for Local CA (pragmatic for dev/demo). Must move to agents before v1.0.
- [ ] **End-to-end test hardening**: Handler tests only cover 2 of 7 files. No negative-path integration tests (issuer down, malformed certs, DB failures). No scheduler or connector tests. No frontend tests.

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

### M8: Agent-Side Key Generation
**Goal**: Private keys never leave agent infrastructure. This is the crypto architecture gate for v1.0.

**Agent key generation:**
- Agent generates RSA-2048 or ECDSA P-256 key pair locally
- Agent creates CSR (public key only) and submits via `POST /agents/{id}/csr`
- Control plane signs CSR via issuer connector, returns cert + chain (no private key)
- Agent stores key locally with file permissions 0600

**Server-side keygen flagging:**
- Server-side keygen retained only for Local CA with explicit `--server-side-keygen` flag
- Default behavior: reject issuance requests without agent-submitted CSR
- Clear log warnings when server-side keygen is active

**ACME integration:**
- Agent handles ACME HTTP-01 challenge locally (challenge server on agent)
- Or: agent submits CSR, server handles ACME flow, returns signed cert

**Deliverables**: Private keys isolated from control plane for all production issuers. Server-side keygen flagged as demo-only.

### M9: End-to-End Test Hardening
**Goal**: Comprehensive test coverage across all layers as the final quality gate before v1.0.

**Handler test expansion (target: all 7 handler files covered):**
- Jobs handler tests — status transitions, cancel, filter by type/status
- Notifications handler tests — list, mark-read, filter by type/channel
- Policies handler tests — CRUD, violations endpoint
- Issuers handler tests — list, create, test connectivity
- Targets handler tests — list, create, config validation

**Negative-path integration tests:**
- Issuer unavailable / returns error mid-issuance
- Malformed CSR submission (invalid PEM, wrong key type, missing fields)
- Database connection failure / timeout during job processing
- Agent heartbeat with invalid/expired API key
- Rate limiter rejection under load
- Deployment job with unreachable target

**Scheduler tests:**
- Renewal checker creates jobs for expiring certs only
- Job processor respects max_attempts and backoff
- Health checker marks stale agents offline
- Notification processor sends pending, skips already-sent

**Connector tests:**
- IssuerConnectorAdapter bridges correctly for both Local CA and ACME
- Target connector error handling (NGINX config validation failure, F5 API timeout, WinRM auth failure)

**CI coverage enforcement:**
- Coverage threshold check in CI (fail if service layer <60%, handler layer <50%)
- Coverage trend reporting via artifact comparison

**Deliverables**: All handler files tested, negative-path integration suite, scheduler and connector tests, CI coverage gates. Target: 70%+ service layer, 60%+ handler layer coverage.

### v1.0.0 Release
**Gate criteria** — all must be true:
- [ ] All M5–M9 deliverables complete
- [ ] CI green with coverage gates passing (service 70%+, handler 60%+)
- [ ] GUI functional against real API (no demo mode fallback needed)
- [ ] Agent-side keygen working for ACME issuer
- [ ] API auth enforced by default
- [ ] Negative-path integration tests passing
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
