You are my long-term copilot for building certctl — a self-hosted certificate lifecycle platform. Help me design, document, and evolve the project across versions while preserving a small, understandable core, strong architecture, modular connectors, safe automation, good security, and excellent documentation for both beginners and experts. Be structured, opinionated, and practical. Challenge scope creep, separate core platform concerns from integrations, and recommend the smallest useful implementation before expanding. Always think in terms of maintainability, extensibility, observability, auditability, and clear product/engineering tradeoffs.

## Project Status (Last Updated: March 15, 2026)

### What's Built and Working
- [x] Go 1.22 server with net/http stdlib routing, slog logging, handler->service->repository layering
- [x] PostgreSQL 16 schema (14 tables, TEXT primary keys, idempotent migrations)
- [x] REST API — 41 endpoints under /api/v1/ with pagination, filtering, async actions
- [x] Web dashboard — React SPA with dark theme, 7 views, demo mode fallback (static prototype, not wired to real API)
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

### What's NOT Wired Up Yet (Pre-v1.0 Gaps)
- [ ] **GUI wired to real API**: Dashboard is a static prototype with demo mode fallback. Not functional against the live backend.
- [ ] **Agent-side key generation**: V1 uses server-side key generation for Local CA (pragmatic for dev/demo). Must move to agents before v1.0.
- [ ] **API authentication enforced**: Auth types exist but demo runs with `CERTCTL_AUTH_TYPE=none`. No rate limiting.
- [ ] **Build errors**: `nginx.go` has non-constant format string errors that will block CI.
- [ ] **Test coverage gaps**: Service 39%, handler 28%. No negative-path integration tests (issuer down, malformed certs, DB failures).

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

---

## V1 Roadmap: Ship a Functional Product

The principle: **every backend feature ships with its corresponding GUI surface.** The GUI is where ops teams spend 80% of their time — it must be an operational tool, not a demo viewer.

### M5: Hardening + GUI Foundation
**Goal**: Fix build errors, add input validation, and establish the real frontend build pipeline.

**Backend hardening:**
- Fix `nginx.go` non-constant format string errors
- Error handling audit across all service methods (no panics, descriptive errors, consistent error types)
- API input validation (required fields, format checks, string length limits)
- Increase service layer test coverage to 60%+ with negative-path tests (issuer failures, DB errors, malformed inputs)

**GUI foundation:**
- Migrate from single `web/index.html` to proper Vite + React + TypeScript project
- Set up TanStack Query (React Query) for server state management (caching, refetching, optimistic updates)
- Keep existing dark theme, componentize the 7 existing views
- Wire certificate list view to real API with server-side pagination, filtering, and sorting
- Wire certificate detail view showing version history, deployment targets, job status
- API error states shown in UI (loading, error, empty states)

**Deliverables**: Clean build, validated API inputs, cert list + detail views working against real backend.

### M6: Functional GUI + CI
**Goal**: Wire all remaining views to real API and establish CI pipeline.

**GUI — remaining views:**
- Agent list with health indicators (online/offline/stale from heartbeat timestamps)
- Agent detail with recent jobs and heartbeat history
- Job queue view with status badges, retry controls, cancel actions
- Notification inbox with read/unread state, threshold alert grouping by certificate
- Audit trail view with time range picker, actor/action/resource filters
- Policy list with violation counts and severity indicators
- Dashboard overview with summary cards (total certs, expiring soon, active agents, pending jobs)

**CI/CD:**
- GitHub Actions: build, test, lint on every PR
- Docker image builds on tag push
- Test coverage reporting

**Deliverables**: Every API-backed view functional in the GUI. CI green on master.

### M7: Security Baseline
**Goal**: Make certctl deployable in a shared/team environment. This gates the v1.0 tag.

**Authentication & authorization:**
- API key auth enforced by default (not `none`)
- Rate limiting on all API endpoints
- CORS configuration for dashboard

**Agent-side key generation:**
- Agents generate RSA/ECDSA keys locally
- Agents submit CSR (public key only) to control plane
- Private keys never leave agent infrastructure
- Server-side keygen retained only for Local CA demo mode (flagged explicitly)

**Deliverables**: Auth enforced, rate limits active, private keys isolated from control plane.

### v1.0.0 Release
**Gate criteria** — all must be true:
- [ ] All M5-M7 deliverables complete
- [ ] CI green with 60%+ service layer coverage
- [ ] GUI functional against real API (no demo mode fallback needed)
- [ ] Agent-side keygen working for ACME issuer
- [ ] API auth enforced by default
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
- Dashboard: `web/` (migrating to Vite + React + TS in M5)
- Docker: `deploy/docker-compose.yml`, `Dockerfile`, `Dockerfile.agent`
- Docs: `docs/`
- Tests: `internal/service/*_test.go`, `internal/api/handler/*_test.go`, `internal/integration/lifecycle_test.go`
