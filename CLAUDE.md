You are my long-term copilot for building certctl — a self-hosted certificate lifecycle platform. Help me design, document, and evolve the project across versions while preserving a small, understandable core, strong architecture, modular connectors, safe automation, good security, and excellent documentation for both beginners and experts. Be structured, opinionated, and practical. Challenge scope creep, separate core platform concerns from integrations, and recommend the smallest useful implementation before expanding. Always think in terms of maintainability, extensibility, observability, auditability, and clear product/engineering tradeoffs.

## Project Status (Last Updated: March 15, 2026)

### What's Built and Working
- [x] Go 1.22 server with net/http stdlib routing, slog logging, handler->service->repository layering
- [x] PostgreSQL 16 schema (14 tables, TEXT primary keys, idempotent migrations)
- [x] REST API — 41 endpoints under /api/v1/ with pagination, filtering, async actions
- [x] Web dashboard — React SPA with dark theme, 7 views, demo mode fallback
- [x] Agent binary — heartbeat, work polling, cert fetch, job status reporting (real HTTP calls)
- [x] Local CA issuer connector — crypto/x509, in-memory CA, self-signed certs
- [x] **Issuer connector wired end-to-end** — Local CA registered in server, adapter bridging connector<->service layers
- [x] **Renewal job processor** — generates RSA key + CSR, calls issuer, stores cert version, creates deployment jobs
- [x] **Issuance job processor** — reuses renewal flow (same mechanics for Local CA)
- [x] **Agent CSR signing** — SubmitCSR forwards to issuer connector, stores signed cert version
- [x] **Agent work API** — GET /agents/{id}/work returns pending deployment jobs
- [x] **Agent job status API** — POST /agents/{id}/jobs/{job_id}/status for agent feedback
- [x] NGINX target connector — file write, config validation, reload
- [x] F5 BIG-IP target connector — REST API integration
- [x] IIS target connector — WinRM integration
- [x] **Expiration threshold alerting** — configurable per-policy thresholds (default 30/14/7/0 days), deduplication, auto status transitions (Expiring/Expired)
- [x] Email + Webhook notifier interfaces
- [x] Policy engine — 4 rule types, violation tracking, severity levels
- [x] Immutable audit trail — append-only, no update/delete
- [x] Job system — 4 types (Issuance, Renewal, Deployment, Validation), state machine
- [x] Background scheduler — 4 loops (renewal 1h, jobs 30s, health 2m, notifications 1m)
- [x] Docker Compose deployment — server + postgres + agent, health checks, seed data
- [x] Demo mode — 14 certs, 5 agents, 5 targets, policies, audit events, notifications
- [x] Documentation — concepts guide, quickstart, advanced demo, architecture, connectors (all updated for M1)
- [x] BSL 1.1 license — 7-year conversion to Apache 2.0 (March 2033)
- [x] **Test suite** — 120 tests across service layer (63), handler layer (46), and integration (11 subtests)

### What's NOT Wired Up Yet (V1 Gaps)
- [x] ~~**End-to-end certificate lifecycle**~~ — DONE: Job processor invokes Local CA issuer, generates real CSR, stores cert versions
- [x] ~~**Agent CSR flow**~~ — DONE: Agent polls for work, fetches certs, reports job status via real HTTP calls
- [ ] **Agent-side key generation**: V1 uses server-side key generation for Local CA (pragmatic for dev/demo). V2 will have agents generate keys locally for production CAs.
- [x] ~~**Agent target connector invocation**~~: DONE (M1.1) — Agent now creates NGINX/F5/IIS connectors from target config, calls DeployCertificate
- [x] ~~**ACME protocol**~~: DONE (M2) — Full ACME v2 implementation with HTTP-01 challenge solving via built-in challenge server
- [x] ~~**Expiration threshold alerting**~~: DONE (M3) — Configurable thresholds per renewal policy, deduplication via threshold tags, auto Expiring/Expired status transitions
- [x] ~~**Unit tests**~~: DONE (M4) — 120 tests: service layer, handler layer, and end-to-end integration test

### Milestone 1: End-to-End Lifecycle COMPLETE
Wire the complete flow: scheduler -> job -> CSR -> issuer -> cert version -> deploy -> status -> audit -> notification.

### Milestone 1.1: Agent-Side Deployment COMPLETE
Work endpoint enriched with target type + config, agent instantiates connectors and calls DeployCertificate.

### Milestone 2: ACME Integration COMPLETE
Full ACME v2 protocol implementation using golang.org/x/crypto/acme with HTTP-01 challenge solving.

### Milestone 3: Expiration Alerting COMPLETE
Configurable alert_thresholds_days JSONB column on renewal_policies, threshold-aware alerting with deduplication, auto status transitions.

### Milestone 4: Test Coverage COMPLETE

**Test Files Created:**
- `internal/service/testutil_test.go` — Mock implementations for all repository interfaces
- `internal/service/certificate_test.go` — 10 tests for CertificateService
- `internal/service/agent_test.go` — 9 tests for AgentService
- `internal/service/audit_test.go` — 9 tests for AuditService
- `internal/service/job_test.go` — 7 tests for JobService
- `internal/service/notification_test.go` — 16 tests for NotificationService
- `internal/service/policy_test.go` — 11 tests for PolicyService
- `internal/service/renewal_test.go` — 12 tests for RenewalService (includes threshold alerting, dedup, status transitions, job processing)
- `internal/api/handler/test_utils.go` — Shared test utilities and error constants
- `internal/api/handler/certificate_handler_test.go` — 22 tests for CertificateHandler (HTTP layer)
- `internal/api/handler/agent_handler_test.go` — 24 tests for AgentHandler (HTTP layer)
- `internal/integration/lifecycle_test.go` — End-to-end integration test (11 subtests) exercising full certificate lifecycle through HTTP API with real Local CA issuer

**Coverage:**
- Service layer: 39% of statements
- Handler layer: 28% of statements
- Integration: Full lifecycle flow through HTTP API with real cert signing

### Milestone 5: Polish & Release
- Error handling audit (no panics, descriptive errors)
- API input validation (required fields, format checks)
- README screenshots of dashboard
- GitHub Actions CI (build, test, lint)
- Tagged v1.0.0 release with Docker images

## V2 Roadmap (Phase 2: Operational Maturity)
- Richer dashboard (charts, trend lines, certificate health scores)
- Bulk import of known certificates
- OIDC/SSO authentication
- Stronger RBAC (role-based access control)
- Deployment rollback support
- CLI tool (certctl CLI)
- Slack/Teams notifiers
- Agent-side key generation (private keys never leave target infrastructure)

## V3 Roadmap (Phase 3: Discovery & Visibility)
- Passive/active certificate discovery
- Network scan import
- Unknown/unmanaged certificate detection
- Ownership recommendation workflows

## V4+ Roadmap
- Kubernetes CRD for certificate management
- Terraform provider
- Multi-region deployment
- HA control plane with etcd backend
- Advanced scheduling policies
- Certificate pinning validation
- Hardware security module (HSM) support

## Architecture Decisions
- **Go 1.22 net/http** — stdlib routing, no external framework (Chi, Gin, Echo)
- **database/sql + lib/pq** — no ORM, raw SQL for clarity and control
- **TEXT primary keys** — human-readable prefixed IDs (mc-api-prod, t-platform, o-alice), not UUIDs
- **Handler->Service->Repository** — handlers define their own service interfaces (dependency inversion)
- **Idempotent migrations** — IF NOT EXISTS + ON CONFLICT for safe repeated execution
- **Agent-based key management** — V2+: private keys generated and stored only on agents, never in control plane. V1: server-side generation for Local CA demo.
- **Connector interfaces** — pluggable issuers (IssuerConnector), targets (TargetConnector), notifiers (Notifier)
- **IssuerConnectorAdapter** — bridges connector-layer `issuer.Connector` with service-layer `service.IssuerConnector` to maintain dependency inversion
- **BSL 1.1 license** — source-available, prevents competing managed services, converts to Apache 2.0 in 2033

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
- Dashboard: `web/index.html`
- Docker: `deploy/docker-compose.yml`, `Dockerfile`, `Dockerfile.agent`
- Docs: `docs/`
- Tests: `internal/service/*_test.go`, `internal/api/handler/*_test.go`, `internal/integration/lifecycle_test.go`
