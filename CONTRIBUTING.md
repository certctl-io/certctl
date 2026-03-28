# Contributing to certctl

## Architecture Conventions

certctl follows a strict **Handler -> Service -> Repository** layering.

**Handlers** define their own service interfaces (dependency inversion). A handler never imports a concrete service type. This means adding a method to a service requires updating the corresponding handler interface and mock.

**Services** contain business logic. Each service should have at most 5-6 direct dependencies. If a service exceeds ~500 lines or ~6 dependencies, decompose it using the facade/delegation pattern (see `CertificateService` -> `RevocationSvc` + `CAOperationsSvc` for the reference implementation).

**Repositories** are PostgreSQL implementations behind interfaces defined in `internal/repository/interfaces.go`. All SQL is hand-written (no ORM). Use `IF NOT EXISTS` for schema, `ON CONFLICT` for idempotent upserts.

**Connectors** implement pluggable interfaces for issuers (`issuer.Connector`), targets (`target.Connector`), and notifiers (`Notifier`). The `IssuerConnectorAdapter` bridges the connector-layer interface with the service-layer interface to maintain dependency inversion.

### When to Split vs. Extend

Split a component when it exceeds ~500 lines, mixes distinct responsibilities (e.g., CRUD + revocation + CRL generation), or has more than 6 dependencies. Use the facade pattern to avoid breaking handler interfaces.

Extend an existing component when the new functionality is tightly coupled to existing state and adding a new file would create unnecessary indirection.

## Middleware Stack Ordering

The HTTP middleware chain is order-sensitive. The current ordering in `cmd/server/main.go`:

1. `RequestID` - assigns a unique request ID
2. `NewLogging` - structured slog middleware with request ID propagation
3. `Recovery` - panic recovery (must be early to catch panics in later middleware)
4. `NewBodyLimit` - request body size limits via `http.MaxBytesReader` (before auth to reject oversized payloads early)
5. `NewCORS` - CORS preflight handling (deny-by-default)
6. `NewAuth` - API key / JWT authentication
7. `NewAuditLog` - records every API call to the audit trail (after auth so actor is available)

When rate limiting is enabled, `NewRateLimiter` is inserted between `NewBodyLimit` and `NewCORS`.

Contributors adding new middleware must respect this ordering. Body-level middleware goes before auth. Auth-dependent middleware goes after auth.

## Test Patterns and Conventions

### Test File Organization

Every package with production code should have corresponding `_test.go` files in the same package (not a `_test` package). Test helpers belong in `testutil_test.go` within the package.

### Mock Naming Convention

Mock types in test files must be **unexported** (lowercase). The convention:

```go
// Good - unexported, test-only
type mockCertificateService struct { ... }
func newMockCertificateService() *mockCertificateService { ... }

// Bad - exported, leaks into package API
type MockCertificateService struct { ... }
```

**Known exception:** Handler test files currently use exported Mock types (e.g., `MockCertificateService`). This is a known deviation being tracked for cleanup.

### Service Layer Tests

Service tests use mock repositories defined in `internal/service/testutil_test.go`. The pattern:

```go
func TestMyService_Method(t *testing.T) {
    repo := newMockCertificateRepository()
    auditRepo := newMockAuditRepository()
    auditService := NewAuditService(auditRepo)
    svc := NewMyService(repo, auditService)

    // Set up test data
    repo.AddCert(&domain.ManagedCertificate{...})

    // Exercise
    err := svc.DoSomething(context.Background(), "cert-1")

    // Verify
    if err != nil {
        t.Fatalf("expected no error, got: %v", err)
    }
}
```

### Handler Layer Tests

Handler tests use `httptest.NewRequest` and `httptest.NewRecorder`. Each handler test file defines its own mock service type implementing the handler's service interface:

```go
type mockFooService struct {
    err error
    // fields for capturing calls and returning data
}

func TestFooHandler_List(t *testing.T) {
    mock := &mockFooService{}
    handler := NewFooHandler(mock)
    // ...
}
```

### Repository Integration Tests

Repository tests in `internal/repository/postgres/` use `testcontainers-go` to spin up a real PostgreSQL 16 container. Key patterns:

- `setupTestDB(t)` creates a shared container for the test run
- `freshSchema(t, db)` creates an isolated PostgreSQL schema per test (`CREATE SCHEMA test_xxx; SET search_path TO test_xxx`)
- All migrations are run in each schema so tests start with a clean database
- Tests are skipped in CI short mode (`testing.Short()`) since they require Docker
- Run locally with: `go test ./internal/repository/postgres/... -v`

### Fuzz Tests

Fuzz tests use Go's native `testing/fuzz` framework. Located in `*_fuzz_test.go` files. Seed corpora include known adversarial inputs (SQL injection, shell metacharacters, etc.). Run with: `go test -fuzz=FuzzValidateShellCommand ./internal/validation/...`

### CI Coverage Thresholds

The CI pipeline enforces per-layer coverage floors:

| Layer | Threshold | Package Pattern |
|-------|-----------|-----------------|
| Service | 60% | `internal/service` |
| Handler | 60% | `internal/api/handler` |
| Domain | 40% | `internal/domain` |
| Middleware | 50% | `internal/api/middleware` |

Adding a new package with tests? Ensure it's included in the `go test` command in `.github/workflows/ci.yml`.

### Race Detection

All tests run with `-race` in CI. Never use shared mutable state without synchronization. The scheduler uses `sync/atomic.Bool` guards; follow the same pattern for any concurrent code.

## Adding New Features

1. **Domain model** in `internal/domain/` - types, constants, validation helpers
2. **Migration** in `migrations/` - `000N_feature.up.sql` and `.down.sql`, idempotent
3. **Repository interface** in `internal/repository/interfaces.go`, implementation in `internal/repository/postgres/`
4. **Service** in `internal/service/` with tests
5. **Handler** in `internal/api/handler/` defining its own service interface, with tests
6. **Route registration** via `HandlerRegistry` struct in `internal/api/router/router.go`
7. **Wire** in `cmd/server/main.go`
8. **OpenAPI spec** update in `api/openapi.yaml`
9. **GUI page** in `web/src/pages/` with route in `web/src/main.tsx`
10. **Seed data** in `migrations/seed_demo.sql` for demo mode

Every backend feature ships with its corresponding GUI surface.

## Environment

- **Go 1.25+**, **PostgreSQL 16+**, **Node.js 22+** (frontend)
- No ORM - raw `database/sql` + `lib/pq`
- No web framework - `net/http` stdlib routing
- Minimal dependencies: 5 direct Go dependencies (see `go.mod`)
- Frontend: Vite + React 18 + TypeScript + TanStack Query + Recharts + Tailwind CSS

## Documentation That Should Exist But Doesn't Yet

The following are recommended future additions:

- **Architecture diagrams** (Mermaid in `docs/architecture.md` covers some, but data flow diagrams for key workflows like renewal and revocation would help)
- **Threat model** (formal STRIDE analysis for the control plane, agent communication, and key management boundaries)
- **Testing philosophy guide** (rationale for mock-vs-real testing decisions, when to use testcontainers vs mocks)
- **Disaster recovery runbook** (PostgreSQL backup/restore, agent re-registration, CA key rotation procedures)
- **Upgrade guide** (migration steps between major versions, breaking change policy)
- **API versioning strategy** (how breaking changes will be handled when /api/v2 is needed)
