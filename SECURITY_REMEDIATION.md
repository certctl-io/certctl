# Security Remediation Changelog

Comprehensive security audit and remediation performed March 2026 against the certctl V2 codebase. This document tracks every change, the vulnerability addressed, CWE classification, and before/after behavior.

## Summary

- **Tickets remediated:** 17 of 20
- **Tickets deferred:** 3 (TICKET-003, TICKET-007, TICKET-010)
- **New tests added:** 100+
- **CWE classes addressed:** 11 distinct CWE categories

## Remediated Tickets

### TICKET-001: Shell Command Injection in Connector Scripts (CRITICAL)

- **CWE:** CWE-78 (OS Command Injection)
- **Severity:** CRITICAL
- **Files created:** `internal/validation/command.go`, `internal/validation/command_test.go`
- **What changed:** New `ValidateShellCommand()` function blocks all shell metacharacters (`;|&$\`(){}><"'\n\r\x00`). `ValidateDomainName()` enforces RFC 1123 compliance. `ValidateACMEToken()` restricts to base64url characters. `SanitizeForShell()` provides defense-in-depth single-quote wrapping.
- **Before:** OpenSSL and ACME connectors passed user-controlled strings directly to shell commands.
- **After:** All shell-facing inputs validated against strict character whitelists; 80+ adversarial test cases.

### TICKET-002: Scheduler Race Conditions and Ungraceful Shutdown (CRITICAL)

- **CWE:** CWE-362 (Race Condition), CWE-404 (Improper Resource Shutdown)
- **Severity:** CRITICAL
- **Files modified:** `internal/scheduler/scheduler.go`, `cmd/server/main.go`
- **Files created:** `internal/scheduler/scheduler_test.go`
- **What changed:** Added `sync/atomic.Bool` idempotency guards on all 6 scheduler loops — if a loop tick fires while the previous iteration is still running, it logs a warning and skips. Added `sync.WaitGroup` for in-flight work tracking. New `WaitForCompletion(timeout)` method blocks until all goroutines finish or timeout expires. Server main wires `sched.WaitForCompletion(30*time.Second)` before database close.
- **Before:** Concurrent scheduler ticks could produce duplicate jobs; `os.Exit` during in-flight work could corrupt state.
- **After:** Each loop runs at most one concurrent iteration; graceful shutdown waits up to 30s for in-flight work.

### TICKET-004: CORS Misconfiguration — Wildcard Allowed by Default (HIGH)

- **CWE:** CWE-942 (Overly Permissive CORS Policy)
- **Severity:** HIGH
- **Files modified:** `internal/api/middleware/middleware.go`
- **Files created:** `internal/api/middleware/cors_test.go`
- **What changed:** Empty `CERTCTL_CORS_ORIGINS` now denies all cross-origin requests (no CORS headers set). Previously, an empty config implicitly allowed all origins.
- **Before:** Deploying without setting `CERTCTL_CORS_ORIGINS` left the API open to cross-origin requests from any domain.
- **After:** Deny-by-default. Operators must explicitly configure allowed origins. 9 test cases cover deny-default, specific origins, wildcard, and preflight behavior.

### TICKET-005: No Race Detection in CI (HIGH)

- **CWE:** CWE-362 (Race Condition)
- **Severity:** HIGH
- **Files modified:** `.github/workflows/ci.yml`
- **What changed:** Added `go test -race` step targeting service, handler, middleware, and scheduler packages with `-count=1 -timeout 300s`.
- **Before:** Data races could ship undetected.
- **After:** Every CI run catches races with Go's built-in race detector.

### TICKET-006: 18-Positional-Parameter Function Signature (MEDIUM)

- **CWE:** CWE-1078 (Inappropriate Source Code Style)
- **Severity:** MEDIUM
- **Files modified:** `internal/api/router/router.go`, `cmd/server/main.go`, `internal/integration/lifecycle_test.go`, `internal/integration/negative_test.go`
- **What changed:** Replaced `RegisterHandlers(18 positional params)` with `HandlerRegistry` struct containing 18 named fields. All call sites updated to use struct literal initialization.
- **Before:** Adding or reordering a handler required updating every call site; parameter order bugs were easy to introduce.
- **After:** Named fields make call sites self-documenting; new handlers added without breaking existing code.

### TICKET-008: No Static Analysis in CI (MEDIUM)

- **CWE:** CWE-1078 (Inappropriate Source Code Style)
- **Severity:** MEDIUM
- **Files modified:** `.github/workflows/ci.yml`
- **Files created:** `.golangci.yml`
- **What changed:** Added `golangci-lint` (11 linters: errcheck, govet, staticcheck, unused, gosimple, ineffassign, typecheck, gocritic, gosec, bodyclose, noctx) and `govulncheck` steps to CI pipeline.
- **Before:** Code quality and known CVEs checked only manually.
- **After:** Every push and PR runs static analysis and vulnerability scanning.

### TICKET-009: Missing HTTP Client Timeouts in Notifier Connectors (HIGH)

- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Severity:** HIGH
- **Files modified:** Slack, Teams, PagerDuty, OpsGenie connector files
- **What changed:** All notifier HTTP clients now use explicit `Timeout: 10 * time.Second` instead of `http.DefaultClient` (no timeout).
- **Before:** A hung webhook endpoint could block a notifier goroutine indefinitely.
- **After:** All outbound HTTP calls timeout after 10 seconds.

### TICKET-012: Context Propagation — `context.Background()` Misuse (MEDIUM)

- **CWE:** CWE-755 (Improper Handling of Exceptional Conditions)
- **Severity:** MEDIUM
- **Files modified:** Multiple service files
- **What changed:** Replaced `context.Background()` usage in request-handling code with proper `ctx` propagation from the incoming HTTP request.
- **Before:** Cancellation signals (client disconnect, shutdown) were not propagated to downstream operations.
- **After:** Request context flows through service calls, enabling proper cancellation and timeout propagation.

### TICKET-013: SSRF in Network Scanner — No Reserved IP Filtering (HIGH)

- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Severity:** HIGH
- **Files modified:** `internal/service/network_scan.go`
- **What changed:** Added `isReservedIP()` function that filters loopback (127.0.0.0/8), link-local (169.254.0.0/16 — includes cloud metadata at 169.254.169.254), multicast (224.0.0.0/4), and broadcast (255.255.255.255) addresses. RFC 1918 private ranges explicitly allowed since certctl is self-hosted for internal networks.
- **Before:** Network scanner could probe cloud metadata endpoints (169.254.169.254) or loopback services.
- **After:** Reserved ranges filtered before CIDR expansion; private ranges preserved for legitimate internal scanning.

### TICKET-014: Agent Verify Tests Generate Invalid Certificates (MEDIUM)

- **CWE:** CWE-1060 (Excessive Runtime Resource Consumption)
- **Severity:** MEDIUM
- **Files modified:** `cmd/agent/verify_test.go`
- **What changed:** `generateTestCert()` now creates valid self-signed ECDSA P-256 certificates with proper serial numbers, validity periods, and key usage.
- **Before:** Tests used invalid certificate stubs that could mask real parsing bugs.
- **After:** Tests exercise real X.509 certificate parsing paths.

### TICKET-015: Flaky Async Audit Tests Using `time.Sleep` (MEDIUM)

- **CWE:** CWE-362 (Race Condition in Tests)
- **Severity:** MEDIUM
- **Files modified:** `internal/api/middleware/audit_test.go`
- **What changed:** Replaced `time.Sleep(50ms)` with `waitableAuditRecorder` that uses channel-based synchronization. Tests block on a channel until the async audit goroutine completes.
- **Before:** Tests depended on wall-clock timing; could flake under load.
- **After:** Deterministic synchronization; no timing dependency.

### TICKET-016: Undocumented `InsecureSkipVerify: true` Usage (LOW)

- **CWE:** CWE-295 (Improper Certificate Validation)
- **Severity:** LOW
- **Files modified:** `cmd/agent/verify.go`, `internal/service/network_scan.go`
- **What changed:** Added detailed security comments explaining why `InsecureSkipVerify: true` is intentional and scoped: it's required for discovery/verification probing of all certificates (including self-signed, expired, internal CA) and is never used for control-plane API calls or issuer communication.
- **Before:** `InsecureSkipVerify` appeared without explanation, creating audit findings.
- **After:** Each usage site documents the security rationale with ticket references.

### TICKET-017: Coverage Thresholds Too Low (MEDIUM)

- **CWE:** CWE-1078 (Inappropriate Source Code Style)
- **Severity:** MEDIUM
- **Files modified:** `.github/workflows/ci.yml`
- **What changed:** Raised CI coverage thresholds: service 30% → 60%, handler 50% → 60%. Added new layers: domain 40%, middleware 50%.
- **Before:** Tests could degrade significantly before CI flagged it.
- **After:** Per-layer coverage floors prevent regression in any single layer.

### TICKET-018: No Fuzz Testing (LOW)

- **CWE:** CWE-20 (Improper Input Validation)
- **Severity:** LOW
- **Files created:** `internal/validation/command_fuzz_test.go`, `internal/domain/revocation_fuzz_test.go`
- **What changed:** Added Go native fuzz tests (`testing/fuzz`) for command validation functions and revocation domain parsing. Fuzz targets exercise `ValidateShellCommand`, `ValidateDomainName`, `ValidateACMEToken` with random inputs.
- **Before:** Input validation tested only with known adversarial inputs.
- **After:** Continuous fuzzing can discover edge cases human testers miss.

### TICKET-019: Inconsistent Error Wrapping (LOW)

- **CWE:** CWE-755 (Improper Handling of Exceptional Conditions)
- **Severity:** LOW
- **Files modified:** Multiple service and handler files
- **What changed:** Standardized on `fmt.Errorf("context: %w", err)` wrapping pattern throughout the codebase. Ensures `errors.Is()` and `errors.As()` work correctly across error chains.
- **Before:** Mix of `%v` (loses error chain) and `%w` (preserves chain) formatting.
- **After:** Consistent `%w` wrapping enables proper error type checking.

### TICKET-020: Missing Godoc on Config Structs (LOW)

- **CWE:** CWE-1078 (Inappropriate Source Code Style)
- **Severity:** LOW
- **Files modified:** `internal/config/config.go`
- **What changed:** Added godoc comments to all fields in all config structs (ServerConfig, KeygenConfig, CAConfig, ACMEConfig, StepCAConfig, OpenSSLConfig, NotifierConfig, ESTConfig, VerificationConfig, DiscoveryConfig, NetworkScanConfig).
- **Before:** Configuration semantics discoverable only by reading code or CLAUDE.md.
- **After:** `go doc` and IDE tooltips show purpose, default values, and env var names.

## Deferred Tickets

### TICKET-003: No Repository Layer Test Scaffolding (HIGH)

- **CWE:** CWE-1060 (Excessive Runtime Resource Consumption)
- **Rationale:** Requires `testcontainers-go` infrastructure (Docker-in-Docker) for real PostgreSQL instances. Estimated 2-3 day effort. Scheduled for next sprint.

### TICKET-007: CertificateService God Object (MEDIUM)

- **CWE:** CWE-1060 (Excessive Runtime Resource Consumption)
- **Rationale:** 700+ line service file mixing CRUD, revocation, CRL/OCSP, and deployment logic. Decomposition into RevocationService, CRLService, OCSPService, and DeploymentService is a multi-day refactor with high regression risk. Scheduled for dedicated refactor sprint.

### TICKET-010: Missing Request Body Size Limits (MEDIUM)

- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Rationale:** Requires `http.MaxBytesReader` integration across all handlers. Lower risk in practice since API key auth limits exposure to authenticated clients. Scheduled for next sprint.

## CI Pipeline Changes

The CI pipeline now enforces:

1. **`go vet`** — basic static analysis
2. **`go test -race`** — race detection on service, handler, middleware, scheduler packages
3. **`golangci-lint`** — 11 linters (errcheck, govet, staticcheck, unused, gosimple, ineffassign, typecheck, gocritic, gosec, bodyclose, noctx)
4. **`govulncheck`** — known CVE scanning against Go dependencies
5. **Coverage thresholds** — service 60%, handler 60%, domain 40%, middleware 50%
6. **Frontend** — TypeScript type check, Vitest tests, Vite production build

## Configuration Changes

### Breaking Change: CORS Deny-by-Default

**Before:** Empty `CERTCTL_CORS_ORIGINS` implicitly allowed all cross-origin requests.
**After:** Empty `CERTCTL_CORS_ORIGINS` denies all cross-origin requests. Set `CERTCTL_CORS_ORIGINS=http://localhost:3000` for development or `CERTCTL_CORS_ORIGINS=*` to restore previous behavior.

This affects any deployment that relied on the implicit wildcard CORS behavior without explicitly setting the env var.
