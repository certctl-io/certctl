# certctl Test Gap Attack Prompt

**Purpose:** Self-contained prompt for a future Claude session to systematically close all identified test gaps. Copy this entire document into a new session along with CLAUDE.md.

**Estimated effort:** 250-350 new test functions across 12-15 new/modified test files.

---

## Context

You are working on certctl, a self-hosted certificate lifecycle platform. The project has ~1100 tests but a comprehensive audit identified 12 gaps across 4 priority tiers. Your job is to close ALL of them in order (P0 first, then P1, then P2). After each file you create or modify, run the specific test file to verify it passes, then run `go vet ./...` to catch issues early.

**Key conventions:**
- Package-level tests (e.g., `package service` not `package service_test`) so you can access unexported fields
- Mock repositories use function-field injection pattern (see `internal/service/testutil_test.go` for all mocks)
- Mocks available: `mockCertRepo`, `mockJobRepo`, `mockNotifRepo`, `mockAuditRepo`, `mockPolicyRepo`, `mockRenewalPolicyRepo`, `mockAgentRepo`, `mockTargetRepo`, `mockIssuerConnector`, `mockIssuerRepository`, `mockRevocationRepo`, `mockNotifier`
- Constructor helpers: `newMockCertificateRepository()`, `newMockJobRepository()`, etc.
- Test naming: `TestServiceName_MethodName_Scenario` (e.g., `TestDeploymentService_CreateDeploymentJobs_Success`)
- All tests use `context.Background()` unless testing cancellation
- The `generateID(prefix)` function exists in the service package for creating IDs

---

## P0-1: `internal/service/deployment_test.go` (NEW FILE)

**File to test:** `internal/service/deployment.go`

Create `internal/service/deployment_test.go` in `package service`.

### DeploymentService struct dependencies:
```go
type DeploymentService struct {
    jobRepo         repository.JobRepository      // mockJobRepo
    targetRepo      repository.TargetRepository    // mockTargetRepo
    agentRepo       repository.AgentRepository     // mockAgentRepo
    certRepo        repository.CertificateRepository // mockCertRepo
    auditService    *AuditService                  // real AuditService with mockAuditRepo
    notificationSvc *NotificationService           // real NotificationService with mockNotifRepo + mockNotifier
}
```

### Setup helper:
```go
func newTestDeploymentService() (*DeploymentService, *mockJobRepo, *mockTargetRepo, *mockAgentRepo, *mockCertRepo, *mockAuditRepo) {
    jobRepo := newMockJobRepository()
    targetRepo := &mockTargetRepo{Targets: make(map[string]*domain.DeploymentTarget)}
    agentRepo := newMockAgentRepository()
    certRepo := newMockCertificateRepository()
    auditRepo := newMockAuditRepository()
    auditSvc := NewAuditService(auditRepo)
    notifRepo := newMockNotificationRepository()
    notifier := newMockNotifier()
    notifSvc := NewNotificationService(notifRepo, auditSvc)
    notifSvc.RegisterNotifier(notifier)

    svc := NewDeploymentService(jobRepo, targetRepo, agentRepo, certRepo, auditSvc, notifSvc)
    return svc, jobRepo, targetRepo, agentRepo, certRepo, auditRepo
}
```

### Required tests (~20 functions):

**CreateDeploymentJobs:**
1. `TestDeploymentService_CreateDeploymentJobs_Success` — 2 targets for cert, verify 2 jobs created with correct CertificateID, Type=Deployment, Status=Pending, TargetID set
2. `TestDeploymentService_CreateDeploymentJobs_NoTargets` — empty targets list, expect error "no targets found"
3. `TestDeploymentService_CreateDeploymentJobs_TargetListError` — targetRepo.ListByCertErr set, expect wrapped error
4. `TestDeploymentService_CreateDeploymentJobs_AllJobCreationsFail` — jobRepo.CreateErr set, expect error "failed to create any deployment jobs"
5. `TestDeploymentService_CreateDeploymentJobs_PartialFailure` — first job create fails (use a counter-based mock or accept that current mock fails all), verify at least error handling
6. `TestDeploymentService_CreateDeploymentJobs_AuditEvent` — verify auditRepo.Events contains "deployment_jobs_created" event with target_count and job_count

**ProcessDeploymentJob:**
7. `TestDeploymentService_ProcessDeploymentJob_Success` — job with TargetID, target has AgentID, agent has recent heartbeat. Verify job status updated to Running, audit event recorded
8. `TestDeploymentService_ProcessDeploymentJob_CertNotFound` — certRepo.GetErr set, verify job marked Failed
9. `TestDeploymentService_ProcessDeploymentJob_NoTargetID` — job.TargetID is nil, verify job marked Failed with "target_id not found"
10. `TestDeploymentService_ProcessDeploymentJob_TargetNotFound` — targetRepo.GetErr set, verify job marked Failed
11. `TestDeploymentService_ProcessDeploymentJob_AgentNotFound` — agentRepo.GetErr set, verify job marked Failed
12. `TestDeploymentService_ProcessDeploymentJob_AgentOffline` — agent.LastHeartbeatAt is 10 minutes ago, verify job marked Failed with "agent is offline", notification sent

**ValidateDeployment:**
13. `TestDeploymentService_ValidateDeployment_Completed` — deployment job exists with Status=Completed, expect (true, nil)
14. `TestDeploymentService_ValidateDeployment_Failed` — deployment job with Status=Failed and LastError, expect (false, error with message)
15. `TestDeploymentService_ValidateDeployment_InProgress` — deployment job with Status=Running, expect (false, "deployment in progress")
16. `TestDeploymentService_ValidateDeployment_NoJob` — no matching deployment job, expect (false, "no deployment job found")
17. `TestDeploymentService_ValidateDeployment_ListError` — jobRepo returns error

**MarkDeploymentComplete:**
18. `TestDeploymentService_MarkDeploymentComplete_Success` — verify job status -> Completed, notification sent (success=true), audit event
19. `TestDeploymentService_MarkDeploymentComplete_JobNotFound` — jobRepo.GetErr set
20. `TestDeploymentService_MarkDeploymentComplete_NoTargetID` — job.TargetID is nil, still completes without notification

**MarkDeploymentFailed:**
21. `TestDeploymentService_MarkDeploymentFailed_Success` — verify job status -> Failed, error message stored, notification sent (success=false), audit event
22. `TestDeploymentService_MarkDeploymentFailed_JobNotFound` — jobRepo.GetErr set

---

## P0-2: `internal/service/target_test.go` (NEW FILE)

**File to test:** `internal/service/target.go`

### Setup:
```go
func newTestTargetService() (*TargetService, *mockTargetRepo, *mockAuditRepo) {
    targetRepo := &mockTargetRepo{Targets: make(map[string]*domain.DeploymentTarget)}
    auditRepo := newMockAuditRepository()
    auditSvc := NewAuditService(auditRepo)
    return NewTargetService(targetRepo, auditSvc), targetRepo, auditRepo
}
```

### Required tests (~15 functions):

**Context-aware methods (List, Get, Create, Update, Delete):**
1. `TestTargetService_List_Success` — 3 targets, page=1 perPage=2, expect 2 returned with total=3
2. `TestTargetService_List_DefaultPagination` — page=0 perPage=0, expect defaults to 1/50
3. `TestTargetService_List_EmptyPage` — page=2 perPage=10 with only 3 targets, expect empty slice, total=3
4. `TestTargetService_List_RepoError` — ListErr set
5. `TestTargetService_Get_Success` — target exists
6. `TestTargetService_Get_NotFound` — target doesn't exist
7. `TestTargetService_Create_Success` — verify target stored, ID generated, timestamps set, audit event
8. `TestTargetService_Create_MissingName` — empty name, expect error
9. `TestTargetService_Create_RepoError` — CreateErr set
10. `TestTargetService_Update_Success` — verify target updated, audit event
11. `TestTargetService_Update_MissingName` — empty name, expect error
12. `TestTargetService_Delete_Success` — verify target removed, audit event
13. `TestTargetService_Delete_RepoError` — DeleteErr set

**Legacy handler interface methods:**
14. `TestTargetService_ListTargets_Success` — verify returns dereferenced targets
15. `TestTargetService_GetTarget_Success`
16. `TestTargetService_CreateTarget_Success` — verify ID generation
17. `TestTargetService_UpdateTarget_Success`
18. `TestTargetService_DeleteTarget_Success`

---

## P0-3: Scheduler Loop Execution Tests

**File to modify:** `internal/scheduler/scheduler_test.go`

The existing tests cover idempotency and graceful shutdown. Add tests that verify each loop actually calls its service method.

### Required tests (~8 functions):

1. `TestSchedulerRenewalLoopCallsService` — start scheduler with 50ms interval, wait 150ms, verify renewalMock.callCount >= 1
2. `TestSchedulerJobProcessorLoopCallsService` — same pattern for jobMock
3. `TestSchedulerAgentHealthCheckLoopCallsService` — same for agentMock
4. `TestSchedulerNotificationLoopCallsService` — same for notificationMock
5. `TestSchedulerNetworkScanLoopCallsService` — same for networkMock
6. `TestSchedulerShortLivedExpiryLoopCallsService` — verify ExpireShortLivedCertificates is called (need to add callCount tracking to mockRenewalService.ExpireShortLivedCertificates)
7. `TestSchedulerLoopErrorRecovery` — set shouldError=true on renewalMock, verify scheduler continues (doesn't crash), subsequent calls still happen
8. `TestSchedulerLoopContextCancellation` — cancel context mid-execution, verify no panics, WaitForCompletion succeeds

**Note:** You'll need to add `expireCallCount` and `expireCallTimes` fields to `mockRenewalService` and track calls in `ExpireShortLivedCertificates`.

---

## P0-4: Agent Binary Tests

**File to create:** `cmd/agent/agent_test.go` (NEW FILE, `package main`)

This is the hardest gap. The agent binary's methods (`executeCSRJob`, `executeDeploymentJob`, heartbeat loop, discovery loop) need a mock HTTP server.

### Setup:
```go
func newTestServer(t *testing.T) *httptest.Server {
    mux := http.NewServeMux()
    // Register mock endpoints
    mux.HandleFunc("/api/v1/agents/", func(w http.ResponseWriter, r *http.Request) {
        // Handle heartbeat (POST /agents/{id}/heartbeat), work (GET /agents/{id}/work),
        // CSR submission (POST /agents/{id}/csr), job status (POST /agents/{id}/jobs/{job_id}/status),
        // discoveries (POST /agents/{id}/discoveries)
    })
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
    })
    return httptest.NewServer(mux)
}
```

### Required tests (~10 functions):

1. `TestAgentHeartbeat_Success` — mock server returns 200, verify request has correct headers
2. `TestAgentHeartbeat_ServerDown` — connection refused, verify error handling (no panic)
3. `TestAgentCSRGeneration` — verify ECDSA P-256 key generation, CSR contains correct CN and SANs
4. `TestAgentCSRGeneration_EmailSAN` — verify email SANs route to EmailAddresses (not DNSNames)
5. `TestAgentWorkPolling_NoWork` — server returns empty work list
6. `TestAgentWorkPolling_DeploymentJob` — server returns deployment work item
7. `TestAgentWorkPolling_CSRJob` — server returns AwaitingCSR work item
8. `TestAgentKeyStorage` — verify keys written to temp dir with 0600 permissions
9. `TestAgentDiscoveryScan` — scan a temp directory with a test PEM file, verify correct extraction
10. `TestAgentDiscoveryScan_EmptyDir` — scan empty directory, verify empty results (no error)

**Important:** The agent code uses global variables and `main()` package patterns. You may need to extract testable functions or use `TestMain` for setup. If the agent's methods are on a struct, mock the HTTP client. If they're standalone functions, use httptest.

---

## P1-1: `CompleteAgentCSRRenewal` Tests

**File to modify:** `internal/service/renewal_test.go`

### Required tests (~8 functions):

The method signature is:
```go
func (s *RenewalService) CompleteAgentCSRRenewal(ctx context.Context, job *domain.Job, cert *domain.ManagedCertificate, csrPEM string) error
```

You need a `RenewalService` with: certRepo, jobRepo, auditService, notificationSvc, issuerConnector (mock), profileRepo (mock), keygenMode="agent".

1. `TestCompleteAgentCSRRenewal_Success` — valid job (AwaitingCSR), valid cert, valid CSR PEM. Verify: issuer.IssueCertificate called, cert version created, job status -> Completed, deployment jobs created
2. `TestCompleteAgentCSRRenewal_IssuerError` — issuerConnector.Err set, verify job status -> Failed
3. `TestCompleteAgentCSRRenewal_InvalidCSR` — garbage CSR PEM, verify error
4. `TestCompleteAgentCSRRenewal_WithEKUs` — cert has certificate_profile_id, profile has allowed_ekus=["emailProtection"], verify EKUs forwarded to issuer
5. `TestCompleteAgentCSRRenewal_NoProfile` — cert has no profile ID, verify default EKUs (nil)
6. `TestCompleteAgentCSRRenewal_CreateVersionError` — certRepo.CreateVersionErr set
7. `TestCompleteAgentCSRRenewal_AuditRecorded` — verify audit event with correct details
8. `TestCompleteAgentCSRRenewal_DeploymentJobsCreated` — after successful signing, verify deployment jobs exist in jobRepo

**Note:** You'll need a `mockProfileRepo` if one doesn't exist in testutil_test.go. Check if `internal/repository/interfaces.go` has `ProfileRepository` and create a mock.

---

## P1-2: `ExpireShortLivedCertificates` Tests

**File to modify:** `internal/service/renewal_test.go`

```go
func (s *RenewalService) ExpireShortLivedCertificates(ctx context.Context) error
```

1. `TestExpireShortLivedCertificates_NoShortLived` — no active certs with short-lived profiles, no changes
2. `TestExpireShortLivedCertificates_ExpiresActiveCert` — cert with profile TTL < 1h, cert active, cert's NotAfter is in the past. Verify status -> Expired
3. `TestExpireShortLivedCertificates_SkipsNonExpired` — cert with short-lived profile but NotAfter is in the future, no change
4. `TestExpireShortLivedCertificates_SkipsNonShortLived` — cert with normal profile (TTL > 1h), even if expired. Verify not touched by this method
5. `TestExpireShortLivedCertificates_RepoError` — certRepo.ListErr set

**Note:** This method needs access to profiles to determine TTL. Read the actual implementation to understand how it queries — it may iterate all active certs and check their profile's max_ttl.

---

## P1-3: Domain Model Tests

### `internal/domain/job_test.go` (NEW FILE)

```go
package domain

import "testing"
```

1. `TestJobType_Constants` — verify all 4 JobType constants have expected string values
2. `TestJobStatus_Constants` — verify all 7 JobStatus constants
3. `TestVerificationStatus_Constants` — verify all 4 VerificationStatus constants (pending, success, failed, skipped)

### `internal/domain/certificate_test.go` (NEW FILE)

1. `TestCertificateStatus_Constants` — verify all 8 CertificateStatus constants
2. `TestRenewalPolicy_EffectiveAlertThresholds_Custom` — policy with custom thresholds returns them
3. `TestRenewalPolicy_EffectiveAlertThresholds_Default` — policy with nil thresholds returns DefaultAlertThresholds()
4. `TestDefaultAlertThresholds` — returns [30, 14, 7, 0]

### `internal/domain/agent_group_test.go` (NEW FILE)

1. `TestAgentGroup_HasDynamicCriteria_True` — group with MatchOS set
2. `TestAgentGroup_HasDynamicCriteria_False` — all criteria empty
3. `TestAgentGroup_MatchesAgent_AllMatch` — all 4 criteria set, agent matches all
4. `TestAgentGroup_MatchesAgent_OSMismatch` — MatchOS="linux", agent.OS="windows"
5. `TestAgentGroup_MatchesAgent_ArchMismatch` — MatchArchitecture="amd64", agent.Architecture="arm64"
6. `TestAgentGroup_MatchesAgent_VersionMismatch` — MatchVersion="1.0", agent.Version="2.0"
7. `TestAgentGroup_MatchesAgent_IPMismatch` — MatchIPCIDR doesn't match agent.IPAddress
8. `TestAgentGroup_MatchesAgent_EmptyCriteriaMatchesAll` — all criteria empty, any agent matches
9. `TestAgentGroup_MatchesAgent_PartialCriteria` — only MatchOS set, agent matches OS, other fields irrelevant
10. `TestAgentGroup_MatchesAgent_NilAgent` — if agent is nil, should not panic (add nil guard or verify behavior)

### `internal/domain/notification_test.go` (NEW FILE)

1. `TestNotificationType_Constants` — verify all 7 types
2. `TestNotificationChannel_Constants` — verify all 6 channels
3. `TestNotificationEvent_ZeroValue` — default struct has empty strings, nil pointers

### `internal/domain/policy_test.go` (NEW FILE)

1. `TestPolicyType_Constants` — verify all 5 policy types
2. `TestPolicySeverity_Constants` — verify all 3 severities
3. `TestPolicyViolation_Fields` — create a violation, verify all fields accessible

---

## P1-4: Handler Gap Tests

### Modify `internal/api/handler/agent_group_handler_test.go`

Add:
1. `TestUpdateAgentGroup_Success` — PUT with valid body, verify 200
2. `TestUpdateAgentGroup_InvalidJSON` — malformed body, verify 400
3. `TestUpdateAgentGroup_MissingName` — empty name field, verify 400
4. `TestUpdateAgentGroup_NotFound` — service returns not found error, verify 404

### Modify `internal/api/handler/issuer_handler_test.go`

Add:
1. `TestUpdateIssuer_Success` — PUT with valid body, verify 200
2. `TestUpdateIssuer_InvalidJSON` — verify 400
3. `TestUpdateIssuer_NotFound` — verify 404

### Modify `internal/api/handler/network_scan_handler_test.go`

Add:
1. `TestGetNetworkScanTarget_Success` — GET by ID, verify 200
2. `TestGetNetworkScanTarget_NotFound` — verify 404
3. `TestUpdateNetworkScanTarget_Success` — PUT with valid body, verify 200
4. `TestUpdateNetworkScanTarget_InvalidJSON` — verify 400
5. `TestUpdateNetworkScanTarget_NotFound` — verify 404

---

## P2-1: Frontend Error Handling Tests

**File to modify:** `web/src/api/client.test.ts`

Add error scenario tests for the 65+ API functions that lack them. Group by resource:

### Pattern:
```typescript
it('listCertificates handles 500 error', async () => {
  fetchMock.mockResponseOnce('', { status: 500 });
  await expect(listCertificates()).rejects.toThrow();
});

it('getCertificate handles 404 error', async () => {
  fetchMock.mockResponseOnce('', { status: 404 });
  await expect(getCertificate('nonexistent')).rejects.toThrow();
});
```

### Required (~40 tests):

Add at minimum a 500 error test and a 404 test (where applicable) for each resource group:
- Certificates (list 500, get 404, renew 404, revoke 404, export 404)
- Agents (list 500, get 404)
- Jobs (list 500, get 404, cancel 404, approve 404, reject 404)
- Policies (list 500, get 404, create 400, update 404, delete 404)
- Profiles (list 500, get 404, create 400)
- Owners (list 500, get 404)
- Teams (list 500, get 404)
- Agent Groups (list 500, get 404)
- Issuers (list 500, get 404)
- Targets (list 500, get 404, create 400)
- Discovery (list 500, claim 404, dismiss 404)
- Network Scans (list 500, create 400, trigger 404)
- Stats/Metrics (500 errors)
- Health (500 error)

---

## P2-2: Context Cancellation Tests

**File to create:** `internal/service/context_test.go` (NEW FILE)

Test that long-running service methods respect context cancellation.

### Pattern:
```go
func TestDeploymentService_CreateDeploymentJobs_ContextCancelled(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    cancel() // Cancel immediately

    svc, _, targetRepo, _, _, _ := newTestDeploymentService()
    targetRepo.AddTarget(&domain.DeploymentTarget{ID: "t1", Name: "test"})

    _, err := svc.CreateDeploymentJobs(ctx, "cert-1")
    // Depending on implementation, may get context.Canceled or proceed normally
    // The key assertion: no panic, no goroutine leak
    t.Logf("result with cancelled context: %v", err)
}
```

### Required (~8 tests):

1. `TestDeploymentService_ProcessDeploymentJob_ContextTimeout` — context with 1ms timeout
2. `TestNetworkScanService_ScanAllTargets_ContextCancelled` — cancel mid-scan
3. `TestDiscoveryService_ProcessDiscoveryReport_ContextCancelled`
4. `TestESTService_SimpleEnroll_ContextCancelled`
5. `TestExportService_ExportPKCS12_ContextCancelled`
6. `TestRenewalService_ProcessRenewalJob_ContextTimeout`
7. `TestCertificateService_RevokeCertificateWithActor_ContextCancelled`
8. `TestVerificationService_RecordVerificationResult_ContextCancelled`

---

## P2-3: Concurrent Operation Tests

**File to create:** `internal/service/concurrent_test.go` (NEW FILE)

Use `sync.WaitGroup` and goroutines to test concurrent access patterns.

### Required (~6 tests):

```go
func TestConcurrentRevocation(t *testing.T) {
    // Setup service with a certificate
    // Launch 5 goroutines all trying to revoke the same cert simultaneously
    // Verify: exactly 1 succeeds (or all succeed idempotently), no panics, no data corruption
    var wg sync.WaitGroup
    errors := make([]error, 5)
    for i := 0; i < 5; i++ {
        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            errors[idx] = svc.RevokeCertificateWithActor(ctx, certID, "keyCompromise", "test-actor")
        }(i)
    }
    wg.Wait()
    // Assert at most 1 "already revoked" error
}
```

1. `TestConcurrentRevocation` — 5 goroutines revoke same cert
2. `TestConcurrentDeploymentJobCreation` — 3 goroutines create deployment jobs for same cert
3. `TestConcurrentDiscoveryReports` — 3 goroutines submit discovery reports simultaneously
4. `TestConcurrentCertificateList` — 10 goroutines list certificates simultaneously (no race)
5. `TestConcurrentJobStatusUpdate` — 5 goroutines update same job status
6. `TestConcurrentTargetCRUD` — create, update, delete targets concurrently

---

## Execution Order

Run these in order, verifying each step:

```bash
# P0 — Critical
go test ./internal/service/ -run TestDeploymentService -v -count=1
go test ./internal/service/ -run TestTargetService -v -count=1
go test ./internal/scheduler/ -run TestScheduler -v -count=1

# P1 — High Priority
go test ./internal/service/ -run TestCompleteAgentCSR -v -count=1
go test ./internal/service/ -run TestExpireShortLived -v -count=1
go test ./internal/domain/ -v -count=1
go test ./internal/api/handler/ -run "TestUpdateAgentGroup|TestUpdateIssuer|TestGetNetworkScan|TestUpdateNetworkScan" -v -count=1

# P2 — Medium Priority
cd web && npx vitest run
go test ./internal/service/ -run TestContext -v -count=1
go test ./internal/service/ -run TestConcurrent -v -count=1

# Full suite verification
go test -race ./internal/service/... ./internal/api/handler/... ./internal/api/middleware/... ./internal/scheduler/... ./internal/connector/... ./internal/domain/... ./internal/validation/... -count=1 -timeout 300s
go vet ./...
cd web && npx vitest run
```

## Final CI Gate

After all tests pass locally, verify the full CI pipeline would pass:

```bash
# Coverage check
go test ./internal/service/... ./internal/api/handler/... ./internal/api/middleware/... ./internal/integration/... ./internal/connector/issuer/... ./internal/connector/target/... ./internal/connector/notifier/... ./internal/mcp/... ./internal/cli/... ./internal/domain/... ./internal/validation/... -count=1 -cover -coverprofile=coverage.out

# Check thresholds
go tool cover -func=coverage.out | grep 'internal/service' | awk '{print $NF}' | sed 's/%//' | awk '{sum+=$1; n++} END {printf "Service: %.1f%%\n", sum/n}'
go tool cover -func=coverage.out | grep 'internal/api/handler' | awk '{print $NF}' | sed 's/%//' | awk '{sum+=$1; n++} END {printf "Handler: %.1f%%\n", sum/n}'
go tool cover -func=coverage.out | grep 'internal/domain' | awk '{print $NF}' | sed 's/%//' | awk '{sum+=$1; n++} END {printf "Domain: %.1f%%\n", sum/n}'

# Targets: service >= 60%, handler >= 60%, domain >= 40%
```

---

## What NOT To Do

- Do NOT modify any production code (only test files)
- Do NOT add new dependencies to go.mod
- Do NOT create mocks that duplicate existing ones in testutil_test.go — reuse them
- Do NOT use `testing.Short()` skips — all these tests should run in CI
- Do NOT use `time.Sleep` for synchronization — use channels, WaitGroups, or atomic counters
- Do NOT write tests that are flaky due to timing — if testing scheduler loops, use generous timeouts and verify "at least 1 call" rather than exact counts
