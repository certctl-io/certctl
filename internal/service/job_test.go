package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// helper to build job service with proper constructor signatures
func newTestJobService(jobRepo *mockJobRepo) *JobService {
	svc, _, _ := newTestJobServiceWithRepos(jobRepo)
	return svc
}

// newTestJobServiceWithRepos returns the service along with the cert+owner
// repos so self-approval tests can seed owner linkage without rebuilding the
// whole dependency graph.
func newTestJobServiceWithRepos(jobRepo *mockJobRepo) (*JobService, *mockCertRepo, *mockOwnerRepo) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	ownerRepo := newMockOwnerRepository()
	renewalPolicyRepo := &mockRenewalPolicyRepo{
		Policies: make(map[string]*domain.RenewalPolicy),
	}
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)
	notifRepo := newMockNotificationRepository()
	notifService := NewNotificationService(notifRepo, make(map[string]Notifier))
	targetRepo := &mockTargetRepo{Targets: make(map[string]*domain.DeploymentTarget)}
	agentRepo := &mockAgentRepo{Agents: make(map[string]*domain.Agent)}

	issuerRegistry := NewIssuerRegistry(logger)
	renewalService := NewRenewalService(certRepo, jobRepo, renewalPolicyRepo, nil, auditService, notifService, issuerRegistry, "server")
	deploymentService := NewDeploymentService(jobRepo, targetRepo, agentRepo, certRepo, auditService, notifService)

	return NewJobService(jobRepo, certRepo, ownerRepo, renewalService, deploymentService, logger), certRepo, ownerRepo
}

func TestProcessPendingJobs_Renewal(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	job := &domain.Job{
		ID:            "job-001",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-001",
		Status:        domain.JobStatusPending,
		Attempts:      0,
		MaxAttempts:   3,
		CreatedAt:     now,
		ScheduledAt:   now,
	}

	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{"job-001": job},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	jobService := newTestJobService(jobRepo)

	err := jobService.ProcessPendingJobs(ctx)
	if err != nil {
		t.Logf("ProcessPendingJobs returned error (expected for renewal without cert): %v", err)
	}
}

func TestProcessPendingJobs_NoJobs(t *testing.T) {
	ctx := context.Background()

	jobRepo := &mockJobRepo{
		Jobs:          make(map[string]*domain.Job),
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	jobService := newTestJobService(jobRepo)

	err := jobService.ProcessPendingJobs(ctx)
	if err != nil {
		t.Fatalf("ProcessPendingJobs failed: %v", err)
	}
}

func TestCancelJob(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	job := &domain.Job{
		ID:            "job-001",
		Type:          domain.JobTypeDeployment,
		CertificateID: "cert-001",
		Status:        domain.JobStatusPending,
		CreatedAt:     now,
		ScheduledAt:   now,
	}

	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{"job-001": job},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	jobService := newTestJobService(jobRepo)

	err := jobService.CancelJob(ctx, "job-001")
	if err != nil {
		t.Fatalf("CancelJob failed: %v", err)
	}

	if jobRepo.StatusUpdates["job-001"] != domain.JobStatusCancelled {
		t.Errorf("expected status Cancelled, got %s", jobRepo.StatusUpdates["job-001"])
	}
}

func TestCancelJob_AlreadyCompleted(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	job := &domain.Job{
		ID:            "job-001",
		Type:          domain.JobTypeDeployment,
		CertificateID: "cert-001",
		Status:        domain.JobStatusCompleted,
		CreatedAt:     now,
		ScheduledAt:   now,
	}

	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{"job-001": job},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	jobService := newTestJobService(jobRepo)

	err := jobService.CancelJob(ctx, "job-001")
	if err == nil {
		t.Fatal("expected error for completed job")
	}
}

func TestGetJob(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	job := &domain.Job{
		ID:            "job-001",
		Type:          domain.JobTypeDeployment,
		CertificateID: "cert-001",
		Status:        domain.JobStatusPending,
		CreatedAt:     now,
		ScheduledAt:   now,
	}

	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{"job-001": job},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	jobService := newTestJobService(jobRepo)

	retrieved, err := jobService.GetJob(ctx, "job-001")
	if err != nil {
		t.Fatalf("GetJob failed: %v", err)
	}

	if retrieved.ID != "job-001" {
		t.Errorf("expected job ID job-001, got %s", retrieved.ID)
	}
	if retrieved.Type != domain.JobTypeDeployment {
		t.Errorf("expected job type Deployment, got %s", retrieved.Type)
	}
}

func TestListJobs(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	job1 := &domain.Job{
		ID:            "job-001",
		Type:          domain.JobTypeDeployment,
		CertificateID: "cert-001",
		Status:        domain.JobStatusCompleted,
		CreatedAt:     now,
		ScheduledAt:   now,
	}
	job2 := &domain.Job{
		ID:            "job-002",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-002",
		Status:        domain.JobStatusPending,
		CreatedAt:     now,
		ScheduledAt:   now,
	}

	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{"job-001": job1, "job-002": job2},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	jobService := newTestJobService(jobRepo)

	jobs, total, err := jobService.ListJobs(ctx, "", "", 1, 50)
	if err != nil {
		t.Fatalf("ListJobs failed: %v", err)
	}

	if len(jobs) != 2 {
		t.Errorf("expected 2 jobs, got %d", len(jobs))
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
}

func TestListJobs_FilterByStatus(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	job1 := &domain.Job{
		ID:            "job-001",
		Type:          domain.JobTypeDeployment,
		CertificateID: "cert-001",
		Status:        domain.JobStatusCompleted,
		CreatedAt:     now,
		ScheduledAt:   now,
	}
	job2 := &domain.Job{
		ID:            "job-002",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-002",
		Status:        domain.JobStatusPending,
		CreatedAt:     now,
		ScheduledAt:   now,
	}

	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{"job-001": job1, "job-002": job2},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	jobService := newTestJobService(jobRepo)

	jobs, total, err := jobService.ListJobs(ctx, string(domain.JobStatusPending), "", 1, 50)
	if err != nil {
		t.Fatalf("ListJobs failed: %v", err)
	}

	if len(jobs) != 1 {
		t.Errorf("expected 1 pending job, got %d", len(jobs))
	}
	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
}

// --- M-003: not-self approval (separation of duties) ---
//
// These regression tests enforce that ApproveJob returns ErrSelfApproval when
// the actor matches the certificate owner's Name or Email (case-insensitive).
// Rejection is intentionally NOT gated — owners may cancel their own pending
// renewals. Handlers map ErrSelfApproval to HTTP 403.

// seedSelfApprovalFixtures populates the mock repos with a realistic
// AwaitingApproval renewal job owned by "alice" and returns the service under
// test. The cert points at owner "o-alice" so checkNotSelf has a full resolution
// path.
func seedSelfApprovalFixtures(t *testing.T) (*JobService, *mockJobRepo) {
	t.Helper()

	now := time.Now()
	job := &domain.Job{
		ID:            "job-self",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-self",
		Status:        domain.JobStatusAwaitingApproval,
		CreatedAt:     now,
		ScheduledAt:   now,
	}
	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{job.ID: job},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	svc, certRepo, ownerRepo := newTestJobServiceWithRepos(jobRepo)

	certRepo.AddCert(&domain.ManagedCertificate{
		ID:        "cert-self",
		OwnerID:   "o-alice",
		CreatedAt: now,
		UpdatedAt: now,
	})
	ownerRepo.AddOwner(&domain.Owner{
		ID:        "o-alice",
		Name:      "alice",
		Email:     "alice@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})

	return svc, jobRepo
}

func TestApproveJob_SelfApprovalForbidden_NameMatch(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo := seedSelfApprovalFixtures(t)

	err := svc.ApproveJob(ctx, "job-self", "alice")
	if err == nil {
		t.Fatal("expected ErrSelfApproval, got nil")
	}
	if !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("expected errors.Is(err, ErrSelfApproval), got %v", err)
	}
	if _, flipped := jobRepo.StatusUpdates["job-self"]; flipped {
		t.Error("expected job status unchanged after self-approval block")
	}
}

func TestApproveJob_SelfApprovalForbidden_EmailMatch(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo := seedSelfApprovalFixtures(t)

	err := svc.ApproveJob(ctx, "job-self", "alice@example.com")
	if err == nil {
		t.Fatal("expected ErrSelfApproval, got nil")
	}
	if !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("expected errors.Is(err, ErrSelfApproval), got %v", err)
	}
	if _, flipped := jobRepo.StatusUpdates["job-self"]; flipped {
		t.Error("expected job status unchanged after self-approval block")
	}
}

func TestApproveJob_SelfApprovalForbidden_CaseInsensitive(t *testing.T) {
	ctx := context.Background()
	svc, _ := seedSelfApprovalFixtures(t)

	// Uppercase name should still collide — the check must be case-insensitive.
	if err := svc.ApproveJob(ctx, "job-self", "ALICE"); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("expected ErrSelfApproval for uppercase name match, got %v", err)
	}

	// Mixed-case email should also collide.
	if err := svc.ApproveJob(ctx, "job-self", "Alice@Example.COM"); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("expected ErrSelfApproval for mixed-case email match, got %v", err)
	}
}

func TestApproveJob_DifferentActor_Permitted(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo := seedSelfApprovalFixtures(t)

	// A different named key must be allowed to approve.
	if err := svc.ApproveJob(ctx, "job-self", "bob"); err != nil {
		t.Fatalf("expected approval to succeed for non-owner actor, got %v", err)
	}
	if jobRepo.StatusUpdates["job-self"] != domain.JobStatusPending {
		t.Errorf("expected status Pending after approval, got %s",
			jobRepo.StatusUpdates["job-self"])
	}
}

func TestApproveJob_EmptyActor_Permitted(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo := seedSelfApprovalFixtures(t)

	// Empty actor represents an internal/system caller. The handler layer
	// enforces authenticated-only, so this branch exists only for defensive
	// in-process paths (scheduler-driven auto-approval, tests, etc.).
	if err := svc.ApproveJob(ctx, "job-self", ""); err != nil {
		t.Fatalf("expected empty actor to be permitted, got %v", err)
	}
	if jobRepo.StatusUpdates["job-self"] != domain.JobStatusPending {
		t.Errorf("expected status Pending after approval, got %s",
			jobRepo.StatusUpdates["job-self"])
	}
}

func TestRejectJob_SelfRejection_Permitted(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo := seedSelfApprovalFixtures(t)

	// Owner must be able to reject their own pending renewal — M-003 scopes the
	// not-self rule to approval only.
	if err := svc.RejectJob(ctx, "job-self", "no longer needed", "alice"); err != nil {
		t.Fatalf("expected owner to reject own job, got %v", err)
	}
	if jobRepo.StatusUpdates["job-self"] != domain.JobStatusCancelled {
		t.Errorf("expected status Cancelled after rejection, got %s",
			jobRepo.StatusUpdates["job-self"])
	}
}

// --- I-001: scheduler-driven retry emits audit events ---
//
// These regression tests prove that RetryFailedJobs (a) transitions eligible
// Failed jobs to Pending, (b) skips jobs that have exhausted their max
// attempts, and (c) records a "job_retry" audit event per transition when the
// audit service is wired. A separate variant (_NoAuditServiceOK) confirms the
// nil-guard path so test/bootstrap wiring that skips the setter still works.

// newTestJobServiceWithAudit wires the optional audit dependency onto the
// standard test JobService so retry assertions can inspect recorded events.
// Mirrors newTestJobServiceWithRepos but also returns the mock audit repo
// holding any emitted events.
func newTestJobServiceWithAudit(jobRepo *mockJobRepo) (*JobService, *mockAuditRepo) {
	svc, _, _ := newTestJobServiceWithRepos(jobRepo)
	auditRepo := &mockAuditRepo{}
	svc.SetAuditService(NewAuditService(auditRepo))
	return svc, auditRepo
}

func TestJobService_RetryFailedJobs_EligibleJobTransitionsAndAudits(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	failed := &domain.Job{
		ID:            "job-retry-1",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-001",
		Status:        domain.JobStatusFailed,
		Attempts:      1,
		MaxAttempts:   3,
		CreatedAt:     now,
		ScheduledAt:   now,
	}
	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{failed.ID: failed},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	svc, auditRepo := newTestJobServiceWithAudit(jobRepo)

	if err := svc.RetryFailedJobs(ctx, 3); err != nil {
		t.Fatalf("RetryFailedJobs failed: %v", err)
	}

	if got := jobRepo.StatusUpdates[failed.ID]; got != domain.JobStatusPending {
		t.Fatalf("expected job %s status Pending after retry, got %s", failed.ID, got)
	}

	if len(auditRepo.Events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(auditRepo.Events))
	}

	ev := auditRepo.Events[0]
	if ev.Action != "job_retry" {
		t.Errorf("expected action job_retry, got %s", ev.Action)
	}
	if ev.Actor != "system" {
		t.Errorf("expected actor system, got %s", ev.Actor)
	}
	if ev.ActorType != domain.ActorTypeSystem {
		t.Errorf("expected actor type System, got %s", ev.ActorType)
	}
	if ev.ResourceType != "job" {
		t.Errorf("expected resource type job, got %s", ev.ResourceType)
	}
	if ev.ResourceID != failed.ID {
		t.Errorf("expected resource ID %s, got %s", failed.ID, ev.ResourceID)
	}

	// Details are stored as json.RawMessage — decode and verify the state
	// transition + attempt counters were captured.
	var details map[string]interface{}
	if err := json.Unmarshal(ev.Details, &details); err != nil {
		t.Fatalf("failed to decode audit event details: %v", err)
	}
	if got, want := details["old_status"], string(domain.JobStatusFailed); got != want {
		t.Errorf("expected details.old_status=%s, got %v", want, got)
	}
	if got, want := details["new_status"], string(domain.JobStatusPending); got != want {
		t.Errorf("expected details.new_status=%s, got %v", want, got)
	}
	// JSON numerics round-trip as float64.
	if got, want := details["attempts"], float64(1); got != want {
		t.Errorf("expected details.attempts=%v, got %v", want, got)
	}
	if got, want := details["max_attempts"], float64(3); got != want {
		t.Errorf("expected details.max_attempts=%v, got %v", want, got)
	}
}

func TestJobService_RetryFailedJobs_SkipsJobsAtMaxAttempts(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	// Eligible: Attempts=0, MaxAttempts=3.
	eligible := &domain.Job{
		ID:            "job-retry-eligible",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-001",
		Status:        domain.JobStatusFailed,
		Attempts:      0,
		MaxAttempts:   3,
		CreatedAt:     now,
		ScheduledAt:   now,
	}
	// Exhausted: Attempts >= MaxAttempts must be skipped.
	exhausted := &domain.Job{
		ID:            "job-retry-exhausted",
		Type:          domain.JobTypeDeployment,
		CertificateID: "cert-002",
		Status:        domain.JobStatusFailed,
		Attempts:      3,
		MaxAttempts:   3,
		CreatedAt:     now,
		ScheduledAt:   now,
	}
	jobRepo := &mockJobRepo{
		Jobs: map[string]*domain.Job{
			eligible.ID:  eligible,
			exhausted.ID: exhausted,
		},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	svc, auditRepo := newTestJobServiceWithAudit(jobRepo)

	if err := svc.RetryFailedJobs(ctx, 3); err != nil {
		t.Fatalf("RetryFailedJobs failed: %v", err)
	}

	if got := jobRepo.StatusUpdates[eligible.ID]; got != domain.JobStatusPending {
		t.Errorf("expected eligible job to transition to Pending, got %s", got)
	}
	if _, flipped := jobRepo.StatusUpdates[exhausted.ID]; flipped {
		t.Errorf("expected exhausted job to be skipped, but status was updated")
	}

	if len(auditRepo.Events) != 1 {
		t.Fatalf("expected 1 audit event (only for eligible job), got %d", len(auditRepo.Events))
	}
	if auditRepo.Events[0].ResourceID != eligible.ID {
		t.Errorf("expected audit event for eligible job %s, got %s",
			eligible.ID, auditRepo.Events[0].ResourceID)
	}
}

func TestJobService_RetryFailedJobs_NoAuditServiceOK(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	failed := &domain.Job{
		ID:            "job-retry-no-audit",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-001",
		Status:        domain.JobStatusFailed,
		Attempts:      0,
		MaxAttempts:   3,
		CreatedAt:     now,
		ScheduledAt:   now,
	}
	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{failed.ID: failed},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	// Intentionally skip SetAuditService: the nil-guard must prevent a panic
	// and still transition the job.
	svc := newTestJobService(jobRepo)

	if err := svc.RetryFailedJobs(ctx, 3); err != nil {
		t.Fatalf("RetryFailedJobs failed without audit wiring: %v", err)
	}
	if got := jobRepo.StatusUpdates[failed.ID]; got != domain.JobStatusPending {
		t.Errorf("expected status Pending after retry, got %s", got)
	}
}

// =============================================================================
// ReapTimedOutJobs Tests (I-003 coverage closure)
// =============================================================================

func TestJobService_ReapTimedOutJobs_AwaitingCSRTransitionsAndAudits(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	job := &domain.Job{
		ID:            "job-reap-csr-1",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-001",
		Status:        domain.JobStatusAwaitingCSR,
		CreatedAt:     now.Add(-36 * time.Hour), // 36 hours old
		ScheduledAt:   now,
	}
	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{job.ID: job},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	svc, auditRepo := newTestJobServiceWithAudit(jobRepo)

	if err := svc.ReapTimedOutJobs(ctx, 24*time.Hour, 168*time.Hour); err != nil {
		t.Fatalf("ReapTimedOutJobs failed: %v", err)
	}

	// Check the job was updated by retrieving from the mock's Jobs map
	updatedJob := jobRepo.Jobs[job.ID]
	if updatedJob.Status != domain.JobStatusFailed {
		t.Fatalf("expected job %s status Failed after timeout, got %s", job.ID, updatedJob.Status)
	}

	// LastError should be set
	if job.LastError == nil || !strings.Contains(*job.LastError, "timed out in AwaitingCSR after 24h") {
		t.Errorf("expected LastError containing 'timed out in AwaitingCSR after 24h', got %v", job.LastError)
	}

	// Audit event should be recorded
	if len(auditRepo.Events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(auditRepo.Events))
	}

	ev := auditRepo.Events[0]
	if ev.Action != "job_timeout" {
		t.Errorf("expected action job_timeout, got %s", ev.Action)
	}
	if ev.Actor != "system" {
		t.Errorf("expected actor system, got %s", ev.Actor)
	}
	if ev.ActorType != domain.ActorTypeSystem {
		t.Errorf("expected actor type System, got %s", ev.ActorType)
	}
	if ev.ResourceType != "job" {
		t.Errorf("expected resource type job, got %s", ev.ResourceType)
	}
	if ev.ResourceID != job.ID {
		t.Errorf("expected resource ID %s, got %s", job.ID, ev.ResourceID)
	}

	// Verify audit details
	var details map[string]interface{}
	if err := json.Unmarshal(ev.Details, &details); err != nil {
		t.Fatalf("failed to decode audit event details: %v", err)
	}
	if got, want := details["old_status"], string(domain.JobStatusAwaitingCSR); got != want {
		t.Errorf("expected details.old_status=%s, got %v", want, got)
	}
	if got, want := details["new_status"], string(domain.JobStatusFailed); got != want {
		t.Errorf("expected details.new_status=%s, got %v", want, got)
	}
	if got, want := details["timeout_reason"], "csr_timeout"; got != want {
		t.Errorf("expected details.timeout_reason=%s, got %v", want, got)
	}
	ageHours, ok := details["age_hours"].(float64)
	if !ok {
		t.Errorf("expected details.age_hours to be float64, got %T", details["age_hours"])
	} else if ageHours < 35 {
		t.Errorf("expected age_hours > 35, got %f", ageHours)
	}
}

func TestJobService_ReapTimedOutJobs_AwaitingApprovalTransitionsAndAudits(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	job := &domain.Job{
		ID:            "job-reap-approval-1",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-002",
		Status:        domain.JobStatusAwaitingApproval,
		CreatedAt:     now.Add(-200 * time.Hour), // 200 hours old
		ScheduledAt:   now,
	}
	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{job.ID: job},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	svc, auditRepo := newTestJobServiceWithAudit(jobRepo)

	if err := svc.ReapTimedOutJobs(ctx, 24*time.Hour, 168*time.Hour); err != nil {
		t.Fatalf("ReapTimedOutJobs failed: %v", err)
	}

	// Check the job was updated
	updatedJob := jobRepo.Jobs[job.ID]
	if updatedJob.Status != domain.JobStatusFailed {
		t.Fatalf("expected job %s status Failed after timeout, got %s", job.ID, updatedJob.Status)
	}

	// LastError should be set
	if updatedJob.LastError == nil || !strings.Contains(*updatedJob.LastError, "timed out in AwaitingApproval after 168h") {
		t.Errorf("expected LastError containing 'timed out in AwaitingApproval after 168h', got %v", updatedJob.LastError)
	}

	// Audit event details
	if len(auditRepo.Events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(auditRepo.Events))
	}

	ev := auditRepo.Events[0]
	var details map[string]interface{}
	if err := json.Unmarshal(ev.Details, &details); err != nil {
		t.Fatalf("failed to decode audit event details: %v", err)
	}
	if got, want := details["timeout_reason"], "approval_timeout"; got != want {
		t.Errorf("expected details.timeout_reason=%s, got %v", want, got)
	}
	ageHours, ok := details["age_hours"].(float64)
	if !ok {
		t.Errorf("expected details.age_hours to be float64, got %T", details["age_hours"])
	} else if ageHours < 199 {
		t.Errorf("expected age_hours > 199, got %f", ageHours)
	}
}

func TestJobService_ReapTimedOutJobs_SkipsJobsWithinTTL(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	job := &domain.Job{
		ID:            "job-within-ttl",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-003",
		Status:        domain.JobStatusAwaitingCSR,
		CreatedAt:     now.Add(-1 * time.Hour), // Only 1 hour old (within 24h TTL)
		ScheduledAt:   now,
	}
	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{job.ID: job},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	svc, auditRepo := newTestJobServiceWithAudit(jobRepo)

	if err := svc.ReapTimedOutJobs(ctx, 24*time.Hour, 168*time.Hour); err != nil {
		t.Fatalf("ReapTimedOutJobs failed: %v", err)
	}

	// Job should NOT transition (still AwaitingCSR)
	if job.Status != domain.JobStatusAwaitingCSR {
		t.Fatalf("expected job status to remain AwaitingCSR, got %s", job.Status)
	}

	// No audit events should be recorded
	if len(auditRepo.Events) != 0 {
		t.Fatalf("expected 0 audit events, got %d", len(auditRepo.Events))
	}
}

func TestJobService_ReapTimedOutJobs_HandlesBothStatusesInOneSweep(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	csr := &domain.Job{
		ID:            "job-sweep-csr",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-csr",
		Status:        domain.JobStatusAwaitingCSR,
		CreatedAt:     now.Add(-36 * time.Hour),
		ScheduledAt:   now,
	}
	approval := &domain.Job{
		ID:            "job-sweep-approval",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-approval",
		Status:        domain.JobStatusAwaitingApproval,
		CreatedAt:     now.Add(-200 * time.Hour),
		ScheduledAt:   now,
	}
	jobRepo := &mockJobRepo{
		Jobs: map[string]*domain.Job{
			csr.ID:      csr,
			approval.ID: approval,
		},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	svc, auditRepo := newTestJobServiceWithAudit(jobRepo)

	if err := svc.ReapTimedOutJobs(ctx, 24*time.Hour, 168*time.Hour); err != nil {
		t.Fatalf("ReapTimedOutJobs failed: %v", err)
	}

	// Both jobs should transition to Failed
	csrUpdated := jobRepo.Jobs[csr.ID]
	if csrUpdated.Status != domain.JobStatusFailed {
		t.Fatalf("expected CSR job status Failed, got %s", csrUpdated.Status)
	}
	approvalUpdated := jobRepo.Jobs[approval.ID]
	if approvalUpdated.Status != domain.JobStatusFailed {
		t.Fatalf("expected approval job status Failed, got %s", approvalUpdated.Status)
	}

	// Two audit events should be recorded
	if len(auditRepo.Events) != 2 {
		t.Fatalf("expected 2 audit events, got %d", len(auditRepo.Events))
	}

	// Verify each event has the correct timeout_reason
	for _, ev := range auditRepo.Events {
		var details map[string]interface{}
		if err := json.Unmarshal(ev.Details, &details); err != nil {
			t.Fatalf("failed to decode details: %v", err)
		}
		if ev.ResourceID == csr.ID && details["timeout_reason"] != "csr_timeout" {
			t.Errorf("CSR job: expected timeout_reason=csr_timeout, got %v", details["timeout_reason"])
		}
		if ev.ResourceID == approval.ID && details["timeout_reason"] != "approval_timeout" {
			t.Errorf("approval job: expected timeout_reason=approval_timeout, got %v", details["timeout_reason"])
		}
	}
}

func TestJobService_ReapTimedOutJobs_NoAuditServiceOK(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	job := &domain.Job{
		ID:            "job-no-audit",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-004",
		Status:        domain.JobStatusAwaitingCSR,
		CreatedAt:     now.Add(-36 * time.Hour),
		ScheduledAt:   now,
	}
	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{job.ID: job},
		StatusUpdates: make(map[string]domain.JobStatus),
	}

	// Create service WITHOUT calling SetAuditService
	svc := newTestJobService(jobRepo)

	// Should not panic and should still transition the job
	if err := svc.ReapTimedOutJobs(ctx, 24*time.Hour, 168*time.Hour); err != nil {
		t.Fatalf("ReapTimedOutJobs failed without audit service: %v", err)
	}

	// Job should still transition to Failed
	updatedJob := jobRepo.Jobs[job.ID]
	if updatedJob.Status != domain.JobStatusFailed {
		t.Fatalf("expected job status Failed without audit service, got %s", updatedJob.Status)
	}
}

func TestJobService_ReapTimedOutJobs_ContinuesOnIndividualUpdateFailure(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	jobA := &domain.Job{
		ID:            "job-fail-update-a",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-a",
		Status:        domain.JobStatusAwaitingCSR,
		CreatedAt:     now.Add(-36 * time.Hour),
		ScheduledAt:   now,
	}
	jobB := &domain.Job{
		ID:            "job-fail-update-b",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-b",
		Status:        domain.JobStatusAwaitingCSR,
		CreatedAt:     now.Add(-48 * time.Hour),
		ScheduledAt:   now,
	}
	jobRepo := &mockJobRepo{
		Jobs: map[string]*domain.Job{
			jobA.ID: jobA,
			jobB.ID: jobB,
		},
		StatusUpdates:    make(map[string]domain.JobStatus),
		UpdateErrorByID:  make(map[string]error),
		UpdateErrorByIDMu: sync.Mutex{},
	}
	// Make Update fail only for jobA
	jobRepo.UpdateErrorByIDMu.Lock()
	jobRepo.UpdateErrorByID[jobA.ID] = errors.New("db connection lost")
	jobRepo.UpdateErrorByIDMu.Unlock()

	svc, auditRepo := newTestJobServiceWithAudit(jobRepo)

	// Should not propagate individual Update errors
	if err := svc.ReapTimedOutJobs(ctx, 24*time.Hour, 168*time.Hour); err != nil {
		t.Fatalf("ReapTimedOutJobs should not propagate individual errors, got: %v", err)
	}

	// Both jobs have their status modified in memory (the service modifies before Update),
	// so both will be Failed. What matters is that jobA's audit failed, so only jobB audited.
	jobAAfter := jobRepo.Jobs[jobA.ID]
	jobBAfter := jobRepo.Jobs[jobB.ID]
	if jobAAfter.Status != domain.JobStatusFailed || jobBAfter.Status != domain.JobStatusFailed {
		t.Fatalf("expected both jobs status Failed (modified before Update), got A=%s B=%s", 
			jobAAfter.Status, jobBAfter.Status)
	}

	// Only one audit event (from jobB, since jobA's Update failed and thus no audit for it)
	if len(auditRepo.Events) != 1 {
		t.Fatalf("expected 1 audit event (only jobB succeeded), got %d", len(auditRepo.Events))
	}
	if auditRepo.Events[0].ResourceID != jobB.ID {
		t.Errorf("expected audit event for jobB, got event for %s", auditRepo.Events[0].ResourceID)
	}
}

func TestJobService_ReapTimedOutJobs_RepoErrorPropagates(t *testing.T) {
	ctx := context.Background()

	jobRepo := &mockJobRepo{
		Jobs:              make(map[string]*domain.Job),
		ListTimedOutErr:   errors.New("database down"),
		StatusUpdates:     make(map[string]domain.JobStatus),
		UpdateErrorByIDMu: sync.Mutex{},
	}

	svc, auditRepo := newTestJobServiceWithAudit(jobRepo)

	err := svc.ReapTimedOutJobs(ctx, 24*time.Hour, 168*time.Hour)
	if err == nil {
		t.Fatalf("expected ReapTimedOutJobs to propagate repo error, got nil")
	}

	if !strings.Contains(err.Error(), "database down") {
		t.Errorf("expected error to contain 'database down', got: %v", err)
	}

	// No audit events should be recorded when repo fails
	if len(auditRepo.Events) != 0 {
		t.Fatalf("expected 0 audit events after repo error, got %d", len(auditRepo.Events))
	}
}
