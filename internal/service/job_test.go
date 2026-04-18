package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
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
