package service

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// helper to build job service with proper constructor signatures
func newTestJobService(jobRepo *mockJobRepo) *JobService {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
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

	return NewJobService(jobRepo, renewalService, deploymentService, logger)
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

	err := jobService.CancelJobWithContext(ctx, "job-001")
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

	err := jobService.CancelJobWithContext(ctx, "job-001")
	if err == nil {
		t.Fatal("expected error for completed job")
	}
}

func TestGetJob(t *testing.T) {
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

	retrieved, err := jobService.GetJob("job-001")
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

	jobs, total, err := jobService.ListJobs("", "", 1, 50)
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

	jobs, total, err := jobService.ListJobs(string(domain.JobStatusPending), "", 1, 50)
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
