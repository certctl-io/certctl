package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// newTestDeploymentService creates a test deployment service with all necessary mocks.
func newTestDeploymentService() (*DeploymentService, *mockJobRepo, *mockTargetRepo, *mockAgentRepo, *mockCertRepo, *mockAuditRepo, *mockNotifier) {
	jobRepo := newMockJobRepository()
	targetRepo := &mockTargetRepo{Targets: make(map[string]*domain.DeploymentTarget)}
	agentRepo := newMockAgentRepository()
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{"Email": notifier})

	svc := NewDeploymentService(jobRepo, targetRepo, agentRepo, certRepo, auditSvc, notifSvc)
	return svc, jobRepo, targetRepo, agentRepo, certRepo, auditRepo, notifier
}

// TestDeploymentService_CreateDeploymentJobs_Success tests successful creation of deployment jobs.
func TestDeploymentService_CreateDeploymentJobs_Success(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, targetRepo, _, _, _, _ := newTestDeploymentService()

	// Add two targets
	target1 := &domain.DeploymentTarget{
		ID:        "tgt-nginx-1",
		Name:      "NGINX Server 1",
		Type:      domain.TargetTypeNGINX,
		AgentID:   "agent-1",
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	target2 := &domain.DeploymentTarget{
		ID:        "tgt-nginx-2",
		Name:      "NGINX Server 2",
		Type:      domain.TargetTypeNGINX,
		AgentID:   "agent-2",
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	targetRepo.AddTarget(target1)
	targetRepo.AddTarget(target2)

	// Create deployment jobs
	jobIDs, err := svc.CreateDeploymentJobs(ctx, "mc-cert-1")
	if err != nil {
		t.Fatalf("CreateDeploymentJobs failed: %v", err)
	}

	// Verify 2 jobs were created
	if len(jobIDs) != 2 {
		t.Errorf("expected 2 jobs, got %d", len(jobIDs))
	}

	// Verify jobs are of correct type and status
	for _, jobID := range jobIDs {
		job, ok := jobRepo.Jobs[jobID]
		if !ok {
			t.Fatalf("job %s not found", jobID)
		}

		if job.Type != domain.JobTypeDeployment {
			t.Errorf("expected job type Deployment, got %v", job.Type)
		}

		if job.Status != domain.JobStatusPending {
			t.Errorf("expected job status Pending, got %v", job.Status)
		}

		if job.CertificateID != "mc-cert-1" {
			t.Errorf("expected CertificateID mc-cert-1, got %s", job.CertificateID)
		}

		if job.TargetID == nil || len(*job.TargetID) == 0 {
			t.Errorf("expected job to have TargetID set")
		}

		// M31: Verify AgentID is set from target's agent assignment
		if job.AgentID == nil {
			t.Errorf("expected job to have AgentID set (M31 agent routing)")
		}
	}
}

// TestDeploymentService_CreateDeploymentJobs_SetsAgentID verifies AgentID is populated from target.
func TestDeploymentService_CreateDeploymentJobs_SetsAgentID(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, targetRepo, _, _, _, _ := newTestDeploymentService()

	target := &domain.DeploymentTarget{
		ID:        "tgt-nginx-1",
		Name:      "NGINX Server 1",
		Type:      domain.TargetTypeNGINX,
		AgentID:   "agent-web-01",
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	targetRepo.AddTarget(target)

	jobIDs, err := svc.CreateDeploymentJobs(ctx, "mc-cert-1")
	if err != nil {
		t.Fatalf("CreateDeploymentJobs failed: %v", err)
	}

	if len(jobIDs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobIDs))
	}

	job := jobRepo.Jobs[jobIDs[0]]
	if job.AgentID == nil {
		t.Fatal("expected AgentID to be set on deployment job")
	}
	if *job.AgentID != "agent-web-01" {
		t.Errorf("expected AgentID 'agent-web-01', got '%s'", *job.AgentID)
	}
}

// TestDeploymentService_CreateDeploymentJobs_NoTargets tests error when no targets exist.
func TestDeploymentService_CreateDeploymentJobs_NoTargets(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _, _, _, _ := newTestDeploymentService()

	// No targets added, so ListByCertificate returns empty slice

	jobIDs, err := svc.CreateDeploymentJobs(ctx, "mc-cert-1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "no targets found") {
		t.Errorf("expected error containing 'no targets found', got %v", err)
	}

	if len(jobIDs) != 0 {
		t.Errorf("expected 0 job IDs, got %d", len(jobIDs))
	}
}

// TestDeploymentService_CreateDeploymentJobs_TargetListError tests error from target list.
func TestDeploymentService_CreateDeploymentJobs_TargetListError(t *testing.T) {
	ctx := context.Background()
	svc, _, targetRepo, _, _, _, _ := newTestDeploymentService()

	// Set target repo to return error
	targetRepo.ListByCertErr = errNotFound

	jobIDs, err := svc.CreateDeploymentJobs(ctx, "mc-cert-1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if len(jobIDs) != 0 {
		t.Errorf("expected 0 job IDs, got %d", len(jobIDs))
	}
}

// TestDeploymentService_CreateDeploymentJobs_AllJobCreationsFail tests when all job creations fail.
func TestDeploymentService_CreateDeploymentJobs_AllJobCreationsFail(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, targetRepo, _, _, _, _ := newTestDeploymentService()

	// Add targets but job creation will fail
	target := &domain.DeploymentTarget{
		ID:      "tgt-1",
		Name:    "Test Target",
		Type:    domain.TargetTypeNGINX,
		AgentID: "agent-1",
	}
	targetRepo.AddTarget(target)

	// Set job repo to fail all creates
	jobRepo.CreateErr = errNotFound

	jobIDs, err := svc.CreateDeploymentJobs(ctx, "mc-cert-1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to create any deployment jobs") {
		t.Errorf("expected error containing 'failed to create any deployment jobs', got %v", err)
	}

	if len(jobIDs) != 0 {
		t.Errorf("expected 0 job IDs, got %d", len(jobIDs))
	}
}

// TestDeploymentService_CreateDeploymentJobs_AuditEvent tests that audit event is recorded.
func TestDeploymentService_CreateDeploymentJobs_AuditEvent(t *testing.T) {
	ctx := context.Background()
	svc, _, targetRepo, _, _, auditRepo, _ := newTestDeploymentService()

	// Add a target
	target := &domain.DeploymentTarget{
		ID:      "tgt-1",
		Name:    "Test Target",
		Type:    domain.TargetTypeNGINX,
		AgentID: "agent-1",
	}
	targetRepo.AddTarget(target)

	_, err := svc.CreateDeploymentJobs(ctx, "mc-cert-1")
	if err != nil {
		t.Fatalf("CreateDeploymentJobs failed: %v", err)
	}

	// Check audit event
	if len(auditRepo.Events) == 0 {
		t.Errorf("expected at least 1 audit event, got %d", len(auditRepo.Events))
	}

	found := false
	for _, event := range auditRepo.Events {
		if event.Action == "deployment_jobs_created" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected audit event with action 'deployment_jobs_created'")
	}
}

// TestDeploymentService_ProcessDeploymentJob_Success tests successful job processing.
func TestDeploymentService_ProcessDeploymentJob_Success(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, targetRepo, agentRepo, certRepo, _, _ := newTestDeploymentService()

	// Create job with TargetID
	targetID := "tgt-1"
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      &targetID,
		Status:        domain.JobStatusPending,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Add target with AgentID
	target := &domain.DeploymentTarget{
		ID:        targetID,
		Name:      "Test Target",
		Type:      domain.TargetTypeNGINX,
		AgentID:   "agent-1",
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	targetRepo.AddTarget(target)

	// Add agent with recent heartbeat
	now := time.Now()
	agent := &domain.Agent{
		ID:               "agent-1",
		Name:             "Test Agent",
		Hostname:         "agent.example.com",
		Status:           domain.AgentStatusOnline,
		LastHeartbeatAt:  &now,
		RegisteredAt:     time.Now(),
		APIKeyHash:       "hash-1",
		OS:               "linux",
		Architecture:     "amd64",
		IPAddress:        "192.168.1.1",
		Version:          "1.0.0",
	}
	agentRepo.AddAgent(agent)

	// Add certificate
	cert := &domain.ManagedCertificate{
		ID:         "mc-cert-1",
		Name:       "Test Cert",
		CommonName: "example.com",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	certRepo.AddCert(cert)

	// Process the job
	err := svc.ProcessDeploymentJob(ctx, job)
	if err != nil {
		t.Fatalf("ProcessDeploymentJob failed: %v", err)
	}

	// Verify job status was updated to Running
	if status, ok := jobRepo.StatusUpdates["job-1"]; !ok || status != domain.JobStatusRunning {
		t.Errorf("expected job status Running, got %v", status)
	}
}

// TestDeploymentService_ProcessDeploymentJob_CertNotFound tests handling when cert is not found.
func TestDeploymentService_ProcessDeploymentJob_CertNotFound(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, targetRepo, agentRepo, certRepo, _, _ := newTestDeploymentService()

	// Create job
	targetID := "tgt-1"
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      &targetID,
		Status:        domain.JobStatusPending,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Add target
	target := &domain.DeploymentTarget{
		ID:      targetID,
		AgentID: "agent-1",
	}
	targetRepo.AddTarget(target)

	// Add agent
	now := time.Now()
	agent := &domain.Agent{
		ID:              "agent-1",
		Status:          domain.AgentStatusOnline,
		LastHeartbeatAt: &now,
	}
	agentRepo.AddAgent(agent)

	// Set cert repo to return error
	certRepo.GetErr = errNotFound

	// Process the job
	err := svc.ProcessDeploymentJob(ctx, job)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	// Verify job status was updated to Failed
	if status, ok := jobRepo.StatusUpdates["job-1"]; !ok || status != domain.JobStatusFailed {
		t.Errorf("expected job status Failed, got %v", status)
	}
}

// TestDeploymentService_ProcessDeploymentJob_NoTargetID tests handling when TargetID is missing.
func TestDeploymentService_ProcessDeploymentJob_NoTargetID(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, _, _, _, _, _ := newTestDeploymentService()

	// Create job without TargetID
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      nil,
		Status:        domain.JobStatusPending,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Process the job
	err := svc.ProcessDeploymentJob(ctx, job)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	// Verify job status was updated to Failed
	if status, ok := jobRepo.StatusUpdates["job-1"]; !ok || status != domain.JobStatusFailed {
		t.Errorf("expected job status Failed, got %v", status)
	}
}

// TestDeploymentService_ProcessDeploymentJob_TargetNotFound tests handling when target is not found.
func TestDeploymentService_ProcessDeploymentJob_TargetNotFound(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, targetRepo, agentRepo, certRepo, _, _ := newTestDeploymentService()

	// Create job
	targetID := "tgt-1"
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      &targetID,
		Status:        domain.JobStatusPending,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Add agent
	now := time.Now()
	agent := &domain.Agent{
		ID:              "agent-1",
		Status:          domain.AgentStatusOnline,
		LastHeartbeatAt: &now,
	}
	agentRepo.AddAgent(agent)

	// Add certificate
	cert := &domain.ManagedCertificate{
		ID:     "mc-cert-1",
		Name:   "Test Cert",
		Status: domain.CertificateStatusActive,
	}
	certRepo.AddCert(cert)

	// Set target repo to return error
	targetRepo.GetErr = errNotFound

	// Process the job
	err := svc.ProcessDeploymentJob(ctx, job)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	// Verify job status was updated to Failed
	if status, ok := jobRepo.StatusUpdates["job-1"]; !ok || status != domain.JobStatusFailed {
		t.Errorf("expected job status Failed, got %v", status)
	}
}

// TestDeploymentService_ProcessDeploymentJob_AgentNotFound tests handling when agent is not found.
func TestDeploymentService_ProcessDeploymentJob_AgentNotFound(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, targetRepo, agentRepo, certRepo, _, _ := newTestDeploymentService()

	// Create job
	targetID := "tgt-1"
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      &targetID,
		Status:        domain.JobStatusPending,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Add target with AgentID
	target := &domain.DeploymentTarget{
		ID:      targetID,
		AgentID: "agent-1",
	}
	targetRepo.AddTarget(target)

	// Add certificate
	cert := &domain.ManagedCertificate{
		ID:     "mc-cert-1",
		Name:   "Test Cert",
		Status: domain.CertificateStatusActive,
	}
	certRepo.AddCert(cert)

	// Set agent repo to return error
	agentRepo.GetErr = errNotFound

	// Process the job
	err := svc.ProcessDeploymentJob(ctx, job)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	// Verify job status was updated to Failed
	if status, ok := jobRepo.StatusUpdates["job-1"]; !ok || status != domain.JobStatusFailed {
		t.Errorf("expected job status Failed, got %v", status)
	}
}

// TestDeploymentService_ProcessDeploymentJob_AgentOffline tests handling when agent is offline.
func TestDeploymentService_ProcessDeploymentJob_AgentOffline(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, targetRepo, agentRepo, certRepo, _, _ := newTestDeploymentService()

	// Create job
	targetID := "tgt-1"
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      &targetID,
		Status:        domain.JobStatusPending,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Add target
	target := &domain.DeploymentTarget{
		ID:      targetID,
		AgentID: "agent-1",
	}
	targetRepo.AddTarget(target)

	// Add agent with old heartbeat (offline)
	oldTime := time.Now().Add(-10 * time.Minute)
	agent := &domain.Agent{
		ID:              "agent-1",
		Status:          domain.AgentStatusOnline,
		LastHeartbeatAt: &oldTime,
	}
	agentRepo.AddAgent(agent)

	// Add certificate
	cert := &domain.ManagedCertificate{
		ID:     "mc-cert-1",
		Name:   "Test Cert",
		Status: domain.CertificateStatusActive,
	}
	certRepo.AddCert(cert)

	// Process the job
	err := svc.ProcessDeploymentJob(ctx, job)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "offline") {
		t.Errorf("expected error containing 'offline', got %v", err)
	}

	// Verify job status was updated to Failed
	if status, ok := jobRepo.StatusUpdates["job-1"]; !ok || status != domain.JobStatusFailed {
		t.Errorf("expected job status Failed, got %v", status)
	}
}

// TestDeploymentService_ValidateDeployment_Completed tests successful validation.
func TestDeploymentService_ValidateDeployment_Completed(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, _, _, _, _, _ := newTestDeploymentService()

	// Create completed deployment job
	targetID := "tgt-1"
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      &targetID,
		Status:        domain.JobStatusCompleted,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Validate deployment
	success, err := svc.ValidateDeployment(ctx, "mc-cert-1", "tgt-1")
	if err != nil {
		t.Fatalf("ValidateDeployment failed: %v", err)
	}

	if !success {
		t.Errorf("expected success=true, got %v", success)
	}
}

// TestDeploymentService_ValidateDeployment_Failed tests validation of failed deployment.
func TestDeploymentService_ValidateDeployment_Failed(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, _, _, _, _, _ := newTestDeploymentService()

	// Create failed deployment job
	targetID := "tgt-1"
	errMsg := "deployment failed"
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      &targetID,
		Status:        domain.JobStatusFailed,
		LastError:     &errMsg,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Validate deployment
	success, err := svc.ValidateDeployment(ctx, "mc-cert-1", "tgt-1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if success {
		t.Errorf("expected success=false, got %v", success)
	}
}

// TestDeploymentService_ValidateDeployment_InProgress tests validation of in-progress deployment.
func TestDeploymentService_ValidateDeployment_InProgress(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, _, _, _, _, _ := newTestDeploymentService()

	// Create running deployment job
	targetID := "tgt-1"
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      &targetID,
		Status:        domain.JobStatusRunning,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Validate deployment
	success, err := svc.ValidateDeployment(ctx, "mc-cert-1", "tgt-1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "in progress") {
		t.Errorf("expected error containing 'in progress', got %v", err)
	}

	if success {
		t.Errorf("expected success=false, got %v", success)
	}
}

// TestDeploymentService_ValidateDeployment_NoJob tests validation when no job exists.
func TestDeploymentService_ValidateDeployment_NoJob(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _, _, _, _ := newTestDeploymentService()

	// No jobs added

	// Validate deployment
	success, err := svc.ValidateDeployment(ctx, "mc-cert-1", "tgt-1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "no deployment job found") {
		t.Errorf("expected error containing 'no deployment job found', got %v", err)
	}

	if success {
		t.Errorf("expected success=false, got %v", success)
	}
}

// TestDeploymentService_MarkDeploymentComplete_Success tests successful completion marking.
func TestDeploymentService_MarkDeploymentComplete_Success(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, targetRepo, _, certRepo, auditRepo, _ := newTestDeploymentService()

	// Create job
	targetID := "tgt-1"
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      &targetID,
		Status:        domain.JobStatusRunning,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Add target
	target := &domain.DeploymentTarget{
		ID:      targetID,
		Name:    "Test Target",
		AgentID: "agent-1",
	}
	targetRepo.AddTarget(target)

	// Add certificate
	cert := &domain.ManagedCertificate{
		ID:     "mc-cert-1",
		Name:   "Test Cert",
		Status: domain.CertificateStatusActive,
	}
	certRepo.AddCert(cert)

	// Mark deployment complete
	err := svc.MarkDeploymentComplete(ctx, "job-1")
	if err != nil {
		t.Fatalf("MarkDeploymentComplete failed: %v", err)
	}

	// Verify job status was updated to Completed
	if status, ok := jobRepo.StatusUpdates["job-1"]; !ok || status != domain.JobStatusCompleted {
		t.Errorf("expected job status Completed, got %v", status)
	}

	// Verify audit event was recorded
	found := false
	for _, event := range auditRepo.Events {
		if event.Action == "deployment_job_completed" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected audit event for deployment_job_completed")
	}
}

// TestDeploymentService_MarkDeploymentComplete_JobNotFound tests error when job not found.
func TestDeploymentService_MarkDeploymentComplete_JobNotFound(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, _, _, _, _, _ := newTestDeploymentService()

	// Set job repo to return error
	jobRepo.GetErr = errNotFound

	// Mark deployment complete
	err := svc.MarkDeploymentComplete(ctx, "job-1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

// TestDeploymentService_MarkDeploymentComplete_NoTargetID tests completion without target ID.
func TestDeploymentService_MarkDeploymentComplete_NoTargetID(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, _, _, certRepo, _, _ := newTestDeploymentService()

	// Create job without TargetID
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      nil,
		Status:        domain.JobStatusRunning,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Add certificate
	cert := &domain.ManagedCertificate{
		ID:     "mc-cert-1",
		Name:   "Test Cert",
		Status: domain.CertificateStatusActive,
	}
	certRepo.AddCert(cert)

	// Mark deployment complete (should succeed, just no notification)
	err := svc.MarkDeploymentComplete(ctx, "job-1")
	if err != nil {
		t.Fatalf("MarkDeploymentComplete failed: %v", err)
	}

	// Verify job status was updated to Completed
	if status, ok := jobRepo.StatusUpdates["job-1"]; !ok || status != domain.JobStatusCompleted {
		t.Errorf("expected job status Completed, got %v", status)
	}
}

// TestDeploymentService_MarkDeploymentFailed_Success tests successful failure marking.
func TestDeploymentService_MarkDeploymentFailed_Success(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, targetRepo, _, certRepo, auditRepo, _ := newTestDeploymentService()

	// Create job
	targetID := "tgt-1"
	job := &domain.Job{
		ID:            "job-1",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-cert-1",
		TargetID:      &targetID,
		Status:        domain.JobStatusRunning,
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Add target
	target := &domain.DeploymentTarget{
		ID:      targetID,
		Name:    "Test Target",
		AgentID: "agent-1",
	}
	targetRepo.AddTarget(target)

	// Add certificate
	cert := &domain.ManagedCertificate{
		ID:     "mc-cert-1",
		Name:   "Test Cert",
		Status: domain.CertificateStatusActive,
	}
	certRepo.AddCert(cert)

	// Mark deployment failed
	err := svc.MarkDeploymentFailed(ctx, "job-1", "connection timeout")
	if err != nil {
		t.Fatalf("MarkDeploymentFailed failed: %v", err)
	}

	// Verify job status was updated to Failed
	if status, ok := jobRepo.StatusUpdates["job-1"]; !ok || status != domain.JobStatusFailed {
		t.Errorf("expected job status Failed, got %v", status)
	}

	// Verify LastError is set
	if jobRepo.Jobs["job-1"].LastError == nil || *jobRepo.Jobs["job-1"].LastError != "connection timeout" {
		t.Errorf("expected LastError to be 'connection timeout', got %v", jobRepo.Jobs["job-1"].LastError)
	}

	// Verify audit event was recorded
	found := false
	for _, event := range auditRepo.Events {
		if event.Action == "deployment_job_failed" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected audit event for deployment_job_failed")
	}
}

// TestDeploymentService_MarkDeploymentFailed_JobNotFound tests error when job not found.
func TestDeploymentService_MarkDeploymentFailed_JobNotFound(t *testing.T) {
	ctx := context.Background()
	svc, jobRepo, _, _, _, _, _ := newTestDeploymentService()

	// Set job repo to return error
	jobRepo.GetErr = errNotFound

	// Mark deployment failed
	err := svc.MarkDeploymentFailed(ctx, "job-1", "error message")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}
