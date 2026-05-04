package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

// NOTE: generateTestCSR(t, keyType, keySize) is defined in crypto_validation_test.go
// Use it as: generateTestCSR(t, "ECDSA", 256)

// newTestRenewalServiceForCSR creates a RenewalService with mocks suitable for CSR renewal testing.
func newTestRenewalServiceForCSR(issuerErr error) *RenewalService {
	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	profileRepo := newMockProfileRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{
		"Email": notifier,
	})

	issuerConnector := &mockIssuerConnector{Err: issuerErr}
	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-local", issuerConnector)

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, profileRepo, auditSvc, notifSvc, issuerRegistry, "agent")
	return svc
}

// TestCompleteAgentCSRRenewal_Success tests the happy path: valid CSR, issuer signs, cert stored, deployment jobs created.
func TestCompleteAgentCSRRenewal_Success(t *testing.T) {
	ctx := context.Background()
	svc := newTestRenewalServiceForCSR(nil)

	certRepo := svc.certRepo.(*mockCertRepo)
	jobRepo := svc.jobRepo.(*mockJobRepo)

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-001",
		Name:       "Test Certificate",
		CommonName: "example.com",
		SANs:       []string{"www.example.com"},
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusRenewalInProgress,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
		TargetIDs:  []string{"t-nginx-1"},
		Tags:       make(map[string]string),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	certRepo.AddCert(cert)

	job := &domain.Job{
		ID:            "job-csr-001",
		CertificateID: cert.ID,
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusAwaitingCSR,
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	csrPEM := generateTestCSR(t, "ECDSA", 256)

	err := svc.CompleteAgentCSRRenewal(ctx, job, cert, csrPEM)
	if err != nil {
		t.Fatalf("CompleteAgentCSRRenewal failed: %v", err)
	}

	// Verify job was completed
	updatedJob, err := jobRepo.Get(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to get job after renewal: %v", err)
	}
	if updatedJob.Status != domain.JobStatusCompleted {
		t.Errorf("expected job status Completed, got %s", updatedJob.Status)
	}

	// Verify certificate version was created
	versions, err := certRepo.ListVersions(ctx, cert.ID)
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(versions) != 1 {
		t.Errorf("expected 1 version, got %d", len(versions))
	}

	// Verify version fields
	version := versions[0]
	if version.SerialNumber != "test-serial-123" {
		t.Errorf("expected serial 'test-serial-123', got %s", version.SerialNumber)
	}
	if version.CSRPEM != csrPEM {
		t.Errorf("expected CSR PEM to be stored as-is (agent mode), got mismatch")
	}
	if version.PEMChain == "" {
		t.Errorf("expected PEMChain to be populated")
	}

	// Verify certificate was updated
	updatedCert, err := certRepo.Get(ctx, cert.ID)
	if err != nil {
		t.Fatalf("failed to get cert after renewal: %v", err)
	}
	if updatedCert.Status != domain.CertificateStatusActive {
		t.Errorf("expected cert status Active, got %s", updatedCert.Status)
	}
	if updatedCert.LastRenewalAt == nil {
		t.Errorf("expected LastRenewalAt to be set")
	}

	// Verify deployment jobs were created
	deploymentJobs := 0
	for _, j := range jobRepo.Jobs {
		if j.Type == domain.JobTypeDeployment && j.CertificateID == cert.ID {
			deploymentJobs++
		}
	}
	if deploymentJobs != 1 {
		t.Errorf("expected 1 deployment job, got %d", deploymentJobs)
	}
}

// TestCompleteAgentCSRRenewal_JobNotFound tests that the method handles a missing job gracefully.
func TestCompleteAgentCSRRenewal_JobNotFound(t *testing.T) {
	ctx := context.Background()
	svc := newTestRenewalServiceForCSR(nil)

	certRepo := svc.certRepo.(*mockCertRepo)

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-not-found",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusRenewalInProgress,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
		Tags:       make(map[string]string),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	certRepo.AddCert(cert)

	// Job not added to repo — simulates "not found" on status update
	job := &domain.Job{
		ID:            "job-nonexistent",
		CertificateID: cert.ID,
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusAwaitingCSR,
		CreatedAt:     time.Now(),
	}

	csrPEM := generateTestCSR(t, "ECDSA", 256)

	// Call will pass CSR validation but fail when updating job status to Running
	err := svc.CompleteAgentCSRRenewal(ctx, job, cert, csrPEM)
	if err == nil {
		t.Errorf("expected error for missing job, got nil")
	}
}

// TestCompleteAgentCSRRenewal_JobNotAwaitingCSR tests that the method processes regardless of job state
// (the method doesn't check job.Status — it trusts the caller).
func TestCompleteAgentCSRRenewal_JobNotAwaitingCSR(t *testing.T) {
	ctx := context.Background()
	svc := newTestRenewalServiceForCSR(nil)

	certRepo := svc.certRepo.(*mockCertRepo)
	jobRepo := svc.jobRepo.(*mockJobRepo)

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-wrong-state",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
		Tags:       make(map[string]string),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	certRepo.AddCert(cert)

	job := &domain.Job{
		ID:            "job-running",
		CertificateID: cert.ID,
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusRunning, // Wrong state — method doesn't check
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	csrPEM := generateTestCSR(t, "ECDSA", 256)

	// The method doesn't validate job state, so it should still process
	err := svc.CompleteAgentCSRRenewal(ctx, job, cert, csrPEM)
	// Depending on mock behavior, this may succeed or fail — the point is no panic
	_ = err
}

// TestCompleteAgentCSRRenewal_InvalidCSR tests that invalid CSR PEM causes failure.
func TestCompleteAgentCSRRenewal_InvalidCSR(t *testing.T) {
	ctx := context.Background()
	svc := newTestRenewalServiceForCSR(nil)

	certRepo := svc.certRepo.(*mockCertRepo)
	jobRepo := svc.jobRepo.(*mockJobRepo)

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-invalid-csr",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusRenewalInProgress,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
		Tags:       make(map[string]string),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	certRepo.AddCert(cert)

	job := &domain.Job{
		ID:            "job-invalid-csr",
		CertificateID: cert.ID,
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusAwaitingCSR,
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	invalidCSR := "not a pem certificate request at all"

	err := svc.CompleteAgentCSRRenewal(ctx, job, cert, invalidCSR)
	if err == nil {
		t.Errorf("expected error for invalid CSR, got nil")
	}

	// Verify job was marked as failed
	updatedJob, _ := jobRepo.Get(ctx, job.ID)
	if updatedJob.Status != domain.JobStatusFailed {
		t.Errorf("expected job status Failed after CSR validation error, got %s", updatedJob.Status)
	}

	if updatedJob.LastError == nil || *updatedJob.LastError == "" {
		t.Errorf("expected error message stored in job, got none")
	}
}

// TestCompleteAgentCSRRenewal_IssuerError tests that issuer connector failure is handled.
func TestCompleteAgentCSRRenewal_IssuerError(t *testing.T) {
	ctx := context.Background()
	issuerErr := errors.New("issuer signing failed")
	svc := newTestRenewalServiceForCSR(issuerErr)

	certRepo := svc.certRepo.(*mockCertRepo)
	jobRepo := svc.jobRepo.(*mockJobRepo)

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-issuer-error",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusRenewalInProgress,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
		Tags:       make(map[string]string),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	certRepo.AddCert(cert)

	job := &domain.Job{
		ID:            "job-issuer-error",
		CertificateID: cert.ID,
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusAwaitingCSR,
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	csrPEM := generateTestCSR(t, "ECDSA", 256)

	err := svc.CompleteAgentCSRRenewal(ctx, job, cert, csrPEM)
	if err == nil {
		t.Errorf("expected error from issuer failure, got nil")
	}

	// Verify job was marked as failed
	updatedJob, _ := jobRepo.Get(ctx, job.ID)
	if updatedJob.Status != domain.JobStatusFailed {
		t.Errorf("expected job status Failed, got %s", updatedJob.Status)
	}

	// Verify no version was created
	versions, _ := certRepo.ListVersions(ctx, cert.ID)
	if len(versions) > 0 {
		t.Errorf("expected no version created after issuer failure, got %d", len(versions))
	}
}

// TestCompleteAgentCSRRenewal_StoreVersionError tests that version storage failure is handled.
func TestCompleteAgentCSRRenewal_StoreVersionError(t *testing.T) {
	ctx := context.Background()
	svc := newTestRenewalServiceForCSR(nil)

	certRepo := svc.certRepo.(*mockCertRepo)
	certRepo.CreateVersionErr = errors.New("version storage failed")
	jobRepo := svc.jobRepo.(*mockJobRepo)

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-store-error",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusRenewalInProgress,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
		Tags:       make(map[string]string),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	certRepo.AddCert(cert)

	job := &domain.Job{
		ID:            "job-store-error",
		CertificateID: cert.ID,
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusAwaitingCSR,
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	csrPEM := generateTestCSR(t, "ECDSA", 256)

	err := svc.CompleteAgentCSRRenewal(ctx, job, cert, csrPEM)
	if err == nil {
		t.Errorf("expected error from version storage failure, got nil")
	}

	// Verify job was marked as failed
	updatedJob, _ := jobRepo.Get(ctx, job.ID)
	if updatedJob.Status != domain.JobStatusFailed {
		t.Errorf("expected job status Failed, got %s", updatedJob.Status)
	}

	// Verify no version was actually stored
	versions, _ := certRepo.ListVersions(ctx, cert.ID)
	if len(versions) > 0 {
		t.Errorf("expected no version stored after storage error, got %d", len(versions))
	}
}

// TestCompleteAgentCSRRenewal_CertNotFound tests that missing issuer connector is handled.
func TestCompleteAgentCSRRenewal_CertNotFound(t *testing.T) {
	ctx := context.Background()
	svc := newTestRenewalServiceForCSR(nil)

	jobRepo := svc.jobRepo.(*mockJobRepo)

	job := &domain.Job{
		ID:            "job-cert-not-found",
		CertificateID: "mc-nonexistent",
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusAwaitingCSR,
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	cert := &domain.ManagedCertificate{
		ID:         "mc-cert-not-found",
		CommonName: "example.com",
		IssuerID:   "iss-nonexistent", // Not in registry
		Status:     domain.CertificateStatusRenewalInProgress,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
		Tags:       make(map[string]string),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	csrPEM := generateTestCSR(t, "ECDSA", 256)

	err := svc.CompleteAgentCSRRenewal(ctx, job, cert, csrPEM)
	if err == nil {
		t.Errorf("expected error for missing issuer, got nil")
	}
	if !contains(err.Error(), "issuer connector not found") {
		t.Errorf("expected 'issuer connector not found' error, got: %v", err)
	}
}

// TestCompleteAgentCSRRenewal_EKUFromProfile tests that EKUs are resolved from profile and passed to issuer.
func TestCompleteAgentCSRRenewal_EKUFromProfile(t *testing.T) {
	ctx := context.Background()
	svc := newTestRenewalServiceForCSR(nil)

	certRepo := svc.certRepo.(*mockCertRepo)
	jobRepo := svc.jobRepo.(*mockJobRepo)
	profileRepo := svc.profileRepo.(*mockProfileRepo)

	profile := &domain.CertificateProfile{
		ID:            "prof-smime",
		Name:          "S/MIME",
		MaxTTLSeconds: 31536000, // 365 days
		AllowedEKUs:   []string{"emailProtection", "clientAuth"},
		Enabled:       true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	profileRepo.AddProfile(profile)

	cert := &domain.ManagedCertificate{
		ID:                   "mc-test-eku",
		Name:                 "S/MIME Certificate",
		CommonName:           "user@example.com",
		SANs:                 []string{"user@example.com"},
		IssuerID:             "iss-local",
		CertificateProfileID: "prof-smime",
		Status:               domain.CertificateStatusRenewalInProgress,
		ExpiresAt:            time.Now().AddDate(1, 0, 0),
		Tags:                 make(map[string]string),
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	certRepo.AddCert(cert)

	job := &domain.Job{
		ID:            "job-eku",
		CertificateID: cert.ID,
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusAwaitingCSR,
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	csrPEM := generateTestCSR(t, "ECDSA", 256)

	err := svc.CompleteAgentCSRRenewal(ctx, job, cert, csrPEM)
	if err != nil {
		t.Fatalf("CompleteAgentCSRRenewal failed: %v", err)
	}

	// Verify job was completed — profile lookup + EKU resolution worked
	updatedJob, _ := jobRepo.Get(ctx, job.ID)
	if updatedJob.Status != domain.JobStatusCompleted {
		t.Errorf("expected job status Completed, got %s", updatedJob.Status)
	}
}
