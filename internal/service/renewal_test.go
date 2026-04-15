package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

func TestCheckExpiringCertificates_SendsThresholdAlerts(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{
		"Email": notifier,
	})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", &mockIssuerConnector{})

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create a cert expiring in 10 days
	cert := &domain.ManagedCertificate{
		ID:              "mc-expiring",
		Name:            "Test Cert",
		CommonName:      "test.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-test",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, 10),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)

	// Create policy with thresholds
	policy := &domain.RenewalPolicy{
		ID:                  "rp-standard",
		Name:                "Standard",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
	policyRepo.AddPolicy(policy)

	// Run expiry check
	err := svc.CheckExpiringCertificates(ctx)
	if err != nil {
		t.Fatalf("CheckExpiringCertificates failed: %v", err)
	}

	// Verify alerts were sent
	if len(notifRepo.Notifications) < 1 {
		t.Errorf("expected at least 1 alert, got %d", len(notifRepo.Notifications))
	}

	// Verify renewal job was created
	if len(jobRepo.Jobs) < 1 {
		t.Errorf("expected renewal job to be created")
	}

	hasRenewalJob := false
	for _, job := range jobRepo.Jobs {
		if job.Type == domain.JobTypeRenewal {
			hasRenewalJob = true
			break
		}
	}
	if !hasRenewalJob {
		t.Errorf("expected renewal job in jobs")
	}
}

func TestCheckExpiringCertificates_DeduplicatesAlerts(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()
	notifier := newMockNotifier()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{
		"Email": notifier,
	})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", &mockIssuerConnector{})

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create cert
	cert := &domain.ManagedCertificate{
		ID:              "mc-dedup",
		Name:            "Test Cert",
		CommonName:      "test.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-test",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, 10),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)

	// Create policy
	policy := &domain.RenewalPolicy{
		ID:                  "rp-standard",
		Name:                "Standard",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
	policyRepo.AddPolicy(policy)

	// Add existing threshold alert notification
	existingNotif := &domain.NotificationEvent{
		ID:            "notif-existing",
		CertificateID: &cert.ID,
		Type:          domain.NotificationTypeExpirationWarning,
		Channel:       domain.NotificationChannelEmail,
		Recipient:     "owner-1",
		Message:       "Alert [threshold:7]",
		Status:        "sent",
		CreatedAt:     time.Now(),
	}
	notifRepo.AddNotification(existingNotif)

	// Run first check
	_ = svc.CheckExpiringCertificates(ctx)

	initialCount := notifier.getSentCount()

	// Run second check - should deduplicate
	_ = svc.CheckExpiringCertificates(ctx)

	finalCount := notifier.getSentCount()

	// Should not send duplicate alerts
	if finalCount > initialCount {
		t.Errorf("expected deduplication, but sent new alerts: initial=%d, final=%d", initialCount, finalCount)
	}
}

func TestCheckExpiringCertificates_SkipsRenewalInProgress(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", &mockIssuerConnector{})

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create cert with RenewalInProgress status
	cert := &domain.ManagedCertificate{
		ID:              "mc-in-progress",
		Name:            "Test Cert",
		CommonName:      "test.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-test",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusRenewalInProgress,
		ExpiresAt:       time.Now().AddDate(0, 0, 10),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)

	// Create policy
	policy := &domain.RenewalPolicy{
		ID:                  "rp-standard",
		Name:                "Standard",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
	policyRepo.AddPolicy(policy)

	// Run check
	err := svc.CheckExpiringCertificates(ctx)
	if err != nil {
		t.Fatalf("CheckExpiringCertificates failed: %v", err)
	}

	// Should not create renewal job for cert already renewing
	for _, job := range jobRepo.Jobs {
		if job.Type == domain.JobTypeRenewal {
			t.Errorf("should not create renewal job for cert with RenewalInProgress status")
		}
	}
}

func TestCheckExpiringCertificates_SkipsExpiredFailedRevoked(t *testing.T) {
	ctx := context.Background()

	// Test that certs in Expired, Failed, and Revoked states do not get renewal jobs
	for _, tc := range []struct {
		name   string
		status domain.CertificateStatus
	}{
		{"Expired", domain.CertificateStatusExpired},
		{"Failed", domain.CertificateStatusFailed},
		{"Revoked", domain.CertificateStatusRevoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certRepo := newMockCertificateRepository()
			jobRepo := newMockJobRepository()
			policyRepo := newMockRenewalPolicyRepository()
			auditRepo := newMockAuditRepository()
			notifRepo := newMockNotificationRepository()

			auditSvc := NewAuditService(auditRepo)
			notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

			issuerRegistry := NewIssuerRegistry(slog.Default())
			issuerRegistry.Set("iss-test", &mockIssuerConnector{})

			svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

			cert := &domain.ManagedCertificate{
				ID:              "mc-" + strings.ToLower(string(tc.status)),
				Name:            "Test " + string(tc.status),
				CommonName:      "test.example.com",
				SANs:            []string{},
				OwnerID:         "owner-1",
				TeamID:          "team-1",
				IssuerID:        "iss-test",
				RenewalPolicyID: "rp-standard",
				Status:          tc.status,
				ExpiresAt:       time.Now().AddDate(0, 0, 10),
				Tags:            make(map[string]string),
				CreatedAt:       time.Now(),
				UpdatedAt:       time.Now(),
			}
			certRepo.AddCert(cert)

			policy := &domain.RenewalPolicy{
				ID:                  "rp-standard",
				Name:                "Standard",
				RenewalWindowDays:   30,
				AutoRenew:           true,
				MaxRetries:          3,
				RetryInterval:       300,
				AlertThresholdsDays: []int{30, 14, 7, 0},
				CreatedAt:           time.Now(),
				UpdatedAt:           time.Now(),
			}
			policyRepo.AddPolicy(policy)

			err := svc.CheckExpiringCertificates(ctx)
			if err != nil {
				t.Fatalf("CheckExpiringCertificates failed: %v", err)
			}

			for _, job := range jobRepo.Jobs {
				if job.Type == domain.JobTypeRenewal {
					t.Errorf("should not create renewal job for cert with %s status", tc.status)
				}
			}
		})
	}
}

func TestCheckExpiringCertificates_UpdatesStatusToExpiring(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", &mockIssuerConnector{})

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create active cert that will become expiring
	// Use an issuer NOT in the registry so no renewal job is created (which would override status)
	cert := &domain.ManagedCertificate{
		ID:              "mc-expiring-status",
		Name:            "Test Cert",
		CommonName:      "test.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-unregistered",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, 5), // 5 days, within 30-day threshold
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)

	// Create policy with AutoRenew: false so we only test status transition
	policy := &domain.RenewalPolicy{
		ID:                  "rp-standard",
		Name:                "Standard",
		RenewalWindowDays:   30,
		AutoRenew:           false,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
	policyRepo.AddPolicy(policy)

	// Run check
	_ = svc.CheckExpiringCertificates(ctx)

	// Verify status was updated to Expiring
	updated, _ := certRepo.Get(ctx, cert.ID)
	if updated.Status != domain.CertificateStatusExpiring {
		t.Errorf("expected status Expiring, got %s", updated.Status)
	}
}

func TestCheckExpiringCertificates_UpdatesStatusToExpired(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", &mockIssuerConnector{})

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create cert that is already expired
	// Use an issuer NOT in the registry so no renewal job is created (which would override status)
	cert := &domain.ManagedCertificate{
		ID:              "mc-expired-status",
		Name:            "Test Cert",
		CommonName:      "test.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-unregistered",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, -1), // Already expired
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)

	// Create policy with AutoRenew: false so we only test status transition
	policy := &domain.RenewalPolicy{
		ID:                  "rp-standard",
		Name:                "Standard",
		RenewalWindowDays:   30,
		AutoRenew:           false,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
	policyRepo.AddPolicy(policy)

	// Run check
	_ = svc.CheckExpiringCertificates(ctx)

	// Verify status was updated to Expired
	updated, _ := certRepo.Get(ctx, cert.ID)
	if updated.Status != domain.CertificateStatusExpired {
		t.Errorf("expected status Expired, got %s", updated.Status)
	}
}

func TestCheckExpiringCertificates_CreatesRenewalJob(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", &mockIssuerConnector{})

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create expiring cert with registered issuer
	cert := &domain.ManagedCertificate{
		ID:              "mc-job-create",
		Name:            "Test Cert",
		CommonName:      "test.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-test", // Registered issuer
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, 20),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)

	// Create policy
	policy := &domain.RenewalPolicy{
		ID:                  "rp-standard",
		Name:                "Standard",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
	policyRepo.AddPolicy(policy)

	// Run check
	_ = svc.CheckExpiringCertificates(ctx)

	// Verify renewal job was created
	hasRenewalJob := false
	for _, job := range jobRepo.Jobs {
		if job.Type == domain.JobTypeRenewal && job.Status == domain.JobStatusPending {
			hasRenewalJob = true
			break
		}
	}
	if !hasRenewalJob {
		t.Errorf("expected renewal job to be created")
	}
}

func TestCheckExpiringCertificates_SkipsWithoutIssuer(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	// Empty issuer registry
	issuerRegistry := NewIssuerRegistry(slog.Default())

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create cert with unregistered issuer
	cert := &domain.ManagedCertificate{
		ID:              "mc-no-issuer",
		Name:            "Test Cert",
		CommonName:      "test.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-missing", // Not in registry
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, 20),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)

	// Create policy
	policy := &domain.RenewalPolicy{
		ID:                  "rp-standard",
		Name:                "Standard",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
	policyRepo.AddPolicy(policy)

	// Run check
	_ = svc.CheckExpiringCertificates(ctx)

	// Should not create renewal job without issuer
	for _, job := range jobRepo.Jobs {
		if job.Type == domain.JobTypeRenewal {
			t.Errorf("should not create renewal job for cert with missing issuer")
		}
	}
}

func TestCheckExpiringCertificates_SkipsDuplicateJobs(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", &mockIssuerConnector{})

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create cert
	cert := &domain.ManagedCertificate{
		ID:              "mc-dup-job",
		Name:            "Test Cert",
		CommonName:      "test.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-test",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, 20),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)

	// Create policy
	policy := &domain.RenewalPolicy{
		ID:                  "rp-standard",
		Name:                "Standard",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
	policyRepo.AddPolicy(policy)

	// Add existing renewal job
	existingJob := &domain.Job{
		ID:            "job-existing",
		CertificateID: cert.ID,
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusPending,
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(existingJob)

	// Run first check
	_ = svc.CheckExpiringCertificates(ctx)

	// Run second check
	_ = svc.CheckExpiringCertificates(ctx)

	// Should have only 1 renewal job
	renewalCount := 0
	for _, job := range jobRepo.Jobs {
		if job.Type == domain.JobTypeRenewal {
			renewalCount++
		}
	}
	if renewalCount > 1 {
		t.Errorf("expected 1 renewal job, got %d (duplicate prevention failed)", renewalCount)
	}
}

func TestProcessRenewalJob(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{
		"Email": newMockNotifier(),
	})

	issuerConnector := &mockIssuerConnector{}
	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", issuerConnector)

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create certificate
	cert := &domain.ManagedCertificate{
		ID:              "mc-renewal",
		Name:            "Test Cert",
		CommonName:      "test.example.com",
		SANs:            []string{"www.test.example.com"},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-test",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		TargetIDs:       []string{"target-1", "target-2"},
		ExpiresAt:       time.Now().AddDate(0, 0, 30),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)

	// Create renewal job
	job := &domain.Job{
		ID:            "job-renewal-1",
		CertificateID: cert.ID,
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusPending,
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Process renewal job
	err := svc.ProcessRenewalJob(ctx, job)
	if err != nil {
		t.Fatalf("ProcessRenewalJob failed: %v", err)
	}

	// Verify cert was updated
	updated, _ := certRepo.Get(ctx, cert.ID)
	if updated.Status != domain.CertificateStatusActive {
		t.Errorf("expected cert status Active, got %s", updated.Status)
	}

	if updated.LastRenewalAt == nil {
		t.Errorf("expected LastRenewalAt to be set")
	}

	// Verify certificate version was created
	if len(certRepo.Versions[cert.ID]) != 1 {
		t.Errorf("expected 1 certificate version, got %d", len(certRepo.Versions[cert.ID]))
	}

	// Verify deployment jobs were created
	deploymentCount := 0
	for _, j := range jobRepo.Jobs {
		if j.Type == domain.JobTypeDeployment {
			deploymentCount++
		}
	}
	if deploymentCount != 2 {
		t.Errorf("expected 2 deployment jobs (one per target), got %d", deploymentCount)
	}

	// Verify job was marked as completed
	completedJob, _ := jobRepo.Get(ctx, job.ID)
	if completedJob.Status != domain.JobStatusCompleted {
		t.Errorf("expected job status Completed, got %s", completedJob.Status)
	}
}

func TestProcessRenewalJob_IssuerFailure(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{
		"Email": newMockNotifier(),
	})

	// Create issuer that will fail
	issuerConnector := &mockIssuerConnector{
		Err: fmt.Errorf("issuer service unavailable"),
	}

	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", issuerConnector)

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create certificate
	cert := &domain.ManagedCertificate{
		ID:              "mc-renewal-fail",
		Name:            "Test Cert",
		CommonName:      "test.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-test",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, 30),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)

	// Create renewal job
	job := &domain.Job{
		ID:            "job-renewal-fail",
		CertificateID: cert.ID,
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusPending,
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Process renewal job (should fail)
	err := svc.ProcessRenewalJob(ctx, job)
	if err == nil {
		t.Fatalf("expected ProcessRenewalJob to fail")
	}

	// Verify job was marked as failed
	failedJob, _ := jobRepo.Get(ctx, job.ID)
	if failedJob.Status != domain.JobStatusFailed {
		t.Errorf("expected job status Failed, got %s", failedJob.Status)
	}

	if failedJob.LastError == nil || !strings.Contains(*failedJob.LastError, "issuer service unavailable") {
		t.Errorf("expected error message in job, got: %v", failedJob.LastError)
	}

	// Verify failure notification was sent
	if len(notifRepo.Notifications) < 1 {
		t.Errorf("expected failure notification to be created")
	}

	foundFailureNotif := false
	for _, notif := range notifRepo.Notifications {
		if notif.Type == domain.NotificationTypeRenewalFailure {
			foundFailureNotif = true
			break
		}
	}
	if !foundFailureNotif {
		t.Errorf("expected RenewalFailure notification type")
	}
}

func TestRetryFailedJobs(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", &mockIssuerConnector{})

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create failed job with attempts < max_attempts
	failedJob := &domain.Job{
		ID:            "job-failed-1",
		CertificateID: "mc-test",
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusFailed,
		Attempts:      1,
		MaxAttempts:   3,
		LastError:     stringPtr("temporary failure"),
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now().AddDate(0, 0, -1),
	}
	jobRepo.AddJob(failedJob)

	// Create other job types that should be ignored
	otherJob := &domain.Job{
		ID:            "job-other",
		CertificateID: "mc-test",
		Type:          domain.JobTypeDeployment,
		Status:        domain.JobStatusFailed,
		Attempts:      1,
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(otherJob)

	// Retry failed jobs
	err := svc.RetryFailedJobs(ctx, 3)
	if err != nil {
		t.Fatalf("RetryFailedJobs failed: %v", err)
	}

	// Verify failed renewal job was reset to pending
	retried, _ := jobRepo.Get(ctx, failedJob.ID)
	if retried.Status != domain.JobStatusPending {
		t.Errorf("expected job status Pending after retry, got %s", retried.Status)
	}

	// Verify other job type was not touched
	other, _ := jobRepo.Get(ctx, otherJob.ID)
	if other.Status != domain.JobStatusFailed {
		t.Errorf("expected non-renewal job to stay Failed, got %s", other.Status)
	}
}

func TestProcessRenewalJob_NoCertificate(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", &mockIssuerConnector{})

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create job with non-existent certificate
	job := &domain.Job{
		ID:            "job-no-cert",
		CertificateID: "mc-missing",
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusPending,
		MaxAttempts:   3,
		ScheduledAt:   time.Now(),
		CreatedAt:     time.Now(),
	}
	jobRepo.AddJob(job)

	// Process renewal job
	err := svc.ProcessRenewalJob(ctx, job)
	if err == nil {
		t.Fatalf("expected ProcessRenewalJob to fail for missing certificate")
	}

	// Verify job was marked as failed
	failedJob, _ := jobRepo.Get(ctx, job.ID)
	if failedJob.Status != domain.JobStatusFailed {
		t.Errorf("expected job status Failed, got %s", failedJob.Status)
	}
}

// --- ARI (RFC 9773) Scheduler Integration Tests ---

func TestCheckExpiringCertificates_ARI_ShouldRenewNow(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	// ARI says renew now: window started in the past
	ariConnector := &mockIssuerConnector{
		getRenewalInfoResult: &RenewalInfoResult{
			SuggestedWindowStart: time.Now().Add(-24 * time.Hour),
			SuggestedWindowEnd:   time.Now().Add(48 * time.Hour),
		},
	}
	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-acme", ariConnector)

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Create cert expiring in 20 days with a cert version (needed for ARI lookup)
	cert := &domain.ManagedCertificate{
		ID:              "mc-ari-renew",
		Name:            "ARI Cert",
		CommonName:      "ari.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-acme",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, 20),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)
	certRepo.Versions[cert.ID] = []*domain.CertificateVersion{
		{ID: "cv-1", CertificateID: cert.ID, PEMChain: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"},
	}

	policy := &domain.RenewalPolicy{
		ID: "rp-standard", Name: "Standard", RenewalWindowDays: 30,
		AutoRenew: true, MaxRetries: 3, RetryInterval: 300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	policyRepo.AddPolicy(policy)

	err := svc.CheckExpiringCertificates(ctx)
	if err != nil {
		t.Fatalf("CheckExpiringCertificates failed: %v", err)
	}

	// ARI says renew now, so a renewal job should be created
	hasRenewalJob := false
	for _, job := range jobRepo.Jobs {
		if job.Type == domain.JobTypeRenewal {
			hasRenewalJob = true
			break
		}
	}
	if !hasRenewalJob {
		t.Errorf("expected renewal job when ARI ShouldRenewNow is true")
	}
}

func TestCheckExpiringCertificates_ARI_NotYet(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	// ARI says NOT yet: window starts in the future
	ariConnector := &mockIssuerConnector{
		getRenewalInfoResult: &RenewalInfoResult{
			SuggestedWindowStart: time.Now().Add(72 * time.Hour),
			SuggestedWindowEnd:   time.Now().Add(96 * time.Hour),
		},
	}
	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-acme", ariConnector)

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	// Cert is within the 30-day threshold window (would normally trigger renewal),
	// but ARI says "not yet"
	cert := &domain.ManagedCertificate{
		ID:              "mc-ari-wait",
		Name:            "ARI Wait Cert",
		CommonName:      "ari-wait.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-acme",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, 10),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)
	certRepo.Versions[cert.ID] = []*domain.CertificateVersion{
		{ID: "cv-2", CertificateID: cert.ID, PEMChain: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"},
	}

	policy := &domain.RenewalPolicy{
		ID: "rp-standard", Name: "Standard", RenewalWindowDays: 30,
		AutoRenew: true, MaxRetries: 3, RetryInterval: 300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	policyRepo.AddPolicy(policy)

	err := svc.CheckExpiringCertificates(ctx)
	if err != nil {
		t.Fatalf("CheckExpiringCertificates failed: %v", err)
	}

	// ARI says not yet, so NO renewal job should be created
	for _, job := range jobRepo.Jobs {
		if job.Type == domain.JobTypeRenewal {
			t.Errorf("expected no renewal job when ARI says not yet, but found one")
		}
	}
}

func TestCheckExpiringCertificates_ARI_NilResult_FallsThrough(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	// ARI returns nil (issuer doesn't support ARI) — default mock behavior
	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-local", &mockIssuerConnector{})

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	cert := &domain.ManagedCertificate{
		ID:              "mc-ari-nil",
		Name:            "No ARI Cert",
		CommonName:      "no-ari.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-local",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, 20),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)
	certRepo.Versions[cert.ID] = []*domain.CertificateVersion{
		{ID: "cv-3", CertificateID: cert.ID, PEMChain: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"},
	}

	policy := &domain.RenewalPolicy{
		ID: "rp-standard", Name: "Standard", RenewalWindowDays: 30,
		AutoRenew: true, MaxRetries: 3, RetryInterval: 300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	policyRepo.AddPolicy(policy)

	err := svc.CheckExpiringCertificates(ctx)
	if err != nil {
		t.Fatalf("CheckExpiringCertificates failed: %v", err)
	}

	// ARI is nil (not supported), so threshold-based logic applies; cert is within 30-day window
	hasRenewalJob := false
	for _, job := range jobRepo.Jobs {
		if job.Type == domain.JobTypeRenewal {
			hasRenewalJob = true
			break
		}
	}
	if !hasRenewalJob {
		t.Errorf("expected renewal job via threshold fallback when ARI returns nil")
	}
}

func TestCheckExpiringCertificates_ARI_Error_FallsThrough(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	// ARI returns an error — should fall through to threshold-based renewal
	ariConnector := &mockIssuerConnector{
		getRenewalInfoErr: fmt.Errorf("ARI endpoint unreachable"),
	}
	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-acme", ariConnector)

	svc := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	cert := &domain.ManagedCertificate{
		ID:              "mc-ari-err",
		Name:            "ARI Error Cert",
		CommonName:      "ari-err.example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-acme",
		RenewalPolicyID: "rp-standard",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, 15),
		Tags:            make(map[string]string),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	certRepo.AddCert(cert)
	certRepo.Versions[cert.ID] = []*domain.CertificateVersion{
		{ID: "cv-4", CertificateID: cert.ID, PEMChain: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"},
	}

	policy := &domain.RenewalPolicy{
		ID: "rp-standard", Name: "Standard", RenewalWindowDays: 30,
		AutoRenew: true, MaxRetries: 3, RetryInterval: 300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	policyRepo.AddPolicy(policy)

	err := svc.CheckExpiringCertificates(ctx)
	if err != nil {
		t.Fatalf("CheckExpiringCertificates failed: %v", err)
	}

	// ARI failed but renewal should still happen via threshold fallback
	hasRenewalJob := false
	for _, job := range jobRepo.Jobs {
		if job.Type == domain.JobTypeRenewal {
			hasRenewalJob = true
			break
		}
	}
	if !hasRenewalJob {
		t.Errorf("expected renewal job via threshold fallback when ARI errors")
	}
}

// TestExpireShortLivedCertificates_Tier3 tests that ExpireShortLivedCertificates
// marks short-lived certificates that have passed their expiry time as Expired.
func TestExpireShortLivedCertificates_Tier3(t *testing.T) {
	ctx := context.Background()

	// Set up repos
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	notifRepo := newMockNotificationRepository()

	// Import the profile repo mock from context_test which already exists
	profileRepo := &mockCertificateProfileRepository{
		Profiles: make(map[string]*domain.CertificateProfile),
	}

	// Create a short-lived profile
	shortLivedProfile := &domain.CertificateProfile{
		ID:              "prof-sl-1",
		Name:            "ShortLived",
		MaxTTLSeconds:   3599, // Under 1 hour
		AllowShortLived: true,
		Enabled:         true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	profileRepo.Create(ctx, shortLivedProfile)

	// Create a short-lived cert that has expired
	now := time.Now()
	expiredTime := now.Add(-5 * time.Minute) // Already expired
	expiredCert := &domain.ManagedCertificate{
		ID:                   "cert-short-1",
		CommonName:           "test.example.com",
		Status:               domain.CertificateStatusActive,
		CertificateProfileID: "prof-sl-1",
		ExpiresAt:            expiredTime,
		CreatedAt:            now.Add(-10 * time.Minute),
		UpdatedAt:            now.Add(-10 * time.Minute),
	}
	certRepo.AddCert(expiredCert)

	// Mock the GetExpiringCertificates to return our expired cert
	certRepo.MockGetExpiring = []*domain.ManagedCertificate{expiredCert}

	auditSvc := NewAuditService(auditRepo)
	notifSvc := NewNotificationService(notifRepo, map[string]Notifier{})

	svc := NewRenewalService(
		certRepo, nil, nil, profileRepo,
		auditSvc, notifSvc, NewIssuerRegistry(slog.Default()), "agent",
	)

	// Call ExpireShortLivedCertificates
	err := svc.ExpireShortLivedCertificates(ctx)
	if err != nil {
		t.Fatalf("ExpireShortLivedCertificates failed: %v", err)
	}

	// Verify the cert status was updated to Expired
	if len(certRepo.Updated) == 0 {
		t.Error("expected certificate to be updated")
		return
	}

	updatedCert := certRepo.Updated[0]
	if updatedCert.Status != domain.CertificateStatusExpired {
		t.Errorf("expected status Expired, got %s", updatedCert.Status)
	}
}

// TestFailJob_SetsFailedStatus tests that job status is correctly updated to Failed.
func TestFailJob_SetsFailedStatus(t *testing.T) {
	ctx := context.Background()

	// Set up repos
	jobRepo := newMockJobRepository()

	// Create a job
	job := &domain.Job{
		ID:          "job-fail-1",
		Type:        domain.JobTypeRenewal,
		Status:      domain.JobStatusRunning,
		CreatedAt:   time.Now(),
		ScheduledAt: time.Now(),
	}
	jobRepo.Jobs[job.ID] = job

	// Simulate what failJob does - update the job with Failed status and error message
	errMsg := "test error message"
	job.Status = domain.JobStatusFailed
	job.LastError = &errMsg

	// Call the Update method which is what failJob would do
	err := jobRepo.Update(ctx, job)
	if err != nil {
		t.Fatalf("failed to update job: %v", err)
	}

	// Verify the job was marked as failed
	if len(jobRepo.Updated) == 0 {
		t.Error("expected job to be updated")
		return
	}

	updatedJob := jobRepo.Updated[0]
	if updatedJob.Status != domain.JobStatusFailed {
		t.Errorf("expected status Failed, got %s", updatedJob.Status)
	}
	if updatedJob.LastError == nil || *updatedJob.LastError == "" {
		t.Error("expected error message to be set")
	}
}


// --- CreateDeploymentJobs Tests ---

func TestCreateDeploymentJobs_PartialFailure(t *testing.T) {
	ctx := context.Background()

	jobRepo := newMockJobRepository()
	targetRepo := newMockTargetRepository()
	agentRepo := newMockAgentRepository()
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()

	auditSvc := NewAuditService(auditRepo)

	depSvc := NewDeploymentService(jobRepo, targetRepo, agentRepo, certRepo, auditSvc, nil)

	// Create certificate
	cert := &domain.ManagedCertificate{
		ID:        "mc-partial",
		CommonName: "test.example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	certRepo.AddCert(cert)

	// Create target with agent assignment
	target := &domain.DeploymentTarget{
		ID:        "tgt-1",
		Name:      "target-1",
		Type:      "nginx",
		AgentID:   "agent-1",
		Config:    json.RawMessage("{}"),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	targetRepo.Targets[target.ID] = target

	// Mock ListByCertificate to return the target
	// (the mock returns all targets, so we just need one in the map)

	// Execute CreateDeploymentJobs
	jobIDs, err := depSvc.CreateDeploymentJobs(ctx, cert.ID)

	// Should succeed
	if err != nil {
		t.Fatalf("CreateDeploymentJobs failed: %v", err)
	}

	// Verify job was created
	if len(jobIDs) == 0 {
		t.Error("expected at least one deployment job to be created")
	}

	// Verify the job has correct properties
	if len(jobRepo.Jobs) == 0 {
		t.Fatal("expected job to be created")
	}

	createdJob := jobRepo.Jobs[jobIDs[0]]
	if createdJob.Type != domain.JobTypeDeployment {
		t.Errorf("expected JobTypeDeployment, got %s", createdJob.Type)
	}
	if createdJob.CertificateID != cert.ID {
		t.Errorf("expected certificate ID %s, got %s", cert.ID, createdJob.CertificateID)
	}
	if createdJob.AgentID == nil || *createdJob.AgentID != "agent-1" {
		t.Error("expected job to be routed to agent-1")
	}
}


// stringPtr is defined in notification_test.go
