package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// setupShortLivedTestService creates a RenewalService with mock dependencies for short-lived cert tests
func setupShortLivedTestService(
	certRepo *mockCertRepo,
	profileRepo *mockProfileRepo,
	auditRepo *mockAuditRepo,
) *RenewalService {
	auditSvc := NewAuditService(auditRepo)

	issuerRegistry := map[string]IssuerConnector{
		"iss-test": &mockIssuerConnector{},
	}

	svc := NewRenewalService(
		certRepo,
		newMockJobRepository(),
		newMockRenewalPolicyRepository(),
		profileRepo,
		auditSvc,
		NewNotificationService(newMockNotificationRepository(), map[string]Notifier{}),
		issuerRegistry,
		"agent",
	)

	return svc
}

// TestExpireShortLivedCertificates_Success verifies that active certificates with
// expired short-lived profiles are transitioned to Expired status
func TestExpireShortLivedCertificates_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	certRepo := newMockCertificateRepository()
	profileRepo := newMockProfileRepository()
	auditRepo := newMockAuditRepository()

	// Create a short-lived profile (TTL < 1 hour = 3600 seconds)
	shortLivedProfile := &domain.CertificateProfile{
		ID:                  "prof-short",
		Name:                "Short-Lived",
		MaxTTLSeconds:       300, // 5 minutes
		AllowShortLived:     true,
		Enabled:             true,
		AllowedKeyAlgorithms: domain.DefaultKeyAlgorithms(),
		AllowedEKUs:         domain.DefaultEKUs(),
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	profileRepo.AddProfile(shortLivedProfile)

	// Create an active certificate that has already expired
	expiredCert := &domain.ManagedCertificate{
		ID:                    "mc-expired-short",
		Name:                  "Expired Short-Lived Cert",
		CommonName:            "short.example.com",
		SANs:                  []string{},
		IssuerID:              "iss-test",
		CertificateProfileID:  "prof-short",
		Status:                domain.CertificateStatusActive,
		ExpiresAt:             now.Add(-5 * time.Minute), // Already expired
		CreatedAt:             now.Add(-15 * time.Minute),
		UpdatedAt:             now.Add(-5 * time.Minute),
		Tags:                  make(map[string]string),
	}
	certRepo.AddCert(expiredCert)

	svc := setupShortLivedTestService(certRepo, profileRepo, auditRepo)

	// Run the expiry check
	err := svc.ExpireShortLivedCertificates(ctx)
	if err != nil {
		t.Fatalf("ExpireShortLivedCertificates failed: %v", err)
	}

	// Verify the cert status was updated to Expired
	updated, err := certRepo.Get(ctx, "mc-expired-short")
	if err != nil {
		t.Fatalf("failed to get updated cert: %v", err)
	}
	if updated.Status != domain.CertificateStatusExpired {
		t.Errorf("expected cert status to be Expired, got %s", updated.Status)
	}

	// Verify an audit event was recorded
	if len(auditRepo.Events) == 0 {
		t.Errorf("expected audit event to be recorded, got none")
	}
}

// TestExpireShortLivedCertificates_NoCertsToExpire verifies the function handles
// empty certificate lists gracefully
func TestExpireShortLivedCertificates_NoCertsToExpire(t *testing.T) {
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	profileRepo := newMockProfileRepository()
	auditRepo := newMockAuditRepository()

	svc := setupShortLivedTestService(certRepo, profileRepo, auditRepo)

	// Run the expiry check on empty certificate list
	err := svc.ExpireShortLivedCertificates(ctx)
	if err != nil {
		t.Fatalf("ExpireShortLivedCertificates failed: %v", err)
	}

	// Verify no audit events were recorded
	if len(auditRepo.Events) != 0 {
		t.Errorf("expected no audit events, got %d", len(auditRepo.Events))
	}
}

// TestExpireShortLivedCertificates_ListError verifies that repository errors
// are properly propagated
func TestExpireShortLivedCertificates_ListError(t *testing.T) {
	ctx := context.Background()

	// Create a custom mock that returns an error from GetExpiringCertificates
	customCertRepo := &mockCertRepoWithGetError{
		GetExpiringCertificatesErr: errors.New("database connection failed"),
	}

	profileRepo := newMockProfileRepository()
	auditRepo := newMockAuditRepository()

	// Create the service manually to use our custom cert repo
	auditSvc := NewAuditService(auditRepo)
	issuerRegistry := map[string]IssuerConnector{
		"iss-test": &mockIssuerConnector{},
	}

	svc := NewRenewalService(
		customCertRepo,
		newMockJobRepository(),
		newMockRenewalPolicyRepository(),
		profileRepo,
		auditSvc,
		NewNotificationService(newMockNotificationRepository(), map[string]Notifier{}),
		issuerRegistry,
		"agent",
	)

	// Run the expiry check, expecting an error
	err := svc.ExpireShortLivedCertificates(ctx)
	if err == nil {
		t.Fatalf("expected ExpireShortLivedCertificates to return an error, got nil")
	}
	if !errors.Is(err, customCertRepo.GetExpiringCertificatesErr) {
		t.Errorf("expected error containing 'database connection failed', got %v", err)
	}
}

// mockCertRepoWithGetError is a minimal custom mock for testing GetExpiringCertificates error handling
type mockCertRepoWithGetError struct {
	GetExpiringCertificatesErr error
}

func (m *mockCertRepoWithGetError) List(ctx context.Context, filter *repository.CertificateFilter) ([]*domain.ManagedCertificate, int, error) {
	return nil, 0, nil
}

func (m *mockCertRepoWithGetError) Get(ctx context.Context, id string) (*domain.ManagedCertificate, error) {
	return nil, nil
}

func (m *mockCertRepoWithGetError) Create(ctx context.Context, cert *domain.ManagedCertificate) error {
	return nil
}

func (m *mockCertRepoWithGetError) Update(ctx context.Context, cert *domain.ManagedCertificate) error {
	return nil
}

func (m *mockCertRepoWithGetError) Archive(ctx context.Context, id string) error {
	return nil
}

func (m *mockCertRepoWithGetError) ListVersions(ctx context.Context, certID string) ([]*domain.CertificateVersion, error) {
	return nil, nil
}

func (m *mockCertRepoWithGetError) CreateVersion(ctx context.Context, version *domain.CertificateVersion) error {
	return nil
}

func (m *mockCertRepoWithGetError) GetLatestVersion(ctx context.Context, certID string) (*domain.CertificateVersion, error) {
	return nil, nil
}

func (m *mockCertRepoWithGetError) GetExpiringCertificates(ctx context.Context, before time.Time) ([]*domain.ManagedCertificate, error) {
	return nil, m.GetExpiringCertificatesErr
}

// TestExpireShortLivedCertificates_PartialUpdateError verifies that update errors
// on individual certs are logged but don't fail the entire operation
func TestExpireShortLivedCertificates_PartialUpdateError(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	certRepo := newMockCertificateRepository()
	profileRepo := newMockProfileRepository()
	auditRepo := newMockAuditRepository()

	// Create a short-lived profile
	shortLivedProfile := &domain.CertificateProfile{
		ID:                  "prof-short",
		Name:                "Short-Lived",
		MaxTTLSeconds:       300,
		AllowShortLived:     true,
		Enabled:             true,
		AllowedKeyAlgorithms: domain.DefaultKeyAlgorithms(),
		AllowedEKUs:         domain.DefaultEKUs(),
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	profileRepo.AddProfile(shortLivedProfile)

	// Create a certificate with a failing update
	expiredCert := &domain.ManagedCertificate{
		ID:                    "mc-expired-fail",
		Name:                  "Expired Cert That Will Fail",
		CommonName:            "fail.example.com",
		SANs:                  []string{},
		IssuerID:              "iss-test",
		CertificateProfileID:  "prof-short",
		Status:                domain.CertificateStatusActive,
		ExpiresAt:             now.Add(-5 * time.Minute),
		CreatedAt:             now.Add(-15 * time.Minute),
		UpdatedAt:             now.Add(-5 * time.Minute),
		Tags:                  make(map[string]string),
	}
	certRepo.AddCert(expiredCert)

	// Set up the repo to fail on update
	certRepo.UpdateErr = errors.New("update failed")

	svc := setupShortLivedTestService(certRepo, profileRepo, auditRepo)

	// Run the expiry check - should not return an error even though update failed
	err := svc.ExpireShortLivedCertificates(ctx)
	if err != nil {
		t.Fatalf("ExpireShortLivedCertificates should not fail on partial update errors, got %v", err)
	}

	// Verify no audit events were recorded (update failure skips audit recording)
	if len(auditRepo.Events) != 0 {
		t.Errorf("expected no audit events on update failure, got %d", len(auditRepo.Events))
	}
}

// TestExpireShortLivedCertificates_AlreadyExpired verifies that certificates
// already in Expired status are not re-processed
func TestExpireShortLivedCertificates_AlreadyExpired(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	certRepo := newMockCertificateRepository()
	profileRepo := newMockProfileRepository()
	auditRepo := newMockAuditRepository()

	// Create a short-lived profile
	shortLivedProfile := &domain.CertificateProfile{
		ID:                  "prof-short",
		Name:                "Short-Lived",
		MaxTTLSeconds:       300,
		AllowShortLived:     true,
		Enabled:             true,
		AllowedKeyAlgorithms: domain.DefaultKeyAlgorithms(),
		AllowedEKUs:         domain.DefaultEKUs(),
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	profileRepo.AddProfile(shortLivedProfile)

	// Create a certificate that's already in Expired status
	alreadyExpiredCert := &domain.ManagedCertificate{
		ID:                    "mc-already-expired",
		Name:                  "Already Expired Cert",
		CommonName:            "already-expired.example.com",
		SANs:                  []string{},
		IssuerID:              "iss-test",
		CertificateProfileID:  "prof-short",
		Status:                domain.CertificateStatusExpired, // Already expired
		ExpiresAt:             now.Add(-30 * time.Minute),
		CreatedAt:             now.Add(-45 * time.Minute),
		UpdatedAt:             now.Add(-10 * time.Minute),
		Tags:                  make(map[string]string),
	}
	certRepo.AddCert(alreadyExpiredCert)

	svc := setupShortLivedTestService(certRepo, profileRepo, auditRepo)

	// Run the expiry check
	err := svc.ExpireShortLivedCertificates(ctx)
	if err != nil {
		t.Fatalf("ExpireShortLivedCertificates failed: %v", err)
	}

	// Verify no new audit events were recorded (cert was skipped)
	if len(auditRepo.Events) != 0 {
		t.Errorf("expected no audit events for already-expired cert, got %d", len(auditRepo.Events))
	}
}

// TestExpireShortLivedCertificates_ProfileNotShortLived verifies that certificates
// with non-short-lived profiles are not expired by this function
func TestExpireShortLivedCertificates_ProfileNotShortLived(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	certRepo := newMockCertificateRepository()
	profileRepo := newMockProfileRepository()
	auditRepo := newMockAuditRepository()

	// Create a regular (not short-lived) profile with TTL > 1 hour
	regularProfile := &domain.CertificateProfile{
		ID:                  "prof-regular",
		Name:                "Regular",
		MaxTTLSeconds:       86400, // 24 hours
		AllowShortLived:     false,
		Enabled:             true,
		AllowedKeyAlgorithms: domain.DefaultKeyAlgorithms(),
		AllowedEKUs:         domain.DefaultEKUs(),
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	profileRepo.AddProfile(regularProfile)

	// Create an expired certificate with the regular profile
	expiredCert := &domain.ManagedCertificate{
		ID:                    "mc-expired-regular",
		Name:                  "Expired Regular Cert",
		CommonName:            "regular.example.com",
		SANs:                  []string{},
		IssuerID:              "iss-test",
		CertificateProfileID:  "prof-regular",
		Status:                domain.CertificateStatusActive,
		ExpiresAt:             now.Add(-1 * time.Hour),
		CreatedAt:             now.Add(-25 * time.Hour),
		UpdatedAt:             now.Add(-1 * time.Hour),
		Tags:                  make(map[string]string),
	}
	certRepo.AddCert(expiredCert)

	svc := setupShortLivedTestService(certRepo, profileRepo, auditRepo)

	// Run the expiry check
	err := svc.ExpireShortLivedCertificates(ctx)
	if err != nil {
		t.Fatalf("ExpireShortLivedCertificates failed: %v", err)
	}

	// Verify the cert status was NOT changed (because profile is not short-lived)
	cert, _ := certRepo.Get(ctx, "mc-expired-regular")
	if cert.Status != domain.CertificateStatusActive {
		t.Errorf("cert should not have been expired (profile not short-lived), got status %s", cert.Status)
	}

	// Verify no audit events were recorded
	if len(auditRepo.Events) != 0 {
		t.Errorf("expected no audit events for non-short-lived profile, got %d", len(auditRepo.Events))
	}
}

// TestExpireShortLivedCertificates_NoProfileRepository verifies the function
// handles nil profileRepo gracefully
func TestExpireShortLivedCertificates_NoProfileRepository(t *testing.T) {
	ctx := context.Background()

	certRepo := newMockCertificateRepository()
	auditRepo := &mockAuditRepo{
		Events: make([]*domain.AuditEvent, 0),
	}

	auditSvc := NewAuditService(auditRepo)
	issuerRegistry := map[string]IssuerConnector{
		"iss-test": &mockIssuerConnector{},
	}

	svc := NewRenewalService(
		certRepo,
		newMockJobRepository(),
		newMockRenewalPolicyRepository(),
		nil, // nil profileRepo
		auditSvc,
		NewNotificationService(newMockNotificationRepository(), map[string]Notifier{}),
		issuerRegistry,
		"agent",
	)

	// Run the expiry check with nil profileRepo
	err := svc.ExpireShortLivedCertificates(ctx)
	if err != nil {
		t.Fatalf("ExpireShortLivedCertificates should handle nil profileRepo gracefully, got error: %v", err)
	}
}
