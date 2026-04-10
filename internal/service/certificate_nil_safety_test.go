package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// TestCertificateService_RevokeCertificate_RevocationSvcNil tests RevokeCertificateWithActor
// when RevocationSvc is not configured (nil).
func TestCertificateService_RevokeCertificate_RevocationSvcNil(t *testing.T) {
	// Setup: Create CertificateService WITHOUT calling SetRevocationSvc
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	policyRepo := newMockPolicyRepository()

	auditService := NewAuditService(auditRepo)
	policyService := NewPolicyService(policyRepo, auditService)

	// Create service WITHOUT RevocationSvc
	certService := NewCertificateService(certRepo, policyService, auditService)
	// Note: NOT calling certService.SetRevocationSvc(...)

	// Add a test certificate
	cert := &domain.ManagedCertificate{
		ID:         "cert-1",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
	}
	certRepo.AddCert(cert)

	// Call RevokeCertificateWithActor with nil RevocationSvc
	err := certService.RevokeCertificateWithActor(context.Background(), "cert-1", "keyCompromise", "admin")

	// Assert: Should return error, NOT panic
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify error message indicates service not configured
	errMsg := err.Error()
	if errMsg != "revocation service not configured" {
		t.Errorf("expected error message 'revocation service not configured', got: %s", errMsg)
	}
}

// TestCertificateService_GenerateDERCRL_CAOpsSvcNil tests GenerateDERCRL
// when CAOperationsSvc is not configured (nil).
func TestCertificateService_GenerateDERCRL_CAOpsSvcNil(t *testing.T) {
	// Setup: Create CertificateService WITHOUT calling SetCAOperationsSvc
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	policyRepo := newMockPolicyRepository()

	auditService := NewAuditService(auditRepo)
	policyService := NewPolicyService(policyRepo, auditService)

	// Create service WITHOUT CAOperationsSvc
	certService := NewCertificateService(certRepo, policyService, auditService)
	// Note: NOT calling certService.SetCAOperationsSvc(...)

	// Call GenerateDERCRL with nil CAOperationsSvc
	_, err := certService.GenerateDERCRL("iss-local")

	// Assert: Should return error, NOT panic
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify error message indicates service not configured
	errMsg := err.Error()
	if errMsg != "CA operations service not configured" {
		t.Errorf("expected error message 'CA operations service not configured', got: %s", errMsg)
	}
}

// TestCertificateService_GetOCSPResponse_CAOpsSvcNil tests GetOCSPResponse
// when CAOperationsSvc is not configured (nil).
func TestCertificateService_GetOCSPResponse_CAOpsSvcNil(t *testing.T) {
	// Setup: Create CertificateService WITHOUT calling SetCAOperationsSvc
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	policyRepo := newMockPolicyRepository()

	auditService := NewAuditService(auditRepo)
	policyService := NewPolicyService(policyRepo, auditService)

	// Create service WITHOUT CAOperationsSvc
	certService := NewCertificateService(certRepo, policyService, auditService)
	// Note: NOT calling certService.SetCAOperationsSvc(...)

	// Call GetOCSPResponse with nil CAOperationsSvc
	_, err := certService.GetOCSPResponse("iss-local", "serial123")

	// Assert: Should return error, NOT panic
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify error message indicates service not configured
	errMsg := err.Error()
	if errMsg != "CA operations service not configured" {
		t.Errorf("expected error message 'CA operations service not configured', got: %s", errMsg)
	}
}

// TestCertificateService_GetRevokedCertificates_RevocationSvcNil tests GetRevokedCertificates
// when RevocationSvc is not configured (nil).
func TestCertificateService_GetRevokedCertificates_RevocationSvcNil(t *testing.T) {
	// Setup: Create CertificateService WITHOUT calling SetRevocationSvc
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	policyRepo := newMockPolicyRepository()

	auditService := NewAuditService(auditRepo)
	policyService := NewPolicyService(policyRepo, auditService)

	// Create service WITHOUT RevocationSvc
	certService := NewCertificateService(certRepo, policyService, auditService)
	// Note: NOT calling certService.SetRevocationSvc(...)

	// Call GetRevokedCertificates with nil RevocationSvc
	_, err := certService.GetRevokedCertificates()

	// Assert: Should return error, NOT panic
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify error message indicates service not configured
	errMsg := err.Error()
	if errMsg != "revocation service not configured" {
		t.Errorf("expected error message 'revocation service not configured', got: %s", errMsg)
	}
}

// TestCertificateService_GetCertificateDeployments_Success tests GetCertificateDeployments
// when TargetRepo is properly configured.
func TestCertificateService_GetCertificateDeployments_Success(t *testing.T) {
	// Setup: Create CertificateService with properly configured TargetRepo
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	policyRepo := newMockPolicyRepository()
	targetRepo := &mockTargetRepo{Targets: make(map[string]*domain.DeploymentTarget)}

	auditService := NewAuditService(auditRepo)
	policyService := NewPolicyService(policyRepo, auditService)

	certService := NewCertificateService(certRepo, policyService, auditService)
	certService.SetTargetRepo(targetRepo)

	// Add a test certificate
	cert := &domain.ManagedCertificate{
		ID:         "cert-1",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
	}
	certRepo.AddCert(cert)

	// Add deployment targets
	target1 := &domain.DeploymentTarget{
		ID:   "t-1",
		Name: "nginx-prod",
		Type: domain.TargetTypeNGINX,
	}
	target2 := &domain.DeploymentTarget{
		ID:   "t-2",
		Name: "apache-prod",
		Type: domain.TargetTypeApache,
	}
	targetRepo.AddTarget(target1)
	targetRepo.AddTarget(target2)

	// Call GetCertificateDeployments
	deployments, err := certService.GetCertificateDeployments("cert-1")

	// Assert: Should return deployment list successfully
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify deployments are returned (note: mock ListByCertificate returns all targets)
	if len(deployments) == 0 {
		t.Error("expected deployment list to be non-empty")
	}
}

// TestCertificateService_GetCertificateDeployments_RepositoryError tests GetCertificateDeployments
// when TargetRepo returns an error.
func TestCertificateService_GetCertificateDeployments_RepositoryError(t *testing.T) {
	// Setup: Create CertificateService with TargetRepo configured to return error
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	policyRepo := newMockPolicyRepository()
	targetRepo := &mockTargetRepo{
		Targets:       make(map[string]*domain.DeploymentTarget),
		ListByCertErr: errNotFound,
	}

	auditService := NewAuditService(auditRepo)
	policyService := NewPolicyService(policyRepo, auditService)

	certService := NewCertificateService(certRepo, policyService, auditService)
	certService.SetTargetRepo(targetRepo)

	// Add a test certificate
	cert := &domain.ManagedCertificate{
		ID:         "cert-1",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
	}
	certRepo.AddCert(cert)

	// Call GetCertificateDeployments with repo error
	_, err := certService.GetCertificateDeployments("cert-1")

	// Assert: Should return error, NOT panic
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify error indicates repo failure
	if err.Error() != "failed to list deployment targets: not found" {
		t.Errorf("expected repo error message, got: %s", err.Error())
	}
}

// TestCertificateService_GetCertificateDeployments_CertNotFound tests GetCertificateDeployments
// when the certificate doesn't exist.
func TestCertificateService_GetCertificateDeployments_CertNotFound(t *testing.T) {
	// Setup: Create CertificateService with empty cert repo
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	policyRepo := newMockPolicyRepository()
	targetRepo := &mockTargetRepo{Targets: make(map[string]*domain.DeploymentTarget)}

	auditService := NewAuditService(auditRepo)
	policyService := NewPolicyService(policyRepo, auditService)

	certService := NewCertificateService(certRepo, policyService, auditService)
	certService.SetTargetRepo(targetRepo)

	// Call GetCertificateDeployments with nonexistent certificate
	_, err := certService.GetCertificateDeployments("nonexistent-cert")

	// Assert: Should return error
	if err == nil {
		t.Fatal("expected error for nonexistent certificate, got nil")
	}

	if err.Error() != "certificate not found: not found" {
		t.Errorf("expected certificate not found error, got: %s", err.Error())
	}
}

// TestCertificateService_GetCertificateDeployments_NilTargetRepo tests GetCertificateDeployments
// when TargetRepo is nil (empty graceful handling).
func TestCertificateService_GetCertificateDeployments_NilTargetRepo(t *testing.T) {
	// Setup: Create CertificateService WITHOUT TargetRepo
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	policyRepo := newMockPolicyRepository()

	auditService := NewAuditService(auditRepo)
	policyService := NewPolicyService(policyRepo, auditService)

	certService := NewCertificateService(certRepo, policyService, auditService)
	// Note: NOT calling certService.SetTargetRepo(...)

	// Add a test certificate
	cert := &domain.ManagedCertificate{
		ID:         "cert-1",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
	}
	certRepo.AddCert(cert)

	// Call GetCertificateDeployments with nil TargetRepo
	deployments, err := certService.GetCertificateDeployments("cert-1")

	// Assert: Should return empty list gracefully (not panic)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(deployments) != 0 {
		t.Errorf("expected empty deployment list, got %d deployments", len(deployments))
	}
}

// TestCertificateService_Multiple_NilSafetyChecks tests multiple nil-safety operations in sequence.
func TestCertificateService_Multiple_NilSafetyChecks(t *testing.T) {
	// Setup: Create CertificateService with partial configuration
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()
	policyRepo := newMockPolicyRepository()

	auditService := NewAuditService(auditRepo)
	policyService := NewPolicyService(policyRepo, auditService)

	certService := NewCertificateService(certRepo, policyService, auditService)
	// Only set RevocationSvc, leave CAOperationsSvc nil
	revSvc := NewRevocationSvc(certRepo, newMockRevocationRepository(), auditService)
	certService.SetRevocationSvc(revSvc)

	// Add a test certificate
	cert := &domain.ManagedCertificate{
		ID:         "cert-1",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(0, 6, 0),
	}
	certRepo.AddCert(cert)

	// Add a certificate version
	version := &domain.CertificateVersion{
		ID:            "ver-1",
		CertificateID: "cert-1",
		SerialNumber:  "ABC123",
		NotBefore:     time.Now(),
		NotAfter:      time.Now().AddDate(1, 0, 0),
		CreatedAt:     time.Now(),
	}
	certRepo.Versions["cert-1"] = []*domain.CertificateVersion{version}

	// Set up issuer registry for revocation
	registry := NewIssuerRegistry(slog.Default())
	registry.Set("iss-local", &mockIssuerConnector{})
	revSvc.SetIssuerRegistry(registry)

	// Test 1: RevokeCertificateWithActor should succeed (RevocationSvc is set)
	errRevoke := certService.RevokeCertificateWithActor(context.Background(), "cert-1", "keyCompromise", "admin")
	if errRevoke != nil {
		t.Fatalf("RevokeCertificateWithActor failed unexpectedly: %v", errRevoke)
	}

	// Test 2: GenerateDERCRL should fail gracefully (CAOperationsSvc is nil)
	_, errCRL := certService.GenerateDERCRL("iss-local")
	if errCRL == nil {
		t.Fatal("GenerateDERCRL expected error, got nil")
	}

	// Test 3: GetOCSPResponse should fail gracefully (CAOperationsSvc is nil)
	_, errOCSP := certService.GetOCSPResponse("iss-local", "ABC123")
	if errOCSP == nil {
		t.Fatal("GetOCSPResponse expected error, got nil")
	}

	// Assert that errors are for correct reasons
	if errCRL.Error() != "CA operations service not configured" {
		t.Errorf("CRL error should be about CA ops service, got: %s", errCRL.Error())
	}
	if errOCSP.Error() != "CA operations service not configured" {
		t.Errorf("OCSP error should be about CA ops service, got: %s", errOCSP.Error())
	}
}
