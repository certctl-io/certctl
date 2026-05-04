package service

import (
	"context"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

func TestCreateCertificate(t *testing.T) {
	ctx := context.Background()
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	auditRepo := &mockAuditRepo{
		Events: []*domain.AuditEvent{},
	}
	policyRepo := &mockPolicyRepo{
		Rules:      make(map[string]*domain.PolicyRule),
		Violations: []*domain.PolicyViolation{},
	}

	policyService := NewPolicyService(policyRepo, NewAuditService(auditRepo))
	auditService := NewAuditService(auditRepo)
	certService := NewCertificateService(certRepo, policyService, auditService)

	now := time.Now()
	cert := &domain.ManagedCertificate{
		ID:              "cert-001",
		Name:            "api-prod",
		CommonName:      "api.example.com",
		SANs:            []string{"api.example.com"},
		Environment:     "production",
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-acme",
		TargetIDs:       []string{"target-1"},
		RenewalPolicyID: "policy-1",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       now.AddDate(1, 0, 0),
		Tags:            map[string]string{"env": "prod"},
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	err := certService.Create(ctx, cert, "user-1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if len(certRepo.Certs) != 1 {
		t.Errorf("expected 1 cert, got %d", len(certRepo.Certs))
	}

	storedCert, ok := certRepo.Certs["cert-001"]
	if !ok {
		t.Fatal("certificate not stored")
	}
	if storedCert.CommonName != "api.example.com" {
		t.Errorf("expected common name api.example.com, got %s", storedCert.CommonName)
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}
}

func TestCreateCertificate_MissingRequired(t *testing.T) {
	ctx := context.Background()
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	auditRepo := &mockAuditRepo{}
	policyRepo := &mockPolicyRepo{Rules: make(map[string]*domain.PolicyRule)}

	policyService := NewPolicyService(policyRepo, NewAuditService(auditRepo))
	auditService := NewAuditService(auditRepo)
	certService := NewCertificateService(certRepo, policyService, auditService)

	cert := &domain.ManagedCertificate{
		ID: "cert-001",
		// Missing CommonName and IssuerID
	}

	err := certService.Create(ctx, cert, "user-1")
	if err == nil {
		t.Fatal("expected error for missing required fields")
	}
}

func TestGetCertificate(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	cert := &domain.ManagedCertificate{
		ID:         "cert-001",
		CommonName: "example.com",
		IssuerID:   "iss-1",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  now.AddDate(1, 0, 0),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	certRepo := &mockCertRepo{
		Certs:    map[string]*domain.ManagedCertificate{"cert-001": cert},
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	auditRepo := &mockAuditRepo{}
	policyRepo := &mockPolicyRepo{Rules: make(map[string]*domain.PolicyRule)}

	policyService := NewPolicyService(policyRepo, NewAuditService(auditRepo))
	auditService := NewAuditService(auditRepo)
	certService := NewCertificateService(certRepo, policyService, auditService)

	retrieved, err := certService.Get(ctx, "cert-001")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.CommonName != "example.com" {
		t.Errorf("expected common name example.com, got %s", retrieved.CommonName)
	}
}

func TestGetCertificate_NotFound(t *testing.T) {
	ctx := context.Background()
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	auditRepo := &mockAuditRepo{}
	policyRepo := &mockPolicyRepo{Rules: make(map[string]*domain.PolicyRule)}

	policyService := NewPolicyService(policyRepo, NewAuditService(auditRepo))
	auditService := NewAuditService(auditRepo)
	certService := NewCertificateService(certRepo, policyService, auditService)

	_, err := certService.Get(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent certificate")
	}
}

func TestUpdateCertificate(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	originalCert := &domain.ManagedCertificate{
		ID:         "cert-001",
		CommonName: "example.com",
		IssuerID:   "iss-1",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  now.AddDate(1, 0, 0),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	certRepo := &mockCertRepo{
		Certs:    map[string]*domain.ManagedCertificate{"cert-001": originalCert},
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	auditRepo := &mockAuditRepo{Events: []*domain.AuditEvent{}}
	policyRepo := &mockPolicyRepo{Rules: make(map[string]*domain.PolicyRule)}

	policyService := NewPolicyService(policyRepo, NewAuditService(auditRepo))
	auditService := NewAuditService(auditRepo)
	certService := NewCertificateService(certRepo, policyService, auditService)

	updatedCert := *originalCert
	updatedCert.Status = domain.CertificateStatusExpiring
	updatedCert.ExpiresAt = now.AddDate(0, 0, 5)

	err := certService.Update(ctx, &updatedCert, "user-1")
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	stored := certRepo.Certs["cert-001"]
	if stored.Status != domain.CertificateStatusExpiring {
		t.Errorf("expected status Expiring, got %s", stored.Status)
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}
}

func TestArchiveCertificate(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	cert := &domain.ManagedCertificate{
		ID:         "cert-001",
		CommonName: "example.com",
		IssuerID:   "iss-1",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  now.AddDate(1, 0, 0),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	certRepo := &mockCertRepo{
		Certs:    map[string]*domain.ManagedCertificate{"cert-001": cert},
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	auditRepo := &mockAuditRepo{Events: []*domain.AuditEvent{}}
	policyRepo := &mockPolicyRepo{Rules: make(map[string]*domain.PolicyRule)}

	policyService := NewPolicyService(policyRepo, NewAuditService(auditRepo))
	auditService := NewAuditService(auditRepo)
	certService := NewCertificateService(certRepo, policyService, auditService)

	err := certService.Archive(ctx, "cert-001", "user-1")
	if err != nil {
		t.Fatalf("Archive failed: %v", err)
	}

	archived := certRepo.Certs["cert-001"]
	if archived.Status != domain.CertificateStatusArchived {
		t.Errorf("expected status Archived, got %s", archived.Status)
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}
}

func TestGetVersions(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	version1 := &domain.CertificateVersion{
		ID:            "ver-1",
		CertificateID: "cert-001",
		SerialNumber:  "serial-1",
		NotBefore:     now.AddDate(-1, 0, 0),
		NotAfter:      now,
		PEMChain:      "cert1-pem",
		CreatedAt:     now.AddDate(-1, 0, 0),
	}
	version2 := &domain.CertificateVersion{
		ID:            "ver-2",
		CertificateID: "cert-001",
		SerialNumber:  "serial-2",
		NotBefore:     now,
		NotAfter:      now.AddDate(1, 0, 0),
		PEMChain:      "cert2-pem",
		CreatedAt:     now,
	}

	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: map[string][]*domain.CertificateVersion{"cert-001": {version1, version2}},
	}
	auditRepo := &mockAuditRepo{}
	policyRepo := &mockPolicyRepo{Rules: make(map[string]*domain.PolicyRule)}

	policyService := NewPolicyService(policyRepo, NewAuditService(auditRepo))
	auditService := NewAuditService(auditRepo)
	certService := NewCertificateService(certRepo, policyService, auditService)

	versions, err := certService.GetVersions(ctx, "cert-001")
	if err != nil {
		t.Fatalf("GetVersions failed: %v", err)
	}

	if len(versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(versions))
	}
}

func TestTriggerRenewal(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	cert := &domain.ManagedCertificate{
		ID:         "cert-001",
		CommonName: "example.com",
		IssuerID:   "iss-1",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  now.AddDate(0, 0, 5),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	certRepo := &mockCertRepo{
		Certs:    map[string]*domain.ManagedCertificate{"cert-001": cert},
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	auditRepo := &mockAuditRepo{Events: []*domain.AuditEvent{}}
	policyRepo := &mockPolicyRepo{Rules: make(map[string]*domain.PolicyRule)}

	policyService := NewPolicyService(policyRepo, NewAuditService(auditRepo))
	auditService := NewAuditService(auditRepo)
	certService := NewCertificateService(certRepo, policyService, auditService)

	err := certService.TriggerRenewal(ctx, "cert-001", "user-1")
	if err != nil {
		t.Fatalf("TriggerRenewal failed: %v", err)
	}

	renewed := certRepo.Certs["cert-001"]
	if renewed.Status != domain.CertificateStatusRenewalInProgress {
		t.Errorf("expected status RenewalInProgress, got %s", renewed.Status)
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}
}

func TestTriggerRenewal_Archived(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	cert := &domain.ManagedCertificate{
		ID:         "cert-001",
		CommonName: "example.com",
		IssuerID:   "iss-1",
		Status:     domain.CertificateStatusArchived,
		ExpiresAt:  now.AddDate(0, 0, 5),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	certRepo := &mockCertRepo{
		Certs:    map[string]*domain.ManagedCertificate{"cert-001": cert},
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	auditRepo := &mockAuditRepo{}
	policyRepo := &mockPolicyRepo{Rules: make(map[string]*domain.PolicyRule)}

	policyService := NewPolicyService(policyRepo, NewAuditService(auditRepo))
	auditService := NewAuditService(auditRepo)
	certService := NewCertificateService(certRepo, policyService, auditService)

	err := certService.TriggerRenewal(ctx, "cert-001", "user-1")
	if err == nil {
		t.Fatal("expected error for archived certificate")
	}
}

func TestListCertificates(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	cert1 := &domain.ManagedCertificate{
		ID:         "cert-001",
		CommonName: "api.example.com",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  now.AddDate(1, 0, 0),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	cert2 := &domain.ManagedCertificate{
		ID:         "cert-002",
		CommonName: "web.example.com",
		Status:     domain.CertificateStatusExpiring,
		ExpiresAt:  now.AddDate(0, 0, 5),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	certRepo := &mockCertRepo{
		Certs:    map[string]*domain.ManagedCertificate{"cert-001": cert1, "cert-002": cert2},
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	auditRepo := &mockAuditRepo{}
	policyRepo := &mockPolicyRepo{Rules: make(map[string]*domain.PolicyRule)}

	policyService := NewPolicyService(policyRepo, NewAuditService(auditRepo))
	auditService := NewAuditService(auditRepo)
	certService := NewCertificateService(certRepo, policyService, auditService)

	certs, total, err := certService.ListCertificates(ctx, "", "", "", "", "", 1, 50)
	if err != nil {
		t.Fatalf("ListCertificates failed: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("expected 2 certs, got %d", len(certs))
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
}
