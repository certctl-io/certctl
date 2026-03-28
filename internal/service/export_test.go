package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// generateTestCertPEM creates a self-signed test certificate PEM for export tests.
func generateTestCertPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))
}

func newMockCertRepoWithVersion(certID string, cert *domain.ManagedCertificate, version *domain.CertificateVersion) *mockCertRepo {
	repo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	if cert != nil {
		repo.Certs[certID] = cert
	}
	if version != nil {
		repo.Versions[certID] = []*domain.CertificateVersion{version}
	}
	return repo
}

func TestExportPEM_Success(t *testing.T) {
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIBxz...\n-----END CERTIFICATE-----\n"
	chainPEM := "-----BEGIN CERTIFICATE-----\nMIIByz...\n-----END CERTIFICATE-----\n"
	fullPEM := certPEM + chainPEM

	certRepo := newMockCertRepoWithVersion("mc-test-1",
		&domain.ManagedCertificate{
			ID:         "mc-test-1",
			CommonName: "test.example.com",
			Status:     domain.CertificateStatusActive,
		},
		&domain.CertificateVersion{
			ID:           "cv-1",
			CertificateID: "mc-test-1",
			SerialNumber: "abc123",
			PEMChain:     fullPEM,
		},
	)
	auditSvc := &AuditService{auditRepo: &mockAuditRepo{}}
	svc := NewExportService(certRepo, auditSvc)

	result, err := svc.ExportPEM(context.Background(), "mc-test-1")
	if err != nil {
		t.Fatalf("ExportPEM failed: %v", err)
	}
	if result.FullPEM == "" {
		t.Error("expected non-empty FullPEM")
	}
	if result.CertPEM == "" {
		t.Error("expected non-empty CertPEM")
	}
}

func TestExportPEM_CertNotFound(t *testing.T) {
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	svc := NewExportService(certRepo, nil)

	_, err := svc.ExportPEM(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent certificate")
	}
}

func TestExportPEM_NoVersion(t *testing.T) {
	certRepo := newMockCertRepoWithVersion("mc-test-1",
		&domain.ManagedCertificate{
			ID:         "mc-test-1",
			CommonName: "test.example.com",
		},
		nil, // no version
	)
	svc := NewExportService(certRepo, nil)

	_, err := svc.ExportPEM(context.Background(), "mc-test-1")
	if err == nil {
		t.Fatal("expected error when no version exists")
	}
}

func TestExportPKCS12_Success(t *testing.T) {
	testCertPEM := generateTestCertPEM(t)

	certRepo := newMockCertRepoWithVersion("mc-test-1",
		&domain.ManagedCertificate{
			ID:         "mc-test-1",
			CommonName: "test.example.com",
			Status:     domain.CertificateStatusActive,
		},
		&domain.CertificateVersion{
			ID:            "cv-1",
			CertificateID: "mc-test-1",
			SerialNumber:  "abc123",
			PEMChain:      testCertPEM,
		},
	)
	auditSvc := &AuditService{auditRepo: &mockAuditRepo{}}
	svc := NewExportService(certRepo, auditSvc)

	pfxData, err := svc.ExportPKCS12(context.Background(), "mc-test-1", "testpass")
	if err != nil {
		t.Fatalf("ExportPKCS12 failed: %v", err)
	}
	if len(pfxData) == 0 {
		t.Error("expected non-empty PKCS#12 data")
	}
}

func TestExportPKCS12_EmptyPassword(t *testing.T) {
	testCertPEM := generateTestCertPEM(t)

	certRepo := newMockCertRepoWithVersion("mc-test-1",
		&domain.ManagedCertificate{ID: "mc-test-1"},
		&domain.CertificateVersion{
			ID:            "cv-1",
			CertificateID: "mc-test-1",
			PEMChain:      testCertPEM,
		},
	)
	svc := NewExportService(certRepo, nil)

	pfxData, err := svc.ExportPKCS12(context.Background(), "mc-test-1", "")
	if err != nil {
		t.Fatalf("ExportPKCS12 with empty password failed: %v", err)
	}
	if len(pfxData) == 0 {
		t.Error("expected non-empty PKCS#12 data")
	}
}

func TestExportPKCS12_CertNotFound(t *testing.T) {
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	svc := NewExportService(certRepo, nil)

	_, err := svc.ExportPKCS12(context.Background(), "nonexistent", "pass")
	if err == nil {
		t.Fatal("expected error for nonexistent certificate")
	}
}

func TestSplitPEMChain_TwoCerts(t *testing.T) {
	cert1 := "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n"
	cert2 := "-----BEGIN CERTIFICATE-----\nBBB=\n-----END CERTIFICATE-----\n"

	certPEM, chainPEM := splitPEMChain(cert1 + cert2)
	if certPEM == "" {
		t.Error("expected non-empty certPEM")
	}
	if chainPEM == "" {
		t.Error("expected non-empty chainPEM")
	}
}

func TestSplitPEMChain_SingleCert(t *testing.T) {
	cert1 := "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n"

	certPEM, chainPEM := splitPEMChain(cert1)
	if certPEM == "" {
		t.Error("expected non-empty certPEM")
	}
	if chainPEM != "" {
		t.Errorf("expected empty chainPEM, got %q", chainPEM)
	}
}

func TestSplitPEMChain_EmptyInput(t *testing.T) {
	certPEM, chainPEM := splitPEMChain("")
	if certPEM != "" {
		t.Errorf("expected empty certPEM for empty input, got %q", certPEM)
	}
	if chainPEM != "" {
		t.Errorf("expected empty chainPEM for empty input, got %q", chainPEM)
	}
}
