package service

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// m11cProfileRepo wraps the existing mockProfileRepo from profile_test.go with AddProfile helper.
// We reuse the existing mock and just create instances with pre-populated profiles.
func newM11cProfileRepo() *mockProfileRepo {
	return &mockProfileRepo{
		profiles: make(map[string]*domain.CertificateProfile),
	}
}

// --- EST Crypto Policy Enforcement Tests ---

func TestESTService_CryptoValidation_RejectsWeakKey(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewESTService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	// Profile requiring ECDSA P-384 minimum
	profileRepo := newM11cProfileRepo()
	profileRepo.profiles["prof-high-sec"] = &domain.CertificateProfile{
		ID:   "prof-high-sec",
		Name: "High Security",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "ECDSA", MinSize: 384},
		},
	}
	svc.SetProfileID("prof-high-sec")
	svc.SetProfileRepo(profileRepo)

	// P-256 CSR should be rejected by P-384 minimum
	csrPEM := generateCSRPEM(t, "weak.example.com", nil)

	_, err := svc.SimpleEnroll(context.Background(), csrPEM)
	if err == nil {
		t.Fatal("expected rejection for ECDSA P-256 against P-384 minimum")
	}
	if !strings.Contains(err.Error(), "EST enrollment rejected") {
		t.Errorf("expected 'EST enrollment rejected' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "does not match any allowed algorithm") {
		t.Errorf("expected algorithm mismatch message, got: %v", err)
	}
}

func TestESTService_CryptoValidation_AcceptsStrongKey(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewESTService("iss-local", mockIssuer, auditSvc, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	// Profile allows P-256+
	profileRepo := newM11cProfileRepo()
	profileRepo.profiles["prof-standard"] = &domain.CertificateProfile{
		ID:   "prof-standard",
		Name: "Standard TLS",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "ECDSA", MinSize: 256},
		},
	}
	svc.SetProfileID("prof-standard")
	svc.SetProfileRepo(profileRepo)

	csrPEM := generateCSRPEM(t, "strong.example.com", nil)

	result, err := svc.SimpleEnroll(context.Background(), csrPEM)
	if err != nil {
		t.Fatalf("expected success for ECDSA P-256 against P-256 minimum: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestESTService_MaxTTL_ForwardedToIssuer(t *testing.T) {
	// Track what the mock issuer receives
	var capturedMaxTTL int
	mockIssuer := &mockIssuerConnector{}
	// Override IssueCertificate to capture maxTTLSeconds
	// We'll use a capturing mock instead
	capturingMock := &capturingIssuerConnector{}

	svc := NewESTService("iss-local", capturingMock, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	profileRepo := newM11cProfileRepo()
	profileRepo.profiles["prof-short"] = &domain.CertificateProfile{
		ID:            "prof-short",
		Name:          "Short Lived",
		MaxTTLSeconds: 3600, // 1 hour
	}
	svc.SetProfileID("prof-short")
	svc.SetProfileRepo(profileRepo)

	csrPEM := generateCSRPEM(t, "short.example.com", nil)

	_, err := svc.SimpleEnroll(context.Background(), csrPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	capturedMaxTTL = capturingMock.lastMaxTTLSeconds
	if capturedMaxTTL != 3600 {
		t.Errorf("expected maxTTLSeconds=3600 forwarded to issuer, got %d", capturedMaxTTL)
	}

	_ = mockIssuer // suppress unused
}

// --- SCEP Crypto Policy Enforcement Tests ---

func TestSCEPService_CryptoValidation_RejectsWeakKey(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	// H-2: SCEPService now requires a configured challenge password. Pass a
	// matching client password so this test exercises the crypto-policy path
	// rather than being short-circuited by the challenge-password guard.
	svc := NewSCEPService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")

	// Profile requiring ECDSA P-384 minimum
	profileRepo := newM11cProfileRepo()
	profileRepo.profiles["prof-high-sec"] = &domain.CertificateProfile{
		ID:   "prof-high-sec",
		Name: "High Security",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "ECDSA", MinSize: 384},
		},
	}
	svc.SetProfileID("prof-high-sec")
	svc.SetProfileRepo(profileRepo)

	// P-256 CSR should be rejected
	csrPEM := generateCSRPEM(t, "device.example.com", nil)

	_, err := svc.PKCSReq(context.Background(), csrPEM, "secret123", "txn-001")
	if err == nil {
		t.Fatal("expected rejection for ECDSA P-256 against P-384 minimum")
	}
	if !strings.Contains(err.Error(), "SCEP enrollment rejected") {
		t.Errorf("expected 'SCEP enrollment rejected' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "does not match any allowed algorithm") {
		t.Errorf("expected algorithm mismatch message, got: %v", err)
	}
}

func TestSCEPService_CryptoValidation_AcceptsStrongKey(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	// H-2: happy path exercises the authenticated branch.
	svc := NewSCEPService("iss-local", mockIssuer, auditSvc, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")

	profileRepo := newM11cProfileRepo()
	profileRepo.profiles["prof-standard"] = &domain.CertificateProfile{
		ID:   "prof-standard",
		Name: "Standard TLS",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "ECDSA", MinSize: 256},
		},
	}
	svc.SetProfileID("prof-standard")
	svc.SetProfileRepo(profileRepo)

	csrPEM := generateCSRPEM(t, "device-ok.example.com", nil)

	result, err := svc.PKCSReq(context.Background(), csrPEM, "secret123", "txn-002")
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestSCEPService_MaxTTL_ForwardedToIssuer(t *testing.T) {
	capturingMock := &capturingIssuerConnector{}

	// H-2: challenge password required for enrollment.
	svc := NewSCEPService("iss-local", capturingMock, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")

	profileRepo := newM11cProfileRepo()
	profileRepo.profiles["prof-device"] = &domain.CertificateProfile{
		ID:            "prof-device",
		Name:          "Device Cert",
		MaxTTLSeconds: 86400, // 24 hours
	}
	svc.SetProfileID("prof-device")
	svc.SetProfileRepo(profileRepo)

	csrPEM := generateCSRPEM(t, "mdm-device.example.com", nil)

	_, err := svc.PKCSReq(context.Background(), csrPEM, "secret123", "txn-003")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturingMock.lastMaxTTLSeconds != 86400 {
		t.Errorf("expected maxTTLSeconds=86400 forwarded to issuer, got %d", capturingMock.lastMaxTTLSeconds)
	}
}

// --- Adapter MaxTTL Forwarding Tests ---

func TestIssuerConnectorAdapter_IssueCertificate_MaxTTLForwarded(t *testing.T) {
	mock := &mockConnectorLayerIssuer{}
	adapter := NewIssuerConnectorAdapter(mock)

	_, err := adapter.IssueCertificate(context.Background(), "test.example.com", nil, "csr", nil, 7200, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.lastIssueReq == nil {
		t.Fatal("expected request to be recorded")
	}
	if mock.lastIssueReq.MaxTTLSeconds != 7200 {
		t.Errorf("expected MaxTTLSeconds=7200, got %d", mock.lastIssueReq.MaxTTLSeconds)
	}
}

func TestIssuerConnectorAdapter_RenewCertificate_MaxTTLForwarded(t *testing.T) {
	mock := &mockConnectorLayerIssuer{}
	adapter := NewIssuerConnectorAdapter(mock)

	_, err := adapter.RenewCertificate(context.Background(), "renew.example.com", nil, "csr", nil, 14400, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.lastRenewReq == nil {
		t.Fatal("expected request to be recorded")
	}
	if mock.lastRenewReq.MaxTTLSeconds != 14400 {
		t.Errorf("expected MaxTTLSeconds=14400, got %d", mock.lastRenewReq.MaxTTLSeconds)
	}
}

func TestIssuerConnectorAdapter_IssueCertificate_ZeroMaxTTL(t *testing.T) {
	mock := &mockConnectorLayerIssuer{}
	adapter := NewIssuerConnectorAdapter(mock)

	_, err := adapter.IssueCertificate(context.Background(), "test.example.com", nil, "csr", nil, 0, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.lastIssueReq.MaxTTLSeconds != 0 {
		t.Errorf("expected MaxTTLSeconds=0 (no cap), got %d", mock.lastIssueReq.MaxTTLSeconds)
	}
}

// --- CreateVersion Key Metadata Persistence Tests ---

func TestCreateVersion_KeyMetadata_Persisted(t *testing.T) {
	certRepo := newMockCertificateRepository()

	version := &domain.CertificateVersion{
		ID:            "ver-001",
		CertificateID: "cert-001",
		SerialNumber:  "serial-001",
		PEMChain:      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		NotBefore:     time.Now(),
		NotAfter:      time.Now().AddDate(1, 0, 0),
		KeyAlgorithm:  "ECDSA",
		KeySize:       256,
	}

	err := certRepo.CreateVersion(context.Background(), version)
	if err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}

	// Retrieve and verify key metadata was stored
	versions, err := certRepo.ListVersions(context.Background(), "cert-001")
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("expected 1 version, got %d", len(versions))
	}
	if versions[0].KeyAlgorithm != "ECDSA" {
		t.Errorf("expected KeyAlgorithm=ECDSA, got %s", versions[0].KeyAlgorithm)
	}
	if versions[0].KeySize != 256 {
		t.Errorf("expected KeySize=256, got %d", versions[0].KeySize)
	}
}

func TestCreateVersion_RSAKeyMetadata_Persisted(t *testing.T) {
	certRepo := newMockCertificateRepository()

	version := &domain.CertificateVersion{
		ID:            "ver-002",
		CertificateID: "cert-002",
		SerialNumber:  "serial-002",
		PEMChain:      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		NotBefore:     time.Now(),
		NotAfter:      time.Now().AddDate(1, 0, 0),
		KeyAlgorithm:  "RSA",
		KeySize:       4096,
	}

	err := certRepo.CreateVersion(context.Background(), version)
	if err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}

	versions, err := certRepo.ListVersions(context.Background(), "cert-002")
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}
	if versions[0].KeyAlgorithm != "RSA" {
		t.Errorf("expected KeyAlgorithm=RSA, got %s", versions[0].KeyAlgorithm)
	}
	if versions[0].KeySize != 4096 {
		t.Errorf("expected KeySize=4096, got %d", versions[0].KeySize)
	}
}

// --- EST/SCEP without profile repo (graceful passthrough) ---

func TestESTService_NoProfileRepo_PassesThrough(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewESTService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	svc.SetProfileID("nonexistent-profile")
	// Deliberately NOT calling SetProfileRepo — should pass through without validation

	csrPEM := generateCSRPEM(t, "no-profile.example.com", nil)

	result, err := svc.SimpleEnroll(context.Background(), csrPEM)
	if err != nil {
		t.Fatalf("expected success when no profile repo set: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestSCEPService_NoProfileRepo_PassesThrough(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	// H-2: challenge password required for enrollment.
	svc := NewSCEPService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")
	svc.SetProfileID("nonexistent-profile")

	csrPEM := generateCSRPEM(t, "no-profile-scep.example.com", nil)

	result, err := svc.PKCSReq(context.Background(), csrPEM, "secret123", "txn-004")
	if err != nil {
		t.Fatalf("expected success when no profile repo set: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// --- capturingIssuerConnector captures maxTTLSeconds for verification ---

type capturingIssuerConnector struct {
	lastMaxTTLSeconds int
	lastEKUs          []string
	// SCEP RFC 8894 + Intune master bundle Phase 5.6 follow-up: capture
	// must-staple too so the integration test can prove the wire reaches
	// the connector for both PKCSReq and renewal paths.
	lastMustStaple bool
}

func (c *capturingIssuerConnector) IssueCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string, maxTTLSeconds int, mustStaple bool) (*IssuanceResult, error) {
	c.lastMaxTTLSeconds = maxTTLSeconds
	c.lastEKUs = ekus
	c.lastMustStaple = mustStaple
	now := time.Now()
	return &IssuanceResult{
		Serial:    "test-serial",
		CertPEM:   "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		ChainPEM:  "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
		NotBefore: now,
		NotAfter:  now.AddDate(1, 0, 0),
	}, nil
}

func (c *capturingIssuerConnector) RenewCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string, maxTTLSeconds int, mustStaple bool) (*IssuanceResult, error) {
	return c.IssueCertificate(ctx, commonName, sans, csrPEM, ekus, maxTTLSeconds, mustStaple)
}

func (c *capturingIssuerConnector) RevokeCertificate(ctx context.Context, serial string, reason string) error {
	return nil
}

func (c *capturingIssuerConnector) GenerateCRL(ctx context.Context, entries []CRLEntry) ([]byte, error) {
	return nil, nil
}

func (c *capturingIssuerConnector) SignOCSPResponse(ctx context.Context, req OCSPSignRequest) ([]byte, error) {
	return nil, nil
}

func (c *capturingIssuerConnector) GetCACertPEM(ctx context.Context) (string, error) {
	return "-----BEGIN CERTIFICATE-----\nmock-ca\n-----END CERTIFICATE-----", nil
}

func (c *capturingIssuerConnector) GetRenewalInfo(ctx context.Context, certPEM string) (*RenewalInfoResult, error) {
	return nil, nil
}
