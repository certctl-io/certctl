package service

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// mockConnectorLayerIssuer is a test implementation of issuer.Connector
type mockConnectorLayerIssuer struct {
	issueResult   *issuer.IssuanceResult
	issueErr      error
	renewResult   *issuer.IssuanceResult
	renewErr      error
	lastIssueReq  *issuer.IssuanceRequest
	lastRenewReq  *issuer.RenewalRequest
	validateErr   error
	revokeErr     error
	orderStatusErr error
	orderStatus   *issuer.OrderStatus
}

func (m *mockConnectorLayerIssuer) ValidateConfig(ctx context.Context, config json.RawMessage) error {
	return m.validateErr
}

func (m *mockConnectorLayerIssuer) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	m.lastIssueReq = &request
	if m.issueErr != nil {
		return nil, m.issueErr
	}
	if m.issueResult != nil {
		return m.issueResult, nil
	}
	// Return default result
	now := time.Now()
	return &issuer.IssuanceResult{
		CertPEM:   "-----BEGIN CERTIFICATE-----\ndefault-cert\n-----END CERTIFICATE-----",
		ChainPEM:  "-----BEGIN CERTIFICATE-----\ndefault-chain\n-----END CERTIFICATE-----",
		Serial:    "default-serial-123",
		NotBefore: now,
		NotAfter:  now.AddDate(1, 0, 0),
		OrderID:   "order-default",
	}, nil
}

func (m *mockConnectorLayerIssuer) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	m.lastRenewReq = &request
	if m.renewErr != nil {
		return nil, m.renewErr
	}
	if m.renewResult != nil {
		return m.renewResult, nil
	}
	// Return default result
	now := time.Now()
	return &issuer.IssuanceResult{
		CertPEM:   "-----BEGIN CERTIFICATE-----\ndefault-renewed-cert\n-----END CERTIFICATE-----",
		ChainPEM:  "-----BEGIN CERTIFICATE-----\ndefault-renewed-chain\n-----END CERTIFICATE-----",
		Serial:    "default-renewed-serial-456",
		NotBefore: now,
		NotAfter:  now.AddDate(1, 0, 0),
		OrderID:   "order-renewed",
	}, nil
}

func (m *mockConnectorLayerIssuer) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	return m.revokeErr
}

func (m *mockConnectorLayerIssuer) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	if m.orderStatusErr != nil {
		return nil, m.orderStatusErr
	}
	if m.orderStatus != nil {
		return m.orderStatus, nil
	}
	status := "pending"
	return &issuer.OrderStatus{
		OrderID:   orderID,
		Status:    status,
		UpdatedAt: time.Now(),
	}, nil
}

func (m *mockConnectorLayerIssuer) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	return []byte("mock-crl-data"), nil
}

func (m *mockConnectorLayerIssuer) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	return []byte("mock-ocsp-response"), nil
}

// Tests for IssueCertificate

func TestIssuerConnectorAdapter_IssueCertificate_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	notAfter := now.AddDate(1, 0, 0)

	mock := &mockConnectorLayerIssuer{
		issueResult: &issuer.IssuanceResult{
			CertPEM:   "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----",
			ChainPEM:  "-----BEGIN CERTIFICATE-----\ntest-chain\n-----END CERTIFICATE-----",
			Serial:    "test-serial-001",
			NotBefore: now,
			NotAfter:  notAfter,
			OrderID:   "order-123",
		},
	}

	adapter := NewIssuerConnectorAdapter(mock)

	result, err := adapter.IssueCertificate(ctx, "example.com", []string{"www.example.com"}, "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----")

	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	if result.Serial != "test-serial-001" {
		t.Errorf("expected serial test-serial-001, got %s", result.Serial)
	}

	if result.CertPEM != "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----" {
		t.Errorf("expected CertPEM test-cert, got %s", result.CertPEM)
	}

	if result.ChainPEM != "-----BEGIN CERTIFICATE-----\ntest-chain\n-----END CERTIFICATE-----" {
		t.Errorf("expected ChainPEM test-chain, got %s", result.ChainPEM)
	}

	if !result.NotBefore.Equal(now) {
		t.Errorf("expected NotBefore %v, got %v", now, result.NotBefore)
	}

	if !result.NotAfter.Equal(notAfter) {
		t.Errorf("expected NotAfter %v, got %v", notAfter, result.NotAfter)
	}
}

func TestIssuerConnectorAdapter_IssueCertificate_Error(t *testing.T) {
	ctx := context.Background()
	testErr := errors.New("issuer connection failed")

	mock := &mockConnectorLayerIssuer{
		issueErr: testErr,
	}

	adapter := NewIssuerConnectorAdapter(mock)

	result, err := adapter.IssueCertificate(ctx, "example.com", []string{}, "csr")

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, testErr) {
		t.Errorf("expected error %v, got %v", testErr, err)
	}

	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
}

func TestIssuerConnectorAdapter_IssueCertificate_RequestTranslation(t *testing.T) {
	ctx := context.Background()

	mock := &mockConnectorLayerIssuer{
		issueResult: &issuer.IssuanceResult{
			CertPEM:   "cert",
			ChainPEM:  "chain",
			Serial:    "serial",
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(1, 0, 0),
		},
	}

	adapter := NewIssuerConnectorAdapter(mock)

	commonName := "test.example.com"
	sans := []string{"www.test.example.com", "api.test.example.com"}
	csrPEM := "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----"

	_, err := adapter.IssueCertificate(ctx, commonName, sans, csrPEM)

	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	// Verify request was passed through correctly
	if mock.lastIssueReq == nil {
		t.Fatal("expected request to be recorded")
	}

	if mock.lastIssueReq.CommonName != commonName {
		t.Errorf("expected CommonName %s, got %s", commonName, mock.lastIssueReq.CommonName)
	}

	if len(mock.lastIssueReq.SANs) != len(sans) {
		t.Errorf("expected %d SANs, got %d", len(sans), len(mock.lastIssueReq.SANs))
	}

	for i, san := range sans {
		if mock.lastIssueReq.SANs[i] != san {
			t.Errorf("expected SAN[%d] %s, got %s", i, san, mock.lastIssueReq.SANs[i])
		}
	}

	if mock.lastIssueReq.CSRPEM != csrPEM {
		t.Errorf("expected CSRPEM %s, got %s", csrPEM, mock.lastIssueReq.CSRPEM)
	}
}

// Tests for RenewCertificate

func TestIssuerConnectorAdapter_RenewCertificate_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	notAfter := now.AddDate(1, 0, 0)

	mock := &mockConnectorLayerIssuer{
		renewResult: &issuer.IssuanceResult{
			CertPEM:   "-----BEGIN CERTIFICATE-----\nrenewed-cert\n-----END CERTIFICATE-----",
			ChainPEM:  "-----BEGIN CERTIFICATE-----\nrenewed-chain\n-----END CERTIFICATE-----",
			Serial:    "renewed-serial-002",
			NotBefore: now,
			NotAfter:  notAfter,
			OrderID:   "order-456",
		},
	}

	adapter := NewIssuerConnectorAdapter(mock)

	result, err := adapter.RenewCertificate(ctx, "example.com", []string{"www.example.com"}, "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----")

	if err != nil {
		t.Fatalf("RenewCertificate failed: %v", err)
	}

	if result.Serial != "renewed-serial-002" {
		t.Errorf("expected serial renewed-serial-002, got %s", result.Serial)
	}

	if result.CertPEM != "-----BEGIN CERTIFICATE-----\nrenewed-cert\n-----END CERTIFICATE-----" {
		t.Errorf("expected CertPEM renewed-cert, got %s", result.CertPEM)
	}

	if result.ChainPEM != "-----BEGIN CERTIFICATE-----\nrenewed-chain\n-----END CERTIFICATE-----" {
		t.Errorf("expected ChainPEM renewed-chain, got %s", result.ChainPEM)
	}

	if !result.NotBefore.Equal(now) {
		t.Errorf("expected NotBefore %v, got %v", now, result.NotBefore)
	}

	if !result.NotAfter.Equal(notAfter) {
		t.Errorf("expected NotAfter %v, got %v", notAfter, result.NotAfter)
	}
}

func TestIssuerConnectorAdapter_RenewCertificate_Error(t *testing.T) {
	ctx := context.Background()
	testErr := errors.New("renewal failed")

	mock := &mockConnectorLayerIssuer{
		renewErr: testErr,
	}

	adapter := NewIssuerConnectorAdapter(mock)

	result, err := adapter.RenewCertificate(ctx, "example.com", []string{}, "csr")

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, testErr) {
		t.Errorf("expected error %v, got %v", testErr, err)
	}

	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
}

func TestIssuerConnectorAdapter_RenewCertificate_RequestTranslation(t *testing.T) {
	ctx := context.Background()

	mock := &mockConnectorLayerIssuer{
		renewResult: &issuer.IssuanceResult{
			CertPEM:   "cert",
			ChainPEM:  "chain",
			Serial:    "serial",
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(1, 0, 0),
		},
	}

	adapter := NewIssuerConnectorAdapter(mock)

	commonName := "renew.example.com"
	sans := []string{"www.renew.example.com"}
	csrPEM := "-----BEGIN CERTIFICATE REQUEST-----\nRENEW-CSR\n-----END CERTIFICATE REQUEST-----"

	_, err := adapter.RenewCertificate(ctx, commonName, sans, csrPEM)

	if err != nil {
		t.Fatalf("RenewCertificate failed: %v", err)
	}

	// Verify request was passed through correctly
	if mock.lastRenewReq == nil {
		t.Fatal("expected request to be recorded")
	}

	if mock.lastRenewReq.CommonName != commonName {
		t.Errorf("expected CommonName %s, got %s", commonName, mock.lastRenewReq.CommonName)
	}

	if len(mock.lastRenewReq.SANs) != len(sans) {
		t.Errorf("expected %d SANs, got %d", len(sans), len(mock.lastRenewReq.SANs))
	}

	for i, san := range sans {
		if mock.lastRenewReq.SANs[i] != san {
			t.Errorf("expected SAN[%d] %s, got %s", i, san, mock.lastRenewReq.SANs[i])
		}
	}

	if mock.lastRenewReq.CSRPEM != csrPEM {
		t.Errorf("expected CSRPEM %s, got %s", csrPEM, mock.lastRenewReq.CSRPEM)
	}
}

// Tests for RevokeCertificate

func TestIssuerConnectorAdapter_RevokeCertificate_Success(t *testing.T) {
	ctx := context.Background()
	mock := &mockConnectorLayerIssuer{}
	adapter := NewIssuerConnectorAdapter(mock)

	err := adapter.RevokeCertificate(ctx, "serial-123", "keyCompromise")
	if err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}
}

func TestIssuerConnectorAdapter_RevokeCertificate_Error(t *testing.T) {
	ctx := context.Background()
	testErr := errors.New("revocation failed at issuer")
	mock := &mockConnectorLayerIssuer{revokeErr: testErr}
	adapter := NewIssuerConnectorAdapter(mock)

	err := adapter.RevokeCertificate(ctx, "serial-123", "keyCompromise")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, testErr) {
		t.Errorf("expected error %v, got %v", testErr, err)
	}
}

func TestIssuerConnectorAdapter_RevokeCertificate_EmptyReason(t *testing.T) {
	ctx := context.Background()
	mock := &mockConnectorLayerIssuer{}
	adapter := NewIssuerConnectorAdapter(mock)

	// Empty reason should pass nil to the connector
	err := adapter.RevokeCertificate(ctx, "serial-456", "")
	if err != nil {
		t.Fatalf("RevokeCertificate with empty reason failed: %v", err)
	}
}

// M15b: CRL and OCSP Adapter Tests

func TestIssuerConnectorAdapter_GenerateCRL_Success(t *testing.T) {
	ctx := context.Background()

	mock := &mockConnectorLayerIssuer{
		// Mock returns a valid DER CRL when GenerateCRL is called
	}

	adapter := NewIssuerConnectorAdapter(mock)

	// Call GenerateCRL on adapter
	crl, err := adapter.GenerateCRL(ctx, nil)

	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}

	if crl == nil {
		t.Fatal("expected non-nil CRL, got nil")
	}

	// Verify we got the mock CRL bytes
	if string(crl) != "mock-crl-data" {
		t.Errorf("expected mock-crl-data, got %s", string(crl))
	}

	t.Log("CRL generation delegated to connector successfully")
}

func TestIssuerConnectorAdapter_GenerateCRL_WithEntries(t *testing.T) {
	ctx := context.Background()
	mock := &mockConnectorLayerIssuer{}
	adapter := NewIssuerConnectorAdapter(mock)

	// Create test entries
	entries := []issuer.RevokedCertEntry{
		{SerialNumber: big.NewInt(111), RevokedAt: time.Now(), ReasonCode: 1},
		{SerialNumber: big.NewInt(222), RevokedAt: time.Now(), ReasonCode: 4},
	}

	crl, err := adapter.GenerateCRL(ctx, entries)

	if err != nil {
		t.Fatalf("GenerateCRL with entries failed: %v", err)
	}

	if crl == nil {
		t.Fatal("expected non-nil CRL")
	}

	if len(crl) == 0 {
		t.Fatal("expected non-empty CRL")
	}

	t.Logf("CRL with %d entries generated via adapter", len(entries))
}

func TestIssuerConnectorAdapter_SignOCSPResponse_Good(t *testing.T) {
	ctx := context.Background()
	mock := &mockConnectorLayerIssuer{}
	adapter := NewIssuerConnectorAdapter(mock)

	now := time.Now()
	req := issuer.OCSPSignRequest{
		CertSerial: big.NewInt(12345),
		CertStatus: 0, // good
		ThisUpdate: now,
		NextUpdate: now.Add(1 * time.Hour),
	}

	resp, err := adapter.SignOCSPResponse(ctx, req)

	if err != nil {
		t.Fatalf("SignOCSPResponse failed: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil OCSP response")
	}

	if len(resp) == 0 {
		t.Fatal("expected non-empty OCSP response")
	}

	if string(resp) != "mock-ocsp-response" {
		t.Errorf("expected mock-ocsp-response, got %s", string(resp))
	}

	t.Log("OCSP response for good cert signed via adapter")
}

func TestIssuerConnectorAdapter_SignOCSPResponse_Revoked(t *testing.T) {
	ctx := context.Background()
	mock := &mockConnectorLayerIssuer{}
	adapter := NewIssuerConnectorAdapter(mock)

	now := time.Now()
	req := issuer.OCSPSignRequest{
		CertSerial:       big.NewInt(67890),
		CertStatus:       1, // revoked
		RevokedAt:        now.Add(-24 * time.Hour),
		RevocationReason: 1, // keyCompromise
		ThisUpdate:       now,
		NextUpdate:       now.Add(1 * time.Hour),
	}

	resp, err := adapter.SignOCSPResponse(ctx, req)

	if err != nil {
		t.Fatalf("SignOCSPResponse for revoked cert failed: %v", err)
	}

	if resp == nil || len(resp) == 0 {
		t.Fatal("expected non-empty OCSP response for revoked cert")
	}

	t.Log("OCSP response for revoked cert signed via adapter")
}

func TestIssuerConnectorAdapter_SignOCSPResponse_Unknown(t *testing.T) {
	ctx := context.Background()
	mock := &mockConnectorLayerIssuer{}
	adapter := NewIssuerConnectorAdapter(mock)

	now := time.Now()
	req := issuer.OCSPSignRequest{
		CertSerial: big.NewInt(99999),
		CertStatus: 2, // unknown
		ThisUpdate: now,
		NextUpdate: now.Add(1 * time.Hour),
	}

	resp, err := adapter.SignOCSPResponse(ctx, req)

	if err != nil {
		t.Fatalf("SignOCSPResponse for unknown cert failed: %v", err)
	}

	if resp == nil || len(resp) == 0 {
		t.Fatal("expected non-empty OCSP response for unknown cert")
	}

	t.Log("OCSP response for unknown cert signed via adapter")
}
