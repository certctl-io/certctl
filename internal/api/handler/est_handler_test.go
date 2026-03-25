package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
)

// mockESTService implements ESTService for testing.
type mockESTService struct {
	CACertPEM    string
	CACertErr    error
	EnrollResult *domain.ESTEnrollResult
	EnrollErr    error
	CSRAttrs     []byte
	CSRAttrsErr  error
}

func (m *mockESTService) GetCACerts(ctx context.Context) (string, error) {
	return m.CACertPEM, m.CACertErr
}

func (m *mockESTService) SimpleEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error) {
	return m.EnrollResult, m.EnrollErr
}

func (m *mockESTService) SimpleReEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error) {
	return m.EnrollResult, m.EnrollErr
}

func (m *mockESTService) GetCSRAttrs(ctx context.Context) ([]byte, error) {
	return m.CSRAttrs, m.CSRAttrsErr
}

// generateTestCSRPEM creates a valid ECDSA P-256 CSR for testing.
func generateTestCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com", "www.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

// generateTestCSRBase64DER creates a valid base64-encoded DER CSR for EST wire format.
func generateTestCSRBase64DER(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	return base64.StdEncoding.EncodeToString(csrDER)
}

func TestESTCACerts_Success(t *testing.T) {
	svc := &mockESTService{
		CACertPEM: "-----BEGIN CERTIFICATE-----\nMIIBmjCCAUCgAwIBAgIRATest\n-----END CERTIFICATE-----\n",
	}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/est/cacerts", nil)
	w := httptest.NewRecorder()
	h.CACerts(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/pkcs7-mime") {
		t.Errorf("expected application/pkcs7-mime content type, got %s", ct)
	}
	cte := w.Header().Get("Content-Transfer-Encoding")
	if cte != "base64" {
		t.Errorf("expected base64 content-transfer-encoding, got %s", cte)
	}
}

func TestESTCACerts_MethodNotAllowed(t *testing.T) {
	svc := &mockESTService{}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/cacerts", nil)
	w := httptest.NewRecorder()
	h.CACerts(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestESTCACerts_ServiceError(t *testing.T) {
	svc := &mockESTService{
		CACertErr: errors.New("issuer unavailable"),
	}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/est/cacerts", nil)
	w := httptest.NewRecorder()
	h.CACerts(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestESTSimpleEnroll_Success_PEM(t *testing.T) {
	csrPEM := generateTestCSRPEM(t)
	svc := &mockESTService{
		EnrollResult: &domain.ESTEnrollResult{
			CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n",
			ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIBchain\n-----END CERTIFICATE-----\n",
		},
	}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(csrPEM))
	req.Header.Set("Content-Type", "application/pkcs10")
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/pkcs7-mime") {
		t.Errorf("expected application/pkcs7-mime, got %s", ct)
	}
}

func TestESTSimpleEnroll_Success_Base64DER(t *testing.T) {
	csrB64 := generateTestCSRBase64DER(t)
	svc := &mockESTService{
		EnrollResult: &domain.ESTEnrollResult{
			CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n",
			ChainPEM: "",
		},
	}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(csrB64))
	req.Header.Set("Content-Type", "application/pkcs10")
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestESTSimpleEnroll_MethodNotAllowed(t *testing.T) {
	svc := &mockESTService{}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/est/simpleenroll", nil)
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestESTSimpleEnroll_EmptyBody(t *testing.T) {
	svc := &mockESTService{}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(""))
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestESTSimpleEnroll_InvalidCSR(t *testing.T) {
	svc := &mockESTService{}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader("not-a-valid-csr"))
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestESTSimpleEnroll_ServiceError(t *testing.T) {
	csrPEM := generateTestCSRPEM(t)
	svc := &mockESTService{
		EnrollErr: errors.New("issuance failed"),
	}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(csrPEM))
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestESTSimpleReEnroll_Success(t *testing.T) {
	csrPEM := generateTestCSRPEM(t)
	svc := &mockESTService{
		EnrollResult: &domain.ESTEnrollResult{
			CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n",
			ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIBchain\n-----END CERTIFICATE-----\n",
		},
	}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simplereenroll", strings.NewReader(csrPEM))
	w := httptest.NewRecorder()
	h.SimpleReEnroll(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestESTSimpleReEnroll_MethodNotAllowed(t *testing.T) {
	svc := &mockESTService{}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/est/simplereenroll", nil)
	w := httptest.NewRecorder()
	h.SimpleReEnroll(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestESTCSRAttrs_NoContent(t *testing.T) {
	svc := &mockESTService{
		CSRAttrs: nil,
	}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/est/csrattrs", nil)
	w := httptest.NewRecorder()
	h.CSRAttrs(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestESTCSRAttrs_WithData(t *testing.T) {
	svc := &mockESTService{
		CSRAttrs: []byte{0x30, 0x00}, // empty SEQUENCE
	}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/est/csrattrs", nil)
	w := httptest.NewRecorder()
	h.CSRAttrs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/csrattrs" {
		t.Errorf("expected application/csrattrs, got %s", ct)
	}
}

func TestESTCSRAttrs_MethodNotAllowed(t *testing.T) {
	svc := &mockESTService{}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/csrattrs", nil)
	w := httptest.NewRecorder()
	h.CSRAttrs(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestBuildCertsOnlyPKCS7(t *testing.T) {
	// Test with a dummy DER certificate
	dummyCert := []byte{0x30, 0x82, 0x01, 0x00} // minimal ASN.1 SEQUENCE
	result, err := buildCertsOnlyPKCS7([][]byte{dummyCert})
	if err != nil {
		t.Fatalf("buildCertsOnlyPKCS7 failed: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected non-empty PKCS#7 output")
	}
	// Verify it starts with SEQUENCE tag
	if result[0] != 0x30 {
		t.Errorf("expected PKCS#7 to start with SEQUENCE tag (0x30), got 0x%02x", result[0])
	}
}

func TestPemToDERChain(t *testing.T) {
	pemData := "-----BEGIN CERTIFICATE-----\nMIIBmjCCAUCgAwIBAgIRATest\n-----END CERTIFICATE-----\n"
	certs, err := pemToDERChain(pemData)
	if err != nil {
		t.Fatalf("pemToDERChain failed: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert, got %d", len(certs))
	}
}

func TestPemToDERChain_NoCerts(t *testing.T) {
	_, err := pemToDERChain("not a PEM")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestASN1EncodeLength(t *testing.T) {
	tests := []struct {
		length   int
		expected []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{256, []byte{0x82, 0x01, 0x00}},
	}
	for _, tt := range tests {
		result := asn1EncodeLength(tt.length)
		if len(result) != len(tt.expected) {
			t.Errorf("asn1EncodeLength(%d): expected %d bytes, got %d", tt.length, len(tt.expected), len(result))
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("asn1EncodeLength(%d): byte %d: expected 0x%02x, got 0x%02x", tt.length, i, tt.expected[i], result[i])
			}
		}
	}
}
