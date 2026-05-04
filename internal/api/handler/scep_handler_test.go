package handler

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
)

// mockSCEPService implements SCEPService for testing.
type mockSCEPService struct {
	CACaps       string
	CACertPEM    string
	CACertErr    error
	EnrollResult *domain.SCEPEnrollResult
	EnrollErr    error
}

func (m *mockSCEPService) GetCACaps(ctx context.Context) string {
	if m.CACaps != "" {
		return m.CACaps
	}
	return "POSTPKIOperation\nSHA-256\nAES\nSCEPStandard\n"
}

func (m *mockSCEPService) GetCACert(ctx context.Context) (string, error) {
	return m.CACertPEM, m.CACertErr
}

func (m *mockSCEPService) PKCSReq(ctx context.Context, csrPEM string, challengePassword string, transactionID string) (*domain.SCEPEnrollResult, error) {
	return m.EnrollResult, m.EnrollErr
}

// PKCSReqWithEnvelope is the RFC 8894 envelope-aware variant added in SCEP
// RFC 8894 + Intune master bundle Phase 2.4. The MVP-only handler tests
// don't exercise this path (RA pair is unset), so this stub is only here
// to satisfy the interface; behavior mirrors PKCSReq's success/failure
// based on the same EnrollResult / EnrollErr fields the existing tests
// already populate.
func (m *mockSCEPService) PKCSReqWithEnvelope(ctx context.Context, csrPEM string, challengePassword string, envelope *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	if m.EnrollErr != nil {
		return &domain.SCEPResponseEnvelope{
			Status:         domain.SCEPStatusFailure,
			FailInfo:       domain.SCEPFailBadRequest,
			TransactionID:  envelope.TransactionID,
			RecipientNonce: envelope.SenderNonce,
		}
	}
	return &domain.SCEPResponseEnvelope{
		Status:         domain.SCEPStatusSuccess,
		Result:         m.EnrollResult,
		TransactionID:  envelope.TransactionID,
		RecipientNonce: envelope.SenderNonce,
	}
}

// RenewalReqWithEnvelope + GetCertInitialWithEnvelope added in Phase 4 to
// satisfy the extended SCEPService interface. Same MVP-only test fixture
// rules apply — these stubs mirror PKCSReqWithEnvelope's shape.
func (m *mockSCEPService) RenewalReqWithEnvelope(ctx context.Context, csrPEM string, challengePassword string, envelope *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	return m.PKCSReqWithEnvelope(ctx, csrPEM, challengePassword, envelope)
}

func (m *mockSCEPService) GetCertInitialWithEnvelope(_ context.Context, envelope *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	return &domain.SCEPResponseEnvelope{
		Status:         domain.SCEPStatusFailure,
		FailInfo:       domain.SCEPFailBadCertID,
		TransactionID:  envelope.TransactionID,
		RecipientNonce: envelope.SenderNonce,
	}
}

func TestSCEP_GetCACaps_Success(t *testing.T) {
	svc := &mockSCEPService{}
	h := NewSCEPHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/scep?operation=GetCACaps", nil)
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if ct != "text/plain" {
		t.Errorf("expected text/plain, got %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "POSTPKIOperation") {
		t.Errorf("expected POSTPKIOperation in response, got: %s", body)
	}
	if !strings.Contains(body, "SHA-256") {
		t.Errorf("expected SHA-256 in response, got: %s", body)
	}
}

func TestSCEP_GetCACaps_MethodNotAllowed(t *testing.T) {
	svc := &mockSCEPService{}
	h := NewSCEPHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/scep?operation=GetCACaps", nil)
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestSCEP_GetCACert_Success_SingleCert(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	svc := &mockSCEPService{
		CACertPEM: certPEM,
	}
	h := NewSCEPHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/scep?operation=GetCACert", nil)
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/x-x509-ca-cert" {
		t.Errorf("expected application/x-x509-ca-cert, got %s", ct)
	}
	if w.Body.Len() == 0 {
		t.Error("expected non-empty body")
	}
}

func TestSCEP_GetCACert_MethodNotAllowed(t *testing.T) {
	svc := &mockSCEPService{}
	h := NewSCEPHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/scep?operation=GetCACert", nil)
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestSCEP_GetCACert_ServiceError(t *testing.T) {
	svc := &mockSCEPService{
		CACertErr: errors.New("CA unavailable"),
	}
	h := NewSCEPHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/scep?operation=GetCACert", nil)
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestSCEP_PKIOperation_MethodNotAllowed(t *testing.T) {
	svc := &mockSCEPService{}
	h := NewSCEPHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/scep?operation=PKIOperation", nil)
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestSCEP_PKIOperation_EmptyBody(t *testing.T) {
	svc := &mockSCEPService{}
	h := NewSCEPHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", strings.NewReader(""))
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSCEP_PKIOperation_InvalidBody(t *testing.T) {
	svc := &mockSCEPService{}
	h := NewSCEPHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", strings.NewReader("not-valid-asn1-or-csr"))
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSCEP_PKIOperation_ServiceError(t *testing.T) {
	svc := &mockSCEPService{
		EnrollErr: errors.New("enrollment failed"),
	}
	h := NewSCEPHandler(svc)

	// Generate a valid raw CSR DER to send as body (fallback path)
	csrPEM := generateTestCSRPEM(t)
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode CSR PEM")
	}

	req := httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", strings.NewReader(string(block.Bytes)))
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSCEP_PKIOperation_Success_RawCSR(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	svc := &mockSCEPService{
		EnrollResult: &domain.SCEPEnrollResult{
			CertPEM:  certPEM,
			ChainPEM: "",
		},
	}
	h := NewSCEPHandler(svc)

	csrPEM := generateTestCSRPEM(t)
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode CSR PEM")
	}

	req := httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", strings.NewReader(string(block.Bytes)))
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/x-pki-message" {
		t.Errorf("expected application/x-pki-message, got %s", ct)
	}
}

func TestSCEP_PKIOperation_ChallengePasswordRejected(t *testing.T) {
	svc := &mockSCEPService{
		EnrollErr: errors.New("invalid challenge password"),
	}
	h := NewSCEPHandler(svc)

	csrPEM := generateTestCSRPEM(t)
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode CSR PEM")
	}

	req := httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", strings.NewReader(string(block.Bytes)))
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSCEP_UnknownOperation(t *testing.T) {
	svc := &mockSCEPService{}
	h := NewSCEPHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/scep?operation=UnknownOp", nil)
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSCEP_MissingOperation(t *testing.T) {
	svc := &mockSCEPService{}
	h := NewSCEPHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/scep", nil)
	w := httptest.NewRecorder()
	h.HandleSCEP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
