package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// mockVerificationService is a test double for VerificationService.
type mockVerificationService struct {
	recordErr error
	getErr    error
	results   map[string]*domain.VerificationResult
}

func (m *mockVerificationService) RecordVerificationResult(ctx context.Context, result *domain.VerificationResult) error {
	if m.recordErr != nil {
		return m.recordErr
	}
	if m.results == nil {
		m.results = make(map[string]*domain.VerificationResult)
	}
	m.results[result.JobID] = result
	return nil
}

func (m *mockVerificationService) GetVerificationResult(ctx context.Context, jobID string) (*domain.VerificationResult, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.results == nil {
		m.results = make(map[string]*domain.VerificationResult)
	}
	return m.results[jobID], nil
}

func TestVerifyDeployment_Success(t *testing.T) {
	mockSvc := &mockVerificationService{
		results: make(map[string]*domain.VerificationResult),
	}
	handler := NewVerificationHandler(mockSvc)

	req := VerifyDeploymentRequest{
		TargetID:            "t-nginx1",
		ExpectedFingerprint: "abc123",
		ActualFingerprint:   "abc123",
		Verified:            true,
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/v1/jobs/j-test1/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.VerifyDeployment(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Verify result was recorded
	result := mockSvc.results["j-test1"]
	if result == nil {
		t.Fatal("expected verification result to be recorded")
	}
	if !result.Verified {
		t.Error("expected Verified to be true")
	}
}

func TestVerifyDeployment_FingerPrintMismatch(t *testing.T) {
	mockSvc := &mockVerificationService{
		results: make(map[string]*domain.VerificationResult),
	}
	handler := NewVerificationHandler(mockSvc)

	req := VerifyDeploymentRequest{
		TargetID:            "t-apache1",
		ExpectedFingerprint: "aaa111",
		ActualFingerprint:   "bbb222",
		Verified:            false,
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/v1/jobs/j-test2/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.VerifyDeployment(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	result := mockSvc.results["j-test2"]
	if result == nil {
		t.Fatal("expected verification result to be recorded")
	}
	if result.Verified {
		t.Error("expected Verified to be false")
	}
}

func TestVerifyDeployment_MissingTargetID(t *testing.T) {
	mockSvc := &mockVerificationService{}
	handler := NewVerificationHandler(mockSvc)

	req := VerifyDeploymentRequest{
		ExpectedFingerprint: "abc123",
		ActualFingerprint:   "abc123",
		Verified:            true,
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/v1/jobs/j-test3/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.VerifyDeployment(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestVerifyDeployment_MissingExpectedFingerprint(t *testing.T) {
	mockSvc := &mockVerificationService{}
	handler := NewVerificationHandler(mockSvc)

	req := VerifyDeploymentRequest{
		TargetID:          "t-nginx1",
		ActualFingerprint: "abc123",
		Verified:          true,
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/v1/jobs/j-test4/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.VerifyDeployment(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestVerifyDeployment_InvalidMethod(t *testing.T) {
	mockSvc := &mockVerificationService{}
	handler := NewVerificationHandler(mockSvc)

	httpReq := httptest.NewRequest("GET", "/api/v1/jobs/j-test5/verify", nil)
	w := httptest.NewRecorder()

	handler.VerifyDeployment(w, httpReq)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestVerifyDeployment_InvalidJSON(t *testing.T) {
	mockSvc := &mockVerificationService{}
	handler := NewVerificationHandler(mockSvc)

	httpReq := httptest.NewRequest("POST", "/api/v1/jobs/j-test6/verify", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()

	handler.VerifyDeployment(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestGetVerificationStatus_Success(t *testing.T) {
	now := time.Now().UTC()
	fp := "xyz789"
	mockSvc := &mockVerificationService{
		results: map[string]*domain.VerificationResult{
			"j-test7": {
				JobID:               "j-test7",
				TargetID:            "t-haproxy1",
				ExpectedFingerprint: "xyz789",
				ActualFingerprint:   fp,
				Verified:            true,
				VerifiedAt:          now,
			},
		},
	}
	handler := NewVerificationHandler(mockSvc)

	httpReq := httptest.NewRequest("GET", "/api/v1/jobs/j-test7/verification", nil)
	w := httptest.NewRecorder()

	handler.GetVerificationStatus(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result domain.VerificationResult
	json.NewDecoder(w.Body).Decode(&result)
	if result.JobID != "j-test7" {
		t.Errorf("expected job ID j-test7, got %s", result.JobID)
	}
	if !result.Verified {
		t.Error("expected Verified to be true")
	}
}

func TestGetVerificationStatus_InvalidMethod(t *testing.T) {
	mockSvc := &mockVerificationService{}
	handler := NewVerificationHandler(mockSvc)

	httpReq := httptest.NewRequest("POST", "/api/v1/jobs/j-test8/verification", nil)
	w := httptest.NewRecorder()

	handler.GetVerificationStatus(w, httpReq)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestVerifyDeployment_ServiceError(t *testing.T) {
	mockSvc := &mockVerificationService{
		recordErr: ErrServiceUnavailable,
	}
	handler := NewVerificationHandler(mockSvc)

	req := VerifyDeploymentRequest{
		TargetID:            "t-nginx1",
		ExpectedFingerprint: "abc123",
		ActualFingerprint:   "abc123",
		Verified:            true,
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/v1/jobs/j-test9/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.VerifyDeployment(w, httpReq)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
}

var ErrServiceUnavailable = NewServiceError("service unavailable")

func NewServiceError(msg string) error {
	return &serviceError{msg: msg}
}

type serviceError struct {
	msg string
}

func (e *serviceError) Error() string {
	return e.msg
}
