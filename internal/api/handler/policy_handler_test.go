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

// MockPolicyService is a mock implementation of PolicyService interface.
type MockPolicyService struct {
	ListPoliciesFn   func(page, perPage int) ([]domain.PolicyRule, int64, error)
	GetPolicyFn      func(id string) (*domain.PolicyRule, error)
	CreatePolicyFn   func(policy domain.PolicyRule) (*domain.PolicyRule, error)
	UpdatePolicyFn   func(id string, policy domain.PolicyRule) (*domain.PolicyRule, error)
	DeletePolicyFn   func(id string) error
	ListViolationsFn func(policyID string, page, perPage int) ([]domain.PolicyViolation, int64, error)
}

func (m *MockPolicyService) ListPolicies(_ context.Context, page, perPage int) ([]domain.PolicyRule, int64, error) {
	if m.ListPoliciesFn != nil {
		return m.ListPoliciesFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *MockPolicyService) GetPolicy(_ context.Context, id string) (*domain.PolicyRule, error) {
	if m.GetPolicyFn != nil {
		return m.GetPolicyFn(id)
	}
	return nil, nil
}

func (m *MockPolicyService) CreatePolicy(_ context.Context, policy domain.PolicyRule) (*domain.PolicyRule, error) {
	if m.CreatePolicyFn != nil {
		return m.CreatePolicyFn(policy)
	}
	return nil, nil
}

func (m *MockPolicyService) UpdatePolicy(_ context.Context, id string, policy domain.PolicyRule) (*domain.PolicyRule, error) {
	if m.UpdatePolicyFn != nil {
		return m.UpdatePolicyFn(id, policy)
	}
	return nil, nil
}

func (m *MockPolicyService) DeletePolicy(_ context.Context, id string) error {
	if m.DeletePolicyFn != nil {
		return m.DeletePolicyFn(id)
	}
	return nil
}

func (m *MockPolicyService) ListViolations(_ context.Context, policyID string, page, perPage int) ([]domain.PolicyViolation, int64, error) {
	if m.ListViolationsFn != nil {
		return m.ListViolationsFn(policyID, page, perPage)
	}
	return nil, 0, nil
}

func TestListPolicies_Success(t *testing.T) {
	now := time.Now()
	p1 := domain.PolicyRule{
		ID:        "pol-001",
		Name:      "Allowed Issuers",
		Type:      domain.PolicyTypeAllowedIssuers,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	p2 := domain.PolicyRule{
		ID:        "pol-002",
		Name:      "Allowed Domains",
		Type:      domain.PolicyTypeAllowedDomains,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	mock := &MockPolicyService{
		ListPoliciesFn: func(page, perPage int) ([]domain.PolicyRule, int64, error) {
			return []domain.PolicyRule{p1, p2}, 2, nil
		},
	}

	handler := NewPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListPolicies(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("expected total 2, got %d", resp.Total)
	}
}

func TestListPolicies_ServiceError(t *testing.T) {
	mock := &MockPolicyService{
		ListPoliciesFn: func(page, perPage int) ([]domain.PolicyRule, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListPolicies(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestListPolicies_MethodNotAllowed(t *testing.T) {
	handler := NewPolicyHandler(&MockPolicyService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies", nil)
	w := httptest.NewRecorder()

	handler.ListPolicies(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestGetPolicy_Success(t *testing.T) {
	now := time.Now()
	mock := &MockPolicyService{
		GetPolicyFn: func(id string) (*domain.PolicyRule, error) {
			return &domain.PolicyRule{
				ID:        id,
				Name:      "Allowed Issuers",
				Type:      domain.PolicyTypeAllowedIssuers,
				Enabled:   true,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	}

	handler := NewPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/pol-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetPolicy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestGetPolicy_NotFound(t *testing.T) {
	mock := &MockPolicyService{
		GetPolicyFn: func(id string) (*domain.PolicyRule, error) {
			return nil, ErrMockNotFound
		},
	}

	handler := NewPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetPolicy(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestCreatePolicy_Success(t *testing.T) {
	now := time.Now()
	mock := &MockPolicyService{
		CreatePolicyFn: func(policy domain.PolicyRule) (*domain.PolicyRule, error) {
			policy.ID = "pol-new"
			policy.CreatedAt = now
			policy.UpdatedAt = now
			return &policy, nil
		},
	}

	body := map[string]interface{}{
		"name": "New Policy",
		"type": "AllowedIssuers",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreatePolicy(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", w.Code)
	}
}

func TestCreatePolicy_MissingName(t *testing.T) {
	body := map[string]interface{}{
		"type": "AllowedIssuers",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewPolicyHandler(&MockPolicyService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreatePolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreatePolicy_MissingType(t *testing.T) {
	body := map[string]interface{}{
		"name": "New Policy",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewPolicyHandler(&MockPolicyService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreatePolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreatePolicy_InvalidType(t *testing.T) {
	body := map[string]interface{}{
		"name": "New Policy",
		"type": "InvalidType",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewPolicyHandler(&MockPolicyService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreatePolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreatePolicy_InvalidJSON(t *testing.T) {
	handler := NewPolicyHandler(&MockPolicyService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader([]byte("not json")))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreatePolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreatePolicy_MethodNotAllowed(t *testing.T) {
	handler := NewPolicyHandler(&MockPolicyService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	w := httptest.NewRecorder()

	handler.CreatePolicy(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestUpdatePolicy_Success(t *testing.T) {
	now := time.Now()
	mock := &MockPolicyService{
		UpdatePolicyFn: func(id string, policy domain.PolicyRule) (*domain.PolicyRule, error) {
			return &domain.PolicyRule{
				ID:        id,
				Name:      policy.Name,
				Type:      domain.PolicyTypeAllowedIssuers,
				Enabled:   true,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	}

	body := map[string]interface{}{
		"name": "Updated Policy",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/policies/pol-001", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdatePolicy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestUpdatePolicy_InvalidType(t *testing.T) {
	body := map[string]interface{}{
		"name": "Updated Policy",
		"type": "InvalidType",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewPolicyHandler(&MockPolicyService{})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/policies/pol-001", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdatePolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestDeletePolicy_Success(t *testing.T) {
	var deletedID string
	mock := &MockPolicyService{
		DeletePolicyFn: func(id string) error {
			deletedID = id
			return nil
		},
	}

	handler := NewPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/pol-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeletePolicy(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
	if deletedID != "pol-001" {
		t.Errorf("expected deleted ID 'pol-001', got '%s'", deletedID)
	}
}

func TestDeletePolicy_ServiceError(t *testing.T) {
	mock := &MockPolicyService{
		DeletePolicyFn: func(id string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/pol-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeletePolicy(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestDeletePolicy_EmptyID(t *testing.T) {
	handler := NewPolicyHandler(&MockPolicyService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeletePolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestListViolations_Success(t *testing.T) {
	now := time.Now()
	v1 := domain.PolicyViolation{
		ID:            "viol-001",
		CertificateID: "mc-prod-001",
		RuleID:        "pol-001",
		Message:       "Certificate uses disallowed issuer",
		Severity:      domain.PolicySeverityWarning,
		CreatedAt:     now,
	}

	var capturedPolicyID string
	mock := &MockPolicyService{
		ListViolationsFn: func(policyID string, page, perPage int) ([]domain.PolicyViolation, int64, error) {
			capturedPolicyID = policyID
			return []domain.PolicyViolation{v1}, 1, nil
		},
	}

	handler := NewPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/pol-001/violations", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListViolations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if capturedPolicyID != "pol-001" {
		t.Errorf("expected policy ID 'pol-001', got '%s'", capturedPolicyID)
	}

	var resp PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("expected total 1, got %d", resp.Total)
	}
}

func TestListViolations_ServiceError(t *testing.T) {
	mock := &MockPolicyService{
		ListViolationsFn: func(policyID string, page, perPage int) ([]domain.PolicyViolation, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/pol-001/violations", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListViolations(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestListViolations_EmptyPolicyID(t *testing.T) {
	handler := NewPolicyHandler(&MockPolicyService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies//violations", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListViolations(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}
