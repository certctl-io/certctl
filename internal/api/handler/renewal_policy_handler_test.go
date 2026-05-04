package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/service"
)

// G-1 red tests: lock in the HTTP surface of /api/v1/renewal-policies before
// the production code exists. Every subtest here references a symbol that
// Phase 2b must introduce:
//
//   - NewRenewalPolicyHandler(svc)             (constructor)
//   - RenewalPolicyService                     (service-layer interface, in this package)
//   - handler.ListRenewalPolicies / GetRenewalPolicy / CreateRenewalPolicy /
//     UpdateRenewalPolicy / DeleteRenewalPolicy
//   - service.ErrRenewalPolicyDuplicateName    (pg 23505 → 409 mapping)
//   - service.ErrRenewalPolicyInUse            (pg 23503 → 409 mapping)

// MockRenewalPolicyService is a mock implementation of RenewalPolicyService.
type MockRenewalPolicyService struct {
	ListRenewalPoliciesFn func(page, perPage int) ([]domain.RenewalPolicy, int64, error)
	GetRenewalPolicyFn    func(id string) (*domain.RenewalPolicy, error)
	CreateRenewalPolicyFn func(rp domain.RenewalPolicy) (*domain.RenewalPolicy, error)
	UpdateRenewalPolicyFn func(id string, rp domain.RenewalPolicy) (*domain.RenewalPolicy, error)
	DeleteRenewalPolicyFn func(id string) error
}

func (m *MockRenewalPolicyService) ListRenewalPolicies(_ context.Context, page, perPage int) ([]domain.RenewalPolicy, int64, error) {
	if m.ListRenewalPoliciesFn != nil {
		return m.ListRenewalPoliciesFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *MockRenewalPolicyService) GetRenewalPolicy(_ context.Context, id string) (*domain.RenewalPolicy, error) {
	if m.GetRenewalPolicyFn != nil {
		return m.GetRenewalPolicyFn(id)
	}
	return nil, nil
}

func (m *MockRenewalPolicyService) CreateRenewalPolicy(_ context.Context, rp domain.RenewalPolicy) (*domain.RenewalPolicy, error) {
	if m.CreateRenewalPolicyFn != nil {
		return m.CreateRenewalPolicyFn(rp)
	}
	return nil, nil
}

func (m *MockRenewalPolicyService) UpdateRenewalPolicy(_ context.Context, id string, rp domain.RenewalPolicy) (*domain.RenewalPolicy, error) {
	if m.UpdateRenewalPolicyFn != nil {
		return m.UpdateRenewalPolicyFn(id, rp)
	}
	return nil, nil
}

func (m *MockRenewalPolicyService) DeleteRenewalPolicy(_ context.Context, id string) error {
	if m.DeleteRenewalPolicyFn != nil {
		return m.DeleteRenewalPolicyFn(id)
	}
	return nil
}

// ----- List -----

func TestListRenewalPolicies_Success(t *testing.T) {
	now := time.Now()
	rp1 := domain.RenewalPolicy{
		ID: "rp-default", Name: "Default", RenewalWindowDays: 30,
		MaxRetries: 3, RetryInterval: 3600, AutoRenew: true,
		CreatedAt: now, UpdatedAt: now,
	}
	rp2 := domain.RenewalPolicy{
		ID: "rp-urgent", Name: "Urgent", RenewalWindowDays: 7,
		MaxRetries: 5, RetryInterval: 600, AutoRenew: true,
		CreatedAt: now, UpdatedAt: now,
	}

	mock := &MockRenewalPolicyService{
		ListRenewalPoliciesFn: func(page, perPage int) ([]domain.RenewalPolicy, int64, error) {
			return []domain.RenewalPolicy{rp1, rp2}, 2, nil
		},
	}

	handler := NewRenewalPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/renewal-policies", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListRenewalPolicies(w, req)

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

func TestListRenewalPolicies_ServiceError(t *testing.T) {
	mock := &MockRenewalPolicyService{
		ListRenewalPoliciesFn: func(page, perPage int) ([]domain.RenewalPolicy, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewRenewalPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/renewal-policies", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListRenewalPolicies(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestListRenewalPolicies_MethodNotAllowed(t *testing.T) {
	handler := NewRenewalPolicyHandler(&MockRenewalPolicyService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/renewal-policies", nil)
	w := httptest.NewRecorder()

	handler.ListRenewalPolicies(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

// ----- Get -----

func TestGetRenewalPolicy_Success(t *testing.T) {
	now := time.Now()
	mock := &MockRenewalPolicyService{
		GetRenewalPolicyFn: func(id string) (*domain.RenewalPolicy, error) {
			return &domain.RenewalPolicy{
				ID: id, Name: "Default", RenewalWindowDays: 30,
				MaxRetries: 3, RetryInterval: 3600, AutoRenew: true,
				CreatedAt: now, UpdatedAt: now,
			}, nil
		},
	}

	handler := NewRenewalPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/renewal-policies/rp-default", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetRenewalPolicy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestGetRenewalPolicy_NotFound(t *testing.T) {
	mock := &MockRenewalPolicyService{
		GetRenewalPolicyFn: func(id string) (*domain.RenewalPolicy, error) {
			return nil, ErrMockNotFound
		},
	}

	handler := NewRenewalPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/renewal-policies/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetRenewalPolicy(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

// ----- Create -----

func TestCreateRenewalPolicy_Success(t *testing.T) {
	now := time.Now()
	mock := &MockRenewalPolicyService{
		CreateRenewalPolicyFn: func(rp domain.RenewalPolicy) (*domain.RenewalPolicy, error) {
			rp.ID = "rp-new"
			rp.CreatedAt = now
			rp.UpdatedAt = now
			return &rp, nil
		},
	}

	body := map[string]interface{}{
		"name":                   "New Policy",
		"renewal_window_days":    30,
		"max_retries":            3,
		"retry_interval_seconds": 3600,
		"auto_renew":             true,
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewRenewalPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/renewal-policies", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateRenewalPolicy(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", w.Code)
	}
}

func TestCreateRenewalPolicy_MissingName(t *testing.T) {
	body := map[string]interface{}{
		"renewal_window_days":    30,
		"max_retries":            3,
		"retry_interval_seconds": 3600,
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewRenewalPolicyHandler(&MockRenewalPolicyService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/renewal-policies", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateRenewalPolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateRenewalPolicy_InvalidJSON(t *testing.T) {
	handler := NewRenewalPolicyHandler(&MockRenewalPolicyService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/renewal-policies", bytes.NewReader([]byte("not json")))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateRenewalPolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateRenewalPolicy_DuplicateName(t *testing.T) {
	// Service bubbles up ErrRenewalPolicyDuplicateName (pg 23505) → handler maps to 409.
	mock := &MockRenewalPolicyService{
		CreateRenewalPolicyFn: func(rp domain.RenewalPolicy) (*domain.RenewalPolicy, error) {
			return nil, service.ErrRenewalPolicyDuplicateName
		},
	}

	body := map[string]interface{}{
		"name":                   "Duplicate",
		"renewal_window_days":    30,
		"max_retries":            3,
		"retry_interval_seconds": 3600,
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewRenewalPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/renewal-policies", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateRenewalPolicy(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected status 409 on duplicate name, got %d", w.Code)
	}
}

func TestCreateRenewalPolicy_MethodNotAllowed(t *testing.T) {
	handler := NewRenewalPolicyHandler(&MockRenewalPolicyService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/renewal-policies", nil)
	w := httptest.NewRecorder()

	handler.CreateRenewalPolicy(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

// ----- Update -----

func TestUpdateRenewalPolicy_Success(t *testing.T) {
	now := time.Now()
	mock := &MockRenewalPolicyService{
		UpdateRenewalPolicyFn: func(id string, rp domain.RenewalPolicy) (*domain.RenewalPolicy, error) {
			return &domain.RenewalPolicy{
				ID: id, Name: rp.Name, RenewalWindowDays: rp.RenewalWindowDays,
				MaxRetries: rp.MaxRetries, RetryInterval: rp.RetryInterval,
				AutoRenew: rp.AutoRenew,
				CreatedAt: now, UpdatedAt: now,
			}, nil
		},
	}

	body := map[string]interface{}{
		"name":                   "Updated Policy",
		"renewal_window_days":    45,
		"max_retries":            5,
		"retry_interval_seconds": 1800,
		"auto_renew":             true,
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewRenewalPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/renewal-policies/rp-default", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateRenewalPolicy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestUpdateRenewalPolicy_NotFound(t *testing.T) {
	mock := &MockRenewalPolicyService{
		UpdateRenewalPolicyFn: func(id string, rp domain.RenewalPolicy) (*domain.RenewalPolicy, error) {
			return nil, ErrMockNotFound
		},
	}

	body := map[string]interface{}{
		"name":                   "Updated",
		"renewal_window_days":    30,
		"max_retries":            3,
		"retry_interval_seconds": 3600,
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewRenewalPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/renewal-policies/rp-missing", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateRenewalPolicy(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

// ----- Delete -----

func TestDeleteRenewalPolicy_Success(t *testing.T) {
	var deletedID string
	mock := &MockRenewalPolicyService{
		DeleteRenewalPolicyFn: func(id string) error {
			deletedID = id
			return nil
		},
	}

	handler := NewRenewalPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/renewal-policies/rp-default", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteRenewalPolicy(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
	if deletedID != "rp-default" {
		t.Errorf("expected deleted ID 'rp-default', got '%s'", deletedID)
	}
}

func TestDeleteRenewalPolicy_NotFound(t *testing.T) {
	mock := &MockRenewalPolicyService{
		DeleteRenewalPolicyFn: func(id string) error {
			return ErrMockNotFound
		},
	}

	handler := NewRenewalPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/renewal-policies/rp-missing", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteRenewalPolicy(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestDeleteRenewalPolicy_InUseConflict(t *testing.T) {
	// Service bubbles up ErrRenewalPolicyInUse (pg 23503 FK-RESTRICT) → handler maps to 409.
	mock := &MockRenewalPolicyService{
		DeleteRenewalPolicyFn: func(id string) error {
			return service.ErrRenewalPolicyInUse
		},
	}

	handler := NewRenewalPolicyHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/renewal-policies/rp-active", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteRenewalPolicy(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected status 409 on in-use conflict, got %d", w.Code)
	}
}

func TestDeleteRenewalPolicy_EmptyID(t *testing.T) {
	handler := NewRenewalPolicyHandler(&MockRenewalPolicyService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/renewal-policies/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteRenewalPolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}
