package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// MockTargetService is a mock implementation of TargetService interface.
type MockTargetService struct {
	ListTargetsFn        func(page, perPage int) ([]domain.DeploymentTarget, int64, error)
	GetTargetFn          func(id string) (*domain.DeploymentTarget, error)
	CreateTargetFn       func(target domain.DeploymentTarget) (*domain.DeploymentTarget, error)
	UpdateTargetFn       func(id string, target domain.DeploymentTarget) (*domain.DeploymentTarget, error)
	DeleteTargetFn       func(id string) error
	TestTargetConnectionFn func(id string) error
}

func (m *MockTargetService) ListTargets(page, perPage int) ([]domain.DeploymentTarget, int64, error) {
	if m.ListTargetsFn != nil {
		return m.ListTargetsFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *MockTargetService) GetTarget(id string) (*domain.DeploymentTarget, error) {
	if m.GetTargetFn != nil {
		return m.GetTargetFn(id)
	}
	return nil, nil
}

func (m *MockTargetService) CreateTarget(target domain.DeploymentTarget) (*domain.DeploymentTarget, error) {
	if m.CreateTargetFn != nil {
		return m.CreateTargetFn(target)
	}
	return nil, nil
}

func (m *MockTargetService) UpdateTarget(id string, target domain.DeploymentTarget) (*domain.DeploymentTarget, error) {
	if m.UpdateTargetFn != nil {
		return m.UpdateTargetFn(id, target)
	}
	return nil, nil
}

func (m *MockTargetService) DeleteTarget(id string) error {
	if m.DeleteTargetFn != nil {
		return m.DeleteTargetFn(id)
	}
	return nil
}

func (m *MockTargetService) TestTargetConnection(id string) error {
	if m.TestTargetConnectionFn != nil {
		return m.TestTargetConnectionFn(id)
	}
	return nil
}

func TestListTargets_Success(t *testing.T) {
	now := time.Now()
	t1 := domain.DeploymentTarget{
		ID:        "t-nginx-01",
		Name:      "NGINX Proxy",
		Type:      "nginx",
		AgentID:   "agent-001",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	t2 := domain.DeploymentTarget{
		ID:        "t-f5-01",
		Name:      "F5 LTM",
		Type:      "f5",
		AgentID:   "agent-002",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	mock := &MockTargetService{
		ListTargetsFn: func(page, perPage int) ([]domain.DeploymentTarget, int64, error) {
			return []domain.DeploymentTarget{t1, t2}, 2, nil
		},
	}

	handler := NewTargetHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListTargets(w, req)

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

func TestListTargets_Pagination(t *testing.T) {
	var capturedPage, capturedPerPage int
	mock := &MockTargetService{
		ListTargetsFn: func(page, perPage int) ([]domain.DeploymentTarget, int64, error) {
			capturedPage = page
			capturedPerPage = perPage
			return []domain.DeploymentTarget{}, 0, nil
		},
	}

	handler := NewTargetHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/targets?page=4&per_page=5", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListTargets(w, req)

	if capturedPage != 4 {
		t.Errorf("expected page 4, got %d", capturedPage)
	}
	if capturedPerPage != 5 {
		t.Errorf("expected per_page 5, got %d", capturedPerPage)
	}
}

func TestListTargets_ServiceError(t *testing.T) {
	mock := &MockTargetService{
		ListTargetsFn: func(page, perPage int) ([]domain.DeploymentTarget, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewTargetHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListTargets(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestListTargets_MethodNotAllowed(t *testing.T) {
	handler := NewTargetHandler(&MockTargetService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/targets", nil)
	w := httptest.NewRecorder()

	handler.ListTargets(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestGetTarget_Success(t *testing.T) {
	now := time.Now()
	mock := &MockTargetService{
		GetTargetFn: func(id string) (*domain.DeploymentTarget, error) {
			return &domain.DeploymentTarget{
				ID:        id,
				Name:      "NGINX Proxy",
				Type:      "nginx",
				AgentID:   "agent-001",
				Enabled:   true,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	}

	handler := NewTargetHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/targets/t-nginx-01", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetTarget(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestGetTarget_NotFound(t *testing.T) {
	mock := &MockTargetService{
		GetTargetFn: func(id string) (*domain.DeploymentTarget, error) {
			return nil, ErrMockNotFound
		},
	}

	handler := NewTargetHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/targets/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetTarget(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestGetTarget_EmptyID(t *testing.T) {
	handler := NewTargetHandler(&MockTargetService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/targets/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetTarget(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateTarget_Success(t *testing.T) {
	now := time.Now()
	mock := &MockTargetService{
		CreateTargetFn: func(target domain.DeploymentTarget) (*domain.DeploymentTarget, error) {
			target.ID = "t-new"
			target.CreatedAt = now
			target.UpdatedAt = now
			return &target, nil
		},
	}

	body := map[string]interface{}{
		"name": "New Target",
		"type": "nginx",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTargetHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/targets", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateTarget(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", w.Code)
	}
}

func TestCreateTarget_MissingName(t *testing.T) {
	body := map[string]interface{}{
		"type": "nginx",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTargetHandler(&MockTargetService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/targets", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateTarget(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateTarget_MissingType(t *testing.T) {
	body := map[string]interface{}{
		"name": "New Target",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTargetHandler(&MockTargetService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/targets", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateTarget(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateTarget_InvalidJSON(t *testing.T) {
	handler := NewTargetHandler(&MockTargetService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/targets", bytes.NewReader([]byte("not json")))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateTarget(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateTarget_NameTooLong(t *testing.T) {
	longName := ""
	for i := 0; i < 256; i++ {
		longName += "x"
	}
	body := map[string]interface{}{
		"name": longName,
		"type": "nginx",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTargetHandler(&MockTargetService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/targets", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateTarget(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateTarget_MethodNotAllowed(t *testing.T) {
	handler := NewTargetHandler(&MockTargetService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
	w := httptest.NewRecorder()

	handler.CreateTarget(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestUpdateTarget_Success(t *testing.T) {
	now := time.Now()
	mock := &MockTargetService{
		UpdateTargetFn: func(id string, target domain.DeploymentTarget) (*domain.DeploymentTarget, error) {
			return &domain.DeploymentTarget{
				ID:        id,
				Name:      target.Name,
				Type:      "nginx",
				AgentID:   "agent-001",
				Enabled:   true,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	}

	body := map[string]interface{}{
		"name": "Updated Target",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTargetHandler(mock)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/targets/t-nginx-01", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateTarget(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestDeleteTarget_Success(t *testing.T) {
	var deletedID string
	mock := &MockTargetService{
		DeleteTargetFn: func(id string) error {
			deletedID = id
			return nil
		},
	}

	handler := NewTargetHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/targets/t-nginx-01", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteTarget(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
	if deletedID != "t-nginx-01" {
		t.Errorf("expected deleted ID 't-nginx-01', got '%s'", deletedID)
	}
}

func TestDeleteTarget_ServiceError(t *testing.T) {
	mock := &MockTargetService{
		DeleteTargetFn: func(id string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewTargetHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/targets/t-nginx-01", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteTarget(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestDeleteTarget_EmptyID(t *testing.T) {
	handler := NewTargetHandler(&MockTargetService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/targets/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteTarget(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestTestTargetConnection_Success(t *testing.T) {
	mock := &MockTargetService{
		TestTargetConnectionFn: func(id string) error {
			return nil
		},
	}

	handler := NewTargetHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/targets/t-nginx-01/test", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.TestTargetConnection(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "success" {
		t.Errorf("expected status 'success', got %v", resp["status"])
	}
}

func TestTestTargetConnection_Failed(t *testing.T) {
	mock := &MockTargetService{
		TestTargetConnectionFn: func(id string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewTargetHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/targets/t-nginx-01/test", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.TestTargetConnection(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "failed" {
		t.Errorf("expected status 'failed', got %v", resp["status"])
	}
}

func TestTestTargetConnection_MethodNotAllowed(t *testing.T) {
	handler := NewTargetHandler(&MockTargetService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/targets/t-nginx-01/test", nil)
	w := httptest.NewRecorder()

	handler.TestTargetConnection(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}
