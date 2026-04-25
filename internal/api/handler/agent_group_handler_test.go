package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
)

// MockAgentGroupService is a mock implementation of AgentGroupService interface.
type MockAgentGroupService struct {
	ListAgentGroupsFn  func(page, perPage int) ([]domain.AgentGroup, int64, error)
	GetAgentGroupFn    func(id string) (*domain.AgentGroup, error)
	CreateAgentGroupFn func(group domain.AgentGroup) (*domain.AgentGroup, error)
	UpdateAgentGroupFn func(id string, group domain.AgentGroup) (*domain.AgentGroup, error)
	DeleteAgentGroupFn func(id string) error
	ListMembersFn      func(id string) ([]domain.Agent, int64, error)
}

func (m *MockAgentGroupService) ListAgentGroups(_ context.Context, page, perPage int) ([]domain.AgentGroup, int64, error) {
	if m.ListAgentGroupsFn != nil {
		return m.ListAgentGroupsFn(page, perPage)
	}
	return []domain.AgentGroup{}, 0, nil
}

func (m *MockAgentGroupService) GetAgentGroup(_ context.Context, id string) (*domain.AgentGroup, error) {
	if m.GetAgentGroupFn != nil {
		return m.GetAgentGroupFn(id)
	}
	return nil, fmt.Errorf("not found: %w", ErrMockNotFound)
}

func (m *MockAgentGroupService) CreateAgentGroup(_ context.Context, group domain.AgentGroup) (*domain.AgentGroup, error) {
	if m.CreateAgentGroupFn != nil {
		return m.CreateAgentGroupFn(group)
	}
	return &group, nil
}

func (m *MockAgentGroupService) UpdateAgentGroup(_ context.Context, id string, group domain.AgentGroup) (*domain.AgentGroup, error) {
	if m.UpdateAgentGroupFn != nil {
		return m.UpdateAgentGroupFn(id, group)
	}
	group.ID = id
	return &group, nil
}

func (m *MockAgentGroupService) DeleteAgentGroup(_ context.Context, id string) error {
	if m.DeleteAgentGroupFn != nil {
		return m.DeleteAgentGroupFn(id)
	}
	return nil
}

func (m *MockAgentGroupService) ListMembers(_ context.Context, id string) ([]domain.Agent, int64, error) {
	if m.ListMembersFn != nil {
		return m.ListMembersFn(id)
	}
	return []domain.Agent{}, 0, nil
}

func TestListAgentGroups_Success(t *testing.T) {
	group := domain.AgentGroup{
		ID:          "ag-linux",
		Name:        "Linux Agents",
		Description: "All Linux-based agents",
		MatchOS:     "linux",
		Enabled:     true,
	}

	mock := &MockAgentGroupService{
		ListAgentGroupsFn: func(page, perPage int) ([]domain.AgentGroup, int64, error) {
			return []domain.AgentGroup{group}, 1, nil
		},
	}

	h := NewAgentGroupHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-groups", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.ListAgentGroups(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("expected total 1, got %d", resp.Total)
	}
}

func TestListAgentGroups_ServiceError(t *testing.T) {
	mock := &MockAgentGroupService{
		ListAgentGroupsFn: func(page, perPage int) ([]domain.AgentGroup, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	h := NewAgentGroupHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-groups", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.ListAgentGroups(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestListAgentGroups_MethodNotAllowed(t *testing.T) {
	h := NewAgentGroupHandler(&MockAgentGroupService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-groups", nil)
	w := httptest.NewRecorder()

	h.ListAgentGroups(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestGetAgentGroup_Success(t *testing.T) {
	mock := &MockAgentGroupService{
		GetAgentGroupFn: func(id string) (*domain.AgentGroup, error) {
			return &domain.AgentGroup{
				ID:      id,
				Name:    "Linux Agents",
				MatchOS: "linux",
				Enabled: true,
			}, nil
		},
	}

	h := NewAgentGroupHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-groups/ag-linux", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.GetAgentGroup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestGetAgentGroup_NotFound(t *testing.T) {
	mock := &MockAgentGroupService{
		GetAgentGroupFn: func(id string) (*domain.AgentGroup, error) {
			return nil, ErrMockNotFound
		},
	}

	h := NewAgentGroupHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-groups/ag-ghost", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.GetAgentGroup(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestCreateAgentGroup_Success(t *testing.T) {
	mock := &MockAgentGroupService{
		CreateAgentGroupFn: func(group domain.AgentGroup) (*domain.AgentGroup, error) {
			group.ID = "ag-new"
			return &group, nil
		},
	}

	body := map[string]interface{}{
		"name":     "Ubuntu Agents",
		"match_os": "linux",
		"enabled":  true,
	}
	bodyBytes, _ := json.Marshal(body)

	h := NewAgentGroupHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-groups", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.CreateAgentGroup(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestCreateAgentGroup_MissingName(t *testing.T) {
	body := map[string]interface{}{
		"match_os": "linux",
	}
	bodyBytes, _ := json.Marshal(body)

	h := NewAgentGroupHandler(&MockAgentGroupService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-groups", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.CreateAgentGroup(w, req)

	// Handler may or may not validate name — service does. Either 400 or 500 acceptable.
	if w.Code == http.StatusCreated || w.Code == http.StatusOK {
		t.Fatalf("expected error for missing name, got %d", w.Code)
	}
}

func TestCreateAgentGroup_InvalidJSON(t *testing.T) {
	h := NewAgentGroupHandler(&MockAgentGroupService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-groups", bytes.NewReader([]byte("not json")))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.CreateAgentGroup(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestDeleteAgentGroup_Success(t *testing.T) {
	var deletedID string
	mock := &MockAgentGroupService{
		DeleteAgentGroupFn: func(id string) error {
			deletedID = id
			return nil
		},
	}

	h := NewAgentGroupHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/agent-groups/ag-linux", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.DeleteAgentGroup(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
	if deletedID != "ag-linux" {
		t.Errorf("expected deleted ID 'ag-linux', got '%s'", deletedID)
	}
}

func TestDeleteAgentGroup_ServiceError(t *testing.T) {
	mock := &MockAgentGroupService{
		DeleteAgentGroupFn: func(id string) error {
			return ErrMockServiceFailed
		},
	}

	h := NewAgentGroupHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/agent-groups/ag-linux", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.DeleteAgentGroup(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestListAgentGroupMembers_Success(t *testing.T) {
	mock := &MockAgentGroupService{
		ListMembersFn: func(id string) ([]domain.Agent, int64, error) {
			return []domain.Agent{
				{ID: "agent-001", Name: "web-1", Hostname: "web-1.prod"},
			}, 1, nil
		},
	}

	h := NewAgentGroupHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-groups/ag-linux/members", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.ListAgentGroupMembers(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("expected total 1, got %d", resp.Total)
	}
}

func TestListAgentGroupMembers_ServiceError(t *testing.T) {
	mock := &MockAgentGroupService{
		ListMembersFn: func(id string) ([]domain.Agent, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	h := NewAgentGroupHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-groups/ag-linux/members", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	h.ListAgentGroupMembers(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}
