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
)

// MockTeamService is a mock implementation of TeamService interface.
type MockTeamService struct {
	ListTeamsFn  func(page, perPage int) ([]domain.Team, int64, error)
	GetTeamFn    func(id string) (*domain.Team, error)
	CreateTeamFn func(team domain.Team) (*domain.Team, error)
	UpdateTeamFn func(id string, team domain.Team) (*domain.Team, error)
	DeleteTeamFn func(id string) error
}

func (m *MockTeamService) ListTeams(_ context.Context, page, perPage int) ([]domain.Team, int64, error) {
	if m.ListTeamsFn != nil {
		return m.ListTeamsFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *MockTeamService) GetTeam(_ context.Context, id string) (*domain.Team, error) {
	if m.GetTeamFn != nil {
		return m.GetTeamFn(id)
	}
	return nil, nil
}

func (m *MockTeamService) CreateTeam(_ context.Context, team domain.Team) (*domain.Team, error) {
	if m.CreateTeamFn != nil {
		return m.CreateTeamFn(team)
	}
	return nil, nil
}

func (m *MockTeamService) UpdateTeam(_ context.Context, id string, team domain.Team) (*domain.Team, error) {
	if m.UpdateTeamFn != nil {
		return m.UpdateTeamFn(id, team)
	}
	return nil, nil
}

func (m *MockTeamService) DeleteTeam(_ context.Context, id string) error {
	if m.DeleteTeamFn != nil {
		return m.DeleteTeamFn(id)
	}
	return nil
}

// TestListTeams_Success tests listing teams with default pagination.
func TestListTeams_Success(t *testing.T) {
	now := time.Now()
	t1 := domain.Team{
		ID:          "t-platform",
		Name:        "Platform Team",
		Description: "Infrastructure team",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	t2 := domain.Team{
		ID:          "t-security",
		Name:        "Security Team",
		Description: "Security operations",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	mock := &MockTeamService{
		ListTeamsFn: func(page, perPage int) ([]domain.Team, int64, error) {
			return []domain.Team{t1, t2}, 2, nil
		},
	}

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListTeams(w, req)

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
	if resp.Page != 1 {
		t.Errorf("expected page 1, got %d", resp.Page)
	}
	if resp.PerPage != 50 {
		t.Errorf("expected per_page 50, got %d", resp.PerPage)
	}
}

// TestListTeams_WithQueryParams tests listing with custom pagination parameters.
func TestListTeams_WithQueryParams(t *testing.T) {
	var capturedPage, capturedPerPage int
	mock := &MockTeamService{
		ListTeamsFn: func(page, perPage int) ([]domain.Team, int64, error) {
			capturedPage = page
			capturedPerPage = perPage
			return []domain.Team{}, 0, nil
		},
	}

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams?page=3&per_page=25", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListTeams(w, req)

	if capturedPage != 3 {
		t.Errorf("expected page 3, got %d", capturedPage)
	}
	if capturedPerPage != 25 {
		t.Errorf("expected per_page 25, got %d", capturedPerPage)
	}
}

// TestListTeams_PerPageMaxLimit tests that per_page values exceeding 500 are rejected
// and fall back to the default of 50 (the handler ignores invalid per_page values).
func TestListTeams_PerPageMaxLimit(t *testing.T) {
	var capturedPerPage int
	mock := &MockTeamService{
		ListTeamsFn: func(page, perPage int) ([]domain.Team, int64, error) {
			capturedPerPage = perPage
			return []domain.Team{}, 0, nil
		},
	}

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams?per_page=1000", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListTeams(w, req)

	// Handler rejects per_page > 500 and falls back to default (50)
	if capturedPerPage != 50 {
		t.Errorf("expected per_page to fall back to default 50 for values > 500, got %d", capturedPerPage)
	}
}

// TestListTeams_ServiceError tests error handling when service fails.
func TestListTeams_ServiceError(t *testing.T) {
	mock := &MockTeamService{
		ListTeamsFn: func(page, perPage int) ([]domain.Team, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListTeams(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

// TestListTeams_MethodNotAllowed tests that non-GET requests are rejected.
func TestListTeams_MethodNotAllowed(t *testing.T) {
	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", nil)
	w := httptest.NewRecorder()

	handler.ListTeams(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

// TestGetTeam_Success tests retrieving a team by ID.
func TestGetTeam_Success(t *testing.T) {
	now := time.Now()
	mock := &MockTeamService{
		GetTeamFn: func(id string) (*domain.Team, error) {
			return &domain.Team{
				ID:          id,
				Name:        "Platform Team",
				Description: "Infrastructure team",
				CreatedAt:   now,
				UpdatedAt:   now,
			}, nil
		},
	}

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams/t-platform", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetTeam(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var team domain.Team
	if err := json.NewDecoder(w.Body).Decode(&team); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if team.ID != "t-platform" {
		t.Errorf("expected ID t-platform, got %s", team.ID)
	}
}

// TestGetTeam_NotFound tests 404 response when team does not exist.
func TestGetTeam_NotFound(t *testing.T) {
	mock := &MockTeamService{
		GetTeamFn: func(id string) (*domain.Team, error) {
			return nil, ErrMockNotFound
		},
	}

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetTeam(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

// TestGetTeam_EmptyID tests 400 response when team ID is empty.
func TestGetTeam_EmptyID(t *testing.T) {
	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetTeam(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestGetTeam_MethodNotAllowed tests that non-GET requests are rejected.
func TestGetTeam_MethodNotAllowed(t *testing.T) {
	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/t-platform", nil)
	w := httptest.NewRecorder()

	handler.GetTeam(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

// TestCreateTeam_Success tests successful team creation.
func TestCreateTeam_Success(t *testing.T) {
	now := time.Now()
	mock := &MockTeamService{
		CreateTeamFn: func(team domain.Team) (*domain.Team, error) {
			team.ID = "t-new"
			team.CreatedAt = now
			team.UpdatedAt = now
			return &team, nil
		},
	}

	body := map[string]interface{}{
		"name":        "New Team",
		"description": "A new team",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateTeam(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", w.Code)
	}

	var team domain.Team
	if err := json.NewDecoder(w.Body).Decode(&team); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if team.ID != "t-new" {
		t.Errorf("expected ID t-new, got %s", team.ID)
	}
	if team.Name != "New Team" {
		t.Errorf("expected name 'New Team', got %s", team.Name)
	}
}

// TestCreateTeam_InvalidJSON tests 400 response for malformed JSON.
func TestCreateTeam_InvalidJSON(t *testing.T) {
	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader([]byte("not json")))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateTeam(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestCreateTeam_MissingName tests 400 response when name is required but missing.
func TestCreateTeam_MissingName(t *testing.T) {
	body := map[string]interface{}{
		"description": "Team without name",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateTeam(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestCreateTeam_NameTooLong tests 400 response when name exceeds max length.
func TestCreateTeam_NameTooLong(t *testing.T) {
	longName := ""
	for i := 0; i < 256; i++ {
		longName += "x"
	}
	body := map[string]interface{}{
		"name": longName,
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateTeam(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestCreateTeam_ServiceError tests error handling when service fails.
func TestCreateTeam_ServiceError(t *testing.T) {
	mock := &MockTeamService{
		CreateTeamFn: func(team domain.Team) (*domain.Team, error) {
			return nil, ErrMockServiceFailed
		},
	}

	body := map[string]interface{}{
		"name": "New Team",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateTeam(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

// TestCreateTeam_MethodNotAllowed tests that non-POST requests are rejected.
func TestCreateTeam_MethodNotAllowed(t *testing.T) {
	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams", nil)
	w := httptest.NewRecorder()

	handler.CreateTeam(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

// TestUpdateTeam_Success tests successful team update.
func TestUpdateTeam_Success(t *testing.T) {
	now := time.Now()
	mock := &MockTeamService{
		UpdateTeamFn: func(id string, team domain.Team) (*domain.Team, error) {
			return &domain.Team{
				ID:          id,
				Name:        team.Name,
				Description: team.Description,
				CreatedAt:   now,
				UpdatedAt:   now,
			}, nil
		},
	}

	body := map[string]interface{}{
		"name":        "Updated Team",
		"description": "Updated description",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/teams/t-platform", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateTeam(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var team domain.Team
	if err := json.NewDecoder(w.Body).Decode(&team); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if team.Name != "Updated Team" {
		t.Errorf("expected name 'Updated Team', got %s", team.Name)
	}
}

// TestUpdateTeam_InvalidJSON tests 400 response for malformed JSON.
func TestUpdateTeam_InvalidJSON(t *testing.T) {
	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/teams/t-platform", bytes.NewReader([]byte("bad json")))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateTeam(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestUpdateTeam_EmptyID tests 400 response when team ID is empty.
func TestUpdateTeam_EmptyID(t *testing.T) {
	body := map[string]interface{}{
		"name": "Updated Team",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/teams/", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateTeam(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestUpdateTeam_ServiceError tests error handling when service fails.
func TestUpdateTeam_ServiceError(t *testing.T) {
	mock := &MockTeamService{
		UpdateTeamFn: func(id string, team domain.Team) (*domain.Team, error) {
			return nil, ErrMockServiceFailed
		},
	}

	body := map[string]interface{}{
		"name": "Updated Team",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/teams/t-platform", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateTeam(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

// TestUpdateTeam_MethodNotAllowed tests that non-PUT requests are rejected.
func TestUpdateTeam_MethodNotAllowed(t *testing.T) {
	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/t-platform", nil)
	w := httptest.NewRecorder()

	handler.UpdateTeam(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

// TestDeleteTeam_Success tests successful team deletion.
func TestDeleteTeam_Success(t *testing.T) {
	mock := &MockTeamService{
		DeleteTeamFn: func(id string) error {
			return nil
		},
	}

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/t-platform", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteTeam(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
}

// TestDeleteTeam_EmptyID tests 400 response when team ID is empty.
func TestDeleteTeam_EmptyID(t *testing.T) {
	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteTeam(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestDeleteTeam_ServiceError tests error handling when service fails.
func TestDeleteTeam_ServiceError(t *testing.T) {
	mock := &MockTeamService{
		DeleteTeamFn: func(id string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/t-platform", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteTeam(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

// TestDeleteTeam_MethodNotAllowed tests that non-DELETE requests are rejected.
func TestDeleteTeam_MethodNotAllowed(t *testing.T) {
	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams/t-platform", nil)
	w := httptest.NewRecorder()

	handler.DeleteTeam(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

// TestCreateTeam_EmptyNameString tests 400 response when name is empty string.
func TestCreateTeam_EmptyNameString(t *testing.T) {
	body := map[string]interface{}{
		"name": "",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewTeamHandler(&MockTeamService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateTeam(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestListTeams_InvalidPagination tests handling of invalid pagination parameters.
func TestListTeams_InvalidPagination(t *testing.T) {
	var capturedPage, capturedPerPage int
	mock := &MockTeamService{
		ListTeamsFn: func(page, perPage int) ([]domain.Team, int64, error) {
			capturedPage = page
			capturedPerPage = perPage
			return []domain.Team{}, 0, nil
		},
	}

	handler := NewTeamHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams?page=invalid&per_page=bad", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListTeams(w, req)

	// Should use defaults when parsing fails
	if capturedPage != 1 {
		t.Errorf("expected default page 1, got %d", capturedPage)
	}
	if capturedPerPage != 50 {
		t.Errorf("expected default per_page 50, got %d", capturedPerPage)
	}
}
