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

// MockOwnerService is a mock implementation of OwnerService interface.
type MockOwnerService struct {
	ListOwnersFn  func(page, perPage int) ([]domain.Owner, int64, error)
	GetOwnerFn    func(id string) (*domain.Owner, error)
	CreateOwnerFn func(owner domain.Owner) (*domain.Owner, error)
	UpdateOwnerFn func(id string, owner domain.Owner) (*domain.Owner, error)
	DeleteOwnerFn func(id string) error
}

func (m *MockOwnerService) ListOwners(_ context.Context, page, perPage int) ([]domain.Owner, int64, error) {
	if m.ListOwnersFn != nil {
		return m.ListOwnersFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *MockOwnerService) GetOwner(_ context.Context, id string) (*domain.Owner, error) {
	if m.GetOwnerFn != nil {
		return m.GetOwnerFn(id)
	}
	return nil, nil
}

func (m *MockOwnerService) CreateOwner(_ context.Context, owner domain.Owner) (*domain.Owner, error) {
	if m.CreateOwnerFn != nil {
		return m.CreateOwnerFn(owner)
	}
	return nil, nil
}

func (m *MockOwnerService) UpdateOwner(_ context.Context, id string, owner domain.Owner) (*domain.Owner, error) {
	if m.UpdateOwnerFn != nil {
		return m.UpdateOwnerFn(id, owner)
	}
	return nil, nil
}

func (m *MockOwnerService) DeleteOwner(_ context.Context, id string) error {
	if m.DeleteOwnerFn != nil {
		return m.DeleteOwnerFn(id)
	}
	return nil
}

// TestListOwners_Success lists owners with pagination, verify data fields.
func TestListOwners_Success(t *testing.T) {
	now := time.Now()
	o1 := domain.Owner{
		ID:        "o-alice",
		Name:      "Alice",
		Email:     "alice@example.com",
		TeamID:    "t-platform",
		CreatedAt: now,
		UpdatedAt: now,
	}
	o2 := domain.Owner{
		ID:        "o-bob",
		Name:      "Bob",
		Email:     "bob@example.com",
		TeamID:    "t-ops",
		CreatedAt: now,
		UpdatedAt: now,
	}

	mock := &MockOwnerService{
		ListOwnersFn: func(page, perPage int) ([]domain.Owner, int64, error) {
			return []domain.Owner{o1, o2}, 2, nil
		},
	}

	handler := NewOwnerHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListOwners(w, req)

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

// TestListOwners_Pagination verifies pagination parameters are passed to service.
func TestListOwners_Pagination(t *testing.T) {
	var capturedPage, capturedPerPage int
	mock := &MockOwnerService{
		ListOwnersFn: func(page, perPage int) ([]domain.Owner, int64, error) {
			capturedPage = page
			capturedPerPage = perPage
			return []domain.Owner{}, 0, nil
		},
	}

	handler := NewOwnerHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners?page=3&per_page=25", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListOwners(w, req)

	if capturedPage != 3 {
		t.Errorf("expected page 3, got %d", capturedPage)
	}
	if capturedPerPage != 25 {
		t.Errorf("expected per_page 25, got %d", capturedPerPage)
	}
}

// TestListOwners_ServiceError returns 500 on service error.
func TestListOwners_ServiceError(t *testing.T) {
	mock := &MockOwnerService{
		ListOwnersFn: func(page, perPage int) ([]domain.Owner, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewOwnerHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListOwners(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

// TestListOwners_MethodNotAllowed returns 405 for non-GET methods.
func TestListOwners_MethodNotAllowed(t *testing.T) {
	handler := NewOwnerHandler(&MockOwnerService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/owners", nil)
	w := httptest.NewRecorder()

	handler.ListOwners(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

// TestGetOwner_Success returns owner with email and team_id.
func TestGetOwner_Success(t *testing.T) {
	now := time.Now()
	mock := &MockOwnerService{
		GetOwnerFn: func(id string) (*domain.Owner, error) {
			return &domain.Owner{
				ID:        id,
				Name:      "Alice",
				Email:     "alice@example.com",
				TeamID:    "t-platform",
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	}

	handler := NewOwnerHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners/o-alice", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetOwner(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var owner domain.Owner
	if err := json.NewDecoder(w.Body).Decode(&owner); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if owner.Email != "alice@example.com" {
		t.Errorf("expected email 'alice@example.com', got '%s'", owner.Email)
	}
	if owner.TeamID != "t-platform" {
		t.Errorf("expected team_id 't-platform', got '%s'", owner.TeamID)
	}
}

// TestGetOwner_NotFound returns 404 when owner not found.
func TestGetOwner_NotFound(t *testing.T) {
	mock := &MockOwnerService{
		GetOwnerFn: func(id string) (*domain.Owner, error) {
			return nil, ErrMockNotFound
		},
	}

	handler := NewOwnerHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetOwner(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

// TestGetOwner_EmptyID returns 400 for empty ID.
func TestGetOwner_EmptyID(t *testing.T) {
	handler := NewOwnerHandler(&MockOwnerService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetOwner(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestGetOwner_MethodNotAllowed returns 405 for non-GET methods.
func TestGetOwner_MethodNotAllowed(t *testing.T) {
	handler := NewOwnerHandler(&MockOwnerService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/owners/o-alice", nil)
	w := httptest.NewRecorder()

	handler.GetOwner(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

// TestCreateOwner_Success returns 201 with email and team_id.
func TestCreateOwner_Success(t *testing.T) {
	now := time.Now()
	mock := &MockOwnerService{
		CreateOwnerFn: func(owner domain.Owner) (*domain.Owner, error) {
			owner.ID = "o-new"
			owner.CreatedAt = now
			owner.UpdatedAt = now
			return &owner, nil
		},
	}

	body := domain.Owner{
		Name:   "Alice",
		Email:  "alice@example.com",
		TeamID: "t-platform",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewOwnerHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/owners", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateOwner(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", w.Code)
	}

	var owner domain.Owner
	if err := json.NewDecoder(w.Body).Decode(&owner); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if owner.Email != "alice@example.com" {
		t.Errorf("expected email 'alice@example.com', got '%s'", owner.Email)
	}
	if owner.TeamID != "t-platform" {
		t.Errorf("expected team_id 't-platform', got '%s'", owner.TeamID)
	}
}

// TestCreateOwner_InvalidJSON returns 400 for malformed JSON.
func TestCreateOwner_InvalidJSON(t *testing.T) {
	handler := NewOwnerHandler(&MockOwnerService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/owners", bytes.NewReader([]byte("not json")))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateOwner(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestCreateOwner_MissingName returns 400 when name is required.
func TestCreateOwner_MissingName(t *testing.T) {
	body := map[string]interface{}{
		"email":   "alice@example.com",
		"team_id": "t-platform",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewOwnerHandler(&MockOwnerService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/owners", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateOwner(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestCreateOwner_NameTooLong returns 400 for name exceeding 255 chars.
func TestCreateOwner_NameTooLong(t *testing.T) {
	longName := ""
	for i := 0; i < 256; i++ {
		longName += "x"
	}
	body := domain.Owner{
		Name:   longName,
		Email:  "alice@example.com",
		TeamID: "t-platform",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewOwnerHandler(&MockOwnerService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/owners", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateOwner(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestCreateOwner_ServiceError returns 500 on service error.
func TestCreateOwner_ServiceError(t *testing.T) {
	mock := &MockOwnerService{
		CreateOwnerFn: func(owner domain.Owner) (*domain.Owner, error) {
			return nil, ErrMockServiceFailed
		},
	}

	body := domain.Owner{
		Name:   "Alice",
		Email:  "alice@example.com",
		TeamID: "t-platform",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewOwnerHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/owners", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.CreateOwner(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

// TestCreateOwner_MethodNotAllowed returns 405 for non-POST methods.
func TestCreateOwner_MethodNotAllowed(t *testing.T) {
	handler := NewOwnerHandler(&MockOwnerService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
	w := httptest.NewRecorder()

	handler.CreateOwner(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

// TestUpdateOwner_Success returns 200 with updated data.
func TestUpdateOwner_Success(t *testing.T) {
	now := time.Now()
	mock := &MockOwnerService{
		UpdateOwnerFn: func(id string, owner domain.Owner) (*domain.Owner, error) {
			return &domain.Owner{
				ID:        id,
				Name:      owner.Name,
				Email:     owner.Email,
				TeamID:    owner.TeamID,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	}

	body := domain.Owner{
		Name:   "Alice Updated",
		Email:  "alice.updated@example.com",
		TeamID: "t-platform",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewOwnerHandler(mock)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/owners/o-alice", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateOwner(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var owner domain.Owner
	if err := json.NewDecoder(w.Body).Decode(&owner); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if owner.Name != "Alice Updated" {
		t.Errorf("expected name 'Alice Updated', got '%s'", owner.Name)
	}
}

// TestUpdateOwner_ServiceError returns 500 on service error.
func TestUpdateOwner_ServiceError(t *testing.T) {
	mock := &MockOwnerService{
		UpdateOwnerFn: func(id string, owner domain.Owner) (*domain.Owner, error) {
			return nil, ErrMockServiceFailed
		},
	}

	body := domain.Owner{
		Name:   "Alice Updated",
		Email:  "alice.updated@example.com",
		TeamID: "t-platform",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewOwnerHandler(mock)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/owners/o-alice", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateOwner(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

// TestUpdateOwner_EmptyID returns 400 for empty ID.
func TestUpdateOwner_EmptyID(t *testing.T) {
	body := domain.Owner{
		Name:   "Alice",
		Email:  "alice@example.com",
		TeamID: "t-platform",
	}
	bodyBytes, _ := json.Marshal(body)

	handler := NewOwnerHandler(&MockOwnerService{})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/owners/", bytes.NewReader(bodyBytes))
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.UpdateOwner(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestDeleteOwner_Success returns 204 No Content.
func TestDeleteOwner_Success(t *testing.T) {
	var deletedID string
	mock := &MockOwnerService{
		DeleteOwnerFn: func(id string) error {
			deletedID = id
			return nil
		},
	}

	handler := NewOwnerHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/owners/o-alice", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteOwner(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
	if deletedID != "o-alice" {
		t.Errorf("expected deleted ID 'o-alice', got '%s'", deletedID)
	}
}

// TestDeleteOwner_ServiceError returns 500 on service error.
func TestDeleteOwner_ServiceError(t *testing.T) {
	mock := &MockOwnerService{
		DeleteOwnerFn: func(id string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewOwnerHandler(mock)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/owners/o-alice", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteOwner(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

// TestDeleteOwner_EmptyID returns 400 for empty ID.
func TestDeleteOwner_EmptyID(t *testing.T) {
	handler := NewOwnerHandler(&MockOwnerService{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/owners/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.DeleteOwner(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// TestDeleteOwner_MethodNotAllowed returns 405 for non-DELETE methods.
func TestDeleteOwner_MethodNotAllowed(t *testing.T) {
	handler := NewOwnerHandler(&MockOwnerService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners/o-alice", nil)
	w := httptest.NewRecorder()

	handler.DeleteOwner(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}
