package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// mockAuditService implements AuditService for testing.
type mockAuditService struct {
	listFunc func(page, perPage int) ([]domain.AuditEvent, int64, error)
	getFunc  func(id string) (*domain.AuditEvent, error)
}

func (m *mockAuditService) ListAuditEvents(_ context.Context, page, perPage int) ([]domain.AuditEvent, int64, error) {
	if m.listFunc != nil {
		return m.listFunc(page, perPage)
	}
	return nil, 0, nil
}

func (m *mockAuditService) GetAuditEvent(_ context.Context, id string) (*domain.AuditEvent, error) {
	if m.getFunc != nil {
		return m.getFunc(id)
	}
	return nil, nil
}

func TestListAuditEvents_Success(t *testing.T) {
	events := []domain.AuditEvent{
		{
			ID:           "ev-1",
			Action:       "certificate_issued",
			Actor:        "user@example.com",
			ActorType:    domain.ActorTypeUser,
			ResourceID:   "mc-api-prod",
			ResourceType: "Certificate",
			Timestamp:    time.Now(),
		},
		{
			ID:           "ev-2",
			Action:       "certificate_renewed",
			Actor:        "user@example.com",
			ActorType:    domain.ActorTypeUser,
			ResourceID:   "mc-api-prod",
			ResourceType: "Certificate",
			Timestamp:    time.Now(),
		},
	}

	mockSvc := &mockAuditService{
		listFunc: func(page, perPage int) ([]domain.AuditEvent, int64, error) {
			if page != 1 || perPage != 50 {
				t.Errorf("ListAuditEvents called with page=%d, perPage=%d, expected 1, 50", page, perPage)
			}
			return events, 2, nil
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	// Add request ID to context
	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusOK)
	}

	var result PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Total != 2 {
		t.Errorf("Total = %d, want 2", result.Total)
	}

	if result.Page != 1 {
		t.Errorf("Page = %d, want 1", result.Page)
	}

	if result.PerPage != 50 {
		t.Errorf("PerPage = %d, want 50", result.PerPage)
	}

	// Check data is present
	if result.Data == nil {
		t.Error("Data is nil, want events slice")
	}
}

func TestListAuditEvents_WithPagination(t *testing.T) {
	events := []domain.AuditEvent{
		{
			ID:           "ev-5",
			Action:       "certificate_issued",
			Actor:        "user@example.com",
			ActorType:    domain.ActorTypeUser,
			ResourceID:   "mc-api-prod",
			ResourceType: "Certificate",
			Timestamp:    time.Now(),
		},
	}

	mockSvc := &mockAuditService{
		listFunc: func(page, perPage int) ([]domain.AuditEvent, int64, error) {
			if page != 2 || perPage != 25 {
				t.Errorf("ListAuditEvents called with page=%d, perPage=%d, expected 2, 25", page, perPage)
			}
			return events, 100, nil
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit?page=2&per_page=25", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusOK)
	}

	var result PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Page != 2 {
		t.Errorf("Page = %d, want 2", result.Page)
	}

	if result.PerPage != 25 {
		t.Errorf("PerPage = %d, want 25", result.PerPage)
	}
}

func TestListAuditEvents_PerPageMaxLimit(t *testing.T) {
	mockSvc := &mockAuditService{
		listFunc: func(page, perPage int) ([]domain.AuditEvent, int64, error) {
			// Should be capped at 500
			if perPage > 500 {
				t.Errorf("perPage = %d, expected <= 500", perPage)
			}
			return []domain.AuditEvent{}, 0, nil
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit?per_page=1000", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusOK)
	}

	var result PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.PerPage > 500 {
		t.Errorf("PerPage = %d, want <= 500", result.PerPage)
	}
}

func TestListAuditEvents_EmptyResult(t *testing.T) {
	mockSvc := &mockAuditService{
		listFunc: func(page, perPage int) ([]domain.AuditEvent, int64, error) {
			return []domain.AuditEvent{}, 0, nil
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusOK)
	}

	var result PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Total != 0 {
		t.Errorf("Total = %d, want 0", result.Total)
	}
}

func TestListAuditEvents_ServiceError(t *testing.T) {
	mockSvc := &mockAuditService{
		listFunc: func(page, perPage int) ([]domain.AuditEvent, int64, error) {
			return nil, 0, errors.New("database error")
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusInternalServerError {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusInternalServerError)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Message != "Failed to list audit events" {
		t.Errorf("Message = %q, want 'Failed to list audit events'", errResp.Message)
	}
}

func TestListAuditEvents_MethodNotAllowed(t *testing.T) {
	mockSvc := &mockAuditService{}
	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodPost, "/api/v1/audit", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ListAuditEvents(w, req)

	if status := w.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("ListAuditEvents returned status %d, want %d", status, http.StatusMethodNotAllowed)
	}
}

func TestGetAuditEvent_Success(t *testing.T) {
	event := &domain.AuditEvent{
		ID:           "ev-123",
		Action:       "certificate_issued",
		Actor:        "user@example.com",
		ActorType:    domain.ActorTypeUser,
		ResourceID:   "mc-api-prod",
		ResourceType: "Certificate",
		Timestamp:    time.Now(),
	}

	mockSvc := &mockAuditService{
		getFunc: func(id string) (*domain.AuditEvent, error) {
			if id != "ev-123" {
				t.Errorf("GetAuditEvent called with id=%q, expected ev-123", id)
			}
			return event, nil
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit/ev-123", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.GetAuditEvent(w, req)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("GetAuditEvent returned status %d, want %d", status, http.StatusOK)
	}

	var result domain.AuditEvent
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.ID != "ev-123" {
		t.Errorf("ID = %q, want ev-123", result.ID)
	}

	if result.Action != "certificate_issued" {
		t.Errorf("Action = %q, want certificate_issued", result.Action)
	}
}

func TestGetAuditEvent_NotFound(t *testing.T) {
	mockSvc := &mockAuditService{
		getFunc: func(id string) (*domain.AuditEvent, error) {
			return nil, errors.New("not found")
		},
	}

	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit/nonexistent", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.GetAuditEvent(w, req)

	if status := w.Code; status != http.StatusNotFound {
		t.Errorf("GetAuditEvent returned status %d, want %d", status, http.StatusNotFound)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Message != "Audit event not found" {
		t.Errorf("Message = %q, want 'Audit event not found'", errResp.Message)
	}
}

func TestGetAuditEvent_MethodNotAllowed(t *testing.T) {
	mockSvc := &mockAuditService{}
	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodDelete, "/api/v1/audit/ev-123", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.GetAuditEvent(w, req)

	if status := w.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("GetAuditEvent returned status %d, want %d", status, http.StatusMethodNotAllowed)
	}
}

func TestGetAuditEvent_EmptyID(t *testing.T) {
	mockSvc := &mockAuditService{}
	handler := NewAuditHandler(mockSvc)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/audit/", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	ctx := context.WithValue(req.Context(), middleware.RequestIDKey{}, "test-req-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.GetAuditEvent(w, req)

	if status := w.Code; status != http.StatusBadRequest {
		t.Errorf("GetAuditEvent returned status %d, want %d", status, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Message != "Audit event ID is required" {
		t.Errorf("Message = %q, want 'Audit event ID is required'", errResp.Message)
	}
}
