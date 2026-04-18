package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// MockNotificationService is a mock implementation of NotificationService interface.
type MockNotificationService struct {
	ListNotificationsFn func(page, perPage int) ([]domain.NotificationEvent, int64, error)
	GetNotificationFn   func(id string) (*domain.NotificationEvent, error)
	MarkAsReadFn        func(id string) error
}

func (m *MockNotificationService) ListNotifications(_ context.Context, page, perPage int) ([]domain.NotificationEvent, int64, error) {
	if m.ListNotificationsFn != nil {
		return m.ListNotificationsFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *MockNotificationService) GetNotification(_ context.Context, id string) (*domain.NotificationEvent, error) {
	if m.GetNotificationFn != nil {
		return m.GetNotificationFn(id)
	}
	return nil, nil
}

func (m *MockNotificationService) MarkAsRead(_ context.Context, id string) error {
	if m.MarkAsReadFn != nil {
		return m.MarkAsReadFn(id)
	}
	return nil
}

func TestListNotifications_Success(t *testing.T) {
	now := time.Now()
	certID := "mc-prod-001"
	n1 := domain.NotificationEvent{
		ID:            "notif-001",
		Type:          domain.NotificationTypeExpirationWarning,
		CertificateID: &certID,
		Channel:       domain.NotificationChannelEmail,
		Recipient:     "admin@example.com",
		Message:       "Certificate expiring in 30 days",
		Status:        "sent",
		CreatedAt:     now,
	}
	n2 := domain.NotificationEvent{
		ID:            "notif-002",
		Type:          domain.NotificationTypeRenewalSuccess,
		CertificateID: &certID,
		Channel:       domain.NotificationChannelWebhook,
		Recipient:     "https://hooks.example.com/cert",
		Message:       "Certificate renewed successfully",
		Status:        "sent",
		CreatedAt:     now,
	}

	mock := &MockNotificationService{
		ListNotificationsFn: func(page, perPage int) ([]domain.NotificationEvent, int64, error) {
			return []domain.NotificationEvent{n1, n2}, 2, nil
		},
	}

	handler := NewNotificationHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListNotifications(w, req)

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

func TestListNotifications_Pagination(t *testing.T) {
	var capturedPage, capturedPerPage int
	mock := &MockNotificationService{
		ListNotificationsFn: func(page, perPage int) ([]domain.NotificationEvent, int64, error) {
			capturedPage = page
			capturedPerPage = perPage
			return []domain.NotificationEvent{}, 0, nil
		},
	}

	handler := NewNotificationHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications?page=2&per_page=10", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListNotifications(w, req)

	if capturedPage != 2 {
		t.Errorf("expected page 2, got %d", capturedPage)
	}
	if capturedPerPage != 10 {
		t.Errorf("expected per_page 10, got %d", capturedPerPage)
	}
}

func TestListNotifications_ServiceError(t *testing.T) {
	mock := &MockNotificationService{
		ListNotificationsFn: func(page, perPage int) ([]domain.NotificationEvent, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewNotificationHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListNotifications(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestListNotifications_MethodNotAllowed(t *testing.T) {
	handler := NewNotificationHandler(&MockNotificationService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications", nil)
	w := httptest.NewRecorder()

	handler.ListNotifications(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestGetNotification_Success(t *testing.T) {
	now := time.Now()
	certID := "mc-prod-001"
	mock := &MockNotificationService{
		GetNotificationFn: func(id string) (*domain.NotificationEvent, error) {
			return &domain.NotificationEvent{
				ID:            id,
				Type:          domain.NotificationTypeExpirationWarning,
				CertificateID: &certID,
				Channel:       domain.NotificationChannelEmail,
				Recipient:     "admin@example.com",
				Message:       "Certificate expiring",
				Status:        "sent",
				CreatedAt:     now,
			}, nil
		},
	}

	handler := NewNotificationHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications/notif-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetNotification(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestGetNotification_NotFound(t *testing.T) {
	mock := &MockNotificationService{
		GetNotificationFn: func(id string) (*domain.NotificationEvent, error) {
			return nil, ErrMockNotFound
		},
	}

	handler := NewNotificationHandler(mock)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetNotification(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestGetNotification_EmptyID(t *testing.T) {
	handler := NewNotificationHandler(&MockNotificationService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetNotification(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestMarkAsRead_Success(t *testing.T) {
	var markedID string
	mock := &MockNotificationService{
		MarkAsReadFn: func(id string) error {
			markedID = id
			return nil
		},
	}

	handler := NewNotificationHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/notif-001/read", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.MarkAsRead(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if markedID != "notif-001" {
		t.Errorf("expected marked ID 'notif-001', got '%s'", markedID)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "marked_as_read" {
		t.Errorf("expected status 'marked_as_read', got '%s'", resp["status"])
	}
}

func TestMarkAsRead_ServiceError(t *testing.T) {
	mock := &MockNotificationService{
		MarkAsReadFn: func(id string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewNotificationHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/notif-001/read", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.MarkAsRead(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestMarkAsRead_MethodNotAllowed(t *testing.T) {
	handler := NewNotificationHandler(&MockNotificationService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications/notif-001/read", nil)
	w := httptest.NewRecorder()

	handler.MarkAsRead(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestMarkAsRead_EmptyID(t *testing.T) {
	handler := NewNotificationHandler(&MockNotificationService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications//read", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.MarkAsRead(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}
