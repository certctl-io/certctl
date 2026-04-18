package handler

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// NotificationService defines the service interface for notification operations.
type NotificationService interface {
	ListNotifications(ctx context.Context, page, perPage int) ([]domain.NotificationEvent, int64, error)
	GetNotification(ctx context.Context, id string) (*domain.NotificationEvent, error)
	MarkAsRead(ctx context.Context, id string) error
}

// NotificationHandler handles HTTP requests for notification operations.
type NotificationHandler struct {
	svc NotificationService
}

// NewNotificationHandler creates a new NotificationHandler with a service dependency.
func NewNotificationHandler(svc NotificationService) NotificationHandler {
	return NotificationHandler{svc: svc}
}

// ListNotifications lists notifications.
// GET /api/v1/notifications?page=1&per_page=50
func (h NotificationHandler) ListNotifications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	page := 1
	perPage := 50
	query := r.URL.Query()
	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if pp := query.Get("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil && parsed > 0 && parsed <= 500 {
			perPage = parsed
		}
	}

	notifications, total, err := h.svc.ListNotifications(r.Context(), page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list notifications", requestID)
		return
	}

	response := PagedResponse{
		Data:    notifications,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetNotification retrieves a single notification by ID.
// GET /api/v1/notifications/{id}
func (h NotificationHandler) GetNotification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/notifications/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Notification ID is required", requestID)
		return
	}
	id = parts[0]

	notification, err := h.svc.GetNotification(r.Context(), id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Notification not found", requestID)
		return
	}

	JSON(w, http.StatusOK, notification)
}

// MarkAsRead marks a notification as read.
// POST /api/v1/notifications/{id}/read
func (h NotificationHandler) MarkAsRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract notification ID from path /api/v1/notifications/{id}/read
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/notifications/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Notification ID is required", requestID)
		return
	}
	notificationID := parts[0]

	if err := h.svc.MarkAsRead(r.Context(), notificationID); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to mark notification as read", requestID)
		return
	}

	response := map[string]string{
		"status": "marked_as_read",
	}

	JSON(w, http.StatusOK, response)
}
