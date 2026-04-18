package handler

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// AuditService defines the service interface for audit event operations.
type AuditService interface {
	ListAuditEvents(ctx context.Context, page, perPage int) ([]domain.AuditEvent, int64, error)
	GetAuditEvent(ctx context.Context, id string) (*domain.AuditEvent, error)
}

// AuditHandler handles HTTP requests for audit event operations.
type AuditHandler struct {
	svc AuditService
}

// NewAuditHandler creates a new AuditHandler with a service dependency.
func NewAuditHandler(svc AuditService) AuditHandler {
	return AuditHandler{svc: svc}
}

// ListAuditEvents lists audit events.
// GET /api/v1/audit?page=1&per_page=50
func (h AuditHandler) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
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

	events, total, err := h.svc.ListAuditEvents(r.Context(), page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list audit events", requestID)
		return
	}

	response := PagedResponse{
		Data:    events,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetAuditEvent retrieves a single audit event by ID.
// GET /api/v1/audit/{id}
func (h AuditHandler) GetAuditEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/audit/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Audit event ID is required", requestID)
		return
	}
	id = parts[0]

	event, err := h.svc.GetAuditEvent(r.Context(), id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Audit event not found", requestID)
		return
	}

	JSON(w, http.StatusOK, event)
}
