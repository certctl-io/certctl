package handler

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/domain"
)

// AuditService defines the service interface for audit event operations.
type AuditService interface {
	ListAuditEvents(ctx context.Context, page, perPage int) ([]domain.AuditEvent, int64, error)
	GetAuditEvent(ctx context.Context, id string) (*domain.AuditEvent, error)
	// ListAuditEventsByCategory (Bundle 1 Phase 8) returns audit
	// rows whose event_category column matches eventCategory.
	// eventCategory is one of "cert_lifecycle", "auth", "config";
	// empty string returns all categories. Used by the auditor role
	// (filtered to "auth" via /v1/audit?category=auth).
	ListAuditEventsByCategory(ctx context.Context, eventCategory string, page, perPage int) ([]domain.AuditEvent, int64, error)
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
// GET /api/v1/audit?page=1&per_page=50&category=auth
//
// Bundle 1 Phase 8 adds the optional `category` query parameter for
// auditor-role filtering. Allowed values: cert_lifecycle, auth, config.
// Unknown values surface 400 so misuse is caught loud (instead of
// silently returning all rows).
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
	category := query.Get("category")
	if category != "" {
		switch category {
		case domain.EventCategoryCertLifecycle, domain.EventCategoryAuth, domain.EventCategoryConfig:
			// ok
		default:
			ErrorWithRequestID(w, http.StatusBadRequest,
				"Invalid category — allowed: cert_lifecycle, auth, config",
				requestID)
			return
		}
	}

	var (
		events []domain.AuditEvent
		total  int64
		err    error
	)
	if category != "" {
		events, total, err = h.svc.ListAuditEventsByCategory(r.Context(), category, page, perPage)
	} else {
		events, total, err = h.svc.ListAuditEvents(r.Context(), page, perPage)
	}
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
