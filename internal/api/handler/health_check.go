package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// HealthCheckServicer defines the interface used by the health check handler.
type HealthCheckServicer interface {
	Create(ctx context.Context, check *domain.EndpointHealthCheck) error
	Get(ctx context.Context, id string) (*domain.EndpointHealthCheck, error)
	Update(ctx context.Context, check *domain.EndpointHealthCheck) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter *repository.HealthCheckFilter) ([]*domain.EndpointHealthCheck, int, error)
	GetHistory(ctx context.Context, healthCheckID string, limit int) ([]*domain.HealthHistoryEntry, error)
	AcknowledgeIncident(ctx context.Context, id string, actor string) error
	GetSummary(ctx context.Context) (*domain.HealthCheckSummary, error)
}

// HealthCheckHandler handles HTTP requests for TLS health monitoring.
type HealthCheckHandler struct {
	service HealthCheckServicer
}

// NewHealthCheckHandler creates a new health check handler.
func NewHealthCheckHandler(service HealthCheckServicer) *HealthCheckHandler {
	return &HealthCheckHandler{service: service}
}

// ListHealthChecks handles GET /api/v1/health-checks
func (h *HealthCheckHandler) ListHealthChecks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	query := r.URL.Query()
	status := query.Get("status")
	certificateID := query.Get("certificate_id")
	networkScanTargetID := query.Get("network_scan_target_id")
	enabledStr := query.Get("enabled")
	page := parseIntDefault(query.Get("page"), 1)
	perPage := parseIntDefault(query.Get("per_page"), 50)
	if perPage > 500 {
		perPage = 50
	}

	// Parse enabled flag if provided
	var enabledFilter *bool
	if enabledStr != "" {
		enabled := enabledStr == "true"
		enabledFilter = &enabled
	}

	filter := &repository.HealthCheckFilter{
		Status:               status,
		CertificateID:        certificateID,
		NetworkScanTargetID:  networkScanTargetID,
		Enabled:              enabledFilter,
		Page:                 page,
		PerPage:              perPage,
	}

	checks, total, err := h.service.List(r.Context(), filter)
	if err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to list health checks: %v", err))
		return
	}

	if checks == nil {
		checks = make([]*domain.EndpointHealthCheck, 0)
	}

	JSON(w, http.StatusOK, PagedResponse{
		Data:    checks,
		Total:   int64(total),
		Page:    page,
		PerPage: perPage,
	})
}

// GetHealthCheck handles GET /api/v1/health-checks/{id}
func (h *HealthCheckHandler) GetHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "health check ID is required")
		return
	}

	check, err := h.service.Get(r.Context(), id)
	if err != nil {
		Error(w, http.StatusNotFound, fmt.Sprintf("health check not found: %v", err))
		return
	}

	JSON(w, http.StatusOK, check)
}

// CreateHealthCheck handles POST /api/v1/health-checks
func (h *HealthCheckHandler) CreateHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var check domain.EndpointHealthCheck
	if err := json.NewDecoder(r.Body).Decode(&check); err != nil {
		Error(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if check.Endpoint == "" {
		Error(w, http.StatusBadRequest, "endpoint is required")
		return
	}

	// Set defaults
	if check.CheckIntervalSecs <= 0 {
		check.CheckIntervalSecs = 300
	}
	if check.DegradedThreshold <= 0 {
		check.DegradedThreshold = 2
	}
	if check.DownThreshold <= 0 {
		check.DownThreshold = 5
	}
	if check.Status == "" {
		check.Status = domain.HealthStatusUnknown
	}

	if err := h.service.Create(r.Context(), &check); err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to create health check: %v", err))
		return
	}

	JSON(w, http.StatusCreated, check)
}

// UpdateHealthCheck handles PUT /api/v1/health-checks/{id}
func (h *HealthCheckHandler) UpdateHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "health check ID is required")
		return
	}

	// Get existing check
	existing, err := h.service.Get(r.Context(), id)
	if err != nil {
		Error(w, http.StatusNotFound, fmt.Sprintf("health check not found: %v", err))
		return
	}

	var updates domain.EndpointHealthCheck
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		Error(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	// Merge updates (only update provided fields)
	if updates.Endpoint != "" {
		existing.Endpoint = updates.Endpoint
	}
	if updates.ExpectedFingerprint != "" {
		existing.ExpectedFingerprint = updates.ExpectedFingerprint
	}
	if updates.CheckIntervalSecs > 0 {
		existing.CheckIntervalSecs = updates.CheckIntervalSecs
	}
	if updates.DegradedThreshold > 0 {
		existing.DegradedThreshold = updates.DegradedThreshold
	}
	if updates.DownThreshold > 0 {
		existing.DownThreshold = updates.DownThreshold
	}
	existing.Enabled = updates.Enabled

	if err := h.service.Update(r.Context(), existing); err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to update health check: %v", err))
		return
	}

	JSON(w, http.StatusOK, existing)
}

// DeleteHealthCheck handles DELETE /api/v1/health-checks/{id}
func (h *HealthCheckHandler) DeleteHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "health check ID is required")
		return
	}

	if err := h.service.Delete(r.Context(), id); err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete health check: %v", err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetHealthCheckHistory handles GET /api/v1/health-checks/{id}/history
func (h *HealthCheckHandler) GetHealthCheckHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "health check ID is required")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if limit > 1000 {
		limit = 1000
	}

	history, err := h.service.GetHistory(r.Context(), id, limit)
	if err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to get health check history: %v", err))
		return
	}

	if history == nil {
		history = make([]*domain.HealthHistoryEntry, 0)
	}

	JSON(w, http.StatusOK, history)
}

// AcknowledgeHealthCheck handles POST /api/v1/health-checks/{id}/acknowledge
func (h *HealthCheckHandler) AcknowledgeHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "health check ID is required")
		return
	}

	var req struct {
		Actor string `json:"actor,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.Actor == "" {
		req.Actor = "unknown"
	}

	if err := h.service.AcknowledgeIncident(r.Context(), id, req.Actor); err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to acknowledge health check: %v", err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetHealthCheckSummary handles GET /api/v1/health-checks/summary
// This route must be registered BEFORE the /{id} routes
func (h *HealthCheckHandler) GetHealthCheckSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	summary, err := h.service.GetSummary(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to get health check summary: %v", err))
		return
	}

	JSON(w, http.StatusOK, summary)
}
