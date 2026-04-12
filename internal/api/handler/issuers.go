package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// IssuerService defines the service interface for issuer operations.
type IssuerService interface {
	ListIssuers(page, perPage int) ([]domain.Issuer, int64, error)
	GetIssuer(id string) (*domain.Issuer, error)
	CreateIssuer(issuer domain.Issuer) (*domain.Issuer, error)
	UpdateIssuer(id string, issuer domain.Issuer) (*domain.Issuer, error)
	DeleteIssuer(id string) error
	TestConnection(id string) error
}

// IssuerHandler handles HTTP requests for issuer operations.
type IssuerHandler struct {
	svc    IssuerService
	logger *slog.Logger
}

// NewIssuerHandler creates a new IssuerHandler with a service dependency.
func NewIssuerHandler(svc IssuerService) IssuerHandler {
	return IssuerHandler{svc: svc, logger: slog.Default()}
}

// NewIssuerHandlerWithLogger creates a new IssuerHandler with a custom logger.
func NewIssuerHandlerWithLogger(svc IssuerService, logger *slog.Logger) IssuerHandler {
	return IssuerHandler{svc: svc, logger: logger}
}

// ListIssuers lists all configured issuers.
// GET /api/v1/issuers?page=1&per_page=50
func (h IssuerHandler) ListIssuers(w http.ResponseWriter, r *http.Request) {
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

	issuers, total, err := h.svc.ListIssuers(page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list issuers", requestID)
		return
	}

	response := PagedResponse{
		Data:    issuers,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetIssuer retrieves a single issuer by ID.
// GET /api/v1/issuers/{id}
func (h IssuerHandler) GetIssuer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/issuers/")
	if id == "" || strings.Contains(id, "/") {
		ErrorWithRequestID(w, http.StatusBadRequest, "Issuer ID is required", requestID)
		return
	}

	issuer, err := h.svc.GetIssuer(id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Issuer not found", requestID)
		return
	}

	JSON(w, http.StatusOK, issuer)
}

// CreateIssuer creates a new issuer configuration.
// POST /api/v1/issuers
func (h IssuerHandler) CreateIssuer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	var issuer domain.Issuer
	if err := json.NewDecoder(r.Body).Decode(&issuer); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate required fields
	if err := ValidateRequired("name", issuer.Name); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateStringLength("name", issuer.Name, 255); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if issuer.Type == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "type is required", requestID)
		return
	}

	created, err := h.svc.CreateIssuer(issuer)
	if err != nil {
		h.logger.Error("failed to create issuer", "error", err, "name", issuer.Name, "type", issuer.Type)
		errMsg := err.Error()
		switch {
		case strings.Contains(errMsg, "unique") || strings.Contains(errMsg, "duplicate"):
			ErrorWithRequestID(w, http.StatusConflict, "An issuer with this name already exists", requestID)
		case strings.Contains(errMsg, "unsupported issuer type"):
			ErrorWithRequestID(w, http.StatusBadRequest, errMsg, requestID)
		default:
			ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to create issuer", requestID)
		}
		return
	}

	JSON(w, http.StatusCreated, created)
}

// UpdateIssuer updates an existing issuer configuration.
// PUT /api/v1/issuers/{id}
func (h IssuerHandler) UpdateIssuer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/issuers/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Issuer ID is required", requestID)
		return
	}
	id = parts[0]

	var issuer domain.Issuer
	if err := json.NewDecoder(r.Body).Decode(&issuer); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	updated, err := h.svc.UpdateIssuer(id, issuer)
	if err != nil {
		h.logger.Error("failed to update issuer", "error", err, "id", id)
		errMsg := err.Error()
		switch {
		case strings.Contains(errMsg, "unique") || strings.Contains(errMsg, "duplicate"):
			ErrorWithRequestID(w, http.StatusConflict, "An issuer with this name already exists", requestID)
		case strings.Contains(errMsg, "not found"):
			ErrorWithRequestID(w, http.StatusNotFound, "Issuer not found", requestID)
		default:
			ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to update issuer", requestID)
		}
		return
	}

	JSON(w, http.StatusOK, updated)
}

// DeleteIssuer deletes an issuer configuration.
// DELETE /api/v1/issuers/{id}
func (h IssuerHandler) DeleteIssuer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/issuers/")
	if id == "" || strings.Contains(id, "/") {
		ErrorWithRequestID(w, http.StatusBadRequest, "Issuer ID is required", requestID)
		return
	}

	if err := h.svc.DeleteIssuer(id); err != nil {
		if strings.Contains(err.Error(), "violates foreign key") || strings.Contains(err.Error(), "RESTRICT") {
			ErrorWithRequestID(w, http.StatusConflict, "Cannot delete issuer: certificates are still using this issuer", requestID)
		} else if strings.Contains(err.Error(), "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, "Issuer not found", requestID)
		} else {
			ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to delete issuer", requestID)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TestConnection tests the connection to an issuer.
// POST /api/v1/issuers/{id}/test
func (h IssuerHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract issuer ID from path /api/v1/issuers/{id}/test
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/issuers/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Issuer ID is required", requestID)
		return
	}
	issuerID := parts[0]

	if err := h.svc.TestConnection(issuerID); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Connection test failed", requestID)
		return
	}

	response := map[string]string{
		"status": "connection_successful",
	}

	JSON(w, http.StatusOK, response)
}
