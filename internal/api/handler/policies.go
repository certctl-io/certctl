package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/domain"
)

// PolicyService defines the service interface for policy rule operations.
type PolicyService interface {
	ListPolicies(ctx context.Context, page, perPage int) ([]domain.PolicyRule, int64, error)
	GetPolicy(ctx context.Context, id string) (*domain.PolicyRule, error)
	CreatePolicy(ctx context.Context, policy domain.PolicyRule) (*domain.PolicyRule, error)
	UpdatePolicy(ctx context.Context, id string, policy domain.PolicyRule) (*domain.PolicyRule, error)
	DeletePolicy(ctx context.Context, id string) error
	ListViolations(ctx context.Context, policyID string, page, perPage int) ([]domain.PolicyViolation, int64, error)
}

// PolicyHandler handles HTTP requests for policy rule operations.
type PolicyHandler struct {
	svc PolicyService
}

// NewPolicyHandler creates a new PolicyHandler with a service dependency.
func NewPolicyHandler(svc PolicyService) PolicyHandler {
	return PolicyHandler{svc: svc}
}

// ListPolicies lists all policy rules.
// GET /api/v1/policies?page=1&per_page=50
func (h PolicyHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
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

	policies, total, err := h.svc.ListPolicies(r.Context(), page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list policies", requestID)
		return
	}

	response := PagedResponse{
		Data:    policies,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetPolicy retrieves a single policy rule by ID.
// GET /api/v1/policies/{id}
func (h PolicyHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Policy ID is required", requestID)
		return
	}
	id = parts[0]

	policy, err := h.svc.GetPolicy(r.Context(), id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Policy not found", requestID)
		return
	}

	JSON(w, http.StatusOK, policy)
}

// CreatePolicy creates a new policy rule.
// POST /api/v1/policies
func (h PolicyHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	var policy domain.PolicyRule
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate required fields
	if err := ValidateRequired("name", policy.Name); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if policy.Type == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "type is required", requestID)
		return
	}
	if err := ValidatePolicyType(policy.Type); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	// Severity is optional on create; default matches the DB default.
	// Any explicit value must pass the TitleCase allowlist; the DB CHECK
	// constraint enforces the same set, but catching it here gives a 400
	// with a clear message instead of a 500 on constraint violation.
	if policy.Severity == "" {
		policy.Severity = domain.PolicySeverityWarning
	}
	if err := ValidatePolicySeverity(policy.Severity); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}

	created, err := h.svc.CreatePolicy(r.Context(), policy)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to create policy", requestID)
		return
	}

	JSON(w, http.StatusCreated, created)
}

// UpdatePolicy updates an existing policy rule.
// PUT /api/v1/policies/{id}
func (h PolicyHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Policy ID is required", requestID)
		return
	}
	id = parts[0]

	var policy domain.PolicyRule
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate fields if provided
	if policy.Name != "" {
		if err := ValidateStringLength("name", policy.Name, 255); err != nil {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
	}
	if policy.Type != "" {
		if err := ValidatePolicyType(policy.Type); err != nil {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
	}
	if policy.Severity != "" {
		if err := ValidatePolicySeverity(policy.Severity); err != nil {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
	}

	updated, err := h.svc.UpdatePolicy(r.Context(), id, policy)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to update policy", requestID)
		return
	}

	JSON(w, http.StatusOK, updated)
}

// DeletePolicy deletes a policy rule.
// DELETE /api/v1/policies/{id}
func (h PolicyHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Policy ID is required", requestID)
		return
	}
	id = parts[0]

	if err := h.svc.DeletePolicy(r.Context(), id); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to delete policy", requestID)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListViolations lists policy violations for a specific policy rule.
// GET /api/v1/policies/{id}/violations?page=1&per_page=50
func (h PolicyHandler) ListViolations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract policy ID from path /api/v1/policies/{id}/violations
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Policy ID is required", requestID)
		return
	}
	policyID := parts[0]

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

	violations, total, err := h.svc.ListViolations(r.Context(), policyID, page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list violations", requestID)
		return
	}

	response := PagedResponse{
		Data:    violations,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}
