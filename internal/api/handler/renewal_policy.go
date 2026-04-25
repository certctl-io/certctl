package handler

import (
	"github.com/shankar0123/certctl/internal/repository"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/service"
)

// RenewalPolicyService defines the service interface for renewal policy
// operations. G-1: all methods take ctx so the handler can propagate
// request-scoped cancellation/deadlines through the full stack.
type RenewalPolicyService interface {
	ListRenewalPolicies(ctx context.Context, page, perPage int) ([]domain.RenewalPolicy, int64, error)
	GetRenewalPolicy(ctx context.Context, id string) (*domain.RenewalPolicy, error)
	CreateRenewalPolicy(ctx context.Context, rp domain.RenewalPolicy) (*domain.RenewalPolicy, error)
	UpdateRenewalPolicy(ctx context.Context, id string, rp domain.RenewalPolicy) (*domain.RenewalPolicy, error)
	DeleteRenewalPolicy(ctx context.Context, id string) error
}

// RenewalPolicyHandler serves /api/v1/renewal-policies CRUD endpoints.
//
// G-1 + S-2 design note: the service-level `ErrRenewalPolicyDuplicateName` /
// `ErrRenewalPolicyInUse` sentinels alias the repository sentinels (same var
// identity), so `errors.Is` walks transparently across layers. S-2 closure
// (cat-s6-efc7f6f6bd50) extends the same convention to not-found detection:
// repos now wrap `sql.ErrNoRows` via `fmt.Errorf("X not found: %w",
// repository.ErrNotFound)`, handler dispatch uses
// `errors.Is(err, repository.ErrNotFound)`, and `ErrMockNotFound` in
// test_utils.go wraps the same sentinel so the mocks still resolve to 404.
type RenewalPolicyHandler struct {
	svc RenewalPolicyService
}

// NewRenewalPolicyHandler constructs the handler with its service dependency.
// Returned by value to match the house pattern (PolicyHandler, IssuerHandler
// etc.) — the registry stores handlers by value in router.HandlerRegistry.
func NewRenewalPolicyHandler(svc RenewalPolicyService) RenewalPolicyHandler {
	return RenewalPolicyHandler{svc: svc}
}

// ListRenewalPolicies lists all renewal policies (paginated).
// GET /api/v1/renewal-policies?page=1&per_page=50
func (h RenewalPolicyHandler) ListRenewalPolicies(w http.ResponseWriter, r *http.Request) {
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

	policies, total, err := h.svc.ListRenewalPolicies(r.Context(), page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list renewal policies", requestID)
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

// GetRenewalPolicy retrieves a single renewal policy by ID.
// GET /api/v1/renewal-policies/{id}
func (h RenewalPolicyHandler) GetRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/renewal-policies/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Renewal policy ID is required", requestID)
		return
	}
	id = parts[0]

	policy, err := h.svc.GetRenewalPolicy(r.Context(), id)
	if err != nil {
		// Matches the PolicyHandler.GetPolicy convention: any error from the
		// service surfaces as 404. The repo wraps sql.ErrNoRows as
		// "renewal policy not found: %s" and there's no other expected failure
		// mode on Get — the caller gets a clean 404.
		ErrorWithRequestID(w, http.StatusNotFound, "Renewal policy not found", requestID)
		return
	}

	JSON(w, http.StatusOK, policy)
}

// CreateRenewalPolicy inserts a new renewal policy.
// POST /api/v1/renewal-policies
//
// Error mapping:
//   - invalid JSON / missing name  → 400
//   - ErrRenewalPolicyDuplicateName (pg 23505 on name UNIQUE) → 409
//   - anything else                → 500
func (h RenewalPolicyHandler) CreateRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	var rp domain.RenewalPolicy
	if err := json.NewDecoder(r.Body).Decode(&rp); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	if err := ValidateRequired("name", rp.Name); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}

	created, err := h.svc.CreateRenewalPolicy(r.Context(), rp)
	if err != nil {
		if errors.Is(err, service.ErrRenewalPolicyDuplicateName) {
			ErrorWithRequestID(w, http.StatusConflict, "A renewal policy with that name already exists", requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to create renewal policy", requestID)
		return
	}

	JSON(w, http.StatusCreated, created)
}

// UpdateRenewalPolicy replaces the fields of an existing renewal policy.
// PUT /api/v1/renewal-policies/{id}
//
// Error mapping:
//   - invalid JSON / empty ID      → 400
//   - ErrRenewalPolicyDuplicateName → 409
//   - error text contains "not found" → 404 (see struct doc comment re: substring check)
//   - anything else                → 500
func (h RenewalPolicyHandler) UpdateRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/renewal-policies/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Renewal policy ID is required", requestID)
		return
	}
	id = parts[0]

	var rp domain.RenewalPolicy
	if err := json.NewDecoder(r.Body).Decode(&rp); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	updated, err := h.svc.UpdateRenewalPolicy(r.Context(), id, rp)
	if err != nil {
		if errors.Is(err, service.ErrRenewalPolicyDuplicateName) {
			ErrorWithRequestID(w, http.StatusConflict, "A renewal policy with that name already exists", requestID)
			return
		}
		if errors.Is(err, repository.ErrNotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, "Renewal policy not found", requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to update renewal policy", requestID)
		return
	}

	JSON(w, http.StatusOK, updated)
}

// DeleteRenewalPolicy removes a renewal policy.
// DELETE /api/v1/renewal-policies/{id}
//
// Error mapping:
//   - empty ID (trailing slash)    → 400
//   - ErrRenewalPolicyInUse (pg 23503 FK-RESTRICT against managed_certificates.renewal_policy_id) → 409
//   - error text contains "not found" → 404
//   - anything else                → 500
func (h RenewalPolicyHandler) DeleteRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/renewal-policies/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Renewal policy ID is required", requestID)
		return
	}
	id = parts[0]

	if err := h.svc.DeleteRenewalPolicy(r.Context(), id); err != nil {
		if errors.Is(err, service.ErrRenewalPolicyInUse) {
			ErrorWithRequestID(w, http.StatusConflict, "Renewal policy is still referenced by managed certificates", requestID)
			return
		}
		if errors.Is(err, repository.ErrNotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, "Renewal policy not found", requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to delete renewal policy", requestID)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
