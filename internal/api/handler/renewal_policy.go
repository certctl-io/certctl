package handler

import (
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
// Error dispatch (post-M-1): every service error routes through the [errToStatus]
// choke point via `errors.Is` walking the wrap chain. Three sentinel identities
// cover the full dispatch surface:
//
//   - [service.ErrRenewalPolicyDuplicateName] / [service.ErrRenewalPolicyInUse]
//     are `var`-aliased to the repository-layer sentinels of the same name (G-1),
//     so handler-side `errors.Is` succeeds against a sentinel raised three layers
//     deep in [internal/repository/postgres.RenewalPolicyRepository] without the
//     service layer having to translate. [errToStatus] routes both to 409.
//   - [repository.ErrNotFound] is wrapped around `sql.ErrNoRows` inside the
//     repo's Get/Update/Delete methods via `fmt.Errorf("%w: renewal policy %s",
//     repository.ErrNotFound, id)` (M-1). [errToStatus] routes that to 404 in
//     the same switch arm as [service.ErrNotFound], preserving the existing
//     404-on-missing behavior that the pre-M-1 substring check provided —
//     without the rewording-regression risk that motivated the migration.
//
// The handler layer keeps two explicit `errors.Is` arms for the
// duplicate-name / in-use sentinels so each 409 response can carry a
// constraint-specific human-readable message ("with that name" vs. "still
// referenced by managed certificates"); every other error path — including
// not-found — delegates the status decision to [errToStatus] and provides a
// generic body via the F-002 redacted-500 pattern.
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
		// M-1: route through errToStatus so a repo-level `sql.ErrNoRows`
		// (wrapped as repository.ErrNotFound) becomes 404, but a transient DB
		// failure no longer masquerades as 404 — it correctly surfaces 500.
		// The pre-M-1 "any error → 404" shortcut was plausible when Get's only
		// expected failure was "not found", but the choke point now gives us
		// correct dispatch for free.
		status := errToStatus(err)
		msg := "Failed to get renewal policy"
		if status == http.StatusNotFound {
			msg = "Renewal policy not found"
		}
		ErrorWithRequestID(w, status, msg, requestID)
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
// Error mapping (post-M-1, sentinel-driven):
//   - invalid JSON / empty ID                      → 400
//   - ErrRenewalPolicyDuplicateName (pg 23505)     → 409 (explicit arm, custom msg)
//   - ErrNotFound (wrapping sql.ErrNoRows)         → 404 (via errToStatus)
//   - anything else                                → 500 (via errToStatus, body redacted)
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
		// M-1: drop the `strings.Contains(err.Error(), "not found")` branch.
		// [repository.ErrNotFound] now wraps sql.ErrNoRows at the three
		// renewal-policy repo methods (Get/Update/Delete), so errToStatus
		// routes a missing row to 404 via errors.Is without depending on the
		// repo's fmt.Errorf format string surviving a future reword.
		status := errToStatus(err)
		msg := "Failed to update renewal policy"
		if status == http.StatusNotFound {
			msg = "Renewal policy not found"
		}
		ErrorWithRequestID(w, status, msg, requestID)
		return
	}

	JSON(w, http.StatusOK, updated)
}

// DeleteRenewalPolicy removes a renewal policy.
// DELETE /api/v1/renewal-policies/{id}
//
// Error mapping (post-M-1, sentinel-driven):
//   - empty ID (trailing slash)                    → 400
//   - ErrRenewalPolicyInUse (pg 23503 FK-RESTRICT) → 409 (explicit arm, custom msg)
//   - ErrNotFound (wrapping sql.ErrNoRows)         → 404 (via errToStatus)
//   - anything else                                → 500 (via errToStatus, body redacted)
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
		// M-1: sentinel dispatch replaces the substring check — see the
		// parallel comment block in UpdateRenewalPolicy for the rationale.
		status := errToStatus(err)
		msg := "Failed to delete renewal policy"
		if status == http.StatusNotFound {
			msg = "Renewal policy not found"
		}
		ErrorWithRequestID(w, status, msg, requestID)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
