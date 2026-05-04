package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/service"
)

// ApprovalServicer is the handler-facing surface of the approval-workflow
// service. Defined here (handler-defined service interface, dependency
// inversion) so the handler stays decoupled from the concrete
// *service.ApprovalService.
//
// Rank 7 of the 2026-05-03 deep-research deliverable, commit 3
// of 4 — the API + RBAC layer.
type ApprovalServicer interface {
	Approve(ctx context.Context, requestID, decidedBy, note string) error
	Reject(ctx context.Context, requestID, decidedBy, note string) error
	Get(ctx context.Context, id string) (*domain.ApprovalRequest, error)
	List(ctx context.Context, filter *repository.ApprovalFilter) ([]*domain.ApprovalRequest, error)
}

// ApprovalHandler handles HTTP requests for the issuance approval workflow.
// All endpoints are pinned at /api/v1/approvals/*.
type ApprovalHandler struct {
	svc ApprovalServicer
}

// NewApprovalHandler constructs an ApprovalHandler with a service dependency.
func NewApprovalHandler(svc ApprovalServicer) ApprovalHandler {
	return ApprovalHandler{svc: svc}
}

// approvalDecisionBody is the JSON body shape for Approve / Reject endpoints.
type approvalDecisionBody struct {
	Note string `json:"note,omitempty"`
}

// ListApprovals returns paginated approval requests, optionally filtered
// by ?state=, ?certificate_id=, ?requested_by=.
//
// GET /api/v1/approvals?state=pending&page=1&per_page=50
func (h ApprovalHandler) ListApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	requestID := middleware.GetRequestID(r.Context())

	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(q.Get("per_page"))
	if perPage < 1 || perPage > 500 {
		perPage = 50
	}

	filter := &repository.ApprovalFilter{
		State:         q.Get("state"),
		CertificateID: q.Get("certificate_id"),
		RequestedBy:   q.Get("requested_by"),
		Page:          page,
		PerPage:       perPage,
	}
	results, err := h.svc.List(r.Context(), filter)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list approval requests", requestID)
		return
	}
	JSON(w, http.StatusOK, map[string]interface{}{
		"data":     results,
		"page":     page,
		"per_page": perPage,
	})
}

// GetApproval returns a single approval request by ID.
//
// GET /api/v1/approvals/{id}
func (h ApprovalHandler) GetApproval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	requestID := middleware.GetRequestID(r.Context())
	id := r.PathValue("id")
	if id == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "id required", requestID)
		return
	}
	req, err := h.svc.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrApprovalNotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, "approval request not found", requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to get approval request", requestID)
		return
	}
	JSON(w, http.StatusOK, req)
}

// Approve transitions a pending approval request to approved + transitions
// the linked Job from AwaitingApproval to Pending. RBAC: the authenticated
// actor extracted via middleware.UserKey must NOT equal the request's
// RequestedBy — the service-layer check enforces this and the handler
// surfaces it as HTTP 403.
//
// POST /api/v1/approvals/{id}/approve
// Body: {"note": "approved per ticket SECOPS-12345"} (optional)
func (h ApprovalHandler) Approve(w http.ResponseWriter, r *http.Request) {
	h.decision(w, r, decisionApprove)
}

// Reject transitions a pending approval request to rejected + cancels
// the linked Job. Same RBAC contract as Approve.
//
// POST /api/v1/approvals/{id}/reject
// Body: {"note": "rejected: not on business-justification list"} (optional)
func (h ApprovalHandler) Reject(w http.ResponseWriter, r *http.Request) {
	h.decision(w, r, decisionReject)
}

type decisionAction int

const (
	decisionApprove decisionAction = iota
	decisionReject
)

func (h ApprovalHandler) decision(w http.ResponseWriter, r *http.Request, action decisionAction) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	requestID := middleware.GetRequestID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "id required", requestID)
		return
	}

	// Extract authenticated actor. The auth middleware sets UserKey to the
	// API-key NamedAPIKey.Name (or empty for unauthenticated). RBAC at the
	// service layer requires a non-empty actor.
	actor, _ := r.Context().Value(middleware.UserKey{}).(string)
	if actor == "" {
		ErrorWithRequestID(w, http.StatusUnauthorized,
			"authentication required to approve / reject", requestID)
		return
	}

	body := approvalDecisionBody{}
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			ErrorWithRequestID(w, http.StatusBadRequest,
				"invalid JSON body", requestID)
			return
		}
	}

	var err error
	switch action {
	case decisionApprove:
		err = h.svc.Approve(r.Context(), id, actor, body.Note)
	case decisionReject:
		err = h.svc.Reject(r.Context(), id, actor, body.Note)
	}
	if err != nil {
		switch {
		case errors.Is(err, service.ErrApprovalNotFound):
			ErrorWithRequestID(w, http.StatusNotFound, err.Error(), requestID)
		case errors.Is(err, service.ErrApprovalAlreadyDecided):
			ErrorWithRequestID(w, http.StatusConflict, err.Error(), requestID)
		case errors.Is(err, service.ErrApproveBySameActor):
			// The load-bearing two-person integrity contract surface.
			// Compliance auditors expect this exact code path.
			ErrorWithRequestID(w, http.StatusForbidden, err.Error(), requestID)
		default:
			ErrorWithRequestID(w, http.StatusInternalServerError,
				"Failed to record decision", requestID)
		}
		return
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"id":         id,
		"decided_by": actor,
		"action":     map[decisionAction]string{decisionApprove: "approved", decisionReject: "rejected"}[action],
	})
}
