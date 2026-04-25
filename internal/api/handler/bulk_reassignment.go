package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/service"
)

// BulkReassignmentService defines the service interface for bulk
// owner-reassignment operations.
type BulkReassignmentService interface {
	BulkReassign(ctx context.Context, request domain.BulkReassignmentRequest, actor string) (*domain.BulkReassignmentResult, error)
}

// BulkReassignmentHandler handles HTTP requests for bulk reassignment
// operations.
type BulkReassignmentHandler struct {
	svc BulkReassignmentService
}

// NewBulkReassignmentHandler creates a new BulkReassignmentHandler.
func NewBulkReassignmentHandler(svc BulkReassignmentService) BulkReassignmentHandler {
	return BulkReassignmentHandler{svc: svc}
}

// bulkReassignRequest is the JSON shape decoded from the request body.
type bulkReassignRequest struct {
	CertificateIDs []string `json:"certificate_ids"`
	OwnerID        string   `json:"owner_id"`
	TeamID         string   `json:"team_id,omitempty"`
}

// BulkReassign handles POST /api/v1/certificates/bulk-reassign
//
// L-2 closure (cat-l-8a1fb258a38a): pre-L-2 the GUI looped
// `await updateCertificate(id, { owner_id })`. Post-L-2 the GUI POSTs
// once and the server mutates owner_id (and optionally team_id) on N
// certs, returning per-cert success/skip/error counts.
//
// Narrower contract than bulk-renew: explicit IDs only, no criteria-mode.
// OwnerID is required; TeamID is optional and updates the team only when
// non-empty (matches the existing per-cert PUT contract).
//
// Auth: any authenticated caller can reassign certs they own/have
// access to. NOT admin-gated — operators reassign ownership during
// team transitions all the time and gating that on admin would block
// the common-case workflow.
//
// Validation order: empty body → 400; empty IDs → 400; missing
// owner_id → 400; non-existent owner_id → 400 via the
// ErrBulkReassignOwnerNotFound sentinel mapped here.
func (h BulkReassignmentHandler) BulkReassign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	requestID := middleware.GetRequestID(r.Context())

	var req bulkReassignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	request := domain.BulkReassignmentRequest{
		CertificateIDs: req.CertificateIDs,
		OwnerID:        req.OwnerID,
		TeamID:         req.TeamID,
	}
	if request.IsEmpty() {
		ErrorWithRequestID(w, http.StatusBadRequest,
			"At least one certificate_id is required",
			requestID)
		return
	}
	if request.OwnerID == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "owner_id is required", requestID)
		return
	}

	actor := resolveActor(r.Context())

	result, err := h.svc.BulkReassign(r.Context(), request, actor)
	if err != nil {
		// Sentinel-error → 400 mapping. ErrBulkReassignOwnerNotFound
		// means the operator picked an owner that doesn't exist; this
		// is bad input (400), not a server error (500). Mirrors the
		// post-M-1 errToStatus convention rather than substring-matching
		// err.Error().
		if errors.Is(err, service.ErrBulkReassignOwnerNotFound) {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Bulk reassignment failed: "+err.Error(), requestID)
		return
	}

	JSON(w, http.StatusOK, result)
}
