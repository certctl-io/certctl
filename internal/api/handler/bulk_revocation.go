package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// BulkRevocationService defines the service interface for bulk certificate revocation.
type BulkRevocationService interface {
	BulkRevoke(ctx context.Context, criteria domain.BulkRevocationCriteria, reason string, actor string) (*domain.BulkRevocationResult, error)
}

// BulkRevocationHandler handles HTTP requests for bulk revocation operations.
type BulkRevocationHandler struct {
	svc BulkRevocationService
}

// NewBulkRevocationHandler creates a new BulkRevocationHandler.
func NewBulkRevocationHandler(svc BulkRevocationService) BulkRevocationHandler {
	return BulkRevocationHandler{svc: svc}
}

// bulkRevokeRequest represents the JSON request body for bulk revocation.
type bulkRevokeRequest struct {
	Reason         string   `json:"reason"`
	ProfileID      string   `json:"profile_id,omitempty"`
	OwnerID        string   `json:"owner_id,omitempty"`
	AgentID        string   `json:"agent_id,omitempty"`
	IssuerID       string   `json:"issuer_id,omitempty"`
	TeamID         string   `json:"team_id,omitempty"`
	CertificateIDs []string `json:"certificate_ids,omitempty"`
}

// BulkRevoke handles bulk certificate revocation.
// POST /api/v1/certificates/bulk-revoke
func (h BulkRevocationHandler) BulkRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	var req bulkRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate reason is present
	if req.Reason == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Revocation reason is required", requestID)
		return
	}

	// Validate reason is a valid RFC 5280 code
	if !domain.IsValidRevocationReason(req.Reason) {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid revocation reason: "+req.Reason, requestID)
		return
	}

	criteria := domain.BulkRevocationCriteria{
		ProfileID:      req.ProfileID,
		OwnerID:        req.OwnerID,
		AgentID:        req.AgentID,
		IssuerID:       req.IssuerID,
		TeamID:         req.TeamID,
		CertificateIDs: req.CertificateIDs,
	}

	// Safety guard: at least one criterion required
	if criteria.IsEmpty() {
		ErrorWithRequestID(w, http.StatusBadRequest, "At least one filter criterion is required (profile_id, owner_id, agent_id, issuer_id, team_id, or certificate_ids)", requestID)
		return
	}

	// Extract actor from auth context
	actor := "api"
	if user, ok := middleware.GetUser(r.Context()); ok && user != "" {
		actor = user
	}

	result, err := h.svc.BulkRevoke(r.Context(), criteria, req.Reason, actor)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Bulk revocation failed: "+err.Error(), requestID)
		return
	}

	JSON(w, http.StatusOK, result)
}
