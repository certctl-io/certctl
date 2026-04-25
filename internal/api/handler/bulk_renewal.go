package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// BulkRenewalService defines the service interface for bulk certificate
// renewal. Mirrors BulkRevocationService — handler doesn't import the
// concrete service struct so tests can inject a mock without pulling in
// the full service-layer dependency graph.
type BulkRenewalService interface {
	BulkRenew(ctx context.Context, criteria domain.BulkRenewalCriteria, actor string) (*domain.BulkRenewalResult, error)
}

// BulkRenewalHandler handles HTTP requests for bulk renewal operations.
type BulkRenewalHandler struct {
	svc BulkRenewalService
}

// NewBulkRenewalHandler creates a new BulkRenewalHandler.
func NewBulkRenewalHandler(svc BulkRenewalService) BulkRenewalHandler {
	return BulkRenewalHandler{svc: svc}
}

// bulkRenewRequest mirrors the BulkRenewalCriteria JSON shape (the
// handler decodes into this struct then hands a domain.BulkRenewalCriteria
// to the service — same indirection as bulkRevokeRequest in
// bulk_revocation.go).
type bulkRenewRequest struct {
	ProfileID      string   `json:"profile_id,omitempty"`
	OwnerID        string   `json:"owner_id,omitempty"`
	AgentID        string   `json:"agent_id,omitempty"`
	IssuerID       string   `json:"issuer_id,omitempty"`
	TeamID         string   `json:"team_id,omitempty"`
	CertificateIDs []string `json:"certificate_ids,omitempty"`
}

// BulkRenew handles POST /api/v1/certificates/bulk-renew
//
// L-1 closure (cat-l-fa0c1ac07ab5): pre-L-1 the GUI looped
// `await triggerRenewal(id)` over the selection. Post-L-1 it POSTs once
// and the server enqueues N renewal jobs server-side, returning a
// per-cert {certificate_id, job_id} envelope.
//
// Request shape mirrors BulkRevokeRequest (criteria-mode + IDs-mode);
// the "renew all certs of profile X before its CA changes" use case is
// why criteria-mode is supported in addition to explicit IDs.
//
// Auth: any authenticated caller can renew certs they have read-access
// to (matches POST /api/v1/certificates/{id}/renew). NOT admin-gated
// like bulk-revoke — bulk-renew is non-destructive (worst case it
// kicks off some redundant ACME orders) so we don't need the
// fleet-scale-destruction gate.
func (h BulkRenewalHandler) BulkRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	requestID := middleware.GetRequestID(r.Context())

	var req bulkRenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	criteria := domain.BulkRenewalCriteria{
		ProfileID:      req.ProfileID,
		OwnerID:        req.OwnerID,
		AgentID:        req.AgentID,
		IssuerID:       req.IssuerID,
		TeamID:         req.TeamID,
		CertificateIDs: req.CertificateIDs,
	}
	if criteria.IsEmpty() {
		ErrorWithRequestID(w, http.StatusBadRequest,
			"At least one filter criterion is required (profile_id, owner_id, agent_id, issuer_id, team_id, or certificate_ids)",
			requestID)
		return
	}

	actor := resolveActor(r.Context())

	result, err := h.svc.BulkRenew(r.Context(), criteria, actor)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Bulk renewal failed: "+err.Error(), requestID)
		return
	}

	JSON(w, http.StatusOK, result)
}
