package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// CertificateService defines the service interface for certificate operations.
type CertificateService interface {
	ListCertificates(status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error)
	GetCertificate(id string) (*domain.ManagedCertificate, error)
	CreateCertificate(cert domain.ManagedCertificate) (*domain.ManagedCertificate, error)
	UpdateCertificate(id string, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error)
	ArchiveCertificate(id string) error
	GetCertificateVersions(certID string, page, perPage int) ([]domain.CertificateVersion, int64, error)
	TriggerRenewal(certID string) error
	TriggerDeployment(certID string, targetID string) error
}

// CertificateHandler handles HTTP requests for certificate operations.
type CertificateHandler struct {
	svc CertificateService
}

// NewCertificateHandler creates a new CertificateHandler with a service dependency.
func NewCertificateHandler(svc CertificateService) CertificateHandler {
	return CertificateHandler{svc: svc}
}

// ListCertificates lists certificates with optional filtering.
// GET /api/v1/certificates?status=Active&environment=prod&owner_id=...&team_id=...&issuer_id=...&page=1&per_page=50
func (h CertificateHandler) ListCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Parse query parameters
	query := r.URL.Query()
	status := query.Get("status")
	environment := query.Get("environment")
	ownerID := query.Get("owner_id")
	teamID := query.Get("team_id")
	issuerID := query.Get("issuer_id")

	page := 1
	perPage := 50
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

	certs, total, err := h.svc.ListCertificates(status, environment, ownerID, teamID, issuerID, page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list certificates", requestID)
		return
	}

	response := PagedResponse{
		Data:    certs,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetCertificate retrieves a single certificate by ID.
// GET /api/v1/certificates/{id}
func (h CertificateHandler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
	if id == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Certificate ID is required", requestID)
		return
	}

	cert, err := h.svc.GetCertificate(id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
		return
	}

	JSON(w, http.StatusOK, cert)
}

// CreateCertificate creates a new certificate.
// POST /api/v1/certificates
func (h CertificateHandler) CreateCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	var cert domain.ManagedCertificate
	if err := json.NewDecoder(r.Body).Decode(&cert); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate required fields
	if err := ValidateRequired("common_name", cert.CommonName); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateCommonName(cert.CommonName); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateRequired("owner_id", cert.OwnerID); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateRequired("team_id", cert.TeamID); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateRequired("issuer_id", cert.IssuerID); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}

	created, err := h.svc.CreateCertificate(cert)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to create certificate", requestID)
		return
	}

	JSON(w, http.StatusCreated, created)
}

// UpdateCertificate updates an existing certificate.
// PUT /api/v1/certificates/{id}
func (h CertificateHandler) UpdateCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Certificate ID is required", requestID)
		return
	}
	id = parts[0]

	var cert domain.ManagedCertificate
	if err := json.NewDecoder(r.Body).Decode(&cert); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate required fields (if provided)
	if cert.CommonName != "" {
		if err := ValidateCommonName(cert.CommonName); err != nil {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
	}
	if cert.OwnerID != "" {
		if err := ValidateStringLength("owner_id", cert.OwnerID, 255); err != nil {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
	}
	if cert.TeamID != "" {
		if err := ValidateStringLength("team_id", cert.TeamID, 255); err != nil {
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
			return
		}
	}

	updated, err := h.svc.UpdateCertificate(id, cert)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to update certificate", requestID)
		return
	}

	JSON(w, http.StatusOK, updated)
}

// ArchiveCertificate archives a certificate (soft delete).
// DELETE /api/v1/certificates/{id}
func (h CertificateHandler) ArchiveCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
	if id == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Certificate ID is required", requestID)
		return
	}

	if err := h.svc.ArchiveCertificate(id); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to archive certificate", requestID)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetCertificateVersions retrieves version history for a certificate.
// GET /api/v1/certificates/{id}/versions
func (h CertificateHandler) GetCertificateVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract certificate ID from path /api/v1/certificates/{id}/versions
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Certificate ID is required", requestID)
		return
	}
	certID := parts[0]

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

	versions, total, err := h.svc.GetCertificateVersions(certID, page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
		return
	}

	response := PagedResponse{
		Data:    versions,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// TriggerRenewal triggers manual renewal for a certificate.
// POST /api/v1/certificates/{id}/renew
func (h CertificateHandler) TriggerRenewal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract certificate ID from path /api/v1/certificates/{id}/renew
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Certificate ID is required", requestID)
		return
	}
	certID := parts[0]

	if err := h.svc.TriggerRenewal(certID); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to trigger renewal", requestID)
		return
	}

	response := map[string]string{
		"status": "renewal_triggered",
	}

	JSON(w, http.StatusAccepted, response)
}

// TriggerDeployment triggers deployment of a certificate to targets.
// POST /api/v1/certificates/{id}/deploy
func (h CertificateHandler) TriggerDeployment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract certificate ID from path /api/v1/certificates/{id}/deploy
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Certificate ID is required", requestID)
		return
	}
	certID := parts[0]

	// Optional: parse request body for specific target ID
	var req struct {
		TargetID string `json:"target_id,omitempty"`
	}
	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Log but don't fail - targetID is optional
			ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
			return
		}
	}

	if err := h.svc.TriggerDeployment(certID, req.TargetID); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to trigger deployment", requestID)
		return
	}

	response := map[string]string{
		"status": "deployment_triggered",
	}

	JSON(w, http.StatusAccepted, response)
}
