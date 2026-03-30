package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// CertificateService defines the service interface for certificate operations.
type CertificateService interface {
	ListCertificates(status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error)
	ListCertificatesWithFilter(filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error)
	GetCertificate(id string) (*domain.ManagedCertificate, error)
	CreateCertificate(cert domain.ManagedCertificate) (*domain.ManagedCertificate, error)
	UpdateCertificate(id string, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error)
	ArchiveCertificate(id string) error
	GetCertificateVersions(certID string, page, perPage int) ([]domain.CertificateVersion, int64, error)
	TriggerRenewal(certID string) error
	TriggerDeployment(certID string, targetID string) error
	RevokeCertificate(certID string, reason string) error
	GetRevokedCertificates() ([]*domain.CertificateRevocation, error)
	GenerateDERCRL(issuerID string) ([]byte, error)
	GetOCSPResponse(issuerID string, serialHex string) ([]byte, error)
	GetCertificateDeployments(certID string) ([]domain.DeploymentTarget, error)
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
// GET /api/v1/certificates?status=Active&environment=prod&owner_id=...&team_id=...&issuer_id=...&agent_id=...&profile_id=...&expires_before=...&expires_after=...&created_after=...&updated_after=...&sort=notAfter&sort_desc=false&cursor=...&page=1&per_page=50&fields=id,commonName,status
func (h CertificateHandler) ListCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Parse query parameters
	query := r.URL.Query()

	// Basic filters
	filter := &repository.CertificateFilter{
		Status:      query.Get("status"),
		Environment: query.Get("environment"),
		OwnerID:     query.Get("owner_id"),
		TeamID:      query.Get("team_id"),
		IssuerID:    query.Get("issuer_id"),
		AgentID:     query.Get("agent_id"),
		ProfileID:   query.Get("profile_id"),
	}

	// Time-range filters
	if eb := query.Get("expires_before"); eb != "" {
		if t, err := time.Parse(time.RFC3339, eb); err == nil {
			filter.ExpiresBefore = &t
		}
	}
	if ea := query.Get("expires_after"); ea != "" {
		if t, err := time.Parse(time.RFC3339, ea); err == nil {
			filter.ExpiresAfter = &t
		}
	}
	if ca := query.Get("created_after"); ca != "" {
		if t, err := time.Parse(time.RFC3339, ca); err == nil {
			filter.CreatedAfter = &t
		}
	}
	if ua := query.Get("updated_after"); ua != "" {
		if t, err := time.Parse(time.RFC3339, ua); err == nil {
			filter.UpdatedAfter = &t
		}
	}

	// Sorting
	if sort := query.Get("sort"); sort != "" {
		// Handle sort direction prefix
		if strings.HasPrefix(sort, "-") {
			filter.Sort = sort[1:]
			filter.SortDesc = true
		} else {
			filter.Sort = sort
			filter.SortDesc = query.Get("sort_desc") == "true"
		}
	}

	// Cursor-based pagination
	filter.Cursor = query.Get("cursor")

	// Page-based pagination
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
	if ps := query.Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 500 {
			filter.PageSize = parsed
		}
	}
	filter.Page = page
	filter.PerPage = perPage

	// Sparse fields
	if fieldsStr := query.Get("fields"); fieldsStr != "" {
		filter.Fields = strings.Split(fieldsStr, ",")
	}

	certs, total, err := h.svc.ListCertificatesWithFilter(filter)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list certificates", requestID)
		return
	}

	// Apply sparse field filtering if requested
	var responseData interface{} = certs
	if len(filter.Fields) > 0 {
		responseData = filterFields(certs, filter.Fields)
	}

	// Return cursor-based or page-based response depending on which pagination is used
	if filter.Cursor != "" {
		// Compute next cursor from last result
		nextCursor := ""
		if len(certs) > 0 {
			lastCert := certs[len(certs)-1]
			nextCursor = encodeCursor(lastCert.CreatedAt, lastCert.ID)
		}
		pageSize := filter.PageSize
		if pageSize == 0 {
			pageSize = filter.PerPage
		}
		response := CursorPagedResponse{
			Data:       responseData,
			Total:      int64(total),
			NextCursor: nextCursor,
			PageSize:   pageSize,
		}
		JSON(w, http.StatusOK, response)
	} else {
		response := PagedResponse{
			Data:    responseData,
			Total:   int64(total),
			Page:    page,
			PerPage: perPage,
		}
		JSON(w, http.StatusOK, response)
	}
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
	if err := ValidateRequired("name", cert.Name); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateRequired("renewal_policy_id", cert.RenewalPolicyID); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}

	created, err := h.svc.CreateCertificate(cert)
	if err != nil {
		slog.Error("failed to create certificate", "error", err, "request_id", requestID, "common_name", cert.CommonName, "name", cert.Name)
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
		if strings.Contains(err.Error(), "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
			return
		}
		slog.Error("UpdateCertificate failed", "cert_id", id, "error", err.Error())
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
		if strings.Contains(err.Error(), "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
			return
		}
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
		if strings.Contains(err.Error(), "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
			return
		}
		slog.Error("GetCertificateVersions failed", "cert_id", certID, "error", err.Error())
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to get certificate versions", requestID)
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
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
			return
		}
		if strings.Contains(errMsg, "cannot renew") {
			ErrorWithRequestID(w, http.StatusBadRequest, errMsg, requestID)
			return
		}
		if strings.Contains(errMsg, "already in progress") {
			ErrorWithRequestID(w, http.StatusConflict, errMsg, requestID)
			return
		}
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

// RevokeCertificate revokes a certificate with an optional reason code.
// POST /api/v1/certificates/{id}/revoke
func (h CertificateHandler) RevokeCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract certificate ID from path /api/v1/certificates/{id}/revoke
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Certificate ID is required", requestID)
		return
	}
	certID := parts[0]

	// Parse optional reason from request body
	var req struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil && r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
			return
		}
	}

	if err := h.svc.RevokeCertificate(certID, req.Reason); err != nil {
		// Distinguish between client errors and server errors
		errMsg := err.Error()
		if strings.Contains(errMsg, "already revoked") ||
			strings.Contains(errMsg, "cannot revoke") ||
			strings.Contains(errMsg, "invalid revocation reason") {
			ErrorWithRequestID(w, http.StatusBadRequest, errMsg, requestID)
			return
		}
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "failed to fetch") || strings.Contains(errMsg, "failed to get") {
			ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to revoke certificate", requestID)
		return
	}

	JSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// GetCRL returns the Certificate Revocation List as structured JSON.
// GET /api/v1/crl
// Note: DER-encoded X.509 CRL generation (requiring CA key access) is planned for M15b
// alongside the embedded OCSP responder. This endpoint provides the same data in JSON format.
func (h CertificateHandler) GetCRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	revocations, err := h.svc.GetRevokedCertificates()
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to generate CRL", requestID)
		return
	}

	type CRLEntry struct {
		SerialNumber     string `json:"serial_number"`
		RevocationDate   string `json:"revocation_date"`
		RevocationReason string `json:"revocation_reason"`
	}

	entries := make([]CRLEntry, 0, len(revocations))
	for _, rev := range revocations {
		entries = append(entries, CRLEntry{
			SerialNumber:     rev.SerialNumber,
			RevocationDate:   rev.RevokedAt.Format("2006-01-02T15:04:05Z"),
			RevocationReason: rev.Reason,
		})
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"version":      1,
		"entries":      entries,
		"total":        len(entries),
		"generated_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// GetDERCRL returns a DER-encoded X.509 CRL signed by the specified issuer.
// GET /api/v1/crl/{issuer_id}
func (h CertificateHandler) GetDERCRL(w http.ResponseWriter, r *http.Request) {
	requestID, _ := r.Context().Value("request_id").(string)

	if r.Method != http.MethodGet {
		ErrorWithRequestID(w, http.StatusMethodNotAllowed, "Method not allowed", requestID)
		return
	}

	issuerID := strings.TrimPrefix(r.URL.Path, "/api/v1/crl/")
	if issuerID == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Issuer ID is required", requestID)
		return
	}

	derBytes, err := h.svc.GenerateDERCRL(issuerID)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, errMsg, requestID)
			return
		}
		if strings.Contains(errMsg, "do not support") || strings.Contains(errMsg, "does not support") {
			ErrorWithRequestID(w, http.StatusNotImplemented, errMsg, requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to generate CRL", requestID)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	w.Write(derBytes)
}

// HandleOCSP processes OCSP requests.
// GET /api/v1/ocsp/{issuer_id}/{serial_hex}
// For simplicity, use GET with path params instead of binary POST.
func (h CertificateHandler) HandleOCSP(w http.ResponseWriter, r *http.Request) {
	requestID, _ := r.Context().Value("request_id").(string)

	if r.Method != http.MethodGet {
		ErrorWithRequestID(w, http.StatusMethodNotAllowed, "Method not allowed", requestID)
		return
	}

	// Extract issuer_id and serial from path: /api/v1/ocsp/{issuer_id}/{serial_hex}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/ocsp/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Issuer ID and serial number are required", requestID)
		return
	}
	issuerID := parts[0]
	serialHex := parts[1]

	derBytes, err := h.svc.GetOCSPResponse(issuerID, serialHex)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, errMsg, requestID)
			return
		}
		if strings.Contains(errMsg, "do not support") || strings.Contains(errMsg, "does not support") {
			ErrorWithRequestID(w, http.StatusNotImplemented, errMsg, requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to generate OCSP response", requestID)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "max-age=3600")
	w.WriteHeader(http.StatusOK)
	w.Write(derBytes)
}

// GetCertificateDeployments retrieves all deployment targets for a certificate.
// GET /api/v1/certificates/{id}/deployments
func (h CertificateHandler) GetCertificateDeployments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract certificate ID from path /api/v1/certificates/{id}/deployments
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Certificate ID is required", requestID)
		return
	}
	certID := parts[0]

	deployments, err := h.svc.GetCertificateDeployments(certID)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to get deployments", requestID)
		return
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"data":  deployments,
		"total": len(deployments),
	})
}
