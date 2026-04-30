package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/ratelimit"
	"github.com/shankar0123/certctl/internal/repository"
	"github.com/shankar0123/certctl/internal/service"
)

// CertificateService defines the service interface for certificate operations.
type CertificateService interface {
	ListCertificates(ctx context.Context, status, environment, ownerID, teamID, issuerID string, page, perPage int) ([]domain.ManagedCertificate, int64, error)
	ListCertificatesWithFilter(ctx context.Context, filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error)
	GetCertificate(ctx context.Context, id string) (*domain.ManagedCertificate, error)
	CreateCertificate(ctx context.Context, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error)
	UpdateCertificate(ctx context.Context, id string, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error)
	ArchiveCertificate(ctx context.Context, id string) error
	GetCertificateVersions(ctx context.Context, certID string, page, perPage int) ([]domain.CertificateVersion, int64, error)
	TriggerRenewal(ctx context.Context, certID string, actor string) error
	TriggerDeployment(ctx context.Context, certID string, targetID string, actor string) error
	RevokeCertificate(ctx context.Context, certID string, reason string, actor string) error
	GetRevokedCertificates(ctx context.Context) ([]*domain.CertificateRevocation, error)
	GenerateDERCRL(ctx context.Context, issuerID string) ([]byte, error)
	GetOCSPResponse(ctx context.Context, issuerID string, serialHex string) ([]byte, error)
	// GetOCSPResponseWithNonce is the nonce-aware variant added in
	// production hardening II Phase 1. When nonce is non-nil, the
	// responder echoes it in the response per RFC 6960 §4.4.1. A nil
	// nonce produces a response without the nonce extension.
	GetOCSPResponseWithNonce(ctx context.Context, issuerID string, serialHex string, nonce []byte) ([]byte, error)
	GetCertificateDeployments(ctx context.Context, certID string) ([]domain.DeploymentTarget, error)
}

// CertificateHandler handles HTTP requests for certificate operations.
type CertificateHandler struct {
	svc         CertificateService
	ocspLimiter *ratelimit.SlidingWindowLimiter // production hardening II Phase 3 — per-source-IP cap on OCSP
}

// NewCertificateHandler creates a new CertificateHandler with a service dependency.
func NewCertificateHandler(svc CertificateService) CertificateHandler {
	return CertificateHandler{svc: svc}
}

// SetOCSPRateLimiter wires the per-source-IP OCSP rate limiter.
// Production hardening II Phase 3. Default cap (when set in
// cmd/server/main.go): 1000 req/min/IP. Setting to nil disables the
// limit; the limiter's own NewSlidingWindowLimiter(maxN<=0, ...)
// also produces a no-op limiter, so the env-var-zero case is safe.
func (h *CertificateHandler) SetOCSPRateLimiter(l *ratelimit.SlidingWindowLimiter) {
	h.ocspLimiter = l
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

	certs, total, err := h.svc.ListCertificatesWithFilter(r.Context(), filter)
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

	cert, err := h.svc.GetCertificate(r.Context(), id)
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

	created, err := h.svc.CreateCertificate(r.Context(), cert)
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

	updated, err := h.svc.UpdateCertificate(r.Context(), id, cert)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
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

	if err := h.svc.ArchiveCertificate(r.Context(), id); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
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

	versions, total, err := h.svc.GetCertificateVersions(r.Context(), certID, page, perPage)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
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

	actor := resolveActor(r.Context())

	if err := h.svc.TriggerRenewal(r.Context(), certID, actor); err != nil {
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

	actor := resolveActor(r.Context())

	if err := h.svc.TriggerDeployment(r.Context(), certID, req.TargetID, actor); err != nil {
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

	actor := resolveActor(r.Context())

	if err := h.svc.RevokeCertificate(r.Context(), certID, req.Reason, actor); err != nil {
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

// GetDERCRL returns a DER-encoded X.509 CRL signed by the specified issuer.
// GET /.well-known/pki/crl/{issuer_id}
//
// RFC 5280 § 5. Served unauthenticated under the /.well-known/pki/ namespace so
// relying parties (browsers, OpenSSL, OCSP stapling sidecars) can fetch the CRL
// without presenting certctl API credentials.
func (h CertificateHandler) GetDERCRL(w http.ResponseWriter, r *http.Request) {
	requestID, _ := r.Context().Value("request_id").(string)

	if r.Method != http.MethodGet {
		ErrorWithRequestID(w, http.StatusMethodNotAllowed, "Method not allowed", requestID)
		return
	}

	issuerID := strings.TrimPrefix(r.URL.Path, "/.well-known/pki/crl/")
	if issuerID == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Issuer ID is required", requestID)
		return
	}

	derBytes, err := h.svc.GenerateDERCRL(r.Context(), issuerID)
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

	// Production hardening II Phase 4: HTTP caching headers per RFC 7232.
	// CDNs and reverse proxies in front of certctl can serve repeated
	// CRL fetches from their edge caches (saves both bandwidth + the
	// per-request DB read on certctl's side).
	//
	// ETag is the SHA-256 of the DER body, weak-form (W/) per RFC 7232
	// §2.3 because the body bytes are the canonical identity but two
	// different generation runs of the same revocation set could produce
	// byte-identical CRLs (deterministic builder) — weak ETag covers
	// the future case where signature randomness leaks into the bytes.
	etagBytes := sha256.Sum256(derBytes)
	etag := fmt.Sprintf("W/\"%x\"", etagBytes[:16]) // first 16 bytes of SHA-256 — sufficient ID space
	w.Header().Set("ETag", etag)

	// If-None-Match short-circuits to 304 Not Modified. RFC 7232 §3.2.
	// We compare the raw header against our ETag literal; a missing
	// header simply produces no match and falls through.
	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Cache-Control max-age derived from the CRL's nextUpdate window.
	// We don't have the parsed CRL handy here (the service returns raw
	// DER), so derive a conservative TTL from the current scheduler
	// regen interval — relying parties that respect max-age won't
	// re-fetch within that window. Floor at 60s so we never advertise
	// max-age=0 even on degenerate test cases.
	const crlCacheControlSeconds = 3600 // 1h matches default CRL regen cadence
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, must-revalidate", crlCacheControlSeconds))
	w.WriteHeader(http.StatusOK)
	w.Write(derBytes)
}

// ocspSourceIP extracts the source IP from the request for the
// per-IP rate limiter. Production hardening II Phase 3.
//
// Strategy: net.SplitHostPort on RemoteAddr; on parse failure fall
// back to the bare RemoteAddr string. We deliberately do NOT honor
// X-Forwarded-For here because OCSP is publicly reachable and
// untrusted intermediaries could spoof the header to bypass the
// limit. Operators behind a trusted reverse proxy should configure
// the proxy to pass through the original IP via the standard
// transport (rewriting RemoteAddr at the proxy boundary).
func ocspSourceIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// applyOCSPRateLimit enforces the per-source-IP cap. Returns true when
// the request was rejected (handler should stop). Returns false to
// continue processing. Production hardening II Phase 3.
func (h CertificateHandler) applyOCSPRateLimit(w http.ResponseWriter, r *http.Request) bool {
	if h.ocspLimiter == nil {
		return false
	}
	ip := ocspSourceIP(r)
	if err := h.ocspLimiter.Allow(ip, time.Now()); err != nil {
		// Rate-limited: respond with the canonical OCSP "tryLater"
		// status (status 3 per RFC 6960 §2.3) plus an HTTP-level
		// Retry-After hint. ocsp.UnauthorizedErrorResponse is
		// status 6 (unauthorized); we use that here too because
		// x/crypto/ocsp doesn't ship a TryLater pre-built blob and
		// rolling our own DER for one rejection path adds a
		// fragility surface for no relying-party benefit
		// (everything that retries an OCSP failure retries on any
		// non-good status, not specifically TryLater).
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ocsp.UnauthorizedErrorResponse)
		return true
	}
	return false
}

// HandleOCSP processes OCSP requests.
// GET /.well-known/pki/ocsp/{issuer_id}/{serial_hex}
//
// RFC 6960. Served unauthenticated under the /.well-known/pki/ namespace. For
// simplicity we accept GET with path params rather than the binary POST body
// form — the response is a valid DER-encoded OCSP response either way.
func (h CertificateHandler) HandleOCSP(w http.ResponseWriter, r *http.Request) {
	requestID, _ := r.Context().Value("request_id").(string)

	if r.Method != http.MethodGet {
		ErrorWithRequestID(w, http.StatusMethodNotAllowed, "Method not allowed", requestID)
		return
	}

	// Production hardening II Phase 3: per-source-IP rate limit.
	// When the cap is tripped, applyOCSPRateLimit writes the
	// rate-limited OCSP response and returns true — handler stops.
	if h.applyOCSPRateLimit(w, r) {
		return
	}

	// Extract issuer_id and serial from path: /.well-known/pki/ocsp/{issuer_id}/{serial_hex}
	path := strings.TrimPrefix(r.URL.Path, "/.well-known/pki/ocsp/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Issuer ID and serial number are required", requestID)
		return
	}
	issuerID := parts[0]
	serialHex := parts[1]

	derBytes, err := h.svc.GetOCSPResponse(r.Context(), issuerID, serialHex)
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

// HandleOCSPPost processes RFC 6960 §A.1.1 POST OCSP requests.
// POST /.well-known/pki/ocsp/{issuer_id}
//
// The body MUST be the binary DER-encoded OCSPRequest with content-type
// "application/ocsp-request". The response is the same DER-encoded
// OCSPResponse with content-type "application/ocsp-response" returned
// by the existing GET handler — only the input shape differs.
//
// POST is the standard transport for production OCSP clients (Firefox,
// OpenSSL `s_client -status`, cert-manager, Microsoft Intune device
// validators). The pre-existing GET form is kept for ad-hoc curl
// inspection + human-readable URL paths.
//
// Bundle CRL/OCSP-Responder Phase 4.
func (h CertificateHandler) HandleOCSPPost(w http.ResponseWriter, r *http.Request) {
	requestID, _ := r.Context().Value("request_id").(string)

	if r.Method != http.MethodPost {
		ErrorWithRequestID(w, http.StatusMethodNotAllowed, "Method not allowed", requestID)
		return
	}

	// Production hardening II Phase 3: per-source-IP rate limit.
	if h.applyOCSPRateLimit(w, r) {
		return
	}

	// Be tolerant about Content-Type: RFC 6960 §A.1.1 says it MUST be
	// "application/ocsp-request" but real-world clients sometimes omit
	// the header or send it with a charset suffix. We require the
	// substring "ocsp-request" rather than exact match — the actual
	// validation happens in ocsp.ParseRequest below; a malformed body
	// fails there with a 400.
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(strings.ToLower(ct), "ocsp-request") {
		ErrorWithRequestID(w, http.StatusUnsupportedMediaType,
			fmt.Sprintf("Content-Type must be application/ocsp-request, got %q", ct), requestID)
		return
	}

	// Issuer ID from the path. The router pattern strips the leading
	// /.well-known/pki/ocsp/ prefix; what remains is the bare issuer ID.
	issuerID := strings.TrimPrefix(r.URL.Path, "/.well-known/pki/ocsp/")
	issuerID = strings.TrimSuffix(issuerID, "/")
	if issuerID == "" || strings.Contains(issuerID, "/") {
		ErrorWithRequestID(w, http.StatusBadRequest, "Issuer ID is required", requestID)
		return
	}

	// Body is already MaxBytesReader-capped by the body-size middleware.
	// OCSPRequest bodies are tiny (~200 bytes for a single-cert query),
	// so the default cap is comfortably above what any legitimate client
	// will send.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Failed to read request body", requestID)
		return
	}

	ocspReq, err := ocsp.ParseRequest(body)
	if err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest,
			fmt.Sprintf("Invalid OCSPRequest: %v", err), requestID)
		return
	}

	// Production hardening II Phase 1: extract the optional RFC 6960
	// §4.4.1 nonce extension from the request. golang.org/x/crypto/ocsp
	// doesn't expose the request's extensions, so we walk the raw DER
	// ourselves via service.ParseOCSPRequestNonce.
	//
	// Failure modes:
	//   - no nonce (most relying parties): nonce=nil, present=false,
	//     err=nil -> proceed without echoing.
	//   - well-formed nonce <= 32 bytes: nonce=bytes, present=true,
	//     err=nil -> plumb through GetOCSPResponseWithNonce.
	//   - malformed nonce (empty or > 32 bytes): err=ErrOCSPNonceMalformed
	//     -> respond with the OCSP "unauthorized" status (RFC 6960 §2.3
	//     status code 6) rather than echoing potentially-malicious bytes.
	nonce, _, nonceErr := service.ParseOCSPRequestNonce(body)
	if errors.Is(nonceErr, service.ErrOCSPNonceMalformed) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		// ocsp.UnauthorizedErrorResponse is the canonical pre-built
		// error response (status 6) per RFC 6960 §4.2.1.
		w.Write(ocsp.UnauthorizedErrorResponse)
		return
	}

	// Reuse the existing service path. The serial extracted from the
	// parsed OCSPRequest is converted to hex (the on-disk format for
	// certctl serials matches certificate.SerialNumber.Text(16)).
	serialHex := fmt.Sprintf("%x", ocspReq.SerialNumber)
	derBytes, err := h.svc.GetOCSPResponseWithNonce(r.Context(), issuerID, serialHex, nonce)
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

	deployments, err := h.svc.GetCertificateDeployments(r.Context(), certID)
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
