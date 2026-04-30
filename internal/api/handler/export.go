package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shankar0123/certctl/internal/repository"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/ratelimit"
	"github.com/shankar0123/certctl/internal/service"
)

// ExportService defines the service interface for certificate export operations.
type ExportService interface {
	ExportPEM(ctx context.Context, certID string) (*service.ExportPEMResult, error)
	ExportPKCS12(ctx context.Context, certID string, password string) ([]byte, error)
}

// ExportHandler handles HTTP requests for certificate export operations.
type ExportHandler struct {
	svc           ExportService
	exportLimiter *ratelimit.SlidingWindowLimiter // production hardening II Phase 3
}

// NewExportHandler creates a new ExportHandler with a service dependency.
func NewExportHandler(svc ExportService) ExportHandler {
	return ExportHandler{svc: svc}
}

// SetExportRateLimiter wires the per-actor cert-export rate limiter.
// Production hardening II Phase 3. Default cap (when set in
// cmd/server/main.go): 50 exports/hr/operator. Setting to nil
// disables the limit.
func (h *ExportHandler) SetExportRateLimiter(l *ratelimit.SlidingWindowLimiter) {
	h.exportLimiter = l
}

// applyExportRateLimit enforces the per-actor cap. Returns true when
// the request was rejected (handler should stop).
//
// On rejection: HTTP 429 + JSON body {"error":"rate_limit_exceeded",
// "retry_after_seconds":3600}. Production hardening II Phase 3.
func (h ExportHandler) applyExportRateLimit(w http.ResponseWriter, r *http.Request) bool {
	if h.exportLimiter == nil {
		return false
	}
	// Auth context populates an actor on the request; cert-export is
	// always behind the API-key middleware so this is non-empty in
	// production. Fall-back to RemoteAddr only if the auth pipeline
	// somehow allowed an empty actor (defensive; shouldn't fire).
	actor := r.Header.Get("X-Actor")
	if actor == "" {
		actor = r.RemoteAddr
	}
	if err := h.exportLimiter.Allow(actor, time.Now()); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, `{"error":"rate_limit_exceeded","retry_after_seconds":3600}`)
		return true
	}
	return false
}

// ExportPEM exports a certificate and its chain in PEM format.
// GET /api/v1/certificates/{id}/export/pem
func (h ExportHandler) ExportPEM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Production hardening II Phase 3: per-actor cert-export rate limit.
	if h.applyExportRateLimit(w, r) {
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract certificate ID from path: /api/v1/certificates/{id}/export/pem
	id := extractCertIDFromExportPath(r.URL.Path)
	if id == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Certificate ID is required", requestID)
		return
	}

	result, err := h.svc.ExportPEM(r.Context(), id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
			return
		}
		slog.Error("ExportPEM failed", "cert_id", id, "error", err.Error())
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to export certificate", requestID)
		return
	}

	// Check if client wants file download via Accept header or ?download=true query param
	if r.URL.Query().Get("download") == "true" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=\"certificate.pem\"")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(result.FullPEM))
		return
	}

	JSON(w, http.StatusOK, result)
}

// ExportPKCS12 exports a certificate and chain in PKCS#12 format.
// POST /api/v1/certificates/{id}/export/pkcs12
// Body: { "password": "optional-password" }
func (h ExportHandler) ExportPKCS12(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Production hardening II Phase 3: per-actor cert-export rate limit.
	if h.applyExportRateLimit(w, r) {
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract certificate ID from path: /api/v1/certificates/{id}/export/pkcs12
	id := extractCertIDFromExportPath(r.URL.Path)
	if id == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Certificate ID is required", requestID)
		return
	}

	// Parse optional password from request body (may be empty)
	var req struct {
		Password string `json:"password"`
	}
	// Body is optional — empty body means empty password
	_ = parseJSONBody(r, &req)

	pfxData, err := h.svc.ExportPKCS12(r.Context(), id, req.Password)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
			return
		}
		if strings.Contains(err.Error(), "cannot be parsed") || strings.Contains(err.Error(), "no certificates found") {
			ErrorWithRequestID(w, http.StatusUnprocessableEntity, "Certificate data cannot be parsed as X.509", requestID)
			return
		}
		slog.Error("ExportPKCS12 failed", "cert_id", id, "error", err.Error())
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to export PKCS#12", requestID)
		return
	}

	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", "attachment; filename=\"certificate.p12\"")
	w.WriteHeader(http.StatusOK)
	w.Write(pfxData)
}

// extractCertIDFromExportPath extracts the certificate ID from an export path.
// Path format: /api/v1/certificates/{id}/export/pem or /api/v1/certificates/{id}/export/pkcs12
func extractCertIDFromExportPath(path string) string {
	prefix := "/api/v1/certificates/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(path, prefix)
	// rest should be "{id}/export/pem" or "{id}/export/pkcs12"
	parts := strings.Split(rest, "/")
	if len(parts) < 3 || parts[1] != "export" {
		return ""
	}
	return parts[0]
}

// parseJSONBody is a helper that decodes JSON from the request body.
// Returns an error if the body is malformed, nil if body is empty.
func parseJSONBody(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return nil
	}
	return json.NewDecoder(r.Body).Decode(v)
}
