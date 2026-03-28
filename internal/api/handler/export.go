package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/service"
)

// ExportService defines the service interface for certificate export operations.
type ExportService interface {
	ExportPEM(ctx context.Context, certID string) (*service.ExportPEMResult, error)
	ExportPKCS12(ctx context.Context, certID string, password string) ([]byte, error)
}

// ExportHandler handles HTTP requests for certificate export operations.
type ExportHandler struct {
	svc ExportService
}

// NewExportHandler creates a new ExportHandler with a service dependency.
func NewExportHandler(svc ExportService) ExportHandler {
	return ExportHandler{svc: svc}
}

// ExportPEM exports a certificate and its chain in PEM format.
// GET /api/v1/certificates/{id}/export/pem
func (h ExportHandler) ExportPEM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
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
		if strings.Contains(err.Error(), "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
			return
		}
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
		if strings.Contains(err.Error(), "not found") {
			ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found", requestID)
			return
		}
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
