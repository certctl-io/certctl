package handler

import (
	"context"
	"encoding/json"
	"log/slog"
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
		// M-1 (P2): dispatch routes through errToStatus. Pre-M-1 this branch
		// classified 404 via strings.Contains(err.Error(), "not found"), which
		// gave false positives on any error whose rendered text happened to
		// contain "not found" — notably a transient DB failure when the service
		// layer wrapped every certRepo.Get error with "certificate not found".
		// Post-M-1: service/export.go now wraps with "failed to get certificate"
		// and only the genuine sql.ErrNoRows path surfaces repository.ErrNotFound
		// through the wrap chain, so errors.Is(err, repository.ErrNotFound) picks
		// up the real 404s and everything else — including transient DB errors —
		// correctly surfaces as 500 with server-side slog.Error capture (F-002
		// redacted-500 pattern preserved).
		status := errToStatus(err)
		if status == http.StatusInternalServerError {
			slog.Error("ExportPEM failed", "cert_id", id, "error", err.Error())
		}
		msg := "Failed to export certificate"
		if status == http.StatusNotFound {
			msg = "Certificate not found"
		}
		ErrorWithRequestID(w, status, msg, requestID)
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
		// M-1 (P2): dispatch routes through errToStatus. The pre-M-1 3-term
		// substring net (`"not found"|"cannot be parsed"|"no certificates
		// found"`) is replaced with sentinel dispatch:
		//   - repository.ErrNotFound (from certificate.go Get/GetLatestVersion
		//     sql.ErrNoRows wrap) → 404
		//   - service.ErrUnprocessable (from service/export.go ExportPKCS12's
		//     parsePEMCertificates-failure and empty-chain wraps) → 422 —
		//     semantically correct because the caller's request is fine; our
		//     stored PEM chain is what cannot be processed
		//   - everything else → 500 with slog.Error capture (F-002 redacted-500
		//     pattern preserved)
		// A transient DB failure that pre-M-1 would have been swept into the
		// 404 substring branch (because the service wrapped every certRepo.Get
		// error with "certificate not found") now correctly surfaces as 500.
		status := errToStatus(err)
		if status == http.StatusInternalServerError {
			slog.Error("ExportPKCS12 failed", "cert_id", id, "error", err.Error())
		}
		msg := "Failed to export PKCS#12"
		switch status {
		case http.StatusNotFound:
			msg = "Certificate not found"
		case http.StatusUnprocessableEntity:
			msg = "Certificate data cannot be parsed as X.509"
		}
		ErrorWithRequestID(w, status, msg, requestID)
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
