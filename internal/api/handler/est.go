package handler

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/pkcs7"
)

// ESTService defines the service interface for EST enrollment operations.
// EST (RFC 7030) is a protocol for certificate enrollment over HTTPS.
type ESTService interface {
	// GetCACerts returns the PEM-encoded CA certificate chain for the EST issuer.
	GetCACerts(ctx context.Context) (string, error)

	// SimpleEnroll processes a PKCS#10 CSR and returns a signed certificate.
	SimpleEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error)

	// SimpleReEnroll processes a re-enrollment CSR (same as enroll for our purposes).
	SimpleReEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error)

	// GetCSRAttrs returns the CSR attributes the server wants clients to include.
	GetCSRAttrs(ctx context.Context) ([]byte, error)
}

// ESTHandler handles HTTP requests for the EST protocol (RFC 7030).
//
// EST endpoints are served under /.well-known/est/ per the RFC.
// Wire format: base64-encoded DER (PKCS#7 for certs, PKCS#10 for CSRs).
//
// Supported operations:
//   - GET  /.well-known/est/cacerts       — CA certificate distribution
//   - POST /.well-known/est/simpleenroll  — initial enrollment
//   - POST /.well-known/est/simplereenroll — re-enrollment
//   - GET  /.well-known/est/csrattrs      — CSR attributes
type ESTHandler struct {
	svc ESTService
}

// NewESTHandler creates a new ESTHandler.
func NewESTHandler(svc ESTService) ESTHandler {
	return ESTHandler{svc: svc}
}

// CACerts handles GET /.well-known/est/cacerts
// Returns the CA certificate chain as base64-encoded PKCS#7 (certs-only).
// Per RFC 7030 Section 4.1, this is a "certs-only" CMC Simple PKI Response.
// For simplicity and broad client compatibility, we return base64-encoded DER certificates.
func (h ESTHandler) CACerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	caCertPEM, err := h.svc.GetCACerts(r.Context())
	if err != nil {
		requestID := middleware.GetRequestID(r.Context())
		ErrorWithRequestID(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get CA certificates: %v", err), requestID)
		return
	}

	// Parse PEM to DER for PKCS#7 encoding
	derCerts, err := pkcs7.PEMToDERChain(caCertPEM)
	if err != nil {
		requestID := middleware.GetRequestID(r.Context())
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to encode CA certificates", requestID)
		return
	}

	// Build a simple PKCS#7 SignedData (certs-only, degenerate) structure
	pkcs7Data, err := pkcs7.BuildCertsOnlyPKCS7(derCerts)
	if err != nil {
		requestID := middleware.GetRequestID(r.Context())
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to build PKCS#7 response", requestID)
		return
	}

	// RFC 7030 Section 4.1.3: response is base64-encoded application/pkcs7-mime
	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	encoded := base64.StdEncoding.EncodeToString(pkcs7Data)
	// Write base64 with line breaks at 76 chars per RFC 2045
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		w.Write([]byte(encoded[i:end]))
		w.Write([]byte("\r\n"))
	}
}

// SimpleEnroll handles POST /.well-known/est/simpleenroll
// Accepts a base64-encoded PKCS#10 CSR and returns a base64-encoded PKCS#7 certificate.
func (h ESTHandler) SimpleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	csrPEM, err := h.readCSRFromRequest(r)
	if err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, fmt.Sprintf("Invalid CSR: %v", err), requestID)
		return
	}

	result, err := h.svc.SimpleEnroll(r.Context(), csrPEM)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, fmt.Sprintf("Enrollment failed: %v", err), requestID)
		return
	}

	h.writeCertResponse(w, result)
}

// SimpleReEnroll handles POST /.well-known/est/simplereenroll
// Same as SimpleEnroll but for re-enrollment (certificate renewal).
func (h ESTHandler) SimpleReEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	csrPEM, err := h.readCSRFromRequest(r)
	if err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, fmt.Sprintf("Invalid CSR: %v", err), requestID)
		return
	}

	result, err := h.svc.SimpleReEnroll(r.Context(), csrPEM)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, fmt.Sprintf("Re-enrollment failed: %v", err), requestID)
		return
	}

	h.writeCertResponse(w, result)
}

// CSRAttrs handles GET /.well-known/est/csrattrs
// Returns the CSR attributes the server wants the client to include in enrollment requests.
func (h ESTHandler) CSRAttrs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	attrs, err := h.svc.GetCSRAttrs(r.Context())
	if err != nil {
		requestID := middleware.GetRequestID(r.Context())
		ErrorWithRequestID(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get CSR attributes: %v", err), requestID)
		return
	}

	if len(attrs) == 0 {
		// No specific attributes required — return 204
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/csrattrs")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(base64.StdEncoding.EncodeToString(attrs)))
}

// readCSRFromRequest reads and decodes the CSR from an EST enrollment request.
// EST sends CSRs as base64-encoded PKCS#10 DER with Content-Type application/pkcs10.
func (h ESTHandler) readCSRFromRequest(r *http.Request) (string, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		return "", fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()

	if len(body) == 0 {
		return "", fmt.Errorf("empty request body")
	}

	// Check if it's already PEM-encoded (some clients send PEM directly)
	bodyStr := strings.TrimSpace(string(body))
	if strings.HasPrefix(bodyStr, "-----BEGIN CERTIFICATE REQUEST-----") {
		// Validate it parses
		block, _ := pem.Decode([]byte(bodyStr))
		if block == nil {
			return "", fmt.Errorf("invalid PEM-encoded CSR")
		}
		if _, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
			return "", fmt.Errorf("invalid CSR: %w", err)
		}
		return bodyStr, nil
	}

	// EST standard: base64-encoded DER PKCS#10
	derBytes, err := base64.StdEncoding.DecodeString(bodyStr)
	if err != nil {
		// Try with padding/whitespace stripped
		cleaned := strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, bodyStr)
		derBytes, err = base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return "", fmt.Errorf("failed to decode base64 CSR: %w", err)
		}
	}

	// Validate it's a valid PKCS#10 CSR
	if _, err := x509.ParseCertificateRequest(derBytes); err != nil {
		return "", fmt.Errorf("invalid PKCS#10 CSR: %w", err)
	}

	// Convert DER to PEM for internal use (certctl services expect PEM)
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: derBytes,
	})
	return string(csrPEM), nil
}

// writeCertResponse writes an EST enrollment response as base64-encoded PKCS#7.
func (h ESTHandler) writeCertResponse(w http.ResponseWriter, result *domain.ESTEnrollResult) {
	// Parse cert and chain PEM to DER
	var derCerts [][]byte

	// Add the issued certificate
	certDER, err := pkcs7.PEMToDERChain(result.CertPEM)
	if err != nil || len(certDER) == 0 {
		http.Error(w, "Failed to encode certificate", http.StatusInternalServerError)
		return
	}
	derCerts = append(derCerts, certDER...)

	// Add the CA chain if present
	if result.ChainPEM != "" {
		chainDER, err := pkcs7.PEMToDERChain(result.ChainPEM)
		if err == nil {
			derCerts = append(derCerts, chainDER...)
		}
	}

	// Build PKCS#7 certs-only
	pkcs7Data, err := pkcs7.BuildCertsOnlyPKCS7(derCerts)
	if err != nil {
		http.Error(w, "Failed to build PKCS#7 response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	encoded := base64.StdEncoding.EncodeToString(pkcs7Data)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		w.Write([]byte(encoded[i:end]))
		w.Write([]byte("\r\n"))
	}
}

// NOTE: PKCS#7 helpers (BuildCertsOnlyPKCS7, PEMToDERChain, ASN.1 wrappers)
// are in the shared internal/pkcs7 package, used by both EST and SCEP handlers.
