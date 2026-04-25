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

	if err := verifyESTTransport(r); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, fmt.Sprintf("EST transport precondition failed: %v", err), requestID)
		return
	}

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

	if err := verifyESTTransport(r); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, fmt.Sprintf("EST transport precondition failed: %v", err), requestID)
		return
	}

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

// verifyESTTransport implements Bundle-4 / M-021 EST transport precondition.
//
// RFC 7030 §3.2.3 ("Linking Identity and POP Information") requires that when
// EST clients use certificate-based authentication AND send a Proof-of-Possession
// (PoP), the PoP MUST be cryptographically bound to the underlying TLS session
// via TLS-Unique (RFC 5929). With TLS 1.3 (which certctl pins via
// `tls.Config.MinVersion = tls.VersionTLS13` per the HTTPS-Everywhere milestone),
// TLS-Unique is unavailable; RFC 9266 defines `tls-exporter` as the TLS 1.3
// replacement.
//
// **Current scope of this function (Bundle-4 closure):** certctl does NOT
// currently support EST client certificate authentication. The EST endpoint
// accepts unauthenticated POSTs (the SCEP equivalent enforces a
// challenge-password via `preflightSCEPChallengePassword`; EST has no
// equivalent today). Per RFC 7030 §3.2.3, channel binding is REQUIRED only
// when client certificate authentication is in use; without that, the §3.2.3
// requirement is moot.
//
// What we DO enforce here as defense-in-depth:
//
//  1. r.TLS must be non-nil — the EST endpoint MUST be reached over TLS.
//     Defensive: certctl pins HTTPS-only at the server-side TLS config, but
//     a future routing-layer regression that exposes EST over plaintext
//     would be caught here.
//  2. Negotiated TLS version must be >= TLS 1.2 — RFC 7030 doesn't mandate
//     a specific TLS version, but a pre-1.2 negotiation indicates a
//     misconfigured client/server pair. certctl's MinVersion is TLS 1.3
//     so this should always hold.
//  3. r.TLS.HandshakeComplete must be true — defensive against partial-
//     handshake replays.
//
// **Deferred to a future bundle (operator decision required):**
//
//   - RFC 9266 `tls-exporter` channel binding when EST mTLS is added.
//   - EST mTLS support itself — currently EST is unauth-or-bearer; mTLS
//     would be a V3-aligned compliance feature.
//
// Returns nil if all preconditions pass; non-nil error otherwise.
func verifyESTTransport(r *http.Request) error {
	if r.TLS == nil {
		return fmt.Errorf("EST endpoint reached over plaintext; TLS required (RFC 7030 §3.2.1)")
	}
	if !r.TLS.HandshakeComplete {
		return fmt.Errorf("EST request reached handler before TLS handshake completed")
	}
	// tls.VersionTLS12 == 0x0303; certctl's MinVersion is TLS 1.3 (0x0304).
	// Defensive lower bound at TLS 1.2 lets us catch a future MinVersion
	// regression cleanly without coupling this guard to the server config.
	if r.TLS.Version < 0x0303 {
		return fmt.Errorf("EST request negotiated TLS version 0x%04x; TLS 1.2 minimum required", r.TLS.Version)
	}
	return nil
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
