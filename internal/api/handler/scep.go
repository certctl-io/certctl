package handler

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
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

// SCEPService defines the service interface for SCEP enrollment operations.
// SCEP (RFC 8894) is a protocol for certificate enrollment used by MDM platforms
// and network devices.
type SCEPService interface {
	// GetCACaps returns the SCEP server capabilities as a newline-separated string.
	GetCACaps(ctx context.Context) string

	// GetCACert returns the PEM-encoded CA certificate chain.
	GetCACert(ctx context.Context) (string, error)

	// PKCSReq processes a PKCS#10 CSR and returns a signed certificate.
	PKCSReq(ctx context.Context, csrPEM string, challengePassword string, transactionID string) (*domain.SCEPEnrollResult, error)
}

// SCEPHandler handles HTTP requests for the SCEP protocol (RFC 8894).
//
// SCEP uses a single endpoint with operation-based dispatch via query parameters.
// All operations use GET or POST to the same path.
//
// Supported operations:
//   - GET  ?operation=GetCACaps    — server capabilities
//   - GET  ?operation=GetCACert    — CA certificate distribution
//   - POST ?operation=PKIOperation — certificate enrollment (PKCSReq)
type SCEPHandler struct {
	svc SCEPService
}

// NewSCEPHandler creates a new SCEPHandler.
func NewSCEPHandler(svc SCEPService) SCEPHandler {
	return SCEPHandler{svc: svc}
}

// HandleSCEP is the single entry point for all SCEP operations.
// It dispatches based on the "operation" query parameter.
func (h SCEPHandler) HandleSCEP(w http.ResponseWriter, r *http.Request) {
	operation := r.URL.Query().Get("operation")

	switch operation {
	case "GetCACaps":
		h.getCACaps(w, r)
	case "GetCACert":
		h.getCACert(w, r)
	case "PKIOperation":
		h.pkiOperation(w, r)
	default:
		http.Error(w, fmt.Sprintf("Unknown SCEP operation: %s", operation), http.StatusBadRequest)
	}
}

// getCACaps handles GET ?operation=GetCACaps
// Returns the SCEP server capabilities as plaintext, one per line.
func (h SCEPHandler) getCACaps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	caps := h.svc.GetCACaps(r.Context())
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(caps))
}

// getCACert handles GET ?operation=GetCACert
// Returns the CA certificate(s). Single cert as DER, chain as PKCS#7.
func (h SCEPHandler) getCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	caCertPEM, err := h.svc.GetCACert(r.Context())
	if err != nil {
		requestID := middleware.GetRequestID(r.Context())
		ErrorWithRequestID(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get CA certificate: %v", err), requestID)
		return
	}

	// Parse PEM to DER chain
	derCerts, err := pkcs7.PEMToDERChain(caCertPEM)
	if err != nil {
		requestID := middleware.GetRequestID(r.Context())
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to parse CA certificates", requestID)
		return
	}

	if len(derCerts) == 1 {
		// Single CA cert — return as raw DER
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.WriteHeader(http.StatusOK)
		w.Write(derCerts[0])
		return
	}

	// Multiple certs (CA + RA or chain) — return as PKCS#7
	pkcs7Data, err := pkcs7.BuildCertsOnlyPKCS7(derCerts)
	if err != nil {
		requestID := middleware.GetRequestID(r.Context())
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to build PKCS#7 response", requestID)
		return
	}

	w.Header().Set("Content-Type", "application/x-x509-ca-ra-cert")
	w.WriteHeader(http.StatusOK)
	w.Write(pkcs7Data)
}

// pkiOperation handles POST ?operation=PKIOperation
// Processes a SCEP enrollment request containing a PKCS#7-wrapped CSR.
func (h SCEPHandler) pkiOperation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Failed to read request body", requestID)
		return
	}
	defer r.Body.Close()

	if len(body) == 0 {
		ErrorWithRequestID(w, http.StatusBadRequest, "Empty request body", requestID)
		return
	}

	// Extract the PKCS#10 CSR from the PKCS#7 SignedData envelope
	csrDER, challengePassword, transactionID, err := extractCSRFromPKCS7(body)
	if err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, fmt.Sprintf("Invalid SCEP message: %v", err), requestID)
		return
	}

	// Validate the CSR
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, fmt.Sprintf("Invalid CSR: %v", err), requestID)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, fmt.Sprintf("CSR signature invalid: %v", err), requestID)
		return
	}

	// Convert DER CSR to PEM for the service layer
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))

	result, err := h.svc.PKCSReq(r.Context(), csrPEM, challengePassword, transactionID)
	if err != nil {
		if strings.Contains(err.Error(), "challenge password") {
			ErrorWithRequestID(w, http.StatusForbidden, "Invalid challenge password", requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError, fmt.Sprintf("Enrollment failed: %v", err), requestID)
		return
	}

	// Build response: issued cert wrapped in PKCS#7 certs-only
	h.writeSCEPResponse(w, result)
}

// writeSCEPResponse writes a SCEP enrollment response as PKCS#7 certs-only (DER).
func (h SCEPHandler) writeSCEPResponse(w http.ResponseWriter, result *domain.SCEPEnrollResult) {
	var derCerts [][]byte

	certDER, err := pkcs7.PEMToDERChain(result.CertPEM)
	if err != nil || len(certDER) == 0 {
		http.Error(w, "Failed to encode certificate", http.StatusInternalServerError)
		return
	}
	derCerts = append(derCerts, certDER...)

	if result.ChainPEM != "" {
		chainDER, err := pkcs7.PEMToDERChain(result.ChainPEM)
		if err == nil {
			derCerts = append(derCerts, chainDER...)
		}
	}

	pkcs7Data, err := pkcs7.BuildCertsOnlyPKCS7(derCerts)
	if err != nil {
		http.Error(w, "Failed to build PKCS#7 response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-pki-message")
	w.WriteHeader(http.StatusOK)
	w.Write(pkcs7Data)
}

// extractCSRFromPKCS7 extracts a PKCS#10 CSR from a SCEP PKCS#7 SignedData envelope.
//
// SCEP clients wrap the CSR in a PKCS#7 SignedData structure. For the MVP, we parse
// the outer ASN.1 structure to find the encapsulated content (the CSR bytes), and
// extract the challenge password from the CSR attributes.
//
// Returns: csrDER, challengePassword, transactionID, error
func extractCSRFromPKCS7(data []byte) ([]byte, string, string, error) {
	// Try to decode as PKCS#7 SignedData
	csrDER, err := parseSignedDataForCSR(data)
	if err != nil {
		// Fallback: some clients send the CSR directly (not wrapped in PKCS#7)
		// or send base64-encoded data
		decoded, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if decErr == nil {
			// Try the decoded data as PKCS#7
			csrDER2, err2 := parseSignedDataForCSR(decoded)
			if err2 == nil {
				return extractCSRFields(csrDER2)
			}
			// Maybe the decoded data IS the CSR directly
			if _, parseErr := x509.ParseCertificateRequest(decoded); parseErr == nil {
				return extractCSRFields(decoded)
			}
		}
		// Maybe the raw data IS the CSR directly (no PKCS#7 wrapping)
		if _, parseErr := x509.ParseCertificateRequest(data); parseErr == nil {
			return extractCSRFields(data)
		}
		return nil, "", "", fmt.Errorf("failed to extract CSR from PKCS#7: %w", err)
	}
	return extractCSRFields(csrDER)
}

// extractCSRFields extracts the challenge password and transaction ID from CSR attributes.
func extractCSRFields(csrDER []byte) ([]byte, string, string, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid CSR: %w", err)
	}

	challengePassword := ""
	transactionID := ""

	// OID for challengePassword: 1.2.840.113549.1.9.7
	oidChallengePassword := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

	// Extract challenge password from parsed CSR attributes.
	// Attributes is []pkix.AttributeTypeAndValueSET where each has Type (OID)
	// and Value ([][]pkix.AttributeTypeAndValue). The challenge password value
	// is stored as a string in the inner AttributeTypeAndValue.Value field.
	for _, attr := range csr.Attributes {
		if attr.Type.Equal(oidChallengePassword) {
			if len(attr.Value) > 0 && len(attr.Value[0]) > 0 {
				if pwd, ok := attr.Value[0][0].Value.(string); ok {
					challengePassword = pwd
				}
			}
		}
	}

	// Use CN as fallback transaction ID if not found in attributes
	if transactionID == "" && csr.Subject.CommonName != "" {
		transactionID = csr.Subject.CommonName
	}

	return csrDER, challengePassword, transactionID, nil
}

// pkcs7ContentInfo represents the outer ContentInfo structure.
type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// pkcs7SignedData represents a simplified SignedData structure for CSR extraction.
type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
}

// pkcs7EncapContent represents the EncapsulatedContentInfo.
type pkcs7EncapContent struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// parseSignedDataForCSR extracts the encapsulated content (CSR) from PKCS#7 SignedData.
func parseSignedDataForCSR(data []byte) ([]byte, error) {
	var contentInfo pkcs7ContentInfo
	rest, err := asn1.Unmarshal(data, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}
	if len(rest) > 0 {
		// Trailing data is OK for some implementations
	}

	// OID for signedData: 1.2.840.113549.1.7.2
	oidSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	if !contentInfo.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("not SignedData: got OID %v", contentInfo.ContentType)
	}

	// Parse the SignedData
	var signedData pkcs7SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SignedData: %w", err)
	}

	// Parse the EncapsulatedContentInfo to get the CSR
	var encapContent pkcs7EncapContent
	_, err = asn1.Unmarshal(signedData.EncapContentInfo.FullBytes, &encapContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EncapsulatedContentInfo: %w", err)
	}

	if len(encapContent.Content.Bytes) == 0 {
		return nil, fmt.Errorf("empty encapsulated content")
	}

	// The content may be wrapped in an OCTET STRING
	var csrBytes []byte
	var octetString asn1.RawValue
	if _, err := asn1.Unmarshal(encapContent.Content.Bytes, &octetString); err == nil && octetString.Tag == asn1.TagOctetString {
		csrBytes = octetString.Bytes
	} else {
		csrBytes = encapContent.Content.Bytes
	}

	// Validate it's a parseable CSR
	if _, err := x509.ParseCertificateRequest(csrBytes); err != nil {
		return nil, fmt.Errorf("extracted content is not a valid CSR: %w", err)
	}

	return csrBytes, nil
}
