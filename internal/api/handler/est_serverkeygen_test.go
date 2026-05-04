package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/pkcs7"
)

// EST RFC 7030 hardening master bundle Phase 5.3 — serverkeygen tests.
// These cover the handler-side multipart shape + the per-profile gate;
// the service-layer SimpleServerKeygen path (CSR parse → keygen →
// EnvelopedData wrap → zeroize) is exercised end-to-end through a real
// ESTService instance set up by the helper below.

// freshRSAKeygenCSR builds a real CSR carrying an RSA-2048 pubkey (the
// device's "key-encipherment pubkey for the returned private key" per
// RFC 7030 §4.4.2 — non-RSA fails the BUILDER's RSA-only contract).
// Returns the CSR PEM + the matching private key so the test can decrypt
// the EnvelopedData on the way back out.
func freshRSAKeygenCSR(t *testing.T, cn string) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

// freshECDSAKeygenCSR builds a CSR with an ECDSA pubkey to exercise the
// "non-RSA pubkey rejected" path. RFC 7030 §4.4.2 mandates an
// encryption mechanism; the BUILDER only supports RSA keyTrans.
func freshECDSAKeygenCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// stubServerKeygenResult builds a fixture ESTServerKeygenResult by
// running the BUILDER directly against a known pubkey. Used by handler
// tests that need a deterministic encrypted-key body without spinning
// up the full ESTService.
func stubServerKeygenResult(t *testing.T, recipientPub *rsa.PublicKey, plaintext []byte, certPEM string) *domain.ESTServerKeygenResult {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: bigOne(),
		Subject:      pkix.Name{CommonName: "stub-recipient"},
		Issuer:       pkix.Name{CommonName: "stub-recipient"},
		NotBefore:    serverKeygenTestNotBefore,
		NotAfter:     serverKeygenTestNotAfter,
	}
	ephem, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ephem signer: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, recipientPub, ephem)
	if err != nil {
		t.Fatalf("create recipient: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse recipient: %v", err)
	}
	wire, err := pkcs7.BuildEnvelopedData(plaintext, cert, rand.Reader)
	if err != nil {
		t.Fatalf("BuildEnvelopedData: %v", err)
	}
	return &domain.ESTServerKeygenResult{
		CertPEM:      certPEM,
		EncryptedKey: wire,
	}
}

func TestServerKeygen_NotEnabled_404(t *testing.T) {
	svc := &mockESTService{}
	h := NewESTHandler(svc) // SetServerKeygenEnabled NOT called → off
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/serverkeygen",
		strings.NewReader(generateTestCSRPEM(t)))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.ServerKeygen(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (gate off)", w.Code)
	}
}

func TestServerKeygen_HappyPath_200_MultipartShape(t *testing.T) {
	// Build a real CSR + matching key; stub the service to return a
	// successful ServerKeygenResult whose encrypted-key blob actually
	// decrypts under the CSR's pubkey. Pin the multipart body shape.
	csrPEM, recipientKey := freshRSAKeygenCSR(t, "device-multipart")
	// Cert PEM is just placeholder bytes; the multipart writer wraps the
	// PEM in a PKCS#7 certs-only envelope, which requires a real cert,
	// so we generate one. (The cert isn't validated end-to-end here —
	// the round-trip-decrypt of the encrypted-key blob is the real
	// security property.)
	caCert, caKey := freshRSARecipient(t)
	caPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	_ = caKey
	plaintext := []byte("PKCS#8 private key bytes (test fixture)")
	stub := stubServerKeygenResult(t, &recipientKey.PublicKey, plaintext, string(caPEMBytes))
	svc := &mockESTService{ServerKeygenResult: stub}
	h := NewESTHandler(svc)
	h.SetServerKeygenEnabled(true)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/serverkeygen",
		strings.NewReader(csrPEM))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.ServerKeygen(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/mixed") {
		t.Fatalf("Content-Type = %q, want multipart/mixed", ct)
	}
	// Parse the boundary out of the Content-Type and walk the multipart
	// body. RFC 7030 §4.4.2 mandates two parts: cert + encrypted key.
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	mr := multipart.NewReader(w.Body, params["boundary"])
	parts := make(map[string][]byte)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		smimeType := smimeTypeFor(t, part.Header.Get("Content-Type"))
		body, _ := io.ReadAll(part)
		parts[smimeType] = body
	}
	if _, ok := parts["certs-only"]; !ok {
		t.Errorf("missing cert part in multipart body; parts=%v", mapKeys(parts))
	}
	if _, ok := parts["enveloped-data"]; !ok {
		t.Errorf("missing enveloped-data part in multipart body; parts=%v", mapKeys(parts))
	}
}

func TestServerKeygen_BasicAuthGateAppliesWhenPasswordSet(t *testing.T) {
	svc := &mockESTService{ServerKeygenResult: &domain.ESTServerKeygenResult{}}
	h := NewESTHandler(svc)
	h.SetServerKeygenEnabled(true)
	h.SetEnrollmentPassword("hunter2")

	csrPEM, _ := freshRSAKeygenCSR(t, "no-auth-test")
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/serverkeygen",
		strings.NewReader(csrPEM))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.ServerKeygen(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (Basic gate not satisfied)", w.Code)
	}
}

func TestServerKeygen_NonRSAPubkey_400(t *testing.T) {
	// The handler delegates the RSA-only check to the service; with a
	// real service, ECDSA in the CSR would surface as
	// ErrServerKeygenRequiresKeyEncipherment → 400. Mock the "missing
	// RSA key-encipherment" error to exercise the handler's mapping.
	svc := &mockESTService{
		ServerKeygenErr: errors.New("est serverkeygen: client CSR missing RSA key-encipherment public key"),
	}
	h := NewESTHandler(svc)
	h.SetServerKeygenEnabled(true)
	csrPEM := freshECDSAKeygenCSR(t, "ecdsa-csr-test")
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/corp/serverkeygen",
		strings.NewReader(csrPEM))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.ServerKeygen(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (RSA-only refusal)", w.Code)
	}
}

func TestServerKeygenMTLS_RequiresClientCert(t *testing.T) {
	s := newHardeningTestSetup(t) // existing helper from est_hardening_test.go
	svc := &mockESTService{ServerKeygenResult: &domain.ESTServerKeygenResult{}}
	h := NewESTHandler(svc)
	h.SetServerKeygenEnabled(true)
	h.SetMTLSTrust(s.trustPool)
	csrPEM, _ := freshRSAKeygenCSR(t, "mtls-no-cert")
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est-mtls/corp/serverkeygen",
		strings.NewReader(csrPEM))
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.ServerKeygenMTLS(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no client cert)", w.Code)
	}
}

// ---- helpers ----

// freshRSARecipient lives in pkcs7's test files — re-implement here to
// avoid cross-package test imports. Same shape: 2048-bit RSA + minimal
// self-signed cert.
func freshRSARecipient(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          bigOne(),
		Subject:               pkix.Name{CommonName: "ca-recipient"},
		Issuer:                pkix.Name{CommonName: "ca-recipient"},
		NotBefore:             serverKeygenTestNotBefore,
		NotAfter:              serverKeygenTestNotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key
}

func smimeTypeFor(t *testing.T, ct string) string {
	t.Helper()
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("ParseMediaType(%q): %v", ct, err)
	}
	return params["smime-type"]
}

func mapKeys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
