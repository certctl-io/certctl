package handler

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
)

// EST RFC 7030 hardening master bundle Phase 10.3 — Cisco IOS quirk
// fixtures. Each fixture is a captured-shape CSR that exercises one
// of the documented IOS wire-format deviations from the EST §4.2.1
// happy-path; the test pins that ESTHandler.readCSRFromRequest +
// the broader handler pipeline accept each shape without operator
// intervention.
//
// Fixtures live under testdata/cisco_ios_*.txt — kept as plain-text
// copies so a future reader can `cat` them + understand the shape
// without re-deriving from a binary blob.

// loadCiscoFixture reads the named testdata file. Path-traversal-safe
// because the fixture name is a compile-time constant per call site;
// we keep filepath.Clean for hygiene.
func loadCiscoFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(filepath.Join("testdata", name)))
	if err != nil {
		t.Fatalf("read fixture %q: %v", name, err)
	}
	return string(body)
}

// TestESTCiscoIOSQuirk_15xPEMUploadAccepted exercises the documented
// IOS 15.x quirk: the device sends Content-Type `application/x-pem-file`
// (PEM-encoded) instead of the EST §4.2.1 canonical
// `application/pkcs10` (base64-DER). The handler's readCSRFromRequest
// dispatches on body-prefix (`-----BEGIN CERTIFICATE REQUEST-----`)
// rather than Content-Type, so the upload should parse cleanly + the
// service should see a properly-formed CSR.
func TestESTCiscoIOSQuirk_15xPEMUploadAccepted(t *testing.T) {
	body := loadCiscoFixture(t, "cisco_ios_15x_pem_csr.txt")
	if !strings.HasPrefix(body, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Fatalf("fixture corrupted: expected PEM prefix, got %q", body[:60])
	}

	svc := &mockESTService{EnrollResult: ciscoQuirkOKResult(t)}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodPost,
		"/.well-known/est/corp/simpleenroll", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-pem-file") // the IOS 15.x quirk
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("IOS 15.x PEM upload status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
}

// TestESTCiscoIOSQuirk_16xTrailingNewlinesAccepted exercises the
// documented IOS 16.x quirk: an extra trailing newline after the
// base64 body. The handler's strings.TrimSpace pass MUST tolerate
// any number of trailing whitespace bytes without surfacing as a
// malformed-CSR rejection.
func TestESTCiscoIOSQuirk_16xTrailingNewlinesAccepted(t *testing.T) {
	body := loadCiscoFixture(t, "cisco_ios_16x_trailing_newline_csr.txt")
	if !strings.HasSuffix(body, "\n\n\n") && !strings.HasSuffix(body, "\n\n") {
		tail := body
		if len(tail) > 10 {
			tail = body[len(body)-10:]
		}
		t.Fatalf("fixture corrupted: expected ≥2 trailing newlines; got tail=%q", tail)
	}

	svc := &mockESTService{EnrollResult: ciscoQuirkOKResult(t)}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodPost,
		"/.well-known/est/corp/simpleenroll", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("IOS 16.x trailing-newlines status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
}

// TestESTCiscoIOSQuirk_CRLFBase64Accepted exercises the documented
// CRLF-line-ending quirk. Some IOS versions emit base64-DER with
// CRLF wrapping (the RFC 2045 §6.8 wire shape) rather than bare LF
// (the JSON-via-curl shape). The handler must strip both CRLF + LF
// before passing to base64.StdEncoding.DecodeString.
func TestESTCiscoIOSQuirk_CRLFBase64Accepted(t *testing.T) {
	body := loadCiscoFixture(t, "cisco_ios_crlf_b64_csr.txt")
	if !strings.Contains(body, "\r\n") {
		t.Fatalf("fixture corrupted: expected CRLF-wrapped body; first 80 = %q", body[:80])
	}

	svc := &mockESTService{EnrollResult: ciscoQuirkOKResult(t)}
	h := NewESTHandler(svc)

	req := httptest.NewRequest(http.MethodPost,
		"/.well-known/est/corp/simpleenroll", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("CRLF-wrapped base64 status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
}

// ciscoQuirkOKResult is the service-side response the mock returns for
// every Cisco-quirk happy-path test. The cert content doesn't matter —
// what matters is that the handler reaches the service call (i.e. it
// successfully parsed the CSR), so we hand back a hard-coded EC cert
// PEM that pkcs7.PEMToDERChain accepts cleanly.
func ciscoQuirkOKResult(t *testing.T) *domain.ESTEnrollResult {
	t.Helper()
	return &domain.ESTEnrollResult{
		CertPEM: "-----BEGIN CERTIFICATE-----\nMIIBnDCCAUOgAwIBAgIBATAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAljaXNjby10\nZXN0MB4XDTI1MDEwMTAwMDAwMFoXDTM1MTIzMTAwMDAwMFowFDESMBAGA1UEAwwJ\nY2lzY28tdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAfNh1+nAo15qVMF\nh0w4EQfHBn5zQgEDLkJhpZ+9PqJkgqdSwJgC+4Ah+UWrJOO6+P9YOPXqkSQU0E2X\n3/Ms2DyjUzBRMB0GA1UdDgQWBBSm1U4Fmh4j9eJDVa8qBOrkxqLhajAfBgNVHSME\nGDAWgBSm1U4Fmh4j9eJDVa8qBOrkxqLhajAPBgNVHRMBAf8EBTADAQH/MAoGCCqG\nSM49BAMCA0gAMEUCIQCY7d0XHVz7AmAFZrYTIVFmRn/PV+0qRu9HSqwvU1HYNgIg\nXKJM6e/0ckLhqLGB1lN9Bz/cvyZuYIcHLgMrlvNUwYE=\n-----END CERTIFICATE-----\n",
	}
}
