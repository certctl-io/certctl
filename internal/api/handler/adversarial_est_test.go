package handler

// Adversarial EST (RFC 7030) enrollment tests — Tier 1F.
//
// EST is the RFC 7030 protocol for certificate enrollment over HTTPS. The
// control-plane parser accepts PKCS#10 CSRs either as PEM or as base64-encoded
// DER, and it's a prime target for:
//
//   * Malformed base64 / non-DER payloads
//   * Valid base64 that doesn't decode to a valid CSR
//   * PEM header spoofing (wrong block type)
//   * Null bytes and control characters embedded in PEM or base64
//   * Huge CSR bodies (we expect the handler's 1 MiB LimitReader to clamp them)
//   * Truncated or partially-written PEM blocks
//   * Unicode homoglyphs in PEM delimiters
//   * Content-Type mismatch (handler ignores Content-Type, but attackers might
//     still try header spoofing)
//
// The contract is the same as other adversarial tiers: the handler must never
// panic and must never return 500 for a malformed CSR (500 is reserved for
// issuer/service failures). For adversarial CSRs, the correct status is 400.

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
)

// adversarialCSRInputs exercises the EST CSR parsing surface. None of these
// should reach the underlying ESTService — they must be rejected by
// readCSRFromRequest with a 400 before any service call is made.
func adversarialCSRInputs() []struct {
	name string
	body string
} {
	// A garbage base64 string that decodes cleanly but isn't a PKCS#10 CSR.
	// base64 of "this is definitely not a CSR" = dGhpcyBpcyBkZWZpbml0ZWx5IG5vdCBhIENTUg==
	nonCSRBase64 := base64.StdEncoding.EncodeToString([]byte("this is definitely not a CSR"))

	return []struct {
		name string
		body string
	}{
		{"garbage_string", "not-a-csr-at-all"},
		{"base64_garbage", "!!!@@@###$$$%%%"},
		{"base64_valid_non_csr", nonCSRBase64},
		{"base64_very_short", "AA=="},
		{"null_byte_only", "\x00"},
		{"null_bytes_padding", "\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"control_chars", "\x01\x02\x03\x04\x05\x06\x07\x08"},
		{"pem_wrong_block_type", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"},
		{"pem_wrong_header_close", "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END PRIVATE KEY-----\n"},
		{"pem_empty_block", "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"},
		{"pem_garbage_body", "-----BEGIN CERTIFICATE REQUEST-----\n!!!not base64!!!\n-----END CERTIFICATE REQUEST-----\n"},
		{"pem_truncated", "-----BEGIN CERTIFICATE REQUEST-----\nMIIBijCCAT"},
		{"pem_no_end_marker", "-----BEGIN CERTIFICATE REQUEST-----\nMIIBijCCATICAQAwFjEUMBIGA1UE\n"},
		{"pem_header_injection", "-----BEGIN CERTIFICATE REQUEST-----\r\nHost: evil.com\r\n\r\nMIIB\n-----END CERTIFICATE REQUEST-----\n"},
		{"pem_embedded_null", "-----BEGIN CERTIFICATE\x00REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"},
		{"unicode_homoglyph_pem", "-----BEGIN CERTIFICATE REQUEST─────\nMIIB\n─────END CERTIFICATE REQUEST-----\n"},
		{"double_pem_block", "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"},
		{"json_body", `{"csr":"MIIB","common_name":"attacker.com"}`},
		{"xml_body", `<?xml version="1.0"?><csr>MIIB</csr>`},
		{"shell_metacharacters", "$(whoami); rm -rf / #"},
		{"sql_injection", "' OR 1=1; DROP TABLE certificates;--"},
		{"long_garbage_10k", strings.Repeat("A", 10000)},
		{"long_base64_not_csr", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xFF}, 5000))},
		{"base64_with_newlines_garbage", "AAAAAAAAAAAAAAAA\nBBBBBBBBBBBBBBBB\nCCCCCCCCCCCCCCCC"},
		{"percent_encoded_pem", "%2D%2D%2D%2D%2DBEGIN+CERTIFICATE+REQUEST%2D%2D%2D%2D%2D"},
	}
}

// assertESTErrorResponse enforces the EST handler contract for adversarial CSRs:
// no panic, no 500, body is valid JSON (since Error helper emits JSON errors).
func assertESTErrorResponse(t *testing.T, w *httptest.ResponseRecorder, label string) {
	t.Helper()

	// The handler must never reach a 500 for parser-rejected CSRs — that would
	// indicate a service call slipped through.
	if w.Code == http.StatusInternalServerError {
		t.Errorf("%s: handler returned 500 body=%q — adversarial CSR should not reach the service layer",
			label, w.Body.String())
	}

	// The handler should return 400 Bad Request for adversarial CSR inputs.
	// A 405 (method not allowed) is impossible here because we always POST.
	if w.Code != http.StatusBadRequest {
		t.Errorf("%s: expected 400, got %d (body=%q)", label, w.Code, w.Body.String())
	}
}

// newESTHandlerWithTrap returns an ESTHandler whose service panics if reached.
// This is the core invariant for Tier 1F: adversarial CSRs must be rejected at
// the parser, never reaching SimpleEnroll/SimpleReEnroll on the service.
func newESTHandlerWithTrap() (ESTHandler, *trappedESTService) {
	svc := &trappedESTService{}
	return NewESTHandler(svc), svc
}

// trappedESTService is a mock that fails the test if any service method is
// called with an adversarial CSR. The parser should reject these before they
// get here.
type trappedESTService struct {
	serviceCalled bool
}

func (t *trappedESTService) GetCACerts(ctx context.Context) (string, error) {
	t.serviceCalled = true
	return "", errors.New("trap: GetCACerts should not be called from adversarial CSR tests")
}

func (t *trappedESTService) SimpleEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error) {
	t.serviceCalled = true
	return nil, errors.New("trap: SimpleEnroll should not be called from adversarial CSR tests")
}

func (t *trappedESTService) SimpleReEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error) {
	t.serviceCalled = true
	return nil, errors.New("trap: SimpleReEnroll should not be called from adversarial CSR tests")
}

func (t *trappedESTService) GetCSRAttrs(ctx context.Context) ([]byte, error) {
	t.serviceCalled = true
	return nil, errors.New("trap: GetCSRAttrs should not be called from adversarial CSR tests")
}

func (t *trappedESTService) SimpleServerKeygen(ctx context.Context, csrPEM string) (*domain.ESTServerKeygenResult, error) {
	t.serviceCalled = true
	return nil, errors.New("trap: SimpleServerKeygen should not be called from adversarial CSR tests")
}

// TestESTSimpleEnroll_AdversarialCSRs runs each adversarial CSR through the
// enrollment endpoint.
func TestESTSimpleEnroll_AdversarialCSRs(t *testing.T) {
	for _, tc := range adversarialCSRInputs() {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handler panicked on body %q: %v", tc.body, r)
				}
			}()

			h, svc := newESTHandlerWithTrap()

			req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/pkcs10")

			w := httptest.NewRecorder()
			h.SimpleEnroll(w, req)

			assertESTErrorResponse(t, w, "SimpleEnroll/"+tc.name)

			if svc.serviceCalled {
				t.Errorf("SimpleEnroll/%s: service was reached with adversarial CSR (body=%q)",
					tc.name, tc.body)
			}
		})
	}
}

// TestESTSimpleReEnroll_AdversarialCSRs runs each adversarial CSR through the
// re-enrollment endpoint. Same contract as simpleenroll.
func TestESTSimpleReEnroll_AdversarialCSRs(t *testing.T) {
	for _, tc := range adversarialCSRInputs() {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handler panicked on body %q: %v", tc.body, r)
				}
			}()

			h, svc := newESTHandlerWithTrap()

			req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simplereenroll", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/pkcs10")

			w := httptest.NewRecorder()
			h.SimpleReEnroll(w, req)

			assertESTErrorResponse(t, w, "SimpleReEnroll/"+tc.name)

			if svc.serviceCalled {
				t.Errorf("SimpleReEnroll/%s: service was reached with adversarial CSR (body=%q)",
					tc.name, tc.body)
			}
		})
	}
}

// TestESTSimpleEnroll_HugeBody verifies the handler's 1 MiB limit truncates
// oversized requests at the LimitReader boundary. We send a 2 MiB body of
// base64 garbage and confirm the handler rejects it cleanly (400, no panic,
// no 500) and the service is never reached.
func TestESTSimpleEnroll_HugeBody(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handler panicked on 2 MiB body: %v", r)
		}
	}()

	// 2 MiB of base64-valid garbage: the LimitReader will truncate to 1 MiB, and
	// the truncated base64 chunk won't parse as a valid PKCS#10 CSR.
	huge := strings.Repeat("A", 2<<20)

	h, svc := newESTHandlerWithTrap()

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(huge))
	req.Header.Set("Content-Type", "application/pkcs10")

	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	// Contract: 400 Bad Request (parser fail), no panic, no 500.
	if w.Code == http.StatusInternalServerError {
		t.Errorf("HugeBody: handler returned 500 for 2 MiB body (body=%q)", w.Body.String())
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("HugeBody: expected 400, got %d (body=%q)", w.Code, w.Body.String())
	}
	if svc.serviceCalled {
		t.Error("HugeBody: service was reached with 2 MiB adversarial body")
	}
}

// TestESTSimpleEnroll_ExactlyAtLimit sends a body exactly at the 1 MiB
// LimitReader boundary. The body is still garbage (won't parse as CSR), but we
// verify the handler doesn't panic or hang on the boundary case.
func TestESTSimpleEnroll_ExactlyAtLimit(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handler panicked on exact-limit body: %v", r)
		}
	}()

	atLimit := strings.Repeat("A", 1<<20) // exactly 1 MiB

	h, _ := newESTHandlerWithTrap()

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(atLimit))
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	if w.Code == http.StatusInternalServerError {
		t.Errorf("ExactlyAtLimit: handler returned 500 (body=%q)", w.Body.String())
	}
}

// TestESTSimpleEnroll_MultipartBody sends a multipart/form-data body that a
// naive parser might try to unwrap. The handler should treat the raw bytes as
// a CSR payload and reject them.
func TestESTSimpleEnroll_MultipartBody(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handler panicked on multipart body: %v", r)
		}
	}()

	multipart := "--boundary\r\nContent-Disposition: form-data; name=\"csr\"\r\n\r\nMIIB\r\n--boundary--\r\n"

	h, svc := newESTHandlerWithTrap()

	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(multipart))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	w := httptest.NewRecorder()
	h.SimpleEnroll(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("MultipartBody: expected 400, got %d (body=%q)", w.Code, w.Body.String())
	}
	if svc.serviceCalled {
		t.Error("MultipartBody: service was reached with multipart wrapper")
	}
}

// TestESTCACerts_MethodAbuse verifies the /cacerts endpoint only accepts GET
// and rejects every other method cleanly. This is a small safety check for
// the spec invariant.
func TestESTCACerts_MethodAbuse(t *testing.T) {
	methods := []string{
		http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodHead, http.MethodOptions,
		"TRACE", "CONNECT", "PROPFIND", "BOGUS",
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handler panicked on method %s: %v", method, r)
				}
			}()

			h, _ := newESTHandlerWithTrap()

			req := httptest.NewRequest(method, "/.well-known/est/cacerts", nil)
			w := httptest.NewRecorder()
			h.CACerts(w, req)

			// HEAD on a GET handler in Go's stdlib is normally accepted, but
			// this handler enforces strict GET-only — so HEAD should also get 405.
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("method %s: expected 405, got %d", method, w.Code)
			}
		})
	}
}

// TestESTSimpleEnroll_MethodAbuse verifies strict POST-only enforcement.
func TestESTSimpleEnroll_MethodAbuse(t *testing.T) {
	methods := []string{
		http.MethodGet, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodHead, http.MethodOptions,
		"TRACE", "CONNECT",
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handler panicked on method %s: %v", method, r)
				}
			}()

			h, svc := newESTHandlerWithTrap()

			req := httptest.NewRequest(method, "/.well-known/est/simpleenroll", strings.NewReader("body"))
			w := httptest.NewRecorder()
			h.SimpleEnroll(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("method %s: expected 405, got %d", method, w.Code)
			}
			if svc.serviceCalled {
				t.Errorf("method %s: service was called for non-POST", method)
			}
		})
	}
}
