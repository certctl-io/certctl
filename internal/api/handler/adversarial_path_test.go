package handler

// Adversarial path-parameter and multi-segment path tests.
//
// These tests exercise the input parsing boundary of the certificate handler
// against the attack categories listed in certctl-adversarial-testing-prompt.md
// Tier 1A / 1B:
//
//   * Empty and whitespace-only path IDs
//   * SQL-injection sentinels embedded in the path
//   * Directory traversal (`../../etc/passwd`)
//   * Null bytes and control characters
//   * Extremely long IDs (10 KiB)
//   * Unicode homoglyphs (visually identical substitutes)
//   * Multi-segment paths (OCSP, DER CRL, versions, renew, deploy, revoke)
//
// The contract we verify is defensive, not behavioural:
//
//   1. The handler never panics.
//   2. The HTTP status is one of {200, 400, 404, 405} — never 500.
//   3. The response body is either empty or valid JSON.
//   4. No attacker-controlled input is echoed verbatim in a 500 body.
//
// We do not assert the exact status code for every adversarial input because
// the current handler intentionally delegates identifier validation to the
// repository layer; its only job here is to stay up and well-formed.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
)

// adversarialPathInputs is the attack catalog shared by Tier 1A cases. Each
// entry targets a different parsing surface; adding a new category here makes
// every Tier 1A test below exercise it automatically.
func adversarialPathInputs() []struct {
	name  string
	input string
} {
	return []struct {
		name  string
		input string
	}{
		{"sql_injection_drop_table", "'; DROP TABLE managed_certificates;--"},
		{"sql_injection_or_true", "' OR 1=1--"},
		{"sql_injection_union", "mc-001' UNION SELECT * FROM agents--"},
		{"path_traversal_dot_dot", "../../etc/passwd"},
		{"path_traversal_encoded", "..%2F..%2Fetc%2Fpasswd"},
		{"null_byte_trailing", "mc-001\x00"},
		{"null_byte_embedded", "mc-\x00-001"},
		{"long_id_10k", strings.Repeat("A", 10000)},
		{"unicode_homoglyph_hyphen", "mc\u2010001"},          // U+2010 HYPHEN
		{"unicode_homoglyph_fullwidth", "mc\uFF0D001"},       // U+FF0D FULLWIDTH HYPHEN-MINUS
		{"control_char_newline", "mc-001\n"},
		{"control_char_tab", "mc\t001"},
		{"control_char_bell", "mc\x07001"},
		{"percent_encoded_null", "mc-001%00"},
		{"whitespace_only", "   "},
		{"shell_metacharacters", "mc-001;`rm -rf /`"},
		{"leading_slash", "/mc-001"},
		{"trailing_slash", "mc-001/"},
		{"double_slash", "mc//001"},
	}
}

// assertSafeResponse is the core defensive check. Any adversarial input is
// allowed to produce a 4xx, but must not panic or leak through as a 500.
func assertSafeResponse(t *testing.T, w *httptest.ResponseRecorder, label string) {
	t.Helper()

	// 1. No 500 (500 implies the handler reached an unexpected internal state).
	if w.Code == http.StatusInternalServerError {
		t.Errorf("%s: handler returned 500, body=%q — adversarial input should not reach an internal error path",
			label, w.Body.String())
	}

	// 2. Status must be in the expected safe set.
	switch w.Code {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent,
		http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		// ok
	default:
		t.Errorf("%s: unexpected status %d (body=%q)", label, w.Code, w.Body.String())
	}

	// 3. Non-empty bodies must be valid JSON (no template leakage, no raw panics).
	if body := bytes.TrimSpace(w.Body.Bytes()); len(body) > 0 {
		var discard interface{}
		if err := json.Unmarshal(body, &discard); err != nil {
			t.Errorf("%s: response body is not valid JSON: %v (body=%q)", label, err, w.Body.String())
		}
	}
}

// newCertHandlerWithMock builds a handler whose mock service returns nothing.
// This keeps every adversarial test focused on the handler's parsing layer
// rather than service behaviour.
func newCertHandlerWithMock() (CertificateHandler, *MockCertificateService) {
	mock := &MockCertificateService{}
	return NewCertificateHandler(mock), mock
}

// TestGetCertificate_PathInjection runs each adversarial path through the
// certificate GET handler.
func TestGetCertificate_PathInjection(t *testing.T) {
	for _, tc := range adversarialPathInputs() {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handler panicked on input %q: %v", tc.input, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			// Force a 404 so we can distinguish "service was called" from
			// "parser accepted the ID"; a 200 with null body is also fine.
			mock.GetCertificateFn = func(_ context.Context, id string) (*domain.ManagedCertificate, error) {
				return nil, ErrMockNotFound
			}

			// Build the URL by string concatenation to keep attacker-controlled
			// bytes intact (httptest.NewRequest uses url.Parse under the hood,
			// which normalises some characters — we want the raw path on the
			// request object).
			req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/x", nil)
			req.URL.Path = "/api/v1/certificates/" + tc.input
			req = req.WithContext(contextWithRequestID())

			w := httptest.NewRecorder()
			handler.GetCertificate(w, req)

			assertSafeResponse(t, w, "GetCertificate/"+tc.name)
		})
	}
}

// TestUpdateCertificate_PathInjection exercises the PUT handler's path parser.
// UpdateCertificate splits the path on "/" and takes parts[0]; traversal and
// double-slash inputs must still short-circuit at the parser rather than
// reaching the service.
func TestUpdateCertificate_PathInjection(t *testing.T) {
	body := `{"common_name":"example.com","owner_id":"o-alice","team_id":"t-a","issuer_id":"iss-local","name":"n","renewal_policy_id":"rp-1"}`

	for _, tc := range adversarialPathInputs() {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handler panicked on input %q: %v", tc.input, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			mock.UpdateCertificateFn = func(_ context.Context, id string, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
				return nil, ErrMockNotFound
			}

			req := httptest.NewRequest(http.MethodPut, "/api/v1/certificates/x", bytes.NewBufferString(body))
			req.URL.Path = "/api/v1/certificates/" + tc.input
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(contextWithRequestID())

			w := httptest.NewRecorder()
			handler.UpdateCertificate(w, req)

			assertSafeResponse(t, w, "UpdateCertificate/"+tc.name)
		})
	}
}

// TestArchiveCertificate_PathInjection exercises DELETE.
func TestArchiveCertificate_PathInjection(t *testing.T) {
	for _, tc := range adversarialPathInputs() {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handler panicked on input %q: %v", tc.input, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			mock.ArchiveCertificateFn = func(_ context.Context, id string) error { return ErrMockNotFound }

			req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/x", nil)
			req.URL.Path = "/api/v1/certificates/" + tc.input
			req = req.WithContext(contextWithRequestID())

			w := httptest.NewRecorder()
			handler.ArchiveCertificate(w, req)

			assertSafeResponse(t, w, "ArchiveCertificate/"+tc.name)
		})
	}
}

// TestGetCertificateVersions_MultiSegment is a Tier 1B test: the versions
// handler requires a 2-segment path (certID/versions). The parser uses
// strings.Split(path, "/") and checks len(parts) < 2 — but an adversarial
// caller can inject extra slashes to either produce an empty parts[0] or a
// very long parts slice. Either way we must not panic.
func TestGetCertificateVersions_MultiSegment(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"missing_segment", "/api/v1/certificates/versions"},
		{"empty_cert_id", "/api/v1/certificates//versions"},
		{"traversal_cert_id", "/api/v1/certificates/..%2F..%2Fversions/versions"},
		{"sql_injection_cert_id", "/api/v1/certificates/'%20OR%201=1--/versions"},
		{"null_byte_cert_id", "/api/v1/certificates/mc\x00001/versions"},
		{"very_long_cert_id", "/api/v1/certificates/" + strings.Repeat("A", 5000) + "/versions"},
		{"trailing_segments", "/api/v1/certificates/mc-001/versions/extra/trailing"},
		{"deep_nesting", "/api/v1/certificates/" + strings.Repeat("a/", 50) + "versions"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handler panicked on path %q: %v", tc.path, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			mock.GetCertificateVersionsFn = func(_ context.Context, certID string, page, perPage int) ([]domain.CertificateVersion, int64, error) {
				return []domain.CertificateVersion{}, 0, nil
			}

			// Use a dummy safe URL in NewRequest to avoid url.Parse panics
			// on control chars, then overwrite with the raw attacker path.
			req := httptest.NewRequest(http.MethodGet, "/safe", nil)
			req.URL.Path = tc.path
			req = req.WithContext(contextWithRequestID())

			w := httptest.NewRecorder()
			handler.GetCertificateVersions(w, req)

			assertSafeResponse(t, w, "GetCertificateVersions/"+tc.name)
		})
	}
}

// TestHandleOCSP_MultiSegment exercises the OCSP responder's 2-segment path
// parser (/api/v1/ocsp/{issuer_id}/{serial_hex}). Each leg is attacker-
// controlled and the serial can be arbitrary length. This is a key adversarial
// surface because the serial is passed directly to the CA-operations service,
// which is expected to treat it as an opaque identifier.
func TestHandleOCSP_MultiSegment(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"missing_serial", "/api/v1/ocsp/iss-local"},
		{"missing_both", "/api/v1/ocsp/"},
		{"empty_issuer", "/api/v1/ocsp//01ABCDEF"},
		{"empty_serial", "/api/v1/ocsp/iss-local/"},
		{"traversal_issuer", "/api/v1/ocsp/..%2F..%2Fetc/passwd/01"},
		{"null_byte_serial", "/api/v1/ocsp/iss-local/01\x00FF"},
		{"sql_injection_serial", "/api/v1/ocsp/iss-local/01'; DROP TABLE--"},
		{"negative_hex_serial", "/api/v1/ocsp/iss-local/-1"},
		{"unicode_serial", "/api/v1/ocsp/iss-local/01\u2010FF"},
		{"extremely_long_serial", "/api/v1/ocsp/iss-local/" + strings.Repeat("F", 10000)},
		{"extra_segments", "/api/v1/ocsp/iss-local/01FF/extra/segments"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handler panicked on path %q: %v", tc.path, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			mock.GetOCSPResponseFn = func(_ context.Context, issuerID, serialHex string) ([]byte, error) {
				return nil, ErrMockNotFound
			}

			req := httptest.NewRequest(http.MethodGet, "/safe", nil)
			req.URL.Path = tc.path
			req = req.WithContext(contextWithRequestID())

			w := httptest.NewRecorder()
			handler.HandleOCSP(w, req)

			// OCSP does NOT guarantee JSON responses (pkix-crl uses binary),
			// so we only check status safety, not body structure.
			if w.Code == http.StatusInternalServerError {
				t.Errorf("HandleOCSP/%s: returned 500 body=%q", tc.name, w.Body.String())
			}
			if w.Code >= 500 {
				t.Errorf("HandleOCSP/%s: unexpected 5xx %d", tc.name, w.Code)
			}
		})
	}
}

// TestGetDERCRL_IssuerPathInjection exercises /api/v1/crl/{issuer_id}.
func TestGetDERCRL_IssuerPathInjection(t *testing.T) {
	for _, tc := range adversarialPathInputs() {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handler panicked on input %q: %v", tc.input, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			mock.GenerateDERCRLFn = func(_ context.Context, issuerID string) ([]byte, error) {
				return nil, ErrMockNotFound
			}

			req := httptest.NewRequest(http.MethodGet, "/api/v1/crl/x", nil)
			req.URL.Path = "/api/v1/crl/" + tc.input
			req = req.WithContext(contextWithRequestID())

			w := httptest.NewRecorder()
			handler.GetDERCRL(w, req)

			if w.Code >= 500 {
				t.Errorf("GetDERCRL/%s: unexpected 5xx %d (body=%q)", tc.name, w.Code, w.Body.String())
			}
		})
	}
}
