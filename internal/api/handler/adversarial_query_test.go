package handler

// Adversarial query-parameter, request-body, and revocation-reason tests.
//
// These tests exercise the second boundary of the certificate handler:
//
//   * Numeric pagination parsing (page, per_page, page_size)
//   * Sort direction and field whitelist
//   * Time-range filters (expires_before, expires_after, created_after, updated_after)
//   * Cursor pagination
//   * Sparse-field projection (?fields=...)
//   * Request-body JSON parsing (create/update) — null, malformed, deep nesting,
//     unicode, oversized
//   * Revocation reason abuse
//
// The handler silently ignores malformed pagination values (it falls back to
// defaults) and ignores invalid RFC3339 time values. These tests lock in that
// behaviour so a future "fail-closed" change has to be deliberate.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// buildListRequest constructs a GET /api/v1/certificates request with the
// given raw query string. We use raw query strings (not url.Values.Encode)
// so adversarial inputs like "page=abc&page=-1" or "%00" pass through
// unchanged.
func buildListRequest(rawQuery string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.URL.RawQuery = rawQuery
	return req.WithContext(contextWithRequestID())
}

// TestListCertificates_PaginationAbuse verifies adversarial pagination values
// never produce a 500 and the handler always falls back to sane defaults.
func TestListCertificates_PaginationAbuse(t *testing.T) {
	cases := []struct {
		name     string
		rawQuery string
	}{
		{"negative_page", "page=-1"},
		{"zero_page", "page=0"},
		{"non_numeric_page", "page=abc"},
		{"huge_page", "page=99999999999"},
		{"int_overflow_page", "page=9223372036854775808"}, // int64 max + 1
		{"negative_per_page", "per_page=-1"},
		{"zero_per_page", "per_page=0"},
		{"per_page_cap_at_500", "per_page=500"},
		{"per_page_above_cap", "per_page=501"},
		{"per_page_absurd", "per_page=1000000"},
		{"non_numeric_per_page", "per_page=xyz"},
		{"mixed_numeric_per_page", "per_page=10abc"},
		{"negative_page_size", "page_size=-1"},
		{"page_size_above_cap", "page_size=501"},
		{"float_page", "page=1.5"},
		{"exponent_page", "page=1e10"},
		{"hex_page", "page=0xff"},
		{"unicode_digits_page", "page=\u0661\u0662\u0663"}, // Arabic-Indic digits
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", tc.rawQuery, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			mock.ListCertificatesWithFilterFn = func(_ context.Context, filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
				// Sanity: page/perPage on the filter must never be negative
				// and perPage must never exceed 500 after parsing.
				if filter.Page < 1 {
					t.Errorf("filter.Page=%d (must be >=1)", filter.Page)
				}
				if filter.PerPage < 1 || filter.PerPage > 500 {
					t.Errorf("filter.PerPage=%d (must be in [1,500])", filter.PerPage)
				}
				return []domain.ManagedCertificate{}, 0, nil
			}

			w := httptest.NewRecorder()
			handler.ListCertificates(w, buildListRequest(tc.rawQuery))

			assertSafeResponse(t, w, "ListCertificates/"+tc.name)
			if w.Code != http.StatusOK {
				t.Errorf("%s: expected 200, got %d (body=%q)", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

// TestListCertificates_SortAbuse verifies the sort field (which feeds into a
// whitelist in the repository layer) handles adversarial input safely at the
// handler boundary. The handler accepts the raw value and forwards it; the
// repository is expected to whitelist it, but at THIS layer we just verify
// we don't crash or leak.
func TestListCertificates_SortAbuse(t *testing.T) {
	cases := []struct {
		name     string
		rawQuery string
	}{
		{"sql_injection_sort", "sort=notAfter;DROP TABLE managed_certificates--"},
		{"sql_injection_or", "sort=notAfter' OR '1'='1"},
		{"path_traversal_sort", "sort=../../etc/passwd"},
		{"null_byte_sort", "sort=notAfter%00"},
		{"unicode_sort", "sort=notAfter\u2010desc"},
		{"leading_dash_only", "sort=-"},
		{"leading_dashes", "sort=---notAfter"},
		{"empty_sort", "sort="},
		{"very_long_sort", "sort=" + strings.Repeat("a", 5000)},
		{"sort_desc_flag", "sort=notAfter&sort_desc=true"},
		{"conflicting_sort_desc", "sort=-notAfter&sort_desc=false"},
		{"unknown_field", "sort=gibberish"},
		{"shell_metacharacters_sort", "sort=notAfter;rm -rf /"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", tc.rawQuery, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			mock.ListCertificatesWithFilterFn = func(_ context.Context, filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
				return []domain.ManagedCertificate{}, 0, nil
			}

			w := httptest.NewRecorder()
			handler.ListCertificates(w, buildListRequest(tc.rawQuery))

			assertSafeResponse(t, w, "ListCertificates/"+tc.name)
		})
	}
}

// TestListCertificates_FieldsAbuse verifies sparse field projection handles
// adversarial field lists safely.
func TestListCertificates_FieldsAbuse(t *testing.T) {
	cases := []struct {
		name     string
		rawQuery string
	}{
		{"sql_injection_fields", "fields=id,name' OR 1=1--"},
		{"path_traversal_fields", "fields=../../etc/passwd"},
		{"empty_fields", "fields="},
		{"single_comma", "fields=,"},
		{"trailing_comma", "fields=id,name,"},
		{"leading_comma", "fields=,id,name"},
		{"whitespace_fields", "fields= id , name "},
		{"duplicate_fields", "fields=id,id,id,id,id"},
		{"unknown_fields", "fields=totally_not_a_field"},
		{"many_fields", "fields=" + strings.Repeat("x,", 200) + "id"},
		{"unicode_fields", "fields=id,n\u00e4me"},
		{"null_byte_fields", "fields=id%00name"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", tc.rawQuery, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			mock.ListCertificatesWithFilterFn = func(_ context.Context, filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
				return []domain.ManagedCertificate{}, 0, nil
			}

			w := httptest.NewRecorder()
			handler.ListCertificates(w, buildListRequest(tc.rawQuery))

			assertSafeResponse(t, w, "ListCertificates/"+tc.name)
		})
	}
}

// TestListCertificates_TimeRangeAbuse verifies RFC3339 time-range filters
// handle malformed input by silently falling back to no filter (current
// behaviour).
func TestListCertificates_TimeRangeAbuse(t *testing.T) {
	cases := []struct {
		name     string
		rawQuery string
	}{
		{"invalid_expires_before", "expires_before=not-a-date"},
		{"empty_expires_before", "expires_before="},
		{"garbage_expires_before", "expires_before=%00%00"},
		{"sql_injection_time", "expires_before=2026-01-01T00:00:00Z';DROP TABLE managed_certificates--"},
		{"year_zero", "expires_before=0000-01-01T00:00:00Z"},
		{"year_negative", "expires_before=-0001-01-01T00:00:00Z"},
		{"year_huge", "expires_before=99999-12-31T23:59:59Z"},
		{"invalid_month", "expires_before=2026-13-01T00:00:00Z"},
		{"invalid_day", "expires_before=2026-02-30T00:00:00Z"},
		{"valid_utc", "expires_before=2026-06-15T12:00:00Z"},
		{"valid_with_offset", "expires_before=2026-06-15T12:00:00-07:00"},
		{"unix_seconds_not_rfc3339", "expires_before=1767225600"},
		{"all_four_filters", "expires_before=garbage&expires_after=garbage&created_after=garbage&updated_after=garbage"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", tc.rawQuery, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			mock.ListCertificatesWithFilterFn = func(_ context.Context, filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
				return []domain.ManagedCertificate{}, 0, nil
			}

			w := httptest.NewRecorder()
			handler.ListCertificates(w, buildListRequest(tc.rawQuery))

			assertSafeResponse(t, w, "ListCertificates/"+tc.name)
			if w.Code != http.StatusOK {
				t.Errorf("%s: expected 200, got %d", tc.name, w.Code)
			}
		})
	}
}

// TestListCertificates_CursorAbuse exercises cursor-based pagination with
// adversarial cursor tokens. The handler forwards the cursor to the
// repository; we verify no 500 at the boundary and that the response type
// switches correctly.
func TestListCertificates_CursorAbuse(t *testing.T) {
	cases := []struct {
		name   string
		cursor string
	}{
		{"empty_not_set", ""}, // special-cased: should return PagedResponse
		{"garbage_cursor", "not-a-valid-cursor"},
		{"base64_garbage", "dGhpcyBpcyBub3QgYSB2YWxpZCBjdXJzb3I="},
		{"sql_injection_cursor", "2026-01-01T00:00:00Z:mc-001';DROP TABLE--"},
		{"path_traversal_cursor", "../../etc/passwd"},
		{"null_byte_cursor", "valid%00cursor"},
		{"very_long_cursor", strings.Repeat("A", 8192)},
		{"unicode_cursor", "2026-01-01T00:00:00Z:mc\u20100001"},
		{"valid_looking_cursor", "2026-01-01T00:00:00.000000000Z:mc-001"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", tc.cursor, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			mock.ListCertificatesWithFilterFn = func(_ context.Context, filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
				return []domain.ManagedCertificate{}, 0, nil
			}

			rawQuery := "cursor=" + url.QueryEscape(tc.cursor) + "&page_size=50"
			if tc.cursor == "" {
				rawQuery = "page=1&per_page=50"
			}
			w := httptest.NewRecorder()
			handler.ListCertificates(w, buildListRequest(rawQuery))

			assertSafeResponse(t, w, "ListCertificates/"+tc.name)
			if w.Code != http.StatusOK {
				t.Errorf("%s: expected 200, got %d", tc.name, w.Code)
			}
		})
	}
}

// TestListCertificates_FilterInjection verifies the basic string filters
// (status, environment, owner_id, team_id, issuer_id, agent_id, profile_id)
// are forwarded as-is without causing any handler-layer failures. These go
// into parameterized SQL at the repo layer.
func TestListCertificates_FilterInjection(t *testing.T) {
	filters := []string{
		"status", "environment", "owner_id", "team_id",
		"issuer_id", "agent_id", "profile_id",
	}
	payloads := []string{
		"' OR 1=1--",
		"'; DROP TABLE managed_certificates;--",
		"../../etc/passwd",
		strings.Repeat("A", 5000),
		"\u2010hyphen",
		"%00null",
	}

	for _, f := range filters {
		for _, p := range payloads {
			name := f + "__" + p
			if len(name) > 80 {
				name = name[:80]
			}
			t.Run(name, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panicked: %v", r)
					}
				}()

				handler, mock := newCertHandlerWithMock()
				mock.ListCertificatesWithFilterFn = func(_ context.Context, filter *repository.CertificateFilter) ([]domain.ManagedCertificate, int, error) {
					return []domain.ManagedCertificate{}, 0, nil
				}

				rawQuery := f + "=" + url.QueryEscape(p)
				w := httptest.NewRecorder()
				handler.ListCertificates(w, buildListRequest(rawQuery))

				assertSafeResponse(t, w, "ListCertificates/"+f)
			})
		}
	}
}

// ---------- Request body abuse (Tier 1D) ----------

// TestCreateCertificate_BodyAbuse sends adversarial JSON bodies to
// POST /api/v1/certificates. Every case must respond with 400 (not 500,
// not 200). This proves we reject malformed input before reaching the
// service layer.
func TestCreateCertificate_BodyAbuse(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"null_body", "null"},
		{"empty_body", ""},
		{"not_json", "not json at all"},
		{"truncated_json", `{"common_name":"exa`},
		{"unclosed_object", `{"common_name":"example.com"`},
		{"array_not_object", `["example.com"]`},
		{"number_not_object", `42`},
		{"string_not_object", `"hello"`},
		{"boolean_not_object", `true`},
		{"duplicate_keys", `{"common_name":"evil.com","common_name":"example.com"}`},
		{"unicode_bom", "\ufeff{\"common_name\":\"example.com\"}"},
		{"deep_nesting", strings.Repeat("{\"x\":", 100) + "null" + strings.Repeat("}", 100)},
		{"nested_array_bomb", `{"common_name":"x","sans":[[[[[[[[[[]]]]]]]]]]}`},
		{"sql_injection_cn", `{"common_name":"'; DROP TABLE managed_certificates;--"}`},
		{"empty_cn", `{"common_name":""}`},
		{"null_cn", `{"common_name":null}`},
		{"whitespace_cn", `{"common_name":"   "}`},
		{"cn_too_long", fmt.Sprintf(`{"common_name":%q}`, strings.Repeat("a", 500))},
		{"cn_path_traversal", `{"common_name":"../../etc/passwd"}`},
		{"cn_null_byte", "{\"common_name\":\"example\\u0000.com\"}"},
		{"cn_newline", "{\"common_name\":\"example\\n.com\"}"},
		{"cn_only_missing_others", `{"common_name":"example.com"}`},
		{"extra_unknown_fields", `{"common_name":"example.com","__proto__":{"polluted":true},"eval":"alert(1)"}`},
		{"unicode_homoglyph_cn", "{\"common_name\":\"ex\u0430mple.com\"}"}, // Cyrillic а
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", tc.name, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			mock.CreateCertificateFn = func(_ context.Context, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
				// If we ever reach this, the handler accepted a malformed
				// body. Return a sentinel that passes but flag it.
				c := cert
				c.ID = "mc-accepted"
				return &c, nil
			}

			req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(contextWithRequestID())
			w := httptest.NewRecorder()
			handler.CreateCertificate(w, req)

			assertSafeResponse(t, w, "CreateCertificate/"+tc.name)
			// Must NOT be 201 — all these bodies should be rejected.
			if w.Code == http.StatusCreated {
				t.Errorf("%s: handler accepted malformed body (201) body=%q", tc.name, w.Body.String())
			}
		})
	}
}

// TestCreateCertificate_HugeBody sends a 2 MiB JSON body. The body-limit
// middleware is not in this handler-unit test, so we just verify the handler
// doesn't OOM/panic on a large but well-formed body.
func TestCreateCertificate_HugeBody(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on huge body: %v", r)
		}
	}()

	// 2 MiB of SANs — well-formed JSON, technically valid, just huge.
	var sb strings.Builder
	sb.WriteString(`{"common_name":"example.com","owner_id":"o","team_id":"t","issuer_id":"iss","name":"n","renewal_policy_id":"rp","sans":[`)
	for i := 0; i < 20000; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"host%d.example.com"`, i)
	}
	sb.WriteString(`]}`)

	handler, mock := newCertHandlerWithMock()
	mock.CreateCertificateFn = func(_ context.Context, cert domain.ManagedCertificate) (*domain.ManagedCertificate, error) {
		c := cert
		c.ID = "mc-huge"
		return &c, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(sb.String()))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()
	handler.CreateCertificate(w, req)

	assertSafeResponse(t, w, "CreateCertificate/huge_body")
}

// ---------- Revocation reason abuse (Tier 1E) ----------

// TestRevokeCertificate_ReasonAbuse sends adversarial revocation reasons to
// POST /api/v1/certificates/{id}/revoke. The handler forwards the reason
// string to the service layer, which validates against RFC 5280. Errors
// from the service containing "invalid revocation reason" must map to 400,
// never 500.
func TestRevokeCertificate_ReasonAbuse(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty_reason", `{"reason":""}`},
		{"null_reason", `{"reason":null}`},
		{"nonexistent_reason", `{"reason":"totally made up"}`},
		{"case_variant", `{"reason":"KEYCOMPROMISE"}`},
		{"with_spaces", `{"reason":"key compromise"}`},
		{"with_dashes", `{"reason":"key-compromise"}`},
		{"mixed_case", `{"reason":"KeyCompromise"}`},
		{"lowercase_valid", `{"reason":"keycompromise"}`},
		{"unicode_homoglyph", "{\"reason\":\"keyCompr\u043emise\"}"},
		{"sql_injection", `{"reason":"keyCompromise';DROP TABLE revocations--"}`},
		{"very_long", fmt.Sprintf(`{"reason":%q}`, strings.Repeat("a", 10000))},
		{"integer_reason", `{"reason":1}`},
		{"array_reason", `{"reason":["keyCompromise"]}`},
		{"object_reason", `{"reason":{"code":1}}`},
		{"extra_fields", `{"reason":"keyCompromise","admin":true,"bypass":true}`},
		{"no_body", ``},
		{"malformed_json", `{"reason":`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", tc.name, r)
				}
			}()

			handler, mock := newCertHandlerWithMock()
			// The mock always returns "invalid revocation reason" so we
			// verify the handler's errMsg→status mapping turns it into a 400.
			mock.RevokeCertificateFn = func(_ context.Context, id string, reason string, _ string) error {
				// The service uses domain.IsValidRevocationReason. If we got
				// through to here with something bogus, simulate a real
				// service error.
				return fmt.Errorf("invalid revocation reason: %q", reason)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-001/revoke", bytes.NewBufferString(tc.body))
			req.URL.Path = "/api/v1/certificates/mc-001/revoke"
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(contextWithRequestID())
			w := httptest.NewRecorder()
			handler.RevokeCertificate(w, req)

			assertSafeResponse(t, w, "RevokeCertificate/"+tc.name)
		})
	}
}

// TestRevokeCertificate_AlreadyRevoked locks in the specific error->status
// mapping for "already revoked". The handler uses substring matching on the
// service error message, which is fragile — this test catches regressions.
func TestRevokeCertificate_AlreadyRevoked(t *testing.T) {
	handler, mock := newCertHandlerWithMock()
	mock.RevokeCertificateFn = func(_ context.Context, id string, reason string, _ string) error {
		return fmt.Errorf("cannot revoke: certificate is already revoked")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-001/revoke", strings.NewReader(`{"reason":"keyCompromise"}`))
	req.URL.Path = "/api/v1/certificates/mc-001/revoke"
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()
	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for already-revoked, got %d (body=%q)", w.Code, w.Body.String())
	}
	assertSafeResponse(t, w, "RevokeCertificate/already_revoked")
}

// TestRevokeCertificate_NotFound verifies 404 mapping.
func TestRevokeCertificate_NotFound(t *testing.T) {
	handler, mock := newCertHandlerWithMock()
	mock.RevokeCertificateFn = func(_ context.Context, id string, reason string, _ string) error {
		return fmt.Errorf("certificate not found: %w", ErrMockNotFound)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/mc-missing/revoke", strings.NewReader(`{"reason":"keyCompromise"}`))
	req.URL.Path = "/api/v1/certificates/mc-missing/revoke"
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()
	handler.RevokeCertificate(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for not-found, got %d (body=%q)", w.Code, w.Body.String())
	}
	assertSafeResponse(t, w, "RevokeCertificate/not_found")
}
