package entrust

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Bundle N.A/B-extended: entrust failure-mode round-out (70.8% → ≥85%).
// Targets uncovered branches in ValidateConfig / GetOrderStatus /
// loadMTLSConfig / parseCertMetadata / mapRevocationReason.
//
// In-package (white-box) tests so we can exercise unexported helpers
// directly.

func buildEntrustConnector(t *testing.T, baseURL string) *Connector {
	t.Helper()
	cfg := &Config{
		APIUrl: baseURL,
		CAId:   "test-ca-id",
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	return NewWithHTTPClient(cfg, slog.Default(), httpClient)
}

// ─────────────────────────────────────────────────────────────────────────────
// mapRevocationReason: every RFC 5280 reason string + nil + default
// ─────────────────────────────────────────────────────────────────────────────

func TestEntrust_MapRevocationReason_AllArms(t *testing.T) {
	cases := []struct {
		reason   *string
		expected string
	}{
		{nil, "Unspecified"},
		{strPtr(""), "Unspecified"},
		{strPtr("unspecified"), "Unspecified"},
		{strPtr("keyCompromise"), "KeyCompromise"},
		{strPtr("caCompromise"), "CACompromise"},
		{strPtr("affiliationChanged"), "AffiliationChanged"},
		{strPtr("superseded"), "Superseded"},
		{strPtr("cessationOfOperation"), "CessationOfOperation"},
		{strPtr("certificateHold"), "CertificateHold"},
		{strPtr("privilegeWithdrawn"), "PrivilegeWithdrawn"},
		{strPtr("frobnicated"), "Unspecified"}, // unknown → default
	}
	for _, tc := range cases {
		name := "nil"
		if tc.reason != nil {
			name = *tc.reason
			if name == "" {
				name = "empty"
			}
		}
		t.Run(name, func(t *testing.T) {
			got := mapRevocationReason(tc.reason)
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func strPtr(s string) *string { return &s }

// ─────────────────────────────────────────────────────────────────────────────
// parseCertMetadata: malformed-PEM + bad-DER branches
// ─────────────────────────────────────────────────────────────────────────────

func TestEntrust_ParseCertMetadata_NotPEM(t *testing.T) {
	_, _, _, err := parseCertMetadata("not a pem block")
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected decode error, got %v", err)
	}
}

func TestEntrust_ParseCertMetadata_BadDER(t *testing.T) {
	pemBlock := "-----BEGIN CERTIFICATE-----\nbm90LWEtZGVy\n-----END CERTIFICATE-----\n"
	_, _, _, err := parseCertMetadata(pemBlock)
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// loadMTLSConfig: nonexistent file + nonexistent key
// ─────────────────────────────────────────────────────────────────────────────

func TestEntrust_LoadMTLSConfig_NonexistentFile(t *testing.T) {
	_, err := loadMTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil || !strings.Contains(err.Error(), "load client certificate") {
		t.Errorf("expected load error, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateConfig: required-field misses + unreachable URL
// ─────────────────────────────────────────────────────────────────────────────

func TestEntrust_ValidateConfig_MissingFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"missing api_url", Config{ClientCertPath: "/c", ClientKeyPath: "/k", CAId: "ca"}, "api_url"},
		{"missing client_cert_path", Config{APIUrl: "http://x", ClientKeyPath: "/k", CAId: "ca"}, "client_cert_path"},
		{"missing client_key_path", Config{APIUrl: "http://x", ClientCertPath: "/c", CAId: "ca"}, "client_key_path"},
		{"missing ca_id", Config{APIUrl: "http://x", ClientCertPath: "/c", ClientKeyPath: "/k"}, "ca_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(nil, slog.Default())
			raw, _ := json.Marshal(tc.cfg)
			err := c.ValidateConfig(context.Background(), raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestEntrust_ValidateConfig_BadCertPath(t *testing.T) {
	c := New(nil, slog.Default())
	cfg := Config{
		APIUrl:         "http://example.invalid",
		ClientCertPath: "/nonexistent/cert.pem",
		ClientKeyPath:  "/nonexistent/key.pem",
		CAId:           "ca-1",
	}
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil || !strings.Contains(err.Error(), "mTLS credentials") {
		t.Errorf("expected mTLS credentials error, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetOrderStatus: 403 / malformed JSON / unknown status / pending happy path
// ─────────────────────────────────────────────────────────────────────────────

func TestEntrust_GetOrderStatus_403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := buildEntrustConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "tracking-id")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 error, got %v", err)
	}
}

func TestEntrust_GetOrderStatus_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()
	c := buildEntrustConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "tracking-id")
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestEntrust_GetOrderStatus_StatusVariants(t *testing.T) {
	cases := []struct {
		statusVal string
		want      string
	}{
		{"PENDING", "pending"},
		{"PROCESSING", "pending"},
		{"REJECTED", "failed"},
		{"DENIED", "failed"},
		{"FAILED", "failed"},
		{"WeirdStatus", "pending"}, // unknown → default pending
	}
	for _, tc := range cases {
		t.Run(tc.statusVal, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":     tc.statusVal,
					"trackingId": "tid-1",
				})
			}))
			defer srv.Close()
			c := buildEntrustConnector(t, srv.URL)
			st, err := c.GetOrderStatus(context.Background(), "tid-1")
			if err != nil {
				t.Fatalf("GetOrderStatus: %v", err)
			}
			if st.Status != tc.want {
				t.Errorf("expected status=%q for input=%q, got %q", tc.want, tc.statusVal, st.Status)
			}
		})
	}
}
