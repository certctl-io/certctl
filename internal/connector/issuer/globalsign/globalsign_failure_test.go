package globalsign_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/issuer/globalsign"
)

// Bundle N.A/B-extended: globalsign failure-mode round-out (78.2% → ≥85%).
// Targets uncovered branches in getHTTPClient / GetOrderStatus / parseCertDates.

func buildGlobalsignConnector(t *testing.T, baseURL string) *globalsign.Connector {
	t.Helper()
	cfg := &globalsign.Config{
		APIUrl:    baseURL,
		APIKey:    "k",
		APISecret: "s",
	}
	// Use NewWithHTTPClient with a test client so getHTTPClient short-circuits
	// (no mTLS cert loading). Custom transport is required so the
	// `httpClient.Transport != nil` test-mode check fires.
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	return globalsign.NewWithHTTPClient(cfg, slog.Default(), httpClient)
}

func TestGlobalsign_GetOrderStatus_403_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()
	c := buildGlobalsignConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "serial-123")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 error, got %v", err)
	}
}

func TestGlobalsign_GetOrderStatus_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()
	c := buildGlobalsignConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "serial-123")
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestGlobalsign_GetOrderStatus_StatusVariants(t *testing.T) {
	cases := []struct {
		statusVal string
		want      string
	}{
		{"pending", "pending"},
		{"processing", "pending"},
		{"rejected", "failed"},
		{"denied", "failed"},
		{"failed", "failed"},
		{"weird-new-status", "pending"}, // unknown → default pending
	}
	for _, tc := range cases {
		t.Run(tc.statusVal, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":        tc.statusVal,
					"serial_number": "serial-123",
				})
			}))
			defer srv.Close()
			c := buildGlobalsignConnector(t, srv.URL)
			st, err := c.GetOrderStatus(context.Background(), "serial-123")
			if err != nil {
				t.Fatalf("GetOrderStatus: %v", err)
			}
			if st.Status != tc.want {
				t.Errorf("expected status=%q for input=%q, got %q", tc.want, tc.statusVal, st.Status)
			}
		})
	}
}

func TestGlobalsign_GetOrderStatus_IssuedButCertMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"issued","certificate":""}`))
	}))
	defer srv.Close()
	c := buildGlobalsignConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "serial-123")
	if err == nil || !strings.Contains(err.Error(), "certificate PEM is missing") {
		t.Errorf("expected 'certificate PEM is missing' error, got %v", err)
	}
}

func TestGlobalsign_GetOrderStatus_IssuedWithMalformedPEM_NonFatalParseDateWarning(t *testing.T) {
	// When status=issued and certificate is non-empty but doesn't parse as PEM,
	// the connector logs a warning but still returns Status=completed (per the
	// existing code: parseCertDates failure is non-fatal).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"issued","certificate":"not-a-pem-block","serial_number":"sn1"}`))
	}))
	defer srv.Close()
	c := buildGlobalsignConnector(t, srv.URL)
	st, err := c.GetOrderStatus(context.Background(), "serial-123")
	if err != nil {
		t.Fatalf("GetOrderStatus: %v", err)
	}
	if st.Status != "completed" {
		t.Errorf("expected completed (parseCertDates failure is non-fatal), got %q", st.Status)
	}
}

func TestGlobalsign_GetHTTPClient_NoMTLSCertPaths_ReturnsClientAsIs(t *testing.T) {
	// When ClientCertPath and ClientKeyPath are both empty, getHTTPClient
	// returns httpClient as-is — exercises that branch.
	cfg := &globalsign.Config{
		APIUrl:    "http://example.invalid",
		APIKey:    "k",
		APISecret: "s",
		// no cert paths
	}
	c := globalsign.NewWithHTTPClient(cfg, slog.Default(), &http.Client{})
	// GetOrderStatus will fail at HTTP do (invalid host), but getHTTPClient
	// will have been exercised through the no-mTLS branch.
	_, err := c.GetOrderStatus(context.Background(), "x")
	if err == nil {
		t.Errorf("expected error from invalid host")
	}
}

func TestGlobalsign_GetHTTPClient_MTLSPathConfigured_LoadsKeyPair(t *testing.T) {
	// Configure cert paths to a non-existent file — exercises the
	// LoadX509KeyPair error branch in getHTTPClient.
	cfg := &globalsign.Config{
		APIUrl:         "http://example.invalid",
		APIKey:         "k",
		APISecret:      "s",
		ClientCertPath: "/nonexistent/cert.pem",
		ClientKeyPath:  "/nonexistent/key.pem",
	}
	c := globalsign.New(cfg, slog.Default())
	_, err := c.GetOrderStatus(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Errorf("expected 'client certificate' load error, got %v", err)
	}
}
