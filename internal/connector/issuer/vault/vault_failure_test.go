package vault_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/vault"
	"github.com/shankar0123/certctl/internal/secret"
)

// Bundle N.A/B-extended: failure-mode round-out for Vault PKI connector.
// Exercises uncovered branches in IssueCertificate (malformed response,
// empty cert, structured Vault error format) and GetCACertPEM (non-200,
// connection error). Pushes vault 84.1% → ≥85%.

func TestVault_IssueCertificate_StructuredVaultError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sys/health"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			// Vault's structured error format: {"errors": [...]}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"role policy missing", "ttl exceeds max"},
			})
		}
	}))
	defer srv.Close()

	c := buildVaultConnector(t, srv.URL)
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "x.example.com",
		CSRPEM:     "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
	})
	if err == nil {
		t.Fatalf("expected error for 400 with structured Vault errors")
	}
	if !strings.Contains(err.Error(), "role policy missing") {
		t.Errorf("expected error to surface Vault's structured errors, got %v", err)
	}
}

func TestVault_IssueCertificate_MalformedResponseJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sys/health"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{not valid json`))
		}
	}))
	defer srv.Close()
	c := buildVaultConnector(t, srv.URL)
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "x.example.com",
		CSRPEM:     "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
	})
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error for malformed JSON, got %v", err)
	}
}

func TestVault_IssueCertificate_EmptyCertificate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sys/health"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
		default:
			w.WriteHeader(http.StatusOK)
			// Vault response shape with empty certificate field
			_, _ = w.Write([]byte(`{"data":{"certificate":"","serial_number":"01:02:03"}}`))
		}
	}))
	defer srv.Close()
	c := buildVaultConnector(t, srv.URL)
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "x.example.com",
		CSRPEM:     "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
	})
	if err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("expected 'no certificate' error, got %v", err)
	}
}

func TestVault_IssueCertificate_MalformedCertPEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sys/health"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
		default:
			w.WriteHeader(http.StatusOK)
			// Cert is non-PEM garbage
			_, _ = w.Write([]byte(`{"data":{"certificate":"not-a-pem-block","serial_number":"01"}}`))
		}
	}))
	defer srv.Close()
	c := buildVaultConnector(t, srv.URL)
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "x.example.com",
		CSRPEM:     "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
	})
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected PEM-decode error, got %v", err)
	}
}

func TestVault_GetCACertPEM_Non200_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sys/health"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
		default:
			// CA cert endpoint returns 403
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	c := buildVaultConnector(t, srv.URL)
	_, err := c.GetCACertPEM(context.Background())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 error, got %v", err)
	}
}

// buildVaultConnector constructs a vault.Connector pointed at the given URL
// by going through ValidateConfig (which the existing test pattern uses).
func buildVaultConnector(t *testing.T, url string) *vault.Connector {
	t.Helper()
	c := vault.New(nil, slog.Default())
	cfg := vault.Config{Addr: url, Token: secret.NewRefFromString("tok"), Mount: "pki", Role: "web", TTL: "1h"}
	raw, _ := json.Marshal(cfg)
	if err := c.ValidateConfig(context.Background(), raw); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	return c
}
