package vault_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/connector/issuer"
	"github.com/certctl-io/certctl/internal/connector/issuer/vault"
	"github.com/certctl-io/certctl/internal/secret"
)

func TestVaultConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("ValidateConfig_Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/sys/health" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := vault.Config{
			Addr:  srv.URL,
			Token: secret.NewRefFromString("s.test-token-12345"),
			Mount: "pki",
			Role:  "web-certs",
			TTL:   "8760h",
		}

		connector := vault.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingAddr", func(t *testing.T) {
		config := vault.Config{
			Token: secret.NewRefFromString("s.test-token"),
			Role:  "web-certs",
		}

		connector := vault.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing addr")
		}
		if !strings.Contains(err.Error(), "addr is required") {
			t.Errorf("Expected addr required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingToken", func(t *testing.T) {
		config := vault.Config{
			Addr: "https://vault.example.com:8200",
			Role: "web-certs",
		}

		connector := vault.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing token")
		}
		if !strings.Contains(err.Error(), "token is required") {
			t.Errorf("Expected token required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingRole", func(t *testing.T) {
		config := vault.Config{
			Addr:  "https://vault.example.com:8200",
			Token: secret.NewRefFromString("s.test-token"),
		}

		connector := vault.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing role")
		}
		if !strings.Contains(err.Error(), "role is required") {
			t.Errorf("Expected role required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_UnreachableVault", func(t *testing.T) {
		config := vault.Config{
			Addr:  "http://localhost:19999",
			Token: secret.NewRefFromString("s.test-token"),
			Role:  "web-certs",
		}

		connector := vault.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for unreachable Vault")
		}
	})

	t.Run("IssueCertificate_Success", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/v1/sys/health":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"initialized":true,"sealed":false}`))
			case strings.HasPrefix(r.URL.Path, "/v1/pki/sign/"):
				// Verify auth header
				if r.Header.Get("X-Vault-Token") != "s.test-token" {
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(`{"errors":["permission denied"]}`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				resp := fmt.Sprintf(`{
					"data": {
						"certificate": %q,
						"issuing_ca": %q,
						"ca_chain": [%q],
						"serial_number": "aa:bb:cc:dd:ee:ff",
						"expiration": 1893456000
					}
				}`, testCertPEM, testCertPEM, testCertPEM)
				w.Write([]byte(resp))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &vault.Config{
			Addr:  srv.URL,
			Token: secret.NewRefFromString("s.test-token"),
			Mount: "pki",
			Role:  "web-certs",
			TTL:   "8760h",
		}
		connector := vault.New(config, logger)

		_, csrPEM := generateTestCSR(t, "app.example.com")

		req := issuer.IssuanceRequest{
			CommonName: "app.example.com",
			SANs:       []string{"app.example.com", "www.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if result.CertPEM == "" {
			t.Error("CertPEM is empty")
		}
		if result.Serial == "" {
			t.Error("Serial is empty")
		}
		if result.OrderID == "" {
			t.Error("OrderID is empty")
		}
		if !strings.HasPrefix(result.OrderID, "vault-") {
			t.Errorf("Expected OrderID to start with 'vault-', got '%s'", result.OrderID)
		}
		// Verify serial normalization (colons replaced with dashes)
		if strings.Contains(result.Serial, ":") {
			t.Errorf("Serial should not contain colons, got '%s'", result.Serial)
		}
		t.Logf("Vault issued cert: serial=%s, orderID=%s", result.Serial, result.OrderID)
	})

	t.Run("IssueCertificate_ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/v1/sys/health":
				w.WriteHeader(http.StatusOK)
			case strings.HasPrefix(r.URL.Path, "/v1/pki/sign/"):
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"errors":["invalid CSR"]}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &vault.Config{
			Addr:  srv.URL,
			Token: secret.NewRefFromString("s.test-token"),
			Mount: "pki",
			Role:  "web-certs",
		}
		connector := vault.New(config, logger)

		_, csrPEM := generateTestCSR(t, "test.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for server error response")
		}
		if !strings.Contains(err.Error(), "invalid CSR") {
			t.Logf("Got error: %v", err)
		}
	})

	t.Run("IssueCertificate_Forbidden", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/v1/sys/health":
				w.WriteHeader(http.StatusOK)
			case strings.HasPrefix(r.URL.Path, "/v1/pki/sign/"):
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"errors":["permission denied"]}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &vault.Config{
			Addr:  srv.URL,
			Token: secret.NewRefFromString("s.bad-token"),
			Mount: "pki",
			Role:  "web-certs",
		}
		connector := vault.New(config, logger)

		_, csrPEM := generateTestCSR(t, "test.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for forbidden response")
		}
		if !strings.Contains(err.Error(), "permission denied") {
			t.Logf("Got error: %v", err)
		}
	})

	t.Run("RenewCertificate_Success", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/v1/sys/health":
				w.WriteHeader(http.StatusOK)
			case strings.HasPrefix(r.URL.Path, "/v1/pki/sign/"):
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				resp := fmt.Sprintf(`{
					"data": {
						"certificate": %q,
						"issuing_ca": %q,
						"serial_number": "11:22:33:44:55:66",
						"expiration": 1893456000
					}
				}`, testCertPEM, testCertPEM)
				w.Write([]byte(resp))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &vault.Config{
			Addr:  srv.URL,
			Token: secret.NewRefFromString("s.test-token"),
			Mount: "pki",
			Role:  "web-certs",
		}
		connector := vault.New(config, logger)

		_, csrPEM := generateTestCSR(t, "renew.example.com")
		renewReq := issuer.RenewalRequest{
			CommonName: "renew.example.com",
			CSRPEM:     csrPEM,
		}

		result, err := connector.RenewCertificate(ctx, renewReq)
		if err != nil {
			t.Fatalf("RenewCertificate failed: %v", err)
		}

		if result.Serial == "" {
			t.Error("Serial is empty")
		}
	})

	t.Run("RevokeCertificate_Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/sys/health":
				w.WriteHeader(http.StatusOK)
			case "/v1/pki/revoke":
				// Verify token
				if r.Header.Get("X-Vault-Token") == "" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":{"revocation_time":1234567890}}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &vault.Config{
			Addr:  srv.URL,
			Token: secret.NewRefFromString("s.test-token"),
			Mount: "pki",
			Role:  "web-certs",
		}
		connector := vault.New(config, logger)

		reason := "keyCompromise"
		revokeReq := issuer.RevocationRequest{
			Serial: "aa-bb-cc-dd-ee-ff",
			Reason: &reason,
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}
	})

	t.Run("RevokeCertificate_ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/sys/health":
				w.WriteHeader(http.StatusOK)
			case "/v1/pki/revoke":
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"errors":["serial not found"]}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &vault.Config{
			Addr:  srv.URL,
			Token: secret.NewRefFromString("s.test-token"),
			Mount: "pki",
			Role:  "web-certs",
		}
		connector := vault.New(config, logger)

		revokeReq := issuer.RevocationRequest{
			Serial: "00-00-00-00",
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err == nil {
			t.Fatal("Expected error for server error response")
		}
	})

	t.Run("GetCACertPEM_Success", func(t *testing.T) {
		expectedPEM := "-----BEGIN CERTIFICATE-----\nTESTCA\n-----END CERTIFICATE-----\n"

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/pki/ca/pem":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(expectedPEM))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &vault.Config{
			Addr:  srv.URL,
			Token: secret.NewRefFromString("s.test-token"),
			Mount: "pki",
			Role:  "web-certs",
		}
		connector := vault.New(config, logger)

		caPEM, err := connector.GetCACertPEM(ctx)
		if err != nil {
			t.Fatalf("GetCACertPEM failed: %v", err)
		}

		if caPEM != expectedPEM {
			t.Errorf("Expected CA PEM %q, got %q", expectedPEM, caPEM)
		}
	})

	t.Run("GetOrderStatus_Synchronous", func(t *testing.T) {
		config := &vault.Config{
			Addr:  "https://vault.example.com:8200",
			Token: secret.NewRefFromString("s.test-token"),
			Mount: "pki",
			Role:  "web-certs",
		}
		connector := vault.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "vault-aa-bb-cc")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "completed" {
			t.Errorf("Expected status 'completed', got '%s'", status.Status)
		}
		if status.OrderID != "vault-aa-bb-cc" {
			t.Errorf("Expected OrderID 'vault-aa-bb-cc', got '%s'", status.OrderID)
		}
	})

	t.Run("GetRenewalInfo_ReturnsNil", func(t *testing.T) {
		config := &vault.Config{
			Addr:  "https://vault.example.com:8200",
			Token: secret.NewRefFromString("s.test-token"),
			Mount: "pki",
			Role:  "web-certs",
		}
		connector := vault.New(config, logger)

		result, err := connector.GetRenewalInfo(ctx, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
		if err != nil {
			t.Fatalf("GetRenewalInfo should not return error, got: %v", err)
		}
		if result != nil {
			t.Fatal("GetRenewalInfo should return nil for Vault")
		}
	})
}

// generateTestCert creates a self-signed test certificate and returns the PEM strings.
func generateTestCert(t *testing.T) (certPEM string, keyPEM string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		DNSNames:              []string{"test.example.com"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	return certPEM, keyPEM
}

// generateTestCSR creates a test CSR for the given common name.
func generateTestCSR(t *testing.T, commonName string) (*x509.CertificateRequest, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:           []string{commonName},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}))

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	return csr, csrPEM
}
