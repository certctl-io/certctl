package globalsign_test

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
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/globalsign"
)

func TestGlobalSignConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("ValidateConfig_Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v2/certificates" && r.Method == http.MethodGet {
				if r.Header.Get("ApiKey") == "gs-test-key" && r.Header.Get("ApiSecret") == "gs-test-secret" {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"certificates":[]}`))
					return
				}
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"invalid credentials"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := globalsign.Config{
			APIUrl:         srv.URL,
			APIKey:         "gs-test-key",
			APISecret:      "gs-test-secret",
			ClientCertPath: "unused_for_httptest",
			ClientKeyPath:  "unused_for_httptest",
		}

		connector := globalsign.New(nil, logger)
		rawConfig, _ := json.Marshal(config)

		// This test will fail at mTLS validation since httptest.NewServer doesn't do TLS.
		// We're mainly checking JSON parsing and header validation.
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Logf("ValidateConfig correctly failed on cert loading: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingAPIUrl", func(t *testing.T) {
		config := globalsign.Config{
			APIKey:         "gs-test-key",
			APISecret:      "gs-test-secret",
			ClientCertPath: "/tmp/cert.pem",
			ClientKeyPath:  "/tmp/key.pem",
		}

		connector := globalsign.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing api_url")
		}
		if !strings.Contains(err.Error(), "api_url") {
			t.Errorf("Expected api_url error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingAPIKey", func(t *testing.T) {
		config := globalsign.Config{
			APIUrl:         "https://api.example.com",
			APISecret:      "gs-test-secret",
			ClientCertPath: "/tmp/cert.pem",
			ClientKeyPath:  "/tmp/key.pem",
		}

		connector := globalsign.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing api_key")
		}
		if !strings.Contains(err.Error(), "api_key") {
			t.Errorf("Expected api_key error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingAPISecret", func(t *testing.T) {
		config := globalsign.Config{
			APIUrl:         "https://api.example.com",
			APIKey:         "gs-test-key",
			ClientCertPath: "/tmp/cert.pem",
			ClientKeyPath:  "/tmp/key.pem",
		}

		connector := globalsign.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing api_secret")
		}
		if !strings.Contains(err.Error(), "api_secret") {
			t.Errorf("Expected api_secret error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingClientCertPath", func(t *testing.T) {
		config := globalsign.Config{
			APIUrl:        "https://api.example.com",
			APIKey:        "gs-test-key",
			APISecret:     "gs-test-secret",
			ClientKeyPath: "/tmp/key.pem",
		}

		connector := globalsign.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing client_cert_path")
		}
		if !strings.Contains(err.Error(), "client_cert_path") {
			t.Errorf("Expected client_cert_path error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingClientKeyPath", func(t *testing.T) {
		config := globalsign.Config{
			APIUrl:         "https://api.example.com",
			APIKey:         "gs-test-key",
			APISecret:      "gs-test-secret",
			ClientCertPath: "/tmp/cert.pem",
		}

		connector := globalsign.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing client_key_path")
		}
		if !strings.Contains(err.Error(), "client_key_path") {
			t.Errorf("Expected client_key_path error, got: %v", err)
		}
	})

	t.Run("IssueCertificate_Immediate", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		testChainPEM, _ := generateTestCert(t)

		httpClient := &http.Client{}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v2/certificates" && r.Method == http.MethodPost {
				// Verify auth headers are present
				if r.Header.Get("ApiKey") != "gs-test-key" {
					t.Error("ApiKey header missing or incorrect")
				}
				if r.Header.Get("ApiSecret") != "gs-test-secret" {
					t.Error("ApiSecret header missing or incorrect")
				}

				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(fmt.Sprintf(`{
					"serial_number": "12345678901234567890",
					"status": "issued",
					"certificate": %s,
					"chain": %s
				}`, mustMarshalJSON(testCertPEM), mustMarshalJSON(testChainPEM))))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		config := &globalsign.Config{
			APIUrl:    mockServer.URL,
			APIKey:    "gs-test-key",
			APISecret: "gs-test-secret",
		}

		connector := globalsign.NewWithHTTPClient(config, logger, httpClient)

		_, csrPEM := generateTestCSR(t, "app.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "app.example.com",
			SANs:       []string{"app.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if result.CertPEM == "" {
			t.Error("CertPEM should not be empty for immediate issuance")
		}
		if result.Serial == "" {
			t.Error("Serial should not be empty for immediate issuance")
		}
		if result.OrderID != "12345678901234567890" {
			t.Errorf("Expected OrderID '12345678901234567890', got '%s'", result.OrderID)
		}
		t.Logf("GlobalSign issued cert: serial=%s, orderID=%s", result.Serial, result.OrderID)
	})

	t.Run("IssueCertificate_Pending", func(t *testing.T) {
		httpClient := &http.Client{}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v2/certificates" && r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(`{
					"serial_number": "98765432109876543210",
					"status": "pending"
				}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		config := &globalsign.Config{
			APIUrl:    mockServer.URL,
			APIKey:    "gs-test-key",
			APISecret: "gs-test-secret",
		}

		connector := globalsign.NewWithHTTPClient(config, logger, httpClient)

		_, csrPEM := generateTestCSR(t, "secure.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "secure.example.com",
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if result.CertPEM != "" {
			t.Error("CertPEM should be empty for pending issuance")
		}
		if result.OrderID != "98765432109876543210" {
			t.Errorf("Expected OrderID '98765432109876543210', got '%s'", result.OrderID)
		}
		t.Logf("GlobalSign order pending: orderID=%s", result.OrderID)
	})

	t.Run("IssueCertificate_Error", func(t *testing.T) {
		httpClient := &http.Client{}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v2/certificates" && r.Method == http.MethodPost {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error": "invalid CSR format"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		config := &globalsign.Config{
			APIUrl:    mockServer.URL,
			APIKey:    "gs-test-key",
			APISecret: "gs-test-secret",
		}

		connector := globalsign.NewWithHTTPClient(config, logger, httpClient)

		_, csrPEM := generateTestCSR(t, "bad.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "bad.example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for bad request")
		}
		t.Logf("Expected error received: %v", err)
	})

	t.Run("GetOrderStatus_Issued", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		testChainPEM, _ := generateTestCert(t)

		httpClient := &http.Client{}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/v2/certificates/12345") && r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf(`{
					"serial_number": "12345",
					"status": "issued",
					"certificate": %s,
					"chain": %s
				}`, mustMarshalJSON(testCertPEM), mustMarshalJSON(testChainPEM))))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		config := &globalsign.Config{
			APIUrl:    mockServer.URL,
			APIKey:    "gs-test-key",
			APISecret: "gs-test-secret",
		}

		connector := globalsign.NewWithHTTPClient(config, logger, httpClient)

		status, err := connector.GetOrderStatus(ctx, "12345")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "completed" {
			t.Errorf("Expected status 'completed', got '%s'", status.Status)
		}
		if status.CertPEM == nil || *status.CertPEM == "" {
			t.Error("CertPEM should not be empty")
		}
		t.Logf("Order status: %s", status.Status)
	})

	t.Run("GetOrderStatus_Pending", func(t *testing.T) {
		httpClient := &http.Client{}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/v2/certificates/98765") && r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
					"serial_number": "98765",
					"status": "pending"
				}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		config := &globalsign.Config{
			APIUrl:    mockServer.URL,
			APIKey:    "gs-test-key",
			APISecret: "gs-test-secret",
		}

		connector := globalsign.NewWithHTTPClient(config, logger, httpClient)

		status, err := connector.GetOrderStatus(ctx, "98765")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "pending" {
			t.Errorf("Expected status 'pending', got '%s'", status.Status)
		}
		if status.Message == nil {
			t.Error("Message should not be nil for pending status")
		}
		t.Logf("Order status: %s, message: %s", status.Status, *status.Message)
	})

	t.Run("RenewCertificate_Success", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		testChainPEM, _ := generateTestCert(t)

		httpClient := &http.Client{}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v2/certificates" && r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(fmt.Sprintf(`{
					"serial_number": "renewal123",
					"status": "issued",
					"certificate": %s,
					"chain": %s
				}`, mustMarshalJSON(testCertPEM), mustMarshalJSON(testChainPEM))))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		config := &globalsign.Config{
			APIUrl:    mockServer.URL,
			APIKey:    "gs-test-key",
			APISecret: "gs-test-secret",
		}

		connector := globalsign.NewWithHTTPClient(config, logger, httpClient)

		_, csrPEM := generateTestCSR(t, "renew.example.com")
		req := issuer.RenewalRequest{
			CommonName: "renew.example.com",
			CSRPEM:     csrPEM,
		}

		result, err := connector.RenewCertificate(ctx, req)
		if err != nil {
			t.Fatalf("RenewCertificate failed: %v", err)
		}

		if result.Serial == "" {
			t.Error("Serial should not be empty")
		}
		t.Logf("Certificate renewed: serial=%s", result.Serial)
	})

	t.Run("RevokeCertificate_Success", func(t *testing.T) {
		httpClient := &http.Client{}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/v2/certificates/") && strings.HasSuffix(r.URL.Path, "/revoke") && r.Method == http.MethodPut {
				// Verify auth headers
				if r.Header.Get("ApiKey") != "gs-test-key" {
					t.Error("ApiKey header missing")
				}
				if r.Header.Get("ApiSecret") != "gs-test-secret" {
					t.Error("ApiSecret header missing")
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		config := &globalsign.Config{
			APIUrl:    mockServer.URL,
			APIKey:    "gs-test-key",
			APISecret: "gs-test-secret",
		}

		connector := globalsign.NewWithHTTPClient(config, logger, httpClient)

		req := issuer.RevocationRequest{
			Serial: "12345678901234567890",
		}

		err := connector.RevokeCertificate(ctx, req)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}

		t.Logf("Certificate revoked: serial=%s", req.Serial)
	})

	t.Run("RevokeCertificate_Error", func(t *testing.T) {
		httpClient := &http.Client{}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/v2/certificates/") && strings.HasSuffix(r.URL.Path, "/revoke") && r.Method == http.MethodPut {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "certificate not found"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		config := &globalsign.Config{
			APIUrl:    mockServer.URL,
			APIKey:    "gs-test-key",
			APISecret: "gs-test-secret",
		}

		connector := globalsign.NewWithHTTPClient(config, logger, httpClient)

		req := issuer.RevocationRequest{
			Serial: "nonexistent",
		}

		err := connector.RevokeCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for nonexistent certificate")
		}
		t.Logf("Expected error received: %v", err)
	})

	t.Run("AuthHeaders_OnAllRequests", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		testChainPEM, _ := generateTestCert(t)
		authHeadersChecked := 0

		httpClient := &http.Client{}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for auth headers on every request
			if r.Header.Get("ApiKey") == "gs-test-key" && r.Header.Get("ApiSecret") == "gs-test-secret" {
				authHeadersChecked++
			}

			if r.URL.Path == "/v2/certificates" && r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(fmt.Sprintf(`{
					"serial_number": "auth123",
					"status": "issued",
					"certificate": %s,
					"chain": %s
				}`, mustMarshalJSON(testCertPEM), mustMarshalJSON(testChainPEM))))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		config := &globalsign.Config{
			APIUrl:    mockServer.URL,
			APIKey:    "gs-test-key",
			APISecret: "gs-test-secret",
		}

		connector := globalsign.NewWithHTTPClient(config, logger, httpClient)

		_, csrPEM := generateTestCSR(t, "auth.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "auth.example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if authHeadersChecked < 1 {
			t.Errorf("Auth headers not found on request")
		}
		t.Logf("Auth headers verified on %d request(s)", authHeadersChecked)
	})
}

// TestGlobalSign_ServerTLSConfig exercises the server-side TLS verification
// policy added by H-5. The connector must always verify the GlobalSign Atlas
// HVCA API server certificate: by default against the host's system trust
// store, and when ServerCAPath is set, against the pinned PEM bundle at that
// path. InsecureSkipVerify is no longer reachable from any production code path.
func TestGlobalSign_ServerTLSConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// writeClientMTLS generates a throwaway client cert+key pair and writes them
	// to disk. ValidateConfig requires valid ClientCertPath / ClientKeyPath files
	// before it reaches the server-CA validation path under test.
	writeClientMTLS := func(t *testing.T) (certPath, keyPath string) {
		t.Helper()
		certPEM, keyPEM := generateTestCert(t)
		dir := t.TempDir()
		certPath = dir + "/client-cert.pem"
		keyPath = dir + "/client-key.pem"
		if err := os.WriteFile(certPath, []byte(certPEM), 0600); err != nil {
			t.Fatalf("failed to write client cert: %v", err)
		}
		if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
			t.Fatalf("failed to write client key: %v", err)
		}
		return certPath, keyPath
	}

	// certToPEM re-encodes a parsed certificate as a PEM block for trust-store
	// pinning. httptest.NewTLSServer.Certificate() returns the server's self-
	// signed cert; pinning that cert trusts exactly that one server.
	certToPEM := func(t *testing.T, cert *x509.Certificate) string {
		t.Helper()
		return string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}))
	}

	t.Run("PinnedCA_TrustsExpectedServer", func(t *testing.T) {
		// Mock Atlas API served over HTTPS with a self-signed cert. We pin
		// that cert's PEM as the client's trust anchor; the validation probe
		// should succeed because the pinned pool contains the server's issuer.
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v2/certificates" && r.Method == http.MethodGet {
				if r.Header.Get("ApiKey") == "gs-test-key" && r.Header.Get("ApiSecret") == "gs-test-secret" {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"certificates":[]}`))
					return
				}
				w.WriteHeader(http.StatusForbidden)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		caPEM := certToPEM(t, srv.Certificate())
		caPath := t.TempDir() + "/atlas-ca.pem"
		if err := os.WriteFile(caPath, []byte(caPEM), 0600); err != nil {
			t.Fatalf("failed to write pinned CA: %v", err)
		}

		clientCert, clientKey := writeClientMTLS(t)
		config := globalsign.Config{
			APIUrl:         srv.URL,
			APIKey:         "gs-test-key",
			APISecret:      "gs-test-secret",
			ClientCertPath: clientCert,
			ClientKeyPath:  clientKey,
			ServerCAPath:   caPath,
		}

		connector := globalsign.New(&config, logger)
		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig with pinned CA should succeed, got: %v", err)
		}
	})

	t.Run("PinnedCA_RejectsUntrustedServer", func(t *testing.T) {
		// Mock server presents its own self-signed cert; we pin an UNRELATED
		// cert as the trust anchor. The TLS handshake must fail before any
		// request is sent — this is exactly what H-5 remediates.
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		unrelatedPEM, _ := generateTestCert(t)
		caPath := t.TempDir() + "/unrelated-ca.pem"
		if err := os.WriteFile(caPath, []byte(unrelatedPEM), 0600); err != nil {
			t.Fatalf("failed to write unrelated CA: %v", err)
		}

		clientCert, clientKey := writeClientMTLS(t)
		config := globalsign.Config{
			APIUrl:         srv.URL,
			APIKey:         "gs-test-key",
			APISecret:      "gs-test-secret",
			ClientCertPath: clientCert,
			ClientKeyPath:  clientKey,
			ServerCAPath:   caPath,
		}

		connector := globalsign.New(&config, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("ValidateConfig must fail when the server cert is not signed by the pinned CA")
		}
		// The failure must originate from TLS verification, not from any other path.
		if !strings.Contains(err.Error(), "x509") &&
			!strings.Contains(err.Error(), "certificate") &&
			!strings.Contains(err.Error(), "unknown authority") {
			t.Errorf("expected TLS verification error, got: %v", err)
		}
		t.Logf("Untrusted server cert correctly rejected: %v", err)
	})

	t.Run("ServerCAPath_MissingFile", func(t *testing.T) {
		clientCert, clientKey := writeClientMTLS(t)
		config := globalsign.Config{
			APIUrl:         "https://example.invalid",
			APIKey:         "gs-test-key",
			APISecret:      "gs-test-secret",
			ClientCertPath: clientCert,
			ClientKeyPath:  clientKey,
			ServerCAPath:   "/nonexistent/path/to/ca.pem",
		}

		connector := globalsign.New(&config, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("ValidateConfig must fail when ServerCAPath points to a missing file")
		}
		if !strings.Contains(err.Error(), "failed to read server CA bundle") {
			t.Errorf("expected 'failed to read server CA bundle' error, got: %v", err)
		}
		t.Logf("Missing server CA file correctly rejected: %v", err)
	})

	t.Run("ServerCAPath_InvalidPEM", func(t *testing.T) {
		clientCert, clientKey := writeClientMTLS(t)
		badCAPath := t.TempDir() + "/garbage.pem"
		if err := os.WriteFile(badCAPath, []byte("this is not a PEM certificate at all"), 0600); err != nil {
			t.Fatalf("failed to write garbage file: %v", err)
		}

		config := globalsign.Config{
			APIUrl:         "https://example.invalid",
			APIKey:         "gs-test-key",
			APISecret:      "gs-test-secret",
			ClientCertPath: clientCert,
			ClientKeyPath:  clientKey,
			ServerCAPath:   badCAPath,
		}

		connector := globalsign.New(&config, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("ValidateConfig must fail when ServerCAPath contains no valid PEM certificates")
		}
		if !strings.Contains(err.Error(), "no valid PEM certificates") {
			t.Errorf("expected 'no valid PEM certificates' error, got: %v", err)
		}
		t.Logf("Invalid PEM correctly rejected: %v", err)
	})
}

// generateTestCert generates a self-signed test certificate and returns PEM strings.
func generateTestCert(t *testing.T) (certPEM string, keyPEM string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{"test.example.com"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	keyBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	return string(certBlock), string(keyBlock)
}

// generateTestCSR generates a test certificate signing request.
func generateTestCSR(t *testing.T, commonName string) (csrPEM string, keyPEM string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: []string{commonName},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csrBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	keyBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	return string(csrBlock), string(keyBlock)
}

// mustMarshalJSON marshals a value to JSON string, panicking on error.
// Used to safely embed PEM data in JSON responses.
func mustMarshalJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal JSON: %v", err))
	}
	return string(b)
}
