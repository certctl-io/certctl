package googlecas_test

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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/connector/issuer"
	"github.com/certctl-io/certctl/internal/connector/issuer/googlecas"
)

func TestGoogleCASConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("ValidateConfig_Success", func(t *testing.T) {
		credPath := createTestCredentialsFile(t)

		config := googlecas.Config{
			Project:     "my-project",
			Location:    "us-central1",
			CAPool:      "my-pool",
			Credentials: credPath,
			TTL:         "8760h",
		}

		connector := googlecas.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingProject", func(t *testing.T) {
		config := googlecas.Config{
			Location:    "us-central1",
			CAPool:      "my-pool",
			Credentials: "/tmp/creds.json",
		}

		connector := googlecas.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing project")
		}
		if !strings.Contains(err.Error(), "project is required") {
			t.Errorf("Expected project required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingLocation", func(t *testing.T) {
		config := googlecas.Config{
			Project:     "my-project",
			CAPool:      "my-pool",
			Credentials: "/tmp/creds.json",
		}

		connector := googlecas.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing location")
		}
		if !strings.Contains(err.Error(), "location is required") {
			t.Errorf("Expected location required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingCAPool", func(t *testing.T) {
		config := googlecas.Config{
			Project:     "my-project",
			Location:    "us-central1",
			Credentials: "/tmp/creds.json",
		}

		connector := googlecas.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing CA pool")
		}
		if !strings.Contains(err.Error(), "CA pool is required") {
			t.Errorf("Expected CA pool required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingCredentials", func(t *testing.T) {
		config := googlecas.Config{
			Project:  "my-project",
			Location: "us-central1",
			CAPool:   "my-pool",
		}

		connector := googlecas.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing credentials")
		}
		if !strings.Contains(err.Error(), "credentials path is required") {
			t.Errorf("Expected credentials required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_InvalidCredentialsFile", func(t *testing.T) {
		config := googlecas.Config{
			Project:     "my-project",
			Location:    "us-central1",
			CAPool:      "my-pool",
			Credentials: "/nonexistent/path/credentials.json",
		}

		connector := googlecas.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for invalid credentials file")
		}
		if !strings.Contains(err.Error(), "credentials invalid") {
			t.Errorf("Expected credentials invalid error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MalformedCredentialsJSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		badFile := filepath.Join(tmpDir, "bad-creds.json")
		if err := os.WriteFile(badFile, []byte("not json"), 0600); err != nil {
			t.Fatal(err)
		}

		config := googlecas.Config{
			Project:     "my-project",
			Location:    "us-central1",
			CAPool:      "my-pool",
			Credentials: badFile,
		}

		connector := googlecas.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for malformed credentials JSON")
		}
		if !strings.Contains(err.Error(), "credentials invalid") {
			t.Errorf("Expected credentials invalid error, got: %v", err)
		}
	})

	t.Run("IssueCertificate_Success", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		credPath := createTestCredentialsFile(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/token":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"test-token-12345","expires_in":3600,"token_type":"Bearer"}`))

			case strings.Contains(r.URL.Path, "/certificates") && r.Method == http.MethodPost &&
				!strings.Contains(r.URL.Path, ":revoke") && !strings.Contains(r.URL.Path, ":fetchCaCerts"):
				// Verify auth header
				auth := r.Header.Get("Authorization")
				if auth != "Bearer test-token-12345" {
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(`{"error":{"code":403,"message":"Permission denied","status":"PERMISSION_DENIED"}}`))
					return
				}
				// Verify certificateId query param
				certID := r.URL.Query().Get("certificateId")
				if certID == "" {
					t.Error("Missing certificateId query parameter")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				chainCert, _ := generateTestCert(t)
				resp := fmt.Sprintf(`{
					"name": "projects/test-project/locations/us-central1/caPools/test-pool/certificates/%s",
					"pemCertificate": %q,
					"pemCertificateChain": [%q]
				}`, certID, testCertPEM, chainCert)
				w.Write([]byte(resp))

			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &googlecas.Config{
			Project:     "test-project",
			Location:    "us-central1",
			CAPool:      "test-pool",
			Credentials: credPath,
			TTL:         "8760h",
			BaseURL:     srv.URL,
			TokenURL:    srv.URL + "/token",
		}
		connector := googlecas.New(config, logger)

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
		if !strings.HasPrefix(result.OrderID, "projects/") {
			t.Errorf("Expected OrderID to be full resource name, got '%s'", result.OrderID)
		}
		if result.ChainPEM == "" {
			t.Error("ChainPEM is empty")
		}
		if result.NotBefore.IsZero() {
			t.Error("NotBefore is zero")
		}
		if result.NotAfter.IsZero() {
			t.Error("NotAfter is zero")
		}
		t.Logf("Google CAS issued cert: serial=%s, orderID=%s", result.Serial, result.OrderID)
	})

	t.Run("IssueCertificate_ServerError", func(t *testing.T) {
		credPath := createTestCredentialsFile(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/token":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
			case strings.Contains(r.URL.Path, "/certificates"):
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":{"code":400,"message":"Invalid CSR","status":"INVALID_ARGUMENT"}}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &googlecas.Config{
			Project:     "test-project",
			Location:    "us-central1",
			CAPool:      "test-pool",
			Credentials: credPath,
			TTL:         "8760h",
			BaseURL:     srv.URL,
			TokenURL:    srv.URL + "/token",
		}
		connector := googlecas.New(config, logger)

		_, csrPEM := generateTestCSR(t, "test.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for server error response")
		}
		if !strings.Contains(err.Error(), "Invalid CSR") {
			t.Logf("Got error: %v", err)
		}
	})

	t.Run("IssueCertificate_InvalidResponse", func(t *testing.T) {
		credPath := createTestCredentialsFile(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/token":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
			case strings.Contains(r.URL.Path, "/certificates"):
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`not-json`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &googlecas.Config{
			Project:     "test-project",
			Location:    "us-central1",
			CAPool:      "test-pool",
			Credentials: credPath,
			TTL:         "8760h",
			BaseURL:     srv.URL,
			TokenURL:    srv.URL + "/token",
		}
		connector := googlecas.New(config, logger)

		_, csrPEM := generateTestCSR(t, "test.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for invalid response")
		}
		if !strings.Contains(err.Error(), "parse") {
			t.Logf("Got error: %v", err)
		}
	})

	t.Run("GetOrderStatus_AlwaysCompleted", func(t *testing.T) {
		config := &googlecas.Config{
			Project:  "test-project",
			Location: "us-central1",
			CAPool:   "test-pool",
			TTL:      "8760h",
		}
		connector := googlecas.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "projects/p/locations/l/caPools/cp/certificates/cert-123")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "completed" {
			t.Errorf("Expected status 'completed', got '%s'", status.Status)
		}
		if status.OrderID != "projects/p/locations/l/caPools/cp/certificates/cert-123" {
			t.Errorf("Expected OrderID preserved, got '%s'", status.OrderID)
		}
	})

	t.Run("RenewCertificate_NewCert", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		credPath := createTestCredentialsFile(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/token":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
			case strings.Contains(r.URL.Path, "/certificates") && r.Method == http.MethodPost &&
				!strings.Contains(r.URL.Path, ":revoke"):
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				resp := fmt.Sprintf(`{
					"name": "projects/test-project/locations/us-central1/caPools/test-pool/certificates/certctl-renew",
					"pemCertificate": %q,
					"pemCertificateChain": []
				}`, testCertPEM)
				w.Write([]byte(resp))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &googlecas.Config{
			Project:     "test-project",
			Location:    "us-central1",
			CAPool:      "test-pool",
			Credentials: credPath,
			TTL:         "8760h",
			BaseURL:     srv.URL,
			TokenURL:    srv.URL + "/token",
		}
		connector := googlecas.New(config, logger)

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
		credPath := createTestCredentialsFile(t)

		var receivedReason string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/token":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
			case strings.Contains(r.URL.Path, ":revoke"):
				var body map[string]interface{}
				json.NewDecoder(r.Body).Decode(&body)
				receivedReason = body["reason"].(string)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"name":"projects/p/locations/l/caPools/cp/certificates/cert-123"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &googlecas.Config{
			Project:     "test-project",
			Location:    "us-central1",
			CAPool:      "test-pool",
			Credentials: credPath,
			TTL:         "8760h",
			BaseURL:     srv.URL,
			TokenURL:    srv.URL + "/token",
		}
		connector := googlecas.New(config, logger)

		reason := "keyCompromise"
		revokeReq := issuer.RevocationRequest{
			Serial: "projects/test-project/locations/us-central1/caPools/test-pool/certificates/cert-123",
			Reason: &reason,
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}

		if receivedReason != "KEY_COMPROMISE" {
			t.Errorf("Expected reason 'KEY_COMPROMISE', got '%s'", receivedReason)
		}
	})

	t.Run("RevokeCertificate_Error", func(t *testing.T) {
		credPath := createTestCredentialsFile(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/token":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
			case strings.Contains(r.URL.Path, ":revoke"):
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error":{"code":404,"message":"Certificate not found","status":"NOT_FOUND"}}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &googlecas.Config{
			Project:     "test-project",
			Location:    "us-central1",
			CAPool:      "test-pool",
			Credentials: credPath,
			TTL:         "8760h",
			BaseURL:     srv.URL,
			TokenURL:    srv.URL + "/token",
		}
		connector := googlecas.New(config, logger)

		revokeReq := issuer.RevocationRequest{
			Serial: "projects/test-project/locations/us-central1/caPools/test-pool/certificates/nonexistent",
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err == nil {
			t.Fatal("Expected error for revoke of nonexistent certificate")
		}
		if !strings.Contains(err.Error(), "Certificate not found") {
			t.Logf("Got error: %v", err)
		}
	})

	t.Run("RevocationReasonMapping", func(t *testing.T) {
		credPath := createTestCredentialsFile(t)

		tests := []struct {
			name     string
			reason   string
			expected string
		}{
			{"keyCompromise", "keyCompromise", "KEY_COMPROMISE"},
			{"caCompromise", "caCompromise", "CERTIFICATE_AUTHORITY_COMPROMISE"},
			{"affiliationChanged", "affiliationChanged", "AFFILIATION_CHANGED"},
			{"superseded", "superseded", "SUPERSEDED"},
			{"cessationOfOperation", "cessationOfOperation", "CESSATION_OF_OPERATION"},
			{"certificateHold", "certificateHold", "CERTIFICATE_HOLD"},
			{"privilegeWithdrawn", "privilegeWithdrawn", "PRIVILEGE_WITHDRAWN"},
			{"unspecified", "unspecified", "REVOCATION_REASON_UNSPECIFIED"},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				var receivedReason string
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.URL.Path == "/token":
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
					case strings.Contains(r.URL.Path, ":revoke"):
						var body map[string]interface{}
						json.NewDecoder(r.Body).Decode(&body)
						receivedReason = body["reason"].(string)
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{}`))
					default:
						http.NotFound(w, r)
					}
				}))
				defer srv.Close()

				config := &googlecas.Config{
					Project:     "test-project",
					Location:    "us-central1",
					CAPool:      "test-pool",
					Credentials: credPath,
					TTL:         "8760h",
					BaseURL:     srv.URL,
					TokenURL:    srv.URL + "/token",
				}
				connector := googlecas.New(config, logger)

				reason := tc.reason
				err := connector.RevokeCertificate(ctx, issuer.RevocationRequest{
					Serial: "projects/p/locations/l/caPools/cp/certificates/cert-1",
					Reason: &reason,
				})
				if err != nil {
					t.Fatalf("RevokeCertificate failed: %v", err)
				}

				if receivedReason != tc.expected {
					t.Errorf("Expected reason '%s', got '%s'", tc.expected, receivedReason)
				}
			})
		}
	})

	t.Run("GetCACertPEM_Success", func(t *testing.T) {
		credPath := createTestCredentialsFile(t)
		caCertPEM, _ := generateTestCert(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/token":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
			case strings.Contains(r.URL.Path, ":fetchCaCerts"):
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				resp := fmt.Sprintf(`{"caCerts":[{"certificates":[%q]}]}`, caCertPEM)
				w.Write([]byte(resp))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &googlecas.Config{
			Project:     "test-project",
			Location:    "us-central1",
			CAPool:      "test-pool",
			Credentials: credPath,
			TTL:         "8760h",
			BaseURL:     srv.URL,
			TokenURL:    srv.URL + "/token",
		}
		connector := googlecas.New(config, logger)

		caPEM, err := connector.GetCACertPEM(ctx)
		if err != nil {
			t.Fatalf("GetCACertPEM failed: %v", err)
		}

		if !strings.Contains(caPEM, "BEGIN CERTIFICATE") {
			t.Errorf("Expected CA PEM to contain certificate, got: %s", caPEM[:50])
		}
	})

	t.Run("GetCACertPEM_Error", func(t *testing.T) {
		credPath := createTestCredentialsFile(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/token":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
			case strings.Contains(r.URL.Path, ":fetchCaCerts"):
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":{"code":403,"message":"Permission denied","status":"PERMISSION_DENIED"}}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &googlecas.Config{
			Project:     "test-project",
			Location:    "us-central1",
			CAPool:      "test-pool",
			Credentials: credPath,
			TTL:         "8760h",
			BaseURL:     srv.URL,
			TokenURL:    srv.URL + "/token",
		}
		connector := googlecas.New(config, logger)

		_, err := connector.GetCACertPEM(ctx)
		if err == nil {
			t.Fatal("Expected error for permission denied")
		}
	})

	t.Run("GetRenewalInfo_ReturnsNil", func(t *testing.T) {
		config := &googlecas.Config{
			Project:  "test-project",
			Location: "us-central1",
			CAPool:   "test-pool",
		}
		connector := googlecas.New(config, logger)

		result, err := connector.GetRenewalInfo(ctx, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
		if err != nil {
			t.Fatalf("GetRenewalInfo should not return error, got: %v", err)
		}
		if result != nil {
			t.Fatal("GetRenewalInfo should return nil for Google CAS")
		}
	})

	t.Run("AuthHeader_BearerToken", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		credPath := createTestCredentialsFile(t)
		var authHeader string

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/token":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"verified-token-abc","expires_in":3600,"token_type":"Bearer"}`))
			case strings.Contains(r.URL.Path, "/certificates") && r.Method == http.MethodPost:
				authHeader = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				resp := fmt.Sprintf(`{
					"name": "projects/p/locations/l/caPools/cp/certificates/c1",
					"pemCertificate": %q,
					"pemCertificateChain": []
				}`, testCertPEM)
				w.Write([]byte(resp))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &googlecas.Config{
			Project:     "test-project",
			Location:    "us-central1",
			CAPool:      "test-pool",
			Credentials: credPath,
			TTL:         "8760h",
			BaseURL:     srv.URL,
			TokenURL:    srv.URL + "/token",
		}
		connector := googlecas.New(config, logger)

		_, csrPEM := generateTestCSR(t, "auth-test.example.com")
		_, err := connector.IssueCertificate(ctx, issuer.IssuanceRequest{
			CommonName: "auth-test.example.com",
			CSRPEM:     csrPEM,
		})
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if authHeader != "Bearer verified-token-abc" {
			t.Errorf("Expected 'Bearer verified-token-abc', got '%s'", authHeader)
		}
	})
}

// createTestCredentialsFile generates a temporary service account JSON file with a test RSA key.
func createTestCredentialsFile(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	creds := map[string]interface{}{
		"type":           "service_account",
		"project_id":     "test-project",
		"private_key_id": "key-123",
		"private_key":    string(keyPEM),
		"client_email":   "certctl@test-project.iam.gserviceaccount.com",
		"token_uri":      "https://oauth2.googleapis.com/token",
	}

	data, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("Failed to marshal credentials: %v", err)
	}

	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "credentials.json")
	if err := os.WriteFile(credPath, data, 0600); err != nil {
		t.Fatalf("Failed to write credentials file: %v", err)
	}

	return credPath
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
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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
