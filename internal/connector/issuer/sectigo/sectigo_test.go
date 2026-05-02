package sectigo_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/sectigo"
)

func TestSectigoConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("ValidateConfig_Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ssl/v1/types" {
				// Verify all 3 auth headers are present
				if r.Header.Get("customerUri") != "test-org" {
					t.Errorf("Expected customerUri 'test-org', got '%s'", r.Header.Get("customerUri"))
				}
				if r.Header.Get("login") != "api-user" {
					t.Errorf("Expected login 'api-user', got '%s'", r.Header.Get("login"))
				}
				if r.Header.Get("password") != "api-pass" {
					t.Errorf("Expected password 'api-pass', got '%s'", r.Header.Get("password"))
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`[{"id":423,"name":"Sectigo OV SSL","term":[365,730]}]`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
			OrgID:       12345,
			CertType:    423,
			Term:        365,
			BaseURL:     srv.URL,
		}

		connector := sectigo.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingCustomerURI", func(t *testing.T) {
		config := sectigo.Config{
			Login:    "api-user",
			Password: "api-pass",
			OrgID:    12345,
		}

		connector := sectigo.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing customer_uri")
		}
		if !strings.Contains(err.Error(), "customer_uri is required") {
			t.Errorf("Expected customer_uri required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingLogin", func(t *testing.T) {
		config := sectigo.Config{
			CustomerURI: "test-org",
			Password:    "api-pass",
			OrgID:       12345,
		}

		connector := sectigo.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing login")
		}
		if !strings.Contains(err.Error(), "login is required") {
			t.Errorf("Expected login required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingPassword", func(t *testing.T) {
		config := sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			OrgID:       12345,
		}

		connector := sectigo.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing password")
		}
		if !strings.Contains(err.Error(), "password is required") {
			t.Errorf("Expected password required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingOrgID", func(t *testing.T) {
		config := sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
		}

		connector := sectigo.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing org_id")
		}
		if !strings.Contains(err.Error(), "org_id is required") {
			t.Errorf("Expected org_id required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_InvalidCredentials", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ssl/v1/types" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"code":0,"description":"Invalid credentials"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := sectigo.Config{
			CustomerURI: "bad-org",
			Login:       "bad-user",
			Password:    "bad-pass",
			OrgID:       12345,
			BaseURL:     srv.URL,
		}

		connector := sectigo.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for invalid credentials")
		}
		if !strings.Contains(err.Error(), "invalid") {
			t.Logf("Got error: %v", err)
		}
	})

	t.Run("IssueCertificate_ImmediateSuccess", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		testChainPEM, _ := generateTestCert(t)
		pemBundle := testCertPEM + testChainPEM

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify auth headers on every request
			if r.Header.Get("customerUri") == "" || r.Header.Get("login") == "" || r.Header.Get("password") == "" {
				t.Error("Missing auth headers on request")
			}

			switch {
			case r.URL.Path == "/ssl/v1/enroll" && r.Method == http.MethodPost:
				// Verify request body structure
				body, _ := io.ReadAll(r.Body)
				var req map[string]interface{}
				json.Unmarshal(body, &req)
				if req["orgId"] == nil {
					t.Error("Expected orgId in enrollment request")
				}
				if req["certType"] == nil {
					t.Error("Expected certType in enrollment request")
				}
				// SANs should be comma-separated string, not array
				if sans, ok := req["subjAltNames"].(string); ok {
					if !strings.Contains(sans, ",") && len(sans) > 0 {
						// Single SAN is fine
					}
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55001,"renewId":"ren-abc"}`))

			case r.URL.Path == "/ssl/v1/55001" && r.Method == http.MethodGet:
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55001,"status":"Issued","commonName":"app.example.com"}`))

			case r.URL.Path == "/ssl/v1/collect/55001/pem" && r.Method == http.MethodGet:
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(pemBundle))

			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
			OrgID:       12345,
			CertType:    423,
			Term:        365,
			BaseURL:     srv.URL,
		}
		connector := sectigo.New(config, logger)

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
			t.Error("CertPEM should not be empty for immediate issuance")
		}
		if result.Serial == "" {
			t.Error("Serial should not be empty for immediate issuance")
		}
		if result.OrderID != "55001" {
			t.Errorf("Expected OrderID '55001', got '%s'", result.OrderID)
		}
		t.Logf("Sectigo issued cert: serial=%s, orderID=%s", result.Serial, result.OrderID)
	})

	t.Run("IssueCertificate_Pending", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ssl/v1/enroll":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55002}`))
			case "/ssl/v1/55002":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55002,"status":"Applied","commonName":"secure.example.com"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
			OrgID:       12345,
			CertType:    423,
			Term:        365,
			BaseURL:     srv.URL,
		}
		connector := sectigo.New(config, logger)

		_, csrPEM := generateTestCSR(t, "secure.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "secure.example.com",
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if result.OrderID != "55002" {
			t.Errorf("Expected OrderID '55002', got '%s'", result.OrderID)
		}
		if result.CertPEM != "" {
			t.Error("CertPEM should be empty for pending order")
		}
		if result.Serial != "" {
			t.Error("Serial should be empty for pending order")
		}
	})

	t.Run("IssueCertificate_ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"code":-14,"description":"Invalid CSR"}`))
		}))
		defer srv.Close()

		config := &sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
			OrgID:       12345,
			CertType:    423,
			Term:        365,
			BaseURL:     srv.URL,
		}
		connector := sectigo.New(config, logger)

		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     "invalid-csr",
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for server error response")
		}
	})

	t.Run("GetOrderStatus_Issued", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		testChainPEM, _ := generateTestCert(t)
		pemBundle := testCertPEM + testChainPEM

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ssl/v1/55001":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55001,"status":"Issued","commonName":"app.example.com"}`))
			case "/ssl/v1/collect/55001/pem":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(pemBundle))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
			OrgID:       12345,
			BaseURL:     srv.URL,
		}
		connector := sectigo.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "55001")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "completed" {
			t.Errorf("Expected status 'completed', got '%s'", status.Status)
		}
		if status.CertPEM == nil || *status.CertPEM == "" {
			t.Error("CertPEM should not be empty for issued order")
		}
		if status.Serial == nil || *status.Serial == "" {
			t.Error("Serial should not be empty for issued order")
		}
	})

	t.Run("GetOrderStatus_Pending", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ssl/v1/55002" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55002,"status":"Applied"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := &sectigo.Config{
			CustomerURI:        "test-org",
			Login:              "api-user",
			Password:           "api-pass",
			OrgID:              12345,
			BaseURL:            srv.URL,
			PollMaxWaitSeconds: 1, // keep pending tests fast
		}
		connector := sectigo.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "55002")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "pending" {
			t.Errorf("Expected status 'pending', got '%s'", status.Status)
		}
		if status.CertPEM != nil {
			t.Error("CertPEM should be nil for pending order")
		}
	})

	t.Run("GetOrderStatus_Rejected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ssl/v1/55003" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55003,"status":"Rejected"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := &sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
			OrgID:       12345,
			BaseURL:     srv.URL,
		}
		connector := sectigo.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "55003")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "failed" {
			t.Errorf("Expected status 'failed', got '%s'", status.Status)
		}
	})

	t.Run("GetOrderStatus_CollectNotReady", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ssl/v1/55004":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55004,"status":"Issued","commonName":"pending-collect.example.com"}`))
			case "/ssl/v1/collect/55004/pem":
				// Sectigo returns 400 with code -183 when cert not yet generated
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"code":-183,"description":"Certificate is not available"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &sectigo.Config{
			CustomerURI:        "test-org",
			Login:              "api-user",
			Password:           "api-pass",
			OrgID:              12345,
			BaseURL:            srv.URL,
			PollMaxWaitSeconds: 1, // keep collect-not-ready tests fast
		}
		connector := sectigo.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "55004")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		// Should be treated as pending (cert approved but not yet generated)
		if status.Status != "pending" {
			t.Errorf("Expected status 'pending' for collect-not-ready, got '%s'", status.Status)
		}
	})

	t.Run("RenewCertificate_NewOrder", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ssl/v1/enroll":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55010}`))
			case "/ssl/v1/55010":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55010,"status":"Applied"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
			OrgID:       12345,
			CertType:    423,
			Term:        365,
			BaseURL:     srv.URL,
		}
		connector := sectigo.New(config, logger)

		_, csrPEM := generateTestCSR(t, "renew.example.com")
		renewReq := issuer.RenewalRequest{
			CommonName: "renew.example.com",
			CSRPEM:     csrPEM,
		}

		result, err := connector.RenewCertificate(ctx, renewReq)
		if err != nil {
			t.Fatalf("RenewCertificate failed: %v", err)
		}

		if result.OrderID == "" {
			t.Error("OrderID should not be empty")
		}
	})

	t.Run("RevokeCertificate_Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/ssl/v1/revoke/") && r.Method == http.MethodPost {
				// Verify auth headers
				if r.Header.Get("customerUri") == "" {
					t.Error("Missing customerUri header on revoke request")
				}
				if r.Header.Get("login") == "" {
					t.Error("Missing login header on revoke request")
				}
				if r.Header.Get("password") == "" {
					t.Error("Missing password header on revoke request")
				}

				// Verify reason in body
				body, _ := io.ReadAll(r.Body)
				var req map[string]interface{}
				json.Unmarshal(body, &req)
				if req["reason"] == nil {
					t.Error("Expected reason in revoke request body")
				}

				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := &sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
			OrgID:       12345,
			BaseURL:     srv.URL,
		}
		connector := sectigo.New(config, logger)

		reason := "keyCompromise"
		revokeReq := issuer.RevocationRequest{
			Serial: "55001",
			Reason: &reason,
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}
	})

	t.Run("RevokeCertificate_Error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"code":-1,"description":"Certificate not found"}`))
		}))
		defer srv.Close()

		config := &sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
			OrgID:       12345,
			BaseURL:     srv.URL,
		}
		connector := sectigo.New(config, logger)

		revokeReq := issuer.RevocationRequest{
			Serial: "00000",
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err == nil {
			t.Fatal("Expected error for revocation of nonexistent cert")
		}
	})

	t.Run("GetRenewalInfo_ReturnsNil", func(t *testing.T) {
		config := &sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
			OrgID:       12345,
			BaseURL:     "https://cert-manager.com/api",
		}
		connector := sectigo.New(config, logger)

		result, err := connector.GetRenewalInfo(ctx, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
		if err != nil {
			t.Fatalf("GetRenewalInfo should not return error, got: %v", err)
		}
		if result != nil {
			t.Fatal("GetRenewalInfo should return nil for Sectigo")
		}
	})

	t.Run("DefaultTerm", func(t *testing.T) {
		config := &sectigo.Config{
			CustomerURI: "test-org",
			Login:       "api-user",
			Password:    "api-pass",
			OrgID:       12345,
			CertType:    423,
			// Term intentionally left as 0
		}
		connector := sectigo.New(config, logger)

		// Verify the connector was created (the default is set in New())
		if connector == nil {
			t.Fatal("Connector should not be nil")
		}

		// Verify via a request that uses the term
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ssl/v1/enroll" {
				body, _ := io.ReadAll(r.Body)
				var req map[string]interface{}
				json.Unmarshal(body, &req)
				// Default term should be 365
				if term, ok := req["term"].(float64); ok {
					if int(term) != 365 {
						t.Errorf("Expected default term 365, got %d", int(term))
					}
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55099}`))
				return
			}
			if r.URL.Path == "/ssl/v1/55099" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55099,"status":"Applied"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		// Reconfigure with test server URL
		config.BaseURL = srv.URL
		connector = sectigo.New(config, logger)

		_, csrPEM := generateTestCSR(t, "test.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate with default term failed: %v", err)
		}
		if result.OrderID == "" {
			t.Error("OrderID should not be empty")
		}
	})

	t.Run("AuthHeaders_PresentOnAllRequests", func(t *testing.T) {
		requestCount := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			// Every single request must have all 3 auth headers
			if r.Header.Get("customerUri") != "verify-org" {
				t.Errorf("Request %d: expected customerUri 'verify-org', got '%s'", requestCount, r.Header.Get("customerUri"))
			}
			if r.Header.Get("login") != "verify-user" {
				t.Errorf("Request %d: expected login 'verify-user', got '%s'", requestCount, r.Header.Get("login"))
			}
			if r.Header.Get("password") != "verify-pass" {
				t.Errorf("Request %d: expected password 'verify-pass', got '%s'", requestCount, r.Header.Get("password"))
			}

			switch r.URL.Path {
			case "/ssl/v1/enroll":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55050}`))
			case "/ssl/v1/55050":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"sslId":55050,"status":"Applied"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &sectigo.Config{
			CustomerURI: "verify-org",
			Login:       "verify-user",
			Password:    "verify-pass",
			OrgID:       12345,
			CertType:    423,
			Term:        365,
			BaseURL:     srv.URL,
		}
		connector := sectigo.New(config, logger)

		_, csrPEM := generateTestCSR(t, "auth-check.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "auth-check.example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if requestCount < 2 {
			t.Errorf("Expected at least 2 requests (enroll + status), got %d", requestCount)
		}
	})

	t.Run("RevocationReasonMapping", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"keyCompromise", "Compromised"},
			{"cessationOfOperation", "Cessation of Operation"},
			{"affiliationChanged", "Affiliation Changed"},
			{"superseded", "Superseded"},
			{"unspecified", "Unspecified"},
			{"unknown_reason", "Unspecified"},
		}

		for _, tt := range tests {
			t.Run(tt.input, func(t *testing.T) {
				var receivedReason string
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(r.URL.Path, "/ssl/v1/revoke/") {
						body, _ := io.ReadAll(r.Body)
						var req map[string]interface{}
						json.Unmarshal(body, &req)
						receivedReason = req["reason"].(string)
						w.WriteHeader(http.StatusNoContent)
						return
					}
					http.NotFound(w, r)
				}))
				defer srv.Close()

				config := &sectigo.Config{
					CustomerURI: "test-org",
					Login:       "api-user",
					Password:    "api-pass",
					OrgID:       12345,
					BaseURL:     srv.URL,
				}
				connector := sectigo.New(config, logger)

				reason := tt.input
				err := connector.RevokeCertificate(ctx, issuer.RevocationRequest{
					Serial: "12345",
					Reason: &reason,
				})
				if err != nil {
					t.Fatalf("RevokeCertificate failed: %v", err)
				}

				if receivedReason != tt.expected {
					t.Errorf("Expected reason '%s', got '%s'", tt.expected, receivedReason)
				}
			})
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
			CommonName: fmt.Sprintf("Test Certificate %s", serial.String()[:8]),
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
