package digicert_test

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

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/digicert"
)

func TestDigiCertConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("ValidateConfig_Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/user/me" {
				if r.Header.Get("X-DC-DEVKEY") == "dc-test-api-key" {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"id":12345,"first_name":"Test","last_name":"User"}`))
					return
				}
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"errors":[{"code":"invalid_api_key"}]}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := digicert.Config{
			APIKey:      "dc-test-api-key",
			OrgID:       "12345",
			ProductType: "ssl_basic",
			BaseURL:     srv.URL,
		}

		connector := digicert.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingAPIKey", func(t *testing.T) {
		config := digicert.Config{
			OrgID: "12345",
		}

		connector := digicert.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing api_key")
		}
		if !strings.Contains(err.Error(), "api_key is required") {
			t.Errorf("Expected api_key required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingOrgID", func(t *testing.T) {
		config := digicert.Config{
			APIKey: "dc-test-key",
		}

		connector := digicert.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing org_id")
		}
		if !strings.Contains(err.Error(), "org_id is required") {
			t.Errorf("Expected org_id required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_InvalidKey", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/user/me" {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"errors":[{"code":"invalid_api_key"}]}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := digicert.Config{
			APIKey:  "dc-bad-key",
			OrgID:   "12345",
			BaseURL: srv.URL,
		}

		connector := digicert.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for invalid API key")
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
			switch {
			case strings.HasPrefix(r.URL.Path, "/order/certificate/ssl_basic"):
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(`{"id":99001,"status":"issued","certificate_id":88001}`))
			case r.URL.Path == "/certificate/88001/download/format/pem_all":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(pemBundle))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &digicert.Config{
			APIKey:      "dc-test-key",
			OrgID:       "12345",
			ProductType: "ssl_basic",
			BaseURL:     srv.URL,
		}
		connector := digicert.New(config, logger)

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
		if result.OrderID != "99001" {
			t.Errorf("Expected OrderID '99001', got '%s'", result.OrderID)
		}
		t.Logf("DigiCert issued cert: serial=%s, orderID=%s", result.Serial, result.OrderID)
	})

	t.Run("IssueCertificate_Pending", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasPrefix(r.URL.Path, "/order/certificate/ssl_ev_basic"):
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(`{"id":99002,"status":"pending"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &digicert.Config{
			APIKey:      "dc-test-key",
			OrgID:       "12345",
			ProductType: "ssl_ev_basic",
			BaseURL:     srv.URL,
		}
		connector := digicert.New(config, logger)

		_, csrPEM := generateTestCSR(t, "secure.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "secure.example.com",
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if result.OrderID != "99002" {
			t.Errorf("Expected OrderID '99002', got '%s'", result.OrderID)
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
			w.Write([]byte(`{"errors":[{"code":"invalid_csr","message":"CSR is malformed"}]}`))
		}))
		defer srv.Close()

		config := &digicert.Config{
			APIKey:      "dc-test-key",
			OrgID:       "12345",
			ProductType: "ssl_basic",
			BaseURL:     srv.URL,
		}
		connector := digicert.New(config, logger)

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
			switch {
			case r.URL.Path == "/order/certificate/99001":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id":99001,"status":"issued","certificate":{"id":88001,"common_name":"app.example.com"}}`))
			case r.URL.Path == "/certificate/88001/download/format/pem_all":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(pemBundle))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &digicert.Config{
			APIKey:  "dc-test-key",
			OrgID:   "12345",
			BaseURL: srv.URL,
		}
		connector := digicert.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "99001")
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
			if r.URL.Path == "/order/certificate/99002" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id":99002,"status":"pending","certificate":{"id":0}}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := &digicert.Config{
			APIKey:  "dc-test-key",
			OrgID:   "12345",
			BaseURL: srv.URL,
		}
		connector := digicert.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "99002")
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
			if r.URL.Path == "/order/certificate/99003" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id":99003,"status":"rejected","certificate":{"id":0}}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := &digicert.Config{
			APIKey:  "dc-test-key",
			OrgID:   "12345",
			BaseURL: srv.URL,
		}
		connector := digicert.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "99003")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "failed" {
			t.Errorf("Expected status 'failed', got '%s'", status.Status)
		}
	})

	t.Run("RenewCertificate_NewOrder", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasPrefix(r.URL.Path, "/order/certificate/"):
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(`{"id":99010,"status":"pending"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &digicert.Config{
			APIKey:      "dc-test-key",
			OrgID:       "12345",
			ProductType: "ssl_basic",
			BaseURL:     srv.URL,
		}
		connector := digicert.New(config, logger)

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
			if strings.HasSuffix(r.URL.Path, "/revoke") && r.Method == http.MethodPut {
				if r.Header.Get("X-DC-DEVKEY") == "" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := &digicert.Config{
			APIKey:  "dc-test-key",
			OrgID:   "12345",
			BaseURL: srv.URL,
		}
		connector := digicert.New(config, logger)

		reason := "keyCompromise"
		revokeReq := issuer.RevocationRequest{
			Serial: "88001",
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
			w.Write([]byte(`{"errors":[{"code":"certificate_not_found"}]}`))
		}))
		defer srv.Close()

		config := &digicert.Config{
			APIKey:  "dc-test-key",
			OrgID:   "12345",
			BaseURL: srv.URL,
		}
		connector := digicert.New(config, logger)

		revokeReq := issuer.RevocationRequest{
			Serial: "00000",
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err == nil {
			t.Fatal("Expected error for revocation of nonexistent cert")
		}
	})

	t.Run("GetOrderStatus_DownloadError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/order/certificate/99004":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id":99004,"status":"issued","certificate":{"id":88004}}`))
			case r.URL.Path == "/certificate/88004/download/format/pem_all":
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"errors":["internal server error"]}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &digicert.Config{
			APIKey:  "dc-test-key",
			OrgID:   "12345",
			BaseURL: srv.URL,
		}
		connector := digicert.New(config, logger)

		_, err := connector.GetOrderStatus(ctx, "99004")
		if err == nil {
			t.Fatal("Expected error when download fails")
		}
		if !strings.Contains(err.Error(), "download") {
			t.Logf("Got error: %v", err)
		}
	})

	t.Run("GetRenewalInfo_ReturnsNil", func(t *testing.T) {
		config := &digicert.Config{
			APIKey:  "dc-test-key",
			OrgID:   "12345",
			BaseURL: "https://api.digicert.com",
		}
		connector := digicert.New(config, logger)

		result, err := connector.GetRenewalInfo(ctx, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
		if err != nil {
			t.Fatalf("GetRenewalInfo should not return error, got: %v", err)
		}
		if result != nil {
			t.Fatal("GetRenewalInfo should return nil for DigiCert")
		}
	})

	t.Run("DefaultProductType", func(t *testing.T) {
		config := &digicert.Config{
			APIKey: "dc-test-key",
			OrgID:  "12345",
			// ProductType intentionally left empty
		}
		connector := digicert.New(config, logger)

		// Verify the connector was created (the default is set in New())
		if connector == nil {
			t.Fatal("Connector should not be nil")
		}

		// Verify via a request that uses the product type
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify the path includes the default product type
			if strings.Contains(r.URL.Path, "ssl_basic") {
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(`{"id":99099,"status":"pending"}`))
				return
			}
			t.Errorf("Expected path to contain 'ssl_basic', got: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer srv.Close()

		// Reconfigure with test server URL
		config.BaseURL = srv.URL
		connector = digicert.New(config, logger)

		_, csrPEM := generateTestCSR(t, "test.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate with default product type failed: %v", err)
		}
		if result.OrderID == "" {
			t.Error("OrderID should not be empty")
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
