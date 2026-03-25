package stepca_test

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
	"testing"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/stepca"
)

func TestStepCAConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("ValidateConfig_Success", func(t *testing.T) {
		// Start a mock step-ca health endpoint
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ok"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
			ValidityDays:    90,
		}

		connector := stepca.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingCAURL", func(t *testing.T) {
		config := stepca.Config{
			ProvisionerName: "test",
		}

		connector := stepca.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing ca_url")
		}
	})

	t.Run("ValidateConfig_MissingProvisioner", func(t *testing.T) {
		config := stepca.Config{
			CAURL: "https://ca.example.com",
		}

		connector := stepca.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing provisioner_name")
		}
	})

	t.Run("ValidateConfig_UnreachableCA", func(t *testing.T) {
		config := stepca.Config{
			CAURL:           "http://localhost:19999",
			ProvisionerName: "test",
		}

		connector := stepca.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for unreachable CA")
		}
	})

	t.Run("IssueCertificate_Success", func(t *testing.T) {
		// Generate a test certificate to return in the mock
		testCertPEM, testKeyPEM := generateTestCert(t)
		_ = testKeyPEM

		// Start a mock step-ca server
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ok"}`))
			case "/sign":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
				w.Write([]byte(resp))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
			ValidityDays:    30,
		}
		connector := stepca.New(config, logger)

		_, csrPEM, err := generateStepCATestCSR("app.internal.corp")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		req := issuer.IssuanceRequest{
			CommonName: "app.internal.corp",
			SANs:       []string{"app.internal.corp"},
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

		t.Logf("step-ca issued cert: serial=%s", result.Serial)
	})

	t.Run("IssueCertificate_ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.WriteHeader(http.StatusOK)
			case "/sign":
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid token"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
		}
		connector := stepca.New(config, logger)

		_, csrPEM, _ := generateStepCATestCSR("test.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for server error response")
		}
		t.Logf("Correctly got error: %v", err)
	})

	t.Run("RenewCertificate", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.WriteHeader(http.StatusOK)
			case "/sign":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
				w.Write([]byte(resp))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
		}
		connector := stepca.New(config, logger)

		_, csrPEM, _ := generateStepCATestCSR("renew.example.com")
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
			case "/health":
				w.WriteHeader(http.StatusOK)
			case "/revoke":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ok"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
		}
		connector := stepca.New(config, logger)

		reason := "keyCompromise"
		revokeReq := issuer.RevocationRequest{
			Serial: "1234567890",
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
			case "/health":
				w.WriteHeader(http.StatusOK)
			case "/revoke":
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"unauthorized"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
		}
		connector := stepca.New(config, logger)

		revokeReq := issuer.RevocationRequest{
			Serial: "1234567890",
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err == nil {
			t.Fatal("Expected error for server error response")
		}
	})

	t.Run("GetOrderStatus", func(t *testing.T) {
		config := &stepca.Config{
			CAURL:           "https://ca.example.com",
			ProvisionerName: "test-provisioner",
		}
		connector := stepca.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "stepca-12345")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "completed" {
			t.Errorf("Expected status 'completed', got '%s'", status.Status)
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

func generateStepCATestCSR(commonName string) (*x509.CertificateRequest, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
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
		return nil, "", err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, "", err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	return csr, string(csrPEM), nil
}

