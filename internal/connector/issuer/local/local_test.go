package local_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/local"
)

func TestLocalConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Test 1: Create connector and validate config
	t.Run("ValidateConfig", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	// Test 2: Issue a certificate
	t.Run("IssueCertificate", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		csr, csrPEM, err := generateTestCSR("test.example.com")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		req := issuer.IssuanceRequest{
			CommonName: csr.Subject.CommonName,
			SANs:       []string{"www.test.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if result.Serial == "" {
			t.Error("Serial is empty")
		}
		if result.CertPEM == "" {
			t.Error("CertPEM is empty")
		}
		if result.ChainPEM == "" {
			t.Error("ChainPEM is empty")
		}
		if result.OrderID == "" {
			t.Error("OrderID is empty")
		}
		if result.NotAfter.IsZero() {
			t.Error("NotAfter is zero")
		}

		t.Logf("Certificate issued: serial=%s, orderID=%s", result.Serial, result.OrderID)
	})

	// Test 3: Renew a certificate
	t.Run("RenewCertificate", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		csr, csrPEM, err := generateTestCSR("test.example.com")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		renewReq := issuer.RenewalRequest{
			CommonName: csr.Subject.CommonName,
			SANs:       []string{"www.test.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.RenewCertificate(ctx, renewReq)
		if err != nil {
			t.Fatalf("RenewCertificate failed: %v", err)
		}

		if result.Serial == "" {
			t.Error("Serial is empty")
		}

		t.Logf("Certificate renewed: serial=%s", result.Serial)
	})

	// Test 4: Get order status
	t.Run("GetOrderStatus", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "local-12345")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "completed" {
			t.Errorf("Expected status 'completed', got '%s'", status.Status)
		}

		t.Logf("Order status: %s", status.Status)
	})

	// Test 5: Revoke a certificate
	t.Run("RevokeCertificate", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		revokeReq := issuer.RevocationRequest{
			Serial: "test-serial-12345",
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}

		t.Logf("Certificate revoked: serial=%s", revokeReq.Serial)
	})

	// Test 6: Invalid CSR
	t.Run("InvalidCSR", func(t *testing.T) {
		config := &local.Config{
			CACommonName: "Test CA",
			ValidityDays: 30,
		}
		connector := local.New(config, logger)

		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     "invalid pem",
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for invalid CSR")
		}

		t.Logf("Correctly rejected invalid CSR: %v", err)
	})
}

// Sub-CA mode tests

func TestSubCAMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("SubCA_RSA_IssueCertificate", func(t *testing.T) {
		certPath, keyPath := generateTestSubCA(t, "rsa")
		defer os.Remove(certPath)
		defer os.Remove(keyPath)

		config := &local.Config{
			ValidityDays: 30,
			CACertPath:   certPath,
			CAKeyPath:    keyPath,
		}
		connector := local.New(config, logger)

		_, csrPEM, err := generateTestCSR("app.internal.corp")
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
			t.Fatalf("SubCA IssueCertificate failed: %v", err)
		}

		if result.CertPEM == "" {
			t.Error("CertPEM is empty")
		}
		if result.ChainPEM == "" {
			t.Error("ChainPEM is empty (should contain sub-CA cert)")
		}
		if result.Serial == "" {
			t.Error("Serial is empty")
		}

		// Verify the issued cert is signed by the sub-CA (not self-signed)
		certBlock, _ := pem.Decode([]byte(result.CertPEM))
		if certBlock == nil {
			t.Fatal("Failed to decode issued cert PEM")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse issued cert: %v", err)
		}

		// The issuer should be the sub-CA, not the cert itself
		if cert.Issuer.CommonName == cert.Subject.CommonName {
			t.Error("Issued cert appears to be self-signed (issuer == subject)")
		}

		t.Logf("Sub-CA issued cert: serial=%s, issuer=%s, subject=%s",
			result.Serial, cert.Issuer.CommonName, cert.Subject.CommonName)
	})

	t.Run("SubCA_ECDSA_IssueCertificate", func(t *testing.T) {
		certPath, keyPath := generateTestSubCA(t, "ecdsa")
		defer os.Remove(certPath)
		defer os.Remove(keyPath)

		config := &local.Config{
			ValidityDays: 30,
			CACertPath:   certPath,
			CAKeyPath:    keyPath,
		}
		connector := local.New(config, logger)

		_, csrPEM, err := generateTestCSR("api.internal.corp")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		req := issuer.IssuanceRequest{
			CommonName: "api.internal.corp",
			SANs:       []string{"api.internal.corp"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("SubCA ECDSA IssueCertificate failed: %v", err)
		}

		if result.CertPEM == "" {
			t.Error("CertPEM is empty")
		}

		t.Logf("Sub-CA (ECDSA) issued cert: serial=%s", result.Serial)
	})

	t.Run("SubCA_ValidateConfig_MissingKeyPath", func(t *testing.T) {
		cfg := local.Config{
			ValidityDays: 30,
			CACertPath:   "/some/cert.pem",
			// CAKeyPath intentionally omitted
		}
		connector := local.New(nil, logger)

		rawConfig, _ := json.Marshal(cfg)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error when only CACertPath is set")
		}
		t.Logf("Correctly rejected partial sub-CA config: %v", err)
	})

	t.Run("SubCA_ValidateConfig_NonexistentPaths", func(t *testing.T) {
		cfg := local.Config{
			ValidityDays: 30,
			CACertPath:   "/nonexistent/ca.pem",
			CAKeyPath:    "/nonexistent/ca-key.pem",
		}
		connector := local.New(nil, logger)

		rawConfig, _ := json.Marshal(cfg)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for nonexistent file paths")
		}
		t.Logf("Correctly rejected nonexistent paths: %v", err)
	})

	t.Run("SubCA_InvalidCertFile", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "bad-cert.pem")
		keyPath := filepath.Join(tmpDir, "bad-key.pem")

		// Write garbage data
		os.WriteFile(certPath, []byte("not a certificate"), 0600)
		os.WriteFile(keyPath, []byte("not a key"), 0600)

		config := &local.Config{
			ValidityDays: 30,
			CACertPath:   certPath,
			CAKeyPath:    keyPath,
		}
		connector := local.New(config, logger)

		_, csrPEM, _ := generateTestCSR("test.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for invalid cert file")
		}
		t.Logf("Correctly rejected invalid cert file: %v", err)
	})

	t.Run("SubCA_NonCACert", func(t *testing.T) {
		// Create a cert that is NOT a CA (no BasicConstraints.IsCA)
		tmpDir := t.TempDir()
		certPath, keyPath := generateTestNonCACert(t, tmpDir)

		config := &local.Config{
			ValidityDays: 30,
			CACertPath:   certPath,
			CAKeyPath:    keyPath,
		}
		connector := local.New(config, logger)

		_, csrPEM, _ := generateTestCSR("test.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for non-CA cert")
		}
		t.Logf("Correctly rejected non-CA cert: %v", err)
	})

	t.Run("SubCA_RenewCertificate", func(t *testing.T) {
		certPath, keyPath := generateTestSubCA(t, "rsa")
		defer os.Remove(certPath)
		defer os.Remove(keyPath)

		config := &local.Config{
			ValidityDays: 30,
			CACertPath:   certPath,
			CAKeyPath:    keyPath,
		}
		connector := local.New(config, logger)

		_, csrPEM, err := generateTestCSR("renew.internal.corp")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		renewReq := issuer.RenewalRequest{
			CommonName: "renew.internal.corp",
			SANs:       []string{"renew.internal.corp"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.RenewCertificate(ctx, renewReq)
		if err != nil {
			t.Fatalf("SubCA RenewCertificate failed: %v", err)
		}

		if result.Serial == "" {
			t.Error("Serial is empty")
		}
		t.Logf("Sub-CA renewed cert: serial=%s", result.Serial)
	})
}

// generateTestSubCA creates a self-signed CA cert+key pair and writes them to temp files.
// keyType can be "rsa" or "ecdsa".
func generateTestSubCA(t *testing.T, keyType string) (certPath, keyPath string) {
	t.Helper()
	tmpDir := t.TempDir()
	certPath = filepath.Join(tmpDir, "ca.pem")
	keyPath = filepath.Join(tmpDir, "ca-key.pem")

	var privKey interface{}
	var pubKey interface{}
	var keyPEM []byte

	switch keyType {
	case "rsa":
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}
		privKey = rsaKey
		pubKey = &rsaKey.PublicKey
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		})
	case "ecdsa":
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}
		privKey = ecKey
		pubKey = &ecKey.PublicKey
		ecKeyBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			t.Fatalf("Failed to marshal ECDSA key: %v", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecKeyBytes,
		})
	default:
		t.Fatalf("Unsupported key type: %s", keyType)
	}

	// Create a CA certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Sub-CA",
			Organization: []string{"CertCtl Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create CA cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write CA key: %v", err)
	}

	return certPath, keyPath
}

// generateTestNonCACert creates a cert+key pair where IsCA=false (not a CA cert).
func generateTestNonCACert(t *testing.T, tmpDir string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(tmpDir, "not-ca.pem")
	keyPath = filepath.Join(tmpDir, "not-ca-key.pem")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Not A CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false, // NOT a CA
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("Failed to create non-CA cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})

	os.WriteFile(certPath, certPEM, 0600)
	os.WriteFile(keyPath, keyPEM, 0600)

	return certPath, keyPath
}

func generateTestCSR(commonName string) (*x509.CertificateRequest, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	subj := pkix.Name{
		CommonName: commonName,
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            subj,
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
