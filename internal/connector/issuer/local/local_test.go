package local_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"strings"
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

	t.Run("SubCA_ExpiredCert_IsRejected", func(t *testing.T) {
		// Sub-CA expired 1 hour ago. M-5: loadCAFromDisk must fail closed
		// instead of minting child certs that immediately fail path validation
		// at every relying party (CWE-672).
		notBefore := time.Now().AddDate(-1, 0, 0)
		notAfter := time.Now().Add(-1 * time.Hour)
		certPath, keyPath := generateTestSubCAWithValidity(t, "rsa", notBefore, notAfter)

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
			CSRPEM:     csrPEM,
		}

		_, err = connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error when loading expired sub-CA; got nil")
		}
		if !strings.Contains(err.Error(), "expired") {
			t.Errorf("Expected error to mention 'expired'; got: %v", err)
		}
		if !strings.Contains(err.Error(), "Test Sub-CA") {
			t.Errorf("Expected error to include CA subject CN 'Test Sub-CA'; got: %v", err)
		}
		t.Logf("Correctly rejected expired sub-CA: %v", err)
	})

	t.Run("SubCA_NotYetValid_IsRejected", func(t *testing.T) {
		// Sub-CA is not valid for another hour (clock skew or operator error
		// pushing a pre-production CA into prod). M-5: loadCAFromDisk must
		// fail closed.
		notBefore := time.Now().Add(1 * time.Hour)
		notAfter := time.Now().AddDate(5, 0, 0)
		certPath, keyPath := generateTestSubCAWithValidity(t, "rsa", notBefore, notAfter)

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
			CSRPEM:     csrPEM,
		}

		_, err = connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error when loading not-yet-valid sub-CA; got nil")
		}
		if !strings.Contains(err.Error(), "not yet valid") {
			t.Errorf("Expected error to mention 'not yet valid'; got: %v", err)
		}
		if !strings.Contains(err.Error(), "Test Sub-CA") {
			t.Errorf("Expected error to include CA subject CN 'Test Sub-CA'; got: %v", err)
		}
		t.Logf("Correctly rejected not-yet-valid sub-CA: %v", err)
	})

	t.Run("SubCA_BarelyValid_IsAccepted", func(t *testing.T) {
		// Sub-CA valid from 1 minute ago to 1 hour from now. Edge case:
		// proves the M-5 window check doesn't over-reject CAs that are
		// legitimately live but close to the boundaries.
		notBefore := time.Now().Add(-1 * time.Minute)
		notAfter := time.Now().Add(1 * time.Hour)
		certPath, keyPath := generateTestSubCAWithValidity(t, "rsa", notBefore, notAfter)

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
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("Barely-valid sub-CA was wrongly rejected: %v", err)
		}
		if result.CertPEM == "" {
			t.Error("CertPEM is empty")
		}
		t.Logf("Correctly accepted barely-valid sub-CA: serial=%s", result.Serial)
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
// keyType can be "rsa" or "ecdsa". Validity window is [now, now+5y].
func generateTestSubCA(t *testing.T, keyType string) (certPath, keyPath string) {
	t.Helper()
	return generateTestSubCAWithValidity(t, keyType, time.Now(), time.Now().AddDate(5, 0, 0))
}

// generateTestSubCAWithValidity creates a self-signed CA cert+key pair with an
// explicit NotBefore/NotAfter window. Used by M-5 tests that exercise expired
// and not-yet-valid CA rejection in loadCAFromDisk.
func generateTestSubCAWithValidity(t *testing.T, keyType string, notBefore, notAfter time.Time) (certPath, keyPath string) {
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
		NotBefore:             notBefore,
		NotAfter:              notAfter,
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

// M15b: CRL and OCSP Tests

func TestGenerateCRL_Empty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &local.Config{
		CACommonName: "Test CA",
		ValidityDays: 30,
	}
	connector := local.New(config, logger)

	// Generate CRL with no revoked certs — should succeed with 0 entries
	crl, err := connector.GenerateCRL(ctx, nil)
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}

	if crl == nil {
		t.Fatal("CRL is nil")
	}

	// Verify it's valid DER by parsing
	parsedCRL, err := x509.ParseRevocationList(crl)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	if len(parsedCRL.RevokedCertificateEntries) != 0 {
		t.Errorf("expected 0 revoked entries, got %d", len(parsedCRL.RevokedCertificateEntries))
	}

	t.Logf("Empty CRL generated successfully with %d entries", len(parsedCRL.RevokedCertificateEntries))
}

func TestGenerateCRL_WithEntries(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &local.Config{
		CACommonName: "Test CA",
		ValidityDays: 30,
	}
	connector := local.New(config, logger)

	// Generate CRL with 2 revoked certs
	entries := []issuer.RevokedCertEntry{
		{SerialNumber: big.NewInt(12345), RevokedAt: time.Now().Add(-24 * time.Hour), ReasonCode: 1},
		{SerialNumber: big.NewInt(67890), RevokedAt: time.Now().Add(-1 * time.Hour), ReasonCode: 4},
	}

	crl, err := connector.GenerateCRL(ctx, entries)
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}

	if crl == nil {
		t.Fatal("CRL is nil")
	}

	parsedCRL, err := x509.ParseRevocationList(crl)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	if len(parsedCRL.RevokedCertificateEntries) != 2 {
		t.Errorf("expected 2 revoked entries, got %d", len(parsedCRL.RevokedCertificateEntries))
	}

	// Verify entries contain expected serials
	serials := make(map[string]bool)
	for _, entry := range parsedCRL.RevokedCertificateEntries {
		serials[entry.SerialNumber.String()] = true
	}

	if !serials["12345"] {
		t.Error("expected serial 12345 in CRL")
	}
	if !serials["67890"] {
		t.Error("expected serial 67890 in CRL")
	}

	t.Logf("CRL with entries generated successfully: %d entries", len(parsedCRL.RevokedCertificateEntries))
}

func TestGenerateCRL_BeforeCAInit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// CRL generation should init the CA automatically
	cfg := &local.Config{ValidityDays: 90}
	connector := local.New(cfg, logger)

	crl, err := connector.GenerateCRL(ctx, nil)
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}

	if crl == nil {
		t.Fatal("CRL is nil")
	}

	// Verify it's valid
	_, err = x509.ParseRevocationList(crl)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	t.Log("CRL generated with auto-initialized CA")
}

func TestGenerateCRL_WithReasonCodes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &local.Config{
		CACommonName: "Test CA",
		ValidityDays: 30,
	}
	connector := local.New(config, logger)

	// Test all RFC 5280 reason codes
	entries := []issuer.RevokedCertEntry{
		{SerialNumber: big.NewInt(100), RevokedAt: time.Now(), ReasonCode: 0}, // unspecified
		{SerialNumber: big.NewInt(101), RevokedAt: time.Now(), ReasonCode: 1}, // keyCompromise
		{SerialNumber: big.NewInt(102), RevokedAt: time.Now(), ReasonCode: 2}, // caCompromise
		{SerialNumber: big.NewInt(103), RevokedAt: time.Now(), ReasonCode: 3}, // affiliationChanged
		{SerialNumber: big.NewInt(104), RevokedAt: time.Now(), ReasonCode: 4}, // superseded
	}

	crl, err := connector.GenerateCRL(ctx, entries)
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}

	parsedCRL, err := x509.ParseRevocationList(crl)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	if len(parsedCRL.RevokedCertificateEntries) != 5 {
		t.Errorf("expected 5 revoked entries, got %d", len(parsedCRL.RevokedCertificateEntries))
	}

	// Verify reason codes are preserved
	reasonCount := 0
	for _, entry := range parsedCRL.RevokedCertificateEntries {
		if entry.ReasonCode >= 0 {
			reasonCount++
		}
	}
	if reasonCount != 5 {
		t.Errorf("expected all 5 entries to have reason codes, got %d", reasonCount)
	}

	t.Logf("CRL with %d reason codes generated successfully", reasonCount)
}

func TestSignOCSPResponse_Good(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &local.Config{
		CACommonName: "Test CA",
		ValidityDays: 30,
	}
	connector := local.New(config, logger)

	now := time.Now()
	resp, err := connector.SignOCSPResponse(ctx, issuer.OCSPSignRequest{
		CertSerial: big.NewInt(12345),
		CertStatus: 0, // good
		ThisUpdate: now,
		NextUpdate: now.Add(1 * time.Hour),
	})

	if err != nil {
		t.Fatalf("SignOCSPResponse failed: %v", err)
	}

	if resp == nil {
		t.Fatal("OCSP response is nil")
	}

	if len(resp) == 0 {
		t.Fatal("OCSP response is empty")
	}

	t.Logf("OCSP response for good cert generated: %d bytes", len(resp))
}

func TestSignOCSPResponse_Revoked(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &local.Config{
		CACommonName: "Test CA",
		ValidityDays: 30,
	}
	connector := local.New(config, logger)

	now := time.Now()
	revokedAt := now.Add(-24 * time.Hour)

	resp, err := connector.SignOCSPResponse(ctx, issuer.OCSPSignRequest{
		CertSerial:       big.NewInt(12345),
		CertStatus:       1, // revoked
		RevokedAt:        revokedAt,
		RevocationReason: 1, // keyCompromise
		ThisUpdate:       now,
		NextUpdate:       now.Add(1 * time.Hour),
	})

	if err != nil {
		t.Fatalf("SignOCSPResponse failed: %v", err)
	}

	if resp == nil {
		t.Fatal("OCSP response is nil")
	}

	if len(resp) == 0 {
		t.Fatal("OCSP response is empty")
	}

	t.Logf("OCSP response for revoked cert generated: %d bytes", len(resp))
}

func TestSignOCSPResponse_Unknown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &local.Config{
		CACommonName: "Test CA",
		ValidityDays: 30,
	}
	connector := local.New(config, logger)

	now := time.Now()
	resp, err := connector.SignOCSPResponse(ctx, issuer.OCSPSignRequest{
		CertSerial: big.NewInt(12345),
		CertStatus: 2, // unknown
		ThisUpdate: now,
		NextUpdate: now.Add(1 * time.Hour),
	})

	if err != nil {
		t.Fatalf("SignOCSPResponse failed: %v", err)
	}

	if resp == nil {
		t.Fatal("OCSP response is nil")
	}

	if len(resp) == 0 {
		t.Fatal("OCSP response is empty")
	}

	t.Logf("OCSP response for unknown cert generated: %d bytes", len(resp))
}

func TestSignOCSPResponse_BeforeCAInit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := &local.Config{ValidityDays: 90}
	connector := local.New(cfg, logger)

	now := time.Now()
	resp, err := connector.SignOCSPResponse(ctx, issuer.OCSPSignRequest{
		CertSerial: big.NewInt(999),
		CertStatus: 0,
		ThisUpdate: now,
		NextUpdate: now.Add(1 * time.Hour),
	})

	if err != nil {
		t.Fatalf("SignOCSPResponse failed: %v", err)
	}

	if resp == nil || len(resp) == 0 {
		t.Fatal("OCSP response is nil or empty")
	}

	t.Log("OCSP response generated with auto-initialized CA")
}

func TestGenerateCRL_SubCA(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	certPath, keyPath := generateTestSubCA(t, "rsa")
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	config := &local.Config{
		ValidityDays: 30,
		CACertPath:   certPath,
		CAKeyPath:    keyPath,
	}
	connector := local.New(config, logger)

	entries := []issuer.RevokedCertEntry{
		{SerialNumber: big.NewInt(555), RevokedAt: time.Now().Add(-12 * time.Hour), ReasonCode: 2},
	}

	crl, err := connector.GenerateCRL(ctx, entries)
	if err != nil {
		t.Fatalf("SubCA GenerateCRL failed: %v", err)
	}

	if crl == nil {
		t.Fatal("CRL is nil")
	}

	parsedCRL, err := x509.ParseRevocationList(crl)
	if err != nil {
		t.Fatalf("failed to parse SubCA CRL: %v", err)
	}

	if len(parsedCRL.RevokedCertificateEntries) != 1 {
		t.Errorf("expected 1 entry in SubCA CRL, got %d", len(parsedCRL.RevokedCertificateEntries))
	}

	t.Log("SubCA CRL generated successfully")
}

// M11c: MaxTTL enforcement tests

func TestIssueCertificate_MaxTTL_CapsValidity(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &local.Config{
		CACommonName: "Test CA",
		ValidityDays: 365, // would normally be 1 year
	}
	connector := local.New(config, logger)

	_, csrPEM, err := generateTestCSR("maxttl.example.com")
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	// MaxTTLSeconds = 3600 (1 hour) should cap the 365-day validity
	req := issuer.IssuanceRequest{
		CommonName:    "maxttl.example.com",
		SANs:          []string{"maxttl.example.com"},
		CSRPEM:        csrPEM,
		MaxTTLSeconds: 3600,
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	// Cert validity should be ~1 hour, not 365 days
	duration := result.NotAfter.Sub(result.NotBefore)
	if duration > 2*time.Hour {
		t.Errorf("expected validity ≤1h, got %v", duration)
	}
	if duration < 30*time.Minute {
		t.Errorf("expected validity ≥30m, got %v (too short)", duration)
	}

	t.Logf("MaxTTL capped: validity=%v (NotBefore=%v, NotAfter=%v)", duration, result.NotBefore, result.NotAfter)
}

func TestIssueCertificate_MaxTTL_ZeroMeansNoCap(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &local.Config{
		CACommonName: "Test CA",
		ValidityDays: 30,
	}
	connector := local.New(config, logger)

	_, csrPEM, err := generateTestCSR("nocap.example.com")
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	req := issuer.IssuanceRequest{
		CommonName:    "nocap.example.com",
		SANs:          []string{"nocap.example.com"},
		CSRPEM:        csrPEM,
		MaxTTLSeconds: 0, // no cap
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	// Should get ~30 days as configured
	duration := result.NotAfter.Sub(result.NotBefore)
	if duration < 29*24*time.Hour {
		t.Errorf("expected ~30 day validity without MaxTTL cap, got %v", duration)
	}

	t.Logf("No MaxTTL cap: validity=%v", duration)
}

func TestIssueCertificate_MaxTTL_LargerThanValidityDays_NoCap(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &local.Config{
		CACommonName: "Test CA",
		ValidityDays: 30,
	}
	connector := local.New(config, logger)

	_, csrPEM, err := generateTestCSR("larger.example.com")
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	// MaxTTL = 365 days, but ValidityDays = 30. The shorter one wins.
	req := issuer.IssuanceRequest{
		CommonName:    "larger.example.com",
		SANs:          []string{"larger.example.com"},
		CSRPEM:        csrPEM,
		MaxTTLSeconds: 365 * 24 * 3600, // 365 days
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	// Should still be ~30 days (ValidityDays wins when shorter)
	duration := result.NotAfter.Sub(result.NotBefore)
	if duration > 31*24*time.Hour {
		t.Errorf("expected ~30 day validity (ValidityDays wins), got %v", duration)
	}

	t.Logf("MaxTTL larger than ValidityDays: validity=%v (ValidityDays wins)", duration)
}

func TestRenewCertificate_MaxTTL_CapsValidity(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &local.Config{
		CACommonName: "Test CA",
		ValidityDays: 365,
	}
	connector := local.New(config, logger)

	_, csrPEM, err := generateTestCSR("renew-maxttl.example.com")
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	req := issuer.RenewalRequest{
		CommonName:    "renew-maxttl.example.com",
		SANs:          []string{"renew-maxttl.example.com"},
		CSRPEM:        csrPEM,
		MaxTTLSeconds: 7200, // 2 hours
	}

	result, err := connector.RenewCertificate(ctx, req)
	if err != nil {
		t.Fatalf("RenewCertificate failed: %v", err)
	}

	duration := result.NotAfter.Sub(result.NotBefore)
	if duration > 3*time.Hour {
		t.Errorf("expected validity ≤2h for renewal MaxTTL, got %v", duration)
	}

	t.Logf("Renewal MaxTTL capped: validity=%v", duration)
}

func TestSignOCSPResponse_SubCA(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	certPath, keyPath := generateTestSubCA(t, "ecdsa")
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	config := &local.Config{
		ValidityDays: 30,
		CACertPath:   certPath,
		CAKeyPath:    keyPath,
	}
	connector := local.New(config, logger)

	now := time.Now()
	resp, err := connector.SignOCSPResponse(ctx, issuer.OCSPSignRequest{
		CertSerial: big.NewInt(777),
		CertStatus: 0,
		ThisUpdate: now,
		NextUpdate: now.Add(1 * time.Hour),
	})

	if err != nil {
		t.Fatalf("SubCA SignOCSPResponse failed: %v", err)
	}

	if resp == nil || len(resp) == 0 {
		t.Fatal("SubCA OCSP response is nil or empty")
	}

	t.Log("SubCA OCSP response generated successfully")
}

// TestSubCA_LoadCAFromDisk_RejectsUnsupportedKeyAlgorithm pins the new
// signer.Wrap error path introduced when local.go was refactored to
// route every CA-signing call through the Signer interface. The
// historical parsePrivateKey accepted any PKCS#8 key that satisfied
// crypto.Signer (including Ed25519). The new flow keeps that
// parse-time acceptance but adds a Wrap step that enforces the
// certctl-supported algorithm enum (RSA-2048/3072/4096, ECDSA-P256/P384).
//
// This test confirms an Ed25519 sub-CA key fails LOUDLY at load time
// with a clear "wrap CA private key as signer" error — instead of
// either crashing later at sign time or silently producing a cert
// chain certctl cannot revalidate. Pins both:
//   - the new error path coverage (recovers the 0.5pp drop introduced
//     by the parsePrivateKey deletion)
//   - the contract that loaded sub-CA keys MUST be in the supported
//     algorithm enum
func TestSubCA_LoadCAFromDisk_RejectsUnsupportedKeyAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Build a valid CA cert signed by RSA so cert-validation passes...
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Mismatched-Key Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	// ...but write an UNRELATED Ed25519 key to disk. The Connector's
	// loadCAFromDisk does not enforce key-cert key match — it only
	// validates the cert and parses the key. The newly-introduced
	// signer.Wrap step is what rejects Ed25519.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatalf("marshal ed25519 PKCS#8: %v", err)
	}
	keyPath := filepath.Join(tmpDir, "ca.key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	conn := local.New(&local.Config{
		CACommonName: "Mismatched-Key Test CA",
		ValidityDays: 90,
		CACertPath:   certPath,
		CAKeyPath:    keyPath,
	}, logger)

	// IssueCertificate triggers ensureCA → loadCAFromDisk → ParsePrivateKey
	// (succeeds for Ed25519 PKCS#8) → signer.Wrap (rejects Ed25519).
	dummyKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrTpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf.example.com"}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTpl, dummyKey)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	_, err = conn.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "leaf.example.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected IssueCertificate to fail for Ed25519 sub-CA key, got nil")
	}
	if !strings.Contains(err.Error(), "wrap CA private key as signer") {
		t.Fatalf("expected error to mention 'wrap CA private key as signer', got: %v", err)
	}
}
