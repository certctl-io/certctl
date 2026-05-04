package caddy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/connector/target"
	"github.com/certctl-io/certctl/internal/connector/target/caddy"
)

// generateTestCertAndKey creates a self-signed cert + ECDSA key for tests
// that exercise the file-mode PEM-validation path added in Bundle 9 (the
// 2026-05-02 deployment-target audit). Pre-Bundle-9 the placeholder
// "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----" was
// enough because ValidateDeployment only checked file existence; Fix 2
// of Bundle 9 PEM-parses the file via certutil.ParseCertificatePEM, so
// real test certs are required wherever the test deploys-then-validates.
func generateTestCertAndKey(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "caddy-test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestCaddyConnector_ValidateConfig_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}
}

func TestCaddyConnector_ValidateConfig_InvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	connector := caddy.New(&caddy.Config{}, logger)
	err := connector.ValidateConfig(ctx, json.RawMessage(`{invalid}`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestCaddyConnector_ValidateConfig_InvalidMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		Mode:     "invalid",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestCaddyConnector_ValidateConfig_FileMode_MissingCertDir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("expected error for missing cert_dir in file mode")
	}
}

func TestCaddyConnector_ValidateConfig_DefaultsApplied(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		CertDir: tmpDir,
		Mode:    "file",
		// Don't specify AdminAPI, CertFile, KeyFile - should use defaults
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}
}

func TestCaddyConnector_DeployViaAPI_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Create a mock Caddy admin API server.
	//
	// Bundle 9 Fix 3 of the 2026-05-02 deployment-target audit added an
	// idempotency short-circuit: the connector now GETs the load endpoint
	// first to compare the active cert hash with the deploy payload. The
	// GET returns an empty array so the comparison falls through to the
	// POST (which is what this test exercises).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/config/apps/tls/certificates/load") {
			switch r.Method {
			case "GET":
				// Idempotency probe — return empty so the connector falls
				// through to the POST path that this test asserts on.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("[]"))
				return
			case "POST":
				body, _ := io.ReadAll(r.Body)
				var payload map[string]string
				json.Unmarshal(body, &payload)
				if payload["cert"] == "" {
					t.Fatal("cert field missing in payload")
				}
				if payload["key"] == "" {
					t.Fatal("key field missing in payload")
				}
				w.WriteHeader(http.StatusOK)
				return
			}
			t.Fatalf("unexpected method: %s", r.Method)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := caddy.Config{
		AdminAPI: server.URL,
		Mode:     "api",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	request := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(ctx, request)
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("deployment should succeed, got: %s", result.Message)
	}

	if !strings.Contains(result.Message, "API") {
		t.Fatalf("expected API deployment message, got: %s", result.Message)
	}
}

func TestCaddyConnector_DeployViaAPI_ServerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Create a mock Caddy admin API server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid certificate"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: server.URL,
		CertDir:  tmpDir,
		Mode:     "api",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	request := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(ctx, request)
	// API fails and falls back to file mode - should succeed
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("deployment should succeed via file fallback, got: %s", result.Message)
	}

	if !strings.Contains(result.Message, "file") {
		t.Fatalf("expected file deployment message after API failure, got: %s", result.Message)
	}
}

func TestCaddyConnector_DeployViaFile_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	request := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(ctx, request)
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("deployment should succeed, got: %s", result.Message)
	}

	// Verify files were created
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatalf("certificate file was not created: %s", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("key file was not created: %s", keyPath)
	}

	// Verify key file has correct permissions
	keyInfo, _ := os.Stat(keyPath)
	if keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("key file permissions are %o, expected 0600", keyInfo.Mode().Perm())
	}
}

func TestCaddyConnector_DeployViaFile_WriteError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  "/root/nonexistent",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)

	request := target.DeploymentRequest{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
	}

	result, err := connector.DeployCertificate(ctx, request)
	if err == nil {
		t.Fatal("expected error for write failure")
	}

	if result.Success {
		t.Fatal("deployment should fail")
	}
}

func TestCaddyConnector_ValidateDeployment_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	// Bundle 9 Fix 2: ValidateDeployment now PEM-parses the cert file, so
	// the deploy-then-validate flow needs a real test cert (placeholder
	// "MIIC..." would fail the new PEM-parse check).
	certPEM, keyPEM := generateTestCertAndKey(t)
	deployRequest := target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
	connector.DeployCertificate(ctx, deployRequest)

	// Validate deployment
	validateRequest := target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123456",
	}

	result, err := connector.ValidateDeployment(ctx, validateRequest)
	if err != nil {
		t.Fatalf("ValidateDeployment failed: %v", err)
	}

	if !result.Valid {
		t.Fatalf("validation should succeed, got: %s", result.Message)
	}

	if result.Serial != "123456" {
		t.Fatalf("serial mismatch: expected 123456, got %s", result.Serial)
	}
}

func TestCaddyConnector_ValidateDeployment_FileNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
		Mode:     "file",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	// Don't deploy, just validate
	validateRequest := target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "123456",
	}

	result, err := connector.ValidateDeployment(ctx, validateRequest)
	if err == nil {
		t.Fatal("expected error for missing certificate file")
	}

	if result.Valid {
		t.Fatal("validation should fail")
	}
}

func TestCaddyConnector_APIMode_NoChain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/config/apps/tls/certificates/load") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := caddy.Config{
		AdminAPI: server.URL,
		Mode:     "api",
	}

	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	request := target.DeploymentRequest{
		CertPEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		// No ChainPEM
	}

	result, err := connector.DeployCertificate(ctx, request)
	if err != nil {
		t.Fatalf("DeployCertificate failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("deployment should succeed, got: %s", result.Message)
	}
}

// --- Bundle 9: duration metric + file-mode PEM validate + api-mode idempotency ---
//
// Six tests pin the three independent fixes added in Bundle 9 of the
// 2026-05-02 deployment-target audit:
//   - Fix 1 (duration metric L176): TestCaddy_API_DurationMetric_NonZero.
//   - Fix 2 (file-mode PEM validate):
//     TestCaddy_ValidateDeployment_FileMode_MalformedPEM_Rejected,
//     TestCaddy_ValidateDeployment_FileMode_ValidPEM_Accepted.
//   - Fix 3 (api-mode idempotency short-circuit):
//     TestCaddy_API_Idempotent_SkipsPOSTWhenCertHashMatches,
//     TestCaddy_API_Idempotent_RunsPOSTWhenCertHashDiffers,
//     TestCaddy_API_Idempotent_GETFails_FallsThroughToPOST.

func TestCaddy_API_DurationMetric_NonZero(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Bundle 9 Fix 1: pre-fix the api-mode duration_ms metric was
	// computed as time.Since(time.Now()).Milliseconds() which always
	// rounded to ~0ms. Post-fix it uses the startTime captured in
	// DeployCertificate. Add a small artificial delay in the handler so
	// the asserted duration_ms is unambiguously non-zero.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/config/apps/tls/certificates/load") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]"))
		case "POST":
			// Simulate a slow Caddy admin reload — 10ms is enough to
			// produce a measurable duration_ms.
			time.Sleep(10 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	cfg := caddy.Config{AdminAPI: server.URL, Mode: "api"}
	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	certPEM, keyPEM := generateTestCertAndKey(t)
	result, err := connector.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}

	// duration_ms must parse as int >= 5 (we slept 10ms in the handler;
	// allow some headroom for clock granularity on slow CI hosts).
	durationStr := result.Metadata["duration_ms"]
	if durationStr == "" {
		t.Fatal("expected duration_ms in metadata")
	}
	durationMs, err := strconv.Atoi(durationStr)
	if err != nil {
		t.Fatalf("duration_ms is not int-parseable: %q (%v)", durationStr, err)
	}
	if durationMs < 5 {
		t.Errorf("duration_ms = %d, expected >= 5 (handler slept 10ms; pre-Bundle-9 bug rounded this to 0)", durationMs)
	}
}

func TestCaddy_ValidateDeployment_FileMode_MalformedPEM_Rejected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Bundle 9 Fix 2: ValidateDeployment now PEM-parses the cert file
	// (was only os.Stat existence check). A cert file containing garbage
	// passes existence-check but fails PEM-decode → Valid=false.
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(certPath, []byte("this is not a PEM cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("this is not a key either"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
		Mode:     "file",
	}
	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	result, err := connector.ValidateDeployment(ctx, target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "0xDEADBEEF",
	})
	if err == nil {
		t.Fatal("expected error when cert file is malformed PEM")
	}
	if result.Valid {
		t.Fatal("expected Valid=false for malformed PEM")
	}
	// Error message must reference the PEM/x509 failure so operators see
	// what's wrong rather than a confusing downstream symptom.
	if !strings.Contains(result.Message, "PEM") && !strings.Contains(result.Message, "x509") {
		t.Errorf("expected error message to mention PEM/x509, got: %s", result.Message)
	}
}

func TestCaddy_ValidateDeployment_FileMode_ValidPEM_Accepted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Bundle 9 Fix 2: a real test cert + key passes both the os.Stat
	// existence check and the new certutil.ParseCertificatePEM check.
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	certPEM, keyPEM := generateTestCertAndKey(t)
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := caddy.Config{
		AdminAPI: "http://localhost:2019",
		CertDir:  tmpDir,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
		Mode:     "file",
	}
	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	result, err := connector.ValidateDeployment(ctx, target.ValidationRequest{
		CertificateID: "mc-test",
		Serial:        "1",
	})
	if err != nil {
		t.Fatalf("ValidateDeployment failed unexpectedly: %v (msg: %s)", err, result.Message)
	}
	if !result.Valid {
		t.Errorf("expected Valid=true for a real PEM cert, got: %s", result.Message)
	}
}

func TestCaddy_API_Idempotent_SkipsPOSTWhenCertHashMatches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Bundle 9 Fix 3: the connector GETs first, hashes the active cert,
	// and skips the POST when SHA-256 matches. Build the deploy payload
	// (cert + trailing newline; no chain in this test) and seed the mock
	// GET response with an identical cert string so the hash matches and
	// the POST counter stays at 0.
	certPEM, keyPEM := generateTestCertAndKey(t)
	expectedCertField := certPEM + "\n" // matches deployViaAPI's "request.CertPEM + \"\\n\"" build step

	var postCount, getCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/config/apps/tls/certificates/load") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case "GET":
			getCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			payload, _ := json.Marshal([]map[string]string{
				{"cert": expectedCertField, "key": keyPEM},
			})
			w.Write(payload)
		case "POST":
			postCount.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	cfg := caddy.Config{AdminAPI: server.URL, Mode: "api"}
	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	result, err := connector.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}
	if got := postCount.Load(); got != 0 {
		t.Errorf("expected 0 POST calls (idempotent skip), got %d", got)
	}
	if got := getCount.Load(); got != 1 {
		t.Errorf("expected exactly 1 GET call (idempotency probe), got %d", got)
	}
	if result.Metadata["idempotent"] != "true" {
		t.Errorf("expected metadata.idempotent=true on the skip path, got: %q", result.Metadata["idempotent"])
	}
}

func TestCaddy_API_Idempotent_RunsPOSTWhenCertHashDiffers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Bundle 9 Fix 3: when the GET response's cert hash differs from
	// the deploy payload, fall through to the POST. metadata.idempotent
	// must NOT be set on the POST path (only on the skip path).
	certPEM, keyPEM := generateTestCertAndKey(t)
	differentCert, _ := generateTestCertAndKey(t) // a DIFFERENT cert in the GET response

	var postCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/config/apps/tls/certificates/load") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			payload, _ := json.Marshal([]map[string]string{
				{"cert": differentCert, "key": "different-key"},
			})
			w.Write(payload)
		case "POST":
			postCount.Add(1)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	cfg := caddy.Config{AdminAPI: server.URL, Mode: "api"}
	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	result, err := connector.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}
	if got := postCount.Load(); got != 1 {
		t.Errorf("expected exactly 1 POST call (cert-hash mismatch fell through), got %d", got)
	}
	if result.Metadata["idempotent"] == "true" {
		t.Error("expected metadata.idempotent absent or false on the non-idempotent POST path")
	}
}

func TestCaddy_API_Idempotent_GETFails_FallsThroughToPOST(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Bundle 9 Fix 3: idempotency is best-effort. A GET that returns 500
	// (or 404, or a malformed JSON body, or a network error) silently
	// falls through to the POST so deploys never get blocked by a
	// misbehaving admin endpoint.
	certPEM, keyPEM := generateTestCertAndKey(t)

	var postCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/config/apps/tls/certificates/load") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case "GET":
			// Return 500 — connector should fall through to POST.
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "internal error")
		case "POST":
			postCount.Add(1)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	cfg := caddy.Config{AdminAPI: server.URL, Mode: "api"}
	connector := caddy.New(&cfg, logger)
	rawConfig, _ := json.Marshal(cfg)
	_ = connector.ValidateConfig(ctx, rawConfig)

	result, err := connector.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}
	if got := postCount.Load(); got != 1 {
		t.Errorf("expected exactly 1 POST call (GET failure fell through), got %d", got)
	}
	if result.Metadata["idempotent"] == "true" {
		t.Error("expected metadata.idempotent absent on the fallthrough POST path")
	}
}
