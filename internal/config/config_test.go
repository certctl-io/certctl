package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// clearCertctlEnv unsets all CERTCTL_* environment variables to ensure test isolation.
func clearCertctlEnv(t *testing.T) {
	t.Helper()
	for _, env := range os.Environ() {
		for i := 0; i < len(env); i++ {
			if env[i] == '=' {
				key := env[:i]
				if len(key) > 7 && key[:8] == "CERTCTL_" {
					t.Setenv(key, "")
					os.Unsetenv(key)
				}
				break
			}
		}
	}
}

// setMinimalValidEnv sets the minimum env vars needed for Load() to succeed (Validate passes).
//
// HTTPS-everywhere milestone (§2.1 + §3 locked decisions): the control plane
// is TLS-only and Validate() refuses to pass without a readable cert/key pair
// on disk. setMinimalValidEnv therefore materializes a throwaway ECDSA P-256
// self-signed pair in t.TempDir() and points the two TLS env vars at it so
// every Load-based test inherits a valid HTTPS posture without each caller
// having to spell out cert generation. The temp dir is cleaned up by
// testing.T at end-of-test.
func setMinimalValidEnv(t *testing.T) {
	t.Helper()
	// api-key auth requires a secret
	t.Setenv("CERTCTL_AUTH_SECRET", "test-secret-key")
	// HTTPS-only control plane requires a real cert/key pair on disk.
	certPath, keyPath := generateTestTLSPair(t)
	t.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", certPath)
	t.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", keyPath)
	// Acquisition-audit RED-003 closure (Sprint 5 ACQ, 2026-05-16):
	// the deny-empty default flipped to true, so Load() now refuses
	// to start with an empty bootstrap token. Supply a placeholder
	// so Load()-based tests that don't specifically test the
	// deny-empty gate continue to pass. Tests that DO exercise the
	// empty-token gate explicitly override via
	// t.Setenv("CERTCTL_AGENT_BOOTSTRAP_TOKEN", "") after this helper.
	t.Setenv("CERTCTL_AGENT_BOOTSTRAP_TOKEN", "test-bootstrap-token-placeholder")
}

// generateTestTLSPair writes an ECDSA P-256 self-signed certificate + private
// key pair to files inside t.TempDir() and returns the paths. Same shape used
// by cmd/server/tls_test.go — this duplicates the generator rather than
// importing it so the config package tests stay independent of cmd/server.
func generateTestTLSPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "certctl-config-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// validServerConfig returns a ServerConfig with Port=8080 plus a freshly
// minted TLS cert/key pair on disk, so Validate() passes the HTTPS-only
// preflight (cert empty → stat → tls.LoadX509KeyPair round-trip). Every
// struct-based Validate test uses this so they fail for the reason they
// claim to test, not for a missing TLS pair.
func validServerConfig(t *testing.T) ServerConfig {
	t.Helper()
	certPath, keyPath := generateTestTLSPair(t)
	return ServerConfig{
		Port: 8080,
		TLS:  ServerTLSConfig{CertPath: certPath, KeyPath: keyPath},
	}
}

func TestLoad_DefaultValues(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Server defaults
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Server.Host = %q, want %q", cfg.Server.Host, "127.0.0.1")
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want %d", cfg.Server.Port, 8080)
	}
	if cfg.Server.MaxBodySize != 1024*1024 {
		t.Errorf("Server.MaxBodySize = %d, want %d", cfg.Server.MaxBodySize, 1024*1024)
	}

	// Auth defaults
	if cfg.Auth.Type != "api-key" {
		t.Errorf("Auth.Type = %q, want %q", cfg.Auth.Type, "api-key")
	}

	// Keygen defaults
	if cfg.Keygen.Mode != "agent" {
		t.Errorf("Keygen.Mode = %q, want %q", cfg.Keygen.Mode, "agent")
	}

	// RateLimit defaults
	if cfg.RateLimit.Enabled != true {
		t.Errorf("RateLimit.Enabled = %v, want true", cfg.RateLimit.Enabled)
	}
	if cfg.RateLimit.RPS != 50 {
		t.Errorf("RateLimit.RPS = %f, want 50", cfg.RateLimit.RPS)
	}
	if cfg.RateLimit.BurstSize != 100 {
		t.Errorf("RateLimit.BurstSize = %d, want 100", cfg.RateLimit.BurstSize)
	}

	// Log defaults
	if cfg.Log.Level != "info" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "info")
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format = %q, want %q", cfg.Log.Format, "json")
	}

	// Scheduler defaults
	if cfg.Scheduler.RenewalCheckInterval != 1*time.Hour {
		t.Errorf("Scheduler.RenewalCheckInterval = %v, want 1h", cfg.Scheduler.RenewalCheckInterval)
	}
	if cfg.Scheduler.JobProcessorInterval != 30*time.Second {
		t.Errorf("Scheduler.JobProcessorInterval = %v, want 30s", cfg.Scheduler.JobProcessorInterval)
	}

	// ACME defaults
	if cfg.ACME.ChallengeType != "http-01" {
		t.Errorf("ACME.ChallengeType = %q, want %q", cfg.ACME.ChallengeType, "http-01")
	}

	// Vault defaults
	if cfg.Vault.Mount != "pki" {
		t.Errorf("Vault.Mount = %q, want %q", cfg.Vault.Mount, "pki")
	}
	if cfg.Vault.TTL != "8760h" {
		t.Errorf("Vault.TTL = %q, want %q", cfg.Vault.TTL, "8760h")
	}

	// EST defaults
	if cfg.EST.Enabled != false {
		t.Errorf("EST.Enabled = %v, want false", cfg.EST.Enabled)
	}
	if cfg.EST.IssuerID != "iss-local" {
		t.Errorf("EST.IssuerID = %q, want %q", cfg.EST.IssuerID, "iss-local")
	}

	// Verification defaults
	if cfg.Verification.Enabled != true {
		t.Errorf("Verification.Enabled = %v, want true", cfg.Verification.Enabled)
	}

	// Digest defaults
	if cfg.Digest.Enabled != false {
		t.Errorf("Digest.Enabled = %v, want false", cfg.Digest.Enabled)
	}
	if cfg.Digest.Interval != 24*time.Hour {
		t.Errorf("Digest.Interval = %v, want 24h", cfg.Digest.Interval)
	}

	// Database defaults
	if cfg.Database.URL != "postgres://localhost/certctl" {
		t.Errorf("Database.URL = %q, want default", cfg.Database.URL)
	}
	// Phase 6 SCALE-M1 (2026-05-14): default bumped from 25 → 50 to
	// relieve pool-saturation pressure on 1K+ agent fleets. The
	// CERTCTL_DATABASE_MAX_CONNS override still works for operators
	// who want the smaller value back; this test pins the default.
	if cfg.Database.MaxConnections != 50 {
		t.Errorf("Database.MaxConnections = %d, want 50", cfg.Database.MaxConnections)
	}
}

func TestLoad_AllEnvVarsSet(t *testing.T) {
	clearCertctlEnv(t)

	// HTTPS-only control plane: Load() → Validate() refuses an empty cert path.
	// Materialize a throwaway ECDSA P-256 pair and point the two TLS env vars
	// at it before setting every other CERTCTL_* var this test cares about.
	certPath, keyPath := generateTestTLSPair(t)
	t.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", certPath)
	t.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", keyPath)

	t.Setenv("CERTCTL_SERVER_HOST", "0.0.0.0")
	t.Setenv("CERTCTL_SERVER_PORT", "9090")
	t.Setenv("CERTCTL_MAX_BODY_SIZE", "2097152")
	t.Setenv("CERTCTL_AUTH_TYPE", "api-key")
	t.Setenv("CERTCTL_AUTH_SECRET", "my-secret")
	t.Setenv("CERTCTL_RATE_LIMIT_ENABLED", "false")
	t.Setenv("CERTCTL_RATE_LIMIT_RPS", "100")
	t.Setenv("CERTCTL_RATE_LIMIT_BURST", "200")
	t.Setenv("CERTCTL_CORS_ORIGINS", "https://a.com,https://b.com")
	t.Setenv("CERTCTL_KEYGEN_MODE", "server")
	// Sprint 4 ARCH-003 made Load()→Validate() refuse to boot in
	// server-keygen mode without an explicit demo-mode acknowledgement.
	// This test exercises the "every CERTCTL_* env var set" path, so
	// it sets KEYGEN_MODE=server — which now requires the demo-ack
	// pair. Mirror the SEC-H3 demo-ack pattern: ACK=true + fresh TS
	// within the 24h window.
	t.Setenv("CERTCTL_DEMO_MODE_ACK", "true")
	t.Setenv("CERTCTL_DEMO_MODE_ACK_TS", strconv.FormatInt(time.Now().Unix(), 10))
	t.Setenv("CERTCTL_LOG_LEVEL", "debug")
	t.Setenv("CERTCTL_LOG_FORMAT", "text")
	t.Setenv("CERTCTL_DATABASE_URL", "postgres://user:pass@db:5432/certctl")
	t.Setenv("CERTCTL_DATABASE_MAX_CONNS", "50")
	t.Setenv("CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL", "2h")
	t.Setenv("CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL", "1m")
	t.Setenv("CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL", "5m")
	t.Setenv("CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL", "2m")
	t.Setenv("CERTCTL_VAULT_ADDR", "https://vault:8200")
	t.Setenv("CERTCTL_VAULT_TOKEN", "hvs.test")
	t.Setenv("CERTCTL_VAULT_MOUNT", "pki-int")
	t.Setenv("CERTCTL_VAULT_ROLE", "web")
	t.Setenv("CERTCTL_VAULT_TTL", "720h")
	t.Setenv("CERTCTL_ACME_CHALLENGE_TYPE", "dns-01")
	t.Setenv("CERTCTL_ACME_ARI_ENABLED", "true")
	t.Setenv("CERTCTL_EST_ENABLED", "true")
	t.Setenv("CERTCTL_EST_ISSUER_ID", "iss-acme")
	t.Setenv("CERTCTL_DIGEST_ENABLED", "true")
	t.Setenv("CERTCTL_DIGEST_INTERVAL", "12h")
	t.Setenv("CERTCTL_DIGEST_RECIPIENTS", "alice@co.com,bob@co.com")
	t.Setenv("CERTCTL_SMTP_HOST", "smtp.example.com")
	t.Setenv("CERTCTL_SMTP_PORT", "465")
	t.Setenv("CERTCTL_SMTP_FROM_ADDRESS", "noreply@co.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Server.Host = %q, want %q", cfg.Server.Host, "0.0.0.0")
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Server.MaxBodySize != 2097152 {
		t.Errorf("Server.MaxBodySize = %d, want 2097152", cfg.Server.MaxBodySize)
	}
	if cfg.RateLimit.Enabled != false {
		t.Errorf("RateLimit.Enabled = %v, want false", cfg.RateLimit.Enabled)
	}
	if cfg.RateLimit.RPS != 100 {
		t.Errorf("RateLimit.RPS = %f, want 100", cfg.RateLimit.RPS)
	}
	if cfg.RateLimit.BurstSize != 200 {
		t.Errorf("RateLimit.BurstSize = %d, want 200", cfg.RateLimit.BurstSize)
	}
	if len(cfg.CORS.AllowedOrigins) != 2 {
		t.Errorf("CORS.AllowedOrigins has %d items, want 2", len(cfg.CORS.AllowedOrigins))
	} else {
		if cfg.CORS.AllowedOrigins[0] != "https://a.com" {
			t.Errorf("CORS.AllowedOrigins[0] = %q, want %q", cfg.CORS.AllowedOrigins[0], "https://a.com")
		}
		if cfg.CORS.AllowedOrigins[1] != "https://b.com" {
			t.Errorf("CORS.AllowedOrigins[1] = %q, want %q", cfg.CORS.AllowedOrigins[1], "https://b.com")
		}
	}
	if cfg.Keygen.Mode != "server" {
		t.Errorf("Keygen.Mode = %q, want %q", cfg.Keygen.Mode, "server")
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "debug")
	}
	if cfg.Log.Format != "text" {
		t.Errorf("Log.Format = %q, want %q", cfg.Log.Format, "text")
	}
	if cfg.Database.MaxConnections != 50 {
		t.Errorf("Database.MaxConnections = %d, want 50", cfg.Database.MaxConnections)
	}
	if cfg.Scheduler.RenewalCheckInterval != 2*time.Hour {
		t.Errorf("Scheduler.RenewalCheckInterval = %v, want 2h", cfg.Scheduler.RenewalCheckInterval)
	}
	if cfg.Scheduler.JobProcessorInterval != 1*time.Minute {
		t.Errorf("Scheduler.JobProcessorInterval = %v, want 1m", cfg.Scheduler.JobProcessorInterval)
	}
	if cfg.Vault.Addr != "https://vault:8200" {
		t.Errorf("Vault.Addr = %q, want %q", cfg.Vault.Addr, "https://vault:8200")
	}
	if cfg.Vault.Mount != "pki-int" {
		t.Errorf("Vault.Mount = %q, want %q", cfg.Vault.Mount, "pki-int")
	}
	if cfg.ACME.ChallengeType != "dns-01" {
		t.Errorf("ACME.ChallengeType = %q, want %q", cfg.ACME.ChallengeType, "dns-01")
	}
	if cfg.ACME.ARIEnabled != true {
		t.Errorf("ACME.ARIEnabled = %v, want true", cfg.ACME.ARIEnabled)
	}
	if cfg.EST.Enabled != true {
		t.Errorf("EST.Enabled = %v, want true", cfg.EST.Enabled)
	}
	if cfg.EST.IssuerID != "iss-acme" {
		t.Errorf("EST.IssuerID = %q, want %q", cfg.EST.IssuerID, "iss-acme")
	}
	if cfg.Digest.Enabled != true {
		t.Errorf("Digest.Enabled = %v, want true", cfg.Digest.Enabled)
	}
	if cfg.Digest.Interval != 12*time.Hour {
		t.Errorf("Digest.Interval = %v, want 12h", cfg.Digest.Interval)
	}
	if len(cfg.Digest.Recipients) != 2 {
		t.Errorf("Digest.Recipients has %d items, want 2", len(cfg.Digest.Recipients))
	}
	if cfg.Notifiers.SMTPHost != "smtp.example.com" {
		t.Errorf("Notifiers.SMTPHost = %q, want %q", cfg.Notifiers.SMTPHost, "smtp.example.com")
	}
	if cfg.Notifiers.SMTPPort != 465 {
		t.Errorf("Notifiers.SMTPPort = %d, want 465", cfg.Notifiers.SMTPPort)
	}
}

func TestLoad_InvalidIntEnvVar(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	t.Setenv("CERTCTL_SERVER_PORT", "notanint")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() should fall back to default, got error: %v", err)
	}
	// Falls back to default
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want 8080 (default fallback)", cfg.Server.Port)
	}
}

func TestLoad_InvalidDurationEnvVar(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	t.Setenv("CERTCTL_DIGEST_INTERVAL", "notaduration")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() should fall back to default, got error: %v", err)
	}
	if cfg.Digest.Interval != 24*time.Hour {
		t.Errorf("Digest.Interval = %v, want 24h (default fallback)", cfg.Digest.Interval)
	}
}

func TestLoad_InvalidBoolEnvVar(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	t.Setenv("CERTCTL_RATE_LIMIT_ENABLED", "notabool")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() should fall back to default, got error: %v", err)
	}
	// getEnvBool only matches "true", "1", "yes" — anything else is false
	if cfg.RateLimit.Enabled != false {
		t.Errorf("RateLimit.Enabled = %v, want false for invalid bool", cfg.RateLimit.Enabled)
	}
}

func TestLoad_CommaSeparatedList(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	t.Setenv("CERTCTL_CORS_ORIGINS", "https://a.com, https://b.com , https://c.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if len(cfg.CORS.AllowedOrigins) != 3 {
		t.Fatalf("CORS.AllowedOrigins has %d items, want 3", len(cfg.CORS.AllowedOrigins))
	}
	// trimSpace should handle spaces around items
	if cfg.CORS.AllowedOrigins[1] != "https://b.com" {
		t.Errorf("CORS.AllowedOrigins[1] = %q, want %q (trimmed)", cfg.CORS.AllowedOrigins[1], "https://b.com")
	}
}

// Phase 2 SEC-H1 (2026-05-13) introduced the AgentBootstrapTokenDenyEmpty
// staged flag with default false. Acquisition-audit RED-003 closure
// (Sprint 5 ACQ, 2026-05-16) flipped the default to true. The test
// below preserves the back-compat path (operator explicitly opts back
// to the v2.1.x warn-mode pass-through); the new default behavior is
// covered by TestLoad_AgentBootstrapTokenDenyEmpty_DefaultIsTrue +
// TestValidate_AgentBootstrapTokenDenyEmpty_True_EmptyTokenFailsClosed
// further down in this file.
func TestValidate_AgentBootstrapTokenDenyEmpty_DefaultFalse_AllowsEmpty(t *testing.T) {
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret", AgentBootstrapToken: "", AgentBootstrapTokenDenyEmpty: false},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned error with deny-empty=false + empty token: %v", err)
	}
}

func TestValidate_AgentBootstrapTokenDenyEmpty_True_EmptyTokenFailsClosed(t *testing.T) {
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret", AgentBootstrapToken: "", AgentBootstrapTokenDenyEmpty: true},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil; want ErrAgentBootstrapTokenRequired")
	}
	if !errors.Is(err, ErrAgentBootstrapTokenRequired) {
		t.Errorf("Validate() err = %v; want errors.Is to match ErrAgentBootstrapTokenRequired", err)
	}
	if !strings.Contains(err.Error(), "CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY=true") {
		t.Errorf("Validate() error = %q; want message to mention the deny-empty env var name", err.Error())
	}
}

func TestValidate_AgentBootstrapTokenDenyEmpty_True_RealTokenPasses(t *testing.T) {
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret", AgentBootstrapToken: "a-real-32-byte-token-value-here-x", AgentBootstrapTokenDenyEmpty: true},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned error with deny-empty=true + real token: %v", err)
	}
}

// Phase 2 SEC-M4 (2026-05-13) — ACME insecure now requires explicit ACK.
func TestValidate_ACMEInsecure_WithoutAck_FailsClosed(t *testing.T) {
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret"},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
		ACME:      ACMEConfig{Insecure: true, InsecureAck: false},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil; want ErrACMEInsecureWithoutAck")
	}
	if !errors.Is(err, ErrACMEInsecureWithoutAck) {
		t.Errorf("Validate() err = %v; want errors.Is to match ErrACMEInsecureWithoutAck", err)
	}
	if !strings.Contains(err.Error(), "CERTCTL_ACME_INSECURE_ACK") {
		t.Errorf("Validate() error = %q; want message to mention CERTCTL_ACME_INSECURE_ACK", err.Error())
	}
}

func TestValidate_ACMEInsecure_WithAck_Passes(t *testing.T) {
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret"},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
		ACME:      ACMEConfig{Insecure: true, InsecureAck: true},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned error with Insecure=true + InsecureAck=true: %v", err)
	}
}

func TestValidate_ACMEInsecureFalse_IgnoresAck(t *testing.T) {
	// InsecureAck is irrelevant when Insecure=false. No fail-closed branch.
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret"},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
		ACME:      ACMEConfig{Insecure: false, InsecureAck: false},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned error with Insecure=false: %v", err)
	}
}

// Phase 2 SEC-H3 (2026-05-13) — DemoModeAck now expires after 24h via DemoModeAckTS.
// Note: DemoModeAck=true on a loopback bind requires only the timestamp guard;
// no HIGH-12 cross-firing because the existing HIGH-12 guard fires only on
// non-loopback hosts. All tests here keep the server host as loopback so we
// observe ONLY the new SEC-H3 behavior.
func TestValidate_DemoModeAck_MissingTS_FailsClosed(t *testing.T) {
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret", DemoModeAck: true, DemoModeAckTS: ""},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil; want ErrDemoModeAckExpired with empty TS")
	}
	if !errors.Is(err, ErrDemoModeAckExpired) {
		t.Errorf("Validate() err = %v; want errors.Is to match ErrDemoModeAckExpired", err)
	}
	if !strings.Contains(err.Error(), "CERTCTL_DEMO_MODE_ACK_TS") {
		t.Errorf("Validate() error = %q; want message to mention CERTCTL_DEMO_MODE_ACK_TS", err.Error())
	}
}

func TestValidate_DemoModeAck_StaleTS_FailsClosed(t *testing.T) {
	// TS older than 24h → expired.
	staleEpoch := time.Now().Add(-25 * time.Hour).Unix()
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret", DemoModeAck: true, DemoModeAckTS: strconv.FormatInt(staleEpoch, 10)},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil; want ErrDemoModeAckExpired with 25h-old TS")
	}
	if !errors.Is(err, ErrDemoModeAckExpired) {
		t.Errorf("Validate() err = %v; want errors.Is to match ErrDemoModeAckExpired", err)
	}
}

func TestValidate_DemoModeAck_FreshTS_Passes(t *testing.T) {
	// TS within 24h → passes.
	freshEpoch := time.Now().Add(-1 * time.Hour).Unix()
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret", DemoModeAck: true, DemoModeAckTS: strconv.FormatInt(freshEpoch, 10)},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned error with 1h-old TS: %v", err)
	}
}

func TestValidate_DemoModeAck_NonNumericTS_FailsClosed(t *testing.T) {
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret", DemoModeAck: true, DemoModeAckTS: "yesterday"},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil; want ErrDemoModeAckExpired with non-numeric TS")
	}
	if !errors.Is(err, ErrDemoModeAckExpired) {
		t.Errorf("Validate() err = %v; want errors.Is to match ErrDemoModeAckExpired", err)
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("Validate() error = %q; want message to mention parse failure", err.Error())
	}
}

func TestValidate_DemoModeAck_FutureDatedTS_FailsClosed(t *testing.T) {
	// > 1m future-dated → clock-skew rejection.
	futureEpoch := time.Now().Add(10 * time.Minute).Unix()
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret", DemoModeAck: true, DemoModeAckTS: strconv.FormatInt(futureEpoch, 10)},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil; want ErrDemoModeAckExpired with future-dated TS")
	}
	if !errors.Is(err, ErrDemoModeAckExpired) {
		t.Errorf("Validate() err = %v; want errors.Is to match ErrDemoModeAckExpired", err)
	}
	if !strings.Contains(err.Error(), "future") {
		t.Errorf("Validate() error = %q; want message to mention future-dated TS", err.Error())
	}
}

func TestValidate_DemoModeAckFalse_IgnoresTS(t *testing.T) {
	// DemoModeAck=false → TS is irrelevant; no fail-closed branch.
	cfg := &Config{
		Server:    validServerConfig(t),
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "test-secret", DemoModeAck: false, DemoModeAckTS: ""},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned error with DemoModeAck=false: %v", err)
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "test-secret"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
			JobTimeoutInterval:          10 * time.Minute,
			AwaitingCSRTimeout:          24 * time.Hour,
			AwaitingApprovalTimeout:     168 * time.Hour,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned error for valid config: %v", err)
	}
}

func TestValidate_AuthTypeNone(t *testing.T) {
	srv := validServerConfig(t)
	// Audit 2026-05-10 HIGH-12: Type=none with non-loopback host now
	// fails closed unless DemoModeAck=true. Bind the unit-test config
	// to 127.0.0.1 so the legitimate "demo on loopback" path stays
	// green (the existing test predates the HIGH-12 guard).
	srv.Host = "127.0.0.1"
	cfg := &Config{
		Server:   srv,
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "none", Secret: ""},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
			JobTimeoutInterval:          10 * time.Minute,
			AwaitingCSRTimeout:          24 * time.Hour,
			AwaitingApprovalTimeout:     168 * time.Hour,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned error for auth type 'none' on loopback: %v", err)
	}
}

// Audit 2026-05-10 HIGH-12 closure — pin the demo-mode listen-address
// guard. Pre-fix, an operator who flipped CERTCTL_AUTH_TYPE=none on a
// non-loopback bind exposed admin functions to anyone reachable on
// port 8443 (the synthetic actor `actor-demo-anon` is wired with
// AdminKey=true). Post-fix, Validate() refuses to start unless
// CERTCTL_DEMO_MODE_ACK=true acknowledges the bypass.
func TestValidate_AuthTypeNone_NonLoopback_FailsClosed(t *testing.T) {
	srv := validServerConfig(t)
	srv.Host = "0.0.0.0"
	cfg := &Config{
		Server:    srv,
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "none", Secret: ""},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil; want HIGH-12 demo-mode guard to fail closed on Host=0.0.0.0 with Type=none and DemoModeAck=false")
	}
	if !strings.Contains(err.Error(), "CERTCTL_DEMO_MODE_ACK=true") {
		t.Errorf("Validate() error = %q; want it to mention CERTCTL_DEMO_MODE_ACK=true", err.Error())
	}
}

func TestValidate_AuthTypeNone_NonLoopback_AckPasses(t *testing.T) {
	srv := validServerConfig(t)
	srv.Host = "0.0.0.0"
	cfg := &Config{
		Server:    srv,
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "none", Secret: "", DemoModeAck: true, DemoModeAckTS: strconv.FormatInt(time.Now().Unix(), 10)},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with DemoModeAck=true returned error: %v", err)
	}
}

func TestValidate_AuthTypeAPIKey_NonLoopback_NotAffected(t *testing.T) {
	// Real authn types are unaffected by the HIGH-12 guard — it only
	// fires when Type=none.
	srv := validServerConfig(t)
	srv.Host = "0.0.0.0"
	cfg := &Config{
		Server:    srv,
		Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:       LogConfig{Level: "info", Format: "json"},
		Auth:      AuthConfig{Type: "api-key", Secret: "real-secret"},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with Type=api-key on 0.0.0.0 returned error: %v", err)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// Loopback positives.
		{"127.0.0.1", true},
		{"::1", true},
		{"localhost", true},
		{"127.0.0.5", true}, // any 127.0.0.0/8
		// Non-loopback negatives — the cases the HIGH-12 guard catches.
		{"", false},
		{"0.0.0.0", false},
		{"::", false},
		{"[::]", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"203.0.113.42", false},
		{"example.com", false}, // hostname → fail closed
		{"my-cert-server.internal", false},
		// Defensive: host:port form should still classify the host part.
		{"127.0.0.1:8443", true},
		{"0.0.0.0:8443", false},
	}
	for _, tc := range cases {
		got := isLoopbackAddr(tc.host)
		if got != tc.want {
			t.Errorf("isLoopbackAddr(%q) = %v; want %v", tc.host, got, tc.want)
		}
	}
}

// validSchedulerConfig returns a SchedulerConfig with all required
// fields set so Validate() doesn't fail for unrelated reasons in the
// HIGH-12 test cases. Mirrors the inline initialization in the
// pre-existing TestValidate_* tests.
func validSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{
		RenewalCheckInterval:        1 * time.Hour,
		JobProcessorInterval:        30 * time.Second,
		AgentHealthCheckInterval:    2 * time.Minute,
		NotificationProcessInterval: 1 * time.Minute,
		NotificationRetryInterval:   2 * time.Minute,
		RetryInterval:               5 * time.Minute,
		JobTimeoutInterval:          10 * time.Minute,
		AwaitingCSRTimeout:          24 * time.Hour,
		AwaitingApprovalTimeout:     168 * time.Hour,
	}
}

func TestValidate_InvalidAuthType(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "oauth", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for unsupported auth type 'oauth'")
	}
}

func TestValidate_APIKeyAuth_MissingSecret(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: ""},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error when api-key auth has empty secret")
	}
}

// TestValidate_JWTAuth_RejectedDedicated locks down the G-1 fix: pre-G-1
// `CERTCTL_AUTH_TYPE=jwt` was accepted by the validator (the bare error
// path was the empty-secret one previously). Post-G-1 the literal "jwt"
// value is rejected with a dedicated diagnostic regardless of whether
// Secret is set, because there is no JWT middleware in the binary —
// operators who need JWT/OIDC must front certctl with an authenticating
// gateway.
//
// Two table rows pin the contract: missing-secret cannot paper over the
// rejection (the dedicated error fires first, before the secret check),
// and a populated secret also cannot paper over it. Both paths must
// hit the dedicated G-1 diagnostic, not the generic "invalid auth
// type" or "auth secret is required".
func TestValidate_JWTAuth_RejectedDedicated(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		secret string
	}{
		{"jwt rejected (no secret)", ""},
		{"jwt rejected (with secret — operator can't paper over)", "anything"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Server:   validServerConfig(t),
				Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
				Log:      LogConfig{Level: "info", Format: "json"},
				Auth:     AuthConfig{Type: "jwt", Secret: tc.secret},
				Keygen:   KeygenConfig{Mode: "agent"},
				Scheduler: SchedulerConfig{
					RenewalCheckInterval:        1 * time.Hour,
					JobProcessorInterval:        30 * time.Second,
					AgentHealthCheckInterval:    2 * time.Minute,
					NotificationProcessInterval: 1 * time.Minute,
					NotificationRetryInterval:   2 * time.Minute,
					RetryInterval:               5 * time.Minute,
				},
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() returned nil; expected dedicated G-1 rejection")
			}
			const wantSubstr = "CERTCTL_AUTH_TYPE=jwt is no longer accepted"
			if !strings.Contains(err.Error(), wantSubstr) {
				t.Errorf("Validate() = %v\nwant substring %q (the dedicated G-1 diagnostic)", err, wantSubstr)
			}
		})
	}
}

// TestValidAuthTypesDoesNotContainJWT is a property-level guard against
// a future PR silently re-introducing "jwt" into the allowed set. If
// someone adds JWT back to ValidAuthTypes(), this test fails immediately
// with a pointer at the audit finding. The matching CI grep guardrail
// in .github/workflows/ci.yml provides a secondary check at build time.
func TestValidAuthTypesDoesNotContainJWT(t *testing.T) {
	t.Parallel()
	for _, at := range ValidAuthTypes() {
		if at == "jwt" {
			t.Fatalf("jwt is in ValidAuthTypes — silent auth downgrade regressed (G-1)")
		}
	}
}

// TestValidAuthTypesIsExactly_APIKey_None_OIDC pins the current allowed
// set. If a future change adds a new auth type, this test must be
// updated alongside the validator and the helm-chart `validateAuthType`
// helper — keeping all three surfaces in sync.
//
// Bundle 2 Phase 0: extended from {api-key, none} to {api-key, none,
// oidc}. The G-1 closure test (TestValidAuthTypesDoesNotContainJWT)
// stays passing because "jwt" is never added back. ID tokens are JWTs
// internally but the auth-type literal is "oidc", so the silent
// auth-downgrade that drove G-1 cannot regress through this addition.
func TestValidAuthTypesIsExactly_APIKey_None_OIDC(t *testing.T) {
	t.Parallel()
	got := ValidAuthTypes()
	if len(got) != 3 {
		t.Fatalf("ValidAuthTypes() returned %d entries, want 3: %v", len(got), got)
	}
	want := map[AuthType]bool{AuthTypeAPIKey: true, AuthTypeNone: true, AuthTypeOIDC: true}
	for _, at := range got {
		if !want[at] {
			t.Errorf("unexpected auth type in ValidAuthTypes: %q", at)
		}
	}
}

// TestValidate_GenericInvalidAuthType ensures that values outside the
// allowed set (other than the special-cased "jwt") still surface the
// generic "invalid auth type" error. Pins that the dedicated G-1
// rejection didn't accidentally swallow non-jwt typos.
func TestValidate_GenericInvalidAuthType(t *testing.T) {
	t.Parallel()
	for _, badType := range []string{"", "garbage", "saml", "mtls", "API-KEY"} {
		t.Run("type="+badType, func(t *testing.T) {
			cfg := &Config{
				Server:   validServerConfig(t),
				Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
				Log:      LogConfig{Level: "info", Format: "json"},
				Auth:     AuthConfig{Type: badType, Secret: "x"},
				Keygen:   KeygenConfig{Mode: "agent"},
				Scheduler: SchedulerConfig{
					RenewalCheckInterval:        1 * time.Hour,
					JobProcessorInterval:        30 * time.Second,
					AgentHealthCheckInterval:    2 * time.Minute,
					NotificationProcessInterval: 1 * time.Minute,
					NotificationRetryInterval:   2 * time.Minute,
					RetryInterval:               5 * time.Minute,
				},
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate(type=%q) returned nil; expected invalid-auth-type rejection", badType)
			}
			if !strings.Contains(err.Error(), "invalid auth type") {
				t.Errorf("Validate(type=%q) = %v; want \"invalid auth type\" error", badType, err)
			}
			if strings.Contains(err.Error(), "G-1 silent auth") {
				t.Errorf("Validate(type=%q) = %v; should not hit the dedicated G-1 path for non-jwt values", badType, err)
			}
		})
	}
}

// G-1 (P1): no need to add `TestValidate_NoneAuth_AcceptsEmptySecret` or
// `TestValidate_APIKeyAuth_RequiresSecret` here — the pre-existing tests
// `TestValidate_AuthTypeNone` (above) and `TestValidate_APIKeyAuth_MissingSecret`
// (above) already cover those paths. Documented for the next reader: the
// G-1 fix flipped jwt off but did not disturb either the
// none-bypasses-secret or the api-key-requires-secret behavior.

func TestValidate_InvalidKeygenMode(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "hybrid"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for unsupported keygen mode 'hybrid'")
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"zero", 0},
		{"negative", -1},
		{"too high", 65536},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Server:   ServerConfig{Port: tt.port},
				Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
				Log:      LogConfig{Level: "info", Format: "json"},
				Auth:     AuthConfig{Type: "api-key", Secret: "key"},
				Keygen:   KeygenConfig{Mode: "agent"},
				Scheduler: SchedulerConfig{
					RenewalCheckInterval:        1 * time.Hour,
					JobProcessorInterval:        30 * time.Second,
					AgentHealthCheckInterval:    2 * time.Minute,
					NotificationProcessInterval: 1 * time.Minute,
					NotificationRetryInterval:   2 * time.Minute,
					RetryInterval:               5 * time.Minute,
				},
			}
			if err := cfg.Validate(); err == nil {
				t.Errorf("Validate() should return error for port %d", tt.port)
			}
		})
	}
}

// TestValidate_TLSCertPathEmpty pins the first of the HTTPS-only fail-loud
// gates in Validate(): an empty CertPath must produce the operator-facing
// "server TLS cert path is required" error. Per §2.1 + §3 locked decisions,
// there is no plaintext HTTP fallback — missing TLS config is a hard startup
// refusal, not a warning.
func TestValidate_TLSCertPathEmpty(t *testing.T) {
	_, keyPath := generateTestTLSPair(t)
	cfg := &Config{
		Server: ServerConfig{
			Port: 8080,
			TLS:  ServerTLSConfig{CertPath: "", KeyPath: keyPath},
		},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for empty TLS cert path")
	}
	if !strings.Contains(err.Error(), "server TLS cert path is required") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server TLS cert path is required")
	}
}

// TestValidate_TLSKeyPathEmpty pins the second HTTPS-only gate: empty KeyPath
// must produce the "server TLS key path is required" error. Runs with a valid
// CertPath so the cert-empty gate (which fires first) is cleanly bypassed —
// proves the key-empty gate is actually reached.
func TestValidate_TLSKeyPathEmpty(t *testing.T) {
	certPath, _ := generateTestTLSPair(t)
	cfg := &Config{
		Server: ServerConfig{
			Port: 8080,
			TLS:  ServerTLSConfig{CertPath: certPath, KeyPath: ""},
		},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for empty TLS key path")
	}
	if !strings.Contains(err.Error(), "server TLS key path is required") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server TLS key path is required")
	}
}

// TestValidate_TLSCertFileMissing pins the os.Stat gate on the cert path. A
// non-existent path must surface "server TLS cert file unreadable" so the
// operator sees the bad path in the error (file=%q) instead of a deferred
// ListenAndServeTLS panic after the scheduler has already fanned out.
func TestValidate_TLSCertFileMissing(t *testing.T) {
	_, keyPath := generateTestTLSPair(t)
	missingCert := filepath.Join(t.TempDir(), "does-not-exist.pem")
	cfg := &Config{
		Server: ServerConfig{
			Port: 8080,
			TLS:  ServerTLSConfig{CertPath: missingCert, KeyPath: keyPath},
		},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for missing TLS cert file")
	}
	if !strings.Contains(err.Error(), "server TLS cert file unreadable") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server TLS cert file unreadable")
	}
}

// TestValidate_TLSKeyFileMissing pins the os.Stat gate on the key path. Uses a
// valid CertPath so the cert-missing gate does not pre-empt; proves the key
// gate is reached and reports the bad key path.
func TestValidate_TLSKeyFileMissing(t *testing.T) {
	certPath, _ := generateTestTLSPair(t)
	missingKey := filepath.Join(t.TempDir(), "does-not-exist.key")
	cfg := &Config{
		Server: ServerConfig{
			Port: 8080,
			TLS:  ServerTLSConfig{CertPath: certPath, KeyPath: missingKey},
		},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for missing TLS key file")
	}
	if !strings.Contains(err.Error(), "server TLS key file unreadable") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server TLS key file unreadable")
	}
}

// TestValidate_TLSMismatchedPair pins the tls.LoadX509KeyPair gate — the
// classic "you shipped the wrong private key" footgun. Generates two
// independent ECDSA pairs and crosses them (pair1 cert + pair2 key). Both
// files exist and parse as PEM, so os.Stat passes; only the cryptographic
// round-trip inside LoadX509KeyPair catches the mismatch.
func TestValidate_TLSMismatchedPair(t *testing.T) {
	certPath1, _ := generateTestTLSPair(t)
	_, keyPath2 := generateTestTLSPair(t)
	cfg := &Config{
		Server: ServerConfig{
			Port: 8080,
			TLS:  ServerTLSConfig{CertPath: certPath1, KeyPath: keyPath2},
		},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for mismatched TLS cert/key pair")
	}
	if !strings.Contains(err.Error(), "server TLS cert/key pair invalid") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server TLS cert/key pair invalid")
	}
}

func TestValidate_EmptyDatabaseURL(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for empty database URL")
	}
}

func TestValidate_InvalidLogLevel(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "verbose", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for invalid log level 'verbose'")
	}
}

func TestValidate_InvalidLogFormat(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "yaml"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for invalid log format 'yaml'")
	}
}

func TestValidate_SchedulerIntervalTooSmall(t *testing.T) {
	tests := []struct {
		name string
		cfg  SchedulerConfig
	}{
		{
			"renewal interval below 1 minute",
			SchedulerConfig{
				RenewalCheckInterval:        30 * time.Second,
				JobProcessorInterval:        30 * time.Second,
				AgentHealthCheckInterval:    2 * time.Minute,
				NotificationProcessInterval: 1 * time.Minute,
			},
		},
		{
			"job processor below 1 second",
			SchedulerConfig{
				RenewalCheckInterval:        1 * time.Hour,
				JobProcessorInterval:        500 * time.Millisecond,
				AgentHealthCheckInterval:    2 * time.Minute,
				NotificationProcessInterval: 1 * time.Minute,
			},
		},
		{
			"agent health below 1 second",
			SchedulerConfig{
				RenewalCheckInterval:        1 * time.Hour,
				JobProcessorInterval:        30 * time.Second,
				AgentHealthCheckInterval:    500 * time.Millisecond,
				NotificationProcessInterval: 1 * time.Minute,
			},
		},
		{
			"notification below 1 second",
			SchedulerConfig{
				RenewalCheckInterval:        1 * time.Hour,
				JobProcessorInterval:        30 * time.Second,
				AgentHealthCheckInterval:    2 * time.Minute,
				NotificationProcessInterval: 500 * time.Millisecond,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Server:    validServerConfig(t),
				Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
				Log:       LogConfig{Level: "info", Format: "json"},
				Auth:      AuthConfig{Type: "api-key", Secret: "key"},
				Keygen:    KeygenConfig{Mode: "agent"},
				Scheduler: tt.cfg,
			}
			if err := cfg.Validate(); err == nil {
				t.Errorf("Validate() should return error for %s", tt.name)
			}
		})
	}
}

func TestValidate_DatabaseMaxConnectionsZero(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 0},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for max_connections=0")
	}
}

func TestGetLogLevel_AllLevels(t *testing.T) {
	tests := []struct {
		level    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo}, // default fallback
		{"", slog.LevelInfo},        // empty string
		{"DEBUG", slog.LevelInfo},   // case-sensitive, no match → default
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			cfg := &Config{Log: LogConfig{Level: tt.level}}
			got := cfg.GetLogLevel()
			if got != tt.expected {
				t.Errorf("GetLogLevel() for %q = %v, want %v", tt.level, got, tt.expected)
			}
		})
	}
}

// Test helper functions
func TestSplitComma(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"single", []string{"single"}},
		{"", []string{""}},
		{",", []string{"", ""}},
		{"a,,c", []string{"a", "", "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitComma(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("splitComma(%q) returned %d items, want %d", tt.input, len(got), len(tt.expected))
			}
			for i, v := range got {
				if v != tt.expected[i] {
					t.Errorf("splitComma(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  hello  ", "hello"},
		{"hello", "hello"},
		{"\thello\t", "hello"},
		{"  ", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := trimSpace(tt.input)
			if got != tt.expected {
				t.Errorf("trimSpace(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestGetEnvFloat(t *testing.T) {
	t.Setenv("TEST_FLOAT", "3.14")
	got := getEnvFloat("TEST_FLOAT", 0)
	if got != 3.14 {
		t.Errorf("getEnvFloat = %f, want 3.14", got)
	}

	// Invalid float falls back to default
	t.Setenv("TEST_FLOAT_BAD", "notafloat")
	got = getEnvFloat("TEST_FLOAT_BAD", 99.9)
	if got != 99.9 {
		t.Errorf("getEnvFloat for invalid = %f, want 99.9", got)
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"true", true},
		{"1", true},
		{"yes", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"anything", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv("TEST_BOOL", tt.value)
			got := getEnvBool("TEST_BOOL", false)
			if got != tt.expected {
				t.Errorf("getEnvBool(%q) = %v, want %v", tt.value, got, tt.expected)
			}
		})
	}
}

// I-003: Job timeout reaper configuration tests
func TestConfig_Scheduler_JobTimeoutDefaults(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	// Explicitly unset the three I-003 env vars to exercise the default path.
	t.Setenv("CERTCTL_JOB_TIMEOUT_INTERVAL", "")
	t.Setenv("CERTCTL_JOB_AWAITING_CSR_TIMEOUT", "")
	t.Setenv("CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Scheduler.JobTimeoutInterval != 10*time.Minute {
		t.Errorf("JobTimeoutInterval = %v, want 10m", cfg.Scheduler.JobTimeoutInterval)
	}
	if cfg.Scheduler.AwaitingCSRTimeout != 24*time.Hour {
		t.Errorf("AwaitingCSRTimeout = %v, want 24h", cfg.Scheduler.AwaitingCSRTimeout)
	}
	if cfg.Scheduler.AwaitingApprovalTimeout != 168*time.Hour {
		t.Errorf("AwaitingApprovalTimeout = %v, want 168h", cfg.Scheduler.AwaitingApprovalTimeout)
	}
}

func TestConfig_Scheduler_JobTimeoutEnvOverride(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	t.Setenv("CERTCTL_JOB_TIMEOUT_INTERVAL", "15m")
	t.Setenv("CERTCTL_JOB_AWAITING_CSR_TIMEOUT", "48h")
	t.Setenv("CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT", "336h")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Scheduler.JobTimeoutInterval != 15*time.Minute {
		t.Errorf("JobTimeoutInterval = %v, want 15m", cfg.Scheduler.JobTimeoutInterval)
	}
	if cfg.Scheduler.AwaitingCSRTimeout != 48*time.Hour {
		t.Errorf("AwaitingCSRTimeout = %v, want 48h", cfg.Scheduler.AwaitingCSRTimeout)
	}
	if cfg.Scheduler.AwaitingApprovalTimeout != 336*time.Hour {
		t.Errorf("AwaitingApprovalTimeout = %v, want 336h", cfg.Scheduler.AwaitingApprovalTimeout)
	}
}

func TestConfig_Scheduler_JobTimeoutValidation(t *testing.T) {
	tests := []struct {
		name       string
		field      string
		value      time.Duration
		wantErrMsg string
	}{
		{
			"JobTimeoutInterval too small",
			"JobTimeoutInterval",
			500 * time.Millisecond,
			"job timeout interval must be at least 1 second",
		},
		{
			"AwaitingCSRTimeout too small",
			"AwaitingCSRTimeout",
			500 * time.Millisecond,
			"awaiting CSR timeout must be at least 1 second",
		},
		{
			"AwaitingApprovalTimeout too small",
			"AwaitingApprovalTimeout",
			500 * time.Millisecond,
			"awaiting approval timeout must be at least 1 second",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start from a fully valid config so the I-003 timeout checks
			// are the only potential failure point.
			cfg := &Config{
				Server:   validServerConfig(t),
				Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
				Log:      LogConfig{Level: "info", Format: "json"},
				Auth:     AuthConfig{Type: "api-key", Secret: "test-secret"},
				Keygen:   KeygenConfig{Mode: "agent"},
				Scheduler: SchedulerConfig{
					RenewalCheckInterval:        1 * time.Minute,
					JobProcessorInterval:        1 * time.Minute,
					AgentHealthCheckInterval:    1 * time.Minute,
					NotificationProcessInterval: 1 * time.Minute,
					NotificationRetryInterval:   2 * time.Minute,
					RetryInterval:               1 * time.Minute,
					JobTimeoutInterval:          10 * time.Minute,
					AwaitingCSRTimeout:          24 * time.Hour,
					AwaitingApprovalTimeout:     168 * time.Hour,
				},
			}

			// Override the specific field under test
			switch tt.field {
			case "JobTimeoutInterval":
				cfg.Scheduler.JobTimeoutInterval = tt.value
			case "AwaitingCSRTimeout":
				cfg.Scheduler.AwaitingCSRTimeout = tt.value
			case "AwaitingApprovalTimeout":
				cfg.Scheduler.AwaitingApprovalTimeout = tt.value
			}

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErrMsg)
			}
			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}

// H-1 closure (cat-r-encryption_key_no_length_validation): validate
// CERTCTL_CONFIG_ENCRYPTION_KEY length. Pre-H-1 the field was accepted
// with any non-empty value (including a single character); post-H-1 a
// minimum 32-byte length is enforced. Empty stays accepted because the
// downstream fail-closed sentinel crypto.ErrEncryptionKeyRequired
// handles the missing-key case for the encrypt/decrypt paths.

func validBaseConfigForEncryption(t *testing.T) *Config {
	t.Helper()
	return &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "test-secret"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
			JobTimeoutInterval:          10 * time.Minute,
			AwaitingCSRTimeout:          24 * time.Hour,
			AwaitingApprovalTimeout:     168 * time.Hour,
		},
	}
}

func TestValidate_EncryptionKey_EmptyAccepted(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	cfg.Encryption.ConfigEncryptionKey = ""
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned error for empty key: %v (empty must be accepted; fail-closed sentinel handles it downstream)", err)
	}
}

func TestValidate_EncryptionKey_TooShortRejected(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	cfg.Encryption.ConfigEncryptionKey = "x" // 1 byte
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for 1-byte key")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("Validate() error = %q, want to contain %q", err.Error(), "too short")
	}
	if !strings.Contains(err.Error(), "openssl rand -base64 32") {
		t.Errorf("Validate() error = %q, must include the canonical generation command", err.Error())
	}
}

func TestValidate_EncryptionKey_BoundaryRejected(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	cfg.Encryption.ConfigEncryptionKey = "12345678901234567890123456789012"[:31] // 31 bytes — one short
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for 31-byte key (boundary -1)")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("Validate() error = %q, want 'too short'", err.Error())
	}
}

func TestValidate_EncryptionKey_MinLengthAccepted(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	cfg.Encryption.ConfigEncryptionKey = "12345678901234567890123456789012" // exactly 32 bytes
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned error for 32-byte key: %v", err)
	}
}

func TestValidate_EncryptionKey_LongAccepted(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	// Realistic operator key from `openssl rand -base64 32` — 44 characters.
	cfg.Encryption.ConfigEncryptionKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned error for 44-byte key: %v", err)
	}
}

// SCEP RFC 8894 Phase 1: Validate() must refuse to start when SCEP is enabled
// without an RA cert + key pair, mirroring the existing CHALLENGE_PASSWORD
// gate. Defense-in-depth with cmd/server/main.go::preflightSCEPRACertKey
// which additionally validates file mode + cert/key match + expiry + alg.
func TestValidate_SCEPEnabled_MissingRAPair_Refuses(t *testing.T) {
	cases := []struct {
		name       string
		raCertPath string
		raKeyPath  string
	}{
		{"both_empty", "", ""},
		{"cert_only", "/etc/certctl/scep/ra.crt", ""},
		{"key_only", "", "/etc/certctl/scep/ra.key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Server:   validServerConfig(t),
				Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
				Log:      LogConfig{Level: "info", Format: "json"},
				Auth:     AuthConfig{Type: "api-key", Secret: "test-secret"},
				Keygen:   KeygenConfig{Mode: "agent"},
				Scheduler: SchedulerConfig{
					RenewalCheckInterval:        1 * time.Hour,
					JobProcessorInterval:        30 * time.Second,
					AgentHealthCheckInterval:    2 * time.Minute,
					NotificationProcessInterval: 1 * time.Minute,
					NotificationRetryInterval:   2 * time.Minute,
					RetryInterval:               5 * time.Minute,
					JobTimeoutInterval:          10 * time.Minute,
					AwaitingCSRTimeout:          24 * time.Hour,
					AwaitingApprovalTimeout:     168 * time.Hour,
				},
				SCEP: SCEPConfig{
					Enabled:           true,
					ChallengePassword: "shared-secret-not-empty",
					RACertPath:        tc.raCertPath,
					RAKeyPath:         tc.raKeyPath,
				},
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error for SCEP enabled with missing RA pair")
			}
			if !strings.Contains(err.Error(), "RA cert/key path missing") {
				t.Errorf("Validate() error = %q, want 'RA cert/key path missing'", err.Error())
			}
		})
	}
}

// SCEP enabled with a complete RA pair (and a non-empty challenge password)
// should pass Validate — the file-existence + mode + match checks live in
// preflightSCEPRACertKey, not in Validate. This pins the boundary so a
// future "validate the file too" refactor doesn't accidentally double up.
func TestValidate_SCEPEnabled_CompleteRAPair_Accepts(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "test-secret"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
			JobTimeoutInterval:          10 * time.Minute,
			AwaitingCSRTimeout:          24 * time.Hour,
			AwaitingApprovalTimeout:     168 * time.Hour,
		},
		SCEP: SCEPConfig{
			Enabled:           true,
			ChallengePassword: "shared-secret-not-empty",
			RACertPath:        "/etc/certctl/scep/ra.crt",
			RAKeyPath:         "/etc/certctl/scep/ra.key",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for complete RA pair (file-existence checked in preflightSCEPRACertKey)", err)
	}
}

// SCEP disabled with empty RA pair fields must NOT trip the gate — the
// fields only matter when SCEP is enabled. Mirrors the CHALLENGE_PASSWORD
// disabled-passes precedent in TestValidate_ValidConfig.
func TestValidate_SCEPDisabled_EmptyRAPair_Accepts(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "test-secret"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
			JobTimeoutInterval:          10 * time.Minute,
			AwaitingCSRTimeout:          24 * time.Hour,
			AwaitingApprovalTimeout:     168 * time.Hour,
		},
		SCEP: SCEPConfig{Enabled: false}, // RACertPath / RAKeyPath stay empty
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for SCEP disabled with empty RA pair", err)
	}
}

// Bundle 2 closure (2026-05-12) — fail-closed startup guards against
// placeholder credentials shipped by the demo overlay
// (deploy/docker-compose.demo.yml). The literal strings below MUST stay
// in sync with the sentinels in internal/config/config.go::Validate; the
// demo overlay also writes these exact values into its env block, so any
// drift between the three locations would silently break the closure.

// TestValidate_Bundle2_PlaceholderAuthSecret_Refused pins the contract
// that the placeholder string "change-me-in-production" in
// CERTCTL_AUTH_SECRET hard-fails Validate() outside demo mode.
func TestValidate_Bundle2_PlaceholderAuthSecret_Refused(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	cfg.Auth.Type = "api-key"
	cfg.Auth.Secret = "change-me-in-production"
	cfg.Auth.DemoModeAck = false

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil; expected refusal on placeholder CERTCTL_AUTH_SECRET")
	}
	for _, want := range []string{"CERTCTL_AUTH_SECRET", "change-me-in-production", "openssl rand"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate() error = %q; missing operator guidance substring %q", err, want)
		}
	}
}

// TestValidate_Bundle2_PlaceholderAuthSecret_DemoAckExempt pins that
// the demo overlay (which sets the placeholder + DemoModeAck=true) is
// exempt — without this exemption the demo path would fail to boot.
func TestValidate_Bundle2_PlaceholderAuthSecret_DemoAckExempt(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	// Demo overlay sets AUTH_TYPE=none (so the placeholder doesn't even
	// hit the api-key branch), but cover the api-key + ack edge case too
	// in case an operator manually flips the demo overlay's AUTH_TYPE.
	cfg.Auth.Type = "api-key"
	cfg.Auth.Secret = "change-me-in-production"
	cfg.Auth.DemoModeAck = true
	cfg.Auth.DemoModeAckTS = strconv.FormatInt(time.Now().Unix(), 10)

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned %v with DemoModeAck=true; demo path must accept placeholder secret", err)
	}
}

// TestValidate_Bundle2_PlaceholderEncryptionKey_Refused pins the
// contract that "change-me-32-char-encryption-key" hard-fails Validate()
// outside demo mode. Note: this string is exactly 32 bytes, so it
// passes the H-1 length floor; the only thing catching it is the
// Bundle 2 value-equality guard.
func TestValidate_Bundle2_PlaceholderEncryptionKey_Refused(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	cfg.Encryption.ConfigEncryptionKey = "change-me-32-char-encryption-key"
	cfg.Auth.DemoModeAck = false

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil; expected refusal on placeholder CERTCTL_CONFIG_ENCRYPTION_KEY")
	}
	for _, want := range []string{"CERTCTL_CONFIG_ENCRYPTION_KEY", "change-me-32-char-encryption-key", "openssl rand"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate() error = %q; missing operator guidance substring %q", err, want)
		}
	}
}

// TestValidate_Bundle2_PlaceholderEncryptionKey_DemoAckExempt covers
// the demo overlay's posture (placeholder + DemoModeAck=true).
func TestValidate_Bundle2_PlaceholderEncryptionKey_DemoAckExempt(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	cfg.Encryption.ConfigEncryptionKey = "change-me-32-char-encryption-key"
	cfg.Auth.DemoModeAck = true
	cfg.Auth.DemoModeAckTS = strconv.FormatInt(time.Now().Unix(), 10)

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned %v with DemoModeAck=true; demo path must accept placeholder encryption key", err)
	}
}

// TestValidate_Bundle2_RealEncryptionKey_NotMistakenForPlaceholder
// pins that a real `openssl rand -base64 32` output sails through.
// Defense against an over-broad match (e.g. accidentally rejecting any
// key starting with "change-me-").
func TestValidate_Bundle2_RealEncryptionKey_NotMistakenForPlaceholder(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	// 44-char base64 sample — same shape `openssl rand -base64 32` produces.
	cfg.Encryption.ConfigEncryptionKey = "Tc1hZ4n3Ph5gC8e2zR0qV6jX9mYwL1pK4wB7uE3nQ5o="
	cfg.Auth.DemoModeAck = false

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned %v; want nil for realistic operator key", err)
	}
}

// TestValidate_Bundle2_CORSWildcard_Refused pins the LOW-5 closure:
// CERTCTL_CORS_ORIGINS containing "*" hard-fails Validate() outside
// demo mode. Wildcard CORS + session cookies = CWE-942 + CWE-352.
func TestValidate_Bundle2_CORSWildcard_Refused(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	cfg.CORS.AllowedOrigins = []string{"*"}
	cfg.Auth.DemoModeAck = false

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil; expected refusal on wildcard CORS")
	}
	for _, want := range []string{"CERTCTL_CORS_ORIGINS", "wildcard", "CSRF"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate() error = %q; missing operator guidance substring %q", err, want)
		}
	}
}

// TestValidate_Bundle2_CORSWildcard_DemoAckExempt covers the demo
// posture (operators frequently want unrestricted CORS for dashboard
// screencaps + curl-from-any-origin diagnostics).
func TestValidate_Bundle2_CORSWildcard_DemoAckExempt(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	cfg.CORS.AllowedOrigins = []string{"*"}
	cfg.Auth.DemoModeAck = true
	cfg.Auth.DemoModeAckTS = strconv.FormatInt(time.Now().Unix(), 10)

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned %v with DemoModeAck=true; demo path must accept wildcard CORS", err)
	}
}

// TestValidate_Bundle2_CORSWildcard_MixedAllowlistStillRefused pins
// that "*" mixed into an otherwise-concrete allowlist still trips the
// guard. The wildcard short-circuits the entire allowlist in
// middleware.NewCORS, so leaving "*" alongside legit origins is just
// as dangerous as "*" alone.
func TestValidate_Bundle2_CORSWildcard_MixedAllowlistStillRefused(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	cfg.CORS.AllowedOrigins = []string{"https://dashboard.example.com", "*", "https://other.example.com"}
	cfg.Auth.DemoModeAck = false

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil; expected refusal on wildcard mixed into allowlist")
	}
	if !strings.Contains(err.Error(), "wildcard") {
		t.Errorf("Validate() error = %q; want wildcard mention", err)
	}
}

// TestValidate_Bundle2_CORSConcreteAllowlist_Accepted pins that a real
// operator allowlist sails through (no false-positive on substring match
// or similar over-broad matching).
func TestValidate_Bundle2_CORSConcreteAllowlist_Accepted(t *testing.T) {
	cfg := validBaseConfigForEncryption(t)
	cfg.CORS.AllowedOrigins = []string{"https://dashboard.example.com", "https://admin.example.com"}
	cfg.Auth.DemoModeAck = false

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned %v; want nil for concrete CORS allowlist", err)
	}
}

// =============================================================================
// DEPL-004 closure (Sprint 3, 2026-05-16). The Helm chart renders the
// bundled-Postgres URL with a literal "$(POSTGRES_PASSWORD)"
// placeholder. Kubernetes does NOT expand `$(VAR)` syntax when the env
// is sourced from a Secret (valueFrom.secretKeyRef), so the server
// receives the placeholder verbatim. expandDatabaseURL substitutes the
// token with os.Getenv("POSTGRES_PASSWORD") at Load() time.
// =============================================================================

func TestExpandDatabaseURL_SubstitutesPlaceholder(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "s3cret!")
	in := "postgres://certctl:$(POSTGRES_PASSWORD)@db:5432/certctl?sslmode=disable"
	got := expandDatabaseURL(in)
	want := "postgres://certctl:s3cret!@db:5432/certctl?sslmode=disable"
	if got != want {
		t.Errorf("expandDatabaseURL = %q; want %q", got, want)
	}
}

func TestExpandDatabaseURL_NoPlaceholderPassesThrough(t *testing.T) {
	// External-Postgres deploys bake the password into the URL string
	// — the helper must not touch URLs that don't carry the placeholder.
	t.Setenv("POSTGRES_PASSWORD", "ignored")
	in := "postgres://user:realpw@external:5432/db?sslmode=require"
	if got := expandDatabaseURL(in); got != in {
		t.Errorf("expandDatabaseURL on non-placeholder URL = %q; want %q (no-op)", got, in)
	}
}

func TestExpandDatabaseURL_PlaceholderButNoEnvLeftAlone(t *testing.T) {
	// When POSTGRES_PASSWORD is unset, leave the URL alone so the
	// downstream connection failure is the same as before (misconfig
	// is the operator's, not our regression).
	t.Setenv("POSTGRES_PASSWORD", "")
	in := "postgres://certctl:$(POSTGRES_PASSWORD)@db:5432/certctl?sslmode=disable"
	if got := expandDatabaseURL(in); got != in {
		t.Errorf("expandDatabaseURL with no POSTGRES_PASSWORD = %q; want unchanged %q", got, in)
	}
}

func TestExpandDatabaseURL_MultipleOccurrences(t *testing.T) {
	// Defensive: belt-and-suspenders. The chart only emits one
	// placeholder today but ReplaceAll guards against future drift.
	t.Setenv("POSTGRES_PASSWORD", "X")
	in := "$(POSTGRES_PASSWORD)/$(POSTGRES_PASSWORD)"
	want := "X/X"
	if got := expandDatabaseURL(in); got != want {
		t.Errorf("expandDatabaseURL = %q; want %q", got, want)
	}
}

// =============================================================================
// ARCH-002 closure (Sprint 4, 2026-05-16). Auth Bundle 2 Phase 6
// shipped the OIDC session middleware + handler chain in code, but
// cmd/server/main.go retained a Phase-0 runtime guard that exited
// the process when CERTCTL_AUTH_TYPE=oidc. The guard was supposed
// to relax once the prerequisites landed; it didn't, and the
// README's "Sign in with OIDC SSO" claim was effectively a lie
// because the server refused to start with auth=oidc.
//
// Post-fix the runtime gate is centralised at
// config.IsRuntimeSupportedAuthType and accepts every entry in
// ValidAuthTypes(). These tests pin the new invariant — the
// runtime support set MUST equal the validator's allowed set.
// A future regression that flips back to "OIDC not supported"
// surfaces here.
// =============================================================================

func TestIsRuntimeSupportedAuthType_AcceptsAllValidEntries(t *testing.T) {
	t.Parallel()
	for _, at := range ValidAuthTypes() {
		if !IsRuntimeSupportedAuthType(at) {
			t.Errorf("IsRuntimeSupportedAuthType(%q) = false; want true (every valid auth type must be runtime-supported)", at)
		}
	}
}

func TestIsRuntimeSupportedAuthType_AcceptsOIDC(t *testing.T) {
	// Explicit ARCH-002 invariant — OIDC must boot cleanly.
	t.Parallel()
	if !IsRuntimeSupportedAuthType(AuthTypeOIDC) {
		t.Fatalf("IsRuntimeSupportedAuthType(oidc) = false; the Bundle-2 stale runtime guard regressed (ARCH-002)")
	}
}

func TestIsRuntimeSupportedAuthType_RejectsUnknown(t *testing.T) {
	t.Parallel()
	for _, bad := range []AuthType{"", "jwt", "saml", "mtls", "API-KEY"} {
		if IsRuntimeSupportedAuthType(bad) {
			t.Errorf("IsRuntimeSupportedAuthType(%q) = true; want false (unknown auth types must be rejected)", bad)
		}
	}
}

// =============================================================================
// ARCH-003 closure (Sprint 4, 2026-05-16). README claimed "private
// keys stay on your infrastructure" / "never touch the control plane"
// as a blanket promise. CERTCTL_KEYGEN_MODE=server breaks both — keys
// are minted in the server process and shipped to the renewal job.
// Pre-fix the server printed a boot WARN and started anyway, so the
// blanket claim was silently false in any deploy that flipped the flag
// without reading logs.
//
// Post-fix Validate() refuses to accept Mode=server unless
// CERTCTL_DEMO_MODE_ACK=true is also set (mirroring the SEC-H3
// 24-hour ACK pattern). Production deploys must use Mode=agent.
// =============================================================================

func TestValidate_RejectsServerKeygenWithoutDemoAck(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "x", DemoModeAck: false},
		Keygen:   KeygenConfig{Mode: "server"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate(KeygenMode=server, DemoAck=false) returned nil; want fail-closed rejection")
	}
	if !strings.Contains(err.Error(), "CERTCTL_KEYGEN_MODE=server") {
		t.Errorf("Validate err = %v; want error citing CERTCTL_KEYGEN_MODE=server", err)
	}
}

func TestValidate_AcceptsServerKeygenWithDemoAck(t *testing.T) {
	t.Parallel()
	// Operators who explicitly acknowledge the demo posture get to boot
	// in server-keygen mode. Same pattern SEC-H3 uses for AUTH_TYPE=none.
	tsRecent := strconv.FormatInt(time.Now().Unix(), 10)
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth: AuthConfig{
			Type:          "api-key",
			Secret:        "x",
			DemoModeAck:   true,
			DemoModeAckTS: tsRecent,
		},
		Keygen: KeygenConfig{Mode: "server"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
			JobTimeoutInterval:          10 * time.Minute,
			AwaitingCSRTimeout:          24 * time.Hour,
			AwaitingApprovalTimeout:     168 * time.Hour,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate(KeygenMode=server, DemoAck=true, fresh TS) = %v; want nil", err)
	}
}

func TestValidate_AgentKeygenIgnoresDemoAck(t *testing.T) {
	t.Parallel()
	// The new gate must NOT regress production deploys — agent mode
	// (the default) boots cleanly without any demo ACK.
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "x", DemoModeAck: false},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
			JobTimeoutInterval:          10 * time.Minute,
			AwaitingCSRTimeout:          24 * time.Hour,
			AwaitingApprovalTimeout:     168 * time.Hour,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate(KeygenMode=agent, DemoAck=false) = %v; want nil (production default must boot)", err)
	}
}

// newBufferLogger returns a slog.Logger that writes JSON records into the
// returned buffer, suitable for asserting WARN emission from
// warnExternalSslmodeDisable. SEC-013 closure (Sprint 2 ACQ).
func newBufferLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), &buf
}

// TestWarnExternalSslmodeDisable_FiresOnExternalHost asserts an external
// host (e.g. RDS) + sslmode=disable produces a WARN. SEC-013 closure
// (Sprint 2 ACQ, 2026-05-16). The advisory exists to surface the
// real-world landmine: an operator who points CERTCTL_DATABASE_URL at a
// managed-Postgres host outside the bridge network without flipping
// sslmode to verify-full.
func TestWarnExternalSslmodeDisable_FiresOnExternalHost(t *testing.T) {
	t.Parallel()
	logger, buf := newBufferLogger()
	warnExternalSslmodeDisable("postgres://certctl:secret@db.internal.example.com:5432/certctl?sslmode=disable", logger)

	out := buf.String()
	if !strings.Contains(out, `"level":"WARN"`) {
		t.Fatalf("expected a WARN record, got: %s", out)
	}
	if !strings.Contains(out, "db.internal.example.com") {
		t.Errorf("WARN should include the external host in structured fields; got: %s", out)
	}
	if !strings.Contains(out, "sslmode") {
		t.Errorf("WARN should include the sslmode structured field; got: %s", out)
	}
}

// TestWarnExternalSslmodeDisable_QuietForLocalSafelist asserts the
// loopback + in-cluster service-name conventions stay silent. These are
// the legitimate sslmode=disable callers — compose bridge network
// (`postgres` / `certctl-postgres`), localhost dev loops, and K8s
// in-cluster service names (`*.svc.cluster.local`). SEC-013 closure.
func TestWarnExternalSslmodeDisable_QuietForLocalSafelist(t *testing.T) {
	t.Parallel()
	silentHosts := []string{
		"postgres://certctl@localhost:5432/certctl?sslmode=disable",
		"postgres://certctl@127.0.0.1:5432/certctl?sslmode=disable",
		"postgres://certctl@[::1]:5432/certctl?sslmode=disable",
		"postgres://certctl@postgres:5432/certctl?sslmode=disable",
		"postgres://certctl@certctl-postgres:5432/certctl?sslmode=disable",
		"postgres://certctl@certctl-postgres.certctl.svc.cluster.local:5432/certctl?sslmode=disable",
	}
	for _, url := range silentHosts {
		url := url
		t.Run(url, func(t *testing.T) {
			t.Parallel()
			logger, buf := newBufferLogger()
			warnExternalSslmodeDisable(url, logger)
			if buf.Len() != 0 {
				t.Errorf("expected silence for safelisted host (%s); got: %s", url, buf.String())
			}
		})
	}
}

// TestWarnExternalSslmodeDisable_QuietWithoutDisable asserts that any
// sslmode other than `disable` (the production-grade modes) stays
// silent even with an external host. SEC-013 closure.
func TestWarnExternalSslmodeDisable_QuietWithoutDisable(t *testing.T) {
	t.Parallel()
	for _, url := range []string{
		"postgres://certctl@db.internal.example.com:5432/certctl?sslmode=verify-full&sslrootcert=/etc/ssl/ca.pem",
		"postgres://certctl@db.internal.example.com:5432/certctl?sslmode=require",
		"postgres://certctl@db.internal.example.com:5432/certctl", // no sslmode at all
	} {
		url := url
		t.Run(url, func(t *testing.T) {
			t.Parallel()
			logger, buf := newBufferLogger()
			warnExternalSslmodeDisable(url, logger)
			if buf.Len() != 0 {
				t.Errorf("expected silence for non-disable sslmode (%s); got: %s", url, buf.String())
			}
		})
	}
}

// TestWarnExternalSslmodeDisable_QuietOnUnparseableOrEmpty asserts the
// helper is permissive on garbage input — downstream sql.Open surfaces
// the real parse error; the SEC-013 advisory must not become a noisy
// hot path. SEC-013 closure.
func TestWarnExternalSslmodeDisable_QuietOnUnparseableOrEmpty(t *testing.T) {
	t.Parallel()
	for _, url := range []string{
		"",
		"not-a-url",
		"mysql://certctl@db:3306/x?sslmode=disable", // non-postgres scheme
	} {
		url := url
		t.Run(url, func(t *testing.T) {
			t.Parallel()
			logger, buf := newBufferLogger()
			warnExternalSslmodeDisable(url, logger)
			if buf.Len() != 0 {
				t.Errorf("expected silence for unparseable/non-postgres input (%q); got: %s", url, buf.String())
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Acquisition-audit Sprint 5 ACQ — RED-003 deny-empty default flip
// (2026-05-16). Three new tests pin the new default + the two
// override paths (operator opt-back, demo-mode override).
// -----------------------------------------------------------------------------

// TestLoad_AgentBootstrapTokenDenyEmpty_DefaultIsTrue pins the post-
// 2026-05-16 default. Load() with no CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY
// set must produce a Config whose AuthConfig.AgentBootstrapTokenDenyEmpty
// is true. Together with the next test, this proves the default flip
// from false → true at the boot path.
func TestLoad_AgentBootstrapTokenDenyEmpty_DefaultIsTrue(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	// Set a real bootstrap token so the deny-empty + empty-token guard
	// doesn't trip — we're asserting the default flag VALUE here, not
	// the guard behavior.
	t.Setenv("CERTCTL_AGENT_BOOTSTRAP_TOKEN", "a-real-32-byte-token-value-here-x")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v; want nil", err)
	}
	if !cfg.Auth.AgentBootstrapTokenDenyEmpty {
		t.Error("Load() default AgentBootstrapTokenDenyEmpty = false; want true (Sprint 5 ACQ flip on 2026-05-16)")
	}
}

// TestValidate_DenyEmptyDefault_RefusesWithoutToken pins the new
// default's effect: an empty token, with the flag at its
// post-2026-05-16 default of true, fails closed at Validate().
// Different shape from
// TestValidate_AgentBootstrapTokenDenyEmpty_True_EmptyTokenFailsClosed
// — that test sets the flag explicitly; this one drives the flag
// value from Load() defaults so it tracks any future default flip.
func TestValidate_DenyEmptyDefault_RefusesWithoutToken(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	// setMinimalValidEnv now sets CERTCTL_AGENT_BOOTSTRAP_TOKEN to
	// a placeholder (post-Sprint-5 ACQ default-flip — most Load()-
	// based tests need it). Override back to empty here because
	// THIS test is specifically the empty-token + default-deny-empty
	// fail-closed assertion.
	t.Setenv("CERTCTL_AGENT_BOOTSTRAP_TOKEN", "")
	// CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY deliberately unset
	// so the default (true) applies.

	_, err := Load()
	if err == nil {
		t.Fatal("Load() = nil; want ErrAgentBootstrapTokenRequired (deny-empty default flipped to true; empty token must fail closed)")
	}
	if !errors.Is(err, ErrAgentBootstrapTokenRequired) {
		t.Errorf("Load() err = %v; want errors.Is to match ErrAgentBootstrapTokenRequired", err)
	}
}

// TestValidate_DenyEmptyExplicitFalse_AllowsEmpty pins the v2.1.x
// back-compat path: an operator who explicitly opts out of the new
// default (CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY=false) keeps the
// warn-mode pass-through. CHANGELOG v2.2.0 documents this as a
// one-upgrade-window escape hatch for operators who haven't generated
// a token yet.
func TestValidate_DenyEmptyExplicitFalse_AllowsEmpty(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	t.Setenv("CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY", "false")
	// Override setMinimalValidEnv's placeholder so we exercise the
	// "operator explicit opt-out + empty token" path.
	t.Setenv("CERTCTL_AGENT_BOOTSTRAP_TOKEN", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v; want nil (explicit deny-empty=false allows empty token)", err)
	}
	if cfg.Auth.AgentBootstrapTokenDenyEmpty {
		t.Error("AgentBootstrapTokenDenyEmpty = true; want false (operator explicit opt-out)")
	}
}

// TestValidate_DenyEmpty_DemoModeAckOverride_AllowsEmpty pins the
// demo-mode escape hatch. A demo deploy with
// CERTCTL_DEMO_MODE_ACK=true (plus the SEC-H3 24h-fresh TS) keeps
// the warn-mode pass-through even with deny-empty=true. The
// accompanying boot banner WARN in cmd/server/main.go keeps the
// posture visible to log scrapers — demo deploys already emit a
// prominent "DEMO MODE ACTIVE" banner at every boot.
func TestValidate_DenyEmpty_DemoModeAckOverride_AllowsEmpty(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth: AuthConfig{
			Type:                         "none",
			AgentBootstrapToken:          "",
			AgentBootstrapTokenDenyEmpty: true,
			DemoModeAck:                  true,
			// 24h-fresh TS — SEC-H3 already gates demo-mode boot on
			// TS freshness; supply a current epoch so we exercise
			// only the deny-empty-override leg, not the SEC-H3 leg.
			DemoModeAckTS: strconv.FormatInt(time.Now().Unix(), 10),
		},
		Keygen:    KeygenConfig{Mode: "agent"},
		Scheduler: validSchedulerConfig(),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v; want nil (demo-mode override should allow empty token)", err)
	}
}
