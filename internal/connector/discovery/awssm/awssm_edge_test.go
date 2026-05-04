package awssm

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/config"
)

// Bundle Q (L-002 closure): edge-case coverage for awssm to push above 80%.
//
// Adds tests for:
//
//   - New() default-constructor path (was 0%): nil config, nil logger, normal path
//   - NewWithClient() default-arg paths
//   - extractKeyInfo for ECDSA + Ed25519 + unknown key types (was RSA-only)
//   - processSecret's NamePrefix filter and TagFilter mismatch skip arms
//   - realSMClient stub methods (ListSecrets / GetSecretValue) — pin the
//     "documented stub returns empty + no error" contract so a future
//     refactor that swaps in real SDK calls without updating callers is
//     caught immediately
//   - ValidateConfig nil-config branch

func TestNew_NilConfig_PopulatesDefaults(t *testing.T) {
	src := New(nil, slog.Default())
	if src == nil {
		t.Fatal("New(nil, _) returned nil source")
	}
	if src.cfg == nil {
		t.Errorf("expected New to populate empty config when nil supplied")
	}
}

func TestNew_NilLogger_PopulatesDefaults(t *testing.T) {
	cfg := &config.AWSSecretsMgrDiscoveryConfig{Region: "us-east-1"}
	src := New(cfg, nil)
	if src == nil {
		t.Fatal("New(_, nil) returned nil source")
	}
	if src.logger == nil {
		t.Errorf("expected New to populate default logger when nil supplied")
	}
}

func TestNew_NormalPath_CreatesSource(t *testing.T) {
	cfg := &config.AWSSecretsMgrDiscoveryConfig{Region: "us-west-2"}
	src := New(cfg, slog.Default())
	if src == nil {
		t.Fatal("New returned nil")
	}
	if src.client == nil {
		t.Errorf("expected New to wire up a real SM client")
	}
	// Sanity: real client should be a *realSMClient pointing at us-west-2.
	rc, ok := src.client.(*realSMClient)
	if !ok {
		t.Fatalf("expected *realSMClient, got %T", src.client)
	}
	if rc.region != "us-west-2" {
		t.Errorf("expected region us-west-2, got %q", rc.region)
	}
}

func TestNewWithClient_NilConfig_NilLogger_PopulatesDefaults(t *testing.T) {
	mock := newMockSMClient()
	src := NewWithClient(nil, mock, nil)
	if src == nil {
		t.Fatal("NewWithClient returned nil")
	}
	if src.cfg == nil || src.logger == nil {
		t.Errorf("expected NewWithClient to populate cfg + logger defaults")
	}
}

func TestValidateConfig_NilConfig_FailsClosed(t *testing.T) {
	src := &Source{} // explicit nil cfg
	if err := src.ValidateConfig(); err == nil {
		t.Errorf("expected ValidateConfig to fail when cfg is nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// extractKeyInfo: every key-type arm.
// ─────────────────────────────────────────────────────────────────────────────

func TestExtractKeyInfo_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	algo, size := extractKeyInfo(cert)
	if algo != "RSA" {
		t.Errorf("expected RSA, got %q", algo)
	}
	if size != 2048 {
		t.Errorf("expected size 2048, got %d", size)
	}
}

func TestExtractKeyInfo_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	algo, size := extractKeyInfo(cert)
	if algo != "ECDSA" {
		t.Errorf("expected ECDSA, got %q", algo)
	}
	if size != 384 {
		t.Errorf("expected size 384 (P-384 curve), got %d", size)
	}
}

func TestExtractKeyInfo_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	cert := &x509.Certificate{PublicKey: pub}
	algo, size := extractKeyInfo(cert)
	if algo != "Ed25519" {
		t.Errorf("expected Ed25519, got %q", algo)
	}
	if size != 256 {
		t.Errorf("expected size 256, got %d", size)
	}
}

func TestExtractKeyInfo_Unknown(t *testing.T) {
	// PublicKey type that's none of the known cases → falls through to default.
	cert := &x509.Certificate{PublicKey: struct{ X int }{42}}
	algo, size := extractKeyInfo(cert)
	if algo != "Unknown" {
		t.Errorf("expected Unknown, got %q", algo)
	}
	if size != 0 {
		t.Errorf("expected size 0 for unknown, got %d", size)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// processSecret: filter arms.
// ─────────────────────────────────────────────────────────────────────────────

func TestProcessSecret_NamePrefixMismatch_SkipsSilently(t *testing.T) {
	// L-002: NamePrefix-mismatched secret must be silently skipped (no error,
	// no entry added, no GetSecretValue call). This exercises the prefix
	// short-circuit that previously sat on the un-tested side of the branch.
	mock := newMockSMClient()
	mock.secrets["other/cert"] = "ignored-value"
	mock.secretMetadata["other/cert"] = SecretMetadata{Name: "other/cert"}

	cfg := &config.AWSSecretsMgrDiscoveryConfig{
		Region:     "us-east-1",
		NamePrefix: "prod/", // "other/cert" doesn't start with "prod/"
	}
	src := NewWithClient(cfg, mock, slog.Default())

	report, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(report.Certificates) != 0 {
		t.Errorf("expected 0 certs (prefix mismatch), got %d", len(report.Certificates))
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected 0 errors, got %v", report.Errors)
	}
}

func TestProcessSecret_TagFilterMismatch_SkipsSilently(t *testing.T) {
	// L-002: TagFilter-mismatched secret must be silently skipped. Pins the
	// branch where the secret has tags but they don't match the configured
	// key=value pair.
	mock := newMockSMClient()
	mock.secrets["prod/cert"] = "ignored"
	mock.secretMetadata["prod/cert"] = SecretMetadata{
		Name: "prod/cert",
		Tags: map[string]string{"type": "password"}, // mismatch: cfg wants type=certificate
	}

	cfg := &config.AWSSecretsMgrDiscoveryConfig{
		Region:    "us-east-1",
		TagFilter: "type=certificate",
	}
	src := NewWithClient(cfg, mock, slog.Default())

	report, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(report.Certificates) != 0 {
		t.Errorf("expected 0 certs (tag mismatch), got %d", len(report.Certificates))
	}
}

func TestProcessSecret_EmptyValue_Skipped(t *testing.T) {
	// L-002: empty secret value short-circuits parseCertificateData and
	// returns nil error.
	mock := newMockSMClient()
	mock.secrets["prod/empty"] = ""
	mock.secretMetadata["prod/empty"] = SecretMetadata{
		Name: "prod/empty",
		Tags: map[string]string{"type": "certificate"},
	}

	cfg := &config.AWSSecretsMgrDiscoveryConfig{Region: "us-east-1"}
	src := NewWithClient(cfg, mock, slog.Default())

	report, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(report.Certificates) != 0 {
		t.Errorf("expected 0 certs (empty value), got %d", len(report.Certificates))
	}
}

func TestProcessSecret_GetSecretError_PropagatesToErrors(t *testing.T) {
	// Round-out for processSecret: GetSecretValue error path adds to report.Errors.
	mock := newMockSMClient()
	mock.secretMetadata["prod/missing"] = SecretMetadata{
		Name: "prod/missing",
		Tags: map[string]string{"type": "certificate"},
	}
	mock.getErrors["prod/missing"] = errors.New("AccessDenied")

	cfg := &config.AWSSecretsMgrDiscoveryConfig{Region: "us-east-1"}
	src := NewWithClient(cfg, mock, slog.Default())

	report, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(report.Errors) == 0 {
		t.Errorf("expected error in report, got none")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// realSMClient: stub-contract pinning.
// ─────────────────────────────────────────────────────────────────────────────

func TestRealSMClient_ListSecrets_StubReturnsEmpty(t *testing.T) {
	// L-002: pin the documented stub contract. ListSecrets in the current
	// implementation is a placeholder — empty slice + no error. A future
	// refactor wiring up the real AWS SDK should update tests, not silently
	// change return values.
	c := newRealSMClient("us-east-1", slog.Default()).(*realSMClient)
	got, err := c.ListSecrets(context.Background(), "tag-key:type")
	if err != nil {
		t.Errorf("expected nil err from stub, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice from stub, got %d entries", len(got))
	}
}

func TestRealSMClient_GetSecretValue_StubReturnsEmpty(t *testing.T) {
	c := newRealSMClient("us-east-1", slog.Default()).(*realSMClient)
	got, err := c.GetSecretValue(context.Background(), "any/secret")
	if err != nil {
		t.Errorf("expected nil err from stub, got %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string from stub, got %q", got)
	}
}

func TestNewRealSMClient_PopulatesFields(t *testing.T) {
	c := newRealSMClient("eu-west-1", slog.Default()).(*realSMClient)
	if c.region != "eu-west-1" {
		t.Errorf("expected region eu-west-1, got %q", c.region)
	}
	if c.logger == nil {
		t.Errorf("expected logger to be populated")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// buildDiscoveredCertEntry: edge cases on EmailAddresses-based SAN extraction.
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildDiscoveredCertEntry_WithEmailSANs(t *testing.T) {
	// Pin the EmailAddresses → SAN append path (was uncovered).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(42),
		Subject:        pkix.Name{CommonName: "test.example.com"},
		NotBefore:      time.Now().Add(-1 * time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"alice@example.com", "bob@example.com"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	src := NewWithClient(&config.AWSSecretsMgrDiscoveryConfig{Region: "us-east-1"}, newMockSMClient(), slog.Default())
	entry, err := src.buildDiscoveredCertEntry(cert, "prod/test")
	if err != nil {
		t.Fatalf("buildDiscoveredCertEntry: %v", err)
	}
	if len(entry.SANs) != 3 {
		t.Errorf("expected 3 SANs (1 DNS + 2 emails), got %d: %v", len(entry.SANs), entry.SANs)
	}
}
