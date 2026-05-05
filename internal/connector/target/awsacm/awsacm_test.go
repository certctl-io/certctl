package awsacm_test

// Rank 5 of the 2026-05-03 Infisical deep-research deliverable
// (the project's deep-research deliverable, Part 5). Happy-path table-
// driven tests for the AWS ACM target connector. Mirrors the
// k8ssecret_test.go ergonomics + the Bundle 5+ atomic-rollback
// assertions from IIS / WinCertStore / JavaKeystore.
//
// Per-error-class failure tests live in awsacm_failure_test.go and
// follow the awsacmpca_failure_test.go shape (commit 60dce0b).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/connector/target"
	"github.com/certctl-io/certctl/internal/connector/target/awsacm"
)

// mockACMClient is the unit-test fake for the ACMClient interface seam.
// Every method records the input it received so tests can assert on
// "did the connector call DescribeCertificate twice for the post-verify
// step?" / "what tags did the second AddTagsToCertificate call use?".
//
// Each method has a corresponding *Err field so a test can inject a
// failure on the specific call it cares about while leaving the others
// healthy.
type mockACMClient struct {
	mu sync.Mutex

	// Per-call recording.
	importCalls   []*awsacm.ImportCertificateInput
	getCalls      []*awsacm.GetCertificateInput
	describeCalls []*awsacm.DescribeCertificateInput
	listCalls     []*awsacm.ListCertificatesInput
	tagCalls      []*awsacm.AddTagsToCertificateInput

	// Per-method canned responses + error injection. Each test case
	// constructs the mock with whatever shape it needs.
	importOutput   *awsacm.ImportCertificateOutput
	importErr      error
	getOutput      *awsacm.GetCertificateOutput
	getErr         error
	describeOutput *awsacm.DescribeCertificateOutput
	describeErr    error
	listOutput     *awsacm.ListCertificatesOutput
	listErr        error
	tagErr         error

	// rollbackHook lets tests inject a different importErr on the
	// SECOND ImportCertificate call (the rollback path) so the
	// "rollback also fails" branch can be exercised independently of
	// the first-import path. nil disables the hook.
	rollbackImportErr error
}

func (m *mockACMClient) ImportCertificate(ctx context.Context, in *awsacm.ImportCertificateInput) (*awsacm.ImportCertificateOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.importCalls = append(m.importCalls, in)
	if len(m.importCalls) > 1 && m.rollbackImportErr != nil {
		return nil, m.rollbackImportErr
	}
	if m.importErr != nil {
		return nil, m.importErr
	}
	if m.importOutput != nil {
		return m.importOutput, nil
	}
	// Default success path: echo the ARN if the caller supplied one,
	// otherwise synthesise a fresh ARN deterministically so tests can
	// assert on it.
	arn := in.CertificateArn
	if arn == "" {
		arn = "arn:aws:acm:us-east-1:123456789012:certificate/abcdef01-2345-6789-abcd-ef0123456789"
	}
	return &awsacm.ImportCertificateOutput{CertificateArn: arn}, nil
}

func (m *mockACMClient) GetCertificate(ctx context.Context, in *awsacm.GetCertificateInput) (*awsacm.GetCertificateOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCalls = append(m.getCalls, in)
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.getOutput != nil {
		return m.getOutput, nil
	}
	return &awsacm.GetCertificateOutput{}, nil
}

func (m *mockACMClient) DescribeCertificate(ctx context.Context, in *awsacm.DescribeCertificateInput) (*awsacm.DescribeCertificateOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.describeCalls = append(m.describeCalls, in)
	if m.describeErr != nil {
		return nil, m.describeErr
	}
	if m.describeOutput != nil {
		return m.describeOutput, nil
	}
	return &awsacm.DescribeCertificateOutput{}, nil
}

func (m *mockACMClient) ListCertificates(ctx context.Context, in *awsacm.ListCertificatesInput) (*awsacm.ListCertificatesOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listCalls = append(m.listCalls, in)
	if m.listErr != nil {
		return nil, m.listErr
	}
	if m.listOutput != nil {
		return m.listOutput, nil
	}
	return &awsacm.ListCertificatesOutput{}, nil
}

func (m *mockACMClient) AddTagsToCertificate(ctx context.Context, in *awsacm.AddTagsToCertificateInput) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tagCalls = append(m.tagCalls, in)
	return m.tagErr
}

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

// generateTestCert constructs a self-signed ECDSA P-256 cert for tests.
// Returns (certPEM, keyPEM, serialFormatted) where serialFormatted
// matches the colon-separated lowercase-hex shape ACM emits via
// DescribeCertificate.
func generateTestCert(t *testing.T, cn string) (certPEM, keyPEM, serial string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serialNum, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serialNum,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	// Format serial as colon-separated lowercase hex (ACM's output shape).
	hex := fmt.Sprintf("%x", serialNum)
	if len(hex)%2 == 1 {
		hex = "0" + hex
	}
	var b strings.Builder
	for i := 0; i < len(hex); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	serial = b.String()
	return
}

func TestAWSACM_ValidateConfig_Success(t *testing.T) {
	ctx := context.Background()
	c := awsacm.NewWithClient(nil, &mockACMClient{}, quietTestLogger())
	cfg := awsacm.Config{Region: "us-east-1"}
	raw, _ := json.Marshal(cfg)
	if err := c.ValidateConfig(ctx, raw); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
}

func TestAWSACM_ValidateConfig_MissingRegion(t *testing.T) {
	ctx := context.Background()
	c := awsacm.NewWithClient(nil, &mockACMClient{}, quietTestLogger())
	raw, _ := json.Marshal(awsacm.Config{})
	err := c.ValidateConfig(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "region is required") {
		t.Errorf("expected region-required error, got %v", err)
	}
}

func TestAWSACM_ValidateConfig_MalformedRegion(t *testing.T) {
	ctx := context.Background()
	c := awsacm.NewWithClient(nil, &mockACMClient{}, quietTestLogger())
	raw, _ := json.Marshal(awsacm.Config{Region: "not-a-region"})
	err := c.ValidateConfig(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "region malformed") {
		t.Errorf("expected region-malformed error, got %v", err)
	}
}

func TestAWSACM_ValidateConfig_MalformedARN(t *testing.T) {
	ctx := context.Background()
	c := awsacm.NewWithClient(nil, &mockACMClient{}, quietTestLogger())
	raw, _ := json.Marshal(awsacm.Config{Region: "us-east-1", CertificateArn: "not-an-arn"})
	err := c.ValidateConfig(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "certificate_arn malformed") {
		t.Errorf("expected ARN-malformed error, got %v", err)
	}
}

func TestAWSACM_ValidateConfig_RejectsReservedTags(t *testing.T) {
	ctx := context.Background()
	c := awsacm.NewWithClient(nil, &mockACMClient{}, quietTestLogger())
	raw, _ := json.Marshal(awsacm.Config{
		Region: "us-east-1",
		Tags:   map[string]string{"certctl-managed-by": "operator-spoofed"},
	})
	err := c.ValidateConfig(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "reserved provenance key") {
		t.Errorf("expected reserved-key rejection, got %v", err)
	}
}

func TestAWSACM_DeployCertificate_FreshImport(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, serial := generateTestCert(t, "fresh.example.com")

	mock := &mockACMClient{
		describeOutput: &awsacm.DescribeCertificateOutput{Serial: serial, Status: "ISSUED"},
	}
	cfg := &awsacm.Config{Region: "us-east-1"}
	c := awsacm.NewWithClient(cfg, mock, quietTestLogger())

	res, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		ChainPEM: "",
		Metadata: map[string]string{"certificate_id": "mc-fresh"},
	})
	if err != nil {
		t.Fatalf("DeployCertificate: %v", err)
	}
	if !res.Success {
		t.Errorf("expected Success=true")
	}
	if res.TargetAddress == "" {
		t.Errorf("expected TargetAddress (ARN) populated")
	}
	if len(mock.importCalls) != 1 {
		t.Errorf("expected exactly 1 ImportCertificate call (fresh import), got %d", len(mock.importCalls))
	}
	// Fresh import: tags MUST be supplied on the ImportCertificate call
	// (ACM strips them on re-import; this is the only window).
	if len(mock.importCalls[0].Tags) < 2 {
		t.Errorf("expected provenance tags (managed-by + cert-id) on fresh import; got %d tags", len(mock.importCalls[0].Tags))
	}
	// No AddTagsToCertificate on fresh import.
	if len(mock.tagCalls) != 0 {
		t.Errorf("fresh import should not call AddTagsToCertificate, got %d", len(mock.tagCalls))
	}
}

func TestAWSACM_DeployCertificate_RotateInPlace(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, serial := generateTestCert(t, "rotate.example.com")

	existingARN := "arn:aws:acm:us-east-1:123456789012:certificate/00000000-1111-2222-3333-444444444444"
	mock := &mockACMClient{
		// Pre-deploy snapshot returns the previous cert bytes (we use
		// a random self-signed for the snapshot).
		getOutput: &awsacm.GetCertificateOutput{
			Certificate: []byte("snapshot-cert-pem"),
		},
		describeOutput: &awsacm.DescribeCertificateOutput{Serial: serial, Status: "ISSUED"},
	}
	cfg := &awsacm.Config{Region: "us-east-1", CertificateArn: existingARN}
	c := awsacm.NewWithClient(cfg, mock, quietTestLogger())

	res, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Metadata: map[string]string{"certificate_id": "mc-rotate"},
	})
	if err != nil {
		t.Fatalf("DeployCertificate: %v", err)
	}
	if res.TargetAddress != existingARN {
		t.Errorf("rotate-in-place should preserve ARN; expected %s, got %s", existingARN, res.TargetAddress)
	}
	// Rotate-in-place: snapshot read happens before import.
	if len(mock.getCalls) != 1 {
		t.Errorf("expected pre-deploy GetCertificate; got %d calls", len(mock.getCalls))
	}
	// Tags re-applied via AddTagsToCertificate (re-import strips them).
	if len(mock.tagCalls) != 1 {
		t.Errorf("rotate-in-place should AddTagsToCertificate once; got %d", len(mock.tagCalls))
	}
	// Import call MUST carry the existing ARN.
	if mock.importCalls[0].CertificateArn != existingARN {
		t.Errorf("rotate import should target existing ARN; got %q", mock.importCalls[0].CertificateArn)
	}
}

func TestAWSACM_DeployCertificate_RollbackOnSerialMismatch(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, _ := generateTestCert(t, "mismatch.example.com")

	existingARN := "arn:aws:acm:us-east-1:123456789012:certificate/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	mock := &mockACMClient{
		getOutput: &awsacm.GetCertificateOutput{Certificate: []byte("snapshot-bytes")},
		// Post-verify returns a DIFFERENT serial than the imported cert
		// — triggers rollback.
		describeOutput: &awsacm.DescribeCertificateOutput{
			Serial: "ff:ff:ff:ff", // intentionally wrong
		},
	}
	cfg := &awsacm.Config{Region: "us-east-1", CertificateArn: existingARN}
	c := awsacm.NewWithClient(cfg, mock, quietTestLogger())

	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Metadata: map[string]string{"certificate_id": "mc-mismatch"},
	})
	if err == nil {
		t.Fatal("expected error on serial mismatch")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("expected error to mention rollback; got %v", err)
	}
	// Two ImportCertificate calls: the failing import + the rollback
	// re-import with snapshot bytes.
	if len(mock.importCalls) != 2 {
		t.Errorf("expected 2 ImportCertificate calls (initial + rollback); got %d", len(mock.importCalls))
	}
	// The second import MUST carry the snapshot bytes.
	if string(mock.importCalls[1].Certificate) != "snapshot-bytes" {
		t.Errorf("rollback should re-import snapshot bytes; got %q", string(mock.importCalls[1].Certificate))
	}
}

func TestAWSACM_DeployCertificate_RollbackAlsoFails(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, _ := generateTestCert(t, "twofail.example.com")

	existingARN := "arn:aws:acm:us-east-1:123456789012:certificate/cccccccc-dddd-eeee-ffff-000000000000"
	mock := &mockACMClient{
		getOutput:         &awsacm.GetCertificateOutput{Certificate: []byte("snapshot")},
		describeOutput:    &awsacm.DescribeCertificateOutput{Serial: "00:00"},
		rollbackImportErr: errors.New("simulated rollback ImportCertificate failure"),
	}
	cfg := &awsacm.Config{Region: "us-east-1", CertificateArn: existingARN}
	c := awsacm.NewWithClient(cfg, mock, quietTestLogger())

	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Metadata: map[string]string{"certificate_id": "mc-twofail"},
	})
	if err == nil {
		t.Fatal("expected error on rollback failure")
	}
	// We still surfaced the original mismatch error to the caller; the
	// rollback failure logs but doesn't change the surfaced error
	// shape. Ensure we attempted the rollback (2 import calls).
	if len(mock.importCalls) != 2 {
		t.Errorf("expected 2 import calls including failed rollback; got %d", len(mock.importCalls))
	}
}

func TestAWSACM_DeployCertificate_EmptyKeyPEM(t *testing.T) {
	ctx := context.Background()
	certPEM, _, _ := generateTestCert(t, "nokey.example.com")
	cfg := &awsacm.Config{Region: "us-east-1"}
	c := awsacm.NewWithClient(cfg, &mockACMClient{}, quietTestLogger())

	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   "",
		Metadata: map[string]string{"certificate_id": "mc-nokey"},
	})
	if err == nil || !strings.Contains(err.Error(), "key_pem is required") {
		t.Errorf("expected key-required error, got %v", err)
	}
}

func TestAWSACM_DeployCertificate_NoClient(t *testing.T) {
	ctx := context.Background()
	cfg := &awsacm.Config{Region: "us-east-1"}
	c := awsacm.NewWithClient(cfg, nil, quietTestLogger())
	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{CertPEM: "x", KeyPEM: "y"})
	if err == nil || !strings.Contains(err.Error(), "client not initialized") {
		t.Errorf("expected client-not-initialized; got %v", err)
	}
}

func TestAWSACM_ValidateOnly_NotSupported(t *testing.T) {
	ctx := context.Background()
	c := awsacm.NewWithClient(&awsacm.Config{Region: "us-east-1"}, &mockACMClient{}, quietTestLogger())
	err := c.ValidateOnly(ctx, target.DeploymentRequest{})
	if !errors.Is(err, target.ErrValidateOnlyNotSupported) {
		t.Errorf("expected ErrValidateOnlyNotSupported, got %v", err)
	}
}

func TestAWSACM_ValidateDeployment_SerialMatch(t *testing.T) {
	ctx := context.Background()
	mock := &mockACMClient{
		describeOutput: &awsacm.DescribeCertificateOutput{Serial: "ab:cd:01"},
	}
	arn := "arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555"
	cfg := &awsacm.Config{Region: "us-east-1", CertificateArn: arn}
	c := awsacm.NewWithClient(cfg, mock, quietTestLogger())

	res, err := c.ValidateDeployment(ctx, target.ValidationRequest{Serial: "ab:cd:01"})
	if err != nil {
		t.Fatalf("ValidateDeployment: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected Valid=true, got %+v", res)
	}
	if res.TargetAddress != arn {
		t.Errorf("expected TargetAddress=%s, got %s", arn, res.TargetAddress)
	}
}

func TestAWSACM_ValidateDeployment_SerialMismatch(t *testing.T) {
	ctx := context.Background()
	mock := &mockACMClient{
		describeOutput: &awsacm.DescribeCertificateOutput{Serial: "00:00"},
	}
	arn := "arn:aws:acm:us-east-1:123456789012:certificate/22222222-3333-4444-5555-666666666666"
	cfg := &awsacm.Config{Region: "us-east-1", CertificateArn: arn}
	c := awsacm.NewWithClient(cfg, mock, quietTestLogger())

	res, err := c.ValidateDeployment(ctx, target.ValidationRequest{Serial: "ab:cd:01"})
	if err != nil {
		t.Fatalf("ValidateDeployment unexpected error: %v", err)
	}
	if res.Valid {
		t.Errorf("expected Valid=false on serial mismatch, got %+v", res)
	}
}

func TestAWSACM_ValidateDeployment_NoARNYet(t *testing.T) {
	ctx := context.Background()
	cfg := &awsacm.Config{Region: "us-east-1"}
	c := awsacm.NewWithClient(cfg, &mockACMClient{}, quietTestLogger())
	res, err := c.ValidateDeployment(ctx, target.ValidationRequest{Serial: "ab:cd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Valid {
		t.Errorf("expected Valid=false when ARN not yet known")
	}
	if !strings.Contains(res.Message, "ARN not yet known") {
		t.Errorf("expected ARN-not-yet-known message; got %q", res.Message)
	}
}
