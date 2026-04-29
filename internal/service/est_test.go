package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
)

// generateCSRPEM creates a valid ECDSA P-256 CSR for testing.
func generateCSRPEM(t *testing.T, cn string, sans []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func TestESTService_GetCACerts_Success(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewESTService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	caPEM, err := svc.GetCACerts(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if caPEM == "" {
		t.Error("expected non-empty CA PEM")
	}
}

func TestESTService_GetCACerts_IssuerError(t *testing.T) {
	mockIssuer := &mockIssuerConnector{Err: errors.New("CA unavailable")}
	svc := NewESTService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	_, err := svc.GetCACerts(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "CA unavailable") {
		t.Errorf("expected error to contain 'CA unavailable', got: %v", err)
	}
}

func TestESTService_SimpleEnroll_Success(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewESTService("iss-local", mockIssuer, auditSvc, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	csrPEM := generateCSRPEM(t, "test.example.com", []string{"test.example.com"})

	result, err := svc.SimpleEnroll(context.Background(), csrPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.CertPEM == "" {
		t.Error("expected non-empty CertPEM")
	}

	// Verify audit event was recorded
	if len(auditRepo.Events) == 0 {
		t.Error("expected audit event to be recorded")
	}
}

func TestESTService_SimpleEnroll_InvalidCSR(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewESTService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	_, err := svc.SimpleEnroll(context.Background(), "not-valid-pem")
	if err == nil {
		t.Fatal("expected error for invalid CSR")
	}
}

func TestESTService_SimpleEnroll_MissingCN(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewESTService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	csrPEM := generateCSRPEM(t, "", []string{"test.example.com"})

	_, err := svc.SimpleEnroll(context.Background(), csrPEM)
	if err == nil {
		t.Fatal("expected error for missing CN")
	}
	if !strings.Contains(err.Error(), "Common Name") {
		t.Errorf("expected 'Common Name' in error, got: %v", err)
	}
}

func TestESTService_SimpleEnroll_IssuerError(t *testing.T) {
	mockIssuer := &mockIssuerConnector{Err: errors.New("issuance failed")}
	svc := NewESTService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	csrPEM := generateCSRPEM(t, "test.example.com", nil)

	_, err := svc.SimpleEnroll(context.Background(), csrPEM)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "issuance failed") {
		t.Errorf("expected 'issuance failed', got: %v", err)
	}
}

func TestESTService_SimpleReEnroll_Success(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewESTService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	csrPEM := generateCSRPEM(t, "renew.example.com", []string{"renew.example.com"})

	result, err := svc.SimpleReEnroll(context.Background(), csrPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestESTService_GetCSRAttrs_Empty(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewESTService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	attrs, err := svc.GetCSRAttrs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attrs != nil {
		t.Errorf("expected nil attrs, got %v", attrs)
	}
}

func TestESTService_SimpleEnroll_WithProfile(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewESTService("iss-local", mockIssuer, auditSvc, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	svc.SetProfileID("profile-wifi-client")

	csrPEM := generateCSRPEM(t, "device.example.com", nil)

	result, err := svc.SimpleEnroll(context.Background(), csrPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Verify audit event includes profile_id
	if len(auditRepo.Events) == 0 {
		t.Fatal("expected audit event")
	}
	lastEvent := auditRepo.Events[len(auditRepo.Events)-1]
	if lastEvent.Details == nil {
		t.Fatal("expected audit details")
	}
}

// EST RFC 7030 hardening master bundle Phase 6.3 csrattrs tests.
// Pin the contract that GetCSRAttrs returns DER(SEQUENCE OF OID) when the
// bound profile carries hints, falls back to the v2.0.x nil/204 stub when
// the profile is absent / empty / corrupt, and silently drops unknown
// EKU/attribute names rather than emitting garbage OIDs.

func newCSRAttrsTestService(t *testing.T) (*ESTService, *mockProfileRepo) {
	t.Helper()
	repo := newMockProfileRepository()
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10}))
	svc := NewESTService("iss-local", &mockIssuerConnector{}, nil, silent)
	svc.SetProfileRepo(repo)
	return svc, repo
}

func TestESTService_GetCSRAttrs_NoProfileBound_Returns204Body(t *testing.T) {
	svc, _ := newCSRAttrsTestService(t)
	// SetProfileID intentionally NOT called — handler should see empty body
	// + write 204 per RFC 7030 §4.5.2 (legacy stub semantic preserved).
	got, err := svc.GetCSRAttrs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("got non-nil body for unbound profile: %x", got)
	}
}

func TestESTService_GetCSRAttrs_ProfileWithEKUsAndAttrs_ReturnsOIDList(t *testing.T) {
	svc, repo := newCSRAttrsTestService(t)
	svc.SetProfileID("prof-corp")
	repo.AddProfile(&domain.CertificateProfile{
		ID:                    "prof-corp",
		Name:                  "corp",
		AllowedEKUs:           []string{"serverAuth", "clientAuth"},
		RequiredCSRAttributes: []string{"serialNumber"},
		Enabled:               true,
	})

	der, err := svc.GetCSRAttrs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("expected non-empty body for profile with hints")
	}
	var got []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &got); err != nil {
		t.Fatalf("body should be DER(SEQUENCE OF OID); unmarshal: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 OIDs (2 EKUs + 1 attribute), got %d: %v", len(got), got)
	}
	// Pin the exact OIDs so a future EKUStringToOID typo trips the test.
	wantSerialNumberOID := asn1.ObjectIdentifier{2, 5, 4, 5}
	wantServerAuthOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	wantClientAuthOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	have := make(map[string]bool, len(got))
	for _, o := range got {
		have[o.String()] = true
	}
	for _, want := range []asn1.ObjectIdentifier{wantServerAuthOID, wantClientAuthOID, wantSerialNumberOID} {
		if !have[want.String()] {
			t.Errorf("missing OID %v in csrattrs response", want)
		}
	}
}

func TestESTService_GetCSRAttrs_EmptyProfile_Returns204Body(t *testing.T) {
	svc, repo := newCSRAttrsTestService(t)
	svc.SetProfileID("prof-empty")
	repo.AddProfile(&domain.CertificateProfile{
		ID:      "prof-empty",
		Name:    "empty",
		Enabled: true,
	})
	got, err := svc.GetCSRAttrs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("empty profile should return nil body for 204; got %x", got)
	}
}

func TestESTService_GetCSRAttrs_GarbageProfile_DropsUnknownAndKeepsValid(t *testing.T) {
	svc, repo := newCSRAttrsTestService(t)
	svc.SetProfileID("prof-garbage")
	repo.AddProfile(&domain.CertificateProfile{
		ID:                    "prof-garbage",
		Name:                  "garbage",
		AllowedEKUs:           []string{"serverAuth", "thisIsNotAnEKU"},
		RequiredCSRAttributes: []string{"serialNumber", "blarg-not-an-attribute"},
		Enabled:               true,
	})
	der, err := svc.GetCSRAttrs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 OIDs (the valid subset); got %d: %v", len(got), got)
	}
}

func TestESTService_GetCSRAttrs_ProfileLookupError_DegradesToNoHints(t *testing.T) {
	svc, repo := newCSRAttrsTestService(t)
	svc.SetProfileID("prof-missing")
	repo.GetErr = errors.New("repo unreachable")
	got, err := svc.GetCSRAttrs(context.Background())
	if err != nil {
		t.Fatalf("profile lookup error must NOT propagate; got: %v", err)
	}
	if got != nil {
		t.Errorf("profile-lookup-error path must degrade to nil body; got %x", got)
	}
}
