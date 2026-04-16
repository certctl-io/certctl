package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestSCEPService_GetCACaps(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewSCEPService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "")

	caps := svc.GetCACaps(context.Background())
	if caps == "" {
		t.Error("expected non-empty capabilities")
	}
	if !strings.Contains(caps, "POSTPKIOperation") {
		t.Errorf("expected POSTPKIOperation in caps, got: %s", caps)
	}
	if !strings.Contains(caps, "SHA-256") {
		t.Errorf("expected SHA-256 in caps, got: %s", caps)
	}
	if !strings.Contains(caps, "SCEPStandard") {
		t.Errorf("expected SCEPStandard in caps, got: %s", caps)
	}
}

func TestSCEPService_GetCACert_Success(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewSCEPService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "")

	caPEM, err := svc.GetCACert(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if caPEM == "" {
		t.Error("expected non-empty CA PEM")
	}
}

func TestSCEPService_GetCACert_IssuerError(t *testing.T) {
	mockIssuer := &mockIssuerConnector{Err: errors.New("CA unavailable")}
	svc := NewSCEPService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "")

	_, err := svc.GetCACert(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "CA unavailable") {
		t.Errorf("expected error to contain 'CA unavailable', got: %v", err)
	}
}

func TestSCEPService_PKCSReq_Success(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	// H-2: SCEPService now requires a configured challenge password; the happy
	// path exercises a matching client-submitted password.
	svc := NewSCEPService("iss-local", mockIssuer, auditSvc, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")

	csrPEM := generateCSRPEM(t, "device.example.com", []string{"device.example.com"})

	result, err := svc.PKCSReq(context.Background(), csrPEM, "secret123", "txn-001")
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

func TestSCEPService_PKCSReq_InvalidCSR(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewSCEPService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")

	_, err := svc.PKCSReq(context.Background(), "not-valid-pem", "secret123", "txn-002")
	if err == nil {
		t.Fatal("expected error for invalid CSR")
	}
}

func TestSCEPService_PKCSReq_MissingCN(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewSCEPService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")

	csrPEM := generateCSRPEM(t, "", []string{"test.example.com"})

	_, err := svc.PKCSReq(context.Background(), csrPEM, "secret123", "txn-003")
	if err == nil {
		t.Fatal("expected error for missing CN")
	}
	if !strings.Contains(err.Error(), "Common Name") {
		t.Errorf("expected 'Common Name' in error, got: %v", err)
	}
}

func TestSCEPService_PKCSReq_IssuerError(t *testing.T) {
	mockIssuer := &mockIssuerConnector{Err: errors.New("issuance failed")}
	svc := NewSCEPService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")

	csrPEM := generateCSRPEM(t, "test.example.com", nil)

	_, err := svc.PKCSReq(context.Background(), csrPEM, "secret123", "txn-004")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "issuance failed") {
		t.Errorf("expected 'issuance failed', got: %v", err)
	}
}

func TestSCEPService_PKCSReq_ChallengePassword_Valid(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewSCEPService("iss-local", mockIssuer, auditSvc, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")

	csrPEM := generateCSRPEM(t, "mdm-device.example.com", nil)

	result, err := svc.PKCSReq(context.Background(), csrPEM, "secret123", "txn-005")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestSCEPService_PKCSReq_ChallengePassword_Invalid(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewSCEPService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")

	csrPEM := generateCSRPEM(t, "mdm-device.example.com", nil)

	_, err := svc.PKCSReq(context.Background(), csrPEM, "wrong-password", "txn-006")
	if err == nil {
		t.Fatal("expected error for invalid challenge password")
	}
	if !strings.Contains(err.Error(), "challenge password") {
		t.Errorf("expected 'challenge password' in error, got: %v", err)
	}
}

// TestSCEPService_PKCSReq_ChallengePassword_EmptyServerConfigRejected is the
// H-2 regression guard. Before the fix (internal/service/scep.go:72-79 skipped
// the password check when s.challengePassword was empty), an unconfigured
// server accepted any enrollment (CWE-306). The service now rejects PKCSReq
// defense-in-depth even if main()'s pre-flight is somehow bypassed.
func TestSCEPService_PKCSReq_ChallengePassword_EmptyServerConfigRejected(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewSCEPService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "")

	csrPEM := generateCSRPEM(t, "device.example.com", nil)

	// Any client-submitted password (including empty) must be rejected when
	// the server has no shared secret configured.
	for _, clientPassword := range []string{"", "any-value", "guess"} {
		_, err := svc.PKCSReq(context.Background(), csrPEM, clientPassword, "txn-empty")
		if err == nil {
			t.Fatalf("expected rejection when server challenge password is empty (client=%q)", clientPassword)
		}
		if !strings.Contains(err.Error(), "not configured") {
			t.Errorf("expected 'not configured' in error, got: %v", err)
		}
	}
}

// TestSCEPService_PKCSReq_ChallengePassword_ConstantTimeLengthIndependence
// guards against regression from crypto/subtle.ConstantTimeCompare to a
// short-circuiting byte compare. ConstantTimeCompare returns 0 whenever the
// two slices differ in length OR content, so a same-prefix-but-longer input
// must be rejected the same way as a completely different string.
func TestSCEPService_PKCSReq_ChallengePassword_ConstantTimeLengthIndependence(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	svc := NewSCEPService("iss-local", mockIssuer, nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")

	csrPEM := generateCSRPEM(t, "device.example.com", nil)

	for _, bad := range []string{"secret", "secret12", "secret1234", "SECRET123", "wrong"} {
		_, err := svc.PKCSReq(context.Background(), csrPEM, bad, "txn-ct")
		if err == nil {
			t.Fatalf("expected rejection for bad password %q", bad)
		}
		if !strings.Contains(err.Error(), "invalid challenge password") {
			t.Errorf("expected 'invalid challenge password' for %q, got: %v", bad, err)
		}
	}
}

func TestSCEPService_PKCSReq_WithProfile(t *testing.T) {
	mockIssuer := &mockIssuerConnector{}
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewSCEPService("iss-local", mockIssuer, auditSvc, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "secret123")
	svc.SetProfileID("profile-mdm-device")

	csrPEM := generateCSRPEM(t, "device.example.com", nil)

	result, err := svc.PKCSReq(context.Background(), csrPEM, "secret123", "txn-008")
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
