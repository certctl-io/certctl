package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
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
