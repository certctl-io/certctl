package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
)

// EST RFC 7030 hardening master bundle Phase 11.4 — audit-code assertions.
// Drive each code path through a real ESTService instance + assert the
// typed action codes land in the audit log alongside the legacy bare
// codes (back-compat preservation).

func newAuditAssertService(t *testing.T) (*ESTService, *mockAuditRepo) {
	t.Helper()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10}))
	svc := NewESTService("iss-corp", &mockIssuerConnector{}, auditSvc, silent)
	return svc, auditRepo
}

// auditActions returns the action codes recorded across every audit
// event in the repo, in emission order. Used to assert that the
// typed _success / _failed events fire in the right order alongside
// the legacy bare codes.
func auditActions(repo *mockAuditRepo) []string {
	out := make([]string, 0, len(repo.Events))
	for _, e := range repo.Events {
		out = append(out, e.Action)
	}
	return out
}

func TestESTAudit_SimpleEnrollSuccess_EmitsLegacyAndTyped(t *testing.T) {
	svc, repo := newAuditAssertService(t)
	csrPEM := generateCSRPEM(t, "device.example.com", []string{"device.example.com"})
	if _, err := svc.SimpleEnroll(context.Background(), csrPEM); err != nil {
		t.Fatalf("SimpleEnroll: %v", err)
	}
	got := auditActions(repo)
	wantBare := "est_simple_enroll"
	wantTyped := AuditActionESTSimpleEnrollSuccess // est_simple_enroll_success
	if !stringSliceContains(got, wantBare) {
		t.Errorf("missing legacy bare code %q in %v", wantBare, got)
	}
	if !stringSliceContains(got, wantTyped) {
		t.Errorf("missing typed code %q in %v", wantTyped, got)
	}
}

func TestESTAudit_SimpleReEnrollSuccess_EmitsTyped(t *testing.T) {
	svc, repo := newAuditAssertService(t)
	csrPEM := generateCSRPEM(t, "device.example.com", nil)
	if _, err := svc.SimpleReEnroll(context.Background(), csrPEM); err != nil {
		t.Fatalf("SimpleReEnroll: %v", err)
	}
	if !stringSliceContains(auditActions(repo), AuditActionESTSimpleReEnrollSuccess) {
		t.Errorf("missing %q; got %v", AuditActionESTSimpleReEnrollSuccess, auditActions(repo))
	}
}

func TestESTAudit_IssuerError_EmitsTypedFailed(t *testing.T) {
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10}))
	svc := NewESTService("iss-corp", &mockIssuerConnector{Err: errors.New("CA down")}, auditSvc, silent)
	csrPEM := generateCSRPEM(t, "device.example.com", nil)
	if _, err := svc.SimpleEnroll(context.Background(), csrPEM); err == nil {
		t.Fatal("expected enroll error")
	}
	if !stringSliceContains(auditActions(auditRepo), AuditActionESTSimpleEnrollFailed) {
		t.Errorf("missing typed failure code; got %v", auditActions(auditRepo))
	}
	// And the bare _failed variant for back-compat:
	if !stringSliceContains(auditActions(auditRepo), "est_simple_enroll_failed") {
		t.Errorf("missing bare _failed variant; got %v", auditActions(auditRepo))
	}
}

func TestESTAudit_PolicyViolation_EmitsTypedAndStandalone(t *testing.T) {
	svc, repo := newAuditAssertService(t)
	repoMock := newMockProfileRepository()
	svc.SetProfileRepo(repoMock)
	svc.SetProfileID("prof-tight")
	repoMock.AddProfile(&domain.CertificateProfile{
		ID:                   "prof-tight",
		Name:                 "tight",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{{Algorithm: "RSA", MinSize: 4096}}, // ECDSA-P256 CSR fails
		Enabled:              true,
	})
	csrPEM := generateCSRPEM(t, "device.example.com", nil) // ECDSA-P256
	if _, err := svc.SimpleEnroll(context.Background(), csrPEM); err == nil {
		t.Fatal("expected policy violation error")
	}
	got := auditActions(repo)
	if !stringSliceContains(got, AuditActionESTCSRPolicyViolation) {
		t.Errorf("missing standalone policy-violation code %q; got %v", AuditActionESTCSRPolicyViolation, got)
	}
	if !stringSliceContains(got, AuditActionESTSimpleEnrollFailed) {
		t.Errorf("missing typed failed code; got %v", got)
	}
}

func TestESTAudit_AuditCodesAreUniqueStrings(t *testing.T) {
	// Tiny invariant test: every audit-action constant is a non-empty
	// distinct string. Prevents a future cut-paste typo where two
	// constants share the same value.
	codes := []string{
		AuditActionESTSimpleEnrollSuccess,
		AuditActionESTSimpleEnrollFailed,
		AuditActionESTSimpleReEnrollSuccess,
		AuditActionESTSimpleReEnrollFailed,
		AuditActionESTServerKeygenSuccess,
		AuditActionESTServerKeygenFailed,
		AuditActionESTAuthFailedBasic,
		AuditActionESTAuthFailedMTLS,
		AuditActionESTAuthFailedChannelBinding,
		AuditActionESTRateLimited,
		AuditActionESTCSRPolicyViolation,
		AuditActionESTBulkRevoke,
		AuditActionESTTrustAnchorReloaded,
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if c == "" {
			t.Errorf("empty audit-action constant")
		}
		if !strings.HasPrefix(c, "est_") {
			t.Errorf("audit-action constant %q must start with est_", c)
		}
		if seen[c] {
			t.Errorf("duplicate audit-action constant: %q", c)
		}
		seen[c] = true
	}
}

func stringSliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// silenceUnusedDomain keeps the domain import live when the policy-
// violation test compiles even if a future refactor removes the only
// reference site.
var _ domain.CertificateProfile
