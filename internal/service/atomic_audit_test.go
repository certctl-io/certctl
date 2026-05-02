// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1
//
// Closes the #3 acquisition-readiness blocker from the 2026-05-01
// issuer coverage audit by pinning the atomic-audit-row contract on
// the issuance, renewal, and revocation paths.
//
// Pre-fix: cert insert / version insert / revocation insert ran on a
// *sql.DB connection while the audit row INSERT ran on a separate
// *sql.DB connection. A failed audit INSERT was logged but did not
// fail the operation — silently incomplete audit trail.
//
// Post-fix: when SetTransactor is wired (production via
// cmd/server/main.go), the operation runs inside Transactor.WithinTx
// and any audit-insert failure rolls back the entire transaction.
//
// These tests use mockTransactor + mockAuditRepo with CreateErr to
// simulate audit-insert failure. The mock repos share state in memory
// (no real rollback), so the test asserts the contract via the
// returned error and the auditService side effect, not by inspecting
// post-rollback row counts. The testcontainers-backed sibling test in
// the postgres package exercises real-Postgres rollback semantics
// against a real audit_events table.

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// TestCertificateService_Create_AtomicWithTx asserts the issuance path
// runs inside Transactor.WithinTx when the transactor is wired. Without
// the wrapping, an audit-insert failure would silently log; with it,
// the failure surfaces as the operation's error.
func TestCertificateService_Create_AtomicWithTx(t *testing.T) {
	auditRepo := newMockAuditRepository()
	auditRepo.CreateErr = errors.New("simulated audit insert failure")
	auditService := NewAuditService(auditRepo)

	certRepo := newMockCertificateRepository()
	policyService := NewPolicyService(newMockPolicyRepository(), auditService)

	svc := NewCertificateService(certRepo, policyService, auditService)
	svc.SetTransactor(newMockTransactor())

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-atomic",
		Name:       "atomic-test",
		CommonName: "atomic.example.com",
		IssuerID:   "iss-test",
	}

	err := svc.Create(context.Background(), cert, "test-actor")
	if err == nil {
		t.Fatal("Create should fail when audit insert fails inside the transaction")
	}
	if !errIncludes(err, "audit") {
		t.Errorf("expected error to mention audit, got: %v", err)
	}
}

// TestCertificateService_Create_LegacyPathLogs asserts the pre-fix
// behavior is preserved when SetTransactor is NOT wired: audit failure
// is logged but the operation succeeds (returns nil). This documents
// the backward-compat fallback so callers that haven't migrated to the
// atomic path still build and run.
func TestCertificateService_Create_LegacyPathLogs(t *testing.T) {
	auditRepo := newMockAuditRepository()
	auditRepo.CreateErr = errors.New("simulated audit insert failure")
	auditService := NewAuditService(auditRepo)

	certRepo := newMockCertificateRepository()
	policyService := NewPolicyService(newMockPolicyRepository(), auditService)

	svc := NewCertificateService(certRepo, policyService, auditService)
	// Intentionally NOT calling SetTransactor — exercise the legacy
	// path.

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-legacy",
		Name:       "legacy-test",
		CommonName: "legacy.example.com",
		IssuerID:   "iss-test",
	}

	err := svc.Create(context.Background(), cert, "test-actor")
	if err != nil {
		t.Fatalf("legacy path should swallow audit failure, got: %v", err)
	}
	// The cert insert still landed in the mock — the audit failure
	// did not roll it back (because there's no transaction). This is
	// the audit's blocker behavior; it remains for callers that
	// haven't wired SetTransactor.
	if _, ok := certRepo.Certs["mc-test-legacy"]; !ok {
		t.Fatal("cert insert should land in legacy path even when audit fails")
	}
}

// TestCertificateService_Create_TransactorBeginFailure asserts that
// when Transactor.WithinTx itself fails (BeginTx error path), the
// operation surfaces the error and no cert insert happens.
func TestCertificateService_Create_TransactorBeginFailure(t *testing.T) {
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	certRepo := newMockCertificateRepository()
	policyService := NewPolicyService(newMockPolicyRepository(), auditService)

	tx := newMockTransactor()
	tx.BeginTxErr = errors.New("simulated begin tx failure")

	svc := NewCertificateService(certRepo, policyService, auditService)
	svc.SetTransactor(tx)

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-begin-fail",
		Name:       "begin-fail",
		CommonName: "begin-fail.example.com",
		IssuerID:   "iss-test",
	}

	err := svc.Create(context.Background(), cert, "test-actor")
	if err == nil {
		t.Fatal("Create should fail when BeginTx fails")
	}
	if _, ok := certRepo.Certs["mc-test-begin-fail"]; ok {
		t.Fatal("cert insert must NOT happen when BeginTx fails — fn never ran")
	}
	if len(auditRepo.Events) > 0 {
		t.Fatal("audit insert must NOT happen when BeginTx fails")
	}
}

// TestCertificateService_Create_TransactorCommitFailure asserts that
// a Commit failure after successful in-fn writes surfaces as the
// operation's error. Real Postgres can fail Commit on serialization
// conflicts; the service must report this rather than swallowing it.
func TestCertificateService_Create_TransactorCommitFailure(t *testing.T) {
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	certRepo := newMockCertificateRepository()
	policyService := NewPolicyService(newMockPolicyRepository(), auditService)

	tx := newMockTransactor()
	tx.CommitErr = errors.New("simulated commit failure")

	svc := NewCertificateService(certRepo, policyService, auditService)
	svc.SetTransactor(tx)

	cert := &domain.ManagedCertificate{
		ID:         "mc-test-commit-fail",
		Name:       "commit-fail",
		CommonName: "commit-fail.example.com",
		IssuerID:   "iss-test",
	}

	err := svc.Create(context.Background(), cert, "test-actor")
	if err == nil {
		t.Fatal("Create should fail when Commit fails")
	}
}

// Compile-time guard: ensure mockTransactor satisfies repository.Transactor.
var _ repository.Transactor = (*mockTransactor)(nil)

// errIncludes is a tiny strings.Contains alias for use in error-message
// assertions — keeps the test file dependency-light.
func errIncludes(err error, sub string) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
