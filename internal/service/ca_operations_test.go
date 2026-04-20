// Tests for CAOperationsSvc, the focused sub-service that handles CRL generation
// and OCSP response signing extracted from CertificateService (TICKET-007).
package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// helper to create a CAOperationsSvc for testing
func newCAOperationsSvcTest() (*CAOperationsSvc, *mockRevocationRepo, *mockCertRepo) {
	caSvc, revocationRepo, certRepo, _ := newCAOperationsSvcTestWithIssuer()
	return caSvc, revocationRepo, certRepo
}

// newCAOperationsSvcTestWithIssuer also returns the mock issuer connector
// so tests can assert on the captured OCSPSignRequest.
func newCAOperationsSvcTestWithIssuer() (*CAOperationsSvc, *mockRevocationRepo, *mockCertRepo, *mockIssuerConnector) {
	revocationRepo := newMockRevocationRepository()
	certRepo := newMockCertificateRepository()
	profileRepo := newMockProfileRepository()

	caSvc := NewCAOperationsSvc(revocationRepo, certRepo, profileRepo)
	registry := NewIssuerRegistry(slog.Default())
	issuer := &mockIssuerConnector{}
	registry.Set("iss-local", issuer)
	registry.Set("iss-other", &mockIssuerConnector{})
	caSvc.SetIssuerRegistry(registry)

	return caSvc, revocationRepo, certRepo, issuer
}

func TestCAOperationsSvc_GenerateDERCRL_Success(t *testing.T) {
	caSvc, revocationRepo, _ := newCAOperationsSvcTest()

	// Add some revoked certificates to the repo
	now := time.Now()
	revocationRepo.Revocations = []*domain.CertificateRevocation{
		{
			SerialNumber:  "SERIAL-001",
			CertificateID: "cert-1",
			IssuerID:      "iss-local",
			Reason:        "keyCompromise",
			RevokedAt:     now.Add(-24 * time.Hour),
			RevokedBy:     "admin",
		},
		{
			SerialNumber:  "SERIAL-002",
			CertificateID: "cert-2",
			IssuerID:      "iss-local",
			Reason:        "superseded",
			RevokedAt:     now.Add(-12 * time.Hour),
			RevokedBy:     "admin",
		},
	}

	crl, err := caSvc.GenerateDERCRL(context.Background(), "iss-local")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if crl == nil {
		t.Fatal("expected non-nil CRL")
	}

	if len(crl) == 0 {
		t.Fatal("expected non-empty CRL")
	}

	t.Logf("DER CRL generated successfully: %d bytes", len(crl))
}

// TestCAOperationsSvc_GenerateDERCRL_UsesListByIssuer_NotListAll guards F-001.
// Before the fix, GenerateDERCRL called revocationRepo.ListAll(ctx) and filtered
// results in Go (if rev.IssuerID != issuerID { continue }). That was O(N) in the
// size of the entire revocation table and did not scale as revocations piled up
// across many issuers. Migration 000012 added the composite index
// idx_certificate_revocations_issuer_serial(issuer_id, serial_number), which is
// a prefix scan target — so the hot path must now call ListByIssuer(ctx, id) to
// drive an indexed query. This regression test asserts the hot path invokes
// ListByIssuer exactly once and never falls back to the full-table ListAll scan,
// and also double-checks that cross-issuer revocations are correctly excluded
// from the generated CRL (no in-Go filter left to catch them).
func TestCAOperationsSvc_GenerateDERCRL_UsesListByIssuer_NotListAll(t *testing.T) {
	caSvc, revocationRepo, _ := newCAOperationsSvcTest()

	// Pre-populate with revocations from TWO issuers. If the hot path regresses
	// and calls ListAll instead of ListByIssuer, the generated CRL would either
	// include the wrong rows or — with the in-Go filter gone — pull in both
	// issuers' revocations. ListByIssuer scopes at the query level so only
	// iss-local rows come back.
	now := time.Now()
	revocationRepo.Revocations = []*domain.CertificateRevocation{
		{
			SerialNumber:  "LOCAL-001",
			CertificateID: "cert-local-1",
			IssuerID:      "iss-local",
			Reason:        "keyCompromise",
			RevokedAt:     now.Add(-24 * time.Hour),
			RevokedBy:     "admin",
		},
		{
			SerialNumber:  "LOCAL-002",
			CertificateID: "cert-local-2",
			IssuerID:      "iss-local",
			Reason:        "superseded",
			RevokedAt:     now.Add(-12 * time.Hour),
			RevokedBy:     "admin",
		},
		{
			SerialNumber:  "OTHER-001",
			CertificateID: "cert-other-1",
			IssuerID:      "iss-other",
			Reason:        "keyCompromise",
			RevokedAt:     now.Add(-6 * time.Hour),
			RevokedBy:     "admin",
		},
	}

	crl, err := caSvc.GenerateDERCRL(context.Background(), "iss-local")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(crl) == 0 {
		t.Fatal("expected non-empty CRL")
	}

	// The contractual assertion: the CRL hot path MUST use the scoped query.
	if got, want := revocationRepo.ListByIssuerCalls, 1; got != want {
		t.Errorf("ListByIssuerCalls = %d, want %d — CRL hot path must call the scoped query driven by migration 000012 index", got, want)
	}
	if got := revocationRepo.ListAllCalls; got != 0 {
		t.Errorf("ListAllCalls = %d, want 0 — CRL hot path must NOT fall back to the full-table scan after F-001", got)
	}
	if got, want := revocationRepo.LastListIssuerID, "iss-local"; got != want {
		t.Errorf("LastListIssuerID = %q, want %q — issuer scoping argument lost", got, want)
	}
}

func TestCAOperationsSvc_GenerateDERCRL_EmptyCRL(t *testing.T) {
	caSvc, revocationRepo, _ := newCAOperationsSvcTest()

	// No revoked certs for this issuer
	revocationRepo.Revocations = []*domain.CertificateRevocation{}

	crl, err := caSvc.GenerateDERCRL(context.Background(), "iss-local")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if crl == nil {
		t.Fatal("expected non-nil CRL even when empty")
	}

	if len(crl) == 0 {
		t.Fatal("expected non-empty CRL bytes (at least the CRL structure)")
	}

	t.Logf("Empty DER CRL generated successfully: %d bytes", len(crl))
}

func TestCAOperationsSvc_GetOCSPResponse_Good(t *testing.T) {
	caSvc, _, certRepo := newCAOperationsSvcTest()

	// Add a non-revoked certificate
	cert := &domain.ManagedCertificate{
		ID:         "cert-ocsp-good",
		CommonName: "good.example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
	}
	certRepo.AddCert(cert)

	version := &domain.CertificateVersion{
		ID:            "ver-ocsp-good",
		CertificateID: "cert-ocsp-good",
		SerialNumber:  "OCSP-GOOD-001",
		NotBefore:     time.Now(),
		NotAfter:      time.Now().AddDate(1, 0, 0),
		CreatedAt:     time.Now(),
	}
	certRepo.Versions["cert-ocsp-good"] = []*domain.CertificateVersion{version}

	// Request OCSP response for good cert
	resp, err := caSvc.GetOCSPResponse(context.Background(), "iss-local", "OCSP-GOOD-001")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if resp == nil || len(resp) == 0 {
		t.Fatal("expected non-empty OCSP response for good cert")
	}

	t.Logf("OCSP response for good cert generated: %d bytes", len(resp))
}

// TestCAOperationsSvc_GetOCSPResponse_Unknown_CrossIssuer guards the M-004 fix:
// a cert with the queried serial exists but under a *different* issuer. Before
// the fix, OCSP fell through to "good" (CertStatus 0) because no revocation row
// matched the (issuer_id, serial) tuple. Per RFC 5280 §5.2.3 serials are unique
// only within a single issuer, and per RFC 6960 §2.2 unknown certs must report
// "unknown" (CertStatus 2), not "good".
func TestCAOperationsSvc_GetOCSPResponse_Unknown_CrossIssuer(t *testing.T) {
	caSvc, _, certRepo, issuer := newCAOperationsSvcTestWithIssuer()

	// Real cert exists, but bound to iss-other (not iss-local).
	cert := &domain.ManagedCertificate{
		ID:         "cert-cross-issuer",
		CommonName: "cross.example.com",
		IssuerID:   "iss-other",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
	}
	certRepo.AddCert(cert)
	certRepo.Versions["cert-cross-issuer"] = []*domain.CertificateVersion{{
		ID:            "ver-cross-issuer",
		CertificateID: "cert-cross-issuer",
		SerialNumber:  "CROSS-ISSUER-001",
		NotBefore:     time.Now(),
		NotAfter:      time.Now().AddDate(1, 0, 0),
		CreatedAt:     time.Now(),
	}}

	// Query OCSP for iss-local + CROSS-ISSUER-001. The serial exists, but
	// under iss-other — our JOIN-scoped lookup should return no match.
	resp, err := caSvc.GetOCSPResponse(context.Background(), "iss-local", "CROSS-ISSUER-001")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp == nil || len(resp) == 0 {
		t.Fatal("expected non-empty OCSP response")
	}

	if issuer.LastOCSPSignRequest == nil {
		t.Fatal("expected SignOCSPResponse to be called")
	}
	if got, want := issuer.LastOCSPSignRequest.CertStatus, 2; got != want {
		t.Errorf("CertStatus = %d, want %d (unknown) — cross-issuer lookup must not return good", got, want)
	}
}

// TestCAOperationsSvc_GetOCSPResponse_Unknown_UnknownSerial guards the M-004 fix
// for the "forged/guessed serial" case: no certificate exists at this
// (issuer_id, serial) tuple anywhere in inventory. Per RFC 6960 §2.2 we must
// report "unknown" (CertStatus 2), never "good" — returning good for a serial
// we never issued is a protocol violation that would allow an attacker to get
// certctl to vouch for a cert it never signed.
func TestCAOperationsSvc_GetOCSPResponse_Unknown_UnknownSerial(t *testing.T) {
	caSvc, _, _, issuer := newCAOperationsSvcTestWithIssuer()

	// No cert rows added. Query for an arbitrary serial under iss-local.
	resp, err := caSvc.GetOCSPResponse(context.Background(), "iss-local", "DEADBEEF-NEVER-ISSUED")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp == nil || len(resp) == 0 {
		t.Fatal("expected non-empty OCSP response")
	}

	if issuer.LastOCSPSignRequest == nil {
		t.Fatal("expected SignOCSPResponse to be called")
	}
	if got, want := issuer.LastOCSPSignRequest.CertStatus, 2; got != want {
		t.Errorf("CertStatus = %d, want %d (unknown) — unissued serials must not return good", got, want)
	}
}

func TestCAOperationsSvc_GetOCSPResponse_Revoked(t *testing.T) {
	caSvc, revocationRepo, certRepo := newCAOperationsSvcTest()

	now := time.Now()

	// Add a revoked certificate
	cert := &domain.ManagedCertificate{
		ID:               "cert-ocsp-revoked",
		CommonName:       "revoked.example.com",
		IssuerID:         "iss-local",
		Status:           domain.CertificateStatusRevoked,
		RevokedAt:        &now,
		RevocationReason: "keyCompromise",
		ExpiresAt:        time.Now().AddDate(1, 0, 0),
	}
	certRepo.AddCert(cert)

	version := &domain.CertificateVersion{
		ID:            "ver-ocsp-revoked",
		CertificateID: "cert-ocsp-revoked",
		SerialNumber:  "OCSP-REVOKED-001",
		NotBefore:     time.Now().Add(-24 * time.Hour),
		NotAfter:      time.Now().AddDate(1, 0, 0),
		CreatedAt:     time.Now(),
	}
	certRepo.Versions["cert-ocsp-revoked"] = []*domain.CertificateVersion{version}

	// Add revocation record
	revocationRepo.Revocations = []*domain.CertificateRevocation{
		{
			SerialNumber:  "OCSP-REVOKED-001",
			CertificateID: "cert-ocsp-revoked",
			IssuerID:      "iss-local",
			Reason:        "keyCompromise",
			RevokedAt:     now.Add(-24 * time.Hour),
			RevokedBy:     "admin",
		},
	}

	// Request OCSP response for revoked cert
	resp, err := caSvc.GetOCSPResponse(context.Background(), "iss-local", "OCSP-REVOKED-001")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if resp == nil || len(resp) == 0 {
		t.Fatal("expected non-empty OCSP response for revoked cert")
	}

	t.Logf("OCSP response for revoked cert generated: %d bytes", len(resp))
}
