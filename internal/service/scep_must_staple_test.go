package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
)

// SCEP RFC 8894 + Intune master bundle Phase 5.6 follow-up: end-to-end
// integration test for the must-staple wire from CertificateProfile.MustStaple
// through the SCEPService into the IssuerConnector.
//
// Background: the original Phase 5.6 commit shipped the local issuer's RFC
// 7633 extension generation + the IssuanceRequest.MustStaple field, but
// the SCEP service layer (and EST + agent + renewal) didn't read
// profile.MustStaple and didn't pass it to IssueCertificate. That made
// CertificateProfile.MustStaple a "lying field" — the operator could set
// it, the API would store + return it, the docs claimed it worked, but
// the cert came back without the extension. Worse than not having the
// field at all.
//
// This test pins the wire end-to-end:
//
//   1. Create a CertificateProfile with MustStaple=true.
//   2. Drive a SCEP enrollment through SCEPService.PKCSReq.
//   3. Assert the mock IssuerConnector saw mustStaple=true (proving the
//      service-layer wire reaches the connector).
//
// The local-issuer-side test (must_staple_test.go) already pins that the
// connector translates that bool into the RFC 7633 extension. Together
// they prove: configurable bit → behavior change, end-to-end.

// stubProfileRepo is a minimal in-memory CertificateProfileRepository for
// the test. Returns the configured profile by ID; other repo methods
// panic if exercised (we only need Get).
type stubProfileRepo struct {
	profile *domain.CertificateProfile
}

func (s *stubProfileRepo) Get(_ context.Context, id string) (*domain.CertificateProfile, error) {
	if s.profile != nil && s.profile.ID == id {
		return s.profile, nil
	}
	return nil, nil
}

func (s *stubProfileRepo) Create(_ context.Context, _ *domain.CertificateProfile) error {
	panic("stubProfileRepo.Create not implemented for this test")
}

func (s *stubProfileRepo) Update(_ context.Context, _ *domain.CertificateProfile) error {
	panic("stubProfileRepo.Update not implemented for this test")
}

func (s *stubProfileRepo) Delete(_ context.Context, _ string) error {
	panic("stubProfileRepo.Delete not implemented for this test")
}

func (s *stubProfileRepo) List(_ context.Context) ([]*domain.CertificateProfile, error) {
	panic("stubProfileRepo.List not implemented for this test")
}

func TestSCEPService_PKCSReq_PlumbsMustStapleToIssuer(t *testing.T) {
	// 1. Mock issuer that records the must-staple bool from the call.
	mock := &mockIssuerConnector{}

	// 2. Profile with MustStaple=true.
	profile := &domain.CertificateProfile{
		ID:            "prof-must-staple",
		Name:          "must-staple",
		MaxTTLSeconds: 86400,
		MustStaple:    true,
		Enabled:       true,
	}
	repo := &stubProfileRepo{profile: profile}

	// 3. Build the service. Use a real challenge password so we exercise
	//    the same gate the production path runs.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := NewSCEPService("iss-test", mock, nil, logger, "shared-secret-123")
	svc.SetProfileRepo(repo)
	svc.SetProfileID(profile.ID)

	// 4. Build a CSR (real crypto so processEnrollment's CheckSignature
	//    + crypto-policy validation both pass).
	csrPEM := buildCSRForSCEPMustStaple(t, "must-staple.example.com")

	// 5. Drive the enrollment.
	_, err := svc.PKCSReq(context.Background(), csrPEM, "shared-secret-123", "txn-must-staple")
	if err != nil {
		t.Fatalf("PKCSReq: %v", err)
	}

	// 6. Assert the must-staple wire reached the connector.
	if !mock.LastMustStaple {
		t.Errorf("mockIssuerConnector.LastMustStaple = false, want true — service layer dropped profile.MustStaple on the floor (the 'lying field' regression)")
	}
}

func TestSCEPService_PKCSReq_NoMustStaplePropagatesFalse(t *testing.T) {
	// Companion: when the profile does NOT have MustStaple set, the
	// connector must see false. Pins the symmetric contract.
	mock := &mockIssuerConnector{LastMustStaple: true} // pre-set to true so we can detect a stuck-at-true bug
	profile := &domain.CertificateProfile{
		ID:            "prof-no-staple",
		Name:          "no-staple",
		MaxTTLSeconds: 86400,
		MustStaple:    false,
		Enabled:       true,
	}
	repo := &stubProfileRepo{profile: profile}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := NewSCEPService("iss-test", mock, nil, logger, "shared-secret-123")
	svc.SetProfileRepo(repo)
	svc.SetProfileID(profile.ID)

	csrPEM := buildCSRForSCEPMustStaple(t, "no-staple.example.com")
	_, err := svc.PKCSReq(context.Background(), csrPEM, "shared-secret-123", "txn-no-staple")
	if err != nil {
		t.Fatalf("PKCSReq: %v", err)
	}
	if mock.LastMustStaple {
		t.Errorf("mockIssuerConnector.LastMustStaple = true, want false — service layer set MustStaple=true despite profile.MustStaple=false")
	}
}

// buildCSRForSCEPMustStaple creates an ECDSA P-256 CSR for the given CN.
// Local helper — kept distinct from buildCSRForSCEP elsewhere in the
// service test suite to avoid name collisions.
func buildCSRForSCEPMustStaple(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
