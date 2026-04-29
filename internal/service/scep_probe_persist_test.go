package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// SCEP RFC 8894 + Intune master prompt §13 line 1859 acceptance —
// coverage uplift on the SCEP probe persistence + clamp paths. Closed
// in the 2026-04-29 audit-closure bundle (Phase H).
//
// Targets the lowest-coverage hot spots in
// internal/service/scep_probe.go (per the audit) without bloating the
// suite:
//
//   1. persistProbeResult is nil-safe + nil-repo-safe.
//   2. persistProbeResult swallows repo errors (probe stays a "best-
//      effort persist") + still surfaces them through the logger.
//   3. ListRecentSCEPProbes returns an empty slice (NOT nil) when no
//      repo is wired so JSON marshaling stays clean.
//   4. describeCertAlgorithm covers RSA/ECDSA/Ed25519/unknown branches
//      including the QF1008 nil-curve defensive branch added in
//      commit 9fcea95.

// stubSCEPProbeRepo is a controllable repository.SCEPProbeResultRepository
// used by the persist + list tests. Returns the configured insertErr +
// listResults from each Insert/ListRecent call; bumps insertCalls so the
// test can assert which probes reached the persist path.
type stubSCEPProbeRepo struct {
	insertCalls int
	insertErr   error
	listResults []*domain.SCEPProbeResult
	listLimit   int
	listErr     error
}

func (r *stubSCEPProbeRepo) Insert(_ context.Context, _ *domain.SCEPProbeResult) error {
	r.insertCalls++
	return r.insertErr
}

func (r *stubSCEPProbeRepo) ListRecent(_ context.Context, limit int) ([]*domain.SCEPProbeResult, error) {
	r.listLimit = limit
	return r.listResults, r.listErr
}

// TestPersistProbeResult_NoRepoIsNoOp verifies persistProbeResult is
// safe to call before SetSCEPProbeRepo wires a repo (the production
// startup order is: build service → wire repo). Without this, a probe
// that runs during the boot window would nil-deref.
func TestPersistProbeResult_NoRepoIsNoOp(t *testing.T) {
	s := newScepProbeServiceForTest(t)
	// Should not panic even though scepProbeRepo is nil.
	s.persistProbeResult(context.Background(), &domain.SCEPProbeResult{
		ID:        "probe-no-repo",
		TargetURL: "https://example.com/scep",
	})
}

// TestPersistProbeResult_RepoErrorDoesNotFailCaller pins the
// "best-effort persist" contract documented on persistProbeResult: a
// repo write failure MUST NOT bubble back to the probe caller (the
// probe's primary contract is "run + return," not "run + persist").
// The repo's insertCalls counter MUST still be bumped so an operator
// can prove the persist code path was reached even when it failed.
func TestPersistProbeResult_RepoErrorDoesNotFailCaller(t *testing.T) {
	repo := &stubSCEPProbeRepo{insertErr: errors.New("simulated db down")}
	s := newScepProbeServiceForTest(t)
	s.SetSCEPProbeRepo(repo)

	s.persistProbeResult(context.Background(), &domain.SCEPProbeResult{
		ID:        "probe-err",
		TargetURL: "https://example.com/scep",
	})
	if repo.insertCalls != 1 {
		t.Errorf("Insert calls = %d, want 1", repo.insertCalls)
	}

	// A logger-less service MUST also survive a repo error — the warn-
	// log branch guards on `s.logger != nil`. Walk the same code path
	// with a logger-nil service to exercise that defensive guard.
	sNoLog := &NetworkScanService{nowFn: time.Now}
	sNoLog.SetSCEPProbeRepo(repo)
	sNoLog.persistProbeResult(context.Background(), &domain.SCEPProbeResult{
		ID:        "probe-err-nologger",
		TargetURL: "https://example.com/scep",
	})
	if repo.insertCalls != 2 {
		t.Errorf("Insert calls (after nologger run) = %d, want 2", repo.insertCalls)
	}
}

// TestListRecentSCEPProbes_NilRepoReturnsEmptySlice pins the
// "JSON-clean empty" contract documented on ListRecentSCEPProbes —
// the absence of a repo MUST surface as an empty slice (not nil) so
// the GUI's JSON consumer doesn't render `null` instead of `[]`.
// Critical for the React Network Scan page that .map()s over the
// result and would crash on null.
func TestListRecentSCEPProbes_NilRepoReturnsEmptySlice(t *testing.T) {
	s := newScepProbeServiceForTest(t)
	got, err := s.ListRecentSCEPProbes(context.Background(), 50)
	if err != nil {
		t.Fatalf("ListRecentSCEPProbes (nil repo): %v", err)
	}
	if got == nil {
		t.Fatal("ListRecentSCEPProbes (nil repo) returned nil, want empty slice for JSON cleanliness")
	}
	if len(got) != 0 {
		t.Errorf("ListRecentSCEPProbes (nil repo) = %d items, want 0", len(got))
	}
}

// TestListRecentSCEPProbes_DelegatesToRepo verifies the wired-repo
// path: the limit value flows through to the repository unmodified
// (the [1, 200] clamp lives at the handler layer, not the service —
// this test pins the service is a thin pass-through).
func TestListRecentSCEPProbes_DelegatesToRepo(t *testing.T) {
	repo := &stubSCEPProbeRepo{
		listResults: []*domain.SCEPProbeResult{
			{ID: "probe-1", TargetURL: "https://a.example.com/scep"},
			{ID: "probe-2", TargetURL: "https://b.example.com/scep"},
		},
	}
	s := newScepProbeServiceForTest(t)
	s.SetSCEPProbeRepo(repo)

	got, err := s.ListRecentSCEPProbes(context.Background(), 17)
	if err != nil {
		t.Fatalf("ListRecentSCEPProbes: %v", err)
	}
	if repo.listLimit != 17 {
		t.Errorf("repo.ListRecent received limit=%d, want 17", repo.listLimit)
	}
	if len(got) != 2 {
		t.Errorf("ListRecentSCEPProbes returned %d items, want 2", len(got))
	}
}

// TestDescribeCertAlgorithm covers every documented branch of the
// describe helper — including the QF1008 nil-curve defensive guard
// added in commit 9fcea95. Walking each branch keeps the staticcheck
// fix exercised in CI so a future "simplify" never reverts the nil
// check + crashes on a malformed cert.
func TestDescribeCertAlgorithm(t *testing.T) {
	rsaCert, _ := fixtureRSACertForDescribeTest(t)
	if got, want := describeCertAlgorithm(rsaCert), "RSA-2048"; got != want {
		t.Errorf("RSA describe = %q, want %q", got, want)
	}

	ecCert, _ := fixtureCACert(t, "ec-describe", time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour))
	if got, want := describeCertAlgorithm(ecCert), "ECDSA-P-256"; got != want {
		t.Errorf("ECDSA describe = %q, want %q", got, want)
	}

	// Defensive branch: an ECDSA public key with a nil Curve. The
	// QF1008 fix keeps the explicit nil check so this case returns
	// "ECDSA" without panicking.
	bogusEC := &x509.Certificate{
		PublicKey:          &ecdsa.PublicKey{Curve: nil},
		PublicKeyAlgorithm: x509.ECDSA,
	}
	if got, want := describeCertAlgorithm(bogusEC), "ECDSA"; got != want {
		t.Errorf("nil-curve ECDSA describe = %q, want %q (QF1008 defensive branch)", got, want)
	}

	// Algorithm-only fall-through (no key type match) → Ed25519/DSA.
	ed := &x509.Certificate{PublicKeyAlgorithm: x509.Ed25519}
	if got, want := describeCertAlgorithm(ed), "Ed25519"; got != want {
		t.Errorf("Ed25519 describe = %q, want %q", got, want)
	}
	dsa := &x509.Certificate{PublicKeyAlgorithm: x509.DSA}
	if got, want := describeCertAlgorithm(dsa), "DSA"; got != want {
		t.Errorf("DSA describe = %q, want %q", got, want)
	}

	// Unrecognized → empty string (the GUI then renders "—").
	unknown := &x509.Certificate{}
	if got := describeCertAlgorithm(unknown); got != "" {
		t.Errorf("unknown describe = %q, want empty", got)
	}
}

// fixtureRSACertForDescribeTest is a tiny helper exclusive to the
// describe-algo coverage test. The package's other RSA cert helpers
// live behind type-specialized fixtures; we want a generic 2048-bit
// RSA cert + nothing else.
func fixtureRSACertForDescribeTest(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa-describe"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return parsed, key
}
