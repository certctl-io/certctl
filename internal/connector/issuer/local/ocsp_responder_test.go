package local_test

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/local"
	"github.com/shankar0123/certctl/internal/crypto/signer"
	"github.com/shankar0123/certctl/internal/domain"
)

// fakeResponderRepo is an in-memory repository.OCSPResponderRepository
// for tests that exercise the responder bootstrap path without needing
// a real Postgres + testcontainers harness. The Postgres impl is
// covered by the testcontainers tests in
// internal/repository/postgres/ocsp_responder_test.go (CI only — needs
// Docker).
type fakeResponderRepo struct {
	mu       sync.Mutex
	rows     map[string]*domain.OCSPResponder
	putCount int // bumped on every Put for assertion
	getCount int
}

func newFakeResponderRepo() *fakeResponderRepo {
	return &fakeResponderRepo{rows: map[string]*domain.OCSPResponder{}}
}

func (r *fakeResponderRepo) Get(ctx context.Context, issuerID string) (*domain.OCSPResponder, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.getCount++
	if row, ok := r.rows[issuerID]; ok {
		// Return a copy so callers can't mutate our state.
		copy := *row
		return &copy, nil
	}
	return nil, nil
}

func (r *fakeResponderRepo) Put(ctx context.Context, responder *domain.OCSPResponder) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.putCount++
	copy := *responder
	r.rows[responder.IssuerID] = &copy
	return nil
}

func (r *fakeResponderRepo) ListExpiring(ctx context.Context, grace time.Duration, now time.Time) ([]*domain.OCSPResponder, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*domain.OCSPResponder
	threshold := now.Add(grace)
	for _, row := range r.rows {
		if !row.NotAfter.After(threshold) {
			copy := *row
			out = append(out, &copy)
		}
	}
	return out, nil
}

// helper: build a Connector wired for the responder bootstrap path.
func newConnectorWithResponderDeps(t *testing.T) (*local.Connector, *fakeResponderRepo) {
	t.Helper()

	conn := local.New(&local.Config{
		CACommonName: "Test Local CA",
		ValidityDays: 30,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	repo := newFakeResponderRepo()
	driver := signer.NewMemoryDriver()

	conn.SetOCSPResponderRepo(repo)
	conn.SetSignerDriver(driver)
	conn.SetIssuerID("iss-test-local")

	return conn, repo
}

// helper: forge an OCSP request for a given serial. The local connector's
// SignOCSPResponse takes a typed request struct, not raw OCSP bytes.
func ocspReqFor(serial *big.Int, status int) issuer.OCSPSignRequest {
	now := time.Now().UTC()
	return issuer.OCSPSignRequest{
		CertSerial: serial,
		CertStatus: status,
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}
}

// ---------------------------------------------------------------------------
// Phase-2 bootstrap path coverage.
// ---------------------------------------------------------------------------

func TestSignOCSPResponse_DedicatedResponder_Bootstrapped(t *testing.T) {
	conn, repo := newConnectorWithResponderDeps(t)
	ctx := context.Background()

	respBytes, err := conn.SignOCSPResponse(ctx, ocspReqFor(big.NewInt(0xDEAD), 0))
	if err != nil {
		t.Fatalf("SignOCSPResponse: %v", err)
	}
	if len(respBytes) == 0 {
		t.Fatal("OCSP response is empty")
	}

	// Verify the responder row was persisted.
	if repo.putCount != 1 {
		t.Errorf("expected exactly 1 Put on first call, got %d", repo.putCount)
	}
	row, _ := repo.Get(ctx, "iss-test-local")
	if row == nil {
		t.Fatal("responder row was not persisted")
	}
	if row.KeyAlg != "ECDSA-P256" {
		t.Errorf("KeyAlg = %q, want ECDSA-P256 (the bootstrap default)", row.KeyAlg)
	}
	if row.NotAfter.Sub(row.NotBefore) < 24*time.Hour {
		t.Errorf("validity window too short: %v", row.NotAfter.Sub(row.NotBefore))
	}

	// Parse the responder cert and check the OCSP-specific properties.
	block, _ := pem.Decode([]byte(row.CertPEM))
	if block == nil {
		t.Fatal("responder CertPEM is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse responder cert: %v", err)
	}

	// EKU must include OCSPSigning per RFC 6960 §4.2.2.2.
	hasOCSPSigning := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			hasOCSPSigning = true
			break
		}
	}
	if !hasOCSPSigning {
		t.Error("responder cert missing ExtKeyUsageOCSPSigning")
	}

	// id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1) — verify the extension OID
	// shows up in the cert's Extensions list. The Go stdlib does not
	// promote this extension into a typed field; check ExtraExtensions
	// equivalent via the raw Extensions slice.
	noCheckOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	hasNoCheck := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(noCheckOID) {
			hasNoCheck = true
			break
		}
	}
	if !hasNoCheck {
		t.Error("responder cert missing id-pkix-ocsp-nocheck extension")
	}

	// The OCSP response should be signed by the responder cert, not by
	// the CA cert. Parse the response with the issuer cert as the trust
	// anchor — ocsp.ParseResponse reads the certificates field from the
	// response itself and verifies the chain back to issuer.
	caPEM, err := conn.GetCACertPEM(ctx)
	if err != nil {
		t.Fatalf("GetCACertPEM: %v", err)
	}
	caBlock, _ := pem.Decode([]byte(caPEM))
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	parsedResp, err := ocsp.ParseResponse(respBytes, caCert)
	if err != nil {
		t.Fatalf("ParseResponse with CA as issuer: %v", err)
	}
	if parsedResp.SerialNumber.Cmp(big.NewInt(0xDEAD)) != 0 {
		t.Errorf("response serial mismatch: got %v want %v", parsedResp.SerialNumber, 0xDEAD)
	}
	if parsedResp.Status != ocsp.Good {
		t.Errorf("response status = %d, want Good (0)", parsedResp.Status)
	}
	// The response's Certificate field should be the responder cert
	// (NOT the CA cert) — that's the proof the dedicated-responder
	// path was taken.
	if parsedResp.Certificate == nil {
		t.Fatal("OCSP response did not include the responder cert")
	}
	if parsedResp.Certificate.Subject.CommonName == caCert.Subject.CommonName {
		t.Errorf("OCSP response was signed by the CA, not by a dedicated responder cert")
	}
}

func TestSignOCSPResponse_DedicatedResponder_ReusedAcrossCalls(t *testing.T) {
	conn, repo := newConnectorWithResponderDeps(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, err := conn.SignOCSPResponse(ctx, ocspReqFor(big.NewInt(int64(i+1)), 0))
		if err != nil {
			t.Fatalf("SignOCSPResponse[%d]: %v", i, err)
		}
	}
	// Bootstrap on first call only — subsequent calls should reuse the
	// persisted responder. putCount > 1 means we re-bootstrapped (bug).
	if repo.putCount != 1 {
		t.Errorf("putCount = %d, want 1 (responder should be reused across calls)", repo.putCount)
	}
}

func TestSignOCSPResponse_FallbackPath_NoResponderDeps(t *testing.T) {
	// Construct a connector WITHOUT responder deps wired. SignOCSPResponse
	// must fall back to the historical CA-key-direct path and not error.
	conn := local.New(&local.Config{ValidityDays: 30}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	respBytes, err := conn.SignOCSPResponse(ctx, ocspReqFor(big.NewInt(0xCAFE), 0))
	if err != nil {
		t.Fatalf("fallback SignOCSPResponse: %v", err)
	}
	if len(respBytes) == 0 {
		t.Fatal("fallback OCSP response is empty")
	}
	// The fallback path uses the CA cert as the responder — the response
	// bytes parse against the CA cert successfully.
	caPEM, err := conn.GetCACertPEM(ctx)
	if err != nil {
		t.Fatalf("GetCACertPEM: %v", err)
	}
	block, _ := pem.Decode([]byte(caPEM))
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	if _, err := ocsp.ParseResponse(respBytes, caCert); err != nil {
		t.Fatalf("fallback OCSP response should validate against CA cert: %v", err)
	}
}

func TestSignOCSPResponse_DedicatedResponder_RecoversFromCorruptKeyRef(t *testing.T) {
	// Simulate the failure mode where the persisted responder row points
	// at a key the signer driver can't load (e.g., operator deleted the
	// key file out from under us). The bootstrap path should recover by
	// generating a fresh responder rather than failing the OCSP request.
	conn, repo := newConnectorWithResponderDeps(t)
	ctx := context.Background()

	// Pre-populate the repo with a stale row whose KeyPath the
	// MemoryDriver doesn't know about. MemoryDriver.Load returns an
	// "unknown ref" error for any ref it didn't issue.
	stale := &domain.OCSPResponder{
		IssuerID:   "iss-test-local",
		CertPEM:    "-----BEGIN CERTIFICATE-----\nbm90LWEtcmVhbC1jZXJ0\n-----END CERTIFICATE-----\n",
		CertSerial: "01",
		KeyPath:    "mem-NEVER-ISSUED",
		KeyAlg:     "ECDSA-P256",
		NotBefore:  time.Now().Add(-time.Hour),
		NotAfter:   time.Now().Add(30 * 24 * time.Hour), // far future, NOT in rotation grace
	}
	if err := repo.Put(ctx, stale); err != nil {
		t.Fatalf("seed stale row: %v", err)
	}
	repo.putCount = 0 // reset so the bootstrap-triggered Put is the only one we count

	// First SignOCSPResponse should detect the bad KeyPath, log a warning,
	// and bootstrap a fresh responder.
	if _, err := conn.SignOCSPResponse(ctx, ocspReqFor(big.NewInt(0xBEEF), 0)); err != nil {
		t.Fatalf("SignOCSPResponse should recover from corrupt key ref, got: %v", err)
	}
	if repo.putCount != 1 {
		t.Errorf("expected fresh bootstrap on corrupt key ref, putCount=%d", repo.putCount)
	}
	row := repo.rows["iss-test-local"]
	if row.CertSerial == "01" {
		t.Error("responder row was not replaced after corrupt key ref recovery")
	}
}

func TestSignOCSPResponse_DedicatedResponder_KeyDirSetter(t *testing.T) {
	// Pin the SetOCSPResponderKeyDir path. The MemoryDriver doesn't
	// honor the dir (it generates in-memory refs), so this is purely a
	// no-side-effect coverage pin for the setter.
	conn, _ := newConnectorWithResponderDeps(t)
	conn.SetOCSPResponderKeyDir(t.TempDir())

	if _, err := conn.SignOCSPResponse(context.Background(), ocspReqFor(big.NewInt(7), 0)); err != nil {
		t.Fatalf("SignOCSPResponse with key dir set: %v", err)
	}
}

func TestSignOCSPResponse_DedicatedResponder_RecoversFromCorruptCertPEM(t *testing.T) {
	// Companion to the corrupt-key-ref test: this time the key loads
	// fine but the persisted CertPEM is not a CERTIFICATE block. The
	// bootstrap should detect via parseSinglePEMCert and re-issue.
	conn, repo := newConnectorWithResponderDeps(t)
	ctx := context.Background()

	// Generate a real key via the MemoryDriver so the load succeeds, then
	// pair it with an INVALID cert PEM (PRIVATE KEY block instead of
	// CERTIFICATE). MemoryDriver.Generate stores the key under a fresh
	// "mem-N" ref; we capture that ref by triggering a Generate and
	// pulling the row out of the repo.
	if _, err := conn.SignOCSPResponse(ctx, ocspReqFor(big.NewInt(1), 0)); err != nil {
		t.Fatalf("seed bootstrap: %v", err)
	}
	row := repo.rows["iss-test-local"]
	row.CertPEM = "-----BEGIN PRIVATE KEY-----\nbm9wZQ==\n-----END PRIVATE KEY-----\n"
	repo.rows["iss-test-local"] = row
	repo.putCount = 0

	if _, err := conn.SignOCSPResponse(ctx, ocspReqFor(big.NewInt(2), 0)); err != nil {
		t.Fatalf("SignOCSPResponse should recover from corrupt cert PEM, got: %v", err)
	}
	if repo.putCount != 1 {
		t.Errorf("expected fresh bootstrap on corrupt cert PEM, putCount=%d", repo.putCount)
	}
}

func TestSignOCSPResponse_DedicatedResponder_RotatesWithinGrace(t *testing.T) {
	conn, repo := newConnectorWithResponderDeps(t)
	ctx := context.Background()

	// Use a short validity + matching grace so the first bootstrap
	// produces a cert that immediately falls inside the rotation
	// window on the next call. validity = 5m, grace = 10m → freshly-
	// bootstrapped cert expires in 5m which is < 10m grace → rotate.
	conn.SetOCSPResponderValidity(5 * time.Minute)
	conn.SetOCSPResponderRotationGrace(10 * time.Minute)

	if _, err := conn.SignOCSPResponse(ctx, ocspReqFor(big.NewInt(1), 0)); err != nil {
		t.Fatalf("first SignOCSPResponse: %v", err)
	}
	firstSerial := repo.rows["iss-test-local"].CertSerial

	// Second call: rotation triggers because the first cert is in the
	// grace window. The new row's RotatedFrom should equal the first
	// cert's serial.
	if _, err := conn.SignOCSPResponse(ctx, ocspReqFor(big.NewInt(2), 0)); err != nil {
		t.Fatalf("second SignOCSPResponse (rotation): %v", err)
	}
	if repo.putCount < 2 {
		t.Fatalf("expected rotation to trigger a second Put, got putCount=%d", repo.putCount)
	}
	row := repo.rows["iss-test-local"]
	if row.CertSerial == firstSerial {
		t.Errorf("CertSerial unchanged across rotation: %q", row.CertSerial)
	}
	if row.RotatedFrom != firstSerial {
		t.Errorf("RotatedFrom = %q, want %q (the first cert's serial)", row.RotatedFrom, firstSerial)
	}
}
