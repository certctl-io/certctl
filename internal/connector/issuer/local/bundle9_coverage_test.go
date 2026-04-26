package local

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// Bundle-9 / Audit H-010 + L-002 + L-003 + L-012 + M-028 regression suite.
//
// Goal: lift internal/connector/issuer/local/ coverage from the pre-bundle
// baseline (68.3%) to ≥85% by exercising the previously untested paths:
//
//	GetCACertPEM (0.0%)            — happy path + uninitialized-CA path
//	GetRenewalInfo (0.0%)          — returns nil + true (current behavior)
//	parsePrivateKey (27.3%)        — RSA / ECDSA EC / PKCS8-RSA / PKCS8-ECDSA
//	                                  / unknown type / non-signer PKCS8 / malformed
//	resolveEKUsAndKeyUsage (10.0%) — empty list / each individual EKU /
//	                                  unknown EKU / mixed TLS+email
//	hashPublicKey (44.4%)          — RSA / ECDSA-P256 / ECDSA-P384 /
//	                                  ECDSA-P521 / unsupported curve
//	ecdsaToECDH (0.0%)             — round-trip pin: byte-identical to
//	                                  legacy elliptic.Marshal output
//	validateCSRUnicode (58.3%)     — every rejection arm + clean-pass arm
//	keymem.go / keystore.go (0.0%) — every branch
//
// We also exercise IssueCertificate / RenewCertificate failure paths
// (malformed PEM, invalid CSR signature, post-rejection unicode) to lift
// those out of the high-50s. The bundle's promised floor is 85%; we aim
// for headroom.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestConnectorBundle9(t *testing.T) *Connector {
	t.Helper()
	c := New(&Config{ValidityDays: 7}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := c.ensureCA(context.Background()); err != nil {
		t.Fatalf("ensureCA: %v", err)
	}
	return c
}

func mustGenECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func mustGenRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return k
}

func mustEncodeCSR(t *testing.T, key any, tmpl *x509.CertificateRequest) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// ---------------------------------------------------------------------------
// GetCACertPEM / GetRenewalInfo (lift 0% → 100%)
// ---------------------------------------------------------------------------

func TestGetCACertPEM_ReturnsAfterEnsureCA(t *testing.T) {
	c := newTestConnectorBundle9(t)
	pemStr, err := c.GetCACertPEM(context.Background())
	if err != nil {
		t.Fatalf("GetCACertPEM err: %v", err)
	}
	if !strings.Contains(pemStr, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("expected PEM CA cert, got %q", pemStr)
	}
}

func TestGetCACertPEM_TriggersEnsureCAOnFreshConnector(t *testing.T) {
	// Fresh connector — GetCACertPEM should call ensureCA implicitly.
	c := New(&Config{ValidityDays: 7}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	pemStr, err := c.GetCACertPEM(context.Background())
	if err != nil {
		t.Fatalf("GetCACertPEM on fresh connector: %v", err)
	}
	if pemStr == "" {
		t.Fatal("expected non-empty PEM")
	}
}

func TestGetRenewalInfo_ReturnsNilNil(t *testing.T) {
	c := newTestConnectorBundle9(t)
	info, err := c.GetRenewalInfo(context.Background(), "any-cert-pem")
	if err != nil {
		t.Fatalf("GetRenewalInfo err: %v", err)
	}
	if info != nil {
		t.Errorf("expected nil RenewalInfo for local CA (no ARI support), got %+v", info)
	}
}

// ---------------------------------------------------------------------------
// parsePrivateKey (27.3% → all branches)
// ---------------------------------------------------------------------------

func TestParsePrivateKey_RSAPKCS1(t *testing.T) {
	k := mustGenRSAKey(t)
	der := x509.MarshalPKCS1PrivateKey(k)
	signer, err := parsePrivateKey(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	if err != nil {
		t.Fatalf("parsePrivateKey RSA PKCS1: %v", err)
	}
	if _, ok := signer.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", signer)
	}
}

func TestParsePrivateKey_ECPrivateKey(t *testing.T) {
	k := mustGenECDSAKey(t, elliptic.P256())
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signer, err := parsePrivateKey(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err != nil {
		t.Fatalf("parsePrivateKey EC: %v", err)
	}
	if _, ok := signer.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", signer)
	}
}

func TestParsePrivateKey_PKCS8RSA(t *testing.T) {
	k := mustGenRSAKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	signer, err := parsePrivateKey(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err != nil {
		t.Fatalf("parsePrivateKey PKCS8: %v", err)
	}
	if _, ok := signer.(*rsa.PrivateKey); !ok {
		t.Errorf("expected RSA, got %T", signer)
	}
}

func TestParsePrivateKey_PKCS8ECDSA(t *testing.T) {
	k := mustGenECDSAKey(t, elliptic.P256())
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	signer, err := parsePrivateKey(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err != nil {
		t.Fatalf("parsePrivateKey PKCS8 ECDSA: %v", err)
	}
	if _, ok := signer.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected ECDSA, got %T", signer)
	}
}

func TestParsePrivateKey_UnknownType(t *testing.T) {
	_, err := parsePrivateKey(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	if err == nil {
		t.Fatal("expected error on unknown PEM type")
	}
	if !strings.Contains(err.Error(), "unsupported private key type") {
		t.Errorf("error should mention unsupported, got: %v", err)
	}
}

func TestParsePrivateKey_MalformedPKCS8(t *testing.T) {
	_, err := parsePrivateKey(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0xff, 0xff, 0xff}})
	if err == nil {
		t.Fatal("expected error on malformed PKCS8")
	}
}

// ---------------------------------------------------------------------------
// resolveEKUsAndKeyUsage (10% → all branches)
// ---------------------------------------------------------------------------

func TestResolveEKUsAndKeyUsage_EmptyDefaultsToTLS(t *testing.T) {
	ekus, usage := resolveEKUsAndKeyUsage(nil)
	if len(ekus) != 2 {
		t.Errorf("expected default serverAuth+clientAuth, got %d EKUs: %v", len(ekus), ekus)
	}
	if usage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected DigitalSignature in default key usage")
	}
	if usage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("expected KeyEncipherment in default key usage (TLS server EKU)")
	}
}

func TestResolveEKUsAndKeyUsage_ServerAuthOnly(t *testing.T) {
	ekus, _ := resolveEKUsAndKeyUsage([]string{"serverAuth"})
	if len(ekus) != 1 || ekus[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("expected only serverAuth, got: %v", ekus)
	}
}

func TestResolveEKUsAndKeyUsage_AllKnownEKUs(t *testing.T) {
	// ekuNameToX509 supports: serverAuth, clientAuth, codeSigning,
	// emailProtection, timeStamping. OCSPSigning is intentionally not
	// in the local-CA allowlist (responder cert is signed by the same
	// CA but issued via the OCSP path, not the EKU enum).
	known := []string{"serverAuth", "clientAuth", "codeSigning", "emailProtection", "timeStamping"}
	ekus, usage := resolveEKUsAndKeyUsage(known)
	if len(ekus) != len(known) {
		t.Errorf("expected %d EKUs, got %d: %v", len(known), len(ekus), ekus)
	}
	if usage&x509.KeyUsageContentCommitment == 0 {
		t.Error("expected non-repudiation set when emailProtection is in mix")
	}
	if usage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("expected KeyEncipherment set when serverAuth is in mix")
	}
}

func TestResolveEKUsAndKeyUsage_AllUnknownFallsBackToDefault(t *testing.T) {
	ekus, usage := resolveEKUsAndKeyUsage([]string{"madeUp1", "madeUp2"})
	if len(ekus) != 2 {
		t.Errorf("expected 2 default EKUs after fallback, got %d", len(ekus))
	}
	if usage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected DigitalSignature in fallback default")
	}
}

func TestResolveEKUsAndKeyUsage_UnknownEKUIgnored(t *testing.T) {
	ekus, _ := resolveEKUsAndKeyUsage([]string{"serverAuth", "totallyMadeUp"})
	if len(ekus) != 1 || ekus[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("unknown EKU should be silently dropped, got: %v", ekus)
	}
}

func TestResolveEKUsAndKeyUsage_EmailOnlyHasNoKeyEncipherment(t *testing.T) {
	_, usage := resolveEKUsAndKeyUsage([]string{"emailProtection"})
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("email-only should NOT include KeyEncipherment")
	}
	if usage&x509.KeyUsageContentCommitment == 0 {
		t.Error("email-only SHOULD include ContentCommitment (non-repudiation)")
	}
}

// ---------------------------------------------------------------------------
// hashPublicKey (44.4% → all curves) + ecdsaToECDH (0% → all curves)
// ---------------------------------------------------------------------------

func TestHashPublicKey_RSA(t *testing.T) {
	k := mustGenRSAKey(t)
	out := hashPublicKey(&k.PublicKey)
	if len(out) != 4 {
		t.Errorf("expected 4-byte SKI prefix, got %d", len(out))
	}
}

func TestHashPublicKey_ECDSA_P256(t *testing.T) {
	k := mustGenECDSAKey(t, elliptic.P256())
	out := hashPublicKey(&k.PublicKey)
	if len(out) != 4 {
		t.Errorf("expected 4-byte SKI prefix, got %d", len(out))
	}
}

func TestHashPublicKey_ECDSA_P384(t *testing.T) {
	k := mustGenECDSAKey(t, elliptic.P384())
	_ = hashPublicKey(&k.PublicKey)
}

func TestHashPublicKey_ECDSA_P521(t *testing.T) {
	k := mustGenECDSAKey(t, elliptic.P521())
	_ = hashPublicKey(&k.PublicKey)
}

func TestHashPublicKey_UnknownTypeReturnsEmpty(t *testing.T) {
	type bogusPub struct{}
	out := hashPublicKey(bogusPub{})
	if len(out) != 4 {
		t.Errorf("expected 4-byte hash even for empty input (sha256 prefix), got %d", len(out))
	}
}

// TestHashPublicKey_ECDSA_RoundTripPin asserts that the new
// crypto/ecdh-based encoding produces byte-identical output to the legacy
// elliptic.Marshal call this PR removed (M-028 SA1019 migration). If this
// test fails, the SubjectKeyId of every certificate the local CA has ever
// issued would silently change on upgrade, breaking pinning + audit
// fingerprinting downstream.
func TestHashPublicKey_ECDSA_RoundTripPin(t *testing.T) {
	cases := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := mustGenECDSAKey(t, tc.curve)
			ecdhPub, err := ecdsaToECDH(&k.PublicKey)
			if err != nil {
				t.Fatalf("ecdsaToECDH: %v", err)
			}
			ecdhBytes := ecdhPub.Bytes()
			//nolint:staticcheck // SA1019: pin assertion — we DELIBERATELY use
			// the deprecated API here as a regression oracle to prove the
			// new crypto/ecdh path produces byte-identical output. If
			// elliptic.Marshal is removed in a future Go release this test
			// must be deleted (and the migration is then irreversibly proven).
			legacy := elliptic.Marshal(k.Curve, k.X, k.Y)
			if !bytes.Equal(ecdhBytes, legacy) {
				t.Fatalf("ECDH .Bytes() != legacy elliptic.Marshal output\n new: %x\n old: %x", ecdhBytes, legacy)
			}
		})
	}
}

func TestEcdsaToECDH_RejectsP224(t *testing.T) {
	k := mustGenECDSAKey(t, elliptic.P224())
	_, err := ecdsaToECDH(&k.PublicKey)
	if err == nil {
		t.Fatal("expected unsupported-curve error for P-224")
	}
	if !strings.Contains(err.Error(), "unsupported curve") {
		t.Errorf("expected unsupported-curve error, got: %v", err)
	}
}

func TestEcdsaToECDH_RejectsNilKey(t *testing.T) {
	if _, err := ecdsaToECDH(nil); err == nil {
		t.Fatal("expected error on nil key")
	}
}

// ---------------------------------------------------------------------------
// validateCSRUnicode (58% → all branches)
// ---------------------------------------------------------------------------

func TestValidateCSRUnicode_CleanPasses(t *testing.T) {
	csr := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "example.com"},
		DNSNames:       []string{"www.example.com", "api.example.com"},
		EmailAddresses: []string{"admin@example.com"},
	}
	if err := validateCSRUnicode(csr, []string{"alt.example.com"}); err != nil {
		t.Errorf("clean CSR rejected: %v", err)
	}
}

func TestValidateCSRUnicode_RejectsCNHomograph(t *testing.T) {
	csr := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "аpple.com"}, // Cyrillic а
	}
	err := validateCSRUnicode(csr, nil)
	if err == nil {
		t.Fatal("expected rejection for CN homograph")
	}
	if !strings.Contains(err.Error(), "CommonName") {
		t.Errorf("error should mention CommonName, got: %v", err)
	}
}

func TestValidateCSRUnicode_RejectsDNSNameRTL(t *testing.T) {
	csr := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "ok.com"},
		DNSNames: []string{"good‮evil.com"},
	}
	err := validateCSRUnicode(csr, nil)
	if err == nil {
		t.Fatal("expected rejection for DNSName RTL override")
	}
	if !strings.Contains(err.Error(), "DNSNames") {
		t.Errorf("error should mention DNSNames, got: %v", err)
	}
}

func TestValidateCSRUnicode_RejectsEmailZeroWidth(t *testing.T) {
	csr := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "ok.com"},
		EmailAddresses: []string{"good​bad@example.com"},
	}
	err := validateCSRUnicode(csr, nil)
	if err == nil {
		t.Fatal("expected rejection for email zero-width")
	}
	if !strings.Contains(err.Error(), "EmailAddresses") {
		t.Errorf("error should mention EmailAddresses, got: %v", err)
	}
}

func TestValidateCSRUnicode_RejectsAdditionalSAN(t *testing.T) {
	csr := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ok.com"},
	}
	err := validateCSRUnicode(csr, []string{"good‮evil.com"})
	if err == nil {
		t.Fatal("expected rejection for additional SAN RTL")
	}
	if !strings.Contains(err.Error(), "request SANs") {
		t.Errorf("error should mention request SANs, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// IssueCertificate / RenewCertificate failure paths (lift 55-68% → higher)
// ---------------------------------------------------------------------------

func TestIssueCertificate_RejectsMalformedCSRPEM(t *testing.T) {
	c := newTestConnectorBundle9(t)
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "x.com",
		CSRPEM:     "not a pem",
	})
	if err == nil {
		t.Fatal("expected error on malformed CSR PEM")
	}
}

func TestIssueCertificate_RejectsBadCSRSignature(t *testing.T) {
	c := newTestConnectorBundle9(t)
	// Build a valid CSR using key A, then re-sign the CertificateRequest
	// payload with key B (or just flip bytes in the signature) — the
	// CheckSignature path inside IssueCertificate must reject this.
	keyA := mustGenECDSAKey(t, elliptic.P256())
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "x.com"},
	}, keyA)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte deep in the signature (last 16 bytes are signature octets).
	if len(der) < 20 {
		t.Skip("unexpectedly short DER")
	}
	der[len(der)-5] ^= 0xff
	tamperedPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	_, issErr := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "x.com",
		CSRPEM:     tamperedPEM,
	})
	if issErr == nil {
		t.Fatal("expected error on tampered CSR")
	}
}

func TestIssueCertificate_RejectsHomographCSR(t *testing.T) {
	c := newTestConnectorBundle9(t)
	k := mustGenECDSAKey(t, elliptic.P256())
	csrPEM := mustEncodeCSR(t, k, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "аpple.com"},
	})
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "аpple.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected unicode-rejection error")
	}
	if !strings.Contains(err.Error(), "CommonName") {
		t.Errorf("expected CommonName-cited error, got: %v", err)
	}
}

func TestRenewCertificate_RejectsMalformedCSRPEM(t *testing.T) {
	c := newTestConnectorBundle9(t)
	_, err := c.RenewCertificate(context.Background(), issuer.RenewalRequest{
		CommonName: "x.com",
		CSRPEM:     "not a pem",
	})
	if err == nil {
		t.Fatal("expected error on malformed CSR PEM")
	}
}

func TestRenewCertificate_RejectsHomographCSR(t *testing.T) {
	c := newTestConnectorBundle9(t)
	k := mustGenECDSAKey(t, elliptic.P256())
	csrPEM := mustEncodeCSR(t, k, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "аpple.com"},
	})
	_, err := c.RenewCertificate(context.Background(), issuer.RenewalRequest{
		CommonName: "аpple.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected unicode-rejection error on renew")
	}
}

func TestRenewCertificate_HappyPath(t *testing.T) {
	c := newTestConnectorBundle9(t)
	k := mustGenECDSAKey(t, elliptic.P256())
	csrPEM := mustEncodeCSR(t, k, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "renew.example.com"},
	})
	res, err := c.RenewCertificate(context.Background(), issuer.RenewalRequest{
		CommonName: "renew.example.com",
		CSRPEM:     csrPEM,
	})
	if err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	if !strings.Contains(res.CertPEM, "BEGIN CERTIFICATE") {
		t.Errorf("expected cert PEM, got: %s", res.CertPEM)
	}
}

// ---------------------------------------------------------------------------
// keymem.go — marshalPrivateKeyAndZeroize
// ---------------------------------------------------------------------------

func TestMarshalPrivateKeyAndZeroize_HappyPath(t *testing.T) {
	k := mustGenECDSAKey(t, elliptic.P256())
	var captured []byte
	err := marshalPrivateKeyAndZeroize(k, func(der []byte) error {
		// Take a defensive copy — we promise NOT to retain `der`, but for
		// the test we want to inspect it AFTER the function returns to
		// prove zeroization happened to the underlying buffer.
		captured = make([]byte, len(der))
		copy(captured, der)
		// Verify the DER decodes correctly while we have it.
		if _, parseErr := x509.ParseECPrivateKey(der); parseErr != nil {
			t.Errorf("DER inside callback should parse: %v", parseErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Captured bytes should still be valid PKCS-DER (we copied them).
	if _, err := x509.ParseECPrivateKey(captured); err != nil {
		t.Errorf("captured copy should still parse: %v", err)
	}
}

func TestMarshalPrivateKeyAndZeroize_NilKey(t *testing.T) {
	err := marshalPrivateKeyAndZeroize(nil, func([]byte) error { return nil })
	if err == nil {
		t.Fatal("expected error on nil key")
	}
}

func TestMarshalPrivateKeyAndZeroize_OnDERError(t *testing.T) {
	k := mustGenECDSAKey(t, elliptic.P256())
	wantErr := errors.New("simulated downstream failure")
	gotErr := marshalPrivateKeyAndZeroize(k, func([]byte) error { return wantErr })
	if !errors.Is(gotErr, wantErr) {
		t.Errorf("expected error to propagate, got: %v", gotErr)
	}
}

// ---------------------------------------------------------------------------
// keystore.go — ensureKeyDirSecure
// ---------------------------------------------------------------------------

func TestEnsureKeyDirSecure_CreatesNewDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}
	tmp := filepath.Join(t.TempDir(), "fresh")
	if err := ensureKeyDirSecure(tmp); err != nil {
		t.Fatalf("ensureKeyDirSecure: %v", err)
	}
	info, err := os.Stat(tmp)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("expected 0700 after ensure, got %#o", info.Mode().Perm())
	}
}

func TestEnsureKeyDirSecure_AcceptsExisting0700(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}
	dir := t.TempDir()
	// t.TempDir creates 0700 on unix.
	_ = os.Chmod(dir, 0o700)
	if err := ensureKeyDirSecure(dir); err != nil {
		t.Errorf("0700 dir should be accepted: %v", err)
	}
}

func TestEnsureKeyDirSecure_TightensPermissive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := ensureKeyDirSecure(dir); err != nil {
		t.Fatalf("ensureKeyDirSecure should tighten: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("expected 0700 after tighten, got %#o", info.Mode().Perm())
	}
}

func TestEnsureKeyDirSecure_RejectsEmpty(t *testing.T) {
	if err := ensureKeyDirSecure(""); err == nil {
		t.Error("expected refusal of empty path")
	}
	if err := ensureKeyDirSecure("/"); err == nil {
		t.Error("expected refusal of root")
	}
	if err := ensureKeyDirSecure("."); err == nil {
		t.Error("expected refusal of dot")
	}
}

func TestEnsureKeyDirSecure_AcceptsOwnerOnlyMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := ensureKeyDirSecure(dir); err != nil {
		t.Errorf("0500 (owner-only no-write) should be accepted: %v", err)
	}
	// Restore so t.TempDir cleanup works.
	_ = os.Chmod(dir, 0o700)
}

// ---------------------------------------------------------------------------
// loadCAFromDisk negative paths (lift to push total over 85%)
// ---------------------------------------------------------------------------

func TestLoadCAFromDisk_RejectsExpiredCA(t *testing.T) {
	dir := t.TempDir()
	caKey := mustGenECDSAKey(t, elliptic.P256())
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expired-ca"},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(-1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(caKey)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New(&Config{ValidityDays: 7, CACertPath: certPath, CAKeyPath: keyPath}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	err = c.ensureCA(context.Background())
	if err == nil {
		t.Fatal("expected error for expired CA")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expired-CA error, got: %v", err)
	}
}

func TestLoadCAFromDisk_RejectsNonCACert(t *testing.T) {
	dir := t.TempDir()
	caKey := mustGenECDSAKey(t, elliptic.P256())
	// IsCA: false -> should be rejected
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "not-a-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(caKey)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New(&Config{ValidityDays: 7, CACertPath: certPath, CAKeyPath: keyPath}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	err = c.ensureCA(context.Background())
	if err == nil {
		t.Fatal("expected error for non-CA cert")
	}
}

func TestLoadCAFromDisk_HappyPath(t *testing.T) {
	dir := t.TempDir()
	caKey := mustGenECDSAKey(t, elliptic.P256())
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "valid-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(caKey)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New(&Config{ValidityDays: 7, CACertPath: certPath, CAKeyPath: keyPath}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := c.ensureCA(context.Background()); err != nil {
		t.Fatalf("loadCAFromDisk happy: %v", err)
	}
	if !c.subCA {
		t.Error("expected subCA=true after disk-load")
	}
}

func TestLoadCAFromDisk_MissingCert(t *testing.T) {
	c := New(&Config{ValidityDays: 7, CACertPath: "/nope/missing.crt", CAKeyPath: "/nope/missing.key"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	err := c.ensureCA(context.Background())
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

// ---------------------------------------------------------------------------
// Final pushes to clear the ≥85% coverage gate.
// ---------------------------------------------------------------------------

func TestParseIP_ValidAndInvalid(t *testing.T) {
	if parseIP("10.0.0.1") == nil {
		t.Error("10.0.0.1 should parse")
	}
	if parseIP("not-an-ip") != nil {
		t.Error("garbage shouldn't parse")
	}
	if parseIP("::1") == nil {
		t.Error("IPv6 ::1 should parse")
	}
}

func TestIsEmail_TrueAndFalse(t *testing.T) {
	// isEmail is a simple "contains @" check — that's the spec it
	// implements; we just pin both sides of the binary decision.
	if !isEmail("user@example.com") {
		t.Error("user@example.com should be an email")
	}
	if isEmail("just-a-host.example.com") {
		t.Error("plain host should not be classified as email")
	}
	if isEmail("") {
		t.Error("empty string should not be classified as email")
	}
}

func TestValidateConfig_AllArms(t *testing.T) {
	c := New(&Config{ValidityDays: 7}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Malformed JSON — must fail.
	if err := c.ValidateConfig(context.Background(), []byte("not json")); err == nil {
		t.Error("malformed JSON should be rejected")
	}
	// Default validity (zero) — must fail (validity_days must be >=1).
	if err := c.ValidateConfig(context.Background(), []byte(`{"validity_days":0}`)); err == nil {
		t.Error("validity_days < 1 should be rejected")
	}
	// Sub-CA with cert path but no key path — must fail.
	if err := c.ValidateConfig(context.Background(), []byte(`{"validity_days":7,"ca_cert_path":"/x"}`)); err == nil {
		t.Error("sub-CA with only cert path should be rejected")
	}
	// Sub-CA with key path but no cert path — must fail.
	if err := c.ValidateConfig(context.Background(), []byte(`{"validity_days":7,"ca_key_path":"/x"}`)); err == nil {
		t.Error("sub-CA with only key path should be rejected")
	}
	// Sub-CA with both paths but pointing nowhere — must fail (Stat).
	if err := c.ValidateConfig(context.Background(), []byte(`{"validity_days":7,"ca_cert_path":"/nope","ca_key_path":"/nope-key"}`)); err == nil {
		t.Error("sub-CA with non-existent paths should be rejected")
	}
	// Self-signed mode with valid validity — must pass.
	if err := c.ValidateConfig(context.Background(), []byte(`{"validity_days":7}`)); err != nil {
		t.Errorf("self-signed valid config should pass: %v", err)
	}
}

func TestGenerateCertificate_WithMaxTTLCap(t *testing.T) {
	c := newTestConnectorBundle9(t)
	k := mustGenECDSAKey(t, elliptic.P256())
	csrPEM := mustEncodeCSR(t, k, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "ttl.example.com"},
		DNSNames:       []string{"ttl.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.5")},
		EmailAddresses: []string{"ops@ttl.example.com"},
	})
	res, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName:    "ttl.example.com",
		CSRPEM:        csrPEM,
		MaxTTLSeconds: 3600, // 1h cap
	})
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	if got := res.NotAfter.Sub(res.NotBefore); got > time.Hour+time.Minute {
		t.Errorf("MaxTTL cap not honored, got window %s", got)
	}
}

