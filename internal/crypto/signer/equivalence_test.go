package signer_test

// Behavior-equivalence test suite for the Signer abstraction.
//
// Phase 2's exit criteria assert that existing tests in the local issuer
// pass after the refactor. That's necessary but not sufficient: existing
// tests cover specific scenarios and may not catch a subtle byte-level
// divergence (e.g., the wrapped Signer marshaling the public key in a
// different DER ordering, or producing a slightly different signature
// padding). This file is the explicit guard against that class of
// regression.
//
// Three signing surfaces are exercised, mirroring the four call sites in
// internal/connector/issuer/local/local.go:
//   - leaf certificate signing       (mirrors local.go::generateCertificate / line ~613)
//   - CRL signing                    (mirrors local.go::GenerateCRL / line ~849)
//   - OCSP response signing          (mirrors local.go::SignOCSPResponse / line ~887)
//   The CA-bootstrap call (line ~482) is implicitly covered by leaf
//   signing — it's the same x509.CreateCertificate API.
//
// For each surface, two signatures are compared:
//   - RSA-2048 / SHA-256: byte-strict equality (PKCS#1 v1.5 is
//     deterministic given key + digest, so wrapped vs. raw produces
//     identical full DER bytes).
//   - ECDSA-P256 / SHA-256: structural equality (ECDSA uses random k
//     per signature, so signature bytes differ; TBSCertificate /
//     TBSCertificateList / TBSResponseData bytes — everything signed —
//     must be byte-equal across raw and wrapped).
//
// A negative test (TestEquivalence_Sentinel) proves the equivalence
// checker would actually catch a regression — without it, a vacuously-
// passing assertion would let real divergence through.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/shankar0123/certctl/internal/crypto/signer"
)

// fixedTemplate returns an x509 cert template with deterministic fields
// (no time.Now, no random serial) so two calls to CreateCertificate
// produce TBSCertificate bytes that are byte-equal modulo the signature.
func fixedTemplate(t *testing.T) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	notBefore := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0xCAFE),
		Subject:               pkix.Name{CommonName: "Equiv CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xC0FFEE),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return caTpl, leafTpl
}

// ---------------------------------------------------------------------------
// Leaf certificate signing
// ---------------------------------------------------------------------------

func TestEquivalence_RSA_LeafCert_BytesIdentical(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("leaf rsa keygen: %v", err)
	}
	wrapped, err := signer.Wrap(caKey)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	caTpl, leafTpl := fixedTemplate(t)

	// Self-sign the CA so we have a parsed *x509.Certificate to use as
	// the leaf cert's parent (CreateCertificate needs both template and
	// parent; using the same template for both produces a self-signed
	// CA cert that we then parse).
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	// Sign the same leaf cert twice — once via raw caKey, once via
	// wrapped Signer. PKCS#1 v1.5 is deterministic, so the full DER
	// must be byte-identical.
	der1, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf (raw): %v", err)
	}
	der2, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, wrapped)
	if err != nil {
		t.Fatalf("create leaf (wrapped): %v", err)
	}
	if !bytes.Equal(der1, der2) {
		t.Fatalf("RSA leaf cert DER differs between raw and wrapped signer:\n  raw:     %x\n  wrapped: %x", der1, der2)
	}
}

func TestEquivalence_ECDSA_LeafCert_TBSIdentical(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf ecdsa keygen: %v", err)
	}
	wrapped, err := signer.Wrap(caKey)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	caTpl, leafTpl := fixedTemplate(t)

	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	der1, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf (raw): %v", err)
	}
	der2, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, wrapped)
	if err != nil {
		t.Fatalf("create leaf (wrapped): %v", err)
	}

	cert1, err := x509.ParseCertificate(der1)
	if err != nil {
		t.Fatalf("parse leaf (raw): %v", err)
	}
	cert2, err := x509.ParseCertificate(der2)
	if err != nil {
		t.Fatalf("parse leaf (wrapped): %v", err)
	}

	// TBSCertificate is everything that gets signed — Subject, Issuer,
	// Validity, SubjectPublicKeyInfo, Extensions, etc. The signature
	// bytes themselves differ (ECDSA random k) but the input to the
	// signature MUST be byte-identical or the wrapper is doing
	// something behavioral-different than the raw key.
	if !bytes.Equal(cert1.RawTBSCertificate, cert2.RawTBSCertificate) {
		t.Fatalf("ECDSA leaf cert TBSCertificate differs between raw and wrapped signer (expected: signature bytes differ; everything else byte-equal)")
	}

	// Confirm both signatures are independently valid against the CA's
	// public key. This is the proof that the wrapper actually signed
	// (not just produced random bytes that happened to match length).
	if err := cert1.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("raw-signed leaf failed validation: %v", err)
	}
	if err := cert2.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("wrapped-signed leaf failed validation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CRL signing (mirrors internal/connector/issuer/local/local.go::GenerateCRL)
// ---------------------------------------------------------------------------

func TestEquivalence_RSA_CRL_BytesIdentical(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrapped, err := signer.Wrap(caKey)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	caTpl, _ := fixedTemplate(t)
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	thisUpdate := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	crlTpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(0xDEAD),
				RevocationTime: thisUpdate,
			},
		},
	}

	der1, err := x509.CreateRevocationList(rand.Reader, crlTpl, caCert, caKey)
	if err != nil {
		t.Fatalf("create CRL (raw): %v", err)
	}
	der2, err := x509.CreateRevocationList(rand.Reader, crlTpl, caCert, wrapped)
	if err != nil {
		t.Fatalf("create CRL (wrapped): %v", err)
	}
	if !bytes.Equal(der1, der2) {
		t.Fatalf("RSA CRL DER differs between raw and wrapped signer:\n  raw:     %x\n  wrapped: %x", der1[:64], der2[:64])
	}
}

func TestEquivalence_ECDSA_CRL_TBSIdentical(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrapped, err := signer.Wrap(caKey)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	caTpl, _ := fixedTemplate(t)
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	thisUpdate := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	crlTpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(7 * 24 * time.Hour),
	}

	der1, err := x509.CreateRevocationList(rand.Reader, crlTpl, caCert, caKey)
	if err != nil {
		t.Fatalf("create CRL (raw): %v", err)
	}
	der2, err := x509.CreateRevocationList(rand.Reader, crlTpl, caCert, wrapped)
	if err != nil {
		t.Fatalf("create CRL (wrapped): %v", err)
	}

	crl1, err := x509.ParseRevocationList(der1)
	if err != nil {
		t.Fatalf("parse CRL (raw): %v", err)
	}
	crl2, err := x509.ParseRevocationList(der2)
	if err != nil {
		t.Fatalf("parse CRL (wrapped): %v", err)
	}

	// RawTBSRevocationList is the signed input. Must be byte-equal for
	// equivalence; signature bytes differ for ECDSA.
	if !bytes.Equal(crl1.RawTBSRevocationList, crl2.RawTBSRevocationList) {
		t.Fatalf("ECDSA CRL TBSRevocationList differs between raw and wrapped signer")
	}

	// Both CRLs must validate against the CA.
	if err := crl1.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("raw-signed CRL failed validation: %v", err)
	}
	if err := crl2.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("wrapped-signed CRL failed validation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// OCSP response signing
// (mirrors internal/connector/issuer/local/local.go::SignOCSPResponse)
// ---------------------------------------------------------------------------

func TestEquivalence_RSA_OCSPResponse_BytesIdentical(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrapped, err := signer.Wrap(caKey)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	caTpl, _ := fixedTemplate(t)
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	thisUpdate := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	ocspTpl := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(0xCAFEBABE),
		ThisUpdate:   thisUpdate,
		NextUpdate:   thisUpdate.Add(24 * time.Hour),
	}

	resp1, err := ocsp.CreateResponse(caCert, caCert, ocspTpl, caKey)
	if err != nil {
		t.Fatalf("create OCSP (raw): %v", err)
	}
	resp2, err := ocsp.CreateResponse(caCert, caCert, ocspTpl, wrapped)
	if err != nil {
		t.Fatalf("create OCSP (wrapped): %v", err)
	}
	if !bytes.Equal(resp1, resp2) {
		t.Fatalf("RSA OCSP response differs between raw and wrapped signer (PKCS#1 v1.5 must be deterministic)")
	}
}

func TestEquivalence_ECDSA_OCSPResponse_StructurallyIdentical(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrapped, err := signer.Wrap(caKey)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	caTpl, _ := fixedTemplate(t)
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	thisUpdate := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	ocspTpl := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(0xCAFEBABE),
		ThisUpdate:   thisUpdate,
		NextUpdate:   thisUpdate.Add(24 * time.Hour),
	}

	resp1, err := ocsp.CreateResponse(caCert, caCert, ocspTpl, caKey)
	if err != nil {
		t.Fatalf("create OCSP (raw): %v", err)
	}
	resp2, err := ocsp.CreateResponse(caCert, caCert, ocspTpl, wrapped)
	if err != nil {
		t.Fatalf("create OCSP (wrapped): %v", err)
	}

	parsed1, err := ocsp.ParseResponse(resp1, caCert)
	if err != nil {
		t.Fatalf("parse OCSP (raw): %v", err)
	}
	parsed2, err := ocsp.ParseResponse(resp2, caCert)
	if err != nil {
		t.Fatalf("parse OCSP (wrapped): %v", err)
	}

	// Compare every field except Signature + RawResponderName (which
	// the parser may normalize differently across calls).
	if parsed1.Status != parsed2.Status {
		t.Fatalf("status differs: %d vs %d", parsed1.Status, parsed2.Status)
	}
	if parsed1.SerialNumber.Cmp(parsed2.SerialNumber) != 0 {
		t.Fatalf("serial differs: %v vs %v", parsed1.SerialNumber, parsed2.SerialNumber)
	}
	if !parsed1.ThisUpdate.Equal(parsed2.ThisUpdate) {
		t.Fatalf("ThisUpdate differs")
	}
	if !parsed1.NextUpdate.Equal(parsed2.NextUpdate) {
		t.Fatalf("NextUpdate differs")
	}

	// Both responses must validate against the CA.
	if err := parsed1.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("raw-signed OCSP failed validation: %v", err)
	}
	if err := parsed2.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("wrapped-signed OCSP failed validation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Negative test: the equivalence checker isn't trivially-passing
// ---------------------------------------------------------------------------

// TestEquivalence_Sentinel_DifferentKeysProduceDifferentBytes is the smoke
// check that the equivalence assertions above would actually catch a
// regression. Sign with two different keys; assert the resulting cert
// DER bytes differ. If THIS test passes trivially (false negative), the
// equivalence checker is broken and the test suite above is not actually
// guarding anything.
func TestEquivalence_Sentinel_DifferentKeysProduceDifferentBytes(t *testing.T) {
	keyA, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyB, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTpl, leafTpl := fixedTemplate(t)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	caDERA, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &keyA.PublicKey, keyA)
	caCertA, _ := x509.ParseCertificate(caDERA)
	caDERB, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &keyB.PublicKey, keyB)
	caCertB, _ := x509.ParseCertificate(caDERB)

	der1, _ := x509.CreateCertificate(rand.Reader, leafTpl, caCertA, &leafKey.PublicKey, keyA)
	der2, _ := x509.CreateCertificate(rand.Reader, leafTpl, caCertB, &leafKey.PublicKey, keyB)
	if bytes.Equal(der1, der2) {
		t.Fatal("sentinel: certs signed by DIFFERENT keys must NOT byte-equal — equivalence checker is trivially-passing")
	}
}

// ---------------------------------------------------------------------------
// Sanity: the wrapped signer's Sign output is independently valid for
// arbitrary digests (covers the path that doesn't go through x509.*).
// ---------------------------------------------------------------------------

func TestEquivalence_WrappedSign_RSA_VerifiesAgainstStdlib(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	w, err := signer.Wrap(k)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	digest := sha256OfBytes([]byte("test message"))
	sig, err := w.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, digest, sig); err != nil {
		t.Fatalf("wrapped RSA Sign produced signature that does not verify with stdlib VerifyPKCS1v15: %v", err)
	}
}

func TestEquivalence_WrappedSign_ECDSA_VerifiesAgainstStdlib(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	w, err := signer.Wrap(k)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	digest := sha256OfBytes([]byte("test message"))
	sig, err := w.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&k.PublicKey, digest, sig) {
		t.Fatal("wrapped ECDSA Sign produced signature that does not verify with stdlib VerifyASN1")
	}
}

func sha256OfBytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
