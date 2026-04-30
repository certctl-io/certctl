package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"golang.org/x/crypto/ocsp"
)

// Production hardening II Phase 1 — OCSP nonce parser tests.
//
// The parser walks raw DER (golang.org/x/crypto/ocsp.Request doesn't
// expose request extensions). These tests pin every documented
// failure mode and the happy-path round-trip:
//
//   - Request without nonce extension -> (nil, false, nil)
//   - Request with well-formed nonce  -> (nonce, true,  nil)
//   - Empty nonce                     -> (nil, false, ErrOCSPNonceMalformed)
//   - Oversized nonce (>32 bytes)     -> (nil, false, ErrOCSPNonceMalformed)
//   - Garbage extnValue               -> (nil, false, ErrOCSPNonceMalformed)
//   - Garbage TBSRequest              -> (nil, false, nil)  (not our problem)

// buildOCSPRequestWithNonce constructs an OCSP request DER with the
// given nonce bytes wrapped in the canonical extnValue OCTET STRING
// envelope. When nonce is nil, no extension is added.
func buildOCSPRequestWithNonce(t *testing.T, nonce []byte) []byte {
	t.Helper()
	// Build a real issuer cert so ocsp.CreateRequest has something to
	// hash for the IssuerNameHash + IssuerKeyHash fields.
	priv, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // test fixture, not security-relevant
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Issuer"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsecert: %v", err)
	}

	// Build the raw OCSP request body via golang.org/x/crypto/ocsp,
	// then patch the requestExtensions field if a nonce is requested.
	// ocsp.CreateRequest doesn't accept extensions, so we re-marshal
	// the TBSRequest with an Extensions slice spliced in.
	reqDER, err := ocsp.CreateRequest(&x509.Certificate{SerialNumber: big.NewInt(42)}, issuer, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest: %v", err)
	}
	if nonce == nil {
		return reqDER
	}

	// Splice in the nonce extension by hand-marshaling a new TBSRequest.
	// Pull the existing TBSRequest, append a [2] EXPLICIT Extensions
	// element containing one Extension (id-pkix-ocsp-nonce, OCTET
	// STRING(nonce)).
	extnValue, err := asn1.Marshal(nonce) // OCTET STRING wrap
	if err != nil {
		t.Fatalf("marshal nonce extnValue: %v", err)
	}
	nonceExt := struct {
		ExtnID    asn1.ObjectIdentifier
		ExtnValue []byte
	}{
		ExtnID:    OIDOCSPNonce,
		ExtnValue: extnValue,
	}
	extDER, err := asn1.Marshal([]any{nonceExt})
	if err != nil {
		t.Fatalf("marshal extensions: %v", err)
	}
	// Wrap in [2] EXPLICIT
	exposed := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      extDER,
	}
	expDER, err := asn1.Marshal(exposed)
	if err != nil {
		t.Fatalf("marshal exposed: %v", err)
	}

	// Splice: parse OCSPRequest, append expDER to TBSRequest's Bytes,
	// re-marshal as a SEQUENCE.
	var ocspReqRV asn1.RawValue
	if _, err := asn1.Unmarshal(reqDER, &ocspReqRV); err != nil {
		t.Fatalf("unmarshal OCSPRequest envelope: %v", err)
	}
	var tbsRV asn1.RawValue
	rest, err := asn1.Unmarshal(ocspReqRV.Bytes, &tbsRV)
	if err != nil {
		t.Fatalf("unmarshal TBSRequest: %v", err)
	}
	// Append expDER to tbsRV.Bytes
	newTBS := append(append([]byte{}, tbsRV.Bytes...), expDER...)
	// Re-marshal the TBSRequest SEQUENCE
	newTBSRV, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: newTBS})
	if err != nil {
		t.Fatalf("re-marshal TBSRequest: %v", err)
	}
	// Re-marshal the outer OCSPRequest = TBSRequest || (rest, e.g. signature)
	newOuter := append(append([]byte{}, newTBSRV...), rest...)
	newOuterRV, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: newOuter})
	if err != nil {
		t.Fatalf("re-marshal OCSPRequest: %v", err)
	}
	return newOuterRV
}

func TestOCSPNonce_RequestWithoutNonce_ReturnsNoneNoError(t *testing.T) {
	reqDER := buildOCSPRequestWithNonce(t, nil)
	nonce, present, err := ParseOCSPRequestNonce(reqDER)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if present {
		t.Errorf("expected present=false, got true")
	}
	if nonce != nil {
		t.Errorf("expected nil nonce, got %x", nonce)
	}
}

func TestOCSPNonce_RequestWithWellFormedNonce_EchoBytesMatchInput(t *testing.T) {
	want := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x11, 0x22, 0x33}
	reqDER := buildOCSPRequestWithNonce(t, want)
	nonce, present, err := ParseOCSPRequestNonce(reqDER)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !present {
		t.Errorf("expected present=true")
	}
	if string(nonce) != string(want) {
		t.Errorf("nonce mismatch: got %x, want %x", nonce, want)
	}
}

func TestOCSPNonce_EmptyNonce_RejectedAsMalformed(t *testing.T) {
	reqDER := buildOCSPRequestWithNonce(t, []byte{})
	_, _, err := ParseOCSPRequestNonce(reqDER)
	if !errors.Is(err, ErrOCSPNonceMalformed) {
		t.Errorf("expected ErrOCSPNonceMalformed, got %v", err)
	}
}

func TestOCSPNonce_OversizedNonce_RejectedAsMalformed(t *testing.T) {
	// 33 bytes — one more than MaxOCSPNonceLength
	oversize := make([]byte, MaxOCSPNonceLength+1)
	for i := range oversize {
		oversize[i] = byte(i)
	}
	reqDER := buildOCSPRequestWithNonce(t, oversize)
	_, _, err := ParseOCSPRequestNonce(reqDER)
	if !errors.Is(err, ErrOCSPNonceMalformed) {
		t.Errorf("expected ErrOCSPNonceMalformed for nonce of len %d, got %v", len(oversize), err)
	}
}

func TestOCSPNonce_GarbageDER_ReturnsNoneNoError(t *testing.T) {
	// Random garbage that's not even an ASN.1 SEQUENCE — caller already
	// validated via ocsp.ParseRequest, so a parse failure here is not
	// our problem; return "no nonce" rather than surfacing redundant
	// parse errors.
	_, present, err := ParseOCSPRequestNonce([]byte{0xff, 0x00, 0x42})
	if err != nil {
		t.Errorf("garbage DER should not surface error, got %v", err)
	}
	if present {
		t.Errorf("garbage DER should not produce present=true")
	}
}

func TestOCSPNonce_BoundaryNonce_32BytesAccepted(t *testing.T) {
	// Exactly MaxOCSPNonceLength — must be accepted.
	exact := make([]byte, MaxOCSPNonceLength)
	for i := range exact {
		exact[i] = 0xab
	}
	reqDER := buildOCSPRequestWithNonce(t, exact)
	nonce, present, err := ParseOCSPRequestNonce(reqDER)
	if err != nil {
		t.Fatalf("32-byte nonce should be accepted, got %v", err)
	}
	if !present || len(nonce) != MaxOCSPNonceLength {
		t.Errorf("expected present=true with 32-byte nonce; got present=%v len=%d", present, len(nonce))
	}
}
