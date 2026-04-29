package cms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"testing"
)

// EST RFC 7030 hardening master bundle Phase 2.4 tests.

// ----- ExtractTLSExporter -----

func TestExtractTLSExporter_NilState(t *testing.T) {
	if _, err := ExtractTLSExporter(nil); !errors.Is(err, ErrChannelBindingMissing) {
		t.Errorf("nil state should return ErrChannelBindingMissing, got %v", err)
	}
}

func TestExtractTLSExporter_HandshakeNotComplete(t *testing.T) {
	state := &tls.ConnectionState{HandshakeComplete: false, Version: 0x0304}
	if _, err := ExtractTLSExporter(state); !errors.Is(err, ErrChannelBindingMissing) {
		t.Errorf("incomplete handshake should return ErrChannelBindingMissing, got %v", err)
	}
}

func TestExtractTLSExporter_PreTLS13Rejected(t *testing.T) {
	state := &tls.ConnectionState{HandshakeComplete: true, Version: 0x0303} // TLS 1.2
	if _, err := ExtractTLSExporter(state); !errors.Is(err, ErrChannelBindingNotTLS13) {
		t.Errorf("TLS 1.2 should return ErrChannelBindingNotTLS13, got %v", err)
	}
}

// TestExtractTLSExporter_TLS13EndToEnd is the only test that builds a full
// real TLS-1.3 session — the exporter is computed on the connection's secret
// state, so we can't fake the ConnectionState. We spin up a localhost TCP
// listener, do a handshake, and then call ExportKeyingMaterial directly to
// pin the contract. This is a small round-trip but we're not testing TLS
// itself — just that ExtractTLSExporter pulls a 32-byte value from a real
// 1.3 state.
func TestExtractTLSExporter_TLS13EndToEnd(t *testing.T) {
	cert, key := freshSelfSignedTLSCert(t)
	tlsCert := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	clientCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // hermetic test cert; not for production use
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Finish the handshake on the server side.
		_ = conn.(*tls.Conn).HandshakeContext(context.Background())
		// Hold the connection open until the client side completes its read.
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()
	if err := conn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	state := conn.ConnectionState()

	out, err := ExtractTLSExporter(&state)
	if err != nil {
		t.Fatalf("ExtractTLSExporter: %v", err)
	}
	if len(out) != TLSExporterLength {
		t.Errorf("len(out) = %d, want %d", len(out), TLSExporterLength)
	}
}

// ----- ExtractCSRChannelBinding -----

func TestExtractCSRChannelBinding_NilCSR(t *testing.T) {
	if _, _, err := ExtractCSRChannelBinding(nil); err == nil {
		t.Fatal("nil CSR should error")
	}
}

func TestExtractCSRChannelBinding_AbsentReturnsFalse(t *testing.T) {
	csr := freshCSRNoBinding(t)
	val, present, err := ExtractCSRChannelBinding(csr)
	if err != nil {
		t.Fatalf("ExtractCSRChannelBinding: %v", err)
	}
	if present {
		t.Errorf("present=true on a CSR without the binding attribute (val=%x)", val)
	}
}

func TestExtractCSRChannelBinding_PresentReturnsExporter(t *testing.T) {
	exporter := repeatByte(0x42, TLSExporterLength)
	csr := freshCSRWithBinding(t, exporter, OIDChannelBindingTLSExporter)
	val, present, err := ExtractCSRChannelBinding(csr)
	if err != nil {
		t.Fatalf("ExtractCSRChannelBinding: %v", err)
	}
	if !present {
		t.Fatal("present=false on a CSR that carries the binding")
	}
	if !bytesEq(val, exporter) {
		t.Errorf("exporter = %x, want %x", val, exporter)
	}
}

func TestExtractCSRChannelBinding_LegacyOIDAccepted(t *testing.T) {
	exporter := repeatByte(0xAA, TLSExporterLength)
	csr := freshCSRWithBinding(t, exporter, OIDCMCEnrollmentBinding)
	val, present, err := ExtractCSRChannelBinding(csr)
	if err != nil {
		t.Fatalf("legacy-OID path failed: %v", err)
	}
	if !present || !bytesEq(val, exporter) {
		t.Errorf("legacy-OID extraction: got present=%v val=%x, want present=true val=%x", present, val, exporter)
	}
}

func TestExtractCSRChannelBinding_WrongLengthRejected(t *testing.T) {
	short := repeatByte(0x55, 16) // half the required length
	csr := freshCSRWithBinding(t, short, OIDChannelBindingTLSExporter)
	_, _, err := ExtractCSRChannelBinding(csr)
	if !errors.Is(err, ErrChannelBindingMissing) {
		t.Errorf("wrong-length binding should wrap ErrChannelBindingMissing, got %v", err)
	}
}

// ----- VerifyChannelBinding (composite) -----

func TestVerifyChannelBinding_NotRequired_NoBinding_Passes(t *testing.T) {
	csr := freshCSRNoBinding(t)
	if err := VerifyChannelBinding(nil, csr, false); err != nil {
		t.Errorf("required=false + no binding should pass; got %v", err)
	}
}

func TestVerifyChannelBinding_Required_NilState_Errors(t *testing.T) {
	csr := freshCSRNoBinding(t)
	if err := VerifyChannelBinding(nil, csr, true); err == nil {
		t.Fatal("required=true + nil state must error")
	}
}

// NOTE: a synthetic *tls.ConnectionState{HandshakeComplete:true, Version:0x0304}
// would seem like the obvious VerifyChannelBinding(required=true) negative-case
// fixture, but stdlib's ExportKeyingMaterial nil-derefs when the underlying
// secret state is unset (see crypto/tls/common.go:330). The
// "no live exporter available" branch is genuinely only reachable via a real
// connection (TestExtractTLSExporter_TLS13EndToEnd above), so we don't try to
// fake it here. The TestVerifyChannelBinding_NotRequired_NoBinding_Passes +
// TestVerifyChannelBinding_Required_NilState_Errors tests cover the policy
// branches; production code paths only ever pass r.TLS from a live request.

// ----- helpers -----

// freshCSRNoBinding returns a CSR with no extra attributes.
func freshCSRNoBinding(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "no-binding-test"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	return csr
}

// freshCSRWithBinding builds a CSR whose TBS carries the channel-binding
// attribute. The stdlib's CreateCertificateRequest doesn't support arbitrary
// attributes (only ExtraExtensions), so we hand-craft the TBS by parsing
// what stdlib produced + splicing our attribute into the [0] IMPLICIT
// Attributes block + re-signing.
func freshCSRWithBinding(t *testing.T, exporter []byte, oid asn1.ObjectIdentifier) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	// 1. Get a baseline CSR with no attributes — we steal its TBS shape.
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "binding-test"}}
	derBaseline, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	baseline, err := x509.ParseCertificateRequest(derBaseline)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}

	// 2. Build the channel-binding attribute (SEQUENCE { OID, SET { OCTET STRING }}).
	octet, err := asn1.Marshal(exporter)
	if err != nil {
		t.Fatalf("marshal octet: %v", err)
	}
	setEnv, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: octet})
	if err != nil {
		t.Fatalf("marshal set: %v", err)
	}
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("marshal oid: %v", err)
	}
	attrSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(append([]byte{}, oidBytes...), setEnv...),
	})
	if err != nil {
		t.Fatalf("marshal attribute SEQUENCE: %v", err)
	}

	// 3. Splice attribute into a [0] IMPLICIT Attributes block and rebuild
	// the TBS by hand. The TBS structure is:
	//   SEQUENCE { version INTEGER, subject Name, subjectPKInfo SubjectPublicKeyInfo,
	//              attributes [0] IMPLICIT SET OF Attribute }
	// We re-extract the first three fields from the baseline TBS and
	// re-marshal with our attribute appended.
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(baseline.RawTBSCertificateRequest, &outer); err != nil {
		t.Fatalf("baseline TBS unmarshal: %v", err)
	}
	rest := outer.Bytes
	var version, subject, spki asn1.RawValue
	for _, target := range []*asn1.RawValue{&version, &subject, &spki} {
		next, err := asn1.Unmarshal(rest, target)
		if err != nil {
			t.Fatalf("baseline TBS skip: %v", err)
		}
		rest = next
	}
	versionDER, _ := asn1.Marshal(version)
	subjectDER, _ := asn1.Marshal(subject)
	spkiDER, _ := asn1.Marshal(spki)
	// Build the [0] IMPLICIT Attributes wrapper.
	attrsField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      attrSeq,
	})
	if err != nil {
		t.Fatalf("marshal attrs field: %v", err)
	}
	tbsBody := append(append(append(append([]byte{}, versionDER...), subjectDER...), spkiDER...), attrsField...)
	newTBS, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      tbsBody,
	})
	if err != nil {
		t.Fatalf("re-marshal TBS: %v", err)
	}

	// 4. Parse the new TBS — we don't need to re-sign for these tests
	// (ExtractCSRChannelBinding doesn't verify the signature; it walks
	// RawTBSCertificateRequest only).
	csr := &x509.CertificateRequest{
		RawTBSCertificateRequest: newTBS,
		Subject:                  baseline.Subject,
		PublicKey:                baseline.PublicKey,
	}
	return csr
}

// freshSelfSignedTLSCert produces a tls.Certificate-compatible cert+key for
// the TLS-1.3 round-trip test.
func freshSelfSignedTLSCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tls-test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key
}

// repeatByte returns a slice of length n filled with b. Used for fixture
// exporter values where we need a deterministic test pattern.
func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// EmbedChannelBindingAttribute round-trip — pins the spec contract that
// what we marshal can be parsed back by ExtractCSRChannelBinding without
// going through the freshCSRWithBinding splice helper.
func TestEmbedChannelBindingAttribute_RoundTrip(t *testing.T) {
	exporter := repeatByte(0x77, TLSExporterLength)
	attrDER, err := EmbedChannelBindingAttribute(exporter)
	if err != nil {
		t.Fatalf("EmbedChannelBindingAttribute: %v", err)
	}
	// Wrap the single attribute in a [0] IMPLICIT SET OF Attribute block
	// and a TBS-lookalike SEQUENCE so we can feed it through the same path
	// the parser uses — the parser doesn't care that version+subject+spki
	// are absent because it walks structurally.
	attrsField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      attrDER,
	})
	if err != nil {
		t.Fatalf("marshal attrs field: %v", err)
	}
	// Synthetic TBS with three placeholder asn1.RawValue fields then attrsField.
	placeholder, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagInteger, Bytes: []byte{0x00}})
	body := append(append(append(append([]byte{}, placeholder...), placeholder...), placeholder...), attrsField...)
	tbs, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      body,
	})
	if err != nil {
		t.Fatalf("marshal TBS: %v", err)
	}
	got, present, err := walkCSRAttributesForBinding(tbs)
	if err != nil {
		t.Fatalf("walkCSRAttributesForBinding: %v", err)
	}
	if !present {
		t.Fatal("present=false on round-trip")
	}
	if !bytesEq(got, exporter) {
		t.Errorf("round-trip mismatch: got %x, want %x", got, exporter)
	}
}
