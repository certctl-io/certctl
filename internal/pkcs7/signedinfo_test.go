package pkcs7

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// SCEP RFC 8894 Phase 2.2: round-trip tests for ParseSignedData +
// SignerInfo.VerifySignature + auth-attr extractors.
//
// Each test materialises a real signing cert + signs auth-attrs over a
// known content, then re-parses and verifies. Catches drift between the
// signing-side encoding and the verification-side re-serialisation
// (RFC 5652 §5.4 SET OF Attribute quirk).

func TestSignerInfo_RoundTrip_RSAWithSHA256(t *testing.T) {
	signer, signerCert := genTestRSASigner(t)
	signedData := buildTestSignedData(t, signer, signerCert,
		domain.SCEPMessageTypePKCSReq, "txn-12345", []byte("0123456789abcdef"),
		[]byte("encapsulated content (typically EnvelopedData bytes)"))

	parsed, err := ParseSignedData(signedData)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if len(parsed.SignerInfos) != 1 {
		t.Fatalf("len(SignerInfos) = %d, want 1", len(parsed.SignerInfos))
	}

	si := parsed.SignerInfos[0]
	if err := si.VerifySignature(); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	// Auth-attr extractors.
	mt, err := si.GetMessageType()
	if err != nil {
		t.Fatalf("GetMessageType: %v", err)
	}
	if mt != domain.SCEPMessageTypePKCSReq {
		t.Errorf("GetMessageType = %d, want %d", mt, domain.SCEPMessageTypePKCSReq)
	}
	tid, err := si.GetTransactionID()
	if err != nil {
		t.Fatalf("GetTransactionID: %v", err)
	}
	if tid != "txn-12345" {
		t.Errorf("GetTransactionID = %q, want %q", tid, "txn-12345")
	}
	nonce, err := si.GetSenderNonce()
	if err != nil {
		t.Fatalf("GetSenderNonce: %v", err)
	}
	if string(nonce) != "0123456789abcdef" {
		t.Errorf("GetSenderNonce = %q, want %q", nonce, "0123456789abcdef")
	}
}

func TestSignerInfo_RoundTrip_ECDSAWithSHA256(t *testing.T) {
	signer, signerCert := genTestECDSASigner(t)
	signedData := buildTestSignedData(t, signer, signerCert,
		domain.SCEPMessageTypeRenewalReq, "txn-ec-1", []byte("nonce-ec-aaaa-bbbb"),
		[]byte("encap content"))

	parsed, err := ParseSignedData(signedData)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	si := parsed.SignerInfos[0]
	if err := si.VerifySignature(); err != nil {
		t.Fatalf("VerifySignature (ECDSA): %v", err)
	}
	mt, err := si.GetMessageType()
	if err != nil {
		t.Fatalf("GetMessageType: %v", err)
	}
	if mt != domain.SCEPMessageTypeRenewalReq {
		t.Errorf("GetMessageType = %d, want RenewalReq (17)", mt)
	}
}

func TestSignerInfo_VerifySignature_TamperedAttrs_Refuses(t *testing.T) {
	signer, signerCert := genTestRSASigner(t)
	signedData := buildTestSignedData(t, signer, signerCert,
		domain.SCEPMessageTypePKCSReq, "txn-tamper", []byte("nonce-aaaa-bbbb"),
		[]byte("content"))

	parsed, err := ParseSignedData(signedData)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	si := parsed.SignerInfos[0]
	// Tamper with rawSignedAttrs by flipping the last byte. Re-verification
	// must reject — proves the signature is bound to the auth-attr bytes.
	si.rawSignedAttrs[len(si.rawSignedAttrs)-1] ^= 0x01
	if err := si.VerifySignature(); !errors.Is(err, ErrSignerInfoVerify) {
		t.Errorf("VerifySignature(tampered attrs) = %v, want ErrSignerInfoVerify", err)
	}
}

func TestParseSignedData_Empty_Refuses(t *testing.T) {
	if _, err := ParseSignedData(nil); err == nil {
		t.Error("ParseSignedData(nil) = nil, want error")
	}
	if _, err := ParseSignedData([]byte{}); err == nil {
		t.Error("ParseSignedData(empty) = nil, want error")
	}
}

func TestParseSignedData_Garbage_Refuses(t *testing.T) {
	garbage := []byte{0x30, 0x82, 0x05, 0x01, 0x02, 0x03}
	if _, err := ParseSignedData(garbage); err == nil {
		t.Error("ParseSignedData(garbage) = nil, want error")
	}
}

// --- helpers -------------------------------------------------------------

type testSigner interface {
	Sign(data []byte) ([]byte, error)
	DigestOID() asn1.ObjectIdentifier
	SignatureOID() asn1.ObjectIdentifier
}

type rsaTestSigner struct{ k *rsa.PrivateKey }

func (s *rsaTestSigner) Sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, s.k, 0+5, h[:]) // 5 == crypto.SHA256 in crypto.Hash enum
}
func (s *rsaTestSigner) DigestOID() asn1.ObjectIdentifier    { return OIDSHA256 }
func (s *rsaTestSigner) SignatureOID() asn1.ObjectIdentifier { return OIDRSAWithSHA256 }

type ecdsaTestSigner struct{ k *ecdsa.PrivateKey }

func (s *ecdsaTestSigner) Sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, s.k, h[:])
}
func (s *ecdsaTestSigner) DigestOID() asn1.ObjectIdentifier    { return OIDSHA256 }
func (s *ecdsaTestSigner) SignatureOID() asn1.ObjectIdentifier { return OIDECDSAWithSHA256 }

func genTestRSASigner(t *testing.T) (testSigner, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() ^ 0xDEAD),
		Subject:      pkix.Name{CommonName: "device-rsa"},
		Issuer:       pkix.Name{CommonName: "device-rsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return &rsaTestSigner{k: key}, cert
}

func genTestECDSASigner(t *testing.T) (testSigner, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() ^ 0xBEEF),
		Subject:      pkix.Name{CommonName: "device-ec"},
		Issuer:       pkix.Name{CommonName: "device-ec"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return &ecdsaTestSigner{k: key}, cert
}

// buildTestSignedData hand-constructs a CMS SignedData with one SignerInfo
// carrying SCEP authenticated attributes (messageType, transactionID,
// senderNonce, plus the standard CMS contentType + messageDigest).
//
// The signing pipeline mirrors what micromdm/scep + the ChromeOS SCEP
// client emit: the device hashes the encap content into messageDigest,
// the auth-attrs are SET-OF re-serialised, hashed, and signed.
//
// Implementation note: built directly with ASN1Wrap helpers rather than
// relying on asn1.Marshal of structs containing asn1.RawValue fields —
// asn1.Marshal of nested RawValues with mixed Class/Tag has been finicky
// and the helpers give us byte-level control that matches what's on the wire.
func buildTestSignedData(t *testing.T, signer testSigner, signerCert *x509.Certificate, messageType domain.SCEPMessageType, transactionID string, senderNonce, encapContent []byte) []byte {
	t.Helper()

	// 1. messageDigest auth-attr: SHA-256 of the encap content.
	contentDigest := sha256.Sum256(encapContent)

	// 2. Build each auth-attr as Attribute ::= SEQUENCE { OID, SET OF Value }
	//    using the helpers. Marshal each value individually then wrap.
	attrSetBody := buildSCEPAuthAttrs(t, contentDigest[:], messageType, transactionID, senderNonce)

	// 3. Compute the signature over SET OF Attribute.
	signedAttrsForSig := ASN1Wrap(0x31, attrSetBody)
	sig, err := signer.Sign(signedAttrsForSig)
	if err != nil {
		t.Fatalf("signer.Sign: %v", err)
	}

	// 4. Build the SignerInfo SEQUENCE byte-by-byte.
	versionBytes := []byte{0x02, 0x01, 0x01} // INTEGER 1
	// SID is IssuerAndSerialNumber: SEQUENCE { Issuer (RDN), SerialNumber INTEGER }
	serialDER, err := asn1.Marshal(signerCert.SerialNumber)
	if err != nil {
		t.Fatalf("marshal serial: %v", err)
	}
	sidBody := append([]byte{}, signerCert.RawIssuer...) // already in DER
	sidBody = append(sidBody, serialDER...)
	sidBytes := ASN1Wrap(0x30, sidBody)

	// DigestAlgorithm: AlgorithmIdentifier — encode via stdlib (small struct, no nested RawValue issues).
	digestAlgBytes := mustMarshal(t, pkix.AlgorithmIdentifier{Algorithm: signer.DigestOID(), Parameters: asn1.NullRawValue})

	// SignedAttrs as [0] IMPLICIT SET OF — tag 0xA0 wraps the SET body.
	signedAttrsImplicitBytes := ASN1Wrap(0xa0, attrSetBody)

	// SignatureAlgorithm.
	sigAlg := pkix.AlgorithmIdentifier{Algorithm: signer.SignatureOID()}
	if signer.SignatureOID().Equal(OIDRSAWithSHA256) {
		sigAlg.Parameters = asn1.NullRawValue
	}
	sigAlgBytes := mustMarshal(t, sigAlg)

	// Signature: OCTET STRING.
	sigOctetBytes := ASN1Wrap(0x04, sig)

	siBody := append([]byte{}, versionBytes...)
	siBody = append(siBody, sidBytes...)
	siBody = append(siBody, digestAlgBytes...)
	siBody = append(siBody, signedAttrsImplicitBytes...)
	siBody = append(siBody, sigAlgBytes...)
	siBody = append(siBody, sigOctetBytes...)
	siBytes := ASN1Wrap(0x30, siBody)

	// 5. Build encapContentInfo SEQUENCE { OID data, [0] EXPLICIT OCTET STRING }.
	octetBytes := ASN1Wrap(0x04, encapContent)         // OCTET STRING
	encapContentExplicit := ASN1Wrap(0xa0, octetBytes) // [0] EXPLICIT
	oidDataBytes := mustMarshal(t, OIDDataContent)
	encapBody := append([]byte{}, oidDataBytes...)
	encapBody = append(encapBody, encapContentExplicit...)
	encapBytes := ASN1Wrap(0x30, encapBody)

	// 6. certificates [0] IMPLICIT SET OF Certificate — body is one cert DER.
	certsBytes := ASN1Wrap(0xa0, signerCert.Raw)

	// 7. digestAlgorithms SET OF AlgorithmIdentifier (one entry).
	digestAlgsBytes := ASN1Wrap(0x31, digestAlgBytes)

	// 8. signerInfos SET OF SignerInfo (one entry).
	signerInfosBytes := ASN1Wrap(0x31, siBytes)

	// 9. Assemble SignedData SEQUENCE.
	sdBody := append([]byte{}, []byte{0x02, 0x01, 0x01}...) // version
	sdBody = append(sdBody, digestAlgsBytes...)
	sdBody = append(sdBody, encapBytes...)
	sdBody = append(sdBody, certsBytes...)
	sdBody = append(sdBody, signerInfosBytes...)
	sdSeq := ASN1Wrap(0x30, sdBody)

	// 10. Wrap as ContentInfo SEQUENCE { OID signedData, [0] EXPLICIT SignedData }.
	contentField := ASN1Wrap(0xa0, sdSeq)
	oidSignedDataDER := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
	ciBody := append([]byte{}, oidSignedDataDER...)
	ciBody = append(ciBody, contentField...)
	return ASN1Wrap(0x30, ciBody)
}

// buildSCEPAuthAttrs builds the SET-OF body of SCEP auth-attrs (the bytes
// inside the [0] IMPLICIT SignedAttrs wrapper). Each Attribute is a SEQUENCE
// of (OID, SET OF Value); we build them with ASN1Wrap to avoid asn1.Marshal
// nuances with nested RawValues.
func buildSCEPAuthAttrs(t *testing.T, msgDigest []byte, messageType domain.SCEPMessageType, transactionID string, senderNonce []byte) []byte {
	t.Helper()
	var out []byte
	// contentType: SET OF OID = SET { OID data }
	out = append(out, attrSeq(t, OIDContentType, ASN1Wrap(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}))...)
	// messageDigest: SET OF OCTET STRING
	out = append(out, attrSeq(t, OIDMessageDigest, ASN1Wrap(0x04, msgDigest))...)
	// SCEP messageType: SET OF PrintableString (decimal ASCII)
	out = append(out, attrSeq(t, OIDSCEPMessageType, ASN1Wrap(0x13, []byte(intToAscii(int(messageType)))))...)
	// SCEP transactionID: SET OF PrintableString
	out = append(out, attrSeq(t, OIDSCEPTransactionID, ASN1Wrap(0x13, []byte(transactionID)))...)
	// SCEP senderNonce: SET OF OCTET STRING
	out = append(out, attrSeq(t, OIDSCEPSenderNonce, ASN1Wrap(0x04, senderNonce))...)
	return out
}

// attrSeq builds one Attribute SEQUENCE: SEQUENCE { OID, SET OF value }.
// The `value` arg is one already-encoded TLV (e.g. an OCTET STRING or
// PrintableString); attrSeq wraps it in a SET and prefixes the OID.
func attrSeq(t *testing.T, oid asn1.ObjectIdentifier, value []byte) []byte {
	t.Helper()
	oidBytes := mustMarshal(t, oid)
	setOfValue := ASN1Wrap(0x31, value)
	body := append([]byte{}, oidBytes...)
	body = append(body, setOfValue...)
	return ASN1Wrap(0x30, body)
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	out, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return out
}

func intToAscii(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
