package pkcs7

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

// SCEP RFC 8894 Phase 2.1: round-trip tests for ParseEnvelopedData +
// EnvelopedData.Decrypt.
//
// Each test materialises a real RSA RA cert + key, builds an EnvelopedData
// by hand (encrypting a known plaintext with AES-256-CBC using a fresh
// random key transported via PKCS#1 v1.5 wrap of the RA pubkey), then
// parses + decrypts and asserts plaintext equality.
//
// The point of the round-trip is to pin the exact wire format: the
// per-field DER encoding has to match what real SCEP clients emit
// (Cisco IOS, ChromeOS, Intune Connector). If the parse succeeds but the
// decrypt comes back garbled, the wire-format encoding is off in a way
// the unit tests catch.

func TestEnvelopedData_RoundTrip_AES256CBC(t *testing.T) {
	raKey, raCert := genTestRSARA(t)
	plaintext := []byte("hello SCEP world — this is the encapsulated CSR DER bytes")

	envelope := buildTestEnvelope(t, raCert, plaintext, OIDAES256CBC, 32)

	parsed, err := ParseEnvelopedData(envelope)
	if err != nil {
		t.Fatalf("ParseEnvelopedData: %v", err)
	}
	if len(parsed.RecipientInfos) != 1 {
		t.Fatalf("len(RecipientInfos) = %d, want 1", len(parsed.RecipientInfos))
	}
	if !parsed.ContentEncryptionAlg.Algorithm.Equal(OIDAES256CBC) {
		t.Errorf("ContentEncryptionAlg = %v, want AES-256-CBC", parsed.ContentEncryptionAlg.Algorithm)
	}

	got, err := parsed.Decrypt(raKey, raCert)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt plaintext mismatch:\n got=%q\nwant=%q", got, plaintext)
	}
}

func TestEnvelopedData_RoundTrip_AES128CBC(t *testing.T) {
	raKey, raCert := genTestRSARA(t)
	plaintext := []byte("AES-128 round-trip — short ciphertext, single-block worth of data")

	envelope := buildTestEnvelope(t, raCert, plaintext, OIDAES128CBC, 16)
	parsed, err := ParseEnvelopedData(envelope)
	if err != nil {
		t.Fatalf("ParseEnvelopedData: %v", err)
	}
	got, err := parsed.Decrypt(raKey, raCert)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch")
	}
}

func TestEnvelopedData_Decrypt_WrongRA_ReturnsBadMessageCheck(t *testing.T) {
	correctKey, correctCert := genTestRSARA(t)
	wrongKey, wrongCert := genTestRSARA(t)
	plaintext := []byte("addressed to the right CA, decrypted with the wrong one")

	envelope := buildTestEnvelope(t, correctCert, plaintext, OIDAES256CBC, 32)
	parsed, err := ParseEnvelopedData(envelope)
	if err != nil {
		t.Fatalf("ParseEnvelopedData: %v", err)
	}

	// Wrong cert (issuer mismatch) — RFC 8894 §3.3.2.2 says BadMessageCheck.
	_, err = parsed.Decrypt(wrongKey, wrongCert)
	if !errors.Is(err, ErrEnvelopedDataDecrypt) {
		t.Errorf("Decrypt with wrong RA cert: err = %v, want ErrEnvelopedDataDecrypt", err)
	}
	// Right cert, wrong key — same generic error to close the timing leak.
	_, err = parsed.Decrypt(wrongKey, correctCert)
	if !errors.Is(err, ErrEnvelopedDataDecrypt) {
		t.Errorf("Decrypt with mismatched key: err = %v, want ErrEnvelopedDataDecrypt", err)
	}
	// Right key, right cert — succeeds.
	got, err := parsed.Decrypt(correctKey, correctCert)
	if err != nil {
		t.Fatalf("Decrypt with correct pair: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch")
	}
}

func TestEnvelopedData_Decrypt_TamperedCiphertext_Refuses(t *testing.T) {
	raKey, raCert := genTestRSARA(t)
	plaintext := []byte("plaintext we'll corrupt mid-flight")

	envelope := buildTestEnvelope(t, raCert, plaintext, OIDAES256CBC, 32)
	parsed, err := ParseEnvelopedData(envelope)
	if err != nil {
		t.Fatalf("ParseEnvelopedData: %v", err)
	}
	// Flip a bit in the LAST ciphertext block — corrupts the padding the
	// constant-time strip should catch.
	if len(parsed.EncryptedContent) < 16 {
		t.Fatal("ciphertext too short to tamper")
	}
	parsed.EncryptedContent[len(parsed.EncryptedContent)-1] ^= 0xff
	_, err = parsed.Decrypt(raKey, raCert)
	if !errors.Is(err, ErrEnvelopedDataDecrypt) {
		t.Errorf("Decrypt tampered ciphertext: err = %v, want ErrEnvelopedDataDecrypt", err)
	}
}

func TestEnvelopedData_Parse_Empty_Refuses(t *testing.T) {
	if _, err := ParseEnvelopedData(nil); err == nil {
		t.Error("ParseEnvelopedData(nil) = nil, want error")
	}
	if _, err := ParseEnvelopedData([]byte{}); err == nil {
		t.Error("ParseEnvelopedData(empty) = nil, want error")
	}
}

func TestEnvelopedData_Parse_RandomGarbage_Refuses(t *testing.T) {
	garbage := []byte{0x30, 0x82, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	if _, err := ParseEnvelopedData(garbage); err == nil {
		t.Error("ParseEnvelopedData(garbage) = nil, want error")
	}
}

// --- helpers -------------------------------------------------------------

func genTestRSARA(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ra-test"},
		Issuer:       pkix.Name{CommonName: "ra-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
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
	return key, cert
}

// buildTestEnvelope hand-constructs an EnvelopedData targeting raCert that
// encrypts plaintext with the given AES-CBC algorithm + keyLen. Mirrors
// what a real SCEP client would emit (Cisco IOS / Intune Connector / etc.).
//
// Returns the raw DER bytes ready to feed into ParseEnvelopedData.
func buildTestEnvelope(t *testing.T, raCert *x509.Certificate, plaintext []byte, algOID asn1.ObjectIdentifier, keyLen int) []byte {
	t.Helper()
	// 1. Generate a random symmetric key + IV.
	symKey := make([]byte, keyLen)
	if _, err := rand.Read(symKey); err != nil {
		t.Fatalf("rand.Read symKey: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand.Read iv: %v", err)
	}

	// 2. PKCS#7-pad the plaintext to a multiple of the block size.
	bs := aes.BlockSize
	padLen := bs - len(plaintext)%bs
	padded := append([]byte{}, plaintext...)
	for i := 0; i < padLen; i++ {
		padded = append(padded, byte(padLen))
	}

	// 3. AES-CBC encrypt.
	block, err := aes.NewCipher(symKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	enc.CryptBlocks(ciphertext, padded)

	// 4. RSA PKCS#1 v1.5 encrypt the symmetric key with the RA pubkey.
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, raCert.PublicKey.(*rsa.PublicKey), symKey)
	if err != nil {
		t.Fatalf("rsa.EncryptPKCS1v15: %v", err)
	}

	// 5. Build the IssuerAndSerialNumber identifying the RA cert.
	issuerRDN := asn1.RawValue{FullBytes: raCert.RawIssuer}
	rid, err := asn1.Marshal(struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}{Issuer: issuerRDN, SerialNumber: raCert.SerialNumber})
	if err != nil {
		t.Fatalf("marshal IssuerAndSerial: %v", err)
	}

	// 6. Build the KeyTransRecipientInfo SEQUENCE.
	keyEncAlg := pkix.AlgorithmIdentifier{Algorithm: OIDRSAEncryption, Parameters: asn1.NullRawValue}
	ktriBytes, err := asn1.Marshal(struct {
		Version          int
		RID              asn1.RawValue
		KeyEncryptionAlg pkix.AlgorithmIdentifier
		EncryptedKey     []byte
	}{
		Version:          0,
		RID:              asn1.RawValue{FullBytes: rid},
		KeyEncryptionAlg: keyEncAlg,
		EncryptedKey:     encryptedKey,
	})
	if err != nil {
		t.Fatalf("marshal KTRI: %v", err)
	}

	// 7. Build the AlgorithmIdentifier with the IV as parameters
	//    (RFC 3565 §2.3 — IV is OCTET STRING, fed in via Parameters).
	ivParam, err := asn1.Marshal(iv)
	if err != nil {
		t.Fatalf("marshal IV: %v", err)
	}
	contentAlg := pkix.AlgorithmIdentifier{
		Algorithm:  algOID,
		Parameters: asn1.RawValue{FullBytes: ivParam},
	}

	// 8. Build the EncryptedContentInfo SEQUENCE.
	//    encryptedContent is [0] IMPLICIT OCTET STRING — the content bytes
	//    appear directly after the [0] tag, without an inner OCTET STRING
	//    wrapper.
	encContent := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: false,
		Bytes:      ciphertext,
	}
	eciBytes, err := asn1.Marshal(struct {
		ContentType                asn1.ObjectIdentifier
		ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedContent           asn1.RawValue
	}{
		ContentType:                OIDDataContent,
		ContentEncryptionAlgorithm: contentAlg,
		EncryptedContent:           encContent,
	})
	if err != nil {
		t.Fatalf("marshal ECI: %v", err)
	}

	// 9. Build the EnvelopedData SEQUENCE.
	envBytes, err := asn1.Marshal(struct {
		Version        int
		RecipientInfos []asn1.RawValue `asn1:"set"`
		EncryptedECI   asn1.RawValue
	}{
		Version:        0,
		RecipientInfos: []asn1.RawValue{{FullBytes: ktriBytes}},
		EncryptedECI:   asn1.RawValue{FullBytes: eciBytes},
	})
	if err != nil {
		t.Fatalf("marshal EnvelopedData: %v", err)
	}
	return envBytes
}
