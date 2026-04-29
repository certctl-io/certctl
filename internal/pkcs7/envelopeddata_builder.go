// EnvelopedData BUILDER (inverse of envelopeddata.go's parser+decryptor).
//
// EST RFC 7030 hardening master bundle Phase 5.2.
//
// The SCEP path landed the parser/decryptor; the EST `serverkeygen`
// endpoint (RFC 7030 §4.4) needs the BUILDER so the server can encrypt
// the server-generated private key TO the client's CSR-supplied
// key-encipherment public key, then return it as a CMS EnvelopedData.
//
// Wire shape produced (matches the parser's input, RFC 5652 §6.1):
//
//	ContentInfo ::= SEQUENCE {
//	  contentType OBJECT IDENTIFIER,                  -- 1.2.840.113549.1.7.3 (envelopedData)
//	  content     [0] EXPLICIT EnvelopedData
//	}
//	EnvelopedData ::= SEQUENCE {
//	  version                  INTEGER (0),           -- v0 (no originatorInfo + no ori)
//	  recipientInfos           SET SIZE(1) OF KeyTransRecipientInfo,
//	  encryptedContentInfo     EncryptedContentInfo
//	}
//	KeyTransRecipientInfo ::= SEQUENCE {
//	  version                  INTEGER (0),           -- v0 (IssuerAndSerialNumber rid)
//	  rid                      IssuerAndSerialNumber, -- recipient cert's issuer + serial
//	  keyEncryptionAlgorithm   AlgorithmIdentifier,   -- rsaEncryption (PKCS#1 v1.5 keyTrans)
//	  encryptedKey             OCTET STRING           -- AES key wrapped to recipient pubkey
//	}
//	EncryptedContentInfo ::= SEQUENCE {
//	  contentType                OBJECT IDENTIFIER,   -- pkcs7-data (1.2.840.113549.1.7.1)
//	  contentEncryptionAlgorithm AlgorithmIdentifier, -- aes-256-cbc with IV in parameters
//	  encryptedContent           [0] IMPLICIT OCTET STRING
//	}
//
// Algorithm choices (locked at GA):
//
//   - Content cipher: AES-256-CBC. Strongest of the parser-supported ciphers
//     (parser also accepts AES-128, AES-192, DES-EDE3-CBC for legacy SCEP
//     interop; the BUILDER emits only AES-256). Random 16-byte IV per call.
//   - Key transport: RSA PKCS#1 v1.5 (rsaEncryption OID). Mirror of what
//     the parser supports — adding OAEP would mean parsing OAEP parameters
//     in the parser too, deferred to V3.
//   - Content-type carrier: pkcs7-data (1.2.840.113549.1.7.1). The
//     plaintext bytes ARE the inner content directly; the parser's
//     decryptCBC strips PKCS#7 padding so the BUILDER's PKCS#7-pad here
//     round-trips correctly.

package pkcs7

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
)

// ErrBuildEnvelopedData is the umbrella build-time error. Unlike the
// decrypt path (which deliberately collapses every internal failure to
// one sentinel to close padding-oracle / Bleichenbacher leaks), the
// BUILDER's errors are caller-introspectable — the caller is local
// server code, not an attacker.
var ErrBuildEnvelopedData = errors.New("envelopedData: build failed")

// BuildEnvelopedData produces the CMS EnvelopedData wire bytes for the
// given plaintext, encrypted to the supplied recipient cert.
//
// Inputs:
//   - plaintext: the bytes to encrypt (e.g. a marshaled PKCS#8 private key
//     for the EST serverkeygen path).
//   - recipientCert: the cert whose pubkey wraps the AES key. MUST be RSA
//     (the parser/decryptor only supports rsaEncryption keyTrans).
//   - rng: source of random bytes for the AES key + IV. Pass nil to use
//     crypto/rand.Reader. Tests can inject a deterministic reader so
//     fixture round-trips are reproducible.
//
// Output: DER bytes of the outer ContentInfo. Suitable for direct embed
// in the EST serverkeygen multipart body's `application/pkcs7-mime;
// smime-type=enveloped-data` part.
//
// Behavior contract pinned by envelopeddata_builder_test.go:
//   - Round-trip: BuildEnvelopedData → ParseEnvelopedData → Decrypt
//     returns the original plaintext byte-for-byte.
//   - Algorithm ID: AES-256-CBC (OID 2.16.840.1.101.3.4.1.42); IV is a
//     random 16-byte value carried in the algorithm parameters as an
//     OCTET STRING per RFC 3565 §2.3.
//   - Recipient: exactly one KeyTransRecipientInfo whose IssuerAndSerial
//     matches recipientCert.RawIssuer + recipientCert.SerialNumber.
func BuildEnvelopedData(plaintext []byte, recipientCert *x509.Certificate, rng io.Reader) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("%w: empty plaintext", ErrBuildEnvelopedData)
	}
	if recipientCert == nil {
		return nil, fmt.Errorf("%w: nil recipient cert", ErrBuildEnvelopedData)
	}
	rsaPub, ok := recipientCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: recipient cert pubkey is not RSA (PKCS#1 v1.5 keyTrans only)", ErrBuildEnvelopedData)
	}
	if rng == nil {
		rng = rand.Reader
	}

	// 1. Generate the symmetric key + IV. AES-256-CBC needs a 32-byte key
	// + 16-byte IV. Both come from the RNG; AES-CBC requires an IV
	// unique-per-message (not strictly random, but a CSPRNG-derived value
	// is the simplest correct choice).
	symKey := make([]byte, 32)
	if _, err := io.ReadFull(rng, symKey); err != nil {
		return nil, fmt.Errorf("%w: gen sym key: %w", ErrBuildEnvelopedData, err)
	}
	iv := make([]byte, aes.BlockSize) // aes.BlockSize == 16
	if _, err := io.ReadFull(rng, iv); err != nil {
		return nil, fmt.Errorf("%w: gen iv: %w", ErrBuildEnvelopedData, err)
	}

	// 2. PKCS#7-pad + AES-256-CBC encrypt the plaintext.
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, fmt.Errorf("%w: aes.NewCipher: %w", ErrBuildEnvelopedData, err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	// 3. Wrap the symmetric key with the recipient's RSA pubkey using
	// PKCS#1 v1.5 keyTrans. Matches the parser's rsa.DecryptPKCS1v15
	// expectation. NOTE: rsa.EncryptPKCS1v15 takes the plaintext (the
	// AES key bytes) directly — no extra ASN.1 wrapping.
	wrappedKey, err := rsa.EncryptPKCS1v15(rng, rsaPub, symKey)
	if err != nil {
		return nil, fmt.Errorf("%w: rsa.EncryptPKCS1v15: %w", ErrBuildEnvelopedData, err)
	}

	// 4. Build the AlgorithmIdentifier for AES-256-CBC. RFC 3565 §2.3:
	// the parameters field is an OCTET STRING carrying the IV.
	ivOctet, err := asn1.Marshal(iv) // marshal as OCTET STRING
	if err != nil {
		return nil, fmt.Errorf("%w: marshal iv: %w", ErrBuildEnvelopedData, err)
	}
	contentEncAlg := pkix.AlgorithmIdentifier{
		Algorithm:  OIDAES256CBC,
		Parameters: asn1.RawValue{FullBytes: ivOctet},
	}

	// 5. Build the IssuerAndSerialNumber rid. The recipient cert's
	// RawIssuer is the DER of its issuer DN (already canonicalised by
	// the cert's encoder); we splice it as a RawValue so re-serialisation
	// preserves byte-for-byte equality with what the recipient sees in
	// its own cert.
	issuerAndSerial := issuerAndSerialASN1{
		Issuer:       asn1.RawValue{FullBytes: recipientCert.RawIssuer},
		SerialNumber: recipientCert.SerialNumber,
	}
	iasDER, err := asn1.Marshal(issuerAndSerial)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal IssuerAndSerial: %w", ErrBuildEnvelopedData, err)
	}

	// 6. Build the KeyTransRecipientInfo SEQUENCE.
	ktri := keyTransRecipientInfoASN1{
		Version:          0, // v0 with IssuerAndSerial rid
		RID:              asn1.RawValue{FullBytes: iasDER},
		KeyEncryptionAlg: pkix.AlgorithmIdentifier{Algorithm: OIDRSAEncryption, Parameters: asn1.NullRawValue},
		EncryptedKey:     wrappedKey,
	}
	ktriDER, err := asn1.Marshal(ktri)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal KTRI: %w", ErrBuildEnvelopedData, err)
	}

	// 7. Build the EncryptedContentInfo. encryptedContent is [0] IMPLICIT
	// OCTET STRING; we marshal as a context-specific RawValue with class
	// CONTEXT-SPECIFIC + tag 0 + the raw ciphertext bytes (no inner
	// OCTET STRING tag since IMPLICIT replaces it).
	encContent := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: false,
		Bytes:      ciphertext,
	}
	enci := encryptedContentInfoASN1{
		ContentType:                OIDDataContent,
		ContentEncryptionAlgorithm: contentEncAlg,
		EncryptedContent:           encContent,
	}

	// 8. Compose the EnvelopedData SEQUENCE. The parser's struct uses
	// `[]asn1.RawValue` for RecipientInfos with `set` tag; we mirror
	// that shape so the parse round-trip exercises the same code path.
	enveloped := envelopedDataASN1{
		Version:              0, // v0 (no originatorInfo, no [1] unprotectedAttrs)
		RecipientInfos:       []asn1.RawValue{{FullBytes: ktriDER}},
		EncryptedContentInfo: enci,
		// UnprotectedAttrs intentionally left zero-value; asn1.Marshal
		// omits OPTIONAL fields whose RawValue is empty.
	}
	envelopedDER, err := asn1.Marshal(enveloped)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal EnvelopedData: %w", ErrBuildEnvelopedData, err)
	}

	// 9. Wrap in the outer ContentInfo so peelContentInfo on the read
	// side picks it up cleanly. RFC 5652 §3 — content is [0] EXPLICIT.
	wrapped, err := asn1.Marshal(contentInfoASN1{
		ContentType: OIDEnvelopedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: envelopedDER},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: marshal ContentInfo: %w", ErrBuildEnvelopedData, err)
	}
	return wrapped, nil
}

// contentInfoASN1 is the outer CMS ContentInfo wrapper. envelopeddata.go's
// peelContentInfo is the read-side complement.
type contentInfoASN1 struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// pkcs7Pad applies PKCS#7 padding (RFC 5652 §6.3 references RFC 2315 §10.3).
// blockSize bytes' worth of (blockSize - len(in) % blockSize) is appended;
// when the input is already a block-multiple, a full block of `blockSize`
// padding bytes is appended (so unpad always has something to strip).
func pkcs7Pad(in []byte, blockSize int) []byte {
	padLen := blockSize - (len(in) % blockSize)
	out := make([]byte, len(in)+padLen)
	copy(out, in)
	for i := len(in); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}
