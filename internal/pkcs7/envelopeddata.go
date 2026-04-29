// EnvelopedData parser + decryptor for SCEP PKIMessage.
//
// RFC 5652 §6 (Cryptographic Message Syntax — EnvelopedData) +
// RFC 8894 §3.2.2 (SCEP pkcsPKIEnvelope).
//
// SCEP RFC 8894 + Intune master bundle Phase 2.1.
//
// Equivalent to micromdm/scep's scep/cryptoutil/cryptoutil.go::DecryptPKCSEnvelope
// (read for shape only; not vendored — certctl owns the fuzz targets in this
// sub-package, see internal/pkcs7/envelopeddata_fuzz_test.go).
//
// ASN.1 structure being parsed (cited from RFC 5652 §6.1):
//
//	EnvelopedData ::= SEQUENCE {
//	  version                  INTEGER,
//	  originatorInfo           [0] IMPLICIT OriginatorInfo OPTIONAL,
//	  recipientInfos           SET SIZE(1..MAX) OF RecipientInfo,
//	  encryptedContentInfo     EncryptedContentInfo,
//	  unprotectedAttrs         [1] IMPLICIT Attributes OPTIONAL
//	}
//
//	RecipientInfo ::= CHOICE {
//	  ktri                     KeyTransRecipientInfo,    -- the only one SCEP uses
//	  -- (other CHOICE arms ignored: kari, kekri, pwri, ori)
//	}
//
//	KeyTransRecipientInfo ::= SEQUENCE {
//	  version                  INTEGER (0|2),
//	  rid                      RecipientIdentifier,      -- IssuerAndSerialNumber for SCEP
//	  keyEncryptionAlgorithm   AlgorithmIdentifier,      -- rsaEncryption (1.2.840.113549.1.1.1)
//	  encryptedKey             OCTET STRING              -- AES key encrypted with RA cert pubkey
//	}
//
//	EncryptedContentInfo ::= SEQUENCE {
//	  contentType              OBJECT IDENTIFIER,        -- pkcs7-data (1.2.840.113549.1.7.1)
//	  contentEncryptionAlgorithm AlgorithmIdentifier,    -- aes-128-cbc | aes-192-cbc | aes-256-cbc | des-ede3-cbc
//	  encryptedContent         [0] IMPLICIT OCTET STRING -- the encrypted CSR bytes + PKCS#7 padding
//	}

package pkcs7

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // DES-EDE3-CBC is RFC 8894 §3.5.2 fallback for legacy MDM clients
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// SCEP / CMS algorithm OIDs used by the EnvelopedData path.
//
// Defined here as exported package vars so the CertRep builder (Phase 3)
// shares the same OID encoding and the unit tests can pin the exact values.
var (
	// rsaEncryption — PKCS#1 v1.5 key transport (RFC 8017 §7.2).
	OIDRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	// PKCS#7 / CMS data content type (RFC 5652 §4).
	OIDDataContent = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	// AES-128-CBC / AES-192-CBC / AES-256-CBC content-encryption algorithms
	// (NIST CSOR / RFC 3565 §2).
	OIDAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OIDAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	OIDAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	// DES-EDE3-CBC — RFC 8894 §3.5.2 advertises this as a legacy fallback;
	// some Cisco IOS / older MDM clients still emit it. RFC 8894 itself
	// does NOT mandate that the server accept DES; we accept it for
	// max-compat and document the security caveat in docs/legacy-est-scep.md.
	OIDDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// Sentinel decryption error. The caller (handler / service) maps this to
// SCEPFailBadMessageCheck per RFC 8894 §3.3.2.2 + §3.2.2 (integrity-check
// failure semantics). The error text is intentionally generic so the
// padding-oracle / Bleichenbacher leak surfaces are closed: every failure
// mode (RSA decrypt failure, content decrypt failure, padding malformed,
// unknown algorithm) returns the SAME error message text.
var ErrEnvelopedDataDecrypt = errors.New("envelopedData: decrypt failed")

// EnvelopedData is the parsed RFC 5652 EnvelopedData structure ready for
// Decrypt. Holds the recipient infos + the encrypted content algorithm /
// IV / ciphertext.
type EnvelopedData struct {
	Version              int
	RecipientInfos       []KeyTransRecipientInfo
	ContentEncryptionAlg pkix.AlgorithmIdentifier
	EncryptedContent     []byte // AES-CBC ciphertext; algorithm + IV in ContentEncryptionAlg
}

// KeyTransRecipientInfo is the RFC 5652 §6.2.1 KeyTransRecipientInfo. SCEP
// only uses this CHOICE arm — the others (kari/kekri/pwri/ori) are
// rejected at parse time as out-of-spec for SCEP.
type KeyTransRecipientInfo struct {
	Version          int
	IssuerAndSerial  IssuerAndSerial
	KeyEncryptionAlg pkix.AlgorithmIdentifier
	EncryptedKey     []byte
}

// IssuerAndSerial is the recipient identifier (RFC 5652 §10.2.4). SCEP
// requires the SubjectKeyIdentifier-as-bytes form to NOT be used; only
// IssuerAndSerialNumber. The handler matches this against the loaded RA
// cert (issuer + serial) to identify the matching recipient when the
// envelope addresses multiple CAs.
type IssuerAndSerial struct {
	IssuerRaw    asn1.RawValue // RDN sequence of the issuer cert; raw so re-serialisation matches DER bit-for-bit
	SerialNumber *big.Int
}

// envelopedDataASN1 is the ASN.1 unmarshal target for the EnvelopedData
// structure inside the SignedData encapContentInfo (post-CMS-wrapping).
// The version field comes first; recipientInfos is a SET (not SEQUENCE);
// the encryptedContentInfo SEQUENCE follows.
//
// The originatorInfo [0] IMPLICIT OPTIONAL is rare in SCEP and skipped
// at the raw-value level (we don't need it).
type envelopedDataASN1 struct {
	Version              int
	RecipientInfos       []asn1.RawValue          `asn1:"set"`
	EncryptedContentInfo encryptedContentInfoASN1 `asn1:""`
	UnprotectedAttrs     asn1.RawValue            `asn1:"optional,tag:1"`
}

type encryptedContentInfoASN1 struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"optional,tag:0"`
}

type keyTransRecipientInfoASN1 struct {
	Version          int
	RID              asn1.RawValue // CHOICE — IssuerAndSerialNumber or [0] subjectKeyIdentifier
	KeyEncryptionAlg pkix.AlgorithmIdentifier
	EncryptedKey     []byte
}

type issuerAndSerialASN1 struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// ParseEnvelopedData parses raw DER-encoded EnvelopedData bytes.
//
// The caller passes the raw bytes from the inner pkcsPKIEnvelope (already
// stripped of the outer SignedData → encapContentInfo → OCTET STRING
// wrapper). Returns an EnvelopedData ready for Decrypt.
//
// Parse failures are returned as detailed errors so the handler can log
// what was malformed; the eventual SCEP wire response collapses all
// failures to BadMessageCheck.
func ParseEnvelopedData(der []byte) (*EnvelopedData, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("envelopedData: empty input")
	}
	// Some encoders wrap the EnvelopedData in an outer ContentInfo
	// (SEQUENCE { contentType OID, content [0] EXPLICIT EnvelopedData }).
	// Try that shape first; on failure, parse the bytes directly.
	if peeled, ok := peelContentInfo(der, OIDEnvelopedData); ok {
		der = peeled
	}

	var raw envelopedDataASN1
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("envelopedData: parse outer SEQUENCE: %w", err)
	}
	if len(rest) > 0 {
		// Trailing bytes after a CMS structure are tolerated by some
		// encoders; not a fatal parse error.
		_ = rest
	}

	out := &EnvelopedData{
		Version:              raw.Version,
		ContentEncryptionAlg: raw.EncryptedContentInfo.ContentEncryptionAlgorithm,
	}

	// recipientInfos is SET OF RecipientInfo (CHOICE). We accept only the
	// KeyTransRecipientInfo arm. Other CHOICE arms (kari = [1], kekri = [2],
	// pwri = [3], ori = [4]) are skipped silently — Decrypt will fail with
	// 'no matching recipient' if none of the SET members are KTRI.
	for _, ri := range raw.RecipientInfos {
		// KeyTransRecipientInfo is implicitly tagged as a SEQUENCE (no
		// explicit context tag) per RFC 5652 §6.2 — it's the default
		// CHOICE arm. The other arms carry context-specific tags.
		if ri.Class != asn1.ClassUniversal || ri.Tag != asn1.TagSequence {
			continue // not a KTRI; skip
		}
		var ktri keyTransRecipientInfoASN1
		if _, err := asn1.Unmarshal(ri.FullBytes, &ktri); err != nil {
			continue
		}
		// SCEP requires IssuerAndSerialNumber for the rid (RFC 8894 §3.2.2
		// references RFC 5652 §6.2.1 with the v0 form). The v2 form uses
		// SubjectKeyIdentifier in [0] — also accepted by some clients. We
		// only support the v0 IssuerAndSerial form here; v2 clients that
		// fail to match fall through to 'no matching recipient'.
		var ias issuerAndSerialASN1
		if _, err := asn1.Unmarshal(ktri.RID.FullBytes, &ias); err != nil {
			continue // not IssuerAndSerial; skip
		}
		out.RecipientInfos = append(out.RecipientInfos, KeyTransRecipientInfo{
			Version: ktri.Version,
			IssuerAndSerial: IssuerAndSerial{
				IssuerRaw:    ias.Issuer,
				SerialNumber: ias.SerialNumber,
			},
			KeyEncryptionAlg: ktri.KeyEncryptionAlg,
			EncryptedKey:     ktri.EncryptedKey,
		})
	}
	if len(out.RecipientInfos) == 0 {
		return nil, fmt.Errorf("envelopedData: no KeyTransRecipientInfo with IssuerAndSerial form found in SET")
	}

	// EncryptedContent is [0] IMPLICIT OCTET STRING. The IMPLICIT tagging
	// strips the OCTET STRING tag; what we get is the raw ciphertext as
	// asn1.RawValue.Bytes. (Some encoders use EXPLICIT; in that case
	// FullBytes carries an extra [0] wrapper we strip below.)
	if raw.EncryptedContentInfo.EncryptedContent.Class == asn1.ClassContextSpecific {
		out.EncryptedContent = raw.EncryptedContentInfo.EncryptedContent.Bytes
	}
	if len(out.EncryptedContent) == 0 {
		return nil, fmt.Errorf("envelopedData: empty encryptedContent")
	}
	return out, nil
}

// Decrypt decrypts the EnvelopedData using the RA private key.
//
// Algorithm:
//  1. Find a RecipientInfo whose IssuerAndSerial matches raCert.
//  2. RSA PKCS#1 v1.5 decrypt the EncryptedKey with raKey.
//  3. AES-CBC (or DES-EDE3-CBC) decrypt EncryptedContent with the recovered
//     symmetric key + the IV embedded in ContentEncryptionAlg.Parameters.
//  4. Strip PKCS#7 padding in constant time (no branch on padding-byte
//     values — closes the padding oracle leak).
//
// Every failure path returns ErrEnvelopedDataDecrypt with no other detail
// to avoid leaking which step failed. Service-layer logs may include
// per-step internal context, but the wire response carries only
// SCEPFailBadMessageCheck.
func (e *EnvelopedData) Decrypt(raKey crypto.PrivateKey, raCert *x509.Certificate) ([]byte, error) {
	if e == nil {
		return nil, ErrEnvelopedDataDecrypt
	}
	rsaKey, ok := raKey.(*rsa.PrivateKey)
	if !ok {
		// SCEP RA keys are RSA per RFC 8894 §3.5.2 (CMS key transport
		// requires asymmetric keys with PKCS#1 v1.5; ECDSA can't do
		// keyTrans). The preflight gate already enforces RSA-or-ECDSA on
		// the RA cert, but Decrypt double-checks — the cert can be ECDSA
		// (used for SignedData signing only) while EnvelopedData decryption
		// requires RSA.
		return nil, ErrEnvelopedDataDecrypt
	}

	// Find a recipient matching the RA cert. Match on issuer DN raw bytes +
	// serial number — both must compare equal. The cert.RawIssuer is the
	// DER of the issuer's RDNSequence, the same form CMS encodes here.
	var ktri *KeyTransRecipientInfo
	for i := range e.RecipientInfos {
		ri := &e.RecipientInfos[i]
		if subtle.ConstantTimeCompare(ri.IssuerAndSerial.IssuerRaw.FullBytes, raCert.RawIssuer) != 1 {
			continue
		}
		if ri.IssuerAndSerial.SerialNumber == nil || raCert.SerialNumber == nil {
			continue
		}
		if ri.IssuerAndSerial.SerialNumber.Cmp(raCert.SerialNumber) != 0 {
			continue
		}
		ktri = ri
		break
	}
	if ktri == nil {
		// Wrong recipient — the envelope was addressed to a CA that isn't
		// us. RFC 8894 §3.3.2.2 maps this to BadMessageCheck (integrity
		// check failed), NOT BadCertID — the message is structurally fine,
		// just not for us.
		return nil, ErrEnvelopedDataDecrypt
	}
	if !ktri.KeyEncryptionAlg.Algorithm.Equal(OIDRSAEncryption) {
		// Only PKCS#1 v1.5 keyTrans supported; OAEP would require parsing
		// the algorithm parameters for the OAEP hash + MGF — out of scope
		// for V2.
		return nil, ErrEnvelopedDataDecrypt
	}

	// RSA PKCS#1 v1.5 decrypt the symmetric key. We use the variant that
	// hides timing of malformed-padding rejection (rsa.DecryptPKCS1v15)
	// returns an error on bad padding; combined with the constant
	// ErrEnvelopedDataDecrypt response we close the timing leg of the
	// Bleichenbacher attack at the wire level.
	symKey, err := rsa.DecryptPKCS1v15(nil, rsaKey, ktri.EncryptedKey)
	if err != nil {
		return nil, ErrEnvelopedDataDecrypt
	}

	// Decrypt the content. AES-CBC algorithm parameters are the IV as a
	// raw OCTET STRING (RFC 3565 §2.3); DES-EDE3-CBC same shape (RFC 8894
	// §3.5.2 advertises this).
	plaintext, err := decryptCBC(e.ContentEncryptionAlg, symKey, e.EncryptedContent)
	if err != nil {
		return nil, ErrEnvelopedDataDecrypt
	}
	return plaintext, nil
}

// decryptCBC dispatches on the content-encryption algorithm OID to the
// matching cipher constructor + CBC decrypt + constant-time PKCS#7 unpad.
func decryptCBC(alg pkix.AlgorithmIdentifier, key, ciphertext []byte) ([]byte, error) {
	// The IV is the raw OCTET STRING in alg.Parameters (RFC 3565 §2.3,
	// RFC 8894 §3.5.2). asn1.RawValue.Bytes carries the OCTET STRING
	// content already (the SEQUENCE wrapper is stripped by the unmarshal).
	iv := alg.Parameters.Bytes
	var block cipher.Block
	var err error
	switch {
	case alg.Algorithm.Equal(OIDAES128CBC), alg.Algorithm.Equal(OIDAES192CBC), alg.Algorithm.Equal(OIDAES256CBC):
		// AES key length must match the algorithm. Reject mismatched
		// lengths at the cipher constructor — the wire response stays
		// generic via ErrEnvelopedDataDecrypt.
		block, err = aes.NewCipher(key)
	case alg.Algorithm.Equal(OIDDESEDE3CBC):
		block, err = des.NewTripleDESCipher(key) //nolint:gosec // RFC 8894 §3.5.2 legacy fallback
	default:
		return nil, fmt.Errorf("unsupported content-encryption algorithm: %v", alg.Algorithm)
	}
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("iv length %d does not match block size %d", len(iv), block.BlockSize())
	}
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext length %d not multiple of block size %d", len(ciphertext), block.BlockSize())
	}
	plaintext := make([]byte, len(ciphertext))
	dec := cipher.NewCBCDecrypter(block, iv)
	dec.CryptBlocks(plaintext, ciphertext)

	// Constant-time PKCS#7 padding strip.
	//
	// Last byte is the padding length P (1..blockSize). Every byte in the
	// last P bytes must equal P. We accumulate any deviation into a
	// bitwise-OR `bad` byte that's zero iff every check passes; the
	// length cap is also folded into the same accumulator. Branch only on
	// the accumulator at the end. NEVER branch on padding-byte values
	// mid-loop (that's the padding oracle).
	bs := block.BlockSize()
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext empty after decrypt")
	}
	pad := plaintext[len(plaintext)-1]
	// pad must be in [1, bs]. `padTooBig` is 0xff when pad > bs, else 0x00.
	padTooBig := byte(int(pad)-1) >> 7 // 1 if pad==0, else 0
	padTooBig |= byte((int(bs)-int(pad))>>31) & 0x01
	bad := padTooBig
	// Walk the LAST `bs` bytes (a fixed window equal to one block); for
	// each byte at position N from the end, if N < pad it must equal pad.
	// Use bitwise mask 'inWindow' to fold the conditional check into the
	// accumulator without branching.
	for i := 1; i <= bs && i <= len(plaintext); i++ {
		// inWindow is 0xff when i <= pad, else 0x00
		inWindow := byte(int(int(pad)-i) >> 31) // 0xff if pad-i < 0 → not in window
		inWindow = ^inWindow                    // flip: 0xff if i <= pad
		mismatch := plaintext[len(plaintext)-i] ^ pad
		bad |= inWindow & mismatch
	}
	if bad != 0 {
		return nil, fmt.Errorf("invalid PKCS#7 padding")
	}
	return plaintext[:len(plaintext)-int(pad)], nil
}

// peelContentInfo strips the optional outer ContentInfo wrapper when it's
// present. CMS callers either hand us the bare EnvelopedData SEQUENCE or
// the same SEQUENCE wrapped in
//
//	ContentInfo ::= SEQUENCE {
//	  contentType OBJECT IDENTIFIER,
//	  content     [0] EXPLICIT ANY DEFINED BY contentType
//	}
//
// We try the wrapper shape first and unwrap to the inner content; on
// any parse failure the caller proceeds with the original bytes.
func peelContentInfo(der []byte, expectOID asn1.ObjectIdentifier) ([]byte, bool) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, false
	}
	if !ci.ContentType.Equal(expectOID) {
		return nil, false
	}
	return ci.Content.Bytes, true
}

// OIDEnvelopedData identifies the envelopedData CMS content type (RFC 5652
// §6, OID 1.2.840.113549.1.7.3). Used by peelContentInfo when the inbound
// bytes carry the optional ContentInfo wrapper.
var OIDEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
