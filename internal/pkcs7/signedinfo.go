// SignerInfo parser + signature verifier for SCEP PKIMessage.
//
// RFC 5652 §5 (SignedData) + RFC 8894 §3.2.1 (SCEP authenticatedAttributes).
//
// SCEP RFC 8894 + Intune master bundle Phase 2.2.
//
// The wire shape this parses (cited from RFC 5652 §5.3):
//
//	SignedData ::= SEQUENCE {
//	  version                  INTEGER,
//	  digestAlgorithms         SET OF AlgorithmIdentifier,
//	  encapContentInfo         EncapsulatedContentInfo,
//	  certificates             [0] IMPLICIT SET OF CertificateChoices OPTIONAL,
//	  crls                     [1] IMPLICIT SET OF RevocationInfoChoices OPTIONAL,
//	  signerInfos              SET OF SignerInfo                              -- the field this file targets
//	}
//
//	SignerInfo ::= SEQUENCE {
//	  version                  INTEGER (1|3),
//	  sid                      SignerIdentifier,        -- IssuerAndSerial for v1, SubjectKeyId for v3
//	  digestAlgorithm          AlgorithmIdentifier,
//	  signedAttrs              [0] IMPLICIT SignedAttributes OPTIONAL,
//	  signatureAlgorithm       AlgorithmIdentifier,
//	  signature                OCTET STRING,
//	  unsignedAttrs            [1] IMPLICIT UnsignedAttributes OPTIONAL
//	}
//
//	SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
//	Attribute ::= SEQUENCE { attrType OID, attrValues SET OF AttributeValue }
//
// The CMS signature is computed over the DER re-serialisation of the
// signedAttrs as a SET OF Attribute (NOT as the [0] IMPLICIT-tagged form
// it appears as in the wire). RFC 5652 §5.4 spells this out — easy to
// get wrong, every CMS implementation has hit this.

package pkcs7

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is RFC 8894 §3.5.2 baseline; SHA-256 also accepted
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/shankar0123/certctl/internal/domain"
)

// SCEP authenticated-attribute OIDs (RFC 8894 §3.2.1.4).
var (
	OIDSCEPMessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	OIDSCEPPKIStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	OIDSCEPFailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	OIDSCEPSenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	OIDSCEPRecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	OIDSCEPTransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}

	// CMS standard authenticated-attribute OIDs used by the signature
	// verification (RFC 5652 §11).
	OIDContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// CMS digest algorithm OIDs.
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// Signature algorithm OIDs the verifier accepts.
	OIDRSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDRSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDRSAWithSHA512   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// signedData CMS content type (RFC 5652 §5).
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// ErrSignerInfoVerify is returned when signature verification fails. Like
// the EnvelopedData decrypt error, the message text is intentionally
// generic so the wire response collapses to BadMessageCheck.
var ErrSignerInfoVerify = errors.New("signerInfo: signature verification failed")

// SignerInfo represents an unwrapped CMS signerInfo with its parsed
// authenticatedAttributes. Used for SCEP POPO verification.
type SignerInfo struct {
	Version            int
	SignerCert         *x509.Certificate        // device's transient signing cert (from the SignedData certificates field)
	AuthAttributes     map[string]asn1.RawValue // keyed by attribute OID dotted-string
	rawSignedAttrs     []byte                   // DER of the [0] IMPLICIT SignedAttributes — used for re-serialisation
	DigestAlgorithm    asn1.ObjectIdentifier
	SignatureAlgorithm asn1.ObjectIdentifier
	Signature          []byte
}

// SignedData is the parsed top-level SignedData structure with the
// signers + the optional certificates the SET carries (used to look up
// the device's transient signing cert by SignerInfo.sid).
type SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier
	EncapContentType asn1.ObjectIdentifier
	EncapContent     []byte // the inner content the SignedData wraps; nil if the wire used external signature
	Certificates     []*x509.Certificate
	SignerInfos      []*SignerInfo
}

// signedDataASN1 is the ASN.1 unmarshal target for the SignedData
// structure. Members tagged with their on-the-wire shapes.
type signedDataASN1 struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfoASN1
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"` // [0] IMPLICIT SET OF Certificate
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

type encapContentInfoASN1 struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type signerInfoASN1 struct {
	Version            int
	SID                asn1.RawValue // CHOICE — IssuerAndSerial (default) or [0] SubjectKeyId
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"` // [0] IMPLICIT SET OF Attribute
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type attributeASN1 struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"` // SET OF AttributeValue — left raw; per-attr decoder handles
}

// ParseSignedData parses a CMS ContentInfo wrapping a SignedData and
// returns the parsed structure including any certs + signerInfos.
//
// SCEP clients put the device's transient signing cert in the
// certificates field; the handler's POPO check picks the cert matching
// each signerInfo's SID and verifies with that cert's public key.
func ParseSignedData(der []byte) (*SignedData, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("signedData: empty input")
	}
	// Try peeling the optional outer ContentInfo (SEQUENCE { OID, [0] EXPLICIT ANY }).
	if peeled, ok := peelContentInfo(der, OIDSignedData); ok {
		der = peeled
	}

	var raw signedDataASN1
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("signedData: parse outer SEQUENCE: %w", err)
	}

	out := &SignedData{
		Version:          raw.Version,
		DigestAlgorithms: raw.DigestAlgorithms,
		EncapContentType: raw.EncapContentInfo.ContentType,
	}
	// EncapContent is [0] EXPLICIT — the [0] EXPLICIT wrapper holds an
	// OCTET STRING whose Bytes are the inner content. Some encoders use
	// a degenerate empty content (external-signature mode); that's fine.
	if len(raw.EncapContentInfo.Content.Bytes) > 0 {
		// The OCTET STRING wrapper inside [0] EXPLICIT — strip it.
		var innerOctet asn1.RawValue
		if _, err := asn1.Unmarshal(raw.EncapContentInfo.Content.Bytes, &innerOctet); err == nil && innerOctet.Tag == asn1.TagOctetString {
			out.EncapContent = innerOctet.Bytes
		} else {
			out.EncapContent = raw.EncapContentInfo.Content.Bytes
		}
	}

	// Parse certificates SET. Each member is a Certificate (SEQUENCE).
	if len(raw.Certificates.Bytes) > 0 {
		certBytes := raw.Certificates.Bytes
		for len(certBytes) > 0 {
			var rv asn1.RawValue
			rest, err := asn1.Unmarshal(certBytes, &rv)
			if err != nil {
				break
			}
			if rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagSequence {
				if cert, err := x509.ParseCertificate(rv.FullBytes); err == nil {
					out.Certificates = append(out.Certificates, cert)
				}
				// else: not a parseable cert (could be other CertificateChoices) — skip
			}
			certBytes = rest
		}
	}

	// Parse each SignerInfo + look up its SignerCert from out.Certificates.
	for _, siRaw := range raw.SignerInfos {
		si, err := parseSignerInfoFromRaw(siRaw, out.Certificates)
		if err != nil {
			// Skip individual unparseable signerInfos rather than failing
			// the whole SignedData — multi-signer CMS may have one bad
			// signer alongside good ones (rare in SCEP, but keep tolerant).
			continue
		}
		out.SignerInfos = append(out.SignerInfos, si)
	}
	// Empty signerInfos is valid for the degenerate certs-only PKCS#7
	// form (RFC 8894 §3.5.1 GetCACert response, RFC 7030 EST cacerts) —
	// a SignedData with only the certificates field populated and no
	// signers. The caller of ParseSignedData decides whether the lack
	// of signers is an error in their context (the SCEP RFC 8894
	// PKIMessage handler treats it as a fall-through to the MVP path;
	// the CertRep certs-only inner content treats it as expected).
	return out, nil
}

// ParseSignerInfos extracts SignerInfo records from a SignedData blob.
// Convenience wrapper around ParseSignedData when the caller only cares
// about the signers, not the certificates list.
func ParseSignerInfos(signedDataDER []byte) ([]*SignerInfo, error) {
	sd, err := ParseSignedData(signedDataDER)
	if err != nil {
		return nil, err
	}
	return sd.SignerInfos, nil
}

func parseSignerInfoFromRaw(raw asn1.RawValue, certs []*x509.Certificate) (*SignerInfo, error) {
	var siRaw signerInfoASN1
	if _, err := asn1.Unmarshal(raw.FullBytes, &siRaw); err != nil {
		return nil, fmt.Errorf("signerInfo: parse SEQUENCE: %w", err)
	}

	si := &SignerInfo{
		Version:            siRaw.Version,
		AuthAttributes:     map[string]asn1.RawValue{},
		DigestAlgorithm:    siRaw.DigestAlgorithm.Algorithm,
		SignatureAlgorithm: siRaw.SignatureAlgorithm.Algorithm,
		Signature:          siRaw.Signature,
		rawSignedAttrs:     siRaw.SignedAttrs.Bytes, // bytes inside the [0] IMPLICIT — used for re-serialisation
	}

	// Walk authenticated attributes (SET OF Attribute). The [0] IMPLICIT
	// wrapper means siRaw.SignedAttrs.Bytes holds the SET-OF body directly
	// (no extra OCTET STRING wrapper).
	attrBytes := siRaw.SignedAttrs.Bytes
	for len(attrBytes) > 0 {
		var attr attributeASN1
		rest, err := asn1.Unmarshal(attrBytes, &attr)
		if err != nil {
			break
		}
		si.AuthAttributes[attr.Type.String()] = attr.Values
		attrBytes = rest
	}

	// Resolve SignerCert by matching the SID against the certs list. SCEP
	// uses IssuerAndSerial for v1; the [0] IMPLICIT SubjectKeyId form is
	// v3 — accept both.
	si.SignerCert = matchSignerCert(siRaw.SID, certs)
	if si.SignerCert == nil {
		return nil, fmt.Errorf("signerInfo: SignerCert not found in SignedData certificates")
	}
	return si, nil
}

func matchSignerCert(sid asn1.RawValue, certs []*x509.Certificate) *x509.Certificate {
	// IssuerAndSerial form: SEQUENCE (no context tag) — universal class.
	if sid.Class == asn1.ClassUniversal && sid.Tag == asn1.TagSequence {
		var ias issuerAndSerialASN1
		if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err == nil {
			for _, c := range certs {
				if c.SerialNumber == nil || ias.SerialNumber == nil {
					continue
				}
				if ias.SerialNumber.Cmp(c.SerialNumber) != 0 {
					continue
				}
				if asn1Equal(ias.Issuer.FullBytes, c.RawIssuer) {
					return c
				}
			}
		}
		return nil
	}
	// SubjectKeyIdentifier form: [0] IMPLICIT OCTET STRING.
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		ski := sid.Bytes
		for _, c := range certs {
			if asn1Equal(c.SubjectKeyId, ski) {
				return c
			}
		}
	}
	return nil
}

func asn1Equal(a, b []byte) bool {
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

// VerifySignature verifies the signerInfo's signature over the
// authenticatedAttributes (SCEP POPO).
//
// CMS signature semantics (RFC 5652 §5.4):
//
//  1. Re-serialise signedAttrs as a SET OF Attribute. The wire form is
//     [0] IMPLICIT, but the signature is computed over the EXPLICIT
//     SET OF re-serialisation. Easy mistake; this is the canonical CMS
//     quirk every implementation hits.
//  2. Hash the re-serialised bytes with DigestAlgorithm.
//  3. Verify Signature against the hash using SignerCert.PublicKey +
//     SignatureAlgorithm.
//
// Supports RSA-PKCS1v15 + ECDSA. Rejects RSA-PSS as out-of-spec for SCEP.
func (s *SignerInfo) VerifySignature() error {
	if s == nil || s.SignerCert == nil {
		return ErrSignerInfoVerify
	}
	if len(s.rawSignedAttrs) == 0 {
		return ErrSignerInfoVerify
	}

	// Re-serialise as SET OF Attribute. We have rawSignedAttrs which is
	// the bytes INSIDE the [0] IMPLICIT wrapper — that's the SET OF body.
	// Wrap with the SET tag (0x31) + length to get the canonical form
	// the signature is computed over.
	signedAttrsForSig := ASN1Wrap(0x31, s.rawSignedAttrs)

	// Hash with the digest algorithm.
	digest, hashAlg, err := hashForOID(s.DigestAlgorithm, signedAttrsForSig)
	if err != nil {
		return ErrSignerInfoVerify
	}

	switch pub := s.SignerCert.PublicKey.(type) {
	case *rsa.PublicKey:
		if !isRSASigAlg(s.SignatureAlgorithm) {
			return ErrSignerInfoVerify
		}
		if err := rsa.VerifyPKCS1v15(pub, hashAlg, digest, s.Signature); err != nil {
			return ErrSignerInfoVerify
		}
		return nil
	case *ecdsa.PublicKey:
		if !isECDSASigAlg(s.SignatureAlgorithm) {
			return ErrSignerInfoVerify
		}
		// crypto/ecdsa.VerifyASN1 takes the same hash, returns bool
		if !ecdsa.VerifyASN1(pub, digest, s.Signature) {
			return ErrSignerInfoVerify
		}
		return nil
	default:
		return ErrSignerInfoVerify
	}
}

func hashForOID(oid asn1.ObjectIdentifier, data []byte) ([]byte, crypto.Hash, error) {
	switch {
	case oid.Equal(OIDSHA256), oid.Equal(OIDRSAWithSHA256), oid.Equal(OIDECDSAWithSHA256):
		h := sha256.Sum256(data)
		return h[:], crypto.SHA256, nil
	case oid.Equal(OIDSHA512), oid.Equal(OIDRSAWithSHA512), oid.Equal(OIDECDSAWithSHA512):
		h := sha512.Sum512(data)
		return h[:], crypto.SHA512, nil
	case oid.Equal(OIDSHA1), oid.Equal(OIDRSAWithSHA1):
		// SHA-1 still appears in legacy SCEP clients (Cisco IOS pre-2018).
		// RFC 8894 §3.5.2 advertises SHA-256 as preferred but does not ban SHA-1.
		h := sha1.Sum(data) //nolint:gosec // RFC 8894 §3.5.2 baseline
		return h[:], crypto.SHA1, nil
	}
	return nil, 0, fmt.Errorf("unsupported digest algorithm: %v", oid)
}

func isRSASigAlg(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(OIDRSAWithSHA1) || oid.Equal(OIDRSAWithSHA256) || oid.Equal(OIDRSAWithSHA512) || oid.Equal(OIDRSAEncryption)
}

func isECDSASigAlg(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(OIDECDSAWithSHA256) || oid.Equal(OIDECDSAWithSHA512)
}

// --- SCEP authenticated-attribute extractors -----------------------------

// GetMessageType returns the SCEP messageType value (RFC 8894 §3.2.1.4.1
// — encoded as a PrintableString containing the decimal ASCII of the
// message type integer, e.g. "19" for PKCSReq).
func (s *SignerInfo) GetMessageType() (domain.SCEPMessageType, error) {
	str, err := s.attrPrintableString(OIDSCEPMessageType)
	if err != nil {
		return 0, err
	}
	mt, err := strconv.Atoi(str)
	if err != nil {
		return 0, fmt.Errorf("messageType: parse %q as integer: %w", str, err)
	}
	return domain.SCEPMessageType(mt), nil
}

// GetTransactionID returns the SCEP transactionID (RFC 8894 §3.2.1.4.4 —
// PrintableString chosen by the client; server MUST echo verbatim in
// CertRep).
func (s *SignerInfo) GetTransactionID() (string, error) {
	return s.attrPrintableString(OIDSCEPTransactionID)
}

// GetSenderNonce returns the 16-byte SCEP senderNonce (RFC 8894 §3.2.1.4.5
// — OCTET STRING).
func (s *SignerInfo) GetSenderNonce() ([]byte, error) {
	return s.attrOctetString(OIDSCEPSenderNonce)
}

// GetMessageDigest returns the standard CMS messageDigest auth-attr
// (RFC 5652 §11.2). Used by the signature verification — when
// signedAttrs is present, the signature is over the re-serialised
// signedAttrs SET; the messageDigest auth-attr is what binds the
// signedAttrs to the encapContent.
func (s *SignerInfo) GetMessageDigest() ([]byte, error) {
	return s.attrOctetString(OIDMessageDigest)
}

// attrPrintableString extracts a PrintableString from the AuthAttributes
// SET-OF-Attribute-Values for the given attribute OID. Caller-side validation
// of length / charset is left to the SCEP-specific extractor.
func (s *SignerInfo) attrPrintableString(oid asn1.ObjectIdentifier) (string, error) {
	rv, ok := s.AuthAttributes[oid.String()]
	if !ok {
		return "", fmt.Errorf("auth-attr %v not present", oid)
	}
	// rv is the SET OF AttributeValue — typically one element. The
	// first element is a PrintableString or IA5String.
	if len(rv.Bytes) == 0 {
		return "", fmt.Errorf("auth-attr %v: empty value", oid)
	}
	var inner asn1.RawValue
	if _, err := asn1.Unmarshal(rv.Bytes, &inner); err != nil {
		return "", fmt.Errorf("auth-attr %v: unmarshal value: %w", oid, err)
	}
	// PrintableString / IA5String / UTF8String all carry their bytes
	// directly in inner.Bytes.
	switch inner.Tag {
	case asn1.TagPrintableString, asn1.TagIA5String, asn1.TagUTF8String:
		return string(inner.Bytes), nil
	}
	return "", fmt.Errorf("auth-attr %v: unexpected value tag %d", oid, inner.Tag)
}

func (s *SignerInfo) attrOctetString(oid asn1.ObjectIdentifier) ([]byte, error) {
	rv, ok := s.AuthAttributes[oid.String()]
	if !ok {
		return nil, fmt.Errorf("auth-attr %v not present", oid)
	}
	if len(rv.Bytes) == 0 {
		return nil, fmt.Errorf("auth-attr %v: empty value", oid)
	}
	var inner asn1.RawValue
	if _, err := asn1.Unmarshal(rv.Bytes, &inner); err != nil {
		return nil, fmt.Errorf("auth-attr %v: unmarshal value: %w", oid, err)
	}
	if inner.Tag != asn1.TagOctetString {
		return nil, fmt.Errorf("auth-attr %v: unexpected value tag %d (want OCTET STRING)", oid, inner.Tag)
	}
	return inner.Bytes, nil
}

// silence unused warning for big.Int — referenced via issuerAndSerialASN1 in
// envelopeddata.go but the linker only sees it once per package; this keeps
// the import healthy if someone deletes envelopeddata.go's helper struct.
var _ = (*big.Int)(nil)
