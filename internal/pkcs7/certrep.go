// CertRep PKIMessage response builder for SCEP.
//
// RFC 8894 §3.3.2 (Certificate Response Message Format) +
// RFC 5652 §5 (SignedData) + RFC 5652 §6 (EnvelopedData).
//
// SCEP RFC 8894 + Intune master bundle Phase 3.1.
//
// Builds the wire shape (cited from RFC 8894 §3.3.2 + §3.2):
//
//	ContentInfo {
//	  contentType: signedData (1.2.840.113549.1.7.2)
//	  content: SignedData {
//	    version: 1
//	    digestAlgorithms: [SHA-256]
//	    encapContentInfo: {
//	      contentType: data (1.2.840.113549.1.7.1)
//	      content: EnvelopedData {                  -- on SUCCESS only
//	        version: 0
//	        recipientInfos: [{
//	          ktri: {
//	            rid: IssuerAndSerialNumber of clientCert
//	            keyEncryptionAlgorithm: rsaEncryption
//	            encryptedKey: AES-256-CBC key encrypted to clientCert.PublicKey
//	          }
//	        }]
//	        encryptedContentInfo: {
//	          contentType: pkcs7-data
//	          contentEncryptionAlgorithm: aes-256-cbc
//	          encryptedContent: AES-CBC-encrypted PKCS#7 certs-only with the issued cert + chain
//	        }
//	      }
//	    }
//	    certificates: [raCert]
//	    signerInfos: [{
//	      sid: IssuerAndSerialNumber of raCert
//	      digestAlgorithm: SHA-256
//	      signedAttrs: [
//	        contentType: data
//	        messageDigest: SHA-256(encapContentInfo.content)
//	        messageType: "3" (CertRep)
//	        pkiStatus: "0" | "2" | "3"
//	        transactionID: <echo of request>
//	        recipientNonce: <echo of request senderNonce>
//	        senderNonce: <fresh 16-byte server nonce>
//	        failInfo: <if pkiStatus="2">
//	      ]
//	      signatureAlgorithm: rsaWithSHA256 | ecdsaWithSHA256
//	      signature: raKey signs DER(SET OF signedAttrs)
//	    }]
//	  }
//	}
//
// On FAILURE, encapContentInfo.content is empty (no EnvelopedData), and the
// failInfo signed attribute is populated.
//
// On PENDING (deferred-issuance flow, not used in v1), encapContentInfo.content
// is empty, and the response carries a transactionID the client polls with
// GetCertInitial.

package pkcs7

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/shankar0123/certctl/internal/domain"
)

// BuildCertRepPKIMessage constructs the SCEP CertRep response PKIMessage.
//
// Inputs:
//   - req: the parsed inbound envelope (provides transactionID, senderNonce
//     to echo, and SignerCert — the device's transient cert we encrypt the
//     CertRep EnvelopedData TO).
//   - resp: the service-layer outcome (Status + FailInfo + Result).
//   - raCert + raKey: the RA pair the server signs the SignedData with
//     (loaded from CERTCTL_SCEP_RA_*; same pair used to decrypt the inbound
//     EnvelopedData in Phase 2).
//
// Critical correctness points (cited as comments in code):
//   - The CertRep encrypts the issued cert chain to the DEVICE's transient
//     signing cert (req.SignerCert), NOT the RA cert. The response goes
//     back to the device, encrypted with its public key.
//   - AES-256-CBC + random 16-byte IV per response. No reuse.
//   - senderNonce must be fresh per response (crypto/rand 16 bytes).
//   - recipientNonce + transactionID echoed verbatim from the request.
//   - The signature is over DER(SET OF signedAttrs) — the canonical CMS
//     quirk per RFC 5652 §5.4. The wire form uses [0] IMPLICIT but the
//     signature is computed over the SET OF re-serialisation. Easy
//     mistake; pinned by the round-trip test.
func BuildCertRepPKIMessage(req *domain.SCEPRequestEnvelope, resp *domain.SCEPResponseEnvelope, raCert *x509.Certificate, raKey crypto.PrivateKey) ([]byte, error) {
	if req == nil || resp == nil {
		return nil, fmt.Errorf("certRep: req and resp required")
	}
	if raCert == nil || raKey == nil {
		return nil, fmt.Errorf("certRep: RA cert/key required")
	}

	// 1. Build the encapContent — for SUCCESS, this is an EnvelopedData
	//    wrapping the issued cert chain encrypted to req.SignerCert. For
	//    FAILURE / PENDING, encapContent is empty.
	var encapContent []byte
	if resp.Status == domain.SCEPStatusSuccess && resp.Result != nil {
		// Parse the device's transient signing cert (recipient).
		if len(req.SignerCert) == 0 {
			return nil, fmt.Errorf("certRep: req.SignerCert required for SUCCESS response (need device pubkey to encrypt response)")
		}
		clientCert, err := x509.ParseCertificate(req.SignerCert)
		if err != nil {
			return nil, fmt.Errorf("certRep: parse req.SignerCert: %w", err)
		}
		clientRSAPub, ok := clientCert.PublicKey.(*rsa.PublicKey)
		if !ok {
			// SCEP requires RSA on the client side for keyTrans (RFC 8894
			// §3.5.2 advertises RSA only for the client-encryption side).
			return nil, fmt.Errorf("certRep: device transient cert must have RSA public key (got %T)", clientCert.PublicKey)
		}

		// Build the certs-only PKCS#7 carrying the issued cert + chain
		// (the inner content the EnvelopedData encrypts).
		issuedDER, err := PEMToDERChain(resp.Result.CertPEM)
		if err != nil {
			return nil, fmt.Errorf("certRep: parse issued cert PEM: %w", err)
		}
		var allDER [][]byte
		allDER = append(allDER, issuedDER...)
		if resp.Result.ChainPEM != "" {
			chainDER, err := PEMToDERChain(resp.Result.ChainPEM)
			if err == nil {
				allDER = append(allDER, chainDER...)
			}
		}
		certsOnly, err := BuildCertsOnlyPKCS7(allDER)
		if err != nil {
			return nil, fmt.Errorf("certRep: build certs-only PKCS#7: %w", err)
		}

		// Build the EnvelopedData encrypting certsOnly to clientRSAPub
		// using a fresh AES-256-CBC key + IV.
		encapContent, err = buildEnvelopedDataAES256(clientCert, clientRSAPub, certsOnly)
		if err != nil {
			return nil, fmt.Errorf("certRep: build EnvelopedData: %w", err)
		}
	}

	// 2. Compute messageDigest = SHA-256(encapContent). When encapContent
	//    is empty (FAILURE/PENDING), the messageDigest is over the empty
	//    byte slice — same hash for both legs, RFC 5652 §11.2 doesn't
	//    require a non-empty content.
	contentDigest := sha256.Sum256(encapContent)

	// 3. Generate a fresh 16-byte senderNonce. crypto/rand source; never
	//    reused across responses (RFC 8894 §3.2.1.4.5 — replay defense).
	senderNonce := make([]byte, 16)
	if _, err := rand.Read(senderNonce); err != nil {
		return nil, fmt.Errorf("certRep: senderNonce rand.Read: %w", err)
	}

	// 4. Build the auth-attrs SET-OF body (the bytes inside [0] IMPLICIT).
	//    Order matches micromdm/scep for byte-level wire-format diffing
	//    (DER SET-OF normalises order anyway, but matching the reference
	//    implementation makes audit + manual inspection easier).
	authAttrs := buildCertRepAuthAttrs(
		contentDigest[:],
		resp.Status,
		resp.FailInfo,
		resp.TransactionID,
		senderNonce,
		resp.RecipientNonce,
	)

	// 5. Sign the SET OF Attribute (re-serialised with the SET tag, not
	//    the [0] IMPLICIT wrapper — RFC 5652 §5.4 quirk).
	signedAttrsForSig := ASN1Wrap(0x31, authAttrs)
	sig, sigAlgOID, err := signCertRep(raKey, signedAttrsForSig)
	if err != nil {
		return nil, fmt.Errorf("certRep: sign auth-attrs: %w", err)
	}

	// 6. Build the SignerInfo SEQUENCE.
	siBytes, err := buildSignerInfoCertRep(raCert, sig, sigAlgOID, authAttrs)
	if err != nil {
		return nil, fmt.Errorf("certRep: build SignerInfo: %w", err)
	}

	// 7. Build encapContentInfo SEQUENCE { OID data, [0] EXPLICIT OCTET
	//    STRING content }.
	encapBytes := buildEncapContentInfo(encapContent)

	// 8. certificates [0] IMPLICIT SET OF Certificate carrying the RA cert
	//    so the device can verify the signature.
	certsBytes := ASN1Wrap(0xa0, raCert.Raw)

	// 9. digestAlgorithms SET OF AlgorithmIdentifier (one entry: SHA-256).
	digestAlg := pkix.AlgorithmIdentifier{Algorithm: OIDSHA256, Parameters: asn1.NullRawValue}
	digestAlgBytes, err := asn1.Marshal(digestAlg)
	if err != nil {
		return nil, fmt.Errorf("certRep: marshal digestAlg: %w", err)
	}
	digestAlgsBytes := ASN1Wrap(0x31, digestAlgBytes)

	// 10. signerInfos SET OF SignerInfo (one entry — the RA's signature).
	signerInfosBytes := ASN1Wrap(0x31, siBytes)

	// 11. Assemble SignedData SEQUENCE.
	sdBody := append([]byte{}, []byte{0x02, 0x01, 0x01}...) // INTEGER version=1
	sdBody = append(sdBody, digestAlgsBytes...)
	sdBody = append(sdBody, encapBytes...)
	sdBody = append(sdBody, certsBytes...)
	sdBody = append(sdBody, signerInfosBytes...)
	sdSeq := ASN1Wrap(0x30, sdBody)

	// 12. Wrap as ContentInfo SEQUENCE { OID signedData, [0] EXPLICIT
	//     SignedData }.
	contentField := ASN1Wrap(0xa0, sdSeq)
	oidSignedDataDER := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
	ciBody := append([]byte{}, oidSignedDataDER...)
	ciBody = append(ciBody, contentField...)
	return ASN1Wrap(0x30, ciBody), nil
}

// buildCertRepAuthAttrs builds the SET-OF body for the CertRep
// signedAttributes. Matches the order micromdm/scep emits (the DER SET-OF
// normalisation makes order irrelevant for the signature, but matching
// the reference implementation makes wire-diff debugging easier).
func buildCertRepAuthAttrs(msgDigest []byte, status domain.SCEPPKIStatus, failInfo domain.SCEPFailInfo, transactionID string, senderNonce, recipientNonce []byte) []byte {
	var out []byte
	// contentType: SET { OID data }
	out = append(out, attrSeqRaw(OIDContentType, ASN1Wrap(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}))...)
	// messageDigest: SET { OCTET STRING }
	out = append(out, attrSeqRaw(OIDMessageDigest, ASN1Wrap(0x04, msgDigest))...)
	// SCEP messageType: SET { PrintableString "3" — CertRep }
	out = append(out, attrSeqRaw(OIDSCEPMessageType, ASN1Wrap(0x13, []byte{'3'}))...)
	// SCEP pkiStatus: SET { PrintableString status code }
	out = append(out, attrSeqRaw(OIDSCEPPKIStatus, ASN1Wrap(0x13, []byte(status)))...)
	// SCEP transactionID: SET { PrintableString }
	out = append(out, attrSeqRaw(OIDSCEPTransactionID, ASN1Wrap(0x13, []byte(transactionID)))...)
	// SCEP senderNonce (server's fresh nonce): SET { OCTET STRING }
	out = append(out, attrSeqRaw(OIDSCEPSenderNonce, ASN1Wrap(0x04, senderNonce))...)
	// SCEP recipientNonce (echo of client's senderNonce): SET { OCTET STRING }
	if len(recipientNonce) > 0 {
		out = append(out, attrSeqRaw(OIDSCEPRecipientNonce, ASN1Wrap(0x04, recipientNonce))...)
	}
	// SCEP failInfo: ONLY when status == failure (RFC 8894 §3.2.1.4.4)
	if status == domain.SCEPStatusFailure {
		out = append(out, attrSeqRaw(OIDSCEPFailInfo, ASN1Wrap(0x13, []byte(failInfo)))...)
	}
	return out
}

// attrSeqRaw builds one Attribute SEQUENCE: SEQUENCE { OID, SET OF value }.
// `value` is one already-encoded TLV (e.g. an OCTET STRING or PrintableString);
// attrSeqRaw wraps it in a SET, prefixes the OID, and SEQUENCE-wraps.
func attrSeqRaw(oid asn1.ObjectIdentifier, value []byte) []byte {
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		// asn1.Marshal of a hardcoded OID never fails; a panic here is
		// a programmer error worth surfacing immediately.
		panic("certRep: marshal OID: " + err.Error())
	}
	setOfValue := ASN1Wrap(0x31, value)
	body := append([]byte{}, oidBytes...)
	body = append(body, setOfValue...)
	return ASN1Wrap(0x30, body)
}

// buildSignerInfoCertRep assembles the SignerInfo for the CertRep response.
// The signature is already computed; this just packages everything into the
// SignerInfo SEQUENCE.
func buildSignerInfoCertRep(raCert *x509.Certificate, sig []byte, sigAlgOID asn1.ObjectIdentifier, authAttrsSetBody []byte) ([]byte, error) {
	versionBytes := []byte{0x02, 0x01, 0x01} // INTEGER version=1

	// SID = IssuerAndSerialNumber: SEQUENCE { Issuer (RDN), SerialNumber }
	serialDER, err := asn1.Marshal(raCert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("marshal RA serial: %w", err)
	}
	sidBody := append([]byte{}, raCert.RawIssuer...)
	sidBody = append(sidBody, serialDER...)
	sidBytes := ASN1Wrap(0x30, sidBody)

	digestAlg := pkix.AlgorithmIdentifier{Algorithm: OIDSHA256, Parameters: asn1.NullRawValue}
	digestAlgBytes, err := asn1.Marshal(digestAlg)
	if err != nil {
		return nil, fmt.Errorf("marshal digestAlg: %w", err)
	}

	signedAttrsImplicitBytes := ASN1Wrap(0xa0, authAttrsSetBody) // [0] IMPLICIT SET OF

	sigAlg := pkix.AlgorithmIdentifier{Algorithm: sigAlgOID}
	if sigAlgOID.Equal(OIDRSAWithSHA256) {
		sigAlg.Parameters = asn1.NullRawValue
	}
	sigAlgBytes, err := asn1.Marshal(sigAlg)
	if err != nil {
		return nil, fmt.Errorf("marshal sigAlg: %w", err)
	}

	sigOctetBytes := ASN1Wrap(0x04, sig) // OCTET STRING

	siBody := append([]byte{}, versionBytes...)
	siBody = append(siBody, sidBytes...)
	siBody = append(siBody, digestAlgBytes...)
	siBody = append(siBody, signedAttrsImplicitBytes...)
	siBody = append(siBody, sigAlgBytes...)
	siBody = append(siBody, sigOctetBytes...)
	return ASN1Wrap(0x30, siBody), nil
}

// signCertRep signs the SET-OF-encoded auth-attrs with the RA key, returning
// the signature bytes and the matching signature-algorithm OID.
func signCertRep(raKey crypto.PrivateKey, signedAttrsForSig []byte) ([]byte, asn1.ObjectIdentifier, error) {
	digest := sha256.Sum256(signedAttrsForSig)
	switch k := raKey.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		if err != nil {
			return nil, nil, fmt.Errorf("rsa sign: %w", err)
		}
		return sig, OIDRSAWithSHA256, nil
	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
		if err != nil {
			return nil, nil, fmt.Errorf("ecdsa sign: %w", err)
		}
		return sig, OIDECDSAWithSHA256, nil
	default:
		return nil, nil, fmt.Errorf("unsupported RA key type %T (want *rsa.PrivateKey or *ecdsa.PrivateKey)", raKey)
	}
}

// buildEncapContentInfo builds SEQUENCE { OID data, [0] EXPLICIT OCTET STRING content }.
// content is empty for FAILURE/PENDING responses; the [0] EXPLICIT wrapper is
// omitted entirely in that case (RFC 5652 §5.2 — the OPTIONAL field is just
// absent rather than carrying an empty OCTET STRING).
func buildEncapContentInfo(content []byte) []byte {
	oidDataBytes := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}
	body := append([]byte{}, oidDataBytes...)
	if len(content) > 0 {
		octetBytes := ASN1Wrap(0x04, content)
		explicitWrapper := ASN1Wrap(0xa0, octetBytes)
		body = append(body, explicitWrapper...)
	}
	return ASN1Wrap(0x30, body)
}

// buildEnvelopedDataAES256 builds an EnvelopedData encrypting `plaintext`
// to `recipientCert`'s public key (RSA). Uses AES-256-CBC + random 16-byte IV
// + PKCS#7 padding. Returns the EnvelopedData DER bytes ready to embed as
// the encapContent of a SignedData.
func buildEnvelopedDataAES256(recipientCert *x509.Certificate, recipientPub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	// 1. Generate random AES-256 key + IV.
	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		return nil, fmt.Errorf("rand symKey: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("rand iv: %w", err)
	}

	// 2. PKCS#7-pad plaintext to AES block boundary.
	bs := aes.BlockSize
	padLen := bs - len(plaintext)%bs
	padded := make([]byte, 0, len(plaintext)+padLen)
	padded = append(padded, plaintext...)
	for i := 0; i < padLen; i++ {
		padded = append(padded, byte(padLen))
	}

	// 3. AES-CBC encrypt.
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	enc.CryptBlocks(ciphertext, padded)

	// 4. RSA PKCS#1 v1.5 encrypt the AES key with recipientPub.
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, recipientPub, symKey)
	if err != nil {
		return nil, fmt.Errorf("rsa encrypt: %w", err)
	}

	// 5. Build IssuerAndSerialNumber identifying the recipient.
	serialDER, err := asn1.Marshal(recipientCert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("marshal recipient serial: %w", err)
	}
	risBody := append([]byte{}, recipientCert.RawIssuer...)
	risBody = append(risBody, serialDER...)
	risBytes := ASN1Wrap(0x30, risBody)

	// 6. Build KeyTransRecipientInfo SEQUENCE.
	keyEncAlg := pkix.AlgorithmIdentifier{Algorithm: OIDRSAEncryption, Parameters: asn1.NullRawValue}
	keyEncAlgBytes, err := asn1.Marshal(keyEncAlg)
	if err != nil {
		return nil, fmt.Errorf("marshal keyEncAlg: %w", err)
	}
	encryptedKeyBytes := ASN1Wrap(0x04, encryptedKey)

	ktriBody := append([]byte{}, []byte{0x02, 0x01, 0x00}...) // INTEGER version=0
	ktriBody = append(ktriBody, risBytes...)
	ktriBody = append(ktriBody, keyEncAlgBytes...)
	ktriBody = append(ktriBody, encryptedKeyBytes...)
	ktriBytes := ASN1Wrap(0x30, ktriBody)

	// 7. recipientInfos SET OF RecipientInfo (one entry).
	recipientInfosBytes := ASN1Wrap(0x31, ktriBytes)

	// 8. Build the AlgorithmIdentifier with the IV as parameters
	//    (RFC 3565 §2.3).
	ivOctet := ASN1Wrap(0x04, iv)
	contentAlg := pkix.AlgorithmIdentifier{
		Algorithm:  OIDAES256CBC,
		Parameters: asn1.RawValue{FullBytes: ivOctet},
	}
	contentAlgBytes, err := asn1.Marshal(contentAlg)
	if err != nil {
		return nil, fmt.Errorf("marshal contentAlg: %w", err)
	}

	// 9. Build EncryptedContentInfo SEQUENCE.
	//    encryptedContent is [0] IMPLICIT OCTET STRING — the OCTET STRING
	//    tag is replaced by the [0] context-specific tag, but the content
	//    bytes are written directly without the inner OCTET STRING tag.
	encContentField := append([]byte{}, ASN1Wrap(0x80, ciphertext)...) // [0] IMPLICIT primitive
	oidDataBytes := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}
	eciBody := append([]byte{}, oidDataBytes...)
	eciBody = append(eciBody, contentAlgBytes...)
	eciBody = append(eciBody, encContentField...)
	eciBytes := ASN1Wrap(0x30, eciBody)

	// 10. Assemble EnvelopedData SEQUENCE.
	envBody := append([]byte{}, []byte{0x02, 0x01, 0x00}...) // INTEGER version=0
	envBody = append(envBody, recipientInfosBytes...)
	envBody = append(envBody, eciBytes...)
	return ASN1Wrap(0x30, envBody), nil
}

// silence unused-import / cross-file linker warnings for big.Int + pem on
// builds that exclude certain code paths.
var (
	_ = (*big.Int)(nil)
	_ = (*pem.Block)(nil)
)
