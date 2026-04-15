// Package pkcs7 provides ASN.1 helpers for building PKCS#7 structures.
// Used by EST (RFC 7030) and SCEP (RFC 8894) protocol handlers.
// No external dependencies — hand-rolled ASN.1 encoding only.
package pkcs7

import (
	"encoding/pem"
	"fmt"
)

// BuildCertsOnlyPKCS7 creates a degenerate PKCS#7 SignedData structure containing only certificates.
// This is the "certs-only" format specified in RFC 7030 Section 4.1.3 for /cacerts responses
// and enrollment responses, and used by SCEP (RFC 8894) for GetCACert responses.
//
// ASN.1 structure (simplified):
//
//	ContentInfo {
//	  contentType: signedData (1.2.840.113549.1.7.2)
//	  content: SignedData {
//	    version: 1
//	    digestAlgorithms: {} (empty)
//	    encapContentInfo: { contentType: data (1.2.840.113549.1.7.1) }
//	    certificates: [cert1, cert2, ...]
//	    signerInfos: {} (empty)
//	  }
//	}
func BuildCertsOnlyPKCS7(derCerts [][]byte) ([]byte, error) {
	// OID for signedData: 1.2.840.113549.1.7.2
	oidSignedData := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
	// OID for data: 1.2.840.113549.1.7.1
	oidData := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}

	// Build certificates [0] IMPLICIT SET OF Certificate
	var certsContent []byte
	for _, cert := range derCerts {
		certsContent = append(certsContent, cert...)
	}
	certsField := ASN1WrapImplicit(0, certsContent)

	// Build encapContentInfo: SEQUENCE { OID data }
	encapContentInfo := ASN1WrapSequence(oidData)

	// Build digestAlgorithms: SET {} (empty)
	digestAlgorithms := ASN1WrapSet(nil)

	// Build signerInfos: SET {} (empty)
	signerInfos := ASN1WrapSet(nil)

	// Version: INTEGER 1
	version := []byte{0x02, 0x01, 0x01}

	// Build SignedData SEQUENCE
	var signedDataContent []byte
	signedDataContent = append(signedDataContent, version...)
	signedDataContent = append(signedDataContent, digestAlgorithms...)
	signedDataContent = append(signedDataContent, encapContentInfo...)
	signedDataContent = append(signedDataContent, certsField...)
	signedDataContent = append(signedDataContent, signerInfos...)
	signedData := ASN1WrapSequence(signedDataContent)

	// Wrap in [0] EXPLICIT for ContentInfo.content
	contentField := ASN1WrapExplicit(0, signedData)

	// Build ContentInfo SEQUENCE
	var contentInfoContent []byte
	contentInfoContent = append(contentInfoContent, oidSignedData...)
	contentInfoContent = append(contentInfoContent, contentField...)
	contentInfo := ASN1WrapSequence(contentInfoContent)

	return contentInfo, nil
}

// PEMToDERChain converts PEM-encoded certificates to a slice of DER-encoded certificates.
func PEMToDERChain(pemData string) ([][]byte, error) {
	var derCerts [][]byte
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			derCerts = append(derCerts, block.Bytes)
		}
	}
	if len(derCerts) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}
	return derCerts, nil
}

// ASN1WrapSequence wraps content in an ASN.1 SEQUENCE tag (0x30).
func ASN1WrapSequence(content []byte) []byte {
	return ASN1Wrap(0x30, content)
}

// ASN1WrapSet wraps content in an ASN.1 SET tag (0x31).
func ASN1WrapSet(content []byte) []byte {
	return ASN1Wrap(0x31, content)
}

// ASN1WrapExplicit wraps content in an ASN.1 context-specific EXPLICIT tag.
func ASN1WrapExplicit(tag int, content []byte) []byte {
	return ASN1Wrap(byte(0xa0|tag), content)
}

// ASN1WrapImplicit wraps content in an ASN.1 context-specific IMPLICIT CONSTRUCTED tag.
func ASN1WrapImplicit(tag int, content []byte) []byte {
	return ASN1Wrap(byte(0xa0|tag), content)
}

// ASN1Wrap wraps content with an ASN.1 tag and length.
func ASN1Wrap(tag byte, content []byte) []byte {
	length := len(content)
	var result []byte
	result = append(result, tag)
	result = append(result, ASN1EncodeLength(length)...)
	result = append(result, content...)
	return result
}

// ASN1EncodeLength encodes a length in ASN.1 DER format.
func ASN1EncodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	// Long form
	var lengthBytes []byte
	l := length
	for l > 0 {
		lengthBytes = append([]byte{byte(l & 0xff)}, lengthBytes...)
		l >>= 8
	}
	return append([]byte{byte(0x80 | len(lengthBytes))}, lengthBytes...)
}
