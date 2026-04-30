package service

import (
	"encoding/asn1"
	"errors"
)

// Production hardening II Phase 1.1 — OCSP nonce extension parsing.
//
// RFC 6960 §4.4.1 defines the optional id-pkix-ocsp-nonce extension
// (OID 1.3.6.1.5.5.7.48.1.2) that defends against replay attacks.
// When present in the request, the responder MUST echo the same
// nonce value in the response. When absent, the response MUST NOT
// include a nonce.
//
// `golang.org/x/crypto/ocsp.Request` does NOT expose the request's
// extensions field — we have to walk the raw DER ourselves to extract
// the nonce. The grammar (RFC 6960 §4.1.1):
//
//	OCSPRequest ::= SEQUENCE {
//	  tbsRequest          TBSRequest,
//	  optionalSignature   [0] EXPLICIT Signature OPTIONAL
//	}
//	TBSRequest ::= SEQUENCE {
//	  version             [0] EXPLICIT Version DEFAULT v1,
//	  requestorName       [1] EXPLICIT GeneralName OPTIONAL,
//	  requestList         SEQUENCE OF Request,
//	  requestExtensions   [2] EXPLICIT Extensions OPTIONAL
//	}
//	Extension ::= SEQUENCE {
//	  extnID    OBJECT IDENTIFIER,
//	  critical  BOOLEAN DEFAULT FALSE,
//	  extnValue OCTET STRING
//	}
//
// The nonce extension's extnValue is itself a DER-encoded OCTET STRING
// containing the nonce bytes (per RFC 6960 §4.4.1 — "The value of the
// extension SHALL be the value of a Nonce ::= OCTET STRING").

// OIDOCSPNonce is the id-pkix-ocsp-nonce extension OID (RFC 6960 §4.4.1).
var OIDOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// MaxOCSPNonceLength is the per-CA/B-Forum-guidance cap on the nonce
// payload size. Larger nonces are rejected as malformed (Phase 1
// frozen decision). The CA/B Forum Baseline Requirements §4.10.2
// notes that nonces SHOULD be at most 32 octets.
const MaxOCSPNonceLength = 32

// ErrOCSPNonceMalformed is returned when the request carries a nonce
// extension but the nonce value violates the documented constraints
// (empty, oversized, or unparseable). The handler maps this to an
// "unauthorized" OCSP response (status 6 per RFC 6960 §2.3) rather
// than echoing potentially-malicious bytes back to the relying party.
var ErrOCSPNonceMalformed = errors.New("OCSP request: nonce extension malformed")

// ParseOCSPRequestNonce extracts the nonce value (if any) from the
// OCSP request's TBSRequest.requestExtensions field.
//
// Returns:
//   - (nonceBytes, true, nil)  — well-formed nonce, echo it.
//   - (nil, false, nil)        — no nonce extension present (back-compat).
//   - (nil, false, ErrOCSPNonceMalformed) — nonce present but malformed
//     (zero length OR > MaxOCSPNonceLength). Handler MUST NOT echo;
//     return an unauthorized OCSP response.
//
// The function is tolerant of arbitrary OCSP requests including those
// with an optionalSignature: it parses the OCSPRequest envelope first,
// then walks tbsRequest.
func ParseOCSPRequestNonce(reqDER []byte) (nonce []byte, present bool, err error) {
	// OCSPRequest ::= SEQUENCE { tbsRequest, [0] OPTIONAL signature }
	var ocspReq asn1.RawValue
	if _, err := asn1.Unmarshal(reqDER, &ocspReq); err != nil {
		// Not our problem — ocsp.ParseRequest already validated this
		// path. Return "no nonce" rather than surfacing a redundant
		// parse error to the caller.
		return nil, false, nil
	}

	// Walk the SEQUENCE: tbsRequest is the first element.
	var tbsRequest asn1.RawValue
	rest, err := asn1.Unmarshal(ocspReq.Bytes, &tbsRequest)
	if err != nil {
		return nil, false, nil
	}
	_ = rest // optionalSignature ignored — we never validate request signatures

	// TBSRequest ::= SEQUENCE { [0] version OPTIONAL, [1] requestorName
	//                           OPTIONAL, requestList, [2] requestExtensions
	//                           OPTIONAL }
	//
	// Walk the elements; pick out the [2] EXPLICIT tag.
	tail := tbsRequest.Bytes
	for len(tail) > 0 {
		var elem asn1.RawValue
		var rerr error
		tail, rerr = asn1.Unmarshal(tail, &elem)
		if rerr != nil {
			return nil, false, nil
		}
		if elem.Class != asn1.ClassContextSpecific || elem.Tag != 2 {
			continue
		}
		// elem.Bytes is the inner Extensions (which is a SEQUENCE OF
		// Extension). Unmarshal into []pkix.Extension-equivalent.
		return extractNonceFromExtensions(elem.Bytes)
	}
	return nil, false, nil
}

// extractNonceFromExtensions walks a SEQUENCE OF Extension looking for
// the id-pkix-ocsp-nonce OID. Returns the OCTET STRING contents on
// match, or (nil, false, nil) on no-match.
func extractNonceFromExtensions(extBytes []byte) ([]byte, bool, error) {
	// extBytes is the SEQUENCE OF Extension wrapped in its outer
	// SEQUENCE tag. Unwrap once.
	var extSeq asn1.RawValue
	if _, err := asn1.Unmarshal(extBytes, &extSeq); err != nil {
		return nil, false, nil
	}
	tail := extSeq.Bytes
	for len(tail) > 0 {
		var ext struct {
			ExtnID    asn1.ObjectIdentifier
			Critical  bool `asn1:"optional"`
			ExtnValue []byte
		}
		var rerr error
		tail, rerr = asn1.Unmarshal(tail, &ext)
		if rerr != nil {
			// Try the no-Critical form (DER allows the BOOLEAN to be
			// omitted entirely when DEFAULT FALSE).
			var ext2 struct {
				ExtnID    asn1.ObjectIdentifier
				ExtnValue []byte
			}
			tail2, rerr2 := asn1.Unmarshal(tail, &ext2)
			if rerr2 != nil {
				return nil, false, nil
			}
			tail = tail2
			ext.ExtnID = ext2.ExtnID
			ext.ExtnValue = ext2.ExtnValue
		}
		if !ext.ExtnID.Equal(OIDOCSPNonce) {
			continue
		}
		// extnValue is itself a DER-encoded OCTET STRING (per RFC 6960
		// §4.4.1: "The value of the extension SHALL be the value of a
		// Nonce ::= OCTET STRING"). Unwrap once more.
		var nonce []byte
		if _, err := asn1.Unmarshal(ext.ExtnValue, &nonce); err != nil {
			return nil, false, ErrOCSPNonceMalformed
		}
		if len(nonce) == 0 {
			return nil, false, ErrOCSPNonceMalformed
		}
		if len(nonce) > MaxOCSPNonceLength {
			return nil, false, ErrOCSPNonceMalformed
		}
		return nonce, true, nil
	}
	return nil, false, nil
}

// (The inverse — wrapping the nonce bytes back into an extnValue
// OCTET STRING — happens inline in the local issuer's
// SignOCSPResponse, where the response's ExtraExtensions field is
// populated. There's no need for a separate marshaling helper here:
// asn1.Marshal([]byte) produces the canonical OCTET STRING DER and
// is the entire extnValue payload per RFC 6960 §4.4.1.)
