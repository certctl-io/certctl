// Package cms implements the small subset of CMS / RFC 7030 / RFC 9266
// helpers that the EST handler needs at request-time: extracting the
// RFC 9266 tls-exporter from a *tls.ConnectionState, and pulling the
// matching value back out of an EST CSR's CMC unsignedAttribute when the
// device proved channel binding.
//
// Why a separate package (vs adding to internal/api/handler/est.go):
//
//  1. internal/api/handler depends on internal/pkcs7 already; if the EST
//     mTLS hardening also pulled CMC parsing into handler we'd grow the
//     handler-side dep graph by another asn1 surface that has nothing
//     specific to HTTP.
//
//  2. Channel-binding extraction is testable in isolation — the unit
//     tests construct a *tls.ConnectionState with raw exporter bytes and
//     a *x509.CertificateRequest with the CMC unsignedAttribute already
//     filled in. No HTTP plumbing required to verify the contract.
//
//  3. Future EST extensions (RFC 7030 §3.5 fullCMC, RFC 9148 EST-coaps)
//     are likely to land here too — keep them out of net/http land.
//
// EST RFC 7030 hardening master bundle Phase 2.4.
package cms

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// ----- RFC 9266 §3 — TLS exporter extraction -----

// TLSExporterLabel is the EXPORTER label registered by RFC 9266 §3.1
// for use as a TLS-1.3 channel binding. Constant rather than string-typed
// so a typo here is a compile error rather than a silent failure mode.
const TLSExporterLabel = "EXPORTER-Channel-Binding"

// TLSExporterLength is the 32-byte exporter length pinned by RFC 9266 §3.1
// (matches the SHA-256 output size; clients and servers MUST agree on the
// length to make the comparison meaningful).
const TLSExporterLength = 32

// ErrChannelBindingMissing is returned when the EST mTLS handler requires
// channel binding (per-profile ChannelBindingRequired=true) but the device's
// CSR has no id-aa-est-tls-exporter unsignedAttribute or the attribute is
// the wrong shape.
var ErrChannelBindingMissing = errors.New("cms: channel binding required but absent or malformed in CSR")

// ErrChannelBindingMismatch is returned when the device's CSR carried a
// channel-binding attribute but its bytes do not match the TLS-1.3 exporter
// extracted from the live connection. This is the signal of an MITM that
// terminates TLS in front of certctl: the device computed exporter X
// against the attacker, certctl sees exporter Y against itself, X≠Y.
var ErrChannelBindingMismatch = errors.New("cms: channel binding in CSR does not match TLS exporter")

// ErrChannelBindingNotTLS13 is returned when the connection is older than
// TLS 1.3 and the per-profile config still requires channel binding.
// RFC 9266's tls-exporter is a TLS-1.3 binding; pre-1.3 connections would
// need RFC 5929 tls-unique, which we deliberately don't support
// (certctl pins TLS-1.3 server-side).
var ErrChannelBindingNotTLS13 = errors.New("cms: tls-exporter channel binding requires TLS 1.3")

// ExtractTLSExporter pulls the 32-byte RFC 9266 channel-binding value from
// the TLS connection state. The connection must be TLS 1.3 + handshake-
// complete; anything else returns a typed error so the caller can map to
// HTTP 400 / 412 cleanly.
//
// Stateless on purpose: callers handle storage + comparison.
//
// Robustness note: stdlib's ConnectionState.ExportKeyingMaterial nil-derefs
// when the underlying secret-derivation closure is unset (i.e. the state
// was hand-constructed by a test fixture rather than produced by a real
// TLS handshake). The recover() below converts that panic into the same
// typed error a missing-binding state would surface, so synthetic test
// states + production TLS-1.3 connections share a single failure mode.
func ExtractTLSExporter(state *tls.ConnectionState) (out []byte, err error) {
	if state == nil {
		return nil, fmt.Errorf("%w: nil ConnectionState", ErrChannelBindingMissing)
	}
	if !state.HandshakeComplete {
		return nil, fmt.Errorf("%w: handshake incomplete", ErrChannelBindingMissing)
	}
	// tls.VersionTLS13 == 0x0304. We use the literal so this package doesn't
	// have to import "crypto/tls" twice (once for tls.VersionTLS13, once for
	// the *tls.ConnectionState type — Go allows it but it's noisy).
	if state.Version < 0x0304 {
		return nil, fmt.Errorf("%w: negotiated 0x%04x", ErrChannelBindingNotTLS13, state.Version)
	}
	defer func() {
		if r := recover(); r != nil {
			out = nil
			err = fmt.Errorf("%w: ExportKeyingMaterial unavailable on this connection state (panic=%v)", ErrChannelBindingMissing, r)
		}
	}()
	out, err = state.ExportKeyingMaterial(TLSExporterLabel, nil, TLSExporterLength)
	if err != nil {
		return nil, fmt.Errorf("cms: ExportKeyingMaterial: %w", err)
	}
	if len(out) != TLSExporterLength {
		return nil, fmt.Errorf("cms: exporter returned %d bytes, want %d", len(out), TLSExporterLength)
	}
	return out, nil
}

// ----- RFC 7030 §3.5 / RFC 9266 §4.1 — CSR-side channel binding -----

// OIDChannelBindingTLSExporter is the id-aa-est-tls-exporter OID from
// RFC 9266 §4.1 (registered under id-aa = 1.2.840.113549.1.9.16.2 with
// arc 56 by RFC 9266). Devices that signed channel binding into their
// CSR add a CMC unsignedAttribute with this OID + an OCTET STRING value.
//
// Note: the EST RFC 7030 §3.5 historical OID for tls-unique is
// id-aa-cmc-binding (1.2.840.113549.1.9.16.2.43). RFC 9266 §4.1 added
// arc 56 for tls-exporter. We accept BOTH OIDs on the read path so a
// device using a slightly older library that still emits the §3.5 OID
// continues to work — the value bytes are still the 32-byte exporter
// (the OID identifies the binding scheme, not the underlying wire
// format).
var (
	OIDChannelBindingTLSExporter = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 56}
	OIDCMCEnrollmentBinding      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 43}
)

// ExtractCSRChannelBinding looks for the RFC 9266 channel-binding
// attribute (or the legacy RFC 7030 §3.5 binding attribute) in the CSR's
// raw attributes block. Returns the raw 32-byte exporter value if
// present.
//
// Why we walk csr.RawTBSCertificateRequest manually instead of using
// csr.Attributes:
//
//   - csr.Attributes is typed as []pkix.AttributeTypeAndValueSET, where
//     the inner Value is [][]pkix.AttributeTypeAndValue. That shape only
//     fits attributes whose AttributeValue is itself a SEQUENCE { OID,
//     ANY } (e.g. the requestedExtensions attribute). RFC 9266's
//     TLSExporterValue is `OCTET STRING` — a primitive, not a SEQUENCE
//     — so the stdlib parse path either drops the attribute silently or
//     fails the whole CSR parse depending on encoding.
//
//   - The PKCS#10 challengePassword path in scep.go works by accident
//     because PrintableString happens to round-trip through the
//     stdlib's interface{}-typed AttributeTypeAndValue.Value. OCTET
//     STRING does not — it's not in the small list of primitive types
//     the stdlib's reflect-based unmarshaller handles for `any`.
//
//   - Walking the raw TBS is ~30 lines of asn1.Unmarshal calls and
//     gives us a stable contract independent of stdlib quirks.
//
// Returns (value, true, nil) on success; (nil, false, nil) when the
// attribute is absent (caller decides whether absence is acceptable per
// the per-profile ChannelBindingRequired flag); (nil, false, err) on
// malformed attribute (always fatal — a present-but-wrong attribute
// signals an attacker rewriting the binding into garbage).
func ExtractCSRChannelBinding(csr *x509.CertificateRequest) ([]byte, bool, error) {
	if csr == nil {
		return nil, false, fmt.Errorf("cms: nil CSR")
	}
	if len(csr.RawTBSCertificateRequest) == 0 {
		// Stdlib fills RawTBSCertificateRequest on every parse path, so an
		// empty value here means the caller hand-crafted the struct. Tests
		// can do that — but real handler-side calls always have raw bytes.
		return nil, false, nil
	}
	return walkCSRAttributesForBinding(csr.RawTBSCertificateRequest)
}

// walkCSRAttributesForBinding parses just enough of TBSCertificationRequestInfo
// to reach the [0] IMPLICIT Attributes field, then iterates each Attribute
// looking for the channel-binding OID. The body is intentionally low-level
// so we can keep the asn1 footprint contained to this one helper.
//
// TBSCertificationRequestInfo per RFC 2986 §4.1:
//
//	TBSCertificationRequestInfo ::= SEQUENCE {
//	    version       INTEGER (0),
//	    subject       Name,
//	    subjectPKInfo SubjectPublicKeyInfo,
//	    attributes    [0] IMPLICIT Attributes (SET OF Attribute)
//	}
func walkCSRAttributesForBinding(tbs []byte) ([]byte, bool, error) {
	// 1. Crack the outer SEQUENCE wrapper.
	var inner asn1.RawValue
	if rest, err := asn1.Unmarshal(tbs, &inner); err != nil {
		return nil, false, fmt.Errorf("cms: TBS outer parse: %w", err)
	} else if len(rest) > 0 {
		return nil, false, fmt.Errorf("cms: TBS trailing bytes: %d", len(rest))
	}
	if inner.Tag != asn1.TagSequence {
		return nil, false, fmt.Errorf("cms: TBS outer tag %d not SEQUENCE", inner.Tag)
	}
	rest := inner.Bytes

	// 2. Skip version (INTEGER), subject (SEQUENCE = Name), subjectPKInfo
	// (SEQUENCE). asn1.Unmarshal into asn1.RawValue advances the cursor
	// without parsing the body — perfect for skipping fields we don't care
	// about.
	for i, label := range []string{"version", "subject", "subjectPKInfo"} {
		var rv asn1.RawValue
		next, err := asn1.Unmarshal(rest, &rv)
		if err != nil {
			return nil, false, fmt.Errorf("cms: skip TBS field %d (%s): %w", i, label, err)
		}
		rest = next
	}

	// 3. Attributes is [0] IMPLICIT — the on-wire tag is 0xA0 with class
	// CONTEXT-SPECIFIC. asn1.Unmarshal into a RawValue accepts arbitrary
	// tags; we then walk its Bytes as a SET OF Attribute.
	var attrsField asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &attrsField); err != nil {
		// No attributes block at all — RFC 2986 says [0] is OPTIONAL when
		// empty (encoders typically omit the field rather than emit an
		// empty SET). Treat as "no binding present", not as an error.
		return nil, false, nil
	}
	if attrsField.Class != asn1.ClassContextSpecific || attrsField.Tag != 0 {
		// Some non-attribute-shaped trailing field: not what we expected
		// but not strictly a corruption signal — skip silently.
		return nil, false, nil
	}

	// 4. Walk each Attribute in the SET. Each Attribute is
	//    SEQUENCE { OID, SET OF ANY }.
	attrBytes := attrsField.Bytes
	for len(attrBytes) > 0 {
		var oneAttr asn1.RawValue
		next, err := asn1.Unmarshal(attrBytes, &oneAttr)
		if err != nil {
			return nil, false, fmt.Errorf("cms: walk attributes: %w", err)
		}
		attrBytes = next
		if oneAttr.Tag != asn1.TagSequence {
			continue
		}
		// Inner: OID, then SET.
		var oid asn1.ObjectIdentifier
		afterOID, err := asn1.Unmarshal(oneAttr.Bytes, &oid)
		if err != nil {
			continue
		}
		if !oid.Equal(OIDChannelBindingTLSExporter) && !oid.Equal(OIDCMCEnrollmentBinding) {
			continue
		}
		// Now afterOID is the SET wrapper. Crack it and pull the OCTET
		// STRING out of the SET's first element.
		var setWrap asn1.RawValue
		if _, err := asn1.Unmarshal(afterOID, &setWrap); err != nil {
			return nil, false, fmt.Errorf("cms: binding SET parse: %w (%w)", err, ErrChannelBindingMissing)
		}
		if setWrap.Tag != asn1.TagSet {
			return nil, false, fmt.Errorf("cms: binding outer tag %d not SET (%w)", setWrap.Tag, ErrChannelBindingMissing)
		}
		var octet asn1.RawValue
		if _, err := asn1.Unmarshal(setWrap.Bytes, &octet); err != nil {
			return nil, false, fmt.Errorf("cms: binding inner parse: %w (%w)", err, ErrChannelBindingMissing)
		}
		if octet.Tag != asn1.TagOctetString {
			return nil, false, fmt.Errorf("cms: binding inner tag %d not OCTET STRING (%w)", octet.Tag, ErrChannelBindingMissing)
		}
		if len(octet.Bytes) != TLSExporterLength {
			return nil, false, fmt.Errorf("cms: binding length %d, want %d (%w)",
				len(octet.Bytes), TLSExporterLength, ErrChannelBindingMissing)
		}
		return octet.Bytes, true, nil
	}
	return nil, false, nil
}

// VerifyChannelBinding is the convenience composite the EST mTLS handler
// calls per request: extract the exporter from the live TLS connection,
// pull the matching value from the CSR, compare in constant time.
//
// Returns:
//   - nil when the binding is present + matches.
//   - ErrChannelBindingMissing when the CSR has no binding attribute.
//   - ErrChannelBindingMismatch when both sides have a value but they
//     differ (the MITM signal).
//   - Any error from the exporter extraction (TLS state is wrong, etc).
//
// The required flag controls absence-handling: when required=false a
// missing attribute returns nil (channel binding is optional for this
// profile); when required=true a missing attribute returns
// ErrChannelBindingMissing.
func VerifyChannelBinding(state *tls.ConnectionState, csr *x509.CertificateRequest, required bool) error {
	live, err := ExtractTLSExporter(state)
	if err != nil {
		// If the profile doesn't require channel binding AND the only
		// problem is "no TLS 1.3 / no handshake", we still let the request
		// through — the binding is opt-in per profile. But if the CSR
		// itself carries a binding attribute, the device clearly INTENDED
		// to bind, so a TLS state mismatch is a genuine error.
		if !required {
			if _, present, _ := ExtractCSRChannelBinding(csr); !present {
				return nil
			}
		}
		return err
	}
	csrBinding, present, err := ExtractCSRChannelBinding(csr)
	if err != nil {
		return err
	}
	if !present {
		if required {
			return ErrChannelBindingMissing
		}
		return nil
	}
	if subtle.ConstantTimeCompare(live, csrBinding) != 1 {
		return ErrChannelBindingMismatch
	}
	// Sanity: the comparison should be identical bytes for matching cases.
	// The bytes.Equal call is dead code under correct subtle.Compare result;
	// it's here only to make the contract obvious to readers and to pin the
	// symmetry test that asserts ExtractCSRChannelBinding is byte-equivalent
	// to ExtractTLSExporter when the device behaved correctly.
	if !bytes.Equal(live, csrBinding) {
		return ErrChannelBindingMismatch
	}
	return nil
}

// EmbedChannelBindingAttribute is the test helper inverse of
// ExtractCSRChannelBinding: given an exporter value, returns the DER
// bytes of the Attribute (SEQUENCE { OID, SET { OCTET STRING } }) that
// the caller can splice into the [0] IMPLICIT Attributes field of
// TBSCertificationRequestInfo. Used by the EST channel-binding tests
// AND by any external caller that wants to forge a CSR with a known
// binding for fixture generation.
func EmbedChannelBindingAttribute(exporter []byte) ([]byte, error) {
	if len(exporter) != TLSExporterLength {
		return nil, fmt.Errorf("cms: exporter length %d, want %d", len(exporter), TLSExporterLength)
	}
	octet, err := asn1.Marshal(exporter) // marshal []byte as OCTET STRING
	if err != nil {
		return nil, fmt.Errorf("cms: marshal exporter octet: %w", err)
	}
	// Wrap in SET OF.
	setBody := octet
	setEnvelope, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      setBody,
	})
	if err != nil {
		return nil, fmt.Errorf("cms: marshal SET: %w", err)
	}
	oid, err := asn1.Marshal(OIDChannelBindingTLSExporter)
	if err != nil {
		return nil, fmt.Errorf("cms: marshal OID: %w", err)
	}
	// Wrap as SEQUENCE { OID, SET }.
	seqBody := append(append([]byte{}, oid...), setEnvelope...)
	seqEnvelope, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      seqBody,
	})
	if err != nil {
		return nil, fmt.Errorf("cms: marshal SEQUENCE: %w", err)
	}
	return seqEnvelope, nil
}
