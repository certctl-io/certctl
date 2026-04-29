package intune

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ChallengeClaim is the parsed payload of an Intune dynamic challenge.
//
// SCEP RFC 8894 + Intune master bundle Phase 7.3.
//
// Fields documented from Microsoft's Connector source traces +
// community implementations (smallstep/step-ca and HashiCorp Vault's
// Intune integrations both reverse-engineered the same format). The
// JSON tags match what the Connector emits today (v1 format); a v2
// format would land alongside via the version-detection dispatcher
// in challenge.go.
//
// Set-equality semantics: the SAN slices are normalised (sorted,
// de-duped) before comparison so Microsoft's Connector emitting in a
// non-deterministic order doesn't break DeviceMatchesCSR.
type ChallengeClaim struct {
	Issuer     string    `json:"iss,omitempty"`         // Connector identity (installation GUID typical)
	Subject    string    `json:"sub,omitempty"`         // device GUID or user UPN
	Audience   string    `json:"aud,omitempty"`         // expected SCEP endpoint URL (replay protection)
	IssuedAt   time.Time `json:"-"`                     // populated by claim unmarshaler from "iat" Unix seconds
	ExpiresAt  time.Time `json:"-"`                     // populated by claim unmarshaler from "exp" Unix seconds
	Nonce      string    `json:"nonce,omitempty"`       // replay-protection token; opaque
	DeviceName string    `json:"device_name,omitempty"` // expected CSR CommonName
	SANDNS     []string  `json:"san_dns,omitempty"`     // expected SAN DNS names
	SANRFC822  []string  `json:"san_rfc822,omitempty"`  // expected SAN email addresses (user certs)
	SANUPN     []string  `json:"san_upn,omitempty"`     // expected SAN userPrincipalName
}

// Typed claim-mismatch errors so the caller can audit the specific
// failure dimension without string-matching on error messages.
var (
	ErrClaimCNMismatch        = errors.New("intune claim: device_name does not match CSR CommonName")
	ErrClaimSANDNSMismatch    = errors.New("intune claim: SAN DNS set does not match CSR")
	ErrClaimSANRFC822Mismatch = errors.New("intune claim: SAN RFC822 (email) set does not match CSR")
	ErrClaimSANUPNMismatch    = errors.New("intune claim: SAN UPN (userPrincipalName) set does not match CSR")
)

// DeviceMatchesCSR returns nil if the CSR's CN and SANs match the
// claim's expected values. Returns a typed error otherwise so the
// caller can audit the specific mismatch.
//
// Set-equality semantics: if the claim says
// SANDNS=["a.example.com","b.example.com"] and the CSR has only
// "a.example.com", that's a mismatch — the operator's Intune profile
// was misconfigured or the CSR was tampered with. Both are "fail
// closed" cases.
//
// Empty claim slices = no constraint on that dimension. So a claim
// with SANDNS=nil + a CSR with DNS SANs is OK (Intune didn't pin DNS,
// the CSR can carry whatever). A claim with SANDNS=["x"] + a CSR
// with no DNS SANs is a mismatch (Intune pinned x, CSR doesn't have
// it).
func (c *ChallengeClaim) DeviceMatchesCSR(csr *x509.CertificateRequest) error {
	if c == nil {
		return errors.New("intune claim: nil claim")
	}
	if csr == nil {
		return errors.New("intune claim: nil CSR")
	}

	// CN is straight equality. Empty claim CN = no constraint.
	if c.DeviceName != "" && c.DeviceName != csr.Subject.CommonName {
		return fmt.Errorf("%w: claim=%q csr=%q", ErrClaimCNMismatch, c.DeviceName, csr.Subject.CommonName)
	}

	// SAN sets — set-equality means the SCEP CSR carries EXACTLY the
	// claim's elements, no extras and no missing. Normalising via
	// sorted lower-case slices makes the compare order-independent.
	if len(c.SANDNS) > 0 {
		got := normaliseSet(csr.DNSNames)
		want := normaliseSet(c.SANDNS)
		if !equalSets(got, want) {
			return fmt.Errorf("%w: claim=%v csr=%v", ErrClaimSANDNSMismatch, want, got)
		}
	}
	if len(c.SANRFC822) > 0 {
		got := normaliseSet(csr.EmailAddresses)
		want := normaliseSet(c.SANRFC822)
		if !equalSets(got, want) {
			return fmt.Errorf("%w: claim=%v csr=%v", ErrClaimSANRFC822Mismatch, want, got)
		}
	}
	if len(c.SANUPN) > 0 {
		// UPN SANs ride otherName extensions per RFC 4985 §1.1; Go's
		// stdlib doesn't surface them as a typed slice. Walk the raw
		// extensions if present. Most Intune deploys use SAN-RFC822
		// (email) for user certs rather than SAN-UPN, so this branch is
		// uncommon but pinned for correctness.
		got := normaliseSet(extractUPNSans(csr))
		want := normaliseSet(c.SANUPN)
		if !equalSets(got, want) {
			return fmt.Errorf("%w: claim=%v csr=%v", ErrClaimSANUPNMismatch, want, got)
		}
	}
	return nil
}

// normaliseSet returns a sorted, lowercased, de-duplicated copy of s.
// Lowercase because DNS / email comparison is case-insensitive (DNS
// per RFC 4343, email local-part is case-sensitive per RFC 5321 but
// Microsoft + most TLS stacks treat it case-insensitively for SAN
// comparison). De-dup so a CSR with ["a","a"] matches a claim with
// ["a"] — the cert's effective SAN set is what we're comparing, not
// the multiset.
func normaliseSet(s []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(s))
	for _, v := range s {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func equalSets(a, b []string) bool {
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

// extractUPNSans walks a CSR's raw extensions for SAN entries with the
// otherName form carrying the id-ms-san-upn OID (1.3.6.1.4.1.311.20.2.3).
// Returns the decoded UTF-8 string values. Returns empty slice when no
// UPN SANs are present (the common case).
//
// Implementation note: Go's stdlib doesn't decode UPN SANs; we'd have
// to walk the SubjectAltName extension's raw value as ASN.1 SEQUENCE OF
// GeneralName, find the [0] otherName tags, parse each as
// {OID, [0] EXPLICIT ANY}, match the OID, and decode the EXPLICIT value
// as a UTF8String. That's ~50 LoC of ASN.1 fiddling. For Phase 7 v1 we
// punt on it: returning an empty slice means SANUPN claims with non-
// empty values fail the equalSets check below — which is the correct
// fail-closed behavior for the rare deploy that pins UPN SANs but
// hasn't audited the wire format. If/when an operator actually needs
// SAN-UPN matching, hot-fix this function with the ASN.1 walker.
func extractUPNSans(_ *x509.CertificateRequest) []string {
	return nil
}
