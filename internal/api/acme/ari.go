// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// Phase 4 — RFC 9773 ACME Renewal Information.
//
// RFC 9773 §4.1: a client computes the cert-id as
//
//	base64url-no-pad(authorityKeyIdentifier) || "." || base64url-no-pad(serial)
//
// and GETs /acme/.../renewal-info/<cert-id>. The server responds with a
// JSON document carrying a `suggestedWindow` (start, end) the client
// SHOULD plan its renewal inside, plus an optional `explanationURL`.
// Response also carries a Retry-After header (RFC 9773 §4.2) hinting
// at the next-poll cadence.
//
// This file:
//
//   - parses the cert-id wire format → (akiBytes, serialBytes).
//   - converts the serial bytes to a hex string in the canonical
//     certctl shape (lowercase, no leading zeros, matching how
//     internal/repository/postgres/certificate.go stores them).
//   - computes the suggested-window from a cert's NotAfter and an
//     optional bound RenewalPolicy (last 33% of validity if no policy
//     is bound).

// RenewalInfoResponse is the JSON document returned by the renewal-
// info endpoint per RFC 9773 §4.1.
type RenewalInfoResponse struct {
	SuggestedWindow RenewalWindow `json:"suggestedWindow"`
	ExplanationURL  string        `json:"explanationURL,omitempty"`
}

// RenewalWindow is the embedded {start, end} pair. RFC 9773 mandates
// start ≤ end; the server is responsible for emitting RFC 3339 UTC
// timestamps.
type RenewalWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ARICertID is the parsed shape of an RFC 9773 §4.1 cert-id —
// authorityKeyIdentifier and serial bytes after base64url-no-pad
// decoding. Callers compare against the certificate they already have
// in the database; AKI is informational on the server side because
// certctl's serial-uniqueness invariant is per-issuer.
type ARICertID struct {
	// AKI is the raw bytes of the certificate's authorityKeyIdentifier
	// extension.
	AKI []byte
	// Serial is the raw bytes of the certificate's serial number, in
	// big-endian unsigned-integer form.
	Serial []byte
}

// SerialHex returns the canonical certctl-shape hex representation of
// the serial number — lowercase, no leading zeros (matches what's
// stored in certificate_versions.serial_number).
func (a ARICertID) SerialHex() string {
	if len(a.Serial) == 0 {
		return ""
	}
	n := new(big.Int).SetBytes(a.Serial)
	if n.Sign() == 0 {
		return "0"
	}
	return strings.ToLower(n.Text(16))
}

// AKIHex returns the AKI as a lowercase hex string. Useful for logging
// + future per-AKI lookup paths.
func (a ARICertID) AKIHex() string {
	return strings.ToLower(hex.EncodeToString(a.AKI))
}

// Sentinel errors. ChooseProblem in writeServiceError translates the
// not-found cases to RFC 7807 + RFC 8555 §6.7 problems.
var (
	ErrARICertIDMalformed   = errors.New("acme ari: cert-id is not <aki>.<serial>")
	ErrARICertIDDecodeAKI   = errors.New("acme ari: cert-id AKI is not valid base64url")
	ErrARICertIDDecodeSeria = errors.New("acme ari: cert-id serial is not valid base64url")
	ErrARICertIDEmpty       = errors.New("acme ari: cert-id has empty AKI or serial")
)

// ParseARICertID decodes an RFC 9773 §4.1 cert-id. The wire format is
// strictly base64url-NO-PADDING; rfc9773 §4.1 forbids regular base64.
//
// Common malformations:
//   - missing or extra `.` separator → ErrARICertIDMalformed.
//   - either side fails base64url decode → ErrARICertIDDecode*.
//   - either side decodes to empty → ErrARICertIDEmpty.
func ParseARICertID(certID string) (*ARICertID, error) {
	parts := strings.Split(certID, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: got %d parts", ErrARICertIDMalformed, len(parts))
	}
	if parts[0] == "" || parts[1] == "" {
		return nil, ErrARICertIDEmpty
	}
	aki, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrARICertIDDecodeAKI, err)
	}
	serial, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrARICertIDDecodeSeria, err)
	}
	if len(aki) == 0 || len(serial) == 0 {
		return nil, ErrARICertIDEmpty
	}
	return &ARICertID{AKI: aki, Serial: serial}, nil
}

// BuildARICertID is the inverse of ParseARICertID — useful for tests
// and operator tools that want to construct a cert-id from a leaf cert.
//
// The input is the leaf certificate's PEM. We extract the
// authorityKeyIdentifier extension and the serial number, then
// base64url-no-pad-encode each + join with a `.`.
func BuildARICertID(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("acme ari: pem decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("acme ari: parse cert: %w", err)
	}
	if len(cert.AuthorityKeyId) == 0 {
		return "", fmt.Errorf("acme ari: certificate has no authorityKeyIdentifier extension")
	}
	if cert.SerialNumber == nil {
		return "", fmt.Errorf("acme ari: certificate has no serial number")
	}
	akiB64 := base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId)
	serialB64 := base64.RawURLEncoding.EncodeToString(cert.SerialNumber.Bytes())
	return akiB64 + "." + serialB64, nil
}

// ComputeRenewalWindow returns the RFC 9773 suggestedWindow for a
// (cert, optional renewal-policy) pair.
//
// Algorithm:
//
//   - When policy is non-nil and policy.RenewalWindowDays > 0: the
//     window starts at NotAfter - RenewalWindowDays + spans half of
//     RenewalWindowDays. So a 30-day-renewal-window cert with NotAfter
//     2026-06-30 emits start=2026-05-31, end=2026-06-15. This matches
//     boulder's default ARI behavior + ensures a Let's-Encrypt-shaped
//     client can plan its renewals exactly inside our renewal window.
//   - When policy is nil OR RenewalWindowDays ≤ 0: the window is the
//     last 33% of validity. So a cert with NotBefore 2026-01-01 +
//     NotAfter 2026-04-01 (90d validity) emits start=2026-03-01 (30d
//     before expiry), end=2026-03-21 (10d before expiry).
//   - When the cert is past NotAfter: the window starts at "now" and
//     ends at "now + 1 day" so a client polling on an expired cert
//     gets a "renew immediately" answer rather than a window in the
//     past.
//
// Returns (start, end). start ≤ end is invariant.
func ComputeRenewalWindow(cert *domain.ManagedCertificate, version *domain.CertificateVersion, policy *domain.RenewalPolicy, now time.Time) (time.Time, time.Time) {
	if cert == nil {
		return time.Time{}, time.Time{}
	}
	notAfter := cert.ExpiresAt.UTC()
	notBefore := notAfter
	if version != nil && !version.NotBefore.IsZero() {
		notBefore = version.NotBefore.UTC()
	}

	// Past expiry: emit a 1-day "renew now" window.
	if !now.IsZero() && now.UTC().After(notAfter) {
		nowUTC := now.UTC()
		return nowUTC, nowUTC.Add(24 * time.Hour)
	}

	if policy != nil && policy.RenewalWindowDays > 0 {
		windowDays := time.Duration(policy.RenewalWindowDays) * 24 * time.Hour
		start := notAfter.Add(-windowDays)
		end := start.Add(windowDays / 2)
		// Defensive: never emit start in the past from "now".
		if !now.IsZero() && start.Before(now.UTC()) {
			start = now.UTC()
		}
		if end.Before(start) {
			end = start
		}
		return start, end
	}

	// No policy → last 33% of validity.
	validity := notAfter.Sub(notBefore)
	if validity <= 0 {
		// Degenerate cert (nb >= na). Use a 1-day default window
		// ending at notAfter.
		return notAfter.Add(-24 * time.Hour), notAfter
	}
	thirty3 := validity / 3
	start := notAfter.Add(-thirty3)
	// End is 1/3 before expiry → midpoint of the renewal third.
	end := notAfter.Add(-thirty3 / 3)
	if !now.IsZero() && start.Before(now.UTC()) {
		start = now.UTC()
	}
	if end.Before(start) {
		end = start
	}
	return start, end
}
