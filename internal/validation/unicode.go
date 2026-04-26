package validation

import (
	"fmt"
	"strings"
	"unicode"
)

// Bundle-9 / Audit L-012 / CWE-1007 (Insufficient Visual Distinction of
// Homoglyphs Presenting to User) + CWE-176 (Improper Handling of Unicode
// Encoding):
//
// Certificate CommonName + Subject Alternative Name fields originate from
// the CSR submitter and feed directly into:
//
//   - The MCP / API surface that humans inspect ("which cert is this?")
//   - The web UI that renders cert lists, deployment targets, audit events
//   - Downstream relying parties that match certs by hostname
//
// An attacker who can submit a CSR (any operator with cert-create capability,
// or anonymous EST/SCEP enrollment) can plant unicode payloads that:
//
//  1. **Visually impersonate** a legitimate hostname via Cyrillic / Greek /
//     Cherokee homoglyphs (e.g. CN="apple.com" with one Cyrillic 'а' that
//     renders identically but routes differently via DNS or matches a
//     different TLS pin).
//
//  2. **Hide content** via zero-width characters (U+200B..U+200D, U+2060,
//     U+FEFF) that don't render but break naive substring matching.
//
//  3. **Reverse render order** via RTL/LTR override characters
//     (U+202A..U+202E, U+2066..U+2069) that make "google.com.evil.org"
//     display as "google.com.evil.org" with the suffix flipped.
//
// ValidateUnicodeSafe rejects all three categories. It does NOT NFC-normalize
// — the audit prompt's invariant is that the validator REJECTS rather than
// silently rewrites, because operators who don't know their CSR's CN was
// rewritten will get certs they didn't ask for.

// ValidateUnicodeSafe returns nil if `name` is safe to use as a certificate
// CN or SAN, or an error describing the first violation found. The error
// message includes the rune offset so operators can locate the problem in
// the CSR they submitted.
//
// Wired in: internal/connector/issuer/local/local.go (CSR-acceptance path).
// Future ride-along sites (M-029): the web frontend's CertificateStep input.
func ValidateUnicodeSafe(name string) error {
	if name == "" {
		// Empty is a different validation concern (handled by ValidateRequired
		// in handler-side ValidateRequired). Don't double-fail here.
		return nil
	}

	// First pass: scan for explicitly forbidden characters.
	for i, r := range name {
		switch {
		case isRTLOverride(r):
			return fmt.Errorf(
				"contains bidirectional override character %U at byte offset %d — refuse (potential reverse-rendering attack, CWE-1007)",
				r, i,
			)
		case isZeroWidth(r):
			return fmt.Errorf(
				"contains zero-width character %U at byte offset %d — refuse (hidden content, CWE-176)",
				r, i,
			)
		case isControl(r):
			return fmt.Errorf(
				"contains control character %U at byte offset %d — refuse",
				r, i,
			)
		}
	}

	// Second pass: per-label mixed-script detection. DNS labels are joined
	// by '.', so we split on '.' and check each label independently. A
	// label that mixes Latin with Cyrillic / Greek / Cherokee is the
	// classic IDN homograph signal.
	for _, label := range strings.Split(name, ".") {
		if err := validateLabelSingleScript(label); err != nil {
			return err
		}
	}

	return nil
}

// isRTLOverride reports whether r is a Unicode bidirectional override
// character that an attacker could use to flip rendered text direction.
func isRTLOverride(r rune) bool {
	switch r {
	case 0x202A, // LEFT-TO-RIGHT EMBEDDING
		0x202B, // RIGHT-TO-LEFT EMBEDDING
		0x202C, // POP DIRECTIONAL FORMATTING
		0x202D, // LEFT-TO-RIGHT OVERRIDE
		0x202E, // RIGHT-TO-LEFT OVERRIDE
		0x2066, // LEFT-TO-RIGHT ISOLATE
		0x2067, // RIGHT-TO-LEFT ISOLATE
		0x2068, // FIRST STRONG ISOLATE
		0x2069: // POP DIRECTIONAL ISOLATE
		return true
	}
	return false
}

// isZeroWidth reports whether r is a Unicode zero-width character that
// renders nothing but breaks substring matching.
func isZeroWidth(r rune) bool {
	switch r {
	case 0x200B, // ZERO WIDTH SPACE
		0x200C, // ZERO WIDTH NON-JOINER
		0x200D, // ZERO WIDTH JOINER
		0x2060, // WORD JOINER
		0xFEFF: // ZERO WIDTH NO-BREAK SPACE / BOM
		return true
	}
	return false
}

// isControl reports whether r is a C0 or C1 control character. Tabs and
// newlines have no business in a certificate name; reject.
func isControl(r rune) bool {
	return r < 0x20 || (r >= 0x7F && r <= 0x9F)
}

// validateLabelSingleScript rejects a DNS label that mixes Latin
// (a–z, A–Z, 0–9, '-') with characters from a different script. Pure-
// non-Latin labels are allowed (e.g. genuine IDN domains in Cyrillic);
// the attack we're defending against is the MIX.
func validateLabelSingleScript(label string) error {
	if label == "" {
		return nil
	}
	hasASCII := false
	for _, r := range label {
		if r < 0x80 {
			hasASCII = true
			break
		}
	}
	if !hasASCII {
		// Pure non-ASCII label — could be a legitimate IDN. Don't
		// reject; the homograph attack we care about is the MIX.
		return nil
	}
	// Has ASCII — assert NO non-ASCII letters present. Non-ASCII
	// non-letter chars (e.g., a digit from a different script) are
	// also rejected to keep the rule simple.
	for i, r := range label {
		if r < 0x80 {
			continue
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) {
			return fmt.Errorf(
				"label %q mixes ASCII with non-ASCII script character %U at byte offset %d — refuse (potential IDN homograph, CWE-1007)",
				label, r, i,
			)
		}
	}
	return nil
}
