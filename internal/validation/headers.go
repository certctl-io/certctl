package validation

import (
	"fmt"
	"strings"
	"unicode"
)

// ValidateHeaderValue rejects any value that contains characters capable of
// breaking out of a header line and injecting additional headers or body
// content. It guards against CRLF injection (CWE-113) in RFC 5322 message
// headers (SMTP, IMAP, etc.) and RFC 7230 HTTP headers alike.
//
// Disallowed characters:
//   - Carriage return ("\r")
//   - Line feed ("\n")
//   - NUL ("\x00")
//
// The field name is included in the returned error solely for operator
// diagnostics; the offending value is not echoed back, so untrusted input
// does not leak into logs that render this error.
//
// Callers should invoke this on any string that will be interpolated into a
// header (From, To, Subject, Reply-To, custom X-* headers, etc.) before the
// headers are serialized. Values containing CR/LF/NUL MUST be rejected
// outright; silent stripping is inappropriate for authentication-relevant
// headers because it can mask malicious intent while still altering the
// message.
func ValidateHeaderValue(field, value string) error {
	if field == "" {
		field = "header"
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("%s contains disallowed control character (CR, LF, or NUL)", field)
	}
	return nil
}

// SanitizeEmailBodyValue scrubs control characters and visually-spoofable
// Unicode from a single field that will be interpolated into a plaintext
// email body. Closes CodeQL go/email-injection (CWE-640 / OWASP Content
// Spoofing): an attacker who controls a field surfaced to an
// operator-bound notification (cert subject DN, discovered cert metadata,
// alert subject / message, event subject / body, metadata key+value
// pairs) could otherwise plant content that:
//
//   - Forges header-like content using bare CR/LF (some mail relays
//     misinterpret bare LF mid-body as a header boundary; RFC 5321
//     mandates CRLF, but defense in depth says strip bare LFs).
//   - Embeds NUL bytes (forbidden by RFC 5321 sec 4.5.2; some MTAs
//     truncate at NUL, allowing content elision).
//   - Plants bidi-override Unicode (U+202A..U+202E, U+2066..U+2069) so a
//     malicious URL renders as a benign one in the recipient's mail
//     client.
//   - Plants zero-width / invisible Unicode (U+200B..U+200D, U+FEFF,
//     U+2060..U+2063) so a phishing-prone URL hides whitespace.
//   - Plants C0 / C1 control characters that mail clients may render
//     unpredictably or strip in surprising ways.
//
// The sanitizer NEVER errors; it always returns a sanitized string. This
// is the right contract for body content (vs. headers, which fail loud)
// because dropping a notification because the cert subject DN happens to
// contain a Mongolian Vowel Separator would be worse than escaping it.
//
// What the sanitizer does:
//
//   - Strip NUL bytes (\x00) entirely.
//   - Replace bare LF / CR with a single space. Multi-line legitimate
//     body content gets its CRLF formatting from the email serializer
//     above this layer; a SINGLE FIELD interpolated into the body
//     should never carry its own line breaks.
//   - Strip bidi-override and zero-width characters.
//   - Strip C0 control chars (< 0x20) except TAB. Strip DEL (0x7F) +
//     C1 control chars (0x80-0x9F).
//   - Leave ordinary printable Unicode (including non-Latin scripts)
//     intact.
//
// Apply this to EVERY user-controllable field before interpolating into
// a plaintext email body. Do NOT apply it to operator-controlled
// constants (template literals, severity tier names) — those don't
// carry the threat. The HTML email path uses html/template upstream
// and does not need this sanitizer (html/template's contextual
// auto-escape handles the same threats for HTML rendering).
func SanitizeEmailBodyValue(value string) string {
	if value == "" {
		return value
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case r == 0:
			// NUL — strip entirely (RFC 5321 sec 4.5.2 violation).
			continue
		case r == '\r' || r == '\n':
			// Strip line breaks within a single interpolated field.
			b.WriteRune(' ')
		case r == '\t':
			// TAB is legitimate body content.
			b.WriteRune(r)
		case r < 0x20:
			// C0 control chars (except TAB above) — strip.
			continue
		case r >= 0x7F && r <= 0x9F:
			// DEL + C1 control chars — strip.
			continue
		case r == 0xFFFD:
			// Replacement character — Go's range emits this for any
			// malformed UTF-8 byte sequence. Defense in depth: an
			// attacker who plants invalid UTF-8 (e.g. raw 0x80..0xFF
			// without a valid lead byte) should not have their input
			// surface as an arbitrary glyph in operator-bound mail.
			continue
		case isBidiOrZeroWidth(r):
			// Bidi-override + zero-width — strip; visually spoofable.
			continue
		case unicode.IsControl(r):
			// Catch-all: any remaining Unicode control class.
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isBidiOrZeroWidth reports whether r is one of the bidi-override or
// zero-width Unicode codepoints used in homograph / direction-spoofing
// attacks. Mirrors the validator in internal/connector/issuer/local
// (validateCSRUnicode); kept inline here to avoid a new import edge
// from internal/validation back to the local issuer package.
//
// Codepoints expressed as numeric ranges instead of rune-literal
// switch cases — Go source rejects literal invisible characters
// (e.g. BOM U+FEFF) mid-file, so we compare against numeric values.
func isBidiOrZeroWidth(r rune) bool {
	switch {
	// LRE U+202A, RLE U+202B, PDF U+202C, LRO U+202D, RLO U+202E
	case r >= 0x202A && r <= 0x202E:
		return true
	// LRI U+2066, RLI U+2067, FSI U+2068, PDI U+2069
	case r >= 0x2066 && r <= 0x2069:
		return true
	// Zero-width space U+200B, ZWNJ U+200C, ZWJ U+200D
	case r >= 0x200B && r <= 0x200D:
		return true
	// Word joiner U+2060, invisible separator U+2061,
	// invisible times U+2062, invisible plus U+2063
	case r >= 0x2060 && r <= 0x2063:
		return true
	// Byte-order mark / zero-width no-break space U+FEFF
	case r == 0xFEFF:
		return true
	// Mongolian Vowel Separator U+180E
	case r == 0x180E:
		return true
	}
	return false
}
