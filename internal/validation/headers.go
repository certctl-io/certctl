package validation

import (
	"fmt"
	"strings"
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
