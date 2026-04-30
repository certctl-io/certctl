package cli

// EST RFC 7030 hardening master bundle Phase 9.1 — CLI subcommands.
//
// The EST endpoints live under /.well-known/est/[<PathID>/]; they are
// HTTPS-only (the certctl control plane is HTTPS-only as of v2.2) and
// per-profile dispatched. The CLI subcommands here mirror what an
// operator would do via libest or curl + base64 + openssl, but with a
// fixed --profile flag + the existing CLI's TLS-pinning semantics.
//
// Subcommands:
//
//	certctl-cli est cacerts --profile corp
//	certctl-cli est csrattrs --profile corp
//	certctl-cli est enroll --profile corp --csr <path-or-stdin>
//	certctl-cli est reenroll --profile corp --csr <path-or-stdin>
//	certctl-cli est serverkeygen --profile corp --csr <path> --out <prefix>
//	certctl-cli est test --profile corp
//
// All write operations stream the issued cert (PEM) to stdout by default
// or to --out when provided. Server-keygen writes <prefix>.cert.pem +
// <prefix>.key.enveloped (the EnvelopedData blob) so the operator can
// decrypt with openssl smime.

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// estPath builds the per-profile EST URL fragment. PathID="" maps to
// the legacy /.well-known/est/ root for backward compat with v2.0.x
// single-profile deploys.
func (c *Client) estPath(profile, op string) string {
	if profile == "" {
		return "/.well-known/est/" + op
	}
	return "/.well-known/est/" + profile + "/" + op
}

// estPostBody POSTs the given body bytes to the EST endpoint with the
// EST-required Content-Type. Returns the raw response body so the
// caller can write the PEM/PKCS#7/multipart bytes through to disk
// without further decoding (the CLI is the device's smime/openssl
// pipeline; we don't second-guess the wire format).
func (c *Client) estPostBody(path, contentType string, body []byte) ([]byte, http.Header, error) {
	u, err := url.JoinPath(c.baseURL, path)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid URL: %w", err)
	}
	req, err := http.NewRequest("POST", u, strings.NewReader(string(body)))
	if err != nil {
		return nil, nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, resp.Header, fmt.Errorf("EST error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	return respBody, resp.Header, nil
}

// estGet performs a GET against the EST endpoint and returns the raw
// response body. Used by cacerts (HTTP 200) and csrattrs (HTTP 200 or
// 204 — both are valid contracts).
func (c *Client) estGet(path string) ([]byte, int, http.Header, error) {
	u, err := url.JoinPath(c.baseURL, path)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("invalid URL: %w", err)
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("creating request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("EST error (HTTP %d): %s", resp.StatusCode, string(body))
	}
	return body, resp.StatusCode, resp.Header, nil
}

// readCSRBytes resolves --csr to actual CSR bytes. "-" reads from
// stdin (so the operator can pipe `openssl req -new …` directly into
// us); otherwise it's a filesystem path.
func readCSRBytes(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// EstCacerts implements `certctl-cli est cacerts --profile <p>`.
// Writes the base64-wrapped PKCS#7 certs-only response to stdout (the
// canonical EST §4.1.3 wire shape).
func (c *Client) EstCacerts(args []string) error {
	fs := flag.NewFlagSet("est cacerts", flag.ContinueOnError)
	profile := fs.String("profile", "", "EST profile PathID (empty = legacy root)")
	out := fs.String("out", "-", "output file path; '-' = stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, _, _, err := c.estGet(c.estPath(*profile, "cacerts"))
	if err != nil {
		return err
	}
	return writeOutput(*out, body)
}

// EstCsrattrs implements `certctl-cli est csrattrs --profile <p>`.
// Writes the base64-encoded ASN.1 SEQUENCE OF OID body to stdout. The
// 204-No-Content case (no profile-derived hints) prints an empty
// payload + a STDERR diagnostic so an operator running the smoke-test
// case knows the endpoint succeeded.
func (c *Client) EstCsrattrs(args []string) error {
	fs := flag.NewFlagSet("est csrattrs", flag.ContinueOnError)
	profile := fs.String("profile", "", "EST profile PathID (empty = legacy root)")
	out := fs.String("out", "-", "output file path; '-' = stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, status, _, err := c.estGet(c.estPath(*profile, "csrattrs"))
	if err != nil {
		return err
	}
	if status == http.StatusNoContent {
		fmt.Fprintln(os.Stderr, "no csrattrs hints configured (HTTP 204)")
		return nil
	}
	return writeOutput(*out, body)
}

// EstEnroll implements `certctl-cli est enroll --profile <p> --csr <path>`.
// POSTs the CSR to /simpleenroll. The CSR body is sent as-is (whether
// PEM or base64-DER); the server's readCSRFromRequest handles either.
func (c *Client) EstEnroll(args []string) error {
	return c.estEnrollOp("simpleenroll", "est enroll", args)
}

// EstReEnroll implements `certctl-cli est reenroll --profile <p> --csr <path>`.
func (c *Client) EstReEnroll(args []string) error {
	return c.estEnrollOp("simplereenroll", "est reenroll", args)
}

// estEnrollOp shares the body of EstEnroll + EstReEnroll. The only
// difference between the two is the URL suffix (simpleenroll vs
// simplereenroll); the audit-action distinction is server-side.
func (c *Client) estEnrollOp(op, helpName string, args []string) error {
	fs := flag.NewFlagSet(helpName, flag.ContinueOnError)
	profile := fs.String("profile", "", "EST profile PathID (empty = legacy root)")
	csrPath := fs.String("csr", "", "path to PKCS#10 CSR (PEM or base64-DER); '-' = stdin")
	out := fs.String("out", "-", "output file path; '-' = stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *csrPath == "" {
		return fmt.Errorf("--csr is required (path to a PKCS#10 CSR file or '-' for stdin)")
	}
	csrBytes, err := readCSRBytes(*csrPath)
	if err != nil {
		return fmt.Errorf("read CSR: %w", err)
	}
	// EST §4.2.1: client MAY send PEM or base64-DER. The server's
	// readCSRFromRequest handles either; we forward what the operator
	// supplied. Content-Type is application/pkcs10 per RFC 7030.
	body, _, err := c.estPostBody(c.estPath(*profile, op), "application/pkcs10", csrBytes)
	if err != nil {
		return err
	}
	return writeOutput(*out, body)
}

// EstServerKeygen implements `certctl-cli est serverkeygen --profile <p>
// --csr <path> --out <prefix>`. The server returns multipart/mixed; we
// split into the cert part and the encrypted-key part, write each to
// <prefix>.cert.pem + <prefix>.key.enveloped so the operator can pipe
// the latter into `openssl smime -decrypt -inkey <client-priv>`.
func (c *Client) EstServerKeygen(args []string) error {
	fs := flag.NewFlagSet("est serverkeygen", flag.ContinueOnError)
	profile := fs.String("profile", "", "EST profile PathID (empty = legacy root)")
	csrPath := fs.String("csr", "", "path to PKCS#10 CSR (PEM or base64-DER); '-' = stdin")
	outPrefix := fs.String("out", "keypair", "output file prefix; produces <prefix>.cert.pem + <prefix>.key.enveloped")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *csrPath == "" {
		return fmt.Errorf("--csr is required")
	}
	csrBytes, err := readCSRBytes(*csrPath)
	if err != nil {
		return fmt.Errorf("read CSR: %w", err)
	}
	body, hdr, err := c.estPostBody(c.estPath(*profile, "serverkeygen"), "application/pkcs10", csrBytes)
	if err != nil {
		return err
	}
	// Parse the multipart body so we can write each part to its own
	// file. The handler emits two parts: certs-only PKCS#7 and
	// EnvelopedData PKCS#7. We don't decrypt the key here — the
	// operator's smime client owns the recipient private key.
	contentType := hdr.Get("Content-Type")
	certPart, keyPart, err := splitServerKeygenMultipart(body, contentType)
	if err != nil {
		return fmt.Errorf("parse multipart response: %w", err)
	}
	certFile := *outPrefix + ".cert.pem"
	keyFile := *outPrefix + ".key.enveloped"
	if err := os.WriteFile(certFile, certPart, 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPart, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s + %s\n", certFile, keyFile)
	return nil
}

// EstTest is a smoke-test that hits cacerts + csrattrs in sequence and
// prints a one-line OK/FAIL per endpoint. Useful for operator post-
// deploy validation: `certctl-cli est test --profile corp` returns
// exit-0 when both endpoints respond successfully.
func (c *Client) EstTest(args []string) error {
	fs := flag.NewFlagSet("est test", flag.ContinueOnError)
	profile := fs.String("profile", "", "EST profile PathID (empty = legacy root)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, _, _, err := c.estGet(c.estPath(*profile, "cacerts")); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL cacerts: %v\n", err)
		return err
	}
	fmt.Fprintln(os.Stderr, "OK   cacerts")
	if _, status, _, err := c.estGet(c.estPath(*profile, "csrattrs")); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL csrattrs: %v\n", err)
		return err
	} else {
		fmt.Fprintf(os.Stderr, "OK   csrattrs (HTTP %d)\n", status)
	}
	return nil
}

// writeOutput writes to disk or stdout depending on --out. Centralises
// the open-truncate-permission semantics so every subcommand uses the
// same shape.
func writeOutput(path string, body []byte) error {
	if path == "-" || path == "" {
		_, err := os.Stdout.Write(body)
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

// splitServerKeygenMultipart cracks the RFC 7030 §4.4.2 multipart body
// into its two PKCS#7 parts. The caller hands us the response body +
// the Content-Type header value (which carries the boundary parameter
// produced by handler.newMultipartBoundary).
//
// Light-weight on purpose — we use stdlib mime/multipart but keep the
// helper self-contained here so the test can swap in fixture bytes
// without spinning up the full ESTHandler.
func splitServerKeygenMultipart(body []byte, contentType string) ([]byte, []byte, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, nil, fmt.Errorf("parse Content-Type %q: %w", contentType, err)
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, nil, fmt.Errorf("multipart Content-Type %q missing boundary parameter", contentType)
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var cert, key []byte
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		ct := part.Header.Get("Content-Type")
		// The handler wraps each part body in base64 (see writeBase64Wrapped).
		raw, _ := io.ReadAll(part)
		decoded, decErr := decodeBase64Wrapped(raw)
		if decErr != nil {
			// Some clients want the base64 verbatim; fall through to raw.
			decoded = raw
		}
		switch {
		case strings.Contains(ct, "smime-type=certs-only"):
			cert = decoded
		case strings.Contains(ct, "smime-type=enveloped-data"):
			key = decoded
		}
	}
	if len(cert) == 0 || len(key) == 0 {
		return nil, nil, fmt.Errorf("multipart response missing required parts (cert=%d bytes, key=%d bytes)", len(cert), len(key))
	}
	return cert, key, nil
}

// decodeBase64Wrapped strips CRLF wrapping then base64-decodes. The
// EST handler emits the body as base64 with CRLF every 76 chars per
// RFC 2045; client-side decode is "rip the whitespace, base64-decode
// the rest".
func decodeBase64Wrapped(in []byte) ([]byte, error) {
	stripped := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, string(in))
	return base64.StdEncoding.DecodeString(stripped)
}

// _ = pem.Decode is referenced by est_test.go to verify the cacerts
// + enroll responses are parseable PEM. Keep the import live without
// growing the public API.
var _ = pem.Decode
