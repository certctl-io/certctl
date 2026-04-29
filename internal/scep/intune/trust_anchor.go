package intune

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// LoadTrustAnchor reads a PEM bundle of one or more Intune Connector
// signing certificates from the configured path. Returns the slice of
// parsed certs that the validator will accept as challenge issuers.
//
// SCEP RFC 8894 + Intune master bundle Phase 7.2.
//
// Behavior:
//
//   - File must exist + be readable.
//   - PEM-decodes the file; non-CERTIFICATE blocks are skipped (so an
//     operator can paste a chain that includes a private key by mistake
//     without breaking the load — the priv key is just ignored).
//   - Returns an error if zero CERTIFICATE blocks parse.
//   - Returns an error if any cert is past NotAfter (a stale trust
//     anchor would silently reject every Intune challenge at runtime;
//     fail loud at startup instead).
//
// Operators rotate Connector signing certs periodically; the trust
// anchor file is reloaded on SIGHUP (handled by the existing config
// watch loop in cmd/server/main.go — see cmd/server/tls.go::watchSIGHUP
// for the precedent).
func LoadTrustAnchor(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, fmt.Errorf("intune: trust anchor path is empty")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("intune: read trust anchor %q: %w", path, err)
	}
	return parseTrustAnchorPEM(body, path, time.Now())
}

// parseTrustAnchorPEM is the file-IO-free core of LoadTrustAnchor. Split
// out so unit tests can hand it byte slices without writing temp files.
// `now` is taken as a parameter so expiry tests can pin a deterministic
// clock.
func parseTrustAnchorPEM(body []byte, sourceLabel string, now time.Time) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("intune: parse trust anchor cert in %q: %w", sourceLabel, err)
		}
		if now.After(cert.NotAfter) {
			return nil, fmt.Errorf("intune: trust anchor cert in %q expired at %s (subject=%q) — operator must rotate the Connector signing cert before restart",
				sourceLabel, cert.NotAfter.Format(time.RFC3339), cert.Subject.CommonName)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("intune: trust anchor %q contains no CERTIFICATE PEM blocks", sourceLabel)
	}
	return out, nil
}
