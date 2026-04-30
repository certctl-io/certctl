package tlsprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// ProbeResult contains the result of probing a TLS endpoint.
type ProbeResult struct {
	Address        string    `json:"address"`
	Success        bool      `json:"success"`
	Fingerprint    string    `json:"fingerprint"`  // SHA-256 hex fingerprint of leaf cert
	TLSVersion     string    `json:"tls_version"`  // e.g. "TLS 1.3"
	CipherSuite    string    `json:"cipher_suite"` // e.g. "TLS_AES_128_GCM_SHA256"
	Subject        string    `json:"subject"`      // cert subject CN
	Issuer         string    `json:"issuer"`       // cert issuer CN
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	SerialNumber   string    `json:"serial_number"`
	ResponseTimeMs int       `json:"response_time_ms"`
	Error          string    `json:"error,omitempty"`
}

// ProbeTLS connects to a TLS endpoint, performs a handshake, and extracts certificate metadata.
// It uses InsecureSkipVerify to discover all certificates including self-signed and expired ones.
// This is safe because the certificate data is extracted and analyzed, not validated for trust.
func ProbeTLS(ctx context.Context, address string, timeout time.Duration) ProbeResult {
	startTime := time.Now()
	result := ProbeResult{
		Address: address,
		Success: false,
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		// SECURITY NOTE: InsecureSkipVerify is intentionally set to true here.
		// The health checker must monitor ALL certificates including self-signed,
		// expired, and internal CA certificates. This setting is scoped to discovery
		// probing only — it is NEVER used for control-plane API calls, issuer
		// connector communication, or any operation that trusts the certificate.
		// The endpoint's certificate chain is extracted and analyzed, not validated.
		// See TICKET-016 for full security audit rationale.
		InsecureSkipVerify: true, //nolint:gosec // discovery probe; documented above + docs/tls.md L-001 table
	})
	if err != nil {
		result.Error = err.Error()
		result.ResponseTimeMs = int(time.Since(startTime).Milliseconds())
		return result
	}
	defer conn.Close()

	result.ResponseTimeMs = int(time.Since(startTime).Milliseconds())
	result.Success = true

	// Extract certificates from TLS connection state
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Fingerprint = CertFingerprint(cert)
		result.Subject = cert.Subject.CommonName
		result.Issuer = cert.Issuer.CommonName
		result.NotBefore = cert.NotBefore
		result.NotAfter = cert.NotAfter
		result.SerialNumber = cert.SerialNumber.Text(16)
	}

	// Extract TLS version string
	result.TLSVersion = tlsVersionString(state.Version)

	// Extract cipher suite name
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	return result
}

// CertFingerprint computes the SHA-256 fingerprint of a certificate (hex-encoded).
func CertFingerprint(cert *x509.Certificate) string {
	fingerprintBytes := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprintBytes[:])
}

// CertKeyInfo extracts key algorithm name and size from a certificate.
// Returns algorithm name (e.g., "RSA", "ECDSA", "Ed25519") and key size in bits.
func CertKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	default:
		switch cert.PublicKeyAlgorithm {
		case x509.Ed25519:
			return "Ed25519", 256
		default:
			return cert.PublicKeyAlgorithm.String(), 0
		}
	}
}

// tlsVersionString converts a TLS version constant to a human-readable string.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%x", version)
	}
}
