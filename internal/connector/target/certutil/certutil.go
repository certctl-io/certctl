// Package certutil provides shared certificate utility functions for target connectors.
// These functions handle PEM/PFX conversion, key parsing, thumbprint computation,
// and random password generation. Extracted from the IIS connector (M39) to enable
// reuse by Windows Certificate Store (M46) and Java Keystore (M46) connectors.
package certutil

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// CreatePFX converts PEM-encoded cert, key, and chain into PKCS#12 (PFX) format.
// Uses go-pkcs12 Modern encoder with strong encryption.
func CreatePFX(certPEM, keyPEM, chainPEM string, password string) ([]byte, error) {
	// Parse leaf certificate
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	leafCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Parse private key (supports PKCS#8, PKCS#1 RSA, and EC)
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	privateKey, err := ParsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Parse CA chain certificates (optional)
	var caCerts []*x509.Certificate
	if chainPEM != "" {
		rest := []byte(chainPEM)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			caCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
			}
			caCerts = append(caCerts, caCert)
		}
	}

	// Encode as PKCS#12 with Modern encryption
	pfxData, err := pkcs12.Modern.Encode(privateKey, leafCert, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PKCS#12: %w", err)
	}

	return pfxData, nil
}

// ParsePrivateKey attempts to parse a DER-encoded private key.
// Tries PKCS#8, PKCS#1 RSA, and EC formats in order.
func ParsePrivateKey(der []byte) (interface{}, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

// ComputeThumbprint calculates the SHA-1 thumbprint of a PEM-encoded certificate.
// Windows uses SHA-1 thumbprints as the primary certificate identifier.
// Returns uppercase hex string matching Windows certutil output.
func ComputeThumbprint(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("failed to decode certificate PEM for thumbprint")
	}
	hash := sha1.Sum(block.Bytes)
	return strings.ToUpper(hex.EncodeToString(hash[:])), nil
}

// GenerateRandomPassword creates a random alphanumeric password.
// Typically used for transient PFX encryption — the password is only used
// between PFX creation and import, it never persists.
func GenerateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}

// ParseCertificatePEM parses a PEM-encoded certificate and returns the x509.Certificate.
func ParseCertificatePEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}
