package signer

import (
	"crypto"
	"encoding/pem"
	"fmt"

	"crypto/x509"
)

// parsePrivateKey parses a PEM block into a crypto.Signer. Recognises the
// three PEM block types historically produced and consumed by certctl's
// local CA:
//
//   - "RSA PRIVATE KEY"   (PKCS#1 / RFC 3447, openssl genrsa default)
//   - "EC PRIVATE KEY"    (SEC 1 / RFC 5915, openssl ecparam default)
//   - "PRIVATE KEY"       (PKCS#8 / RFC 5208 — wraps RSA, ECDSA, others)
//
// This function is the single source of truth for PEM private-key parsing
// inside certctl. It was moved here from
// internal/connector/issuer/local/local.go as part of the Signer
// abstraction work; the local package now calls into here. Do not
// reintroduce a parallel implementation elsewhere.
//
// Behavior preserved exactly across the move:
//   - Block type matching is case-sensitive (PEM convention).
//   - PKCS#8 blocks that contain a non-Signer key (e.g., a Diffie-Hellman
//     key, an Ed25519 key absent stdlib Signer support) return an error
//     rather than a panic.
//   - The error wrapping format is intentionally stable so existing test
//     assertions in internal/connector/issuer/local/local_test.go and
//     bundle9_coverage_test.go continue to match without modification.
func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		// PKCS#8 — can contain RSA or ECDSA
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not a signing key")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %s (expected RSA PRIVATE KEY, EC PRIVATE KEY, or PRIVATE KEY)", block.Type)
	}
}

// ParsePrivateKey is the exported wrapper used by callers outside this
// package. It exists so that internal/connector/issuer/local/ (and any
// future caller that needs to load a PEM private key without going
// through a Driver — e.g., a one-off tool, a migration helper) can
// share the parser without re-implementing the block-type dispatch.
//
// Most callers should use a Driver instead — Driver.Load handles the
// file-read + PEM decode + key parse + Signer wrap in one call.
// ParsePrivateKey is exposed for the corner cases where a caller
// already holds the *pem.Block (e.g., the block was extracted from a
// multi-block PEM bundle).
func ParsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	return parsePrivateKey(block)
}
