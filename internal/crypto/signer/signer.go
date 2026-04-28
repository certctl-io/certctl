package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
)

// Signer extends crypto.Signer with an Algorithm method that lets callers
// pick the matching x509.SignatureAlgorithm without reflecting on the key.
//
// Implementations MUST satisfy the crypto.Signer contract: Public() returns
// the matching public key, and Sign(rand, digest, opts) produces a
// signature in the algorithm's standard wire format (PKCS#1 v1.5 / PSS for
// RSA, ASN.1 DER-encoded ECDSA-Sig-Value for ECDSA). The Algorithm method
// is purely a metadata accessor — it MUST NOT cause I/O.
type Signer interface {
	crypto.Signer
	Algorithm() Algorithm
}

// Algorithm enumerates the certctl-supported signing algorithms.
//
// The set is deliberately small. Adding an algorithm requires updating
// signer.go's enum, parse.go's algorithmFromKey, the SignatureAlgorithm
// helper below, and the corresponding profile validators in
// internal/service that gate operator-facing key-policy choices. Do not
// add Ed25519 (or any new algorithm) without that full sweep — the
// half-implemented case is worse than the absent case.
type Algorithm string

// Algorithm constants enumerate the certctl-supported signing algorithms.
// Wire-format strings match the operator-facing values used in
// CertificateProfile validators so the values are stable across the
// audit/policy/connector boundary.
const (
	// AlgorithmRSA2048 is RSA with a 2048-bit modulus.
	AlgorithmRSA2048 Algorithm = "RSA-2048"
	// AlgorithmRSA3072 is RSA with a 3072-bit modulus.
	AlgorithmRSA3072 Algorithm = "RSA-3072"
	// AlgorithmRSA4096 is RSA with a 4096-bit modulus.
	AlgorithmRSA4096 Algorithm = "RSA-4096"
	// AlgorithmECDSAP256 is ECDSA over the NIST P-256 (secp256r1) curve.
	AlgorithmECDSAP256 Algorithm = "ECDSA-P256"
	// AlgorithmECDSAP384 is ECDSA over the NIST P-384 (secp384r1) curve.
	AlgorithmECDSAP384 Algorithm = "ECDSA-P384"
)

// ErrUnsupportedAlgorithm is returned when a key uses a curve, modulus,
// or type the signer package does not recognize. Callers can use
// errors.Is to distinguish this from other failure modes.
var ErrUnsupportedAlgorithm = errors.New("signer: unsupported key algorithm")

// SignatureAlgorithm maps a Signer's Algorithm to the matching
// x509.SignatureAlgorithm. Used by call sites that build cert / CRL /
// OCSP templates so they don't have to do their own type-switch.
//
// Returns x509.UnknownSignatureAlgorithm for unrecognized inputs;
// callers SHOULD treat that as a bug (the only supported values are the
// constants above).
func SignatureAlgorithm(a Algorithm) x509.SignatureAlgorithm {
	switch a {
	case AlgorithmRSA2048, AlgorithmRSA3072, AlgorithmRSA4096:
		return x509.SHA256WithRSA
	case AlgorithmECDSAP256:
		return x509.ECDSAWithSHA256
	case AlgorithmECDSAP384:
		return x509.ECDSAWithSHA384
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// Wrap adapts a stdlib crypto.Signer into a signer.Signer by inferring
// the Algorithm from the key's public half. Returns ErrUnsupportedAlgorithm
// (wrapped with key-shape detail) for keys outside the supported enum.
//
// This is the canonical adapter used by every Driver in this package
// and by callers that already hold a crypto.Signer (e.g., a key parsed
// elsewhere). Drivers SHOULD NOT implement Signer from scratch; wrapping
// keeps the Algorithm-detection logic in one place.
func Wrap(s crypto.Signer) (Signer, error) {
	if s == nil {
		return nil, fmt.Errorf("signer.Wrap: nil signer")
	}
	alg, err := algorithmFromKey(s.Public())
	if err != nil {
		return nil, err
	}
	return &wrappedSigner{inner: s, alg: alg}, nil
}

// wrappedSigner is the concrete type returned by Wrap. It is unexported
// so the only path to a Signer is through Wrap (or a Driver that calls
// Wrap internally) — that keeps Algorithm()'s value-semantics consistent.
type wrappedSigner struct {
	inner crypto.Signer
	alg   Algorithm
}

func (w *wrappedSigner) Public() crypto.PublicKey { return w.inner.Public() }

func (w *wrappedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return w.inner.Sign(rand, digest, opts)
}

func (w *wrappedSigner) Algorithm() Algorithm { return w.alg }

// algorithmFromKey infers the Algorithm enum value from a public key.
// Used by Wrap; exported via the Signer contract through Algorithm().
//
// Bounds-checked against the enum exactly: an RSA-1024 key returns
// ErrUnsupportedAlgorithm even though it would otherwise satisfy
// crypto.Signer — the local CA never produces RSA-1024 and operators
// importing such a key into a sub-CA path should fail loudly at load
// time, not at first-sign time.
func algorithmFromKey(pub crypto.PublicKey) (Algorithm, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048:
			return AlgorithmRSA2048, nil
		case 3072:
			return AlgorithmRSA3072, nil
		case 4096:
			return AlgorithmRSA4096, nil
		default:
			return "", fmt.Errorf("%w: RSA modulus %d bits (supported: 2048, 3072, 4096)",
				ErrUnsupportedAlgorithm, k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return AlgorithmECDSAP256, nil
		case elliptic.P384():
			return AlgorithmECDSAP384, nil
		default:
			name := "unknown"
			if p := k.Curve.Params(); p != nil {
				name = p.Name
			}
			return "", fmt.Errorf("%w: ECDSA curve %s (supported: P-256, P-384)",
				ErrUnsupportedAlgorithm, name)
		}
	default:
		return "", fmt.Errorf("%w: %T (supported: *rsa.PublicKey, *ecdsa.PublicKey)",
			ErrUnsupportedAlgorithm, pub)
	}
}
