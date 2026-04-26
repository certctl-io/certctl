package local

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
)

// Bundle-9 / Audit L-002 (Private-key bytes linger in heap after marshal):
//
// x509.MarshalECPrivateKey copies the private scalar into a fresh DER buffer.
// If the caller PEM-encodes that buffer, writes it to disk, and returns, the
// buffer remains in the goroutine's heap until the GC sweeps it — at which
// point the bytes may persist further (Go's GC does not zero released memory).
//
// A heap dump (debug attach, core dump, swap-out, container memory snapshot
// taken by an attacker with host access) can then recover the private key.
//
// marshalPrivateKeyAndZeroize wraps MarshalECPrivateKey + a deferred
// `clear(buf)` so the caller can copy the DER into a PEM block and the
// underlying bytes are zeroed on function return. It is the caller's
// responsibility to do the same on whatever PEM/file buffer they derive.
//
// This is a defense-in-depth measure — Go memory hygiene cannot match the
// guarantees of a process-isolated HSM. See L-014's documentation in
// local.go for the explicit threat-model carve-out around CA private keys
// resident in the server process.

// marshalPrivateKeyAndZeroize marshals an ECDSA private key to DER and
// invokes onDER with the bytes. After onDER returns, the DER buffer is
// zeroized via the builtin `clear`. This bounds the window during which
// the private scalar lives in the heap to exactly the duration of onDER.
//
// Callers that PEM-encode + write to disk should structure as:
//
//	err := marshalPrivateKeyAndZeroize(priv, func(der []byte) error {
//	    pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
//	    defer clear(pemBytes)
//	    return os.WriteFile(path, pemBytes, 0o600)
//	})
//
// onDER MUST NOT retain a reference to the slice — the bytes are zeroed
// after it returns.
func marshalPrivateKeyAndZeroize(priv *ecdsa.PrivateKey, onDER func([]byte) error) error {
	if priv == nil {
		return fmt.Errorf("marshalPrivateKeyAndZeroize: nil private key")
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	defer clear(der)
	return onDER(der)
}
