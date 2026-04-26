package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// Bundle-9 / Audit L-002 + L-003 (agent edition).
//
// The agent generates an ECDSA P-256 key locally and writes it to disk with
// mode 0600 in a directory it expects to be 0700. The duplication of the
// local-issuer helpers (instead of importing from internal/...) is deliberate:
//
//   - cmd/agent is a separate binary with its own threat model (runs on every
//     deployment target, not just the control plane). Coupling it to
//     internal/connector/issuer/local would pull deployment-target footprint
//     into a connector that's only relevant on the server.
//   - The behavior is small and self-contained; copy-paste is cheaper than
//     a refactor that introduces an internal/keystore package.
//
// If a third call site emerges, lift these into internal/keystore.

// marshalAgentKeyAndZeroize marshals an ECDSA private key to DER and invokes
// onDER with the bytes; the buffer is zeroized via builtin clear() after
// onDER returns. Caller must NOT retain the slice.
func marshalAgentKeyAndZeroize(priv *ecdsa.PrivateKey, onDER func([]byte) error) error {
	if priv == nil {
		return fmt.Errorf("marshalAgentKeyAndZeroize: nil private key")
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	defer clear(der)
	return onDER(der)
}

// ensureAgentKeyDirSecure creates dir (and ancestors) with mode 0700 or
// asserts an existing dir is owner-only. If a pre-existing dir is more
// permissive than 0700 we tighten it to 0700 (logging-free; this is a
// startup-style invariant, not a per-request check).
func ensureAgentKeyDirSecure(dir string) error {
	if dir == "" || dir == "." || dir == "/" {
		return fmt.Errorf("ensureAgentKeyDirSecure: refuse empty/root dir %q", dir)
	}
	clean := filepath.Clean(dir)
	info, err := os.Stat(clean)
	switch {
	case os.IsNotExist(err):
		if mkErr := os.MkdirAll(clean, 0o700); mkErr != nil {
			return fmt.Errorf("create agent key dir %q: %w", clean, mkErr)
		}
		info, err = os.Stat(clean)
		if err != nil {
			return fmt.Errorf("stat newly-created agent key dir %q: %w", clean, err)
		}
		fallthrough
	case err == nil:
		mode := info.Mode().Perm()
		if mode == 0o700 || mode&0o077 == 0 {
			return nil
		}
		if chmodErr := os.Chmod(clean, 0o700); chmodErr != nil {
			return fmt.Errorf("tighten agent key dir %q from %#o to 0700: %w", clean, mode, chmodErr)
		}
		return nil
	default:
		return fmt.Errorf("stat agent key dir %q: %w", clean, err)
	}
}
