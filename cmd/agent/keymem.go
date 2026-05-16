// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// SEC-002 closure (Sprint 1, 2026-05-16). The agent derives an on-disk
// key path from job.CertificateID via filepath.Join. Pre-fix, a
// crafted certificate_id ("../../etc/passwd", "/absolute/path",
// "abc\x00d", "..\\Windows\\path") would drive arbitrary file
// write/read on the agent host. The shape regex below mirrors the
// server-side internal/validation.ValidateCertificateID gate — both
// ends MUST hold for the load-bearing defense (the server can't be
// trusted in isolation; a compromised control plane could deliver a
// crafted job).
//
// agentCertIDPattern accepts ASCII letters, digits, ".", "_", "-",
// bounded to 128 chars. Existing prefixed IDs (mc-..., cert-..., etc.)
// satisfy this trivially. Deliberately rejects path separators (POSIX
// and Windows), NUL byte, whitespace, control characters, and the
// bare relative-path tokens "." and "..".
var agentCertIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// validateAgentCertID returns an error if id is not a well-formed
// certificate identifier. Mirrors internal/validation.ValidateCertificateID
// — the duplication is deliberate per the package-level comment
// ("cmd/agent is a separate binary; copy-paste cheaper than lifting
// a shared internal/keystore for a single shape check").
func validateAgentCertID(id string) error {
	if id == "" {
		return fmt.Errorf("certificate_id is required")
	}
	if len(id) > 128 {
		return fmt.Errorf("certificate_id length %d exceeds 128", len(id))
	}
	if !agentCertIDPattern.MatchString(id) {
		return fmt.Errorf("certificate_id %q contains disallowed characters", id)
	}
	if id == "." || id == ".." {
		return fmt.Errorf("certificate_id %q is a relative-path token", id)
	}
	return nil
}

// safeAgentKeyPath returns the on-disk key path for the given
// certificateID, after validating the ID shape AND asserting the
// joined path is contained within keyDir. Containment is the
// authoritative guard — even if validateAgentCertID is bypassed (e.g.
// a future refactor removes it), the post-Clean rel-path check below
// rejects any path that escapes keyDir.
//
// The two-leg defense:
//
//	leg 1: shape check (validateAgentCertID)  → cheap up-front fail
//	leg 2: containment check (filepath.Rel)   → load-bearing guard
//
// Returns the joined path on success, or a non-nil error describing
// the rejected vector.
func safeAgentKeyPath(keyDir, certificateID string) (string, error) {
	if err := validateAgentCertID(certificateID); err != nil {
		return "", err
	}
	if keyDir == "" {
		return "", fmt.Errorf("safeAgentKeyPath: empty keyDir")
	}
	cleanDir, err := filepath.Abs(filepath.Clean(keyDir))
	if err != nil {
		return "", fmt.Errorf("safeAgentKeyPath: resolve keyDir: %w", err)
	}
	joined := filepath.Join(cleanDir, certificateID+".key")
	cleanJoined := filepath.Clean(joined)
	rel, err := filepath.Rel(cleanDir, cleanJoined)
	if err != nil {
		return "", fmt.Errorf("safeAgentKeyPath: rel(%q,%q): %w", cleanDir, cleanJoined, err)
	}
	// Reject any path that escapes the directory: a leading ".." in the
	// relative form means the joined path resolved outside keyDir.
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("safeAgentKeyPath: %q escapes keyDir %q (rel=%q)", certificateID, cleanDir, rel)
	}
	// Belt-and-suspenders: the rel form must also not contain a NUL.
	if strings.ContainsRune(rel, 0) {
		return "", fmt.Errorf("safeAgentKeyPath: NUL byte in computed path")
	}
	return cleanJoined, nil
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
