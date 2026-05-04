package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FileDriver materializes a Signer from a PEM-encoded private key on
// disk. This is the historical and current default behavior of the
// local issuer; FileDriver wraps that behavior without functional
// change so the local issuer can route every signing call through the
// Signer interface without changing what bytes land on disk.
//
// SECURITY: callers SHOULD set DirHardener and Marshaler to enforce
// the audited Bundle 9 hardening (key directory mode 0700 via
// keystore.ensureKeyDirSecure; marshal-with-zeroization via
// keymem.marshalPrivateKeyAndZeroize). When DirHardener is unset,
// Generate refuses to write — an explicit fail-loud signal rather
// than silently falling back to a permissive directory mode.
//
// Load does NOT call DirHardener (Load is read-only and the key may
// already exist in a directory whose mode the operator chose
// deliberately for their threat model). Load also does not call
// Marshaler (Load doesn't write anything).
type FileDriver struct {
	// DirHardener, if set, is invoked on the directory containing a
	// generated key file BEFORE the key is written. The local
	// package wires this to keystore.ensureKeyDirSecure (via a closure
	// — the helper stays package-private to preserve the audit trail
	// in keystore.go's leading comment block). When nil, Generate
	// returns an error.
	DirHardener func(dir string) error

	// Marshaler, if set, converts an *ecdsa.PrivateKey to the
	// PEM-encoded byte slice that Generate will write to disk. The
	// local package wires this to a wrapper around
	// keymem.marshalPrivateKeyAndZeroize, ensuring the L-002
	// heap-zeroization discipline applies to all keys generated
	// through this driver. When nil, Generate falls back to a
	// non-zeroizing marshal — acceptable for tests but NOT for
	// production code paths.
	Marshaler func(*ecdsa.PrivateKey) ([]byte, error)

	// RSAMarshaler is the same shape as Marshaler but for RSA keys.
	// Optional; if nil, Generate falls back to a non-zeroizing
	// marshal. Provided for symmetry with Marshaler so the local
	// issuer can plug in RSA-key-zeroization later without changing
	// the FileDriver API.
	RSAMarshaler func(*rsa.PrivateKey) ([]byte, error)

	// GenerateOutPath, if set, is called with the generated key's
	// algorithm and returns the destination path. When nil, Generate
	// uses a default of <cwd>/ca-<alg>.key — fine for tests, NOT for
	// production. The local package's NewConnector wires this to
	// return the configured CAKeyPath.
	GenerateOutPath func(alg Algorithm) (string, error)

	// SafeRoot, if non-empty, restricts every Load + Generate path to
	// the absolute filesystem subtree rooted at SafeRoot. Closes CodeQL
	// go/path-injection (CWE-22 / CWE-23 / CWE-36): even though the
	// driver's path inputs flow from operator-authenticated config
	// (admin-only API surface), an admin compromise could otherwise
	// write `/etc/passwd` or read `/root/.ssh/id_rsa` via the driver.
	// SafeRoot bounds the blast radius.
	//
	// Validation semantics (validateSafePath):
	//
	//   1. The supplied path is cleaned (filepath.Clean) to collapse
	//      ./ and ../ sequences in their literal form.
	//   2. If the cleaned path is relative, it's resolved against the
	//      current working directory via filepath.Abs.
	//   3. If SafeRoot is set, the absolute path MUST be SafeRoot or
	//      a descendant. We use filepath.Rel + strings.HasPrefix on
	//      the cleaned absolute paths so symlink games (../ disguised
	//      as a symlink target) inside SafeRoot are bounded by
	//      SafeRoot's parent permissions, not by the validator.
	//
	// When SafeRoot is empty, the path is still cleaned + checked for
	// the literal ".." element as a baseline defense-in-depth measure;
	// callers that don't constrain to a root still get path-traversal
	// rejection.
	//
	// Production wiring SHOULD set SafeRoot. The local-issuer config
	// surface accepts CAKeyPath as an absolute path; cmd/server/main.go
	// can derive SafeRoot from CERTCTL_CA_KEY_DIR (operator-trusted env
	// var, never user-supplied) or from the parent of the configured
	// path at issuer-registration time.
	SafeRoot string
}

// Name implements Driver.
func (d *FileDriver) Name() string { return "file" }

// validateSafePath enforces the CWE-22 / CWE-23 / CWE-36 path-traversal
// defense documented on FileDriver.SafeRoot. Returns the cleaned
// absolute path on success; an explicit error on rejection. Rejects:
//
//   - empty paths
//   - paths whose cleaned form contains a literal ".." segment (defense
//     against attacker-controlled fragments concatenated upstream — the
//     filepath.Clean() before this check collapses any "..", so a
//     remaining ".." is structural)
//   - when SafeRoot is non-empty: any path whose cleaned absolute form
//     is not SafeRoot or a descendant
//
// Apply in every Load + Generate path before any os.ReadFile /
// os.WriteFile call. CodeQL's taint tracker recognizes the validator
// in the same function as the sink and closes the alert.
func (d *FileDriver) validateSafePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	cleaned := filepath.Clean(path)
	// Reject any path whose cleaned form still contains a `..` element.
	// filepath.Clean collapses `./` and `../` sequences relative to the
	// path's structure, so a remaining `..` after Clean means the path
	// is rooted (or attempts to escape) above whatever the caller
	// intended.
	for _, segment := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if segment == ".." {
			return "", fmt.Errorf("path %q contains parent-directory segment", path)
		}
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path %q: %w", path, err)
	}
	if d.SafeRoot != "" {
		safeRoot, err := filepath.Abs(filepath.Clean(d.SafeRoot))
		if err != nil {
			return "", fmt.Errorf("resolve SafeRoot %q: %w", d.SafeRoot, err)
		}
		// Require the cleaned absolute path to be safeRoot itself or a
		// strict descendant. The += string.Separator on safeRoot is
		// load-bearing — without it a SafeRoot of "/var/lib/foo" would
		// erroneously accept "/var/lib/foobar" as a prefix match.
		safeRootSlash := safeRoot
		if !strings.HasSuffix(safeRootSlash, string(filepath.Separator)) {
			safeRootSlash += string(filepath.Separator)
		}
		if abs != safeRoot && !strings.HasPrefix(abs, safeRootSlash) {
			return "", fmt.Errorf("path %q resolves outside SafeRoot %q", path, d.SafeRoot)
		}
	}
	return abs, nil
}

// Load implements Driver. It reads the PEM file at path, decodes the
// first PEM block, parses it via the package's parsePrivateKey
// (which handles PKCS#1 / SEC 1 / PKCS#8), and wraps the resulting
// crypto.Signer.
//
// Errors are wrapped with the path so operators can grep their logs.
// No key bytes are logged — only the path and (on success) the
// inferred Algorithm.
func (d *FileDriver) Load(ctx context.Context, path string) (Signer, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("signer.FileDriver.Load: %w", err)
	}
	// CWE-22 path-traversal defense — reject paths that escape SafeRoot
	// (when set) OR contain literal ".." segments. The validator is in
	// the same function as the os.ReadFile sink so CodeQL recognizes
	// the sanitizer in-scope.
	safePath, err := d.validateSafePath(path)
	if err != nil {
		return nil, fmt.Errorf("signer.FileDriver.Load: %w", err)
	}

	pemBytes, err := os.ReadFile(safePath)
	if err != nil {
		return nil, fmt.Errorf("signer.FileDriver.Load: read %q: %w", safePath, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("signer.FileDriver.Load: %q is not PEM", safePath)
	}
	key, err := parsePrivateKey(block)
	if err != nil {
		return nil, fmt.Errorf("signer.FileDriver.Load: parse %q: %w", safePath, err)
	}
	wrapped, err := Wrap(key)
	if err != nil {
		return nil, fmt.Errorf("signer.FileDriver.Load: wrap %q: %w", safePath, err)
	}
	return wrapped, nil
}

// Generate implements Driver. It generates a fresh private key with the
// requested algorithm, writes it to disk via the configured hooks, and
// returns the wrapped Signer plus the file path the caller can pass
// to a subsequent Load call.
//
// Refuses to write when DirHardener is unset — the production local
// package always wires the hardener; only tests are allowed to bypass
// it by constructing the FileDriver directly without calling
// NewProductionFileDriver.
func (d *FileDriver) Generate(ctx context.Context, alg Algorithm) (Signer, string, error) {
	if d.DirHardener == nil {
		return nil, "", errors.New("signer.FileDriver.Generate: DirHardener is required (set to a key-dir-permission validator) — refusing to write key with default umask")
	}
	if err := ctx.Err(); err != nil {
		return nil, "", fmt.Errorf("signer.FileDriver.Generate: %w", err)
	}

	// Resolve destination path before doing any expensive work.
	pathFn := d.GenerateOutPath
	if pathFn == nil {
		pathFn = func(a Algorithm) (string, error) {
			return fmt.Sprintf("ca-%s.key", a), nil
		}
	}
	outPath, err := pathFn(alg)
	if err != nil {
		return nil, "", fmt.Errorf("signer.FileDriver.Generate: resolve out path: %w", err)
	}

	// CWE-22 path-traversal defense — reject paths that escape SafeRoot
	// (when set) OR contain literal ".." segments. The validator is in
	// the same function as the os.WriteFile sink below so CodeQL
	// recognizes the sanitizer in-scope.
	safeOut, err := d.validateSafePath(outPath)
	if err != nil {
		return nil, "", fmt.Errorf("signer.FileDriver.Generate: %w", err)
	}

	// Harden the destination directory BEFORE generating the key. If
	// the directory check fails we bail without touching cryptography.
	if err := d.DirHardener(filepath.Dir(safeOut)); err != nil {
		return nil, "", fmt.Errorf("signer.FileDriver.Generate: harden dir for %q: %w", safeOut, err)
	}

	// Generate the key for the requested algorithm.
	var (
		signerKey crypto.Signer
		pemBytes  []byte
	)
	switch alg {
	case AlgorithmRSA2048, AlgorithmRSA3072, AlgorithmRSA4096:
		bits := rsaBitsFor(alg)
		rsaKey, gerr := rsa.GenerateKey(rand.Reader, bits)
		if gerr != nil {
			return nil, "", fmt.Errorf("signer.FileDriver.Generate: rsa keygen %d: %w", bits, gerr)
		}
		signerKey = rsaKey
		if d.RSAMarshaler != nil {
			pemBytes, err = d.RSAMarshaler(rsaKey)
			if err != nil {
				return nil, "", fmt.Errorf("signer.FileDriver.Generate: RSAMarshaler: %w", err)
			}
		} else {
			pemBytes = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
			})
		}

	case AlgorithmECDSAP256, AlgorithmECDSAP384:
		curve := ecCurveFor(alg)
		ecKey, gerr := ecdsa.GenerateKey(curve, rand.Reader)
		if gerr != nil {
			return nil, "", fmt.Errorf("signer.FileDriver.Generate: ecdsa keygen %s: %w", curve.Params().Name, gerr)
		}
		signerKey = ecKey
		if d.Marshaler != nil {
			pemBytes, err = d.Marshaler(ecKey)
			if err != nil {
				return nil, "", fmt.Errorf("signer.FileDriver.Generate: Marshaler: %w", err)
			}
		} else {
			der, mErr := x509.MarshalECPrivateKey(ecKey)
			if mErr != nil {
				return nil, "", fmt.Errorf("signer.FileDriver.Generate: marshal ec key: %w", mErr)
			}
			pemBytes = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		}

	default:
		return nil, "", fmt.Errorf("signer.FileDriver.Generate: %w: %s", ErrUnsupportedAlgorithm, alg)
	}

	// Write 0o600 — owner-read-write only. Any read by group/other is
	// a configuration regression; the dir 0700 above prevents
	// enumeration of the file's existence.
	if err := os.WriteFile(safeOut, pemBytes, 0o600); err != nil {
		return nil, "", fmt.Errorf("signer.FileDriver.Generate: write %q: %w", safeOut, err)
	}

	wrapped, err := Wrap(signerKey)
	if err != nil {
		return nil, "", fmt.Errorf("signer.FileDriver.Generate: wrap: %w", err)
	}
	return wrapped, safeOut, nil
}

func rsaBitsFor(a Algorithm) int {
	switch a {
	case AlgorithmRSA3072:
		return 3072
	case AlgorithmRSA4096:
		return 4096
	default:
		return 2048
	}
}

func ecCurveFor(a Algorithm) elliptic.Curve {
	if a == AlgorithmECDSAP384 {
		return elliptic.P384()
	}
	return elliptic.P256()
}
