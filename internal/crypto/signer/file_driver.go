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
}

// Name implements Driver.
func (d *FileDriver) Name() string { return "file" }

// Load implements Driver. It reads the PEM file at path, decodes the
// first PEM block, parses it via the package's parsePrivateKey
// (which handles PKCS#1 / SEC 1 / PKCS#8), and wraps the resulting
// crypto.Signer.
//
// Errors are wrapped with the path so operators can grep their logs.
// No key bytes are logged — only the path and (on success) the
// inferred Algorithm.
func (d *FileDriver) Load(ctx context.Context, path string) (Signer, error) {
	if path == "" {
		return nil, errors.New("signer.FileDriver.Load: empty path")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("signer.FileDriver.Load: %w", err)
	}

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signer.FileDriver.Load: read %q: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("signer.FileDriver.Load: %q is not PEM", path)
	}
	key, err := parsePrivateKey(block)
	if err != nil {
		return nil, fmt.Errorf("signer.FileDriver.Load: parse %q: %w", path, err)
	}
	wrapped, err := Wrap(key)
	if err != nil {
		return nil, fmt.Errorf("signer.FileDriver.Load: wrap %q: %w", path, err)
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

	// Harden the destination directory BEFORE generating the key. If
	// the directory check fails we bail without touching cryptography.
	if err := d.DirHardener(filepath.Dir(outPath)); err != nil {
		return nil, "", fmt.Errorf("signer.FileDriver.Generate: harden dir for %q: %w", outPath, err)
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
	if err := os.WriteFile(outPath, pemBytes, 0o600); err != nil {
		return nil, "", fmt.Errorf("signer.FileDriver.Generate: write %q: %w", outPath, err)
	}

	wrapped, err := Wrap(signerKey)
	if err != nil {
		return nil, "", fmt.Errorf("signer.FileDriver.Generate: wrap: %w", err)
	}
	return wrapped, outPath, nil
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
