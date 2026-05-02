// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

// Package secret provides Ref, an opaque handle to a credential.
//
// Closes the #6 acquisition-readiness blocker from the 2026-05-01
// issuer coverage audit. Pre-fix, GlobalSign / EJBCA / Sectigo stored
// API keys / OAuth tokens / 3-header credentials as plain Go strings
// on the Connector struct. Encrypted at rest via
// internal/crypto/encryption.go (AES-256-GCM v3 + PBKDF2-600k), they
// sat in process memory in the clear after load and were written to
// HTTP headers on every API call. DEBUG-level HTTP request logging
// leaked them into logs.
//
// Ref defeats casual heap-dump extraction and accidental log leaks:
//
//   - The bytes are never marshalled into a string. Use(fn) is the
//     only access path; Ref.String() returns "[redacted]".
//   - The buffer passed to fn is zeroed (overwritten with 0 bytes)
//     after fn returns. The credential is present in the heap only
//     for the duration of fn.
//   - MarshalJSON returns "[redacted]" so JSON-encoding a config
//     struct (e.g., GET /issuers response) doesn't leak.
//
// Ref is paired with the request-logging middleware filter in
// internal/api/middleware/redact.go which strips known credential
// headers (Authorization, X-API-Key, X-DC-DEVKEY, X-Vault-Token,
// customerUri, login, password) from outbound DEBUG logs as a
// belt-and-braces defense against third-party HTTP clients (AWS SDK
// at DEBUG, etc.) that format headers themselves.
package secret

import (
	"fmt"
	"io"
)

// Ref is an opaque handle to a credential. Use Use(fn) or WriteTo(w)
// to obtain the underlying bytes; do not store the slice beyond the
// callback's return — the buffer is zeroed and may be reused.
type Ref struct {
	// src returns a fresh copy of the credential bytes on every
	// invocation. Production: a closure that decrypts an at-rest
	// blob. Test: a closure that returns a copy of a static []byte.
	src func() ([]byte, error)
}

// NewRef constructs a Ref backed by the supplied source. The source
// closure is called every time Use / WriteTo is invoked; it must
// return a fresh slice (the caller will zero it).
func NewRef(src func() ([]byte, error)) *Ref {
	return &Ref{src: src}
}

// NewRefFromString is a convenience for tests / config-loading paths
// that have a plaintext string already. The source returns a copy of
// the string's bytes on every invocation; the original string still
// lives in the caller's memory (immutable Go string semantics) — the
// caller should drop the reference once it has been wrapped in a Ref.
//
// Production code paths should prefer NewRef with a decrypt-on-demand
// closure so the plaintext is never present in process memory at rest.
func NewRefFromString(s string) *Ref {
	return &Ref{
		src: func() ([]byte, error) {
			// Copy so the returned slice is independent — Use will
			// zero the copy without disturbing s.
			b := make([]byte, len(s))
			copy(b, s)
			return b, nil
		},
	}
}

// Use invokes fn with a freshly-allocated buffer holding the secret
// bytes. After fn returns (or panics), the buffer is overwritten with
// zeros and dropped.
//
// fn MUST NOT retain the slice beyond its return. Storing the slice
// in a struct field, sending it on a channel, or passing it to a
// goroutine that runs after Use returns are all bugs — the buffer
// will be zeroed before the consumer reads it.
func (r *Ref) Use(fn func(buf []byte) error) error {
	if r == nil {
		return fmt.Errorf("secret.Ref.Use: nil Ref")
	}
	buf, err := r.src()
	if err != nil {
		return fmt.Errorf("secret.Ref: source: %w", err)
	}
	defer zero(buf)
	return fn(buf)
}

// WriteTo writes the secret bytes to w (typically an HTTP header
// writer or a CSR signing routine) and zeros the staging buffer
// afterwards. Convenience over Use for the common "set a header"
// case.
//
// Returns the byte count and any write error.
func (r *Ref) WriteTo(w io.Writer) (int64, error) {
	if r == nil {
		return 0, fmt.Errorf("secret.Ref.WriteTo: nil Ref")
	}
	buf, err := r.src()
	if err != nil {
		return 0, fmt.Errorf("secret.Ref: source: %w", err)
	}
	defer zero(buf)
	n, werr := w.Write(buf)
	return int64(n), werr
}

// String returns "[redacted]" — the type intentionally never
// stringifies the underlying bytes. Catches accidental leak via
// fmt.Sprintf("%v", cfg), slog attribute formatting, etc.
func (r *Ref) String() string { return "[redacted]" }

// MarshalJSON returns "[redacted]" so a config struct holding *Ref
// fields can be JSON-encoded without leaking credentials. Used by
// the API surface (GET /issuers etc.) and any operator-facing
// serialization path.
func (r *Ref) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted]"`), nil
}

// IsEmpty reports whether the source returns an empty byte slice
// (zero-length credential). Useful for ValidateConfig paths that need
// to check "did the operator set the credential" without obtaining
// the bytes.
func (r *Ref) IsEmpty() bool {
	if r == nil {
		return true
	}
	buf, err := r.src()
	if err != nil {
		return true
	}
	defer zero(buf)
	return len(buf) == 0
}

// zero overwrites b with zero bytes. Visible for testing.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
