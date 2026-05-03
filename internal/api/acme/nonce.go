// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"
)

// NonceStore is the persistence-layer contract for ACME nonces. The
// production implementation lives at internal/repository/postgres/acme.go
// and is DB-backed (NOT in-memory) — replay protection requires the
// store to outlast the client's nonce caching window.
//
// Issue creates a new nonce and stores it with a TTL. The string return
// is what the handler echoes in the Replay-Nonce response header.
//
// Consume marks a nonce used and returns an error if the nonce is
// missing, already used, or expired. The handler maps that error to
// urn:ietf:params:acme:error:badNonce per RFC 8555 §6.5.1.
//
// Phase 1a: Issue is wired (every directory + new-nonce response carries
// a Replay-Nonce header). Consume is exposed but not yet invoked —
// JWS-authenticated POSTs (which consume nonces) arrive in Phase 1b.
type NonceStore interface {
	Issue(ctx context.Context, ttl time.Duration) (string, error)
	Consume(ctx context.Context, nonce string) error
}

// nonceByteLen is 32 bytes (256 bits) of entropy. RFC 8555 §6.5.1 only
// requires nonces to be hard-to-guess; 256 bits is overkill on purpose
// (matches the consumer-side ACME library + every other ACME server).
const nonceByteLen = 32

// GenerateNonce returns 32 cryptographically-random bytes encoded as
// base64url-no-padding per RFC 7515 §2 (the encoding ACME wire format
// uses for the protected-header nonce field).
func GenerateNonce() (string, error) {
	b := make([]byte, nonceByteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
