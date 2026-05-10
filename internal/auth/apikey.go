package auth

import (
	"crypto/sha256"
	"encoding/hex"
)

// NamedAPIKey represents a named API key with optional admin flag.
//
// Name is the canonical actor identity propagated through the request
// context (UserKey) and into the audit trail. Two NamedAPIKey rows
// MAY share a Name during a rotation overlap window per audit L-004
// (CWE-924); both keys validate to the same actor + admin flag so the
// per-user rate-limit bucket stays consistent during rotation.
type NamedAPIKey struct {
	Name  string
	Key   string
	Admin bool
}

// HashAPIKey computes the SHA-256 hash of an API key for secure storage.
// We use SHA-256 rather than bcrypt because API keys are high-entropy
// random strings (not user-chosen passwords), so rainbow tables and
// brute-force attacks are not a practical concern.
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}
