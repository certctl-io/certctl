package auth

import (
	"crypto/subtle"
	"sync"
)

// KeyStore is the lookup contract NewAuthWithKeyStore consults to
// resolve a Bearer token (already SHA-256 hashed by the middleware) to
// a NamedAPIKey identity. The interface exists so the same auth
// middleware can serve both the env-var-keys-only path (immutable
// in-memory hash table built at startup) and the bootstrap-extended
// path (env-var keys plus runtime-minted admin keys persisted in
// `api_keys`). Bundle 2 will plug in an OIDC-session lookup behind the
// same interface.
//
// LookupByHash MUST be safe for concurrent reads. Implementations that
// support runtime additions wrap their backing slice/map in a
// sync.RWMutex (see MutableKeyStore) so the request path remains lock-
// free in the steady state.
type KeyStore interface {
	// LookupByHash returns the NamedAPIKey whose SHA-256 hash matches
	// the supplied hex-encoded hash. The matched bool is false when no
	// entry matches; callers MUST treat false as "wrong key" (HTTP
	// 401) and never as "fall through to a default identity".
	//
	// The supplied hash is the output of HashAPIKey(token) — already a
	// 64-char lowercase hex string. Implementations compare it against
	// stored hashes via crypto/subtle.ConstantTimeCompare so a
	// timing-attacking caller can't byte-by-byte recover a key.
	LookupByHash(hash string) (NamedAPIKey, bool)
}

// StaticKeyStore is the immutable Bundle-0 behaviour: the entries are
// fixed at construction and the lookup is a constant-time scan. Used
// by deployments that haven't enabled the Bundle-1 bootstrap flow and
// by tests that don't need runtime additions.
type StaticKeyStore struct {
	entries []entry
}

type entry struct {
	hash  string // SHA-256 hex
	name  string
	admin bool
}

// NewStaticKeyStore builds an immutable KeyStore from a slice of
// NamedAPIKey values. Each key is hashed once at construction. The
// returned store is safe for concurrent reads with no locking; mutation
// is not supported.
func NewStaticKeyStore(keys []NamedAPIKey) *StaticKeyStore {
	out := &StaticKeyStore{
		entries: make([]entry, 0, len(keys)),
	}
	for _, nk := range keys {
		out.entries = append(out.entries, entry{
			hash:  HashAPIKey(nk.Key),
			name:  nk.Name,
			admin: nk.Admin,
		})
	}
	return out
}

// LookupByHash implements KeyStore.
func (s *StaticKeyStore) LookupByHash(hash string) (NamedAPIKey, bool) {
	for i := range s.entries {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(s.entries[i].hash)) == 1 {
			e := s.entries[i]
			return NamedAPIKey{Name: e.name, Admin: e.admin}, true
		}
	}
	return NamedAPIKey{}, false
}

// Len reports how many entries the store holds. Test/debug helper; the
// request path uses LookupByHash which is the load-bearing contract.
func (s *StaticKeyStore) Len() int { return len(s.entries) }

// MutableKeyStore is the Bundle-1 Phase 6 KeyStore that supports
// runtime additions. The Bundle 1 bootstrap flow inserts a new row
// into `api_keys`, then calls Add(...) so the just-minted key
// authenticates the very next request without a server restart. The
// backing store loads the same `api_keys` rows on startup so DB-
// persisted keys survive process restart.
//
// Concurrency: a sync.RWMutex guards a slice of entries. Reads
// (LookupByHash) take the read lock; Add takes the write lock. The
// in-memory slice mirrors the env-var named-key entries plus every
// `api_keys` row loaded at boot plus every Add that fires after
// startup.
type MutableKeyStore struct {
	mu      sync.RWMutex
	entries []entry
}

// NewMutableKeyStore seeds a MutableKeyStore with the provided keys.
// Pass the env-var named keys here at boot; Add additional keys
// (loaded from `api_keys` or minted by bootstrap) after construction.
func NewMutableKeyStore(seed []NamedAPIKey) *MutableKeyStore {
	out := &MutableKeyStore{
		entries: make([]entry, 0, len(seed)),
	}
	for _, nk := range seed {
		out.entries = append(out.entries, entry{
			hash:  HashAPIKey(nk.Key),
			name:  nk.Name,
			admin: nk.Admin,
		})
	}
	return out
}

// LookupByHash implements KeyStore.
func (s *MutableKeyStore) LookupByHash(hash string) (NamedAPIKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.entries {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(s.entries[i].hash)) == 1 {
			e := s.entries[i]
			return NamedAPIKey{Name: e.name, Admin: e.admin}, true
		}
	}
	return NamedAPIKey{}, false
}

// Add registers a new key with the store. The plaintext key is hashed
// once and stored alongside the name + admin flag. Idempotent on
// duplicate hashes (an existing entry for the same hash is replaced
// in-place so re-running the bootstrap loader on startup is safe).
func (s *MutableKeyStore) Add(key NamedAPIKey) {
	s.AddHashed(key.Name, HashAPIKey(key.Key), key.Admin)
}

// AddHashed registers a key whose SHA-256 hash is already computed.
// Used by the api_keys boot loader (the DB stores the hash, not the
// plaintext, so the loader has no plaintext to re-hash).
func (s *MutableKeyStore) AddHashed(name, hashHex string, admin bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.entries {
		if s.entries[i].hash == hashHex {
			s.entries[i].name = name
			s.entries[i].admin = admin
			return
		}
	}
	s.entries = append(s.entries, entry{hash: hashHex, name: name, admin: admin})
}

// Len reports the current entry count. Test helper.
func (s *MutableKeyStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}
