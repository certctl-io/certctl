// Package bootstrap ships the day-0 admin-creation primitive for Bundle 1
// Phase 6. The control plane comes up with no admin-roled actors; the
// operator hands the env-var token to a single curl call; the server
// mints the first admin API key, returns the key value once, then locks
// the bootstrap door behind it.
//
// The Strategy interface is the forward-compat seam: Bundle 2 plugs in an
// OIDC-first-admin strategy (the operator logs in via OIDC, the server
// recognizes their group claim, the first such login auto-grants r-admin)
// alongside the env-var-token strategy this file ships. Both implementations
// satisfy the same interface; the boot path picks one based on which
// CERTCTL_BOOTSTRAP_* env var is set.
package bootstrap

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
)

// Sentinel errors the HTTP handler maps to status codes.
var (
	// ErrDisabled is returned when the bootstrap path is not callable
	// either because (a) no token was set, or (b) admin actors already
	// exist, or (c) the token was already consumed by an earlier call.
	// Maps to HTTP 410 Gone.
	ErrDisabled = errors.New("bootstrap: endpoint disabled")

	// ErrInvalidToken is returned when the supplied token does not
	// match the env-var token (constant-time compared). Maps to HTTP
	// 401 Unauthorized. Deliberately does NOT distinguish between
	// "wrong token" and "no token configured" so callers cannot use
	// timing or status to probe the server's bootstrap state.
	ErrInvalidToken = errors.New("bootstrap: invalid token")

	// ErrInvalidActorName is returned when the requested admin-key
	// name is empty or contains characters that would break audit
	// attribution. Maps to HTTP 400.
	ErrInvalidActorName = errors.New("bootstrap: invalid actor name")
)

// Strategy is the bundle 1 -> bundle 2 forward-compat seam. Each
// strategy gates the day-0 admin path with a different credential type:
// Bundle 1 ships EnvTokenStrategy (CERTCTL_BOOTSTRAP_TOKEN); Bundle 2
// adds OIDCFirstAdminStrategy (CERTCTL_BOOTSTRAP_OIDC_GROUP). The
// service holds whichever strategy was wired at boot.
type Strategy interface {
	// Available reports whether the strategy is currently callable.
	// Returns false once the strategy is consumed (one-shot semantics)
	// OR once the strategy detects an existing admin (via the
	// AdminExistenceProbe). The HTTP handler maps !Available to 410
	// Gone before doing any token validation, so probing for "is there
	// a bootstrap path open" is safe.
	Available(ctx context.Context) (bool, error)

	// Validate consumes the credential and returns nil when the caller
	// is permitted to mint the first admin. The strategy MUST atomic-
	// flip its consumed state on first successful Validate so a
	// concurrent racing call gets ErrDisabled. Returning a non-nil
	// error MUST NOT mark the strategy consumed; the operator can
	// retry with the correct credential.
	Validate(ctx context.Context, token string) error
}

// AdminExistenceProbe is the callback the EnvTokenStrategy uses to ask
// the actor-role repository whether any actor holds r-admin. Lives at
// this package boundary so the strategy doesn't import internal/repository
// (would create a cycle: bootstrap -> repository -> postgres -> bootstrap
// when the postgres adapter is wired).
type AdminExistenceProbe func(ctx context.Context) (bool, error)

// EnvTokenStrategy is the env-var-token Bundle 1 implementation. The
// operator sets CERTCTL_BOOTSTRAP_TOKEN, the server boots with this
// strategy, the first valid Validate call atomically flips the
// `consumed` flag and the next call returns ErrDisabled.
//
// The token comparison is crypto/subtle.ConstantTimeCompare so timing
// attacks can't leak the token byte-by-byte. The token itself never
// leaves this package: the strategy holds it in memory, the handler
// receives only error sentinels, the audit row records the event but
// not the token value.
type EnvTokenStrategy struct {
	token       string              // set once at construction; never mutated
	probe       AdminExistenceProbe // optional; nil = skip the existence probe
	mu          sync.Mutex          // guards consumed
	consumed    bool                // flipped to true after first successful Validate
	tokenLength int                 // cached for early-reject fast path
}

// NewEnvTokenStrategy constructs the env-var-token strategy. token must
// be the raw value of CERTCTL_BOOTSTRAP_TOKEN. probe is optional; when
// non-nil it gates Available + Validate on "no admin exists yet" so the
// caller can't bootstrap a second admin after the fleet has stabilized.
//
// When token is empty the returned strategy is born consumed —
// Available returns false, Validate returns ErrDisabled. This matches
// the boot-path contract that an unset env var disables the endpoint.
func NewEnvTokenStrategy(token string, probe AdminExistenceProbe) *EnvTokenStrategy {
	s := &EnvTokenStrategy{
		token:       token,
		probe:       probe,
		tokenLength: len(token),
	}
	if token == "" {
		s.consumed = true
	}
	return s
}

// Available implements Strategy.
func (s *EnvTokenStrategy) Available(ctx context.Context) (bool, error) {
	s.mu.Lock()
	consumed := s.consumed
	s.mu.Unlock()
	if consumed {
		return false, nil
	}
	if s.probe != nil {
		exists, err := s.probe(ctx)
		if err != nil {
			return false, err
		}
		if exists {
			return false, nil
		}
	}
	return true, nil
}

// Validate implements Strategy.
func (s *EnvTokenStrategy) Validate(ctx context.Context, token string) error {
	// Fast-path: if the strategy is disabled, return Disabled before
	// doing any constant-time compare. The state flip below acquires
	// the same mutex so this read is safe.
	s.mu.Lock()
	if s.consumed {
		s.mu.Unlock()
		return ErrDisabled
	}
	// Refuse zero-length tokens up front. ConstantTimeCompare returns
	// 1 when both inputs are empty, which would otherwise produce a
	// permanent backdoor on misconfigured deployments where token=""
	// at construction; NewEnvTokenStrategy already covers that, but
	// belt-and-braces here in case a future caller passes the strategy
	// raw.
	if s.tokenLength == 0 || len(token) == 0 {
		s.mu.Unlock()
		return ErrInvalidToken
	}
	// Constant-time compare. Length-pad implicit: ConstantTimeCompare
	// returns 0 when lengths differ (and runs in constant time
	// relative to the shorter length).
	if subtle.ConstantTimeCompare([]byte(s.token), []byte(token)) != 1 {
		s.mu.Unlock()
		return ErrInvalidToken
	}
	// External probe: respect the "admin already exists" gate even
	// after a valid token was supplied. This closes the race where a
	// fleet first-admin lands during the gap between Available and
	// Validate.
	if s.probe != nil {
		// Drop the lock for the probe — repo calls may be slow and
		// holding the mutex through I/O would serialize every
		// concurrent bootstrap attempt. Re-acquire after.
		s.mu.Unlock()
		exists, err := s.probe(ctx)
		if err != nil {
			return err
		}
		if exists {
			return ErrDisabled
		}
		s.mu.Lock()
		// Re-check consumed because a concurrent caller might have
		// flipped it while we were probing.
		if s.consumed {
			s.mu.Unlock()
			return ErrDisabled
		}
	}
	s.consumed = true
	s.mu.Unlock()
	return nil
}

// IsConsumed reports whether the strategy has already been used. Test
// helper; production callers should use Available which also runs the
// admin-existence probe.
func (s *EnvTokenStrategy) IsConsumed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.consumed
}
