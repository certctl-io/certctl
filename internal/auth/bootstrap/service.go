package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
)

// actorNameRe matches the operator-supplied admin-key name. Constraints:
// 3-64 chars, lowercase alphanumeric + hyphen + underscore. Strict
// charset prevents audit-attribution shenanigans (control characters,
// log-injection sequences, mixed-case look-alikes for an existing
// admin actor's name).
var actorNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,63}$`)

// APIKeyMinter is the slice of APIKeyRepository the bootstrap service
// needs. Pulled out as a small interface so the service can be unit-
// tested with an in-memory fake.
type APIKeyMinter interface {
	Create(ctx context.Context, key *authdomain.APIKey) error
	GetByName(ctx context.Context, name string) (*authdomain.APIKey, error)
}

// RoleGranter is the slice of ActorRoleRepository the bootstrap
// service needs.
type RoleGranter interface {
	Grant(ctx context.Context, ar *authdomain.ActorRole) error
}

// AuditRecorder is the slice of AuditService the bootstrap service
// needs. Phase 8 ships RecordEventWithCategory which classifies the
// row's event_category column directly; the bootstrap path always
// emits with category=auth.
type AuditRecorder interface {
	RecordEventWithCategory(ctx context.Context, actor string, actorType domain.ActorType, action, eventCategory, resourceType, resourceID string, details map[string]interface{}) error
}

// KeyStoreAdder is the runtime hook the bootstrap service uses to
// register the just-minted key with the auth middleware so the next
// request authenticates without a process restart. The HTTP-layer
// auth middleware exposes this via internal/auth.MutableKeyStore.
type KeyStoreAdder interface {
	AddHashed(name, hashHex string, admin bool)
}

// Service ties the bootstrap Strategy to the persistence layer. Kept
// separate from the HTTP handler so unit tests can drive it without
// httptest, and so the same service can back a future
// `certctl auth bootstrap` CLI command.
type Service struct {
	strategy   Strategy
	keys       APIKeyMinter
	roles      RoleGranter
	audit      AuditRecorder
	keyStore   KeyStoreAdder
	hashAPIKey func(string) string // injected so the auth package's HashAPIKey doesn't import this package
}

// NewService constructs a bootstrap Service.
//
// hashAPIKey takes the plaintext key and returns the SHA-256 hex used
// by the auth middleware's keystore lookup. Pass internal/auth.HashAPIKey
// at the production wire site; tests can pass a deterministic hash for
// matching against MutableKeyStore lookups.
//
// keyStore is optional. Production wires the same MutableKeyStore the
// auth middleware reads from so the minted key authenticates the next
// request; when nil the bootstrap still persists the key to the DB
// but the operator must restart to pick it up via the boot loader.
func NewService(strategy Strategy, keys APIKeyMinter, roles RoleGranter, audit AuditRecorder, keyStore KeyStoreAdder, hashAPIKey func(string) string) *Service {
	return &Service{
		strategy:   strategy,
		keys:       keys,
		roles:      roles,
		audit:      audit,
		keyStore:   keyStore,
		hashAPIKey: hashAPIKey,
	}
}

// MintResult is the success payload returned to the HTTP handler. Key
// is the plaintext value the operator must capture before the response
// is dropped — the server holds it for ~milliseconds and never logs it.
type MintResult struct {
	APIKey   *authdomain.APIKey
	KeyValue string
}

// Available reports whether the bootstrap endpoint is currently
// callable. Returns the strategy's verdict plus a sentinel
// (ErrDisabled) when not. The HTTP handler maps the sentinel to 410
// Gone before reading any token from the request body so a probing
// attacker can't distinguish "no token configured" from "wrong
// token".
func (s *Service) Available(ctx context.Context) (bool, error) {
	if s == nil || s.strategy == nil {
		return false, ErrDisabled
	}
	return s.strategy.Available(ctx)
}

// ValidateAndMint consumes the strategy's credential and persists the
// first admin API key. The response carries the plaintext key value
// once; the operator MUST capture it before the response goes out the
// wire. Subsequent calls return ErrDisabled (one-shot semantics).
//
// Side effects:
//  1. Strategy.Validate atomically flips its consumed state.
//  2. A new row is written to api_keys (id, name, sha256(key), admin=true).
//  3. A new row is written to actor_roles (actor=name, role=r-admin).
//  4. The MutableKeyStore (if wired) gains a runtime entry so the next
//     request authenticates without a restart.
//  5. An audit event records the bootstrap consumption with
//     event_category=auth, action=bootstrap.consume.
//
// The plaintext key is NEVER logged. It exists in three places:
//   - the random buffer this function generates,
//   - the MintResult.KeyValue field (the handler writes it to the
//     response then discards),
//   - the HTTP response body itself.
//
// If the persistence calls fail AFTER the strategy is consumed, the
// service does NOT roll back the strategy state — by design. A failed
// ValidateAndMint call leaves bootstrap closed; the operator must
// recover via DB seeding (insert into actor_roles directly) rather
// than retry. The alternative (retry) opens a window for a successful
// validate-then-fail sequence to mint two admin keys on retry, which
// silently widens the trust radius.
func (s *Service) ValidateAndMint(ctx context.Context, token, actorName string) (*MintResult, error) {
	if s == nil || s.strategy == nil || s.keys == nil || s.roles == nil {
		return nil, ErrDisabled
	}
	if !actorNameRe.MatchString(actorName) {
		return nil, ErrInvalidActorName
	}
	if err := s.strategy.Validate(ctx, token); err != nil {
		return nil, err
	}
	// Strategy is now consumed; if anything below fails the operator
	// has to recover via DB. See the docstring on MintFirstAdmin.
	keyValue, err := generateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("bootstrap: random key generation: %w", err)
	}
	keyHash := s.hashAPIKey(keyValue)
	now := time.Now().UTC()
	apiKey := &authdomain.APIKey{
		Name:      actorName,
		KeyHash:   keyHash,
		TenantID:  authdomain.DefaultTenantID,
		Admin:     true,
		CreatedBy: "bootstrap",
		CreatedAt: now,
	}
	if err := s.keys.Create(ctx, apiKey); err != nil {
		return nil, fmt.Errorf("bootstrap: persist key: %w", err)
	}
	if err := s.roles.Grant(ctx, &authdomain.ActorRole{
		ActorID:   actorName,
		ActorType: authdomain.ActorTypeValue(domain.ActorTypeAPIKey),
		RoleID:    authdomain.RoleIDAdmin,
		TenantID:  authdomain.DefaultTenantID,
		GrantedBy: "bootstrap",
	}); err != nil {
		return nil, fmt.Errorf("bootstrap: grant admin role: %w", err)
	}
	if s.keyStore != nil {
		s.keyStore.AddHashed(actorName, keyHash, true)
	}
	if s.audit != nil {
		// Phase 8 promotes event_category to a first-class column.
		// Bootstrap is unambiguously an auth event. Errors from the
		// audit write are intentionally ignored: the bootstrap mint
		// succeeded and the consequent audit-row miss is preferable
		// to surfacing a 500 to the operator after the admin-key
		// already landed in the DB. The audit-row gap is detectable
		// in monitoring (every successful mint should have a paired
		// bootstrap.consume row).
		// Audit 2026-05-10 HIGH-6 partial closure — emit WARN on audit-
		// write failure so the silent-row-miss is observable. The
		// transactional-leg WithinTx refactor is a v3 follow-on.
		if err := s.audit.RecordEventWithCategory(ctx, "bootstrap-token", domain.ActorTypeSystem,
			"bootstrap.consume", domain.EventCategoryAuth, "api_key", apiKey.ID,
			map[string]interface{}{
				"actor_name": actorName,
				"role_id":    authdomain.RoleIDAdmin,
			}); err != nil {
			slog.WarnContext(ctx, "bootstrap.consume audit write failed (admin key minted; audit row may be missing)",
				"actor_name", actorName,
				"api_key_id", apiKey.ID,
				"err", err)
		}
	}
	return &MintResult{APIKey: apiKey, KeyValue: keyValue}, nil
}

// generateAPIKey returns 32 random bytes hex-encoded (64-char output).
// Same entropy budget as `openssl rand -hex 32` which the agent
// bootstrap docs recommend.
func generateAPIKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
