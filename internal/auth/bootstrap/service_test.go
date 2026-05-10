package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
)

type fakeMinter struct {
	created   []*authdomain.APIKey
	createErr error
}

func (f *fakeMinter) Create(_ context.Context, k *authdomain.APIKey) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, k)
	return nil
}
func (f *fakeMinter) GetByName(_ context.Context, _ string) (*authdomain.APIKey, error) {
	return nil, errors.New("not implemented for these tests")
}

type fakeGranter struct {
	grants []*authdomain.ActorRole
	err    error
}

func (f *fakeGranter) Grant(_ context.Context, ar *authdomain.ActorRole) error {
	f.grants = append(f.grants, ar)
	return f.err
}

type fakeAudit struct {
	calls    []map[string]interface{}
	category string
}

func (f *fakeAudit) RecordEventWithCategory(_ context.Context, _ string, _ domain.ActorType, _ string, eventCategory, _ string, _ string, details map[string]interface{}) error {
	f.calls = append(f.calls, details)
	f.category = eventCategory
	return nil
}

type fakeKeyStore struct {
	added []addedEntry
}

type addedEntry struct {
	name  string
	hash  string
	admin bool
}

func (f *fakeKeyStore) AddHashed(name, hash string, admin bool) {
	f.added = append(f.added, addedEntry{name: name, hash: hash, admin: admin})
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestService_ValidateAndMint_HappyPath pins the load-bearing flow:
// valid token → strategy consumed → api_keys row created → admin role
// granted → keystore updated → audit row recorded → result carries the
// plaintext key + the persisted APIKey row.
func TestService_ValidateAndMint_HappyPath(t *testing.T) {
	strategy := NewEnvTokenStrategy("the-token", nil)
	minter := &fakeMinter{}
	granter := &fakeGranter{}
	audit := &fakeAudit{}
	store := &fakeKeyStore{}
	svc := NewService(strategy, minter, granter, audit, store, sha)

	result, err := svc.ValidateAndMint(context.Background(), "the-token", "first-admin")
	if err != nil {
		t.Fatalf("ValidateAndMint err = %v", err)
	}
	if result == nil || result.KeyValue == "" {
		t.Fatalf("result.KeyValue empty")
	}
	if len(result.KeyValue) < 32 {
		t.Errorf("KeyValue length = %d, want >= 32 (entropy budget)", len(result.KeyValue))
	}
	if !strategy.IsConsumed() {
		t.Errorf("strategy not consumed after successful mint")
	}
	if len(minter.created) != 1 {
		t.Fatalf("minter.Create call count = %d, want 1", len(minter.created))
	}
	apiKey := minter.created[0]
	if apiKey.Name != "first-admin" || !apiKey.Admin || apiKey.CreatedBy != "bootstrap" {
		t.Errorf("api_key wrong fields: %+v", apiKey)
	}
	if apiKey.KeyHash != sha(result.KeyValue) {
		t.Errorf("KeyHash != sha(KeyValue); persistence shape is wrong")
	}
	if len(granter.grants) != 1 {
		t.Fatalf("granter.Grant call count = %d, want 1", len(granter.grants))
	}
	if granter.grants[0].RoleID != authdomain.RoleIDAdmin {
		t.Errorf("granted role = %q, want %q", granter.grants[0].RoleID, authdomain.RoleIDAdmin)
	}
	if granter.grants[0].ActorID != "first-admin" {
		t.Errorf("granted actor = %q, want first-admin", granter.grants[0].ActorID)
	}
	if granter.grants[0].GrantedBy != "bootstrap" {
		t.Errorf("GrantedBy = %q, want bootstrap", granter.grants[0].GrantedBy)
	}
	if len(store.added) != 1 || store.added[0].name != "first-admin" || !store.added[0].admin {
		t.Errorf("keystore.AddHashed not called with first-admin/admin=true: %+v", store.added)
	}
	if store.added[0].hash != apiKey.KeyHash {
		t.Errorf("keystore hash != api_key hash; runtime auth would fail")
	}
	if len(audit.calls) != 1 {
		t.Fatalf("audit RecordEventWithCategory calls = %d, want 1", len(audit.calls))
	}
	if audit.calls[0]["actor_name"] != "first-admin" {
		t.Errorf("audit details lost actor_name: %+v", audit.calls[0])
	}
	if audit.category != "auth" {
		t.Errorf("audit category = %q, want auth", audit.category)
	}
}

// TestService_ValidateAndMint_RejectsInvalidActorName pins the
// ErrInvalidActorName mapping (HTTP 400). Strict charset prevents
// log-injection / lookalike actor names.
func TestService_ValidateAndMint_RejectsInvalidActorName(t *testing.T) {
	svc := NewService(NewEnvTokenStrategy("t", nil), &fakeMinter{}, &fakeGranter{}, nil, nil, sha)
	cases := []string{
		"",                      // empty
		"AB",                    // too short
		"Has-Caps",              // uppercase rejected
		"contains spaces",       // space rejected
		strings.Repeat("a", 65), // 65 chars > 64 max
		"newline\nsuffix",       // log injection
		"💀-evil",                // non-ASCII
	}
	for _, name := range cases {
		_, err := svc.ValidateAndMint(context.Background(), "t", name)
		if !errors.Is(err, ErrInvalidActorName) {
			t.Errorf("name=%q err = %v, want ErrInvalidActorName", name, err)
		}
	}
}

// TestService_ValidateAndMint_PropagatesStrategyError pins that a
// failed Validate (wrong token / disabled / probe error) propagates
// without persisting anything.
func TestService_ValidateAndMint_PropagatesStrategyError(t *testing.T) {
	strategy := NewEnvTokenStrategy("the-token", nil)
	minter := &fakeMinter{}
	granter := &fakeGranter{}
	store := &fakeKeyStore{}
	svc := NewService(strategy, minter, granter, nil, store, sha)

	_, err := svc.ValidateAndMint(context.Background(), "wrong-token", "first-admin")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
	if len(minter.created) != 0 || len(granter.grants) != 0 || len(store.added) != 0 {
		t.Errorf("persistence side effects fired despite Validate failure: minter=%d grants=%d keystore=%d", len(minter.created), len(granter.grants), len(store.added))
	}
}

// TestService_ValidateAndMint_NilDepsReturnDisabled exercises the
// no-strategy / no-repo guard. Returns ErrDisabled (handler maps to
// 410). Belt-and-braces for partially-wired test or future call sites.
func TestService_ValidateAndMint_NilDepsReturnDisabled(t *testing.T) {
	cases := []struct {
		name string
		svc  *Service
	}{
		{"nil service", nil},
		{"nil strategy", NewService(nil, &fakeMinter{}, &fakeGranter{}, nil, nil, sha)},
		{"nil minter", NewService(NewEnvTokenStrategy("t", nil), nil, &fakeGranter{}, nil, nil, sha)},
		{"nil granter", NewService(NewEnvTokenStrategy("t", nil), &fakeMinter{}, nil, nil, nil, sha)},
	}
	for _, tc := range cases {
		_, err := tc.svc.ValidateAndMint(context.Background(), "t", "first-admin")
		if !errors.Is(err, ErrDisabled) {
			t.Errorf("%s: err = %v, want ErrDisabled", tc.name, err)
		}
	}
}

// TestService_GenerateAPIKey_HighEntropy pins the generated key shape:
// 64 hex chars (32 random bytes). Belt-and-braces against future
// refactors that might shrink the entropy budget.
func TestService_GenerateAPIKey_HighEntropy(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		k, err := generateAPIKey()
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if len(k) != 64 {
			t.Errorf("len = %d, want 64", len(k))
		}
		if seen[k] {
			t.Errorf("key collision in 100 iters — entropy budget regressed")
		}
		seen[k] = true
	}
}
