package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/auth/session"
	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// =============================================================================
// Bundle 2 Phase 13 — PreLoginAdapter unit-test backfill.
//
// Phase 5 shipped the production-side PreLoginStore (PreLoginAdapter
// in prelogin.go) without dedicated unit tests; service_test.go covers
// HandleAuthRequest + HandleCallback against a stub PreLoginStore but
// the Adapter itself was 0% covered, dragging the package below the
// 90% floor. This file backfills:
//
//   - Constructor + test-helper happy path.
//   - CreatePreLogin: GetActive failure / DecryptKeyMaterial failure /
//     RNG failure / repo.Create failure / happy path.
//   - LookupAndConsume: ParseCookieValue failure / unknown signing-key
//     id / decrypt failure / HMAC mismatch / repo not-found / repo
//     expired / repo other-error / happy path.
//
// Pattern mirrors service_test.go's stub-driven design.
// =============================================================================

// stubPreLoginRepo is an in-memory repository.PreLoginRepository.
type stubPreLoginRepo struct {
	rows         map[string]*repository.PreLoginSession
	createErr    error
	lookupErr    error // when set, LookupAndConsume returns this error
	wrappedErr   error // when set, LookupAndConsume returns this error WITHOUT mapping (tests the "other repo error" branch)
	createCount  int
	lookupCount  int
	gcCount      int
	expireOnNext bool // when true, the next LookupAndConsume returns ErrPreLoginExpired
}

func newStubPreLoginRepo() *stubPreLoginRepo {
	return &stubPreLoginRepo{rows: make(map[string]*repository.PreLoginSession)}
}

func (s *stubPreLoginRepo) Create(_ context.Context, p *repository.PreLoginSession) error {
	s.createCount++
	if s.createErr != nil {
		return s.createErr
	}
	cp := *p
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	if cp.AbsoluteExpiresAt.IsZero() {
		cp.AbsoluteExpiresAt = time.Now().Add(10 * time.Minute).UTC()
	}
	s.rows[p.ID] = &cp
	return nil
}

func (s *stubPreLoginRepo) LookupAndConsume(_ context.Context, id string) (*repository.PreLoginSession, error) {
	s.lookupCount++
	if s.wrappedErr != nil {
		return nil, s.wrappedErr
	}
	if s.lookupErr != nil {
		return nil, s.lookupErr
	}
	if s.expireOnNext {
		s.expireOnNext = false
		delete(s.rows, id)
		return nil, repository.ErrPreLoginExpired
	}
	row, ok := s.rows[id]
	if !ok {
		return nil, repository.ErrPreLoginNotFound
	}
	delete(s.rows, id)
	return row, nil
}

func (s *stubPreLoginRepo) GarbageCollectExpired(_ context.Context) (int, error) {
	s.gcCount++
	return 0, nil
}

// stubSigningKeyLookup is an in-memory SigningKeyLookup.
type stubSigningKeyLookup struct {
	active    *sessiondomain.SessionSigningKey
	byID      map[string]*sessiondomain.SessionSigningKey
	getActErr error
	getErr    error // when set, Get returns this for any id
}

func newStubSigningKeyLookup(active *sessiondomain.SessionSigningKey) *stubSigningKeyLookup {
	m := map[string]*sessiondomain.SessionSigningKey{}
	if active != nil {
		m[active.ID] = active
	}
	return &stubSigningKeyLookup{active: active, byID: m}
}

func (s *stubSigningKeyLookup) GetActive(_ context.Context, _ string) (*sessiondomain.SessionSigningKey, error) {
	if s.getActErr != nil {
		return nil, s.getActErr
	}
	return s.active, nil
}

func (s *stubSigningKeyLookup) Get(_ context.Context, id string) (*sessiondomain.SessionSigningKey, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	k, ok := s.byID[id]
	if !ok {
		return nil, errors.New("signing key not found")
	}
	return k, nil
}

// activeKeyForTest mints a SessionSigningKey with KeyMaterialEncrypted
// set to plaintext bytes (DecryptKeyMaterial round-trips when the
// passphrase is empty — internal/crypto.EncryptIfKeySet's empty-key
// passthrough). 32 bytes of HMAC key material is what production uses.
func activeKeyForTest(t *testing.T, id string) *sessiondomain.SessionSigningKey {
	t.Helper()
	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = byte(i + 1)
	}
	return &sessiondomain.SessionSigningKey{
		ID:                   id,
		TenantID:             "t-default",
		KeyMaterialEncrypted: plaintext, // empty-passphrase passthrough
		CreatedAt:            time.Now().UTC(),
	}
}

// ---------------------------------------------------------------------------
// Constructor + test helper
// ---------------------------------------------------------------------------

func TestPreLoginAdapter_NewAdapterRoundTrip(t *testing.T) {
	repo := newStubPreLoginRepo()
	keys := newStubSigningKeyLookup(activeKeyForTest(t, "sk-1"))
	a := NewPreLoginAdapter(repo, keys, "t-default", "")
	if a == nil {
		t.Fatal("NewPreLoginAdapter returned nil")
	}
	if a.tenantID != "t-default" {
		t.Errorf("tenantID = %q, want t-default", a.tenantID)
	}
	if a.encryptionKey != "" {
		t.Errorf("encryptionKey = %q, want empty", a.encryptionKey)
	}
	if a.readRand == nil {
		t.Error("readRand must default to crypto/rand.Read")
	}
}

func TestPreLoginAdapter_SetRandReaderForTest(t *testing.T) {
	repo := newStubPreLoginRepo()
	keys := newStubSigningKeyLookup(activeKeyForTest(t, "sk-1"))
	a := NewPreLoginAdapter(repo, keys, "t-default", "")
	called := 0
	a.SetRandReaderForTest(func(b []byte) (int, error) {
		called++
		for i := range b {
			b[i] = 0xAA
		}
		return len(b), nil
	})
	id, err := a.newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	if !strings.HasPrefix(id, "pl-") {
		t.Errorf("id = %q, want pl- prefix", id)
	}
	if called != 1 {
		t.Errorf("readRand called %d times, want 1", called)
	}
}

// ---------------------------------------------------------------------------
// CreatePreLogin error paths
// ---------------------------------------------------------------------------

func TestPreLoginAdapter_CreatePreLogin_GetActiveFailure(t *testing.T) {
	repo := newStubPreLoginRepo()
	keys := newStubSigningKeyLookup(nil)
	keys.getActErr = errors.New("postgres unavailable")
	a := NewPreLoginAdapter(repo, keys, "t-default", "")
	_, _, err := a.CreatePreLogin(context.Background(), "op-x", "s", "n", "v", "", "")
	if err == nil || !strings.Contains(err.Error(), "get active signing key") {
		t.Errorf("err = %v, want wrapped 'get active signing key'", err)
	}
}

func TestPreLoginAdapter_CreatePreLogin_DecryptFailure(t *testing.T) {
	// Set a non-empty encryptionKey while the signing key holds raw
	// (non-v3-blob) bytes. DecryptKeyMaterial then fails the AEAD step.
	repo := newStubPreLoginRepo()
	key := activeKeyForTest(t, "sk-1")
	key.KeyMaterialEncrypted = []byte{0x03, 0x00, 0x01, 0x02} // bogus v3 blob
	keys := newStubSigningKeyLookup(key)
	a := NewPreLoginAdapter(repo, keys, "t-default", "passphrase-set")
	_, _, err := a.CreatePreLogin(context.Background(), "op-x", "s", "n", "v", "", "")
	if err == nil || !strings.Contains(err.Error(), "decrypt active key") {
		t.Errorf("err = %v, want wrapped 'decrypt active key'", err)
	}
}

func TestPreLoginAdapter_CreatePreLogin_RNGFailure(t *testing.T) {
	repo := newStubPreLoginRepo()
	keys := newStubSigningKeyLookup(activeKeyForTest(t, "sk-1"))
	a := NewPreLoginAdapter(repo, keys, "t-default", "")
	a.SetRandReaderForTest(func(_ []byte) (int, error) {
		return 0, errors.New("RNG drained")
	})
	_, _, err := a.CreatePreLogin(context.Background(), "op-x", "s", "n", "v", "", "")
	if err == nil || !strings.Contains(err.Error(), "generate id") {
		t.Errorf("err = %v, want wrapped 'generate id'", err)
	}
}

func TestPreLoginAdapter_CreatePreLogin_PersistFailure(t *testing.T) {
	repo := newStubPreLoginRepo()
	repo.createErr = errors.New("FK violation")
	keys := newStubSigningKeyLookup(activeKeyForTest(t, "sk-1"))
	a := NewPreLoginAdapter(repo, keys, "t-default", "")
	_, _, err := a.CreatePreLogin(context.Background(), "op-x", "s", "n", "v", "", "")
	if err == nil || !strings.Contains(err.Error(), "persist row") {
		t.Errorf("err = %v, want wrapped 'persist row'", err)
	}
	if repo.createCount != 1 {
		t.Errorf("createCount = %d, want 1", repo.createCount)
	}
}

func TestPreLoginAdapter_CreatePreLogin_HappyPath(t *testing.T) {
	repo := newStubPreLoginRepo()
	keys := newStubSigningKeyLookup(activeKeyForTest(t, "sk-1"))
	a := NewPreLoginAdapter(repo, keys, "t-default", "")
	cookie, sid, err := a.CreatePreLogin(context.Background(), "op-x", "the-state", "the-nonce", "verifier-xxx", "", "")
	if err != nil {
		t.Fatalf("CreatePreLogin: %v", err)
	}
	if !strings.HasPrefix(cookie, "v1.pl-") {
		t.Errorf("cookie = %q, want prefix v1.pl-", cookie)
	}
	if !strings.HasPrefix(sid, "pl-") {
		t.Errorf("sid = %q, want pl- prefix", sid)
	}
	if got := repo.rows[sid]; got == nil {
		t.Fatal("row not persisted")
	} else {
		if got.OIDCProviderID != "op-x" {
			t.Errorf("OIDCProviderID = %q, want op-x", got.OIDCProviderID)
		}
		if got.State != "the-state" || got.Nonce != "the-nonce" || got.PKCEVerifier != "verifier-xxx" {
			t.Errorf("row triple = %v", got)
		}
		if got.SigningKeyID != "sk-1" {
			t.Errorf("SigningKeyID = %q, want sk-1", got.SigningKeyID)
		}
	}
}

// ---------------------------------------------------------------------------
// LookupAndConsume error paths
// ---------------------------------------------------------------------------

func TestPreLoginAdapter_LookupAndConsume_MalformedCookie(t *testing.T) {
	a := NewPreLoginAdapter(newStubPreLoginRepo(),
		newStubSigningKeyLookup(activeKeyForTest(t, "sk-1")), "t-default", "")
	_, _, _, _, _, _, err := a.LookupAndConsume(context.Background(), "definitely-not-a-cookie")
	if !errors.Is(err, ErrPreLoginNotFound) {
		t.Errorf("err = %v, want ErrPreLoginNotFound", err)
	}
}

func TestPreLoginAdapter_LookupAndConsume_UnknownSigningKey(t *testing.T) {
	// Create a real cookie with sk-1, then point the adapter at a key
	// store that doesn't have it.
	repo := newStubPreLoginRepo()
	createKey := activeKeyForTest(t, "sk-1")
	createKeys := newStubSigningKeyLookup(createKey)
	createAdapter := NewPreLoginAdapter(repo, createKeys, "t-default", "")
	cookie, _, err := createAdapter.CreatePreLogin(context.Background(), "op-x", "s", "n", "v", "", "")
	if err != nil {
		t.Fatalf("CreatePreLogin: %v", err)
	}

	emptyKeys := newStubSigningKeyLookup(nil) // sk-1 is not in this lookup
	consumeAdapter := NewPreLoginAdapter(repo, emptyKeys, "t-default", "")
	_, _, _, _, _, _, err = consumeAdapter.LookupAndConsume(context.Background(), cookie)
	if !errors.Is(err, ErrPreLoginNotFound) {
		t.Errorf("err = %v, want ErrPreLoginNotFound (unknown signing key)", err)
	}
}

func TestPreLoginAdapter_LookupAndConsume_DecryptKeyFailure(t *testing.T) {
	// Build a cookie under a key whose plaintext we know, then swap the
	// stored key material to a bogus v3 blob so DecryptKeyMaterial fails.
	repo := newStubPreLoginRepo()
	createKey := activeKeyForTest(t, "sk-1")
	createKeys := newStubSigningKeyLookup(createKey)
	createAdapter := NewPreLoginAdapter(repo, createKeys, "t-default", "")
	cookie, _, err := createAdapter.CreatePreLogin(context.Background(), "op-x", "s", "n", "v", "", "")
	if err != nil {
		t.Fatalf("CreatePreLogin: %v", err)
	}

	// Now swap to a passphrase-set adapter where the key material is bogus.
	corruptedKey := *createKey
	corruptedKey.KeyMaterialEncrypted = []byte{0x03, 0x00, 0x01, 0x02} // bogus v3
	corruptedKeys := newStubSigningKeyLookup(&corruptedKey)
	consumeAdapter := NewPreLoginAdapter(repo, corruptedKeys, "t-default", "passphrase-set")
	_, _, _, _, _, _, err = consumeAdapter.LookupAndConsume(context.Background(), cookie)
	if !errors.Is(err, ErrPreLoginNotFound) {
		t.Errorf("err = %v, want ErrPreLoginNotFound (decrypt failure → uniform sentinel)", err)
	}
}

func TestPreLoginAdapter_LookupAndConsume_HMACMismatch(t *testing.T) {
	// Build a real cookie under one key material; on consume, swap the
	// signing key's material to a different plaintext so HMAC doesn't
	// match.
	repo := newStubPreLoginRepo()
	createKey := activeKeyForTest(t, "sk-1")
	createKeys := newStubSigningKeyLookup(createKey)
	createAdapter := NewPreLoginAdapter(repo, createKeys, "t-default", "")
	cookie, _, err := createAdapter.CreatePreLogin(context.Background(), "op-x", "s", "n", "v", "", "")
	if err != nil {
		t.Fatalf("CreatePreLogin: %v", err)
	}

	swapped := *createKey
	swappedMaterial := make([]byte, 32)
	for i := range swappedMaterial {
		swappedMaterial[i] = byte(0xFF - i)
	}
	swapped.KeyMaterialEncrypted = swappedMaterial
	swappedKeys := newStubSigningKeyLookup(&swapped)
	consumeAdapter := NewPreLoginAdapter(repo, swappedKeys, "t-default", "")
	_, _, _, _, _, _, err = consumeAdapter.LookupAndConsume(context.Background(), cookie)
	if !errors.Is(err, ErrPreLoginNotFound) {
		t.Errorf("err = %v, want ErrPreLoginNotFound (HMAC mismatch)", err)
	}
}

func TestPreLoginAdapter_LookupAndConsume_RepoNotFound(t *testing.T) {
	// Build a valid cookie + signing key, but never persist the row.
	// The HMAC check passes, the repo lookup returns NotFound.
	repo := newStubPreLoginRepo()
	keys := newStubSigningKeyLookup(activeKeyForTest(t, "sk-1"))
	a := NewPreLoginAdapter(repo, keys, "t-default", "")

	// Build the cookie manually using the same shape CreatePreLogin would,
	// without going through Create (so the row is absent from the repo).
	hmacKey, _ := session.DecryptKeyMaterial(keys.active.KeyMaterialEncrypted, "")
	plID := "pl-orphan-id"
	cookie := session.SignCookieValue(plID, keys.active.ID, hmacKey)

	_, _, _, _, _, _, err := a.LookupAndConsume(context.Background(), cookie)
	if !errors.Is(err, ErrPreLoginNotFound) {
		t.Errorf("err = %v, want ErrPreLoginNotFound (repo miss)", err)
	}
}

func TestPreLoginAdapter_LookupAndConsume_RepoExpired(t *testing.T) {
	repo := newStubPreLoginRepo()
	keys := newStubSigningKeyLookup(activeKeyForTest(t, "sk-1"))
	a := NewPreLoginAdapter(repo, keys, "t-default", "")
	cookie, _, err := a.CreatePreLogin(context.Background(), "op-x", "s", "n", "v", "", "")
	if err != nil {
		t.Fatalf("CreatePreLogin: %v", err)
	}
	repo.expireOnNext = true
	_, _, _, _, _, _, err = a.LookupAndConsume(context.Background(), cookie)
	if !errors.Is(err, ErrPreLoginNotFound) {
		t.Errorf("err = %v, want ErrPreLoginNotFound (expired → uniform sentinel)", err)
	}
}

func TestPreLoginAdapter_LookupAndConsume_RepoOtherError(t *testing.T) {
	repo := newStubPreLoginRepo()
	keys := newStubSigningKeyLookup(activeKeyForTest(t, "sk-1"))
	a := NewPreLoginAdapter(repo, keys, "t-default", "")
	cookie, _, err := a.CreatePreLogin(context.Background(), "op-x", "s", "n", "v", "", "")
	if err != nil {
		t.Fatalf("CreatePreLogin: %v", err)
	}
	// Inject a non-NotFound, non-Expired error to exercise the wrap branch.
	repo.wrappedErr = errors.New("postgres dropped connection")
	_, _, _, _, _, _, err = a.LookupAndConsume(context.Background(), cookie)
	if errors.Is(err, ErrPreLoginNotFound) {
		t.Error("err must NOT be ErrPreLoginNotFound for non-sentinel repo failure")
	}
	if err == nil || !strings.Contains(err.Error(), "lookup_and_consume") {
		t.Errorf("err = %v, want wrapped 'lookup_and_consume'", err)
	}
}

func TestPreLoginAdapter_LookupAndConsume_HappyPath(t *testing.T) {
	repo := newStubPreLoginRepo()
	keys := newStubSigningKeyLookup(activeKeyForTest(t, "sk-1"))
	a := NewPreLoginAdapter(repo, keys, "t-default", "")
	cookie, _, err := a.CreatePreLogin(context.Background(), "op-okta", "the-state-42", "the-nonce-42", "the-verifier-42", "", "")
	if err != nil {
		t.Fatalf("CreatePreLogin: %v", err)
	}
	pid, st, nn, vf, _, _, err := a.LookupAndConsume(context.Background(), cookie)
	if err != nil {
		t.Fatalf("LookupAndConsume: %v", err)
	}
	if pid != "op-okta" || st != "the-state-42" || nn != "the-nonce-42" || vf != "the-verifier-42" {
		t.Errorf("triple = (%q,%q,%q,%q), want (op-okta, the-state-42, the-nonce-42, the-verifier-42)", pid, st, nn, vf)
	}

	// Single-use: second consume returns ErrPreLoginNotFound.
	_, _, _, _, _, _, err = a.LookupAndConsume(context.Background(), cookie)
	if !errors.Is(err, ErrPreLoginNotFound) {
		t.Errorf("second consume err = %v, want ErrPreLoginNotFound (single-use violated)", err)
	}
}
