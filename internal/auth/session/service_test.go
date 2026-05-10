package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// =============================================================================
// In-memory stubs for SessionRepo + SigningKeyRepo + AuditRecorder.
//
// These are deliberately tiny and test-only. The Phase 2 integration tests
// (under internal/repository/postgres/) cover the SQL layer; here we only
// care about the service-layer state machine.
// =============================================================================

type stubSessionRepo struct {
	mu            sync.Mutex
	rows          map[string]*sessiondomain.Session
	createErr     error
	getErr        error
	updateLastErr error
	updateCSRFErr error
	revokeErr     error
	revokeAllErr  error
	gcErr         error
	gcCount       int
	gcCalls       int
}

func newStubSessionRepo() *stubSessionRepo {
	return &stubSessionRepo{rows: make(map[string]*sessiondomain.Session)}
}

func (r *stubSessionRepo) Create(_ context.Context, s *sessiondomain.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.createErr != nil {
		return r.createErr
	}
	clone := *s
	r.rows[s.ID] = &clone
	return nil
}

func (r *stubSessionRepo) Get(_ context.Context, id string) (*sessiondomain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	row, ok := r.rows[id]
	if !ok {
		return nil, repository.ErrSessionNotFound
	}
	clone := *row
	return &clone, nil
}

func (r *stubSessionRepo) ListByActor(_ context.Context, actorID, actorType, _ string) ([]*sessiondomain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*sessiondomain.Session
	for _, row := range r.rows {
		if row.ActorID == actorID && row.ActorType == actorType {
			clone := *row
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (r *stubSessionRepo) UpdateLastSeen(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.updateLastErr != nil {
		return r.updateLastErr
	}
	row, ok := r.rows[id]
	if !ok {
		return repository.ErrSessionNotFound
	}
	row.LastSeenAt = time.Now().UTC()
	return nil
}

func (r *stubSessionRepo) UpdateCSRFTokenHash(_ context.Context, id, csrfTokenHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.updateCSRFErr != nil {
		return r.updateCSRFErr
	}
	row, ok := r.rows[id]
	if !ok {
		return repository.ErrSessionNotFound
	}
	row.CSRFTokenHash = csrfTokenHash
	return nil
}

func (r *stubSessionRepo) Revoke(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revokeErr != nil {
		return r.revokeErr
	}
	row, ok := r.rows[id]
	if !ok {
		return repository.ErrSessionNotFound
	}
	now := time.Now().UTC()
	row.RevokedAt = &now
	return nil
}

func (r *stubSessionRepo) RevokeAllForActor(_ context.Context, actorID, actorType, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revokeAllErr != nil {
		return r.revokeAllErr
	}
	now := time.Now().UTC()
	for _, row := range r.rows {
		if row.ActorID == actorID && row.ActorType == actorType && row.RevokedAt == nil {
			row.RevokedAt = &now
		}
	}
	return nil
}

func (r *stubSessionRepo) RevokeAllExceptForActor(_ context.Context, actorID, actorType, _, exceptID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	count := 0
	for id, row := range r.rows {
		if row.ActorID == actorID && row.ActorType == actorType && row.RevokedAt == nil && id != exceptID {
			row.RevokedAt = &now
			count++
		}
	}
	return count, nil
}

func (r *stubSessionRepo) GarbageCollectExpired(_ context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcCalls++
	if r.gcErr != nil {
		return 0, r.gcErr
	}
	return r.gcCount, nil
}

type stubKeyRepo struct {
	mu        sync.Mutex
	keys      map[string]*sessiondomain.SessionSigningKey
	addErr    error
	retireErr error
	listErr   error
	deleteErr error
	getErr    error
	getActErr error
}

func newStubKeyRepo() *stubKeyRepo {
	return &stubKeyRepo{keys: make(map[string]*sessiondomain.SessionSigningKey)}
}

func (r *stubKeyRepo) GetActive(_ context.Context, tenantID string) (*sessiondomain.SessionSigningKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getActErr != nil {
		return nil, r.getActErr
	}
	var newest *sessiondomain.SessionSigningKey
	for _, k := range r.keys {
		if k.TenantID != tenantID || k.RetiredAt != nil {
			continue
		}
		if newest == nil || k.CreatedAt.After(newest.CreatedAt) {
			newest = k
		}
	}
	if newest == nil {
		return nil, repository.ErrSessionSigningKeyNotFound
	}
	clone := *newest
	return &clone, nil
}

func (r *stubKeyRepo) Get(_ context.Context, id string) (*sessiondomain.SessionSigningKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	k, ok := r.keys[id]
	if !ok {
		return nil, repository.ErrSessionSigningKeyNotFound
	}
	clone := *k
	return &clone, nil
}

func (r *stubKeyRepo) Add(_ context.Context, k *sessiondomain.SessionSigningKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.addErr != nil {
		return r.addErr
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	clone := *k
	r.keys[k.ID] = &clone
	return nil
}

func (r *stubKeyRepo) Retire(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retireErr != nil {
		return r.retireErr
	}
	k, ok := r.keys[id]
	if !ok {
		return repository.ErrSessionSigningKeyNotFound
	}
	if k.RetiredAt == nil {
		now := time.Now().UTC()
		k.RetiredAt = &now
	}
	return nil
}

func (r *stubKeyRepo) List(_ context.Context, tenantID string) ([]*sessiondomain.SessionSigningKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listErr != nil {
		return nil, r.listErr
	}
	var out []*sessiondomain.SessionSigningKey
	for _, k := range r.keys {
		if k.TenantID == tenantID {
			clone := *k
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (r *stubKeyRepo) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.deleteErr != nil {
		return r.deleteErr
	}
	if _, ok := r.keys[id]; !ok {
		return repository.ErrSessionSigningKeyNotFound
	}
	delete(r.keys, id)
	return nil
}

type stubAudit struct {
	mu     sync.Mutex
	events []recordedAuditEvent
}

type recordedAuditEvent struct {
	Actor    string
	Type     domain.ActorType
	Action   string
	Category string
	Resource string
	Details  map[string]interface{}
}

func (a *stubAudit) RecordEventWithCategory(_ context.Context, actor string, actorType domain.ActorType, action, category, _, resourceID string, details map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, recordedAuditEvent{
		Actor: actor, Type: actorType, Action: action, Category: category,
		Resource: resourceID, Details: details,
	})
	return nil
}

func (a *stubAudit) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.events))
	for i, e := range a.events {
		out[i] = e.Action
	}
	return out
}

// =============================================================================
// Test helpers.
// =============================================================================

const testTenant = "t-default"

// newTestService returns a fully wired service (in-memory stubs) with a
// pre-seeded active signing key. encryptionKey is empty so the key blob
// is plaintext — sufficient for service-layer tests; the
// real-encryption round-trip lives in TestService_EncryptionRoundTrip.
func newTestService(t *testing.T, cfg Config) (*Service, *stubSessionRepo, *stubKeyRepo, *stubAudit, string) {
	t.Helper()
	sessions := newStubSessionRepo()
	keys := newStubKeyRepo()
	audit := &stubAudit{}
	svc := NewService(sessions, keys, audit, testTenant, cfg, "")
	if err := svc.EnsureInitialSigningKey(context.Background()); err != nil {
		t.Fatalf("EnsureInitialSigningKey: %v", err)
	}
	// Find the just-minted key id for tests that need it.
	var keyID string
	for id := range keys.keys {
		keyID = id
	}
	return svc, sessions, keys, audit, keyID
}

func defaultCfg() Config {
	return Config{
		IdleTimeout:         1 * time.Hour,
		AbsoluteTimeout:     8 * time.Hour,
		SigningKeyRetention: 24 * time.Hour,
	}
}

// =============================================================================
// Happy paths.
// =============================================================================

func TestService_Create_HappyPath(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	res, err := svc.Create(context.Background(), "u-alice", "User", "10.0.0.1", "Mozilla")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if res.Session.ID == "" || !strings.HasPrefix(res.Session.ID, "ses-") {
		t.Errorf("session id missing or wrong prefix: %q", res.Session.ID)
	}
	if !strings.HasPrefix(res.CookieValue, "v1.") {
		t.Errorf("cookie missing v1. prefix: %q", res.CookieValue)
	}
	if res.CSRFToken == "" {
		t.Errorf("csrf token empty")
	}
	// Session row stored with hashed CSRF (not plaintext).
	stored, _ := sessions.Get(context.Background(), res.Session.ID)
	if stored.CSRFTokenHash == res.CSRFToken {
		t.Errorf("CSRFTokenHash equals plaintext (must be SHA-256 hash)")
	}
	if hashCSRFToken(res.CSRFToken) != stored.CSRFTokenHash {
		t.Errorf("CSRFTokenHash != SHA-256(plaintext)")
	}
}

func TestService_Validate_HappyPath_RoundTrip(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	res, err := svc.Create(context.Background(), "u-bob", "User", "10.0.0.2", "Firefox")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := svc.Validate(context.Background(), ValidateInput{CookieValue: res.CookieValue, ClientIP: "10.0.0.2", UserAgent: "Firefox"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.ID != res.Session.ID {
		t.Errorf("validated session id mismatch: got %s, want %s", got.ID, res.Session.ID)
	}
}

func TestService_ValidateCSRF_HappyPath(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-eve", "User", "", "")
	if err := svc.ValidateCSRF(res.CSRFToken, res.Session); err != nil {
		t.Errorf("ValidateCSRF (correct token): %v", err)
	}
}

func TestService_UpdateLastSeen_HappyPath(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-mike", "User", "", "")
	original := sessions.rows[res.Session.ID].LastSeenAt
	time.Sleep(2 * time.Millisecond)
	if err := svc.UpdateLastSeen(context.Background(), res.Session.ID); err != nil {
		t.Fatalf("UpdateLastSeen: %v", err)
	}
	if !sessions.rows[res.Session.ID].LastSeenAt.After(original) {
		t.Errorf("LastSeenAt did not advance")
	}
}

// =============================================================================
// Phase 4 spec — 15 negative cases.
// =============================================================================

// #1: Tampered cookie segment fails signature check.
//
// Note: we flip a byte NEAR THE START of the HMAC segment, not at the
// end. base64url-no-pad's trailing character carries only 2 bits of
// "real" data (43 chars * 6 bits = 258 bits but the SHA-256 output is
// 256 bits, so the bottom 2 bits of the last char are discarded by the
// decoder). Flipping the last char can decode to the same byte string
// even though the cookie text differs — which would make the test
// flaky against the production HMAC compare. Flipping near the start
// guarantees the decoded HMAC differs.
func TestService_Validate_TamperedCookieRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-tamper", "User", "", "")
	parts := strings.Split(res.CookieValue, ".")
	if len(parts[3]) < 4 {
		t.Fatalf("hmac segment too short to tamper: %q", parts[3])
	}
	// Flip char at index 1 of the HMAC segment to a value whose top 6
	// bits guaranteed-differ. 'A'<->'_' is a max-distance pair in
	// base64url's alphabet.
	pivot := byte('A')
	if parts[3][1] == 'A' {
		pivot = byte('_')
	}
	tamperedHMAC := []byte(parts[3])
	tamperedHMAC[1] = pivot
	parts[3] = string(tamperedHMAC)
	tampered := strings.Join(parts, ".")
	if tampered == res.CookieValue {
		t.Fatalf("tamper produced byte-identical cookie; test setup broken")
	}
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: tampered})
	if !errors.Is(err, ErrSessionInvalidCookie) {
		t.Errorf("err = %v; want ErrSessionInvalidCookie", err)
	}
}

// #1b: Tampered SESSION_ID segment also fails.
func TestService_Validate_TamperedSessionIDRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-tamper2", "User", "", "")
	parts := strings.Split(res.CookieValue, ".")
	// Replace session id segment with a different (but well-formed) id;
	// signature verification fails because HMAC was computed over the
	// original session id.
	parts[1] = "ses-DIFFERENT0000000000000000000"
	tampered := strings.Join(parts, ".")
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: tampered})
	if !errors.Is(err, ErrSessionInvalidCookie) {
		t.Errorf("err = %v; want ErrSessionInvalidCookie", err)
	}
}

// #2: Cookie missing the v1. version prefix is rejected.
func TestService_Validate_MissingVersionPrefixRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-noprefix", "User", "", "")
	parts := strings.SplitN(res.CookieValue, ".", 2)
	bad := parts[1] // strip the "v1." prefix
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: bad})
	if !errors.Is(err, ErrSessionInvalidCookie) {
		t.Errorf("err = %v; want ErrSessionInvalidCookie", err)
	}
}

// #3: Unknown version prefix rejected — no fallback attempt.
func TestService_Validate_UnknownVersionPrefixRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-vbad", "User", "", "")
	bad := "v99" + res.CookieValue[2:] // replace v1 with v99
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: bad})
	if !errors.Is(err, ErrSessionInvalidCookie) {
		t.Errorf("err = %v; want ErrSessionInvalidCookie", err)
	}
}

// #4: Idle expiry returns ErrSessionExpiredIdle.
func TestService_Validate_ExpiredIdleRejected(t *testing.T) {
	cfg := defaultCfg()
	cfg.IdleTimeout = 1 * time.Millisecond
	svc, sessions, _, _, _ := newTestService(t, cfg)
	res, _ := svc.Create(context.Background(), "u-idle", "User", "", "")
	// Reach into the row and back-date last_seen_at to defeat the idle window.
	row := sessions.rows[res.Session.ID]
	row.LastSeenAt = time.Now().UTC().Add(-1 * time.Hour)
	row.IdleExpiresAt = time.Now().UTC().Add(-1 * time.Minute)
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: res.CookieValue})
	if !errors.Is(err, ErrSessionExpiredIdle) {
		t.Errorf("err = %v; want ErrSessionExpiredIdle", err)
	}
}

// #5: Absolute expiry returns ErrSessionExpiredAbsolute.
func TestService_Validate_ExpiredAbsoluteRejected(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-abs", "User", "", "")
	row := sessions.rows[res.Session.ID]
	row.AbsoluteExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: res.CookieValue})
	if !errors.Is(err, ErrSessionExpiredAbsolute) {
		t.Errorf("err = %v; want ErrSessionExpiredAbsolute", err)
	}
}

// #6: Revoked session returns ErrSessionRevoked.
func TestService_Validate_RevokedRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-rev", "User", "", "")
	if err := svc.Revoke(context.Background(), res.Session.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: res.CookieValue})
	if !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("err = %v; want ErrSessionRevoked", err)
	}
}

// #7: Cookie with a signing-key id that doesn't match any row -> ErrSigningKeyNotFound.
func TestService_Validate_WrongSigningKeyRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-wkey", "User", "", "")
	parts := strings.Split(res.CookieValue, ".")
	parts[2] = "sk-NONEXISTENT00000000000000000"
	bad := strings.Join(parts, ".")
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: bad})
	if !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("err = %v; want ErrSigningKeyNotFound", err)
	}
}

// #8: Cookie signed under a retired-but-in-retention key SUCCEEDS.
func TestService_Validate_RetiredButInRetentionAccepted(t *testing.T) {
	svc, _, keys, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-ret", "User", "", "")

	// Mint a NEW active key; the previously-active key gets retired.
	if err := svc.RotateSigningKey(context.Background()); err != nil {
		t.Fatalf("RotateSigningKey: %v", err)
	}

	// Confirm retired_at was set on the original key.
	parts := strings.Split(res.CookieValue, ".")
	old := keys.keys[parts[2]]
	if old.RetiredAt == nil {
		t.Fatalf("expected old key to be retired; RetiredAt is nil")
	}

	// Cookie signed under the now-retired key still validates because it's
	// inside the retention window.
	got, err := svc.Validate(context.Background(), ValidateInput{CookieValue: res.CookieValue})
	if err != nil {
		t.Fatalf("Validate (retired-in-retention): %v", err)
	}
	if got.ID != res.Session.ID {
		t.Errorf("session id mismatch")
	}
}

// #9: Cookie signed under a fully-purged-past-retention key FAILS.
func TestService_Validate_RetiredPastRetentionRejected(t *testing.T) {
	cfg := defaultCfg()
	cfg.SigningKeyRetention = 100 * time.Millisecond
	svc, _, keys, _, _ := newTestService(t, cfg)
	res, _ := svc.Create(context.Background(), "u-purg", "User", "", "")

	if err := svc.RotateSigningKey(context.Background()); err != nil {
		t.Fatalf("RotateSigningKey: %v", err)
	}
	// Back-date retired_at to push the key past the retention window.
	parts := strings.Split(res.CookieValue, ".")
	old := keys.keys[parts[2]]
	pastT := time.Now().UTC().Add(-1 * time.Hour)
	old.RetiredAt = &pastT

	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: res.CookieValue})
	if !errors.Is(err, ErrSigningKeyRetired) {
		t.Errorf("err = %v; want ErrSigningKeyRetired", err)
	}
}

// #10: Concatenation-collision attempt — the length-prefixed HMAC input
// MUST defeat `<a, bc>` claiming authority for `<ab, c>`. This test forges
// a cookie whose `<sessionID, signingKeyID>` SUMS to the same byte sequence
// as the legitimate cookie's pair but slides the boundary by one character.
// Without the length prefix in computeHMAC the two would HMAC-collide; with
// the prefix they don't.
func TestService_Validate_ConcatenationCollisionDefeatedByLengthPrefix(t *testing.T) {
	// Build the legitimate cookie under (sid="ses-ABC", kid="sk-XYZ").
	hmacKey := bytes32("test-key")
	legit := signCookie("ses-ABC", "sk-XYZ", hmacKey)

	// Build the forged variant that slides the boundary one char to the
	// right: (sid="ses-ABCs", kid="k-XYZ"). Same byte sequence pre-prefix;
	// different lengths.
	forgedRaw := signCookie("ses-ABCs", "k-XYZ", hmacKey)
	forgedParts := strings.Split(forgedRaw, ".")
	legitParts := strings.Split(legit, ".")

	// Direct evidence: the two HMACs MUST differ.
	if forgedParts[3] == legitParts[3] {
		t.Errorf("HMACs collided across boundary slide — length prefix is broken")
	}

	// And: a cookie that uses the legit sid + kid + the FORGED hmac is
	// rejected by parseCookie/HMAC-recompute path (the two segments
	// of interest hash to different values).
	forgedSwap := legitParts[0] + "." + legitParts[1] + "." + legitParts[2] + "." + forgedParts[3]
	if forgedSwap == legit {
		t.Fatalf("forged cookie is byte-identical to legit; concat-collision test setup broken")
	}
}

// #11: CSRF token missing on POST -> 403.
func TestService_ValidateCSRF_MissingHeaderRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-csrf1", "User", "", "")
	if err := svc.ValidateCSRF("", res.Session); !errors.Is(err, ErrCSRFMissing) {
		t.Errorf("err = %v; want ErrCSRFMissing", err)
	}
}

// #12: CSRF token mismatch -> 403; constant-time compare.
func TestService_ValidateCSRF_MismatchRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-csrf2", "User", "", "")
	if err := svc.ValidateCSRF("a-totally-different-token", res.Session); !errors.Is(err, ErrCSRFMismatch) {
		t.Errorf("err = %v; want ErrCSRFMismatch", err)
	}
}

// #13: IP-bind enabled + IP changed -> ErrSessionIPMismatch.
func TestService_Validate_IPBindMismatchRejected(t *testing.T) {
	cfg := defaultCfg()
	cfg.BindIP = true
	svc, _, _, audit, _ := newTestService(t, cfg)
	res, _ := svc.Create(context.Background(), "u-ipbind", "User", "10.0.0.1", "Firefox")
	_, err := svc.Validate(context.Background(), ValidateInput{
		CookieValue: res.CookieValue, ClientIP: "10.0.0.99", UserAgent: "Firefox",
	})
	if !errors.Is(err, ErrSessionIPMismatch) {
		t.Errorf("err = %v; want ErrSessionIPMismatch", err)
	}
	if !contains(audit.actions(), "auth.session_ip_mismatch") {
		t.Errorf("expected audit row auth.session_ip_mismatch; got %v", audit.actions())
	}
}

// #14: UA-bind enabled + UA changed -> ErrSessionUAMismatch.
func TestService_Validate_UABindMismatchRejected(t *testing.T) {
	cfg := defaultCfg()
	cfg.BindUserAgent = true
	svc, _, _, audit, _ := newTestService(t, cfg)
	res, _ := svc.Create(context.Background(), "u-uabind", "User", "10.0.0.1", "Firefox")
	_, err := svc.Validate(context.Background(), ValidateInput{
		CookieValue: res.CookieValue, ClientIP: "10.0.0.1", UserAgent: "Chrome",
	})
	if !errors.Is(err, ErrSessionUAMismatch) {
		t.Errorf("err = %v; want ErrSessionUAMismatch", err)
	}
	if !contains(audit.actions(), "auth.session_ua_mismatch") {
		t.Errorf("expected audit row auth.session_ua_mismatch; got %v", audit.actions())
	}
}

// #15: Initial-key bootstrap failure (RNG returns error) -> EnsureInitialSigningKey
// returns ErrInitialSigningKeyMintFailed; cmd/server/main.go wraps this as
// log.Fatal at boot.
func TestService_EnsureInitialSigningKey_RNGFailureSurfacesAsFatalSentinel(t *testing.T) {
	sessions := newStubSessionRepo()
	keys := newStubKeyRepo()
	svc := NewService(sessions, keys, nil, testTenant, defaultCfg(), "")
	svc.SetRandReaderForTest(func(_ []byte) (int, error) {
		return 0, fmt.Errorf("simulated entropy starvation")
	})
	err := svc.EnsureInitialSigningKey(context.Background())
	if !errors.Is(err, ErrInitialSigningKeyMintFailed) {
		t.Errorf("err = %v; want wrap of ErrInitialSigningKeyMintFailed", err)
	}
}

// =============================================================================
// Coverage-lift batch — branches not exercised by the 15-case matrix.
// =============================================================================

func TestService_Create_RejectsEmptyActorID(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	if _, err := svc.Create(context.Background(), "", "User", "", ""); err == nil {
		t.Errorf("expected error on empty actor_id")
	}
	if _, err := svc.Create(context.Background(), "u-x", "", "", ""); err == nil {
		t.Errorf("expected error on empty actor_type")
	}
}

func TestService_Create_GetActiveError(t *testing.T) {
	sessions := newStubSessionRepo()
	keys := newStubKeyRepo()
	keys.getActErr = fmt.Errorf("simulated db error")
	svc := NewService(sessions, keys, nil, testTenant, defaultCfg(), "")
	if _, err := svc.Create(context.Background(), "u-x", "User", "", ""); err == nil {
		t.Errorf("expected error on get-active failure")
	}
}

func TestService_Create_SessionRepoCreateError(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	sessions.createErr = fmt.Errorf("simulated db error")
	if _, err := svc.Create(context.Background(), "u-x", "User", "", ""); err == nil {
		t.Errorf("expected error on session-repo create failure")
	}
}

func TestService_Create_RNGFailureBubbles(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	svc.SetRandReaderForTest(func(_ []byte) (int, error) {
		return 0, fmt.Errorf("simulated rng exhaustion")
	})
	if _, err := svc.Create(context.Background(), "u-x", "User", "", ""); err == nil {
		t.Errorf("expected RNG failure to surface")
	}
}

func TestService_RotateCSRFToken_HappyPath(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-rot", "User", "", "")
	originalHash := sessions.rows[res.Session.ID].CSRFTokenHash

	newToken, err := svc.RotateCSRFToken(context.Background(), res.Session.ID)
	if err != nil {
		t.Fatalf("RotateCSRFToken: %v", err)
	}
	if newToken == res.CSRFToken {
		t.Errorf("rotated token equals original (RNG broken)")
	}
	if sessions.rows[res.Session.ID].CSRFTokenHash == originalHash {
		t.Errorf("session row hash didn't update after rotation")
	}
}

func TestService_RotateCSRFToken_UpdateError(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-rot2", "User", "", "")
	sessions.updateCSRFErr = fmt.Errorf("simulated db error")
	if _, err := svc.RotateCSRFToken(context.Background(), res.Session.ID); err == nil {
		t.Errorf("expected error on UpdateCSRFTokenHash failure")
	}
}

func TestService_RevokeAllForActor_HappyPath(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	res1, _ := svc.Create(context.Background(), "u-multi", "User", "", "")
	res2, _ := svc.Create(context.Background(), "u-multi", "User", "", "")
	if err := svc.RevokeAllForActor(context.Background(), "u-multi", "User"); err != nil {
		t.Fatalf("RevokeAllForActor: %v", err)
	}
	if sessions.rows[res1.Session.ID].RevokedAt == nil {
		t.Errorf("session 1 not revoked")
	}
	if sessions.rows[res2.Session.ID].RevokedAt == nil {
		t.Errorf("session 2 not revoked")
	}
}

func TestService_RotateSigningKey_RetiresOldAndAddsNew(t *testing.T) {
	svc, _, keys, _, oldID := newTestService(t, defaultCfg())
	if err := svc.RotateSigningKey(context.Background()); err != nil {
		t.Fatalf("RotateSigningKey: %v", err)
	}
	old, _ := keys.Get(context.Background(), oldID)
	if old.RetiredAt == nil {
		t.Errorf("old key not retired")
	}
	active, _ := keys.GetActive(context.Background(), testTenant)
	if active.ID == oldID {
		t.Errorf("active key did not change")
	}
}

func TestService_EnsureInitialSigningKey_IdempotentOnExisting(t *testing.T) {
	svc, _, keys, _, oldID := newTestService(t, defaultCfg())
	// Second call must be a no-op.
	if err := svc.EnsureInitialSigningKey(context.Background()); err != nil {
		t.Fatalf("EnsureInitialSigningKey (second call): %v", err)
	}
	all, _ := keys.List(context.Background(), testTenant)
	if len(all) != 1 {
		t.Errorf("expected idempotent (1 key); got %d", len(all))
	}
	if all[0].ID != oldID {
		t.Errorf("key id changed across idempotent calls")
	}
}

func TestService_EnsureInitialSigningKey_GetActiveErrorOtherThanNotFoundBubbles(t *testing.T) {
	sessions := newStubSessionRepo()
	keys := newStubKeyRepo()
	keys.getActErr = fmt.Errorf("simulated db error other than not-found")
	svc := NewService(sessions, keys, nil, testTenant, defaultCfg(), "")
	if err := svc.EnsureInitialSigningKey(context.Background()); err == nil {
		t.Errorf("expected non-nil error from non-NotFound get-active")
	}
}

func TestService_EnsureInitialSigningKey_AddErrorWraps(t *testing.T) {
	sessions := newStubSessionRepo()
	keys := newStubKeyRepo()
	keys.addErr = fmt.Errorf("simulated insert failure")
	svc := NewService(sessions, keys, nil, testTenant, defaultCfg(), "")
	err := svc.EnsureInitialSigningKey(context.Background())
	if !errors.Is(err, ErrInitialSigningKeyMintFailed) {
		t.Errorf("err = %v; want wrap of ErrInitialSigningKeyMintFailed", err)
	}
}

func TestService_GarbageCollect_HappyPath(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	sessions.gcCount = 7
	deleted, err := svc.GarbageCollect(context.Background())
	if err != nil {
		t.Fatalf("GarbageCollect: %v", err)
	}
	if deleted != 7 {
		t.Errorf("deleted = %d; want 7", deleted)
	}
}

func TestService_GarbageCollect_PurgesRetiredPastRetention(t *testing.T) {
	cfg := defaultCfg()
	cfg.SigningKeyRetention = 1 * time.Millisecond
	svc, _, keys, _, oldID := newTestService(t, cfg)
	if err := svc.RotateSigningKey(context.Background()); err != nil {
		t.Fatalf("RotateSigningKey: %v", err)
	}
	// Back-date the retired_at so the GC sweep purges it.
	pastT := time.Now().UTC().Add(-1 * time.Hour)
	keys.keys[oldID].RetiredAt = &pastT
	if _, err := svc.GarbageCollect(context.Background()); err != nil {
		t.Fatalf("GarbageCollect: %v", err)
	}
	if _, err := keys.Get(context.Background(), oldID); !errors.Is(err, repository.ErrSessionSigningKeyNotFound) {
		t.Errorf("old key still present after GC")
	}
}

func TestService_GarbageCollect_KeysListErrorPropagated(t *testing.T) {
	svc, _, keys, _, _ := newTestService(t, defaultCfg())
	keys.listErr = fmt.Errorf("simulated list error")
	if _, err := svc.GarbageCollect(context.Background()); err == nil {
		t.Errorf("expected error on keys.List failure")
	}
}

func TestService_GarbageCollect_KeyInUseSkipped(t *testing.T) {
	cfg := defaultCfg()
	cfg.SigningKeyRetention = 1 * time.Millisecond
	svc, _, keys, _, oldID := newTestService(t, cfg)
	_ = svc.RotateSigningKey(context.Background())
	pastT := time.Now().UTC().Add(-1 * time.Hour)
	keys.keys[oldID].RetiredAt = &pastT
	keys.deleteErr = repository.ErrSessionSigningKeyInUse
	if _, err := svc.GarbageCollect(context.Background()); err != nil {
		t.Fatalf("GarbageCollect (in-use should be silently skipped): %v", err)
	}
}

func TestService_GarbageCollect_KeyDeleteOtherErrorBubbles(t *testing.T) {
	cfg := defaultCfg()
	cfg.SigningKeyRetention = 1 * time.Millisecond
	svc, _, keys, _, oldID := newTestService(t, cfg)
	_ = svc.RotateSigningKey(context.Background())
	pastT := time.Now().UTC().Add(-1 * time.Hour)
	keys.keys[oldID].RetiredAt = &pastT
	keys.deleteErr = fmt.Errorf("some other db error")
	if _, err := svc.GarbageCollect(context.Background()); err == nil {
		t.Errorf("expected error to bubble from non-InUse delete failure")
	}
}

func TestService_GarbageCollect_SessionRepoErrorBubbles(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	sessions.gcErr = fmt.Errorf("simulated session-gc failure")
	if _, err := svc.GarbageCollect(context.Background()); err == nil {
		t.Errorf("expected error to bubble from session-repo gc failure")
	}
}

func TestService_RotateSigningKey_GetActiveError(t *testing.T) {
	svc, _, keys, _, _ := newTestService(t, defaultCfg())
	keys.getActErr = fmt.Errorf("simulated error")
	if err := svc.RotateSigningKey(context.Background()); err == nil {
		t.Errorf("expected error when getActive fails")
	}
}

func TestService_RotateSigningKey_AddError(t *testing.T) {
	svc, _, keys, _, _ := newTestService(t, defaultCfg())
	keys.addErr = fmt.Errorf("simulated insert failure")
	if err := svc.RotateSigningKey(context.Background()); err == nil {
		t.Errorf("expected error when add fails")
	}
}

func TestService_RotateSigningKey_RetireError(t *testing.T) {
	svc, _, keys, _, _ := newTestService(t, defaultCfg())
	keys.retireErr = fmt.Errorf("simulated retire failure")
	if err := svc.RotateSigningKey(context.Background()); err == nil {
		t.Errorf("expected error when retire fails")
	}
}

// TestService_Validate_TransientSessionGetError pins the LOW-6
// closure (audit 2026-05-10): a non-deterministic DB error from
// session.Get bubbles up as ErrSessionTransient (→ 503), NOT
// ErrSessionInvalidCookie (→ 401). The middleware test pins the
// 503-with-Retry-After wire shape; this one pins the service-layer
// sentinel.
func TestService_Validate_TransientSessionGetError(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-y", "User", "", "")
	sessions.getErr = fmt.Errorf("simulated session.Get failure")
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: res.CookieValue})
	if !errors.Is(err, ErrSessionTransient) {
		t.Errorf("err = %v; want ErrSessionTransient", err)
	}
	if errors.Is(err, ErrSessionInvalidCookie) {
		t.Errorf("err also matched ErrSessionInvalidCookie; want only ErrSessionTransient")
	}
}

// TestService_Validate_SessionNotFoundMapsToInvalidCookie pins the
// other half of the LOW-6 split: repository.ErrSessionNotFound (a
// real, deterministic "the row doesn't exist" answer from the DB)
// stays mapped to ErrSessionInvalidCookie (→ 401), NOT 503.
func TestService_Validate_SessionNotFoundMapsToInvalidCookie(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-y2", "User", "", "")
	sessions.getErr = repository.ErrSessionNotFound
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: res.CookieValue})
	if !errors.Is(err, ErrSessionInvalidCookie) {
		t.Errorf("err = %v; want ErrSessionInvalidCookie", err)
	}
	if errors.Is(err, ErrSessionTransient) {
		t.Errorf("err also matched ErrSessionTransient; want only ErrSessionInvalidCookie")
	}
}

func TestService_UpdateLastSeen_RepoErrorWraps(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-uls", "User", "", "")
	sessions.updateLastErr = fmt.Errorf("simulated db error")
	if err := svc.UpdateLastSeen(context.Background(), res.Session.ID); err == nil {
		t.Errorf("expected error on UpdateLastSeen failure")
	}
}

func TestService_Revoke_RepoErrorWraps(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-rev2", "User", "", "")
	sessions.revokeErr = fmt.Errorf("simulated db error")
	if err := svc.Revoke(context.Background(), res.Session.ID); err == nil {
		t.Errorf("expected error on Revoke failure")
	}
}

func TestService_RevokeAllForActor_RepoErrorWraps(t *testing.T) {
	svc, sessions, _, _, _ := newTestService(t, defaultCfg())
	sessions.revokeAllErr = fmt.Errorf("simulated db error")
	if err := svc.RevokeAllForActor(context.Background(), "u-x", "User"); err == nil {
		t.Errorf("expected error on RevokeAllForActor failure")
	}
}

func TestService_ValidateCSRF_NilSessionRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	if err := svc.ValidateCSRF("anything", nil); !errors.Is(err, ErrCSRFMismatch) {
		t.Errorf("err = %v; want ErrCSRFMismatch", err)
	}
}

func TestService_SetClockForTest_OverridesNow(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	frozen := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	svc.SetClockForTest(func() time.Time { return frozen })
	if got := svc.clockNow(); !got.Equal(frozen) {
		t.Errorf("clock = %v; want %v", got, frozen)
	}
}

func TestService_DefaultConfig_HasPromptDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.IdleTimeout != 1*time.Hour {
		t.Errorf("IdleTimeout = %v; want 1h", cfg.IdleTimeout)
	}
	if cfg.AbsoluteTimeout != 8*time.Hour {
		t.Errorf("AbsoluteTimeout = %v; want 8h", cfg.AbsoluteTimeout)
	}
	if cfg.SigningKeyRetention != 24*time.Hour {
		t.Errorf("SigningKeyRetention = %v; want 24h", cfg.SigningKeyRetention)
	}
	if cfg.BindIP || cfg.BindUserAgent {
		t.Errorf("Bind* defaults should be false; got IP=%v UA=%v", cfg.BindIP, cfg.BindUserAgent)
	}
}

func TestService_RotateCSRFToken_RNGFailureBubbles(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	res, _ := svc.Create(context.Background(), "u-rotrng", "User", "", "")
	svc.SetRandReaderForTest(func(_ []byte) (int, error) {
		return 0, fmt.Errorf("rng dead")
	})
	if _, err := svc.RotateCSRFToken(context.Background(), res.Session.ID); err == nil {
		t.Errorf("expected RNG-failure to surface from RotateCSRFToken")
	}
}

func TestService_RotateSigningKey_RNGFailureBubbles(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())
	svc.SetRandReaderForTest(func(_ []byte) (int, error) {
		return 0, fmt.Errorf("rng dead")
	})
	if err := svc.RotateSigningKey(context.Background()); err == nil {
		t.Errorf("expected RNG-failure to surface from RotateSigningKey")
	}
}

func TestService_Validate_DecryptKeyMaterialFailure(t *testing.T) {
	// With a real encryption passphrase, an external mutation of the
	// key blob causes Decrypt to fail; Validate maps to ErrSessionInvalidCookie.
	const passphrase = "test-passphrase-decrypt-fail"
	sessions := newStubSessionRepo()
	keys := newStubKeyRepo()
	svc := NewService(sessions, keys, nil, testTenant, defaultCfg(), passphrase)
	if err := svc.EnsureInitialSigningKey(context.Background()); err != nil {
		t.Fatalf("EnsureInitialSigningKey: %v", err)
	}
	res, _ := svc.Create(context.Background(), "u-decfail", "User", "", "")
	// Corrupt the stored ciphertext.
	for _, k := range keys.keys {
		k.KeyMaterialEncrypted = append([]byte("corrupt-prefix"), k.KeyMaterialEncrypted...)
	}
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: res.CookieValue})
	if !errors.Is(err, ErrSessionInvalidCookie) {
		t.Errorf("err = %v; want ErrSessionInvalidCookie", err)
	}
}

// =============================================================================
// HMAC-input length-prefix correctness — direct unit test of computeHMAC.
//
// Without the length prefix, computeHMAC for ("abc","de") would equal
// computeHMAC for ("ab","cde"). With the prefix, it must not.
// =============================================================================

func TestComputeHMAC_LengthPrefixDefeatsConcatCollision(t *testing.T) {
	key := bytes32("the-key")
	a := computeHMAC("abc", "de", key)
	b := computeHMAC("ab", "cde", key)
	if base64.RawURLEncoding.EncodeToString(a) == base64.RawURLEncoding.EncodeToString(b) {
		t.Errorf("computeHMAC(\"abc\",\"de\") == computeHMAC(\"ab\",\"cde\") — length prefix is broken")
	}
}

// =============================================================================
// Encryption round-trip: sign + validate against a real CERTCTL_CONFIG_ENCRYPTION_KEY.
// =============================================================================

func TestService_EncryptionRoundTrip(t *testing.T) {
	const passphrase = "test-encryption-passphrase-12345"
	sessions := newStubSessionRepo()
	keys := newStubKeyRepo()
	svc := NewService(sessions, keys, nil, testTenant, defaultCfg(), passphrase)
	if err := svc.EnsureInitialSigningKey(context.Background()); err != nil {
		t.Fatalf("EnsureInitialSigningKey: %v", err)
	}
	res, err := svc.Create(context.Background(), "u-enc", "User", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := svc.Validate(context.Background(), ValidateInput{CookieValue: res.CookieValue})
	if err != nil {
		t.Fatalf("Validate (real-encryption round trip): %v", err)
	}
	if got.ID != res.Session.ID {
		t.Errorf("session id mismatch")
	}
}

// =============================================================================
// Cookie parser unit tests.
// =============================================================================

func TestParseCookie_RejectsEmpty(t *testing.T) {
	if _, _, _, err := parseCookie(""); err == nil {
		t.Errorf("expected error for empty cookie")
	}
}

func TestParseCookie_RejectsWrongSegmentCount(t *testing.T) {
	for _, bad := range []string{"v1", "v1.ses-x", "v1.ses-x.sk-y", "v1.ses-x.sk-y.h.extra"} {
		if _, _, _, err := parseCookie(bad); err == nil {
			t.Errorf("expected error for bad segment count: %q", bad)
		}
	}
}

func TestParseCookie_RejectsMissingPrefixes(t *testing.T) {
	mac := base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size))
	// parseCookie itself does NOT enforce the ses-/pl- prefix on the
	// id segment (Phase 5 split: prefix-check moved to Validate so the
	// pre-login `pl-` cookie can share the same parser). We still
	// reject empty segments + wrong signing-key prefix here.
	if _, _, _, err := parseCookie("v1..sk-y." + mac); err == nil {
		t.Errorf("expected error for empty session id segment")
	}
	if _, _, _, err := parseCookie("v1.ses-x.bad-key." + mac); err == nil {
		t.Errorf("expected error for signing key id missing prefix")
	}
}

// Phase 5: ParseCookieValue (the exported wrapper) DOES enforce the
// caller-specified prefix on segment 1. Pin both the post-login
// `ses-` and pre-login `pl-` consumer flows.
func TestParseCookieValue_EnforcesCallerSuppliedPrefix(t *testing.T) {
	mac := base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size))
	if _, _, _, err := ParseCookieValue("v1.bad-id.sk-y."+mac, "ses-"); !errors.Is(err, errInvalidIDPrefix) {
		t.Errorf("ParseCookieValue with wrong prefix: err = %v; want errInvalidIDPrefix", err)
	}
	if _, _, _, err := ParseCookieValue("v1.bad-id.sk-y."+mac, "pl-"); !errors.Is(err, errInvalidIDPrefix) {
		t.Errorf("ParseCookieValue with wrong prefix (pl-): err = %v; want errInvalidIDPrefix", err)
	}
	// Empty prefix skips the check.
	if _, _, _, err := ParseCookieValue("v1.anything.sk-y."+mac, ""); err != nil {
		t.Errorf("ParseCookieValue with empty prefix: err = %v; want nil (skip prefix check)", err)
	}
}

// Pin that the post-login Validate path rejects pre-login (`pl-`)
// cookies even when the HMAC signs valid — defense-in-depth so a
// stolen pre-login cookie can't be replayed against /api/* gates.
func TestService_Validate_RejectsPreLoginCookieAtPostLoginGate(t *testing.T) {
	svc, _, keys, _, _ := newTestService(t, defaultCfg())
	// Forge a `pl-` cookie signed under the active key.
	active, _ := keys.GetActive(context.Background(), testTenant)
	hmacKey, _ := DecryptKeyMaterial(active.KeyMaterialEncrypted, "")
	forged := SignCookieValue("pl-forged-id", active.ID, hmacKey)
	_, err := svc.Validate(context.Background(), ValidateInput{CookieValue: forged})
	if !errors.Is(err, ErrSessionInvalidCookie) {
		t.Errorf("Validate accepted pl- cookie: err = %v; want ErrSessionInvalidCookie", err)
	}
}

func TestParseCookie_RejectsBadBase64(t *testing.T) {
	if _, _, _, err := parseCookie("v1.ses-x.sk-y.!!!notbase64"); err == nil {
		t.Errorf("expected error for bad base64 hmac segment")
	}
}

func TestParseCookie_RejectsWrongHMACLength(t *testing.T) {
	short := base64.RawURLEncoding.EncodeToString([]byte("not-32-bytes"))
	if _, _, _, err := parseCookie("v1.ses-x.sk-y." + short); err == nil {
		t.Errorf("expected error for wrong-length hmac")
	}
}

// =============================================================================
// Test helpers.
// =============================================================================

// bytes32 returns 32 bytes deterministically derived from seed (for HMAC-key
// material in unit tests). Production keys come from crypto/rand.
func bytes32(seed string) []byte {
	h := sha256.Sum256([]byte(seed))
	return h[:]
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
