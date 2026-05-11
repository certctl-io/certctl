package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// =============================================================================
// SessionSigningKey tests
// =============================================================================

func newValidSigningKey(suffix string) *sessiondomain.SessionSigningKey {
	return &sessiondomain.SessionSigningKey{
		ID:                   "sk-" + suffix,
		TenantID:             "t-default",
		KeyMaterialEncrypted: []byte{0x02, 0x00, 0x01, 0x02, 0x03},
	}
}

func TestSessionSigningKeyRepository_AddAndGetActive(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewSessionSigningKeyRepository(db)
	ctx := context.Background()

	k := newValidSigningKey("a")
	if err := repo.Add(ctx, k); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if k.CreatedAt.IsZero() {
		t.Errorf("Add did not populate CreatedAt")
	}

	got, err := repo.GetActive(ctx, "t-default")
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if got.ID != k.ID {
		t.Errorf("GetActive returned %q; want %q", got.ID, k.ID)
	}
}

func TestSessionSigningKeyRepository_GetActiveSkipsRetired(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewSessionSigningKeyRepository(db)
	ctx := context.Background()

	// Add older key, retire it. Add newer key. GetActive must return newer.
	older := newValidSigningKey("older")
	if err := repo.Add(ctx, older); err != nil {
		t.Fatalf("Add older: %v", err)
	}
	if err := repo.Retire(ctx, older.ID); err != nil {
		t.Fatalf("Retire older: %v", err)
	}
	// Sleep a millisecond so created_at orders deterministically.
	time.Sleep(10 * time.Millisecond)
	newer := newValidSigningKey("newer")
	if err := repo.Add(ctx, newer); err != nil {
		t.Fatalf("Add newer: %v", err)
	}

	got, err := repo.GetActive(ctx, "t-default")
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if got.ID != newer.ID {
		t.Errorf("GetActive returned %q; want %q (older was retired)", got.ID, newer.ID)
	}
}

func TestSessionSigningKeyRepository_GetActiveReturnsNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewSessionSigningKeyRepository(db)
	ctx := context.Background()

	_, err := repo.GetActive(ctx, "t-default")
	if !errors.Is(err, repository.ErrSessionSigningKeyNotFound) {
		t.Errorf("err = %v; want ErrSessionSigningKeyNotFound", err)
	}
}

func TestSessionSigningKeyRepository_RetireIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewSessionSigningKeyRepository(db)
	ctx := context.Background()

	k := newValidSigningKey("retire")
	if err := repo.Add(ctx, k); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := repo.Retire(ctx, k.ID); err != nil {
		t.Fatalf("first Retire: %v", err)
	}
	if err := repo.Retire(ctx, k.ID); err != nil {
		t.Errorf("second Retire (already retired) should be idempotent; got %v", err)
	}
}

func TestSessionSigningKeyRepository_DeleteRefusedWhenSessionsReference(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	keyRepo := postgres.NewSessionSigningKeyRepository(db)
	sessRepo := postgres.NewSessionRepository(db)
	ctx := context.Background()

	k := newValidSigningKey("inuse")
	if err := keyRepo.Add(ctx, k); err != nil {
		t.Fatalf("Add key: %v", err)
	}
	s := newValidSession("s1", k.ID)
	if err := sessRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create session: %v", err)
	}

	err := keyRepo.Delete(ctx, k.ID)
	if !errors.Is(err, repository.ErrSessionSigningKeyInUse) {
		t.Errorf("Delete with referencing session err = %v; want ErrSessionSigningKeyInUse", err)
	}
}

// =============================================================================
// Session tests
// =============================================================================

func newValidSession(suffix, signingKeyID string) *sessiondomain.Session {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &sessiondomain.Session{
		ID:                "ses-" + suffix,
		TenantID:          "t-default",
		ActorID:           "u-" + suffix,
		ActorType:         "User",
		SigningKeyID:      signingKeyID,
		IsPreLogin:        false,
		CSRFTokenHash:     strings.Repeat("a", 64),
		IdleExpiresAt:     now.Add(time.Hour),
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
		CreatedAt:         now,
		LastSeenAt:        now,
		IPAddress:         "10.0.0.1",
		UserAgent:         "Mozilla/5.0",
	}
}

func TestSessionRepository_CreateAndGet(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	keyRepo := postgres.NewSessionSigningKeyRepository(db)
	sessRepo := postgres.NewSessionRepository(db)
	ctx := context.Background()

	k := newValidSigningKey("k1")
	if err := keyRepo.Add(ctx, k); err != nil {
		t.Fatalf("Add key: %v", err)
	}
	s := newValidSession("s1", k.ID)
	if err := sessRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := sessRepo.Get(ctx, s.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ActorID != s.ActorID {
		t.Errorf("ActorID roundtrip mismatch")
	}
	if got.RevokedAt != nil {
		t.Errorf("RevokedAt should be nil on fresh session")
	}
}

func TestSessionRepository_GetNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewSessionRepository(db)
	ctx := context.Background()

	_, err := repo.Get(ctx, "ses-nonexistent")
	if !errors.Is(err, repository.ErrSessionNotFound) {
		t.Errorf("err = %v; want ErrSessionNotFound", err)
	}
}

func TestSessionRepository_RevokeAndGet(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	keyRepo := postgres.NewSessionSigningKeyRepository(db)
	sessRepo := postgres.NewSessionRepository(db)
	ctx := context.Background()

	k := newValidSigningKey("k2")
	if err := keyRepo.Add(ctx, k); err != nil {
		t.Fatalf("Add key: %v", err)
	}
	s := newValidSession("s2", k.ID)
	if err := sessRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := sessRepo.Revoke(ctx, s.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, err := sessRepo.Get(ctx, s.ID)
	if err != nil {
		t.Fatalf("Get post-revoke: %v", err)
	}
	if got.RevokedAt == nil {
		t.Errorf("RevokedAt nil after Revoke")
	}

	// Idempotent re-revoke: returns nil, no panic, no double-update.
	if err := sessRepo.Revoke(ctx, s.ID); err != nil {
		t.Errorf("re-Revoke (idempotent) err = %v; want nil", err)
	}
}

func TestSessionRepository_RevokeNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewSessionRepository(db)
	ctx := context.Background()

	if err := repo.Revoke(ctx, "ses-nonexistent"); !errors.Is(err, repository.ErrSessionNotFound) {
		t.Errorf("err = %v; want ErrSessionNotFound", err)
	}
}

func TestSessionRepository_ListByActorActiveOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	keyRepo := postgres.NewSessionSigningKeyRepository(db)
	sessRepo := postgres.NewSessionRepository(db)
	ctx := context.Background()

	k := newValidSigningKey("la")
	if err := keyRepo.Add(ctx, k); err != nil {
		t.Fatalf("Add key: %v", err)
	}
	// 3 active + 1 revoked + 1 pre-login.
	for i, suf := range []string{"a1", "a2", "a3"} {
		s := newValidSession(suf, k.ID)
		s.ActorID = "u-list-actor"
		// uniqueness: stagger created_at so list ordering is stable
		s.CreatedAt = s.CreatedAt.Add(time.Duration(i) * time.Millisecond)
		if err := sessRepo.Create(ctx, s); err != nil {
			t.Fatalf("Create %s: %v", suf, err)
		}
	}
	revoked := newValidSession("rev", k.ID)
	revoked.ActorID = "u-list-actor"
	if err := sessRepo.Create(ctx, revoked); err != nil {
		t.Fatalf("Create revoked: %v", err)
	}
	if err := sessRepo.Revoke(ctx, revoked.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	preLogin := newValidSession("pre", k.ID)
	preLogin.ActorID = "u-list-actor"
	preLogin.IsPreLogin = true
	preLogin.CSRFTokenHash = "" // pre-login rows have no CSRF token
	if err := sessRepo.Create(ctx, preLogin); err != nil {
		t.Fatalf("Create pre-login: %v", err)
	}

	out, err := sessRepo.ListByActor(ctx, "u-list-actor", "User", "t-default")
	if err != nil {
		t.Fatalf("ListByActor: %v", err)
	}
	if len(out) != 3 {
		t.Errorf("ListByActor count = %d; want 3 (revoked + pre-login excluded)", len(out))
	}
}

func TestSessionRepository_RevokeAllForActor(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	keyRepo := postgres.NewSessionSigningKeyRepository(db)
	sessRepo := postgres.NewSessionRepository(db)
	ctx := context.Background()

	k := newValidSigningKey("ra")
	if err := keyRepo.Add(ctx, k); err != nil {
		t.Fatalf("Add key: %v", err)
	}
	// 3 sessions for one actor.
	for _, suf := range []string{"r1", "r2", "r3"} {
		s := newValidSession(suf, k.ID)
		s.ActorID = "u-fired"
		if err := sessRepo.Create(ctx, s); err != nil {
			t.Fatalf("Create %s: %v", suf, err)
		}
	}
	if err := sessRepo.RevokeAllForActor(ctx, "u-fired", "User", "t-default"); err != nil {
		t.Fatalf("RevokeAllForActor: %v", err)
	}
	out, err := sessRepo.ListByActor(ctx, "u-fired", "User", "t-default")
	if err != nil {
		t.Fatalf("ListByActor post-revoke: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("RevokeAllForActor left %d sessions active; want 0", len(out))
	}
}

func TestSessionRepository_GarbageCollectExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	keyRepo := postgres.NewSessionSigningKeyRepository(db)
	sessRepo := postgres.NewSessionRepository(db)
	ctx := context.Background()

	k := newValidSigningKey("gc")
	if err := keyRepo.Add(ctx, k); err != nil {
		t.Fatalf("Add key: %v", err)
	}

	// One session with absolute expiry in the past (write directly via SQL
	// to bypass the CHECK constraints; this simulates a row that aged
	// past expiry without GC having run yet).
	now := time.Now().UTC()
	old := time.Now().UTC().Add(-2 * time.Hour)
	older := time.Now().UTC().Add(-3 * time.Hour)
	_, err := db.ExecContext(ctx, `
		INSERT INTO sessions (id, tenant_id, actor_id, actor_type, signing_key_id,
			is_pre_login, csrf_token_hash, idle_expires_at, absolute_expires_at,
			created_at, last_seen_at, ip_address, user_agent)
		VALUES ($1, 't-default', 'u-gc', 'User', $2, FALSE, '',
			$3, $4, $5, $5, '', '')`,
		"ses-expired", k.ID, older, old, time.Now().UTC().Add(-4*time.Hour))
	if err != nil {
		t.Fatalf("seed expired: %v", err)
	}

	// One pre-login row older than 10 minutes.
	_, err = db.ExecContext(ctx, `
		INSERT INTO sessions (id, tenant_id, actor_id, actor_type, signing_key_id,
			is_pre_login, csrf_token_hash, idle_expires_at, absolute_expires_at,
			created_at, last_seen_at, ip_address, user_agent)
		VALUES ($1, 't-default', 'u-gc', 'User', $2, TRUE, '',
			$3, $4, $5, $5, '', '')`,
		"ses-prelogin-old", k.ID,
		now.Add(-15*time.Minute).Add(time.Hour),   // idle in future relative to created
		now.Add(-15*time.Minute).Add(2*time.Hour), // absolute > idle, both > created
		now.Add(-15*time.Minute))                  // created 15 min ago (older than 10 min TTL)
	if err != nil {
		t.Fatalf("seed pre-login: %v", err)
	}

	// One active session (NOT to be GC'd).
	active := newValidSession("active", k.ID)
	active.ActorID = "u-gc"
	if err := sessRepo.Create(ctx, active); err != nil {
		t.Fatalf("seed active: %v", err)
	}

	n, err := sessRepo.GarbageCollectExpired(ctx)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 2 {
		t.Errorf("GC deleted %d rows; want 2 (expired + old pre-login)", n)
	}

	// Active session survives.
	if _, err := sessRepo.Get(ctx, active.ID); err != nil {
		t.Errorf("active session should survive GC; got %v", err)
	}
}

func TestSessionRepository_UpdateLastSeen(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	keyRepo := postgres.NewSessionSigningKeyRepository(db)
	sessRepo := postgres.NewSessionRepository(db)
	ctx := context.Background()

	k := newValidSigningKey("uls")
	if err := keyRepo.Add(ctx, k); err != nil {
		t.Fatalf("Add key: %v", err)
	}
	s := newValidSession("uls", k.ID)
	if err := sessRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	originalSeen := s.LastSeenAt
	time.Sleep(10 * time.Millisecond)
	if err := sessRepo.UpdateLastSeen(ctx, s.ID); err != nil {
		t.Fatalf("UpdateLastSeen: %v", err)
	}
	got, _ := sessRepo.Get(ctx, s.ID)
	if !got.LastSeenAt.After(originalSeen) {
		t.Errorf("LastSeenAt did not advance after UpdateLastSeen")
	}
}
