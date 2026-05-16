// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	userdomain "github.com/certctl-io/certctl/internal/auth/user/domain"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// Sprint 6 COMP-002-RETENTION unit tests. The repo + session deps are
// covered by in-memory stubs in this file; the integration shape
// (deactivated_at SQL filter, session revocation in PG) is covered by
// the existing postgres tests for those repositories.

type retentionStubUserRepo struct {
	mu       sync.Mutex
	byID     map[string]*userdomain.User
	updateOK bool
	updateCh chan struct{}
}

func newRetentionStubUserRepo() *retentionStubUserRepo {
	return &retentionStubUserRepo{
		byID:     make(map[string]*userdomain.User),
		updateOK: true,
		updateCh: make(chan struct{}, 100),
	}
}

func (r *retentionStubUserRepo) seed(u *userdomain.User) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[u.ID] = u
}

func (r *retentionStubUserRepo) Get(_ context.Context, id string) (*userdomain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byID[id]
	if !ok {
		return nil, repository.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (r *retentionStubUserRepo) GetByOIDCSubject(_ context.Context, _, _ string) (*userdomain.User, error) {
	return nil, repository.ErrUserNotFound
}

func (r *retentionStubUserRepo) Create(_ context.Context, _ *userdomain.User) error { return nil }

func (r *retentionStubUserRepo) Update(_ context.Context, u *userdomain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.updateOK {
		return errors.New("retentionStubUserRepo: update disabled")
	}
	cp := *u
	r.byID[u.ID] = &cp
	r.updateCh <- struct{}{}
	return nil
}

func (r *retentionStubUserRepo) ListAll(_ context.Context, _ string) ([]*userdomain.User, error) {
	return nil, nil
}

func (r *retentionStubUserRepo) ListDeactivatedBefore(_ context.Context, threshold time.Time) ([]*userdomain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*userdomain.User
	for _, u := range r.byID {
		if u.DeactivatedAt != nil && u.DeactivatedAt.Before(threshold) {
			cp := *u
			out = append(out, &cp)
		}
	}
	return out, nil
}

type retentionStubSessionRepo struct {
	mu            sync.Mutex
	revokedActors []string
	revokeError   error
}

// retentionStubSessionRepo satisfies the full repository.SessionRepository
// surface. user_retention.go only calls RevokeAllForActor; the other
// methods are no-op stubs that exist so the fixture compiles against
// the interface.

func (s *retentionStubSessionRepo) Create(_ context.Context, _ *sessiondomain.Session) error {
	return nil
}
func (s *retentionStubSessionRepo) Get(_ context.Context, _ string) (*sessiondomain.Session, error) {
	return nil, repository.ErrSessionNotFound
}
func (s *retentionStubSessionRepo) ListByActor(_ context.Context, _, _, _ string) ([]*sessiondomain.Session, error) {
	return nil, nil
}
func (s *retentionStubSessionRepo) UpdateLastSeen(_ context.Context, _ string) error {
	return nil
}
func (s *retentionStubSessionRepo) UpdateCSRFTokenHash(_ context.Context, _, _ string) error {
	return nil
}
func (s *retentionStubSessionRepo) Revoke(_ context.Context, _ string) error { return nil }
func (s *retentionStubSessionRepo) RevokeAllForActor(_ context.Context, actorID, _, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revokeError != nil {
		return s.revokeError
	}
	s.revokedActors = append(s.revokedActors, actorID)
	return nil
}
func (s *retentionStubSessionRepo) RevokeAllExceptForActor(_ context.Context, _, _, _, _ string) (int, error) {
	return 0, nil
}
func (s *retentionStubSessionRepo) GarbageCollectExpired(_ context.Context) (int, error) {
	return 0, nil
}
func (s *retentionStubSessionRepo) Delete(_ context.Context, _ string) error {
	return nil
}

func newTestUser(id, email, displayName, subject string, deactivated *time.Time) *userdomain.User {
	return &userdomain.User{
		ID:                  id,
		TenantID:            "t-default",
		Email:               email,
		DisplayName:         displayName,
		OIDCSubject:         subject,
		OIDCProviderID:      "op-test",
		LastLoginAt:         time.Now(),
		WebAuthnCredentials: []byte(`[]`),
		CreatedAt:           time.Now().Add(-90 * 24 * time.Hour),
		UpdatedAt:           time.Now(),
		DeactivatedAt:       deactivated,
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10}))
}

// TestDeleteUserPII_ScrubsAndRevokes: the operator-facing primitive
// nullifies email + display_name, hashes oidc_subject, and revokes
// sessions on the affected actor.
func TestDeleteUserPII_ScrubsAndRevokes(t *testing.T) {
	t.Parallel()

	users := newRetentionStubUserRepo()
	sessions := &retentionStubSessionRepo{}
	now := time.Now()
	deact := now.Add(-45 * 24 * time.Hour)
	users.seed(newTestUser("u-1", "alice@example.com", "Alice", "sub-alice", &deact))

	svc := NewUserRetentionService(users, sessions, nil, discardLogger(), 30*24*time.Hour, 0)
	if err := svc.DeleteUserPII(context.Background(), "u-1"); err != nil {
		t.Fatalf("DeleteUserPII: %v", err)
	}

	got, err := users.Get(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("post-purge Get: %v", err)
	}
	if got.Email != "purged@redacted.local" {
		t.Errorf("email not scrubbed: %q", got.Email)
	}
	if got.DisplayName != "[purged]" {
		t.Errorf("display_name not scrubbed: %q", got.DisplayName)
	}
	if !strings.HasPrefix(got.OIDCSubject, "sha256:") {
		t.Errorf("oidc_subject not hashed: %q", got.OIDCSubject)
	}
	if got.OIDCSubject == "sha256:" {
		t.Errorf("oidc_subject hash is empty")
	}

	sessions.mu.Lock()
	if len(sessions.revokedActors) != 1 || sessions.revokedActors[0] != "u-1" {
		t.Errorf("RevokeAllForActor not called for u-1; got %v", sessions.revokedActors)
	}
	sessions.mu.Unlock()
}

// TestDeleteUserPII_IsIdempotent: scrubbing an already-scrubbed row
// is safe — the oidc_subject hash recurses (sha256 of sha256:hex)
// without breaking the UNIQUE constraint or returning an error. We
// verify the scrubbed values + the prefix.
func TestDeleteUserPII_IsIdempotent(t *testing.T) {
	t.Parallel()

	users := newRetentionStubUserRepo()
	sessions := &retentionStubSessionRepo{}
	now := time.Now()
	deact := now.Add(-100 * 24 * time.Hour)
	users.seed(newTestUser("u-2", "bob@example.com", "Bob", "sub-bob", &deact))

	svc := NewUserRetentionService(users, sessions, nil, discardLogger(), 30*24*time.Hour, 0)
	if err := svc.DeleteUserPII(context.Background(), "u-2"); err != nil {
		t.Fatalf("first DeleteUserPII: %v", err)
	}
	first, _ := users.Get(context.Background(), "u-2")
	if err := svc.DeleteUserPII(context.Background(), "u-2"); err != nil {
		t.Fatalf("second DeleteUserPII: %v", err)
	}
	second, _ := users.Get(context.Background(), "u-2")

	// oidc_subject doesn't get re-hashed (prefix guard).
	if first.OIDCSubject != second.OIDCSubject {
		t.Errorf("idempotent re-scrub re-hashed oidc_subject: %q -> %q",
			first.OIDCSubject, second.OIDCSubject)
	}
	if !strings.HasPrefix(second.OIDCSubject, "sha256:") {
		t.Errorf("scrubbed oidc_subject lost prefix: %q", second.OIDCSubject)
	}
}

// TestPurgeDeactivatedUsers_RespectsWindow: only users whose
// deactivated_at is older than now-retentionWindow get scrubbed; rows
// deactivated within the window remain intact.
func TestPurgeDeactivatedUsers_RespectsWindow(t *testing.T) {
	t.Parallel()

	users := newRetentionStubUserRepo()
	sessions := &retentionStubSessionRepo{}
	now := time.Now()
	stale := now.Add(-45 * 24 * time.Hour) // past 30d window
	recent := now.Add(-7 * 24 * time.Hour) // inside 30d window
	users.seed(newTestUser("u-stale", "stale@example.com", "Stale", "sub-stale", &stale))
	users.seed(newTestUser("u-recent", "recent@example.com", "Recent", "sub-recent", &recent))
	users.seed(newTestUser("u-active", "active@example.com", "Active", "sub-active", nil))

	svc := NewUserRetentionService(users, sessions, nil, discardLogger(), 30*24*time.Hour, 0)
	purged, failed, err := svc.PurgeDeactivatedUsers(context.Background())
	if err != nil {
		t.Fatalf("PurgeDeactivatedUsers: %v", err)
	}
	if purged != 1 {
		t.Errorf("expected 1 row purged, got %d", purged)
	}
	if failed != 0 {
		t.Errorf("expected 0 failures, got %d", failed)
	}

	staleU, _ := users.Get(context.Background(), "u-stale")
	if staleU.Email != "purged@redacted.local" {
		t.Errorf("stale row not scrubbed: %q", staleU.Email)
	}
	recentU, _ := users.Get(context.Background(), "u-recent")
	if recentU.Email != "recent@example.com" {
		t.Errorf("recent row should not have been scrubbed: %q", recentU.Email)
	}
	activeU, _ := users.Get(context.Background(), "u-active")
	if activeU.Email != "active@example.com" {
		t.Errorf("active row should not have been scrubbed: %q", activeU.Email)
	}
}

// TestPurgeDeactivatedUsers_BatchCap caps the per-tick blast radius.
func TestPurgeDeactivatedUsers_BatchCap(t *testing.T) {
	t.Parallel()

	users := newRetentionStubUserRepo()
	sessions := &retentionStubSessionRepo{}
	stale := time.Now().Add(-100 * 24 * time.Hour)
	for i := 0; i < 5; i++ {
		id := "u-cap-" + string(rune('0'+i))
		users.seed(newTestUser(id, id+"@example.com", id, "sub-"+id, &stale))
	}

	svc := NewUserRetentionService(users, sessions, nil, discardLogger(), 30*24*time.Hour, 2)
	purged, failed, err := svc.PurgeDeactivatedUsers(context.Background())
	if err != nil {
		t.Fatalf("PurgeDeactivatedUsers: %v", err)
	}
	if purged != 2 {
		t.Errorf("expected exactly 2 rows purged (batch cap = 2), got %d", purged)
	}
	if failed != 0 {
		t.Errorf("expected 0 failures, got %d", failed)
	}
}

// _ guard for unused-import lint when one of the helpers above is
// removed during future refactors.
var _ = domain.ActorTypeUser
