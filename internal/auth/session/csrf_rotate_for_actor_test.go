package session

import (
	"context"
	"testing"
	"time"

	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
)

// Audit 2026-05-10 HIGH-2 closure — regression test pinning
// RotateCSRFTokenForActor. Pre-fix the rotate primitive existed but
// was only called at login mint; this method now rotates across every
// active (non-revoked, non-expired) session of an actor for the
// role-mutation defense-in-depth path.

func TestRotateCSRFTokenForActor_RotatesAllActiveRows(t *testing.T) {
	svc, repo, _, _, _ := newTestService(t, defaultCfg())

	now := time.Now().UTC()
	// 3 active sessions for u-alice.
	for _, id := range []string{"s-a-1", "s-a-2", "s-a-3"} {
		repo.rows[id] = &sessiondomain.Session{
			ID: id, TenantID: "t-default",
			ActorID: "u-alice", ActorType: "User",
			IdleExpiresAt:     now.Add(1 * time.Hour),
			AbsoluteExpiresAt: now.Add(8 * time.Hour),
			CSRFTokenHash:     "old-hash-" + id,
		}
	}
	// 1 revoked row — should NOT be rotated.
	revokedAt := now.Add(-1 * time.Minute)
	repo.rows["s-a-revoked"] = &sessiondomain.Session{
		ID: "s-a-revoked", TenantID: "t-default",
		ActorID: "u-alice", ActorType: "User",
		IdleExpiresAt: now.Add(1 * time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
		CSRFTokenHash: "stale",
		RevokedAt:     &revokedAt,
	}
	// 1 expired row — should NOT be rotated.
	repo.rows["s-a-expired"] = &sessiondomain.Session{
		ID: "s-a-expired", TenantID: "t-default",
		ActorID: "u-alice", ActorType: "User",
		IdleExpiresAt:     now.Add(-1 * time.Minute), // expired
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
		CSRFTokenHash:     "stale",
	}
	// 2 rows for a DIFFERENT actor — should NOT be rotated.
	for _, id := range []string{"s-b-1", "s-b-2"} {
		repo.rows[id] = &sessiondomain.Session{
			ID: id, TenantID: "t-default",
			ActorID: "u-bob", ActorType: "User",
			IdleExpiresAt: now.Add(1 * time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
			CSRFTokenHash: "bob-hash",
		}
	}

	rotated := svc.RotateCSRFTokenForActor(context.Background(), "u-alice", "User")
	if rotated != 3 {
		t.Fatalf("rotated count = %d; want 3 (3 active alice rows; revoked + expired + bob skipped)", rotated)
	}

	// Confirm: the 3 active alice rows now have NEW CSRF hashes.
	for _, id := range []string{"s-a-1", "s-a-2", "s-a-3"} {
		row := repo.rows[id]
		if row.CSRFTokenHash == "old-hash-"+id || row.CSRFTokenHash == "" {
			t.Errorf("session %s CSRF hash not rotated (still %q)", id, row.CSRFTokenHash)
		}
	}
	// Bob's rows: untouched.
	for _, id := range []string{"s-b-1", "s-b-2"} {
		if repo.rows[id].CSRFTokenHash != "bob-hash" {
			t.Errorf("bob's session %s CSRF was rotated; should not be", id)
		}
	}
}

func TestRotateCSRFTokenForActor_NoSessionsReturnsZero(t *testing.T) {
	svc, _, _, _, _ := newTestService(t, defaultCfg())

	got := svc.RotateCSRFTokenForActor(context.Background(), "u-no-sessions", "User")
	if got != 0 {
		t.Errorf("got %d; want 0", got)
	}
}
