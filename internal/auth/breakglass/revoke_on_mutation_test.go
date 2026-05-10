package breakglass

import (
	"context"
	"errors"
	"testing"

	bgdomain "github.com/certctl-io/certctl/internal/auth/breakglass/domain"
)

// Audit 2026-05-10 HIGH-1 closure — regression tests pinning the
// wire from break-glass mutations to SessionMinter.RevokeAllForActor.
// Pre-fix, SetPassword and RemoveCredential rotated the password /
// removed the row but left active sessions for the target actor alive
// (CWE-613). The fix calls RevokeAllForActor(targetActorID, "User")
// best-effort after each mutation.

func TestService_SetPassword_RevokesExistingSessions(t *testing.T) {
	svc, repo, _, sess := newSvc(t, true)
	// Seed: target actor already has a break-glass credential.
	repo.rows["u-target"] = &bgdomain.BreakglassCredential{
		ID: "bg-target", TenantID: "t-default", ActorID: "u-target", PasswordHash: "$argon2id$old",
	}

	if _, err := svc.SetPassword(context.Background(), "u-admin", "u-target", "new-password-12345"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	if len(sess.revokeAllIDs) != 1 || sess.revokeAllIDs[0] != "u-target" {
		t.Errorf("expected RevokeAllForActor(u-target); got %v", sess.revokeAllIDs)
	}
	if len(sess.revokeAllTypes) != 1 || sess.revokeAllTypes[0] != "User" {
		t.Errorf("expected actor_type=User; got %v", sess.revokeAllTypes)
	}
}

func TestService_RemoveCredential_RevokesExistingSessions(t *testing.T) {
	svc, repo, _, sess := newSvc(t, true)
	repo.rows["u-target"] = &bgdomain.BreakglassCredential{
		ID: "bg-target", TenantID: "t-default", ActorID: "u-target", PasswordHash: "$argon2id$x",
	}

	if err := svc.RemoveCredential(context.Background(), "u-admin", "u-target"); err != nil {
		t.Fatalf("RemoveCredential: %v", err)
	}
	if len(sess.revokeAllIDs) != 1 || sess.revokeAllIDs[0] != "u-target" {
		t.Errorf("expected RevokeAllForActor(u-target); got %v", sess.revokeAllIDs)
	}
}

// TestService_SetPassword_RevokeFailureDoesNotRollback pins the
// best-effort contract: if RevokeAllForActor errors, the password
// rotation itself still SUCCEEDS (the operator rotated for a reason,
// forcing rollback opens a worse window). The failure is logged +
// audited but not surfaced to the caller.
func TestService_SetPassword_RevokeFailureDoesNotRollback(t *testing.T) {
	svc, repo, _, sess := newSvc(t, true)
	repo.rows["u-target"] = &bgdomain.BreakglassCredential{
		ID: "bg-target", TenantID: "t-default", ActorID: "u-target", PasswordHash: "$argon2id$old",
	}
	sess.revokeAllErr = errors.New("transient db reset")

	res, err := svc.SetPassword(context.Background(), "u-admin", "u-target", "new-password-12345")
	if err != nil {
		t.Fatalf("SetPassword should succeed even when revoke fails; got %v", err)
	}
	if res == nil || res.ActorID != "u-target" {
		t.Fatalf("expected result with actor_id=u-target; got %+v", res)
	}
	// RevokeAllForActor WAS attempted.
	if len(sess.revokeAllIDs) != 1 {
		t.Errorf("expected RevokeAllForActor attempted; got %v", sess.revokeAllIDs)
	}
}
