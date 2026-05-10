package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/certctl-io/certctl/internal/auth"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
)

// fakeGranter is a tiny in-memory stand-in for the postgres ActorRoleRepository
// — enough surface area for backfillNamedKeyActorRoles to call Grant against.
type fakeGranter struct {
	calls []*authdomain.ActorRole
	err   error
}

func (f *fakeGranter) Grant(_ context.Context, ar *authdomain.ActorRole) error {
	f.calls = append(f.calls, ar)
	return f.err
}

// TestBackfillNamedKeyActorRoles_RoleMapping pins the Bundle 1 Phase 3
// closure (C2) invariant: admin-flagged named keys grant r-admin,
// non-admin keys grant r-viewer, both at TenantID t-default with
// ActorType APIKey and GrantedBy=bootstrap.
func TestBackfillNamedKeyActorRoles_RoleMapping(t *testing.T) {
	repo := &fakeGranter{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	keys := []auth.NamedAPIKey{
		{Name: "alice-admin", Key: "AAA", Admin: true},
		{Name: "bob-viewer", Key: "BBB", Admin: false},
		{Name: "carol-admin", Key: "CCC", Admin: true},
	}
	backfillNamedKeyActorRoles(context.Background(), repo, keys, logger)

	if len(repo.calls) != 3 {
		t.Fatalf("Grant call count = %d, want 3", len(repo.calls))
	}
	type want struct {
		actor, role string
	}
	wants := []want{
		{actor: "alice-admin", role: authdomain.RoleIDAdmin},
		{actor: "bob-viewer", role: authdomain.RoleIDViewer},
		{actor: "carol-admin", role: authdomain.RoleIDAdmin},
	}
	for i, w := range wants {
		got := repo.calls[i]
		if got.ActorID != w.actor {
			t.Errorf("call[%d].ActorID = %q, want %q", i, got.ActorID, w.actor)
		}
		if got.RoleID != w.role {
			t.Errorf("call[%d].RoleID = %q, want %q", i, got.RoleID, w.role)
		}
		if got.TenantID != authdomain.DefaultTenantID {
			t.Errorf("call[%d].TenantID = %q, want %q", i, got.TenantID, authdomain.DefaultTenantID)
		}
		if string(got.ActorType) != "APIKey" {
			t.Errorf("call[%d].ActorType = %q, want APIKey", i, got.ActorType)
		}
		if got.GrantedBy != "bootstrap" {
			t.Errorf("call[%d].GrantedBy = %q, want bootstrap", i, got.GrantedBy)
		}
	}
}

// TestBackfillNamedKeyActorRoles_EmptyKeysIsNoOp confirms the boot path
// is safe when no named keys are configured (typical CERTCTL_AUTH_TYPE=
// none deploy). No Grant calls; no panic.
func TestBackfillNamedKeyActorRoles_EmptyKeysIsNoOp(t *testing.T) {
	repo := &fakeGranter{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backfillNamedKeyActorRoles(context.Background(), repo, nil, logger)
	if len(repo.calls) != 0 {
		t.Errorf("Grant called %d times for empty keys, want 0", len(repo.calls))
	}
}

// TestBackfillNamedKeyActorRoles_GrantErrorIsNonFatal confirms the
// closure invariant that a Grant failure logs a warning and proceeds
// rather than crashing the server during boot. Subsequent keys still
// get processed.
func TestBackfillNamedKeyActorRoles_GrantErrorIsNonFatal(t *testing.T) {
	repo := &fakeGranter{err: errors.New("simulated DB error")}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	keys := []auth.NamedAPIKey{
		{Name: "alice", Key: "A", Admin: true},
		{Name: "bob", Key: "B", Admin: false},
	}
	// Should not panic.
	backfillNamedKeyActorRoles(context.Background(), repo, keys, logger)

	if len(repo.calls) != 2 {
		t.Errorf("Grant calls = %d, want 2 (every key processed even when prior Grant errored)", len(repo.calls))
	}
}

// TestBackfillNamedKeyActorRoles_NilLoggerIsSafe pins that callers
// passing nil for the logger don't NPE the goroutine. Belt-and-braces
// for tests + future call sites that may not have a logger plumbed.
func TestBackfillNamedKeyActorRoles_NilLoggerIsSafe(t *testing.T) {
	repo := &fakeGranter{err: errors.New("simulated")}
	keys := []auth.NamedAPIKey{
		{Name: "alice", Key: "A", Admin: true},
	}
	backfillNamedKeyActorRoles(context.Background(), repo, keys, nil)
	if len(repo.calls) != 1 {
		t.Errorf("Grant calls = %d, want 1", len(repo.calls))
	}
}
