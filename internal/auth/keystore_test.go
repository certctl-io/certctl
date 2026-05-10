package auth

import (
	"context"
	"errors"
	"testing"
)

// =============================================================================
// Coverage-floor closure (post-Bundle-1 follow-on, 2026-05-09).
//
// CI run #486 caught internal/auth at 66.3% (CI global) / 72.8%
// (per-package), well below the 85 floor. The Phase 12 gate file
// claimed full negative-test coverage; turned out the keystore +
// HasPermission helper had zero tests. The tests below close the gap
// without lowering the gate. Each function listed had 0% coverage at
// the time of the closure:
//
//   StaticKeyStore.Len                0%
//   NewMutableKeyStore                0%
//   MutableKeyStore.LookupByHash      0%
//   MutableKeyStore.Add               0%
//   MutableKeyStore.AddHashed         0%
//   MutableKeyStore.Len               0%
//   HasPermission                     0%
// =============================================================================

func TestStaticKeyStore_LenReportsEntryCount(t *testing.T) {
	ks := NewStaticKeyStore([]NamedAPIKey{
		{Name: "alice", Key: "alice-key", Admin: true},
		{Name: "bob", Key: "bob-key", Admin: false},
	})
	if got := ks.Len(); got != 2 {
		t.Errorf("Len() = %d; want 2", got)
	}
}

func TestStaticKeyStore_LookupHitAndMiss(t *testing.T) {
	ks := NewStaticKeyStore([]NamedAPIKey{
		{Name: "alice", Key: "alice-key", Admin: true},
	})
	got, ok := ks.LookupByHash(HashAPIKey("alice-key"))
	if !ok {
		t.Fatalf("LookupByHash(alice-key) ok=false; want true")
	}
	if got.Name != "alice" || !got.Admin {
		t.Errorf("LookupByHash returned %+v; want alice/admin=true", got)
	}
	if _, ok := ks.LookupByHash(HashAPIKey("not-a-key")); ok {
		t.Errorf("LookupByHash(unknown) ok=true; want false")
	}
}

func TestMutableKeyStore_SeededLookupAndLen(t *testing.T) {
	ks := NewMutableKeyStore([]NamedAPIKey{
		{Name: "alice", Key: "alice-key", Admin: true},
	})
	if ks.Len() != 1 {
		t.Errorf("Len after construction = %d; want 1", ks.Len())
	}
	got, ok := ks.LookupByHash(HashAPIKey("alice-key"))
	if !ok {
		t.Fatalf("LookupByHash(alice-key) ok=false; want true")
	}
	if got.Name != "alice" || !got.Admin {
		t.Errorf("LookupByHash returned %+v; want alice/admin=true", got)
	}
	if _, ok := ks.LookupByHash(HashAPIKey("missing")); ok {
		t.Errorf("LookupByHash(missing) ok=true; want false")
	}
}

func TestMutableKeyStore_AddRegistersNewKey(t *testing.T) {
	ks := NewMutableKeyStore(nil)
	ks.Add(NamedAPIKey{Name: "carol", Key: "carol-key", Admin: false})
	if ks.Len() != 1 {
		t.Errorf("Len after Add = %d; want 1", ks.Len())
	}
	got, ok := ks.LookupByHash(HashAPIKey("carol-key"))
	if !ok || got.Name != "carol" {
		t.Errorf("LookupByHash after Add = (%+v, %v); want carol/true", got, ok)
	}
}

func TestMutableKeyStore_AddHashedRegistersFromPrecomputedHash(t *testing.T) {
	ks := NewMutableKeyStore(nil)
	hash := HashAPIKey("dan-key")
	ks.AddHashed("dan", hash, true)
	got, ok := ks.LookupByHash(hash)
	if !ok || got.Name != "dan" || !got.Admin {
		t.Errorf("LookupByHash(dan-hash) = (%+v, %v); want dan/admin=true", got, ok)
	}
}

func TestMutableKeyStore_AddHashedReplacesOnDuplicateHash(t *testing.T) {
	// Same hash submitted twice with different name/admin must replace
	// the existing entry in-place (idempotent boot-loader contract).
	ks := NewMutableKeyStore(nil)
	hash := HashAPIKey("eve-key")
	ks.AddHashed("eve", hash, false)
	ks.AddHashed("eve", hash, true) // same name, flipped admin
	if ks.Len() != 1 {
		t.Errorf("Len after duplicate-hash AddHashed = %d; want 1 (idempotent replace)", ks.Len())
	}
	got, _ := ks.LookupByHash(hash)
	if !got.Admin {
		t.Errorf("LookupByHash after second AddHashed: admin=%v; want true (replace took effect)", got.Admin)
	}
}

// =============================================================================
// HasPermission convenience helper — used by handlers that branch on a
// permission rather than 403'ing the whole request.
// =============================================================================

func TestHasPermission_NoActorReturnsErrNoActor(t *testing.T) {
	checker := &fakeChecker{check: func(_ context.Context, _, _, _, _, _ string, _ *string) (bool, error) {
		t.Fatalf("checker should not be called when no actor in context")
		return false, nil
	}}
	_, err := HasPermission(context.Background(), checker, "cert.read", "global", nil)
	if !errors.Is(err, ErrNoActor) {
		t.Errorf("HasPermission(no actor) err = %v; want ErrNoActor", err)
	}
}

func TestHasPermission_DefaultsActorTypeToAPIKey(t *testing.T) {
	var capturedActorType string
	checker := &fakeChecker{check: func(_ context.Context, _, actorType, _, _, _ string, _ *string) (bool, error) {
		capturedActorType = actorType
		return true, nil
	}}
	// Set actor ID but NOT actor type → should default to APIKey.
	ctx := context.WithValue(context.Background(), ActorIDKey{}, "alice")
	ok, err := HasPermission(ctx, checker, "cert.read", "global", nil)
	if err != nil {
		t.Fatalf("HasPermission err: %v", err)
	}
	if !ok {
		t.Errorf("HasPermission ok=false; want true")
	}
	if capturedActorType != ActorTypeAPIKey {
		t.Errorf("HasPermission defaulted actor type to %q; want %q", capturedActorType, ActorTypeAPIKey)
	}
}

func TestHasPermission_CheckerErrorPropagates(t *testing.T) {
	sentinel := errors.New("repo: down")
	checker := &fakeChecker{check: func(_ context.Context, _, _, _, _, _ string, _ *string) (bool, error) {
		return false, sentinel
	}}
	ctx := context.WithValue(context.Background(), ActorIDKey{}, "alice")
	ctx = context.WithValue(ctx, ActorTypeKey{}, ActorTypeAPIKey)
	_, err := HasPermission(ctx, checker, "cert.read", "global", nil)
	if !errors.Is(err, sentinel) {
		t.Errorf("HasPermission err = %v; want propagated sentinel", err)
	}
}

func TestHasPermission_ScopedCheckThreadsThrough(t *testing.T) {
	var capturedScopeType string
	var capturedScopeID *string
	checker := &fakeChecker{check: func(_ context.Context, _, _, _, _, scopeType string, scopeID *string) (bool, error) {
		capturedScopeType = scopeType
		capturedScopeID = scopeID
		return true, nil
	}}
	ctx := context.WithValue(context.Background(), ActorIDKey{}, "alice")
	ctx = context.WithValue(ctx, ActorTypeKey{}, ActorTypeAPIKey)
	scopeID := "p-corp"
	ok, err := HasPermission(ctx, checker, "profile.edit", "profile", &scopeID)
	if err != nil {
		t.Fatalf("HasPermission err: %v", err)
	}
	if !ok {
		t.Errorf("HasPermission ok=false; want true")
	}
	if capturedScopeType != "profile" {
		t.Errorf("scopeType captured = %q; want profile", capturedScopeType)
	}
	if capturedScopeID == nil || *capturedScopeID != "p-corp" {
		t.Errorf("scopeID captured = %v; want p-corp", capturedScopeID)
	}
}
