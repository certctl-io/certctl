package config

import (
	"strings"
	"testing"
)

// Audit L-004 (CWE-924): graceful API key rotation overlap window.
// Pre-bundle ParseNamedAPIKeys rejected duplicate names. Post-bundle
// duplicates are allowed iff the admin flag matches across entries —
// this gives operators a zero-downtime rotation primitive without
// requiring schema, GUI, or DB-resident key storage.
//
// These tests pin the contract end-to-end through ParseNamedAPIKeys.
// The auth-middleware side is exercised separately in
// internal/api/middleware via auth_l004_rotation_test.go.

func TestL004_DualKeyRotation_SameAdmin_Accepted(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"both_admin", "alice:OLDKEY:admin,alice:NEWKEY:admin"},
		{"both_non_admin", "ci-runner:OLD,ci-runner:NEW"},
		{"three_keys_admin", "ops:K1:admin,ops:K2:admin,ops:K3:admin"},
		{"mixed_with_other_users", "alice:OLDKEY:admin,bob:UNRELATED,alice:NEWKEY:admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := ParseNamedAPIKeys(tc.input)
			if err != nil {
				t.Fatalf("expected dual-key rotation to parse, got error: %v", err)
			}
			if len(keys) < 2 {
				t.Errorf("expected ≥2 entries, got %d", len(keys))
			}
		})
	}
}

func TestL004_DualKeyRotation_AdminMismatch_Rejected(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"first_admin_then_user", "alice:OLD:admin,alice:NEW"},
		{"first_user_then_admin", "alice:OLD,alice:NEW:admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseNamedAPIKeys(tc.input)
			if err == nil {
				t.Fatal("expected admin-flag mismatch to be rejected")
			}
			if !strings.Contains(err.Error(), "mismatched admin flag") {
				t.Errorf("error must cite admin flag mismatch, got: %v", err)
			}
		})
	}
}

func TestL004_DualKeyRotation_IdenticalNameAndKey_Rejected(t *testing.T) {
	// Same name + same key is a typo, not a rotation. The rotation
	// case is DIFFERENT keys under the same name.
	_, err := ParseNamedAPIKeys("alice:SAMEKEY:admin,alice:SAMEKEY:admin")
	if err == nil {
		t.Fatal("expected (name,key) duplicate to be rejected")
	}
	if !strings.Contains(err.Error(), "duplicate (name,key)") {
		t.Errorf("error must cite (name,key) duplicate, got: %v", err)
	}
}

func TestL004_DualKeyRotation_SteadyStateUnchanged(t *testing.T) {
	// Single-key (no rotation) and multi-distinct-name configs must
	// continue to parse the same way they did pre-bundle.
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{"single", "alice:KEY:admin", 1},
		{"two_distinct_names", "alice:KEY1:admin,bob:KEY2", 2},
		{"three_distinct_names", "alice:K1:admin,bob:K2,carol:K3:admin", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := ParseNamedAPIKeys(tc.input)
			if err != nil {
				t.Fatalf("steady-state parse failed: %v", err)
			}
			if len(keys) != tc.want {
				t.Errorf("got %d entries, want %d", len(keys), tc.want)
			}
		})
	}
}

func TestL004_DualKeyRotation_PreservesAllEntries(t *testing.T) {
	// Round-trip: every input entry must appear in the parsed output.
	keys, err := ParseNamedAPIKeys("alice:OLDKEY:admin,alice:NEWKEY:admin")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d, want 2", len(keys))
	}
	gotKeys := map[string]bool{keys[0].Key: true, keys[1].Key: true}
	for _, want := range []string{"OLDKEY", "NEWKEY"} {
		if !gotKeys[want] {
			t.Errorf("missing key %q in parsed entries: %+v", want, keys)
		}
	}
	for _, k := range keys {
		if k.Name != "alice" {
			t.Errorf("entry %+v has wrong name; want alice", k)
		}
		if !k.Admin {
			t.Errorf("entry %+v lost admin flag", k)
		}
	}
}
