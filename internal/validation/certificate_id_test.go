// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package validation

import (
	"strings"
	"testing"
)

// SEC-002 closure (Sprint 1, 2026-05-16). Pin the server-side
// certificate_id shape gate. Companion to the agent-side
// safeAgentKeyPath containment check in cmd/agent/keymem.go.

func TestValidateCertificateID_AcceptsProductionShapes(t *testing.T) {
	cases := []string{
		"mc-cdn-edge",
		"mc-cdn-edge-2026.q1",
		"mc_internal_api",
		"abc123",
		"MC-UPPER-CASE",
		strings.Repeat("a", 128), // exact-length boundary
	}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			if err := ValidateCertificateID(id); err != nil {
				t.Errorf("ValidateCertificateID(%q): unexpected error %v", id, err)
			}
		})
	}
}

func TestValidateCertificateID_RejectsEmpty(t *testing.T) {
	if err := ValidateCertificateID(""); err == nil {
		t.Errorf("empty id: expected rejection, got nil")
	}
}

func TestValidateCertificateID_RejectsOverlong(t *testing.T) {
	id := strings.Repeat("a", 129)
	err := ValidateCertificateID(id)
	if err == nil {
		t.Fatalf("overlong id: expected rejection, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds 128") {
		t.Errorf("expected length error, got %v", err)
	}
}

// TestValidateCertificateID_RejectsPathTraversalVectors pins the four
// vectors called out in SEC-002 (../../etc/passwd, /absolute/path,
// NUL-byte, Windows separators) plus the bare ".." token.
func TestValidateCertificateID_RejectsPathTraversalVectors(t *testing.T) {
	cases := []struct {
		name string
		id   string
	}{
		{"posix_traversal", "../../etc/passwd"},
		{"absolute_posix", "/absolute/path"},
		{"absolute_root", "/"},
		{"parent_token", ".."},
		{"current_token", "."},
		{"windows_traversal", `..\..\evil`},
		{"windows_separator", `bad\path`},
		{"nul_byte", "abc\x00def"},
		{"newline_injection", "abc\ndef"},
		{"tab_injection", "abc\tdef"},
		{"colon_drive", "C:\\Windows"},
		{"space_inside", "id with spaces"},
		{"unicode_dots", "abc․def"}, // U+2024 ONE DOT LEADER — looks like .
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateCertificateID(tc.id); err == nil {
				t.Errorf("id=%q: expected rejection, got nil", tc.id)
			}
		})
	}
}
