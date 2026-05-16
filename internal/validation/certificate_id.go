// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package validation

// SEC-002 closure (Sprint 1, 2026-05-16). The agent derives an on-disk
// key path from `job.CertificateID` via filepath.Join:
//
//   keyPath := filepath.Join(a.config.KeyDir, job.CertificateID+".key")
//
// migrations/000001_initial_schema.up.sql declares managed_certificates.id
// as TEXT PRIMARY KEY with no shape constraint, so a compromised control
// plane (or a crafted row in the database) could deliver a job whose
// certificate_id is "../../etc/passwd", "/absolute/path", a NUL-byte
// payload, or a Windows-separator-laden string — driving arbitrary
// file write/read on the agent host.
//
// ValidateCertificateID is the server-side shape gate. It pins the
// canonical TEXT-PK prefix convention used across certctl (lowercase
// alphanumeric + `_-`, bounded length) and rejects everything else
// before the row reaches the database or a downstream agent. The
// agent host owns a symmetric containment check via safeAgentKeyPath
// in cmd/agent/keymem.go — both ends MUST hold for the load-bearing
// defense.

import (
	"fmt"
	"regexp"
)

// certificateIDPattern is the canonical shape for managed_certificates.id.
// Permits ASCII letters, digits, underscore, hyphen, and dot (so existing
// rows like "mc-cdn-edge-2026.q1" continue to validate). Length capped at
// 128 — well beyond any human-readable identifier and short enough that
// a path built from it stays within typical filesystem path limits.
//
// Deliberately rejects:
//   - "/"  and "\\"  (path separators on POSIX + Windows)
//   - ".." (relative-path escape token)
//   - "\x00"          (NUL byte truncates the path on many syscalls)
//   - whitespace / control characters
//   - the empty string
//
// Existing prefixed IDs in production (`mc-…`, `t-…`, `o-…`, etc.) all
// satisfy this pattern.
var certificateIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ValidateCertificateID returns an error if id is not a well-formed
// certificate identifier. Callers MUST run this before passing the id
// to any filesystem-touching code path.
func ValidateCertificateID(id string) error {
	if id == "" {
		return fmt.Errorf("certificate_id is required")
	}
	if len(id) > 128 {
		return fmt.Errorf("certificate_id length %d exceeds 128", len(id))
	}
	if !certificateIDPattern.MatchString(id) {
		return fmt.Errorf("certificate_id %q contains disallowed characters; allowed: A-Z a-z 0-9 . _ -", id)
	}
	// Defense-in-depth: even within the allowed set, ".." would slip
	// through the regex. Reject it explicitly.
	if id == ".." || id == "." {
		return fmt.Errorf("certificate_id %q is a relative-path token", id)
	}
	return nil
}
