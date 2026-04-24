// Internal-package tests for db.go — covers the diagnostic dispatch in
// wrapPingError. Lives in `package postgres` (not `postgres_test`) so it can
// call the unexported helper directly without exposing it on the API surface.
//
// Sibling integration tests in this directory live in `package postgres_test`
// (testcontainers-driven, schema-per-test). They exercise the live-DB
// happy path; this file owns the unit-level diagnostic dispatch and runs in
// `-short` mode without spinning up postgres.
//
// U-1 (P1, GitHub #10): closes the audit-flagged
// cat-u-quickstart_postgres_password_volume_trap finding by pinning the
// post-fix wrap-text contract for `db.Ping()` failures. Pre-U-1 every Ping
// error was wrapped with the same opaque `"failed to ping database: %w"`,
// so an operator who edited POSTGRES_PASSWORD after first-boot saw only
// `pq: password authentication failed for user "certctl"` in the server
// log with no pointer to the actual cause (postgres data dir retains the
// initial password from first-boot initdb; subsequent boots ignore the env
// var). Post-U-1 the SQLSTATE-28P01 path emits a multi-line diagnostic
// pointing at the down -v / ALTER ROLE remediation; non-auth failures
// retain the original wrap shape so verbose noise does not bleed into
// transient connection-refused / timeout paths.
package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/lib/pq"
)

// TestWrapPingError_AuthFailureGuidance asserts the diagnostic wrap fires on
// SQLSTATE 28P01 (invalid_password) and contains all three contract elements:
// the SQLSTATE code (so operators can grep), the down-v destructive
// remediation, and the ALTER ROLE non-destructive remediation. Also asserts
// the wrap chain still satisfies errors.As(err, &*pq.Error) so callers that
// programmatically inspect the underlying postgres error code keep working.
func TestWrapPingError_AuthFailureGuidance(t *testing.T) {
	t.Parallel()

	original := &pq.Error{
		Code:    pq.ErrorCode("28P01"),
		Message: `password authentication failed for user "certctl"`,
	}

	wrapped := wrapPingError(original)
	if wrapped == nil {
		t.Fatal("wrapPingError returned nil for a non-nil input")
	}

	got := wrapped.Error()

	// Contract elements — the operator-facing string is what we ship.
	wantSubstrings := []string{
		"SQLSTATE 28P01",                       // operators grep on this
		"POSTGRES_PASSWORD",                    // names the variable that traps
		"first boot",                           // the mechanism in plain language
		"down -v",                              // destructive remediation
		"ALTER ROLE",                           // non-destructive remediation
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(got, s) {
			t.Errorf("wrap text missing %q\ngot: %s", s, got)
		}
	}

	// Wrap chain must still expose the underlying *pq.Error for callers
	// that want to inspect Code / Detail / Constraint fields. Pre-fix
	// callers used errors.As(err, &pqErr) on the unwrapped Ping result;
	// the new wrap is fmt.Errorf("...%w", err) so errors.As must walk it.
	var pqErr *pq.Error
	if !errors.As(wrapped, &pqErr) {
		t.Fatalf("errors.As did not extract *pq.Error from wrapped chain: %v", wrapped)
	}
	if pqErr.Code != "28P01" {
		t.Errorf("extracted pq.Error.Code = %q, want %q", pqErr.Code, "28P01")
	}
}

// TestWrapPingError_NonAuthErrorPreservesOriginalWrap guards against the
// guidance text bleeding into unrelated failure modes. SQLSTATE 08006
// (connection_failure) is the canonical non-auth case — server unreachable,
// TLS handshake failure, network drop. The wrap should be the original
// shape so transient-error log noise does not include the (now lengthy)
// volume-state remediation paragraph.
func TestWrapPingError_NonAuthErrorPreservesOriginalWrap(t *testing.T) {
	t.Parallel()

	original := &pq.Error{
		Code:    pq.ErrorCode("08006"),
		Message: "connection refused",
	}

	wrapped := wrapPingError(original)
	if wrapped == nil {
		t.Fatal("wrapPingError returned nil for a non-nil input")
	}

	got := wrapped.Error()

	// Original-wrap shape: prefix only, no guidance text.
	const wantPrefix = "failed to ping database: "
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("expected prefix %q, got: %s", wantPrefix, got)
	}

	// Negative assertions: guidance text MUST NOT appear on non-auth paths.
	mustNotContain := []string{
		"SQLSTATE 08006", // we only call out 28P01 specifically
		"POSTGRES_PASSWORD",
		"down -v",
		"ALTER ROLE",
	}
	for _, s := range mustNotContain {
		if strings.Contains(got, s) {
			t.Errorf("non-auth wrap leaked guidance substring %q\ngot: %s", s, got)
		}
	}

	// Wrap chain still walks for errors.As — same contract as auth path.
	var pqErr *pq.Error
	if !errors.As(wrapped, &pqErr) {
		t.Fatalf("errors.As did not extract *pq.Error from non-auth wrapped chain: %v", wrapped)
	}
	if pqErr.Code != "08006" {
		t.Errorf("extracted pq.Error.Code = %q, want %q", pqErr.Code, "08006")
	}
}

// TestWrapPingError_NonPqErrorPreservesOriginalWrap guards the network-level
// case: a pre-handshake failure (TCP refused, DNS, TLS) returns a
// non-*pq.Error from db.Ping(). errors.As must return false, the helper
// must fall through to the generic wrap, and the chain must remain walkable.
func TestWrapPingError_NonPqErrorPreservesOriginalWrap(t *testing.T) {
	t.Parallel()

	original := errors.New("dial tcp 127.0.0.1:5432: connect: connection refused")

	wrapped := wrapPingError(original)
	if wrapped == nil {
		t.Fatal("wrapPingError returned nil for a non-nil input")
	}

	got := wrapped.Error()

	const wantPrefix = "failed to ping database: "
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("expected prefix %q, got: %s", wantPrefix, got)
	}
	if strings.Contains(got, "SQLSTATE") || strings.Contains(got, "POSTGRES_PASSWORD") {
		t.Errorf("network-level wrap leaked SQLSTATE/postgres guidance\ngot: %s", got)
	}
	if !errors.Is(wrapped, original) {
		t.Errorf("errors.Is did not walk to original sentinel: %v", wrapped)
	}
}

// TestWrapPingError_NilReturnsNil — defensive contract: if Ping returned nil
// (no failure), the helper must not synthesize a fake error. This isn't on
// the documented call path (NewDB only invokes wrapPingError inside the
// `if err != nil` branch), but pinning it prevents a future refactor from
// regressing the contract silently.
func TestWrapPingError_NilReturnsNil(t *testing.T) {
	t.Parallel()
	if got := wrapPingError(nil); got != nil {
		t.Errorf("wrapPingError(nil) = %v, want nil", got)
	}
}
