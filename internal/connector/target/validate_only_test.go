package target

import (
	"errors"
	"testing"
)

// Phase 3 of the deploy-hardening I master bundle: pin the
// ErrValidateOnlyNotSupported sentinel contract. Connectors
// returning this from ValidateOnly indicate they cannot dry-run
// (e.g. K8s — no API for "would this Secret update succeed?").
//
// Every connector compile-time-implements ValidateOnly via the
// per-package validate_only.go stub; Phases 4-9 replace the stub
// with a real validate-with-the-target implementation per
// connector. Until then the sentinel is the contract.

// TestErrValidateOnlyNotSupported_Sentinel pins the sentinel's
// identity and message so downstream connectors can rely on
// errors.Is checks.
func TestErrValidateOnlyNotSupported_Sentinel(t *testing.T) {
	if ErrValidateOnlyNotSupported == nil {
		t.Fatal("sentinel is nil")
	}
	if !errors.Is(ErrValidateOnlyNotSupported, ErrValidateOnlyNotSupported) {
		t.Fatal("errors.Is fails on the sentinel against itself")
	}
	want := "target connector does not support ValidateOnly dry-run"
	if got := ErrValidateOnlyNotSupported.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestErrValidateOnlyNotSupported_WrappableForCallerContext
// confirms callers can wrap the sentinel with extra context (e.g.
// "k8s: ValidateOnly: ErrValidateOnlyNotSupported") and the
// wrapped error still satisfies errors.Is for the operator's
// triage logic.
func TestErrValidateOnlyNotSupported_WrappableForCallerContext(t *testing.T) {
	wrapped := errors.New("connector wraps with extra info: " + ErrValidateOnlyNotSupported.Error())
	// errors.Is should NOT match a wrapped-by-string copy (no %w).
	if errors.Is(wrapped, ErrValidateOnlyNotSupported) {
		t.Error("errors.Is matched a string-wrapped copy; should require %w wrap")
	}
	// %w wrap MUST match.
	properly := wrapErr(ErrValidateOnlyNotSupported, "k8s")
	if !errors.Is(properly, ErrValidateOnlyNotSupported) {
		t.Error("errors.Is failed to match %w-wrapped sentinel")
	}
}

// wrapErr is a small test-only helper proving the %w pattern.
func wrapErr(err error, ctx string) error {
	return &wrappedErr{ctx: ctx, err: err}
}

type wrappedErr struct {
	ctx string
	err error
}

func (w *wrappedErr) Error() string { return w.ctx + ": " + w.err.Error() }
func (w *wrappedErr) Unwrap() error { return w.err }
