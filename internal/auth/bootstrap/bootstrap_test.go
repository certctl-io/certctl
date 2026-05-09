package bootstrap

import (
	"context"
	"errors"
	"testing"
)

// TestEnvTokenStrategy_EmptyTokenIsBornDisabled pins the load-bearing
// invariant that an unset CERTCTL_BOOTSTRAP_TOKEN closes the bootstrap
// path at construction time. The handler depends on this — without it,
// a misconfigured deploy that forgot to set the env var would expose
// the endpoint with a token of "" that an attacker could trivially
// match by also sending "".
func TestEnvTokenStrategy_EmptyTokenIsBornDisabled(t *testing.T) {
	s := NewEnvTokenStrategy("", nil)
	avail, err := s.Available(context.Background())
	if err != nil {
		t.Fatalf("Available err = %v, want nil", err)
	}
	if avail {
		t.Errorf("Available = true for empty token, want false")
	}
	if got := s.Validate(context.Background(), ""); !errors.Is(got, ErrDisabled) {
		t.Errorf("Validate('') for empty-token strategy = %v, want ErrDisabled", got)
	}
	if got := s.Validate(context.Background(), "anything"); !errors.Is(got, ErrDisabled) {
		t.Errorf("Validate('anything') for empty-token strategy = %v, want ErrDisabled", got)
	}
}

// TestEnvTokenStrategy_WrongTokenReturnsInvalidToken pins that the
// strategy maps a token mismatch to ErrInvalidToken (HTTP 401), not
// ErrDisabled (410). Misclassifying these would let a probing attacker
// distinguish "no token set" from "wrong token" via response status.
func TestEnvTokenStrategy_WrongTokenReturnsInvalidToken(t *testing.T) {
	s := NewEnvTokenStrategy("correct-token", nil)
	if got := s.Validate(context.Background(), "wrong-token"); !errors.Is(got, ErrInvalidToken) {
		t.Errorf("Validate(wrong) = %v, want ErrInvalidToken", got)
	}
	if got := s.Validate(context.Background(), ""); !errors.Is(got, ErrInvalidToken) {
		t.Errorf("Validate('') = %v, want ErrInvalidToken", got)
	}
	if s.IsConsumed() {
		t.Errorf("strategy consumed after failed Validate; must remain available for retry")
	}
}

// TestEnvTokenStrategy_OneShotConsumption pins the invariant that the
// first valid Validate call locks the strategy. The bootstrap path is
// strictly one-shot; the second call MUST return ErrDisabled (HTTP
// 410), not ErrInvalidToken (which would suggest "wrong token, try
// again").
func TestEnvTokenStrategy_OneShotConsumption(t *testing.T) {
	s := NewEnvTokenStrategy("correct-token", nil)
	if err := s.Validate(context.Background(), "correct-token"); err != nil {
		t.Fatalf("first Validate = %v, want nil", err)
	}
	if !s.IsConsumed() {
		t.Errorf("IsConsumed = false after successful Validate, want true")
	}
	if got := s.Validate(context.Background(), "correct-token"); !errors.Is(got, ErrDisabled) {
		t.Errorf("second Validate = %v, want ErrDisabled", got)
	}
	avail, err := s.Available(context.Background())
	if err != nil {
		t.Fatalf("Available err = %v", err)
	}
	if avail {
		t.Errorf("Available = true after consumption, want false")
	}
}

// TestEnvTokenStrategy_AdminExistsClosesPath pins the invariant that
// the admin-existence probe gates Available + Validate. The strategy
// must NOT mint a second admin even if the operator forgot to unset
// CERTCTL_BOOTSTRAP_TOKEN after onboarding.
func TestEnvTokenStrategy_AdminExistsClosesPath(t *testing.T) {
	probe := func(_ context.Context) (bool, error) { return true, nil }
	s := NewEnvTokenStrategy("correct-token", probe)
	avail, err := s.Available(context.Background())
	if err != nil {
		t.Fatalf("Available err = %v", err)
	}
	if avail {
		t.Errorf("Available = true with admin exists probe, want false")
	}
	if got := s.Validate(context.Background(), "correct-token"); !errors.Is(got, ErrDisabled) {
		t.Errorf("Validate = %v with admin exists, want ErrDisabled", got)
	}
	if s.IsConsumed() {
		t.Errorf("strategy must NOT be consumed when admin-existence probe rejects; allows retry after operator removes the duplicate admin")
	}
}

// TestEnvTokenStrategy_AdminProbeError surfaces the error to the
// caller without consuming the strategy. The HTTP handler maps this
// to 500; the operator can retry once the underlying issue is fixed.
func TestEnvTokenStrategy_AdminProbeError(t *testing.T) {
	probeErr := errors.New("boom")
	probe := func(_ context.Context) (bool, error) { return false, probeErr }
	s := NewEnvTokenStrategy("correct-token", probe)
	if _, err := s.Available(context.Background()); !errors.Is(err, probeErr) {
		t.Errorf("Available err = %v, want probeErr", err)
	}
	if got := s.Validate(context.Background(), "correct-token"); !errors.Is(got, probeErr) {
		t.Errorf("Validate err = %v, want probeErr", got)
	}
	if s.IsConsumed() {
		t.Errorf("strategy must NOT be consumed on probe error")
	}
}

// TestEnvTokenStrategy_ZeroLengthRejectedEvenWithMatchingToken belt-
// and-braces against the ConstantTimeCompare("","")=1 footgun. A
// strategy explicitly constructed with token="" is born disabled
// (ErrDisabled); but if a future caller bypasses the constructor, the
// Validate path also rejects zero-length tokens up front.
func TestEnvTokenStrategy_ZeroLengthRejectedEvenWithMatchingToken(t *testing.T) {
	// Directly construct a strategy with token=""
	s := &EnvTokenStrategy{token: "", tokenLength: 0, consumed: false}
	if got := s.Validate(context.Background(), ""); !errors.Is(got, ErrInvalidToken) {
		t.Errorf("Validate('','') = %v, want ErrInvalidToken (zero-length guard)", got)
	}
}
