package service

import (
	"errors"
	"fmt"
	"testing"
)

// TestGenericSentinels_IdentityDistinct guards against an accidental
// `var ErrX = ErrY` alias where two generic sentinels share identity. Each
// must be a distinct error value so errors.Is dispatch in errToStatus can
// route them to different HTTP status codes.
func TestGenericSentinels_IdentityDistinct(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrNotFound", ErrNotFound},
		{"ErrValidation", ErrValidation},
		{"ErrConflict", ErrConflict},
		{"ErrForbidden", ErrForbidden},
		{"ErrUnauthenticated", ErrUnauthenticated},
		{"ErrNotImplemented", ErrNotImplemented},
	}
	for i := range sentinels {
		for j := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(sentinels[i].err, sentinels[j].err) {
				t.Errorf("%s and %s alias the same error value — each generic sentinel must be distinct",
					sentinels[i].name, sentinels[j].name)
			}
		}
	}
}

// TestWrappedSentinels_ChainWalk is the core M-1 invariant: wrapping a
// domain-specific sentinel under a generic sentinel via fmt.Errorf("%w: ...")
// must preserve BOTH identities on the wrap chain. Call sites that check
// errors.Is(err, ErrSelfApproval) for domain logic AND the handler-layer
// errToStatus that checks errors.Is(err, ErrForbidden) for the HTTP status
// both need to succeed on the same error value.
//
// If this test fails, every handler dispatch that routes through errToStatus
// is silently broken.
func TestWrappedSentinels_ChainWalk(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		generic error
	}{
		{"ErrSelfApproval wraps ErrForbidden", ErrSelfApproval, ErrForbidden},
		{"ErrAgentIsSentinel wraps ErrForbidden", ErrAgentIsSentinel, ErrForbidden},
		{"ErrBlockedByDependencies wraps ErrConflict", ErrBlockedByDependencies, ErrConflict},
		{"ErrForceReasonRequired wraps ErrValidation", ErrForceReasonRequired, ErrValidation},
		{"ErrAgentNotFound wraps ErrValidation", ErrAgentNotFound, ErrValidation},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !errors.Is(c.err, c.generic) {
				t.Errorf("errors.Is(%v, %v) = false; want true", c.err, c.generic)
			}
			if !errors.Is(c.err, c.err) {
				t.Errorf("errors.Is(err, err) = false; want true — domain sentinel lost self-identity after wrap")
			}
		})
	}
}

// TestErrAgentRetired_StandaloneGone locks the 410 Gone semantics in place.
// ErrAgentRetired MUST NOT wrap any generic sentinel — 410 is semantically
// distinct from 403/404/409 (permanently-terminated resource identity) and
// the errToStatus dispatch tests it FIRST before any generic check. If this
// test goes red because someone wrapped it under ErrForbidden or ErrNotFound,
// the agent-binary shutdown behavior at cmd/agent/main.go:1291 silently
// regresses.
func TestErrAgentRetired_StandaloneGone(t *testing.T) {
	if errors.Is(ErrAgentRetired, ErrForbidden) {
		t.Error("ErrAgentRetired must NOT wrap ErrForbidden — 410 Gone would demote to 403")
	}
	if errors.Is(ErrAgentRetired, ErrNotFound) {
		t.Error("ErrAgentRetired must NOT wrap ErrNotFound — 410 Gone would demote to 404")
	}
	if errors.Is(ErrAgentRetired, ErrConflict) {
		t.Error("ErrAgentRetired must NOT wrap ErrConflict — 410 Gone would demote to 409")
	}
	if errors.Is(ErrAgentRetired, ErrValidation) {
		t.Error("ErrAgentRetired must NOT wrap ErrValidation — 410 Gone would demote to 400")
	}
	if !errors.Is(ErrAgentRetired, ErrAgentRetired) {
		t.Error("ErrAgentRetired lost self-identity")
	}
}

// TestSentinels_SurviveDoubleWrap verifies that wrapping a sentinel-wrapped
// error a SECOND time (e.g., a call site doing fmt.Errorf("%w: ctx-info",
// ErrSelfApproval)) preserves both the domain sentinel and the generic
// sentinel. This is critical because the errToStatus dispatch order places
// ErrForbidden BEFORE ErrValidation — if double-wrapping broke the chain,
// the M-003 gate would demote to 400.
func TestSentinels_SurviveDoubleWrap(t *testing.T) {
	doubled := fmt.Errorf("%w: additional context from call site", ErrSelfApproval)
	if !errors.Is(doubled, ErrSelfApproval) {
		t.Error("double-wrapped ErrSelfApproval lost domain identity")
	}
	if !errors.Is(doubled, ErrForbidden) {
		t.Error("double-wrapped ErrSelfApproval lost ErrForbidden wrap — M-003 gate would demote to 500")
	}
}
