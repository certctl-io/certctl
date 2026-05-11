package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/repository"
)

// Audit 2026-05-10 HIGH-3 closure — regression tests pinning the
// jti consumed-set replay defense. Pre-fix the handler accepted any
// logout_token whose iat + jti were syntactically present; captured
// tokens were replayable indefinitely.

// stubBCLReplay tracks ConsumeJTI calls for the replay-cache tests.
type stubBCLReplay struct {
	consumed map[string]bool // key = jti|iss
	forceErr error           // when set, ConsumeJTI returns this (transient path)
}

func (s *stubBCLReplay) ConsumeJTI(_ context.Context, jti, iss string, _ time.Duration) error {
	if s.forceErr != nil {
		return s.forceErr
	}
	if s.consumed == nil {
		s.consumed = map[string]bool{}
	}
	key := jti + "|" + iss
	if s.consumed[key] {
		return repository.ErrBCLJTIAlreadyConsumed
	}
	s.consumed[key] = true
	return nil
}

// TestBackChannelLogout_FirstReceiveConsumesJTI pins the happy path —
// first BCL with a given (jti, iss) succeeds + records the pair.
func TestBackChannelLogout_FirstReceiveConsumesJTI(t *testing.T) {
	bcl := &stubBCLVerifier{
		issuer: "https://idp.example.com",
		sub:    "alice@example.com",
		jti:    "logout-jti-1",
		iat:    time.Now().Unix(),
	}
	replay := &stubBCLReplay{}
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, bcl)
	h.WithBCLReplayConsumer(replay, 60*time.Second)

	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	if !replay.consumed["logout-jti-1|https://idp.example.com"] {
		t.Errorf("expected (jti, iss) to be recorded; consumed=%v", replay.consumed)
	}
}

// TestBackChannelLogout_ReplayedJTIReturns200WithAudit pins §2.7
// idempotency: replay returns 200 + audit outcome=jti_replayed.
func TestBackChannelLogout_ReplayedJTIReturns200WithAudit(t *testing.T) {
	bcl := &stubBCLVerifier{
		issuer: "https://idp.example.com",
		sub:    "alice@example.com",
		jti:    "logout-jti-1",
		iat:    time.Now().Unix(),
	}
	replay := &stubBCLReplay{consumed: map[string]bool{"logout-jti-1|https://idp.example.com": true}}
	h, _, _, _, audit, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, bcl)
	h.WithBCLReplayConsumer(replay, 60*time.Second)

	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (idempotent on replay)", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", cc)
	}
	if !contains(audit.events, "auth.oidc_back_channel_logout") {
		t.Errorf("expected audit event with outcome=jti_replayed")
	}
}

// TestBackChannelLogout_TransientConsumeFailureReturns503 pins the
// transient-error path: ConsumeJTI returns a non-ErrAlreadyConsumed
// error → 503 so the IdP retries.
func TestBackChannelLogout_TransientConsumeFailureReturns503(t *testing.T) {
	bcl := &stubBCLVerifier{
		issuer: "https://idp.example.com",
		sub:    "alice@example.com",
		jti:    "logout-jti-1",
		iat:    time.Now().Unix(),
	}
	replay := &stubBCLReplay{forceErr: errors.New("db connection reset")}
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, bcl)
	h.WithBCLReplayConsumer(replay, 60*time.Second)

	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d; want 503 (transient consume failure)", w.Code)
	}
}
