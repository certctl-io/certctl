package session

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
)

// Audit 2026-05-10 HIGH-8 regression tests pinning the cause-aware
// WWW-Authenticate header. Pre-fix, every session-cookie failure
// emitted a generic 401 with no machine-readable cause; OIDC users
// who hit idle-timeout / absolute-timeout / back-channel-revoked
// got an indistinguishable "Authentication required" with no hint
// about how to recover. Post-fix, the 401 emitter sets:
//
//   WWW-Authenticate: Bearer realm="certctl", error="invalid_token",
//                     error_description="<cause>"
//
// where <cause> ∈ {idle_timeout, absolute_timeout,
// back_channel_revoked, invalid_token}. The GUI reads this on its
// fetch wrapper and routes the user into OIDC re-login (vs a generic
// "logged out" notice) when the cause is BCL revocation.

// classifySessionError direct-test matrix — pin the four stable
// wire-strings the GUI consumes.
func TestClassifySessionError_StableCategories(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"idle", ErrSessionExpiredIdle, "idle_timeout"},
		{"absolute", ErrSessionExpiredAbsolute, "absolute_timeout"},
		{"revoked", ErrSessionRevoked, "back_channel_revoked"},
		{"opaque", errors.New("totally-other-cause"), "invalid_token"},
		// Wrapped sentinels still classify (errors.Is).
		{"wrapped_idle", wrap(ErrSessionExpiredIdle, "outer"), "idle_timeout"},
		{"wrapped_revoked", wrap(ErrSessionRevoked, "outer"), "back_channel_revoked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifySessionError(tc.err)
			if got != tc.want {
				t.Errorf("classifySessionError(%v) = %q; want %q",
					tc.err, got, tc.want)
			}
		})
	}
}

// HIGH-8: a 401 emitted from bearerSkipIfAuthenticated when no
// Bearer middleware is wired must carry WWW-Authenticate with
// error_description=<cause> when the upstream SessionMiddleware
// stashed a cause classification.
func TestBearerSkipIfAuthenticated_Emits_WWWAuthenticate_WithCause(t *testing.T) {
	cases := []struct {
		name      string
		sessErr   error
		wantCause string
	}{
		{"idle_timeout", ErrSessionExpiredIdle, "idle_timeout"},
		{"absolute_timeout", ErrSessionExpiredAbsolute, "absolute_timeout"},
		{"back_channel_revoked", ErrSessionRevoked, "back_channel_revoked"},
		{"opaque_falls_back_to_invalid_token", errors.New("opaque"), "invalid_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubSessionValidator{validateErr: tc.sessErr}
			// Bearer middleware nil so the chain emits its own 401.
			chain := ChainAuthSessionThenBearer(NewSessionMiddleware(stub), nil)(markAuthenticated())
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.AddCookie(&http.Cookie{
				Name:  sessiondomain.PostLoginCookieName,
				Value: "v1.ses.sk.bad",
			})
			w := httptest.NewRecorder()
			chain.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d; want 401", w.Code)
			}
			ww := w.Header().Get("WWW-Authenticate")
			if !strings.Contains(ww, `Bearer realm="certctl"`) {
				t.Errorf("WWW-Authenticate = %q; want Bearer realm=\"certctl\"", ww)
			}
			if !strings.Contains(ww, `error="invalid_token"`) {
				t.Errorf("WWW-Authenticate = %q; want error=\"invalid_token\"", ww)
			}
			wantDesc := `error_description="` + tc.wantCause + `"`
			if !strings.Contains(ww, wantDesc) {
				t.Errorf("WWW-Authenticate = %q; want %s", ww, wantDesc)
			}
		})
	}
}

// HIGH-8: a 401 emitted with NO upstream session context (no cookie
// at all) still carries WWW-Authenticate, but with the
// invalid_token fallback (no stashed cause).
func TestBearerSkipIfAuthenticated_NoSessionContext_FallsBackToInvalidToken(t *testing.T) {
	stub := &stubSessionValidator{validateErr: ErrSessionInvalidCookie}
	chain := ChainAuthSessionThenBearer(NewSessionMiddleware(stub), nil)(markAuthenticated())
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	// No cookie at all → SessionMiddleware skips entirely and falls
	// through; bearerSkipIfAuthenticated emits 401 without a stashed
	// cause; should fall back to error_description="invalid_token".
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", w.Code)
	}
	ww := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(ww, `error_description="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q; want fallback error_description=\"invalid_token\"", ww)
	}
}

// wrap is a tiny errors.Wrap-style helper used by the wrapped-sentinel
// classifier matrix above. We can't pull in fmt.Errorf with %w as a
// const here, so this is the local convenience.
func wrap(inner error, outer string) error {
	return &wrappedErr{inner: inner, outer: outer}
}

type wrappedErr struct {
	inner error
	outer string
}

func (w *wrappedErr) Error() string { return w.outer + ": " + w.inner.Error() }
func (w *wrappedErr) Unwrap() error { return w.inner }
