package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/auth"
	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
)

// =============================================================================
// In-memory stubs.
// =============================================================================

type stubSessionValidator struct {
	sess          *sessiondomain.Session
	validateErr   error
	updateLastErr error
	validateCalls int
	updateCalls   int
}

func (s *stubSessionValidator) Validate(_ context.Context, _ ValidateInput) (*sessiondomain.Session, error) {
	s.validateCalls++
	return s.sess, s.validateErr
}
func (s *stubSessionValidator) UpdateLastSeen(_ context.Context, _ string) error {
	s.updateCalls++
	return s.updateLastErr
}
func (s *stubSessionValidator) ValidateCSRF(headerValue string, sess *sessiondomain.Session) error {
	if sess == nil {
		return ErrCSRFMismatch
	}
	if headerValue == "" {
		return ErrCSRFMissing
	}
	if hashCSRFToken(headerValue) != sess.CSRFTokenHash {
		return ErrCSRFMismatch
	}
	return nil
}

// =============================================================================
// Helpers.
// =============================================================================

// mockBearer returns a Bearer middleware stub that authenticates any
// "Authorization: Bearer XYZ" header by setting the actor context.
// Mimics auth.NewAuthWithKeyStore's success-path behavior for tests
// without spinning up a real KeyStore.
func mockBearer(_ *testing.T) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "Bearer test-key" {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				http.Error(w, `{"error":"Invalid API key"}`, http.StatusUnauthorized)
				return
			}
			ctx := r.Context()
			ctx = context.WithValue(ctx, auth.UserKey{}, "api-key-actor")
			ctx = context.WithValue(ctx, auth.ActorIDKey{}, "api-key-actor")
			ctx = context.WithValue(ctx, auth.ActorTypeKey{}, "APIKey")
			ctx = context.WithValue(ctx, auth.TenantIDKey{}, "t-default")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// markAuthenticated returns a tiny handler that 200s + writes the
// actor id from context so tests can inspect which auth path won.
func markAuthenticated() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actorID, _ := r.Context().Value(auth.ActorIDKey{}).(string)
		fmt.Fprintf(w, `{"actor_id":%q}`, actorID)
	})
}

func newSession(t *testing.T, csrfPlaintext string) *sessiondomain.Session {
	t.Helper()
	now := time.Now().UTC()
	return &sessiondomain.Session{
		ID:                "ses-test",
		ActorID:           "u-alice",
		ActorType:         "User",
		SigningKeyID:      "sk-test",
		CSRFTokenHash:     hashCSRFToken(csrfPlaintext),
		IdleExpiresAt:     now.Add(time.Hour),
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
		CreatedAt:         now,
		LastSeenAt:        now,
		TenantID:          "t-default",
	}
}

// =============================================================================
// 7 Phase 6 spec-mandated middleware-chain tests.
// =============================================================================

// #1: Session cookie + correct CSRF -> succeeds.
func TestPhase6_SessionPlusCorrectCSRF_Succeeds(t *testing.T) {
	csrf := "the-csrf-token-plaintext"
	stub := &stubSessionValidator{sess: newSession(t, csrf)}
	chain := buildPhase6Chain(stub, stub)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/whatever", nil)
	req.AddCookie(&http.Cookie{Name: sessiondomain.PostLoginCookieName, Value: "v1.ses-test.sk-test.mac"})
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200; body=%q", w.Code, w.Body.String())
	}
	if !strContains(w.Body.String(), "u-alice") {
		t.Errorf("body missing actor id; got %q", w.Body.String())
	}
}

// #2: Session cookie + WRONG CSRF -> 403.
func TestPhase6_SessionPlusWrongCSRF_403(t *testing.T) {
	stub := &stubSessionValidator{sess: newSession(t, "real-csrf")}
	chain := buildPhase6Chain(stub, stub)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/whatever", nil)
	req.AddCookie(&http.Cookie{Name: sessiondomain.PostLoginCookieName, Value: "v1.ses-test.sk-test.mac"})
	req.Header.Set("X-CSRF-Token", "wrong-csrf")
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d; want 403", w.Code)
	}
}

// #3: Bearer-only (no session) + no CSRF -> succeeds (API-key actors are CSRF-exempt).
func TestPhase6_BearerOnly_NoCSRF_Succeeds(t *testing.T) {
	stub := &stubSessionValidator{validateErr: errors.New("no cookie")}
	chain := buildPhase6Chain(stub, stub)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/whatever", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200; body=%q", w.Code, w.Body.String())
	}
	if !strContains(w.Body.String(), "api-key-actor") {
		t.Errorf("body missing api-key actor id; got %q", w.Body.String())
	}
}

// #4: No cookie + no Bearer -> 401.
func TestPhase6_NeitherCookieNorBearer_401(t *testing.T) {
	stub := &stubSessionValidator{}
	chain := buildPhase6Chain(stub, stub)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/whatever", nil)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401; body=%q", w.Code, w.Body.String())
	}
}

// #5: Expired cookie + valid Bearer -> falls back to Bearer, succeeds.
func TestPhase6_ExpiredCookieValidBearer_FallsBackToBearer(t *testing.T) {
	stub := &stubSessionValidator{validateErr: ErrSessionExpiredAbsolute}
	chain := buildPhase6Chain(stub, stub)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/whatever", nil)
	req.AddCookie(&http.Cookie{Name: sessiondomain.PostLoginCookieName, Value: "v1.ses-expired.sk-x.mac"})
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200; body=%q", w.Code, w.Body.String())
	}
	if !strContains(w.Body.String(), "api-key-actor") {
		t.Errorf("expected Bearer fallback to win; body=%q", w.Body.String())
	}
}

// #6: Tampered cookie -> 401 (no Bearer to fall back to).
func TestPhase6_TamperedCookie_401(t *testing.T) {
	stub := &stubSessionValidator{validateErr: ErrSessionInvalidCookie}
	chain := buildPhase6Chain(stub, stub)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/whatever", nil)
	req.AddCookie(&http.Cookie{Name: sessiondomain.PostLoginCookieName, Value: "v1.ses-x.sk-x.tampered"})
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", w.Code)
	}
}

// #7: Bypass-list awareness — the protocol-endpoint allowlist is
// enforced by the dispatch layer (cmd/server/main.go::buildFinalHandler)
// and the public-route allowlist by direct r.mux.Handle in router.go;
// neither reaches the auth chain. Pin the contract by asserting that
// the chained-auth combinator's behavior on a request with no auth +
// a state-changing method is uniformly 401, NOT a CSRF 403 — i.e., the
// CSRF check is gated on session-row presence and never fires for
// unauthenticated requests.
func TestPhase6_StateChangingMethod_Unauthenticated_Returns401NotCSRF403(t *testing.T) {
	stub := &stubSessionValidator{}
	chain := buildPhase6Chain(stub, stub)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/whatever", nil)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401 (not 403); body=%q", w.Code, w.Body.String())
	}
}

// =============================================================================
// Coverage-lift tests.
// =============================================================================

func TestSessionMiddleware_NilService_PassThrough(t *testing.T) {
	mw := NewSessionMiddleware(nil)
	handler := mw(markAuthenticated())
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("nil service should pass through; got %d", w.Code)
	}
}

func TestCSRFMiddleware_NilService_PassThrough(t *testing.T) {
	mw := NewCSRFMiddleware(nil)
	handler := mw(markAuthenticated())
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("nil service should pass through; got %d", w.Code)
	}
}

func TestCSRFMiddleware_SafeMethodsBypass(t *testing.T) {
	stub := &stubSessionValidator{sess: newSession(t, "csrf")}
	mw := NewCSRFMiddleware(stub)
	handler := mw(markAuthenticated())
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace} {
		req := httptest.NewRequest(method, "/x", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("safe method %s blocked by CSRF middleware; status=%d", method, w.Code)
		}
	}
}

func TestSessionFromContext_NilMissing(t *testing.T) {
	if s := SessionFromContext(context.Background()); s != nil {
		t.Errorf("expected nil; got %v", s)
	}
}

func TestSessionFromContext_PopulatedReturnsSession(t *testing.T) {
	sess := newSession(t, "csrf")
	ctx := context.WithValue(context.Background(), sessionContextKey{}, sess)
	if s := SessionFromContext(ctx); s != sess {
		t.Errorf("expected returned session pointer to match; got %v", s)
	}
}

func TestIsStateChangingMethod(t *testing.T) {
	for _, tc := range []struct {
		method string
		want   bool
	}{
		{http.MethodGet, false},
		{http.MethodHead, false},
		{http.MethodOptions, false},
		{http.MethodTrace, false},
		{http.MethodPost, true},
		{http.MethodPut, true},
		{http.MethodDelete, true},
		{http.MethodPatch, true},
	} {
		if got := isStateChangingMethod(tc.method); got != tc.want {
			t.Errorf("isStateChangingMethod(%s) = %v; want %v", tc.method, got, tc.want)
		}
	}
}

func TestClientIPFromRequest_Variants(t *testing.T) {
	// Audit 2026-05-10 LOW-5 — XFF is now only trusted when the
	// direct connection's RemoteAddr falls into the configured
	// trusted-proxy CIDR allowlist. Reset to a known state before/after.
	prev := trustedProxyCIDRs
	t.Cleanup(func() { trustedProxyCIDRs = prev })

	// (1) No XFF trust configured (empty allowlist) — XFF is IGNORED.
	trustedProxyCIDRs = nil
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:5555"
	if ip := clientIPFromRequest(r); ip != "1.2.3.4" {
		t.Errorf("RemoteAddr: got %q; want 1.2.3.4", ip)
	}
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	if ip := clientIPFromRequest(r); ip != "1.2.3.4" {
		t.Errorf("XFF without trusted proxy: got %q; want 1.2.3.4 (ignored)", ip)
	}

	// (2) Trusted-proxy CIDR matches RemoteAddr — XFF IS honored.
	trustedProxyCIDRs = []string{"1.2.3.0/24"}
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	if ip := clientIPFromRequest(r); ip != "10.0.0.1" {
		t.Errorf("XFF first hop (trusted): got %q; want 10.0.0.1", ip)
	}
	r.Header.Set("X-Forwarded-For", "10.0.0.99")
	if ip := clientIPFromRequest(r); ip != "10.0.0.99" {
		t.Errorf("XFF single (trusted): got %q; want 10.0.0.99", ip)
	}

	// (3) No-port RemoteAddr unchanged.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "no-port"
	if ip := clientIPFromRequest(r2); ip != "no-port" {
		t.Errorf("no-port RemoteAddr: got %q; want no-port", ip)
	}
}

func TestChainAuthSessionThenBearer_NilBearer_Session401Path(t *testing.T) {
	stub := &stubSessionValidator{validateErr: ErrSessionInvalidCookie}
	chain := ChainAuthSessionThenBearer(NewSessionMiddleware(stub), nil)(markAuthenticated())
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: sessiondomain.PostLoginCookieName, Value: "v1.ses.sk.bad"})
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", w.Code)
	}
}

func TestChainAuthSessionThenBearer_NilBearer_SessionAuthSucceeds(t *testing.T) {
	stub := &stubSessionValidator{sess: newSession(t, "csrf")}
	chain := ChainAuthSessionThenBearer(NewSessionMiddleware(stub), nil)(markAuthenticated())
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: sessiondomain.PostLoginCookieName, Value: "v1.ses.sk.mac"})
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
}

// =============================================================================
// Helpers.
// =============================================================================

func buildPhase6Chain(svcSession SessionValidator, svcCSRF CSRFValidator) http.Handler {
	auth := ChainAuthSessionThenBearer(NewSessionMiddleware(svcSession), mockBearer(nil))
	csrf := NewCSRFMiddleware(svcCSRF)
	return auth(csrf(markAuthenticated()))
}

func strContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
