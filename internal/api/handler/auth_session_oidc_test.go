package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/auth"
	oidcsvc "github.com/certctl-io/certctl/internal/auth/oidc"
	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
	sessionsvc "github.com/certctl-io/certctl/internal/auth/session"
	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	userdomain "github.com/certctl-io/certctl/internal/auth/user/domain"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// authWithActor builds a context indistinguishable from what the auth
// middleware would set after a successful Bearer-or-cookie auth.
func authWithActor(ctx context.Context, actorID, actorType string) context.Context {
	ctx = context.WithValue(ctx, auth.ActorIDKey{}, actorID)
	ctx = context.WithValue(ctx, auth.ActorTypeKey{}, actorType)
	ctx = context.WithValue(ctx, auth.TenantIDKey{}, "t-default")
	return ctx
}

// =============================================================================
// In-memory stubs.
// =============================================================================

type stubOIDCSvc struct {
	authURL     string
	cookie      string
	preLoginID  string
	authReqErr  error
	callbackRes *oidcsvc.CallbackResult
	callbackErr error
	refreshErr  error
}

func (s *stubOIDCSvc) HandleAuthRequest(_ context.Context, _ string) (string, string, string, error) {
	return s.authURL, s.cookie, s.preLoginID, s.authReqErr
}
func (s *stubOIDCSvc) HandleCallback(_ context.Context, _, _, _, _, _, _ string) (*oidcsvc.CallbackResult, error) {
	return s.callbackRes, s.callbackErr
}
func (s *stubOIDCSvc) RefreshKeys(_ context.Context, _ string) error { return s.refreshErr }

type stubSession struct {
	createRes      *sessionsvc.CreateResult
	createErr      error
	validateRes    *sessiondomain.Session
	validateErr    error
	revokeErr      error
	revokeAllErr   error
	revokedIDs     []string
	revokeAllIDs   []string
	revokeAllTypes []string
}

func (s *stubSession) Create(_ context.Context, _, _, _, _ string) (*sessionsvc.CreateResult, error) {
	return s.createRes, s.createErr
}
func (s *stubSession) Validate(_ context.Context, _ sessionsvc.ValidateInput) (*sessiondomain.Session, error) {
	return s.validateRes, s.validateErr
}
func (s *stubSession) Revoke(_ context.Context, id string) error {
	s.revokedIDs = append(s.revokedIDs, id)
	return s.revokeErr
}
func (s *stubSession) RevokeAllForActor(_ context.Context, actorID, actorType string) error {
	s.revokeAllIDs = append(s.revokeAllIDs, actorID)
	s.revokeAllTypes = append(s.revokeAllTypes, actorType)
	return s.revokeAllErr
}

type stubBCLVerifier struct {
	issuer string
	sub    string
	sid    string
	jti    string
	iat    int64
	err    error
}

func (s *stubBCLVerifier) Verify(_ context.Context, _ string) (string, string, string, string, int64, error) {
	return s.issuer, s.sub, s.sid, s.jti, s.iat, s.err
}

// stubProviderRepo implements just enough of repository.OIDCProviderRepository.
type stubProviderRepo struct {
	provs     []*oidcdomain.OIDCProvider
	getErr    error
	deleteErr error
	createErr error
	updateErr error
}

func (s *stubProviderRepo) List(_ context.Context, _ string) ([]*oidcdomain.OIDCProvider, error) {
	return s.provs, nil
}
func (s *stubProviderRepo) Get(_ context.Context, id string) (*oidcdomain.OIDCProvider, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	for _, p := range s.provs {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, repository.ErrOIDCProviderNotFound
}
func (s *stubProviderRepo) GetByName(_ context.Context, _, _ string) (*oidcdomain.OIDCProvider, error) {
	return nil, repository.ErrOIDCProviderNotFound
}
func (s *stubProviderRepo) Create(_ context.Context, p *oidcdomain.OIDCProvider) error {
	if s.createErr != nil {
		return s.createErr
	}
	s.provs = append(s.provs, p)
	return nil
}
func (s *stubProviderRepo) Update(_ context.Context, _ *oidcdomain.OIDCProvider) error {
	return s.updateErr
}
func (s *stubProviderRepo) Delete(_ context.Context, _ string) error { return s.deleteErr }

type stubMappingRepo struct {
	mappings []*oidcdomain.GroupRoleMapping
	addErr   error
	rmErr    error
}

func (s *stubMappingRepo) ListByProvider(_ context.Context, _ string) ([]*oidcdomain.GroupRoleMapping, error) {
	return s.mappings, nil
}
func (s *stubMappingRepo) Get(_ context.Context, _ string) (*oidcdomain.GroupRoleMapping, error) {
	return nil, repository.ErrGroupRoleMappingNotFound
}
func (s *stubMappingRepo) Add(_ context.Context, m *oidcdomain.GroupRoleMapping) error {
	if s.addErr != nil {
		return s.addErr
	}
	s.mappings = append(s.mappings, m)
	return nil
}
func (s *stubMappingRepo) Remove(_ context.Context, _ string) error { return s.rmErr }
func (s *stubMappingRepo) Map(_ context.Context, _ string, _ []string) ([]string, error) {
	return nil, nil
}

type stubSessionRepo struct {
	rows map[string]*sessiondomain.Session
}

func newStubSessionRepo() *stubSessionRepo {
	return &stubSessionRepo{rows: make(map[string]*sessiondomain.Session)}
}
func (s *stubSessionRepo) Create(_ context.Context, sess *sessiondomain.Session) error {
	s.rows[sess.ID] = sess
	return nil
}
func (s *stubSessionRepo) Get(_ context.Context, id string) (*sessiondomain.Session, error) {
	r, ok := s.rows[id]
	if !ok {
		return nil, repository.ErrSessionNotFound
	}
	return r, nil
}
func (s *stubSessionRepo) ListByActor(_ context.Context, actorID, actorType, _ string) ([]*sessiondomain.Session, error) {
	var out []*sessiondomain.Session
	for _, r := range s.rows {
		if r.ActorID == actorID && r.ActorType == actorType {
			out = append(out, r)
		}
	}
	return out, nil
}
func (s *stubSessionRepo) UpdateLastSeen(_ context.Context, _ string) error { return nil }
func (s *stubSessionRepo) UpdateCSRFTokenHash(_ context.Context, _, _ string) error {
	return nil
}
func (s *stubSessionRepo) Revoke(_ context.Context, id string) error {
	if r, ok := s.rows[id]; ok {
		t := time.Now()
		r.RevokedAt = &t
	}
	return nil
}
func (s *stubSessionRepo) RevokeAllForActor(_ context.Context, _, _, _ string) error { return nil }
func (s *stubSessionRepo) RevokeAllExceptForActor(_ context.Context, _, _, _, _ string) (int, error) {
	return 0, nil
}
func (s *stubSessionRepo) GarbageCollectExpired(_ context.Context) (int, error) { return 0, nil }
func (s *stubSessionRepo) Delete(_ context.Context, _ string) error             { return nil }

// stubUserRepo implements just enough of repository.UserRepository for
// the BCL sub→actor_id resolution path (CRIT-2 closure). Lookups by
// (providerID, subject) return the seeded row if present, ErrUserNotFound
// otherwise. lookupErr forces a non-NotFound error (the "transient"
// 503 path).
type stubUserRepo struct {
	users     map[string]*userdomain.User // key = providerID|subject
	lookupErr error                       // when non-nil, GetByOIDCSubject returns this
}

func (s *stubUserRepo) Get(_ context.Context, _ string) (*userdomain.User, error) {
	return nil, repository.ErrUserNotFound
}

func (s *stubUserRepo) GetByOIDCSubject(_ context.Context, providerID, subject string) (*userdomain.User, error) {
	if s.lookupErr != nil {
		return nil, s.lookupErr
	}
	if s.users == nil {
		return nil, repository.ErrUserNotFound
	}
	if u, ok := s.users[providerID+"|"+subject]; ok {
		return u, nil
	}
	return nil, repository.ErrUserNotFound
}

func (s *stubUserRepo) Create(_ context.Context, _ *userdomain.User) error { return nil }
func (s *stubUserRepo) Update(_ context.Context, _ *userdomain.User) error { return nil }
func (s *stubUserRepo) ListAll(_ context.Context, _ string) ([]*userdomain.User, error) {
	return nil, nil
}

type phase5StubAudit struct {
	events []string
}

func (s *phase5StubAudit) RecordEventWithCategory(_ context.Context, _ string, _ domain.ActorType, action, _, _, _ string, _ map[string]interface{}) error {
	s.events = append(s.events, action)
	return nil
}

// =============================================================================
// Helpers.
// =============================================================================

func newPhase5Handler(
	t *testing.T,
	oidcSvc *stubOIDCSvc,
	sess *stubSession,
	bcl *stubBCLVerifier,
) (*AuthSessionOIDCHandler, *stubProviderRepo, *stubMappingRepo, *stubSessionRepo, *phase5StubAudit, *stubUserRepo) {
	t.Helper()
	provRepo := &stubProviderRepo{}
	mapRepo := &stubMappingRepo{}
	sessRepo := newStubSessionRepo()
	userRepo := &stubUserRepo{}
	audit := &phase5StubAudit{}
	h := NewAuthSessionOIDCHandler(
		oidcSvc, sess, bcl, provRepo, mapRepo, sessRepo, userRepo, audit,
		"", "t-default", "/dashboard",
		SessionCookieAttrs{SameSite: http.SameSiteLaxMode, Secure: true},
	)
	return h, provRepo, mapRepo, sessRepo, audit, userRepo
}

// withActor adds the same context keys the auth middleware would set.
func withActor(req *http.Request, actorID, actorType string) *http.Request {
	ctx := req.Context()
	// Use the same context-key constants the production auth package
	// sets via NewDemoModeAuth — since we don't have a clean export,
	// rely on the auth package's GetActorID accessors. The handler
	// uses callerFromRequest which calls auth.GetActorID etc.
	// Easiest: use auth.WithActor helper which is in
	// internal/auth/testfixtures.go (Bundle 1 Phase 0).
	return req.WithContext(authWithActor(ctx, actorID, actorType))
}

// =============================================================================
// 1. /auth/oidc/login — happy path + missing provider param.
// =============================================================================

func TestLoginInitiate_HappyPath(t *testing.T) {
	o := &stubOIDCSvc{
		authURL:    "https://idp/authorize?state=x&nonce=y",
		cookie:     "v1.pl-abc.sk-xyz.somemac",
		preLoginID: "pl-abc",
	}
	h, _, _, _, _, _ := newPhase5Handler(t, o, &stubSession{}, &stubBCLVerifier{})

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login?provider=op-x", nil)
	w := httptest.NewRecorder()
	h.LoginInitiate(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d; want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "idp/authorize") {
		t.Errorf("Location header missing IdP URL: %q", loc)
	}
	cookies := w.Result().Cookies()
	hasPreLogin := false
	for _, c := range cookies {
		if c.Name == sessiondomain.PreLoginCookieName && c.Value == o.cookie {
			hasPreLogin = true
		}
	}
	if !hasPreLogin {
		t.Errorf("pre-login cookie not set")
	}
}

func TestLoginInitiate_MissingProvider(t *testing.T) {
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil)
	w := httptest.NewRecorder()
	h.LoginInitiate(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestLoginInitiate_ProviderNotFound(t *testing.T) {
	o := &stubOIDCSvc{authReqErr: repository.ErrOIDCProviderNotFound}
	h, _, _, _, _, _ := newPhase5Handler(t, o, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login?provider=op-missing", nil)
	w := httptest.NewRecorder()
	h.LoginInitiate(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

// =============================================================================
// 2. /auth/oidc/callback — happy path + 3 spec-mandated negatives.
// =============================================================================

func TestLoginCallback_HappyPath(t *testing.T) {
	user := &userdomain.User{ID: "u-alice"}
	o := &stubOIDCSvc{callbackRes: &oidcsvc.CallbackResult{
		User:        user,
		RoleIDs:     []string{"r-operator"},
		CookieValue: "v1.ses-abc.sk-xyz.mac",
		CSRFToken:   "csrf-token-value",
	}}
	h, _, _, _, audit, _ := newPhase5Handler(t, o, &stubSession{}, &stubBCLVerifier{})

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=abc&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: sessiondomain.PreLoginCookieName, Value: "v1.pl-abc.sk-xyz.mac"})
	w := httptest.NewRecorder()
	h.LoginCallback(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d; want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("Location = %q; want /dashboard", loc)
	}
	if !contains(audit.events, "auth.oidc_login_succeeded") {
		t.Errorf("expected auth.oidc_login_succeeded audit event; got %v", audit.events)
	}
	if !contains(audit.events, "auth.session_created") {
		t.Errorf("expected auth.session_created audit event")
	}
}

// Phase 5 spec mandate #4: Callback with replayed state -> 302 to /login.
// (The OIDC service's PreLoginStore.LookupAndConsume returns
// ErrPreLoginNotFound on the second call; Audit 2026-05-10 HIGH-7
// flipped this from a blank 400 to a 302 to /login?error=oidc_failed
// &reason=<category>. The audit row still records failure_category.)
func TestLoginCallback_ReplayedState_Returns400(t *testing.T) {
	o := &stubOIDCSvc{callbackErr: oidcsvc.ErrPreLoginNotFound}
	h, _, _, _, audit, _ := newPhase5Handler(t, o, &stubSession{}, &stubBCLVerifier{})

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=abc&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: sessiondomain.PreLoginCookieName, Value: "v1.pl-abc.sk-xyz.mac"})
	w := httptest.NewRecorder()
	h.LoginCallback(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("status = %d; want 302 (post-HIGH-7 redirect)", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/login?error=oidc_failed&reason=") {
		t.Errorf("Location = %q; want /login?error=oidc_failed&reason=...", loc)
	}
	if !contains(audit.events, "auth.oidc_login_failed") {
		t.Errorf("expected auth.oidc_login_failed audit event; got %v", audit.events)
	}
}

// Phase 5 spec mandate #5: Callback with PKCE verifier mismatch -> 302.
// The OIDC service's code-exchange step fails when the verifier doesn't
// match the challenge; HIGH-7 redirects to /login with reason.
func TestLoginCallback_PKCEVerifierMismatch_Returns400(t *testing.T) {
	o := &stubOIDCSvc{callbackErr: errors.New("oidc: code exchange failed: invalid_grant")}
	h, _, _, _, _, _ := newPhase5Handler(t, o, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=abc&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: sessiondomain.PreLoginCookieName, Value: "v1.pl-abc.sk-xyz.mac"})
	w := httptest.NewRecorder()
	h.LoginCallback(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("status = %d; want 302 (post-HIGH-7 redirect)", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/login?error=oidc_failed") {
		t.Errorf("Location = %q; want /login?error=oidc_failed&reason=...", loc)
	}
}

// Phase 5 spec mandate #6: Callback with expired pre-login row -> 302.
func TestLoginCallback_ExpiredPreLoginRow_Returns400(t *testing.T) {
	// Adapter maps ErrPreLoginExpired -> ErrPreLoginNotFound; HIGH-7
	// flipped the wire shape from 400 to a 302 redirect (specific
	// reason still in audit row).
	o := &stubOIDCSvc{callbackErr: oidcsvc.ErrPreLoginNotFound}
	h, _, _, _, _, _ := newPhase5Handler(t, o, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=abc&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: sessiondomain.PreLoginCookieName, Value: "v1.pl-abc.sk-xyz.mac"})
	w := httptest.NewRecorder()
	h.LoginCallback(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("status = %d; want 302 (post-HIGH-7 redirect)", w.Code)
	}
}

func TestLoginCallback_MissingPreLoginCookie_Returns400(t *testing.T) {
	h, _, _, _, audit, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=abc&state=xyz", nil)
	w := httptest.NewRecorder()
	h.LoginCallback(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
	if !contains(audit.events, "auth.oidc_login_failed") {
		t.Errorf("expected auth.oidc_login_failed audit; got %v", audit.events)
	}
}

func TestLoginCallback_UnmappedGroups_AuditRowDistinguished(t *testing.T) {
	o := &stubOIDCSvc{callbackErr: oidcsvc.ErrGroupsUnmapped}
	h, _, _, _, audit, _ := newPhase5Handler(t, o, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=abc&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: sessiondomain.PreLoginCookieName, Value: "v1.pl-abc.sk-xyz.mac"})
	w := httptest.NewRecorder()
	h.LoginCallback(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("status = %d; want 302 (post-HIGH-7 redirect)", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "reason=unmapped_groups") {
		t.Errorf("Location = %q; want reason=unmapped_groups", loc)
	}
	if !contains(audit.events, "auth.oidc_login_unmapped_groups") {
		t.Errorf("expected auth.oidc_login_unmapped_groups; got %v", audit.events)
	}
}

// =============================================================================
// 3. /auth/oidc/back-channel-logout — 3 spec-mandated negatives.
// =============================================================================

// Phase 5 spec mandate #1: BCL with missing events claim -> 400.
func TestBackChannelLogout_MissingEvents_Returns400(t *testing.T) {
	bcl := &stubBCLVerifier{err: errors.New("missing events claim")}
	h, _, _, _, audit, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, bcl)
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
	if !contains(audit.events, "auth.oidc_back_channel_logout_failed") {
		t.Errorf("expected failure audit event; got %v", audit.events)
	}
}

// Phase 5 spec mandate #2: BCL with nonce present -> 400 (per spec §2.4).
func TestBackChannelLogout_NoncePresent_Returns400(t *testing.T) {
	bcl := &stubBCLVerifier{err: errors.New("nonce claim must be absent in logout_token")}
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, bcl)
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

// Phase 5 spec mandate #3: BCL with sig signed by an unknown key -> 400.
func TestBackChannelLogout_UnknownKeySig_Returns400(t *testing.T) {
	bcl := &stubBCLVerifier{err: errors.New("verify: signature key not found in JWKS")}
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, bcl)
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

// TestBackChannelLogout_HappyPath_RevokesSubject pins the CRIT-2
// closure happy-path: an IdP fires BCL with sub=<oidc-subject>, the
// handler resolves sub → user.ID via providerRepo (issuer match) +
// userRepo.GetByOIDCSubject, then calls sessionSvc.RevokeAllForActor
// with the RESOLVED actor_id (NOT the OIDC subject — pre-fix bug
// where the handler called RevokeAllForActor(sub, "User") and silently
// revoked nothing because session rows are keyed by user.ID).
func TestBackChannelLogout_HappyPath_RevokesSubject(t *testing.T) {
	bcl := &stubBCLVerifier{issuer: "https://idp", sub: "alice@example.com"}
	sess := &stubSession{}
	h, provRepo, _, _, audit, userRepo := newPhase5Handler(t, &stubOIDCSvc{}, sess, bcl)

	// Seed: provider with matching IssuerURL + user keyed by (provider.ID, sub).
	provRepo.provs = []*oidcdomain.OIDCProvider{
		{ID: "iss-1", IssuerURL: "https://idp", TenantID: "t-default"},
	}
	userRepo.users = map[string]*userdomain.User{
		"iss-1|alice@example.com": {ID: "u-alice", TenantID: "t-default"},
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", cc)
	}
	if len(sess.revokeAllIDs) != 1 || sess.revokeAllIDs[0] != "u-alice" {
		t.Errorf("expected RevokeAllForActor(u-alice); got %v", sess.revokeAllIDs)
	}
	if len(sess.revokeAllTypes) != 1 || sess.revokeAllTypes[0] != "User" {
		t.Errorf("expected actor_type=User; got %v", sess.revokeAllTypes)
	}
	if !contains(audit.events, "auth.oidc_back_channel_logout") {
		t.Errorf("expected auth.oidc_back_channel_logout audit event")
	}
}

// TestBackChannelLogout_UnknownUserReturns200WithAudit covers the
// idempotent-200 path when the IdP BCLs a user we never logged in.
// Per OIDC BCL §2.7 we still return 200 + Cache-Control: no-store; the
// audit row carries outcome=user_unknown so forensics can distinguish.
func TestBackChannelLogout_UnknownUserReturns200WithAudit(t *testing.T) {
	bcl := &stubBCLVerifier{issuer: "https://idp", sub: "stranger@example.com"}
	sess := &stubSession{}
	h, provRepo, _, _, audit, _ := newPhase5Handler(t, &stubOIDCSvc{}, sess, bcl)
	// Provider matches, but no user is seeded for the subject.
	provRepo.provs = []*oidcdomain.OIDCProvider{
		{ID: "iss-1", IssuerURL: "https://idp", TenantID: "t-default"},
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 (idempotent); got %d", http.StatusOK, w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", cc)
	}
	if len(sess.revokeAllIDs) != 0 {
		t.Errorf("expected no RevokeAllForActor calls (no user seeded); got %v", sess.revokeAllIDs)
	}
	if !contains(audit.events, "auth.oidc_back_channel_logout") {
		t.Errorf("expected auth.oidc_back_channel_logout audit event with outcome=user_unknown")
	}
}

// TestBackChannelLogout_IssuerUnknownReturns200WithAudit covers the
// "iss doesn't match any configured provider" path. Per RFC idempotency,
// still 200; outcome=issuer_unknown in the audit row.
func TestBackChannelLogout_IssuerUnknownReturns200WithAudit(t *testing.T) {
	bcl := &stubBCLVerifier{issuer: "https://wrong-idp", sub: "alice@example.com"}
	sess := &stubSession{}
	h, provRepo, _, _, audit, _ := newPhase5Handler(t, &stubOIDCSvc{}, sess, bcl)
	provRepo.provs = []*oidcdomain.OIDCProvider{
		{ID: "iss-1", IssuerURL: "https://idp", TenantID: "t-default"}, // mismatched
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 (idempotent on unknown issuer)", w.Code)
	}
	if len(sess.revokeAllIDs) != 0 {
		t.Errorf("expected no RevokeAllForActor calls; got %v", sess.revokeAllIDs)
	}
	if !contains(audit.events, "auth.oidc_back_channel_logout") {
		t.Errorf("expected audit event with outcome=issuer_unknown")
	}
}

// TestBackChannelLogout_TransientUserRepoErrorReturns503 covers the
// transient-DB-failure path. A non-NotFound error from the user
// repository surfaces as 503 so the IdP follows its retry semantics
// (per OIDC BCL §2.8 IdPs SHOULD retry on transient failures).
func TestBackChannelLogout_TransientUserRepoErrorReturns503(t *testing.T) {
	bcl := &stubBCLVerifier{issuer: "https://idp", sub: "alice@example.com"}
	sess := &stubSession{}
	h, provRepo, _, _, _, userRepo := newPhase5Handler(t, &stubOIDCSvc{}, sess, bcl)
	provRepo.provs = []*oidcdomain.OIDCProvider{
		{ID: "iss-1", IssuerURL: "https://idp", TenantID: "t-default"},
	}
	userRepo.lookupErr = errors.New("db connection reset")

	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d; want 503 (transient → IdP retries)", w.Code)
	}
	if len(sess.revokeAllIDs) != 0 {
		t.Errorf("expected no revoke on transient error; got %v", sess.revokeAllIDs)
	}
}

// TestBackChannelLogout_RevokeFailureReturns200WithAuditFailureOutcome
// covers the path where user resolution succeeds but the
// RevokeAllForActor call fails. BCL is best-effort per §2.8; still 200,
// audit row carries outcome=revoke_failed.
func TestBackChannelLogout_RevokeFailureReturns200WithAuditFailureOutcome(t *testing.T) {
	bcl := &stubBCLVerifier{issuer: "https://idp", sub: "alice@example.com"}
	sess := &stubSession{revokeAllErr: errors.New("transient")}
	h, provRepo, _, _, audit, userRepo := newPhase5Handler(t, &stubOIDCSvc{}, sess, bcl)
	provRepo.provs = []*oidcdomain.OIDCProvider{
		{ID: "iss-1", IssuerURL: "https://idp", TenantID: "t-default"},
	}
	userRepo.users = map[string]*userdomain.User{
		"iss-1|alice@example.com": {ID: "u-alice", TenantID: "t-default"},
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 (best-effort on revoke failure)", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", cc)
	}
	// RevokeAllForActor WAS called (and failed); audit MUST record the
	// outcome so the operator can debug.
	if len(sess.revokeAllIDs) != 1 || sess.revokeAllIDs[0] != "u-alice" {
		t.Errorf("expected RevokeAllForActor(u-alice) attempted; got %v", sess.revokeAllIDs)
	}
	if !contains(audit.events, "auth.oidc_back_channel_logout") {
		t.Errorf("expected audit event with outcome=revoke_failed")
	}
}

func TestBackChannelLogout_HappyPath_RevokesSid(t *testing.T) {
	bcl := &stubBCLVerifier{issuer: "https://idp", sid: "ses-xyz"}
	sess := &stubSession{}
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, sess, bcl)
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout",
		strings.NewReader("logout_token=eyJ.payload.sig"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
	if len(sess.revokedIDs) != 1 || sess.revokedIDs[0] != "ses-xyz" {
		t.Errorf("expected Revoke(ses-xyz); got %v", sess.revokedIDs)
	}
}

func TestBackChannelLogout_MissingTokenReturns400(t *testing.T) {
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.BackChannelLogout(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

// =============================================================================
// 4. /auth/logout — happy path.
// =============================================================================

func TestLogout_HappyPath(t *testing.T) {
	sess := &stubSession{validateRes: &sessiondomain.Session{ID: "ses-abc", ActorID: "u-x", ActorType: "User"}}
	h, _, _, _, audit, _ := newPhase5Handler(t, &stubOIDCSvc{}, sess, &stubBCLVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req = withActor(req, "u-x", "User")
	req.AddCookie(&http.Cookie{Name: sessiondomain.PostLoginCookieName, Value: "v1.ses-abc.sk-xyz.mac"})
	w := httptest.NewRecorder()
	h.Logout(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d; want 204", w.Code)
	}
	if len(sess.revokedIDs) != 1 || sess.revokedIDs[0] != "ses-abc" {
		t.Errorf("expected Revoke(ses-abc); got %v", sess.revokedIDs)
	}
	if !contains(audit.events, "auth.session_revoked") {
		t.Errorf("expected auth.session_revoked audit; got %v", audit.events)
	}
}

func TestLogout_NoCookie_Returns204(t *testing.T) {
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req = withActor(req, "u-x", "User")
	w := httptest.NewRecorder()
	h.Logout(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d; want 204", w.Code)
	}
}

// =============================================================================
// 5. /api/v1/auth/sessions — list + revoke.
// =============================================================================

func TestListSessions_OwnSessions(t *testing.T) {
	h, _, _, sessRepo, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	now := time.Now()
	sessRepo.rows["ses-1"] = &sessiondomain.Session{
		ID: "ses-1", ActorID: "u-x", ActorType: "User",
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	req = withActor(req, "u-x", "User")
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "ses-1") {
		t.Errorf("response missing session id; body = %q", body)
	}
}

func TestRevokeSession_HappyPath(t *testing.T) {
	h, _, _, sessRepo, audit, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	sessRepo.rows["ses-rev"] = &sessiondomain.Session{ID: "ses-rev", ActorID: "u-x", ActorType: "User"}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/ses-rev", nil)
	req.SetPathValue("id", "ses-rev")
	req = withActor(req, "u-x", "User")
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d; want 204", w.Code)
	}
	if !contains(audit.events, "auth.session_revoked") {
		t.Errorf("expected auth.session_revoked audit; got %v", audit.events)
	}
}

func TestRevokeSession_NotFound(t *testing.T) {
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/ses-nope", nil)
	req.SetPathValue("id", "ses-nope")
	req = withActor(req, "u-x", "User")
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

// =============================================================================
// 6. OIDC provider CRUD.
// =============================================================================

func TestListProviders(t *testing.T) {
	h, provRepo, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	provRepo.provs = []*oidcdomain.OIDCProvider{
		{ID: "op-x", Name: "Okta", IssuerURL: "https://x", ClientID: "c"},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/providers", nil)
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.ListProviders(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "op-x") {
		t.Errorf("response missing provider id")
	}
}

func TestCreateProvider_MissingClientSecret(t *testing.T) {
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	body := strings.NewReader(`{"name":"x","issuer_url":"https://x","client_id":"c","redirect_uri":"https://r","groups_claim_path":"groups","groups_claim_format":"string-array"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/providers", body)
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.CreateProvider(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestDeleteProvider_InUse_Returns409(t *testing.T) {
	h, provRepo, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	provRepo.deleteErr = repository.ErrOIDCProviderInUse
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/oidc/providers/op-x", nil)
	req.SetPathValue("id", "op-x")
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.DeleteProvider(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d; want 409", w.Code)
	}
}

func TestRefreshProvider_HappyPath(t *testing.T) {
	o := &stubOIDCSvc{}
	h, _, _, _, audit, _ := newPhase5Handler(t, o, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/providers/op-x/refresh", nil)
	req.SetPathValue("id", "op-x")
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.RefreshProvider(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
	if !contains(audit.events, "auth.oidc_provider_refreshed") {
		t.Errorf("expected auth.oidc_provider_refreshed audit; got %v", audit.events)
	}
}

// =============================================================================
// 7. Group-mapping CRUD.
// =============================================================================

func TestListGroupMappings_MissingProviderID(t *testing.T) {
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/group-mappings", nil)
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.ListGroupMappings(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestAddGroupMapping_HappyPath(t *testing.T) {
	h, _, _, _, audit, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	body := strings.NewReader(`{"provider_id":"op-x","group_name":"engineers","role_id":"r-operator"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/group-mappings", body)
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.AddGroupMapping(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d; want 201", w.Code)
	}
	if !contains(audit.events, "auth.group_mapping_added") {
		t.Errorf("expected auth.group_mapping_added audit; got %v", audit.events)
	}
}

func TestRemoveGroupMapping_NotFound(t *testing.T) {
	h, _, mapRepo, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	mapRepo.rmErr = repository.ErrGroupRoleMappingNotFound
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/oidc/group-mappings/grm-x", nil)
	req.SetPathValue("id", "grm-x")
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.RemoveGroupMapping(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

// =============================================================================
// Helpers.
// =============================================================================

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// peekIssuer test (touches the BCL verifier helper directly).
func TestDefaultIfBlank(t *testing.T) {
	if got := defaultIfBlank("", "x"); got != "x" {
		t.Errorf("got %q; want x", got)
	}
	if got := defaultIfBlank("y", "x"); got != "y" {
		t.Errorf("got %q; want y", got)
	}
	if got := defaultIfBlank("   ", "x"); got != "x" {
		t.Errorf("got %q; want x (whitespace-only treated as blank)", got)
	}
}

func TestDefaultIntIfZero(t *testing.T) {
	if got := defaultIntIfZero(0, 5); got != 5 {
		t.Errorf("got %d; want 5", got)
	}
	if got := defaultIntIfZero(7, 5); got != 7 {
		t.Errorf("got %d; want 7", got)
	}
}

func TestClientIPFromRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:5555"
	if ip := clientIPFromRequest(r); ip != "1.2.3.4" {
		t.Errorf("RemoteAddr: got %q; want 1.2.3.4", ip)
	}
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	if ip := clientIPFromRequest(r); ip != "10.0.0.1" {
		t.Errorf("XFF first hop: got %q; want 10.0.0.1", ip)
	}
	r.Header.Set("X-Forwarded-For", "10.0.0.99")
	if ip := clientIPFromRequest(r); ip != "10.0.0.99" {
		t.Errorf("XFF single: got %q; want 10.0.0.99", ip)
	}
}

func TestNewAuthSessionOIDCHandler_DefaultsPostLoginURL(t *testing.T) {
	h := NewAuthSessionOIDCHandler(
		&stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{},
		&stubProviderRepo{}, &stubMappingRepo{}, newStubSessionRepo(), &stubUserRepo{}, &phase5StubAudit{},
		"key", "t-default", "", // empty postLoginURL
		SessionCookieAttrs{},
	)
	if h.postLoginURL != "/" {
		t.Errorf("default postLoginURL = %q; want /", h.postLoginURL)
	}
}

func TestEncryptClientSecret_EmptyKeyPassthrough(t *testing.T) {
	h := &AuthSessionOIDCHandler{encryptionKey: ""}
	got, err := h.encryptClientSecret([]byte("secret"))
	if err != nil {
		t.Fatalf("encryptClientSecret: %v", err)
	}
	if string(got) != "secret" {
		t.Errorf("got %q; want secret (passthrough)", string(got))
	}
}

func TestEncryptClientSecret_RealEncryption(t *testing.T) {
	h := &AuthSessionOIDCHandler{encryptionKey: "test-passphrase-12345-abcdef"}
	got, err := h.encryptClientSecret([]byte("secret"))
	if err != nil {
		t.Fatalf("encryptClientSecret: %v", err)
	}
	if string(got) == "secret" {
		t.Errorf("encrypted output equals plaintext; encryption did not run")
	}
}

func TestNewDefaultBCLVerifier_DefaultsAlgs(t *testing.T) {
	v := NewDefaultBCLVerifier(&stubProviderRepo{}, "t-default", nil)
	if len(v.allowedAlgs) == 0 {
		t.Errorf("expected default allowedAlgs; got empty")
	}
	v2 := NewDefaultBCLVerifier(&stubProviderRepo{}, "t-default", []string{"RS256"})
	if len(v2.allowedAlgs) != 1 || v2.allowedAlgs[0] != "RS256" {
		t.Errorf("explicit alg list not honored: %v", v2.allowedAlgs)
	}
}

func TestDefaultBCLVerifier_NoMatchingProviderRejected(t *testing.T) {
	provs := &stubProviderRepo{provs: []*oidcdomain.OIDCProvider{
		{ID: "op-x", IssuerURL: "https://different-idp"},
	}}
	v := NewDefaultBCLVerifier(provs, "t-default", nil)
	// JWT with iss=https://idp (which doesn't match any registered provider).
	// header={"alg":"RS256"}, payload={"iss":"https://idp"}.
	jwt := "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcCJ9.AAAA"
	_, _, _, _, _, err := v.Verify(context.Background(), jwt)
	if err == nil {
		t.Errorf("expected error when iss doesn't match any registered provider")
	}
}

func TestPeekIssuer_HappyPath(t *testing.T) {
	// header.payload.sig where payload base64-decodes to {"iss":"https://idp"}.
	header := "eyJhbGciOiJSUzI1NiJ9"
	payload := "eyJpc3MiOiJodHRwczovL2lkcCJ9"
	sig := "AAAA"
	jwt := fmt.Sprintf("%s.%s.%s", header, payload, sig)
	iss, err := peekIssuer(jwt)
	if err != nil {
		t.Fatalf("peekIssuer: %v", err)
	}
	if iss != "https://idp" {
		t.Errorf("iss = %q; want https://idp", iss)
	}
}

func TestPeekIssuer_RejectsBadSegmentCount(t *testing.T) {
	if _, err := peekIssuer("just.two"); err == nil {
		t.Errorf("expected error for 2-segment JWT")
	}
}

func TestCreateProvider_HappyPath(t *testing.T) {
	h, _, _, _, audit, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	body := strings.NewReader(`{"name":"OktaTest","issuer_url":"https://example.okta.com","client_id":"c","client_secret":"s","redirect_uri":"https://r/cb","groups_claim_path":"groups","groups_claim_format":"string-array","scopes":["openid","profile","email"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/providers", body)
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.CreateProvider(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d; want 201; body=%q", w.Code, w.Body.String())
	}
	if !contains(audit.events, "auth.oidc_provider_created") {
		t.Errorf("expected auth.oidc_provider_created audit; got %v", audit.events)
	}
}

func TestCreateProvider_DuplicateName_Returns409(t *testing.T) {
	h, provRepo, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	provRepo.createErr = repository.ErrOIDCProviderDuplicateName
	body := strings.NewReader(`{"name":"DupTest","issuer_url":"https://example.okta.com","client_id":"c","client_secret":"s","redirect_uri":"https://r/cb","groups_claim_path":"groups","groups_claim_format":"string-array","scopes":["openid"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/providers", body)
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.CreateProvider(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d; want 409", w.Code)
	}
}

func TestCreateProvider_InvalidJSON_Returns400(t *testing.T) {
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/providers", strings.NewReader("{not-json"))
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.CreateProvider(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestUpdateProvider_HappyPath(t *testing.T) {
	h, provRepo, _, _, audit, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	provRepo.provs = []*oidcdomain.OIDCProvider{
		{
			ID: "op-x", TenantID: "t-default", Name: "Old",
			IssuerURL: "https://x", ClientID: "c", ClientSecretEncrypted: []byte("blob"),
			RedirectURI: "https://r/cb", GroupsClaimPath: "groups",
			GroupsClaimFormat: "string-array", Scopes: []string{"openid"},
			IATWindowSeconds: 300, JWKSCacheTTLSeconds: 3600,
		},
	}
	body := strings.NewReader(`{"name":"NewName","issuer_url":"https://x","client_id":"c","redirect_uri":"https://r/cb","groups_claim_path":"groups","groups_claim_format":"string-array","scopes":["openid","email"]}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/auth/oidc/providers/op-x", body)
	req.SetPathValue("id", "op-x")
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.UpdateProvider(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200; body=%q", w.Code, w.Body.String())
	}
	if !contains(audit.events, "auth.oidc_provider_updated") {
		t.Errorf("expected auth.oidc_provider_updated audit; got %v", audit.events)
	}
}

func TestUpdateProvider_NotFound(t *testing.T) {
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	body := strings.NewReader(`{"name":"X"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/auth/oidc/providers/op-missing", body)
	req.SetPathValue("id", "op-missing")
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.UpdateProvider(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

func TestRefreshProvider_NotFound(t *testing.T) {
	o := &stubOIDCSvc{refreshErr: repository.ErrOIDCProviderNotFound}
	h, _, _, _, _, _ := newPhase5Handler(t, o, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/providers/op-missing/refresh", nil)
	req.SetPathValue("id", "op-missing")
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.RefreshProvider(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

func TestListGroupMappings_HappyPath(t *testing.T) {
	h, _, mapRepo, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	mapRepo.mappings = []*oidcdomain.GroupRoleMapping{
		{ID: "grm-1", ProviderID: "op-x", GroupName: "engineers", RoleID: "r-operator", TenantID: "t-default"},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/group-mappings?provider_id=op-x", nil)
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.ListGroupMappings(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
}

func TestAddGroupMapping_Duplicate_Returns409(t *testing.T) {
	h, _, mapRepo, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	mapRepo.addErr = repository.ErrGroupRoleMappingDuplicate
	body := strings.NewReader(`{"provider_id":"op-x","group_name":"g","role_id":"r-operator"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/group-mappings", body)
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.AddGroupMapping(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d; want 409", w.Code)
	}
}

func TestRemoveGroupMapping_HappyPath(t *testing.T) {
	h, _, _, _, audit, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/oidc/group-mappings/grm-x", nil)
	req.SetPathValue("id", "grm-x")
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.RemoveGroupMapping(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d; want 204", w.Code)
	}
	if !contains(audit.events, "auth.group_mapping_removed") {
		t.Errorf("expected auth.group_mapping_removed audit")
	}
}

func TestRevokeSession_MissingID(t *testing.T) {
	h, _, _, _, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/", nil)
	req = withActor(req, "u-x", "User")
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestListSessions_AsAdmin_QueryActorID(t *testing.T) {
	h, _, _, sessRepo, _, _ := newPhase5Handler(t, &stubOIDCSvc{}, &stubSession{}, &stubBCLVerifier{})
	now := time.Now()
	sessRepo.rows["ses-other"] = &sessiondomain.Session{
		ID: "ses-other", ActorID: "u-other", ActorType: "User",
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions?actor_id=u-other&actor_type=User", nil)
	req = withActor(req, "u-admin", "User")
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ses-other") {
		t.Errorf("expected ses-other in response")
	}
}

func TestClassifyOIDCFailure(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "ok"},
		{errors.New("oidc: pre-login session not found"), "pre_login_consume_failed"},
		{errors.New("oidc: state parameter mismatch"), "state_mismatch"},
		{errors.New("oidc: nonce mismatch"), "nonce_mismatch"},
		{errors.New("oidc: audience mismatch"), "audience_mismatch"},
		{errors.New("oidc: ID token expired"), "token_expired"},
		{errors.New("oidc: azp mismatch"), "azp_mismatch"},
		{errors.New("oidc: at_hash mismatch"), "at_hash_mismatch"},
		{errors.New("oidc: ID token iat older than configured window"), "iat_window"},
		{errors.New("oidc: alg rejected"), "alg_rejected"},
		{errors.New("oidc: groups did not match any configured mapping"), "unmapped_groups"},
		{errors.New("oidc: configured groups claim missing or malformed"), "groups_missing"},
		{errors.New("oidc: jwks unreachable"), "jwks_unreachable"},
		// Audit 2026-05-10 MED-17 — typed dispatch beats the substring
		// fallthrough because all three iss-family sentinels contain
		// "iss" in their message and would otherwise mis-classify.
		{oidcsvc.ErrIssParamMissing, "iss_param_missing"},
		{oidcsvc.ErrIssParamMismatch, "iss_param_mismatch"},
		{oidcsvc.ErrIssuerMismatch, "id_token_iss_mismatch"},
		// Wrapped variants must round-trip through errors.Is.
		{fmt.Errorf("upstream: %w", oidcsvc.ErrIssParamMissing), "iss_param_missing"},
		{fmt.Errorf("upstream: %w", oidcsvc.ErrIssParamMismatch), "iss_param_mismatch"},
		{errors.New("some other error"), "unspecified"},
	}
	for _, tc := range cases {
		got := classifyOIDCFailure(tc.err)
		if got != tc.want {
			t.Errorf("classifyOIDCFailure(%v) = %q; want %q", tc.err, got, tc.want)
		}
	}
}
