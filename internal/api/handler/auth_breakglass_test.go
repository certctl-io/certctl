package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/auth/breakglass"
	bgdomain "github.com/certctl-io/certctl/internal/auth/breakglass/domain"
)

// Coverage fill — v2.1.0 release gate Phase 3.
//
// Handler-level tests for the Phase 7.5 break-glass HTTP surface.
// Bundle 2 originally shipped these endpoints with service-level
// tests only; the 6 0%-handler functions dragged the internal/api/
// handler average below its 75 floor. This file backfills the
// canonical positive + negative cases at the handler layer.

// =============================================================================
// Fake BreakglassService.
// =============================================================================

type fakeBreakglassSvc struct {
	enabled bool

	// Per-method return shapes. Tests set the field they care about.
	setPasswordRes *breakglass.SetPasswordResult
	setPasswordErr error
	authRes        *breakglass.AuthenticateResult
	authErr        error
	unlockErr      error
	removeErr      error
	listOut        []*bgdomain.BreakglassCredential
	listErr        error

	// Captured args (for assertions).
	gotSetCaller, gotSetTarget, gotSetPass          string
	gotAuthActor, gotAuthPass, gotAuthIP, gotAuthUA string
	gotUnlockCaller, gotUnlockTarget                string
	gotRemoveCaller, gotRemoveTarget                string
}

func (f *fakeBreakglassSvc) Enabled() bool { return f.enabled }

func (f *fakeBreakglassSvc) SetPassword(ctx context.Context, caller, target, pw string) (*breakglass.SetPasswordResult, error) {
	f.gotSetCaller, f.gotSetTarget, f.gotSetPass = caller, target, pw
	return f.setPasswordRes, f.setPasswordErr
}
func (f *fakeBreakglassSvc) Authenticate(ctx context.Context, actor, pw, ip, ua string) (*breakglass.AuthenticateResult, error) {
	f.gotAuthActor, f.gotAuthPass, f.gotAuthIP, f.gotAuthUA = actor, pw, ip, ua
	return f.authRes, f.authErr
}
func (f *fakeBreakglassSvc) Unlock(ctx context.Context, caller, target string) error {
	f.gotUnlockCaller, f.gotUnlockTarget = caller, target
	return f.unlockErr
}
func (f *fakeBreakglassSvc) RemoveCredential(ctx context.Context, caller, target string) error {
	f.gotRemoveCaller, f.gotRemoveTarget = caller, target
	return f.removeErr
}
func (f *fakeBreakglassSvc) List(ctx context.Context) ([]*bgdomain.BreakglassCredential, error) {
	return f.listOut, f.listErr
}

func newBreakglassHandlerWithFake(t *testing.T, enabled bool) (*AuthBreakglassHandler, *fakeBreakglassSvc) {
	t.Helper()
	svc := &fakeBreakglassSvc{enabled: enabled}
	attrs := SessionCookieAttrs{Secure: true, SameSite: http.SameSiteLaxMode}
	return NewAuthBreakglassHandler(svc, attrs), svc
}

// =============================================================================
// 1. Public login endpoint.
// =============================================================================

func TestBreakglassLogin_DisabledReturns404(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, false /* disabled */)
	body := bytes.NewBufferString(`{"actor_id":"alice","password":"hunter2!!"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass/login", body)
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled service must yield 404 (surface invisibility); got %d", rec.Code)
	}
}

func TestBreakglassLogin_InvalidJSONReturns401(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, true)
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass/login", bytes.NewBufferString("not-json"))
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("invalid JSON must map to 401 (NOT 400); got %d", rec.Code)
	}
}

func TestBreakglassLogin_EmptyFieldsReturns401(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, true)
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass/login", bytes.NewBufferString(`{"actor_id":"","password":""}`))
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("empty actor/password must map to 401; got %d", rec.Code)
	}
}

func TestBreakglassLogin_ServiceErrorReturns401(t *testing.T) {
	h, svc := newBreakglassHandlerWithFake(t, true)
	svc.authErr = errors.New("locked")
	body := bytes.NewBufferString(`{"actor_id":"alice","password":"wrong"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass/login", body)
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("auth error must map to 401; got %d", rec.Code)
	}
	if svc.gotAuthActor != "alice" {
		t.Errorf("expected actor=alice; got %q", svc.gotAuthActor)
	}
}

func TestBreakglassLogin_SuccessSetsCookies(t *testing.T) {
	h, svc := newBreakglassHandlerWithFake(t, true)
	svc.authRes = &breakglass.AuthenticateResult{CookieValue: "ses-1.abc", CSRFToken: "csrf-xyz"}
	body := bytes.NewBufferString(`{"actor_id":"alice","password":"hunter2!!"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass/login", body)
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204; got %d (body=%s)", rec.Code, rec.Body.String())
	}
	res := rec.Result()
	defer res.Body.Close()
	gotSession, gotCSRF := false, false
	for _, c := range res.Cookies() {
		if strings.Contains(c.Name, "session") || strings.Contains(c.Name, "Session") {
			gotSession = true
		}
		if strings.Contains(c.Name, "csrf") || strings.Contains(c.Name, "CSRF") {
			gotCSRF = true
		}
	}
	if !gotSession {
		t.Errorf("expected session cookie")
	}
	if !gotCSRF {
		t.Errorf("expected CSRF cookie")
	}
}

// =============================================================================
// 2. Admin endpoints — no caller context = 401.
// =============================================================================

func TestBreakglassSetPassword_NoCallerReturns401(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, true)
	body := bytes.NewBufferString(`{"actor_id":"alice","password":"StrongPW123!"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/breakglass/credentials", body)
	rec := httptest.NewRecorder()
	h.SetPassword(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing actor ctx must yield 401; got %d", rec.Code)
	}
}

func TestBreakglassSetPassword_DisabledReturns404(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, false)
	body := bytes.NewBufferString(`{"actor_id":"alice","password":"StrongPW123!"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/breakglass/credentials", body)
	req = withAuthCtx(req, "admin", "User")
	rec := httptest.NewRecorder()
	h.SetPassword(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled must yield 404; got %d", rec.Code)
	}
}

func TestBreakglassSetPassword_InvalidJSONReturns400(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, true)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/breakglass/credentials", bytes.NewBufferString("nope"))
	req = withAuthCtx(req, "admin", "User")
	rec := httptest.NewRecorder()
	h.SetPassword(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON must map to 400 on admin endpoint; got %d", rec.Code)
	}
}

func TestBreakglassSetPassword_HappyPath(t *testing.T) {
	h, svc := newBreakglassHandlerWithFake(t, true)
	svc.setPasswordRes = &breakglass.SetPasswordResult{}
	body := bytes.NewBufferString(`{"actor_id":"alice","password":"StrongPW123!"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/breakglass/credentials", body)
	req = withAuthCtx(req, "admin", "User")
	rec := httptest.NewRecorder()
	h.SetPassword(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Errorf("expected 2xx; got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if svc.gotSetTarget != "alice" {
		t.Errorf("expected target=alice; got %q", svc.gotSetTarget)
	}
	if svc.gotSetCaller != "admin" {
		t.Errorf("expected caller=admin; got %q", svc.gotSetCaller)
	}
}

func TestBreakglassUnlock_DisabledReturns404(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/breakglass/credentials/alice/unlock", nil)
	req = withAuthCtx(req, "admin", "User")
	rec := httptest.NewRecorder()
	h.Unlock(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled must yield 404; got %d", rec.Code)
	}
}

func TestBreakglassUnlock_NoActorReturns401(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, true)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/breakglass/credentials/alice/unlock", nil)
	rec := httptest.NewRecorder()
	h.Unlock(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing actor ctx must yield 401; got %d", rec.Code)
	}
}

func TestBreakglassRemove_DisabledReturns404(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, false)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/breakglass/credentials/alice", nil)
	req = withAuthCtx(req, "admin", "User")
	rec := httptest.NewRecorder()
	h.Remove(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled must yield 404; got %d", rec.Code)
	}
}

func TestBreakglassRemove_NoActorReturns401(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, true)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/breakglass/credentials/alice", nil)
	rec := httptest.NewRecorder()
	h.Remove(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing actor ctx must yield 401; got %d", rec.Code)
	}
}

// ListCredentials surfaces the read side.

func TestBreakglassListCredentials_DisabledReturns404(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/breakglass/credentials", nil)
	req = withAuthCtx(req, "admin", "User")
	rec := httptest.NewRecorder()
	h.ListCredentials(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled must yield 404; got %d", rec.Code)
	}
}

// ListCredentials does not re-check the actor context — the auth
// gate sits at the router/middleware layer via rbacGate. So a missing
// actor ctx here just means the test fixture wasn't authenticated;
// the handler itself returns 200 with the body content. The test
// pins this contract so a future refactor that adds a handler-level
// actor check will trip this case.
func TestBreakglassListCredentials_NoActorCtxStillReturns200(t *testing.T) {
	h, _ := newBreakglassHandlerWithFake(t, true)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/breakglass/credentials", nil)
	rec := httptest.NewRecorder()
	h.ListCredentials(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("handler-only path returns 200 (router rbacGate is the auth gate); got %d", rec.Code)
	}
}

func TestBreakglassListCredentials_HappyPath(t *testing.T) {
	h, svc := newBreakglassHandlerWithFake(t, true)
	svc.listOut = []*bgdomain.BreakglassCredential{
		{ActorID: "alice", TenantID: "t-default"},
		{ActorID: "bob", TenantID: "t-default"},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/breakglass/credentials", nil)
	req = withAuthCtx(req, "admin", "User")
	rec := httptest.NewRecorder()
	h.ListCredentials(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200; got %d (body=%s)", rec.Code, rec.Body.String())
	}
	// Body should be JSON with both actors. We don't assume the exact
	// envelope shape; just check the names appear and the password
	// hashes are NOT present in the wire response.
	body := rec.Body.String()
	if !strings.Contains(body, "alice") || !strings.Contains(body, "bob") {
		t.Errorf("expected both actors in body; got: %s", body)
	}
	// The PasswordHash field carries json:"-" so the encoded value
	// must NEVER contain the hash. The field name "password_hash" or
	// any Argon2id PHC prefix is the signal.
	if strings.Contains(body, "password_hash") || strings.Contains(body, "$argon2") {
		t.Errorf("password hashes must NOT appear in wire response; got: %s", body)
	}
	// Defensive — confirm it's valid JSON.
	var anyResp interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &anyResp); err != nil {
		t.Errorf("response body must be valid JSON: %v", err)
	}
}
