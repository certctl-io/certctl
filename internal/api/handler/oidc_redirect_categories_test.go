package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	oidcsvc "github.com/certctl-io/certctl/internal/auth/oidc"
	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
)

// Audit 2026-05-10 HIGH-7 regression matrix — pin every classified
// failure category to its post-redirect query reason. Pre-fix, every
// failure surfaced as "OIDC login failed" with status 400 and no
// machine-readable hint; the LoginPage couldn't tell idle-timeout
// from email-domain rejection from PKCE breakage. Post-fix, the
// handler 302-redirects to /login?error=oidc_failed&reason=<cat>
// where the GUI renders an operator-friendly cause.

func TestLoginCallback_RedirectsWithReason_AllCategories(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantReason string
	}{
		{
			name:       "pre_login_consume_failed",
			err:        oidcsvc.ErrPreLoginNotFound,
			wantReason: "pre_login_consume_failed",
		},
		{
			name:       "state_mismatch",
			err:        errors.New("state mismatch"),
			wantReason: "state_mismatch",
		},
		{
			name:       "nonce_mismatch",
			err:        errors.New("nonce mismatch"),
			wantReason: "nonce_mismatch",
		},
		{
			name:       "audience_mismatch",
			err:        errors.New("audience mismatch"),
			wantReason: "audience_mismatch",
		},
		{
			name:       "token_expired",
			err:        errors.New("token expired"),
			wantReason: "token_expired",
		},
		{
			name:       "azp_mismatch",
			err:        errors.New("azp does not match"),
			wantReason: "azp_mismatch",
		},
		{
			name:       "at_hash_mismatch",
			err:        errors.New("at_hash mismatch"),
			wantReason: "at_hash_mismatch",
		},
		{
			name:       "iat_window",
			err:        errors.New("iat outside window"),
			wantReason: "iat_window",
		},
		{
			name:       "alg_rejected",
			err:        errors.New("alg not in allowlist"),
			wantReason: "alg_rejected",
		},
		{
			name:       "unmapped_groups",
			err:        oidcsvc.ErrGroupsUnmapped,
			wantReason: "unmapped_groups",
		},
		{
			name:       "groups_missing",
			err:        errors.New("groups missing"),
			wantReason: "groups_missing",
		},
		{
			name:       "jwks_unreachable",
			err:        errors.New("jwks fetch failed"),
			wantReason: "jwks_unreachable",
		},
		// HIGH-7 added these three categories so CRIT-5 (email domain)
		// and PKCE failures get distinguishable GUI rendering.
		{
			name:       "email_domain_not_allowed",
			err:        errors.New("email domain not in allowlist"),
			wantReason: "email_domain_not_allowed",
		},
		{
			name:       "email_missing_but_required",
			err:        errors.New("provider requires email but token has none"),
			wantReason: "email_missing_but_required",
		},
		{
			name:       "pkce_invalid",
			err:        errors.New("pkce verifier mismatch"),
			wantReason: "pkce_invalid",
		},
		{
			name:       "unspecified_fallback",
			err:        errors.New("totally unrecognized error"),
			wantReason: "unspecified",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := &stubOIDCSvc{callbackErr: tc.err}
			h, _, _, _, audit, _ := newPhase5Handler(t, o, &stubSession{}, &stubBCLVerifier{})
			req := httptest.NewRequest(http.MethodGet,
				"/auth/oidc/callback?code=abc&state=xyz", nil)
			req.AddCookie(&http.Cookie{
				Name:  sessiondomain.PreLoginCookieName,
				Value: "v1.pl-abc.sk-xyz.mac",
			})
			w := httptest.NewRecorder()
			h.LoginCallback(w, req)
			if w.Code != http.StatusFound {
				t.Fatalf("status = %d; want 302", w.Code)
			}
			loc := w.Header().Get("Location")
			wantPrefix := "/login?error=oidc_failed&reason=" + tc.wantReason
			if !strings.HasPrefix(loc, wantPrefix) {
				t.Errorf("Location = %q; want prefix %q", loc, wantPrefix)
			}
			// The audit row must still record the failure_category for
			// server-side observability — that's the load-bearing leg
			// of the HIGH-7 fix (audit retention is not narrowed by the
			// GUI redirect).
			if !contains(audit.events, "auth.oidc_login_failed") {
				t.Errorf("expected auth.oidc_login_failed audit event; got %v", audit.events)
			}
		})
	}
}
