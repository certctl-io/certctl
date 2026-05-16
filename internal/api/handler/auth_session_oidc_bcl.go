// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	oidcsvc "github.com/certctl-io/certctl/internal/auth/oidc"
	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// Phase 9 ARCH-M2 closure Sprint 11 (2026-05-14): extracted from
// internal/api/handler/auth_session_oidc.go via the Option B
// sibling-file pattern.
//
// This file holds the DefaultBCLVerifier — the default
// implementation of the BackChannelLogoutVerifier interface
// declared in auth_session_oidc.go. Verifies an OIDC
// back-channel-logout token per OpenID Connect Back-Channel
// Logout 1.0 §2.6: enforces the events claim, iat window,
// algorithm allowlist, audience match against the provider's
// configured client ID, and decodes sub/sid/jti for the
// revocation lookup.
//
// External callers:
//   - cmd/server/main.go wires NewDefaultBCLVerifier(...) +
//     DefaultBCLVerifierMaxAge into the AuthSessionOIDCHandler
//     via WithBCLReplayConsumer.
//
// peekIssuer (unexported) is consumed only by Verify so it moves
// with the verifier. The go-oidc/v3 client is the underlying JWS
// verification + IdP-key-cache; everything else here is policy.

// =============================================================================
// Default BackChannelLogoutVerifier — wraps go-oidc/v3.
// =============================================================================

// DefaultBCLVerifierMaxAge is the default iat-freshness skew window
// (60 seconds; tokens older or newer than this are rejected). Override
// per-server via CERTCTL_OIDC_BCL_MAX_AGE_SECONDS. Audit 2026-05-10
// HIGH-3 closure.
const DefaultBCLVerifierMaxAge = 60 * time.Second

// DefaultBCLVerifier is the production BackChannelLogoutVerifier. It
// resolves the IdP by issuer (matched against the OIDCProviderRepository),
// fetches the IdP's JWKS via gooidc.Provider, and validates the
// logout_token JWT signature + required claims.
type DefaultBCLVerifier struct {
	providerRepo repository.OIDCProviderRepository
	tenantID     string
	allowedAlgs  []string
	// maxAge is the iat-freshness skew window. Tokens with iat in the
	// past beyond this OR in the future beyond this are rejected. Set
	// via WithMaxAge; defaults to DefaultBCLVerifierMaxAge.
	maxAge time.Duration
	// nowFn is the clock seam (test injection).
	nowFn func() time.Time

	// Injectable for tests so unit tests don't hit a real IdP.
	verifyOverride func(ctx context.Context, providerIssuer, rawIDToken string) (*gooidc.IDToken, error)
}

// NewDefaultBCLVerifier constructs a verifier wired against the given
// provider repo + tenant.
func NewDefaultBCLVerifier(providerRepo repository.OIDCProviderRepository, tenantID string, allowedAlgs []string) *DefaultBCLVerifier {
	if len(allowedAlgs) == 0 {
		allowedAlgs = []string{
			gooidc.RS256, gooidc.RS512, gooidc.ES256, gooidc.ES384, gooidc.EdDSA,
		}
	}
	return &DefaultBCLVerifier{
		providerRepo: providerRepo,
		tenantID:     tenantID,
		allowedAlgs:  allowedAlgs,
		maxAge:       DefaultBCLVerifierMaxAge,
		nowFn:        time.Now,
	}
}

// WithMaxAge returns a copy of the verifier with the iat-skew window
// overridden. Audit 2026-05-10 HIGH-3 — operator-configurable via
// CERTCTL_OIDC_BCL_MAX_AGE_SECONDS at cmd/server/main.go.
func (v *DefaultBCLVerifier) WithMaxAge(d time.Duration) *DefaultBCLVerifier {
	v.maxAge = d
	return v
}

// Verify implements BackChannelLogoutVerifier.
func (v *DefaultBCLVerifier) Verify(ctx context.Context, logoutToken string) (issuer, sub, sid, jti string, iat int64, err error) {
	// We don't know which provider the logout_token came from until we
	// peek at the iss claim. Parse-without-verify, look up the matching
	// provider, then verify against that provider's JWKS.
	iss, peekErr := peekIssuer(logoutToken)
	if peekErr != nil {
		return "", "", "", "", 0, fmt.Errorf("peek issuer: %w", peekErr)
	}
	provs, lerr := v.providerRepo.List(ctx, v.tenantID)
	if lerr != nil {
		return "", "", "", "", 0, fmt.Errorf("list providers: %w", lerr)
	}
	var matched *oidcdomain.OIDCProvider
	for _, p := range provs {
		if p.IssuerURL == iss {
			matched = p
			break
		}
	}
	if matched == nil {
		return "", "", "", "", 0, fmt.Errorf("no provider configured for issuer %q", iss)
	}

	var idToken *gooidc.IDToken
	if v.verifyOverride != nil {
		idToken, err = v.verifyOverride(ctx, matched.IssuerURL, logoutToken)
	} else {
		// Acquisition-audit SEC-021 closure (Sprint 1 follow-up to SEC-001,
		// 2026-05-16). Per-request discovery re-fetch threaded through
		// SafeOIDCContext so the dial-time SSRF guard
		// (validation.SafeHTTPDialContext) re-resolves the issuer host and
		// refuses reserved-address answers — matching the SEC-001 sweep
		// over the runtime + dry-run discovery legs in internal/auth/oidc.
		provider, perr := gooidc.NewProvider(oidcsvc.SafeOIDCContext(ctx), matched.IssuerURL)
		if perr != nil {
			return "", "", "", "", 0, fmt.Errorf("provider discovery: %w", perr)
		}
		verifier := provider.Verifier(&gooidc.Config{
			ClientID:             matched.ClientID,
			SupportedSigningAlgs: v.allowedAlgs,
			SkipExpiryCheck:      true, // OIDC BCL §2.4 — no exp claim required
		})
		idToken, err = verifier.Verify(ctx, logoutToken)
	}
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("verify: %w", err)
	}

	// Required claims per spec §2.4.
	var claims struct {
		Iss    string                 `json:"iss"`
		Aud    interface{}            `json:"aud"`
		Iat    int64                  `json:"iat"`
		Jti    string                 `json:"jti"`
		Events map[string]interface{} `json:"events"`
		Sub    string                 `json:"sub"`
		Sid    string                 `json:"sid"`
		Nonce  string                 `json:"nonce"`
	}
	if cerr := idToken.Claims(&claims); cerr != nil {
		return "", "", "", "", 0, fmt.Errorf("claims unmarshal: %w", cerr)
	}
	if claims.Iat == 0 {
		return "", "", "", "", 0, errors.New("missing iat claim")
	}
	// Audit 2026-05-10 HIGH-3 — iat freshness check. Reject tokens
	// whose iat is outside the skew window. RFC 9700 §2.7 + the
	// existing ID-token-path skew tolerance (oidc/service.go:463).
	maxAge := v.maxAge
	if maxAge <= 0 {
		maxAge = DefaultBCLVerifierMaxAge
	}
	now := v.nowFn().UTC()
	iatTime := time.Unix(claims.Iat, 0).UTC()
	if iatTime.After(now.Add(maxAge)) {
		return "", "", "", "", 0, fmt.Errorf("iat is in the future beyond max-age %s", maxAge)
	}
	if now.Sub(iatTime) > maxAge {
		return "", "", "", "", 0, fmt.Errorf("iat is stale (age %s > max-age %s)", now.Sub(iatTime), maxAge)
	}
	if claims.Jti == "" {
		return "", "", "", "", 0, errors.New("missing jti claim")
	}
	if claims.Events == nil {
		return "", "", "", "", 0, errors.New("missing events claim")
	}
	if _, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		return "", "", "", "", 0, errors.New("events claim missing back-channel-logout URI")
	}
	if claims.Nonce != "" {
		// Spec §2.4: nonce MUST NOT be present.
		return "", "", "", "", 0, errors.New("nonce claim must be absent in logout_token")
	}
	if claims.Sub == "" && claims.Sid == "" {
		return "", "", "", "", 0, errors.New("logout_token must carry sub or sid")
	}
	return claims.Iss, claims.Sub, claims.Sid, claims.Jti, claims.Iat, nil
}

// peekIssuer base64-decodes the JWT payload (segment 1 after the `.`)
// and pulls the `iss` claim out without verifying the signature. Used
// to find the matching provider before we know which JWKS to use.
// peekIssuer extracts the `iss` claim from an unsigned JWT payload —
// used by the BCL handler to route the logout_token to the right
// provider for verification.
//
// Audit 2026-05-10 Nit-3 — peekIssuer is INTENTIONALLY unsigned-permissive.
// The returned issuer is used ONLY to select the verifier; the full
// signature + claim verification happens in DefaultBCLVerifier.Verify
// (which re-checks the `iss` claim against the matched provider's
// IssuerURL after JWS signature validation). Callers MUST NOT trust
// peekIssuer output for any access-control decision before the verify
// step completes; the pin is encoded in the BCL handler's call shape
// (peek → match provider → verify-against-provider → consume).
func peekIssuer(jwt string) (string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", errors.New("expected 3 JWT segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("payload base64: %w", err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if jerr := json.Unmarshal(payload, &c); jerr != nil {
		return "", fmt.Errorf("payload json: %w", jerr)
	}
	if c.Iss == "" {
		return "", errors.New("missing iss claim in payload")
	}
	return c.Iss, nil
}
