package oidc

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
	"github.com/certctl-io/certctl/internal/auth/oidc/groupclaim"
	userdomain "github.com/certctl-io/certctl/internal/auth/user/domain"
	"github.com/certctl-io/certctl/internal/crypto"
	"github.com/certctl-io/certctl/internal/repository"
)

// =============================================================================
// Auth Bundle 2 / Phase 3 / OIDC Service
//
// The Service implements the certctl side of the OpenID Connect 1.0
// authorization-code flow with PKCE-S256 (RFC 7636), against any IdP
// that satisfies the OIDC discovery doc + JWKS contract. Token
// validation enforces every fail-closed check from OIDC core
// §3.1.3.7 plus the operator-policy gates (alg allow-list, audience,
// `azp` for multi-aud tokens, `at_hash` when access tokens are
// returned, `iat` window, `nonce`, single-use state).
//
// Security posture:
//
//  1. JWKS endpoints MUST be HTTPS (validated at provider creation
//     by the domain layer; transport never weakened).
//  2. PKCE S256 is REQUIRED on every login per RFC 9700 §2.1.1;
//     the `plain` challenge method is rejected.
//  3. State is server-generated random 32 bytes (256 bits of
//     entropy), single-use, stored in the pre-login session row.
//  4. Nonce is server-generated random 32 bytes, single-use,
//     stored in the pre-login session row, validated against the
//     ID token nonce claim via constant-time compare.
//  5. Algorithms are pinned to an allow-list (default: RS256, RS512,
//     ES256, ES384, EdDSA). HS256/HS384/HS512 are NEVER allowed
//     (HMAC + JWKS is alg confusion); `none` is NEVER allowed.
//  6. IdP downgrade-attack defense: at provider creation /
//     RefreshKeys, the discovery doc's
//     `id_token_signing_alg_values_supported` is intersected with
//     the allow-list. If the IdP advertises HS* / none AT ALL, the
//     provider is rejected with an actionable error so a future
//     compromised IdP can't downgrade.
//  7. JWKS handling delegated to coreos/go-oidc/v3; on JWKS fetch
//     failure during a key rotation the service returns
//     ErrJWKSUnreachable (HTTP 503), existing sessions untouched,
//     no exponential backoff.
//  8. Token-leak hygiene: ID tokens, access tokens, refresh tokens,
//     authorization codes, PKCE verifiers, state, nonce, and any
//     signing key bytes MUST NEVER be logged. The service contains
//     ZERO log statements that include these values; tests in
//     logging_test.go pin the invariant.
// =============================================================================

// Service implements the OIDC integration.
type Service struct {
	providers OIDCProviderLookup
	mappings  repository.GroupRoleMappingRepository
	users     repository.UserRepository
	sessions  SessionMinter
	preLogin  PreLoginStore

	encryptionKey string // CERTCTL_CONFIG_ENCRYPTION_KEY for client_secret decrypt

	mu       sync.RWMutex
	cache    map[string]*providerEntry // keyed by provider ID
	clockNow func() time.Time          // injectable for tests

	// adminBootstrapHook is the optional Phase 7 first-admin bootstrap
	// closure. When set, HandleCallback consults it after group
	// resolution + user upsert; on grantAdmin=true the user's resolved
	// role IDs are extended with r-admin. See bootstrap_hook.go.
	adminBootstrapHook AdminBootstrapHook
}

// providerEntry caches the go-oidc Provider + the OAuth2 config + the
// IdP-advertised algs (used for the downgrade-attack defense check on
// every RefreshKeys). The Provider's internal JWKS cache handles
// rotation transparently.
type providerEntry struct {
	cfgRow      *oidcdomain.OIDCProvider
	provider    *gooidc.Provider
	verifier    *gooidc.IDTokenVerifier
	oauthConfig *oauth2.Config
	allowedAlgs []string // intersected: domain config ∩ allow-list ∩ IdP-advertised
	plaintext   []byte   // decrypted client secret; held for token exchange

	// Audit 2026-05-10 MED-17 — RFC 9207 iss-URL-parameter support.
	// Populated from the discovery doc's
	// `authorization_response_iss_parameter_supported` claim during
	// getOrLoad. When true, HandleCallback REQUIRES a non-empty
	// callback iss URL param and compares it against the provider's
	// IssuerURL. When false (the default for most IdPs that haven't
	// rolled RFC 9207 yet), the check is skipped.
	issParamSupported bool
}

// OIDCProviderLookup is a narrow read-side projection of
// repository.OIDCProviderRepository — service.go only ever reads
// providers; mutations go through the repo from the handler / GUI side.
// Defined here so test mocks can satisfy the smaller surface.
type OIDCProviderLookup interface {
	Get(ctx context.Context, id string) (*oidcdomain.OIDCProvider, error)
	List(ctx context.Context, tenantID string) ([]*oidcdomain.OIDCProvider, error)
}

// PreLoginStore wraps the pre-login session row that holds state +
// nonce + PKCE verifier across the IdP redirect. Phase 4's
// SessionService satisfies this interface; Phase 3 defines it so the
// Service can be unit-tested without the full session machinery.
type PreLoginStore interface {
	// CreatePreLogin persists a row with the given identifiers.
	// providerID is the configured op-... id; state, nonce, verifier
	// are server-generated random strings the callback will validate.
	// Returns the opaque cookie value the handler sets, plus the
	// session ID (used as the audit trail anchor).
	CreatePreLogin(ctx context.Context, providerID, state, nonce, verifier string) (cookieValue, sessionID string, err error)

	// LookupAndConsume reads the pre-login row by cookie value AND
	// deletes it atomically. Single-use: a second call with the same
	// cookie value returns ErrPreLoginNotFound. Returns the stored
	// state/nonce/verifier/providerID for the caller to validate
	// against the callback parameters.
	LookupAndConsume(ctx context.Context, cookieValue string) (providerID, state, nonce, verifier string, err error)
}

// SessionMinter wraps the post-login session creation. Phase 4's
// SessionService satisfies this. Defined here so the OIDC service
// can be unit-tested independently of session signing.
type SessionMinter interface {
	// MintForUser creates a post-login session for the named user.
	// Returns the cookie value the handler sets and a CSRF token
	// the GUI echoes into the X-CSRF-Token header on POSTs.
	MintForUser(ctx context.Context, user *userdomain.User, roleIDs []string, ip, userAgent string) (cookieValue, csrfToken string, err error)
}

// IDGenerator returns a new opaque session id. Defaults to 32 random
// bytes base64url-no-pad-encoded. Injectable for tests.
type IDGenerator func() (string, error)

// Service-layer sentinels. Handler-layer translates to HTTP status.
var (
	// ErrPreLoginNotFound: the pre-login cookie doesn't match a row.
	// Either the row was already consumed (replay) or never existed
	// (forged cookie). HTTP 400.
	ErrPreLoginNotFound = errors.New("oidc: pre-login session not found or already consumed")

	// ErrStateMismatch: callback `state` differs from the stored
	// pre-login state. HTTP 400.
	ErrStateMismatch = errors.New("oidc: state parameter mismatch (replay or forgery)")

	// ErrNonceMismatch: ID token `nonce` differs from the stored
	// pre-login nonce. HTTP 400.
	ErrNonceMismatch = errors.New("oidc: nonce mismatch")

	// ErrIssuerMismatch: ID token `iss` doesn't match the configured
	// provider issuer_url. HTTP 400.
	//
	// Audit 2026-05-10 MED-17 — also returned when the RFC 9207 iss
	// URL parameter check fails (provider advertises
	// authorization_response_iss_parameter_supported=true but the
	// callback iss is missing or mismatched). The handler's
	// classifyOIDCFailure breaks the two cases apart by audit
	// failure_category (iss_param_missing / iss_param_mismatch /
	// id_token_iss_mismatch).
	ErrIssuerMismatch = errors.New("oidc: issuer mismatch")

	// ErrIssParamMissing: provider's discovery doc advertises
	// authorization_response_iss_parameter_supported=true but the
	// callback URL had no `iss` query parameter. Per RFC 9207 §2.4 the
	// client MUST reject the response in this case. HTTP 400. Pre-fix,
	// the callback path ignored the parameter entirely.
	ErrIssParamMissing = errors.New("oidc: provider advertises iss-parameter support but callback omitted it")

	// ErrIssParamMismatch: provider's discovery doc advertises
	// authorization_response_iss_parameter_supported=true and the
	// callback supplied an `iss` query parameter, but it doesn't match
	// the matched provider's issuer URL. Mixed-up attack defense per
	// RFC 9207 §2.3. HTTP 400.
	ErrIssParamMismatch = errors.New("oidc: callback iss parameter does not match provider issuer URL")

	// ErrAudienceMismatch: ID token `aud` doesn't include the
	// configured client_id. HTTP 400.
	ErrAudienceMismatch = errors.New("oidc: audience mismatch")

	// ErrAZPRequired: ID token has multi-valued aud but no `azp`
	// claim. Per OIDC core §3.1.3.7 step 5, `azp` MUST be present
	// when there are multiple audiences. HTTP 400.
	ErrAZPRequired = errors.New("oidc: multi-aud ID token missing required azp claim")

	// ErrAZPMismatch: ID token `azp` doesn't equal client_id. HTTP 400.
	ErrAZPMismatch = errors.New("oidc: azp claim does not match client_id")

	// ErrATHashMismatch: ID token `at_hash` doesn't match the
	// re-computed hash of the access token. HTTP 400.
	ErrATHashMismatch = errors.New("oidc: at_hash claim does not match access token")

	// ErrATHashRequired: an access token was returned alongside the ID
	// token but the ID token carries no `at_hash` claim. Per the Phase 3
	// spec (OIDC core §3.1.3.6 + §3.2.2.9), at_hash is REQUIRED in this
	// case so a substituted access token can be detected. Fail closed.
	// HTTP 400.
	ErrATHashRequired = errors.New("oidc: access_token present but ID token has no at_hash claim")

	// ErrTokenExpired: ID token `exp` is in the past (with 60s
	// clock-skew tolerance). HTTP 400.
	ErrTokenExpired = errors.New("oidc: ID token expired")

	// ErrIATInFuture: ID token `iat` is in the future beyond the 60s
	// skew tolerance. HTTP 400.
	ErrIATInFuture = errors.New("oidc: ID token iat is in the future")

	// ErrIATTooOld: ID token `iat` is older than the configured
	// IATWindow. HTTP 400.
	ErrIATTooOld = errors.New("oidc: ID token iat older than configured window")

	// ErrAlgRejected: ID token signed with an alg outside the
	// allow-list. HTTP 400.
	ErrAlgRejected = errors.New("oidc: ID token signed with disallowed algorithm")

	// ErrIdPDowngradeAdvertised: provider's discovery doc advertises
	// HS* or `none` algorithms. Provider creation / refresh rejects.
	// HTTP 400.
	ErrIdPDowngradeAdvertised = errors.New("oidc: IdP advertises weak signing algorithms (HS*/none); refusing to use as defense against downgrade attacks")

	// ErrJWKSUnreachable: JWKS endpoint fetch failed during a
	// rotation. The in-flight login fails 503; existing sessions
	// untouched.
	ErrJWKSUnreachable = errors.New("oidc: JWKS endpoint unreachable; in-flight login fails, existing sessions untouched")

	// ErrGroupsMissing: the configured groups_claim_path resolves
	// to nothing or is malformed. Phase 3 fails closed.
	ErrGroupsMissing = errors.New("oidc: configured groups claim missing or malformed")

	// ErrEmailDomainNotAllowed: the configured
	// OIDCProvider.AllowedEmailDomains list is non-empty but the
	// authenticated user's email domain isn't in it. CRIT-5 closure
	// of the 2026-05-10 audit (pre-fix, the field was persisted +
	// surfaced through the API + MCP + GUI but never read here).
	// Operator-facing: configure the IdP to issue tokens for only
	// the right tenants, or add the domain to the provider's
	// allowed_email_domains list.
	ErrEmailDomainNotAllowed = errors.New("oidc: email domain not in allowlist")

	// ErrEmailMissingButRequired: AllowedEmailDomains is set on the
	// provider but the ID token / userinfo response did not surface
	// an email claim. Operator-facing: ensure the IdP scope set
	// includes `email` and the IdP releases the claim.
	ErrEmailMissingButRequired = errors.New("oidc: provider requires email but token has none")

	// ErrProviderDisabled signals the operator has flipped
	// OIDCProvider.Enabled=false on the matched provider. HandleAuthRequest
	// rejects with this sentinel so the LoginPage doesn't initiate a
	// handshake; AuthInfo's provider list filters disabled providers
	// out so the LoginPage button doesn't appear in the first place.
	// Audit 2026-05-10 MED-9 closure.
	ErrProviderDisabled = errors.New("oidc: provider is disabled")

	// ErrGroupsUnmapped: the user's groups don't match any of the
	// operator's group_role_mappings for this provider. No session
	// minted; audit row records auth.oidc_login_unmapped_groups.
	ErrGroupsUnmapped = errors.New("oidc: groups did not match any configured mapping")

	// ErrPKCEPlainRejected: somehow `plain` PKCE method got into
	// the flow. Defense-in-depth; the service NEVER generates a plain
	// verifier, but this sentinel exists in case a future code path
	// regresses.
	ErrPKCEPlainRejected = errors.New("oidc: PKCE method 'plain' is rejected; S256 is mandatory")
)

// DefaultAllowedAlgs is the operator-default ID-token signing algorithm
// allow-list. Configurable per-provider but the union must be a subset
// of this set. HMAC algorithms (HS256/HS384/HS512) and `none` are
// NEVER in the default set; the IdP downgrade defense rejects any
// provider that advertises them in discovery.
var DefaultAllowedAlgs = []string{
	gooidc.RS256, gooidc.RS512,
	gooidc.ES256, gooidc.ES384,
	gooidc.EdDSA,
}

// disallowedAlgs is the explicit deny-list. Anything in this set
// fails the IdP downgrade check at provider creation / RefreshKeys
// AND fails the per-token alg check at HandleCallback time, even if
// the operator somehow added it to AllowedAlgs by hand.
var disallowedAlgs = map[string]struct{}{
	"HS256": {},
	"HS384": {},
	"HS512": {},
	"none":  {},
}

// NewService constructs an OIDC Service.
func NewService(
	providers OIDCProviderLookup,
	mappings repository.GroupRoleMappingRepository,
	users repository.UserRepository,
	sessions SessionMinter,
	preLogin PreLoginStore,
	encryptionKey string,
) *Service {
	return &Service{
		providers:     providers,
		mappings:      mappings,
		users:         users,
		sessions:      sessions,
		preLogin:      preLogin,
		encryptionKey: encryptionKey,
		cache:         make(map[string]*providerEntry),
		clockNow:      time.Now,
	}
}

// SetClockForTest replaces the clock used for `iat`/`exp` checks. ONLY
// for tests; production paths read time.Now via the default.
func (s *Service) SetClockForTest(now func() time.Time) {
	s.clockNow = now
}

// =============================================================================
// HandleAuthRequest: kicks off the OIDC handshake.
//
// Returns the IdP authorization URL (302 target), the cookie value to
// set for the pre-login session, and the pre-login session ID for the
// audit trail. The caller (HTTP handler) sets the cookie + redirects.
//
// PKCE-S256 is mandatory: a 43-128 character base64url-no-pad random
// verifier is generated, the challenge is the SHA-256 of the verifier
// base64url-encoded, the method is hard-coded `S256`. No code path in
// this service ever sets `code_challenge_method=plain`.
// =============================================================================

// HandleAuthRequest builds the IdP redirect URL + persists the
// pre-login session row holding state + nonce + PKCE verifier.
func (s *Service) HandleAuthRequest(ctx context.Context, providerID string) (authURL, cookieValue, preLoginID string, err error) {
	entry, err := s.getOrLoad(ctx, providerID)
	if err != nil {
		return "", "", "", err
	}
	// Audit 2026-05-10 MED-9 closure — refuse to mint a pre-login row
	// for a disabled provider. The LoginPage's AuthInfo filter should
	// already prevent the button from rendering, but defense-in-depth
	// catches the direct-API/MCP/CLI invocation path too.
	if entry.cfgRow != nil && !entry.cfgRow.Enabled {
		return "", "", "", ErrProviderDisabled
	}

	state, err := randomB64URL(32)
	if err != nil {
		return "", "", "", fmt.Errorf("oidc: state generate: %w", err)
	}
	nonce, err := randomB64URL(32)
	if err != nil {
		return "", "", "", fmt.Errorf("oidc: nonce generate: %w", err)
	}
	// PKCE S256 verifier: 32 random bytes -> 43-char base64url-no-pad
	// (well within the RFC 7636 43-128 character bound).
	verifier := oauth2.GenerateVerifier()

	cookieValue, preLoginID, err = s.preLogin.CreatePreLogin(ctx, providerID, state, nonce, verifier)
	if err != nil {
		return "", "", "", fmt.Errorf("oidc: pre-login store: %w", err)
	}

	// Build the IdP redirect URL. PKCE S256 is hard-coded via
	// oauth2.S256ChallengeOption; nonce is added via OIDC's
	// AuthCodeOption.
	authURL = entry.oauthConfig.AuthCodeURL(
		state,
		oauth2.AccessTypeOnline,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	)

	return authURL, cookieValue, preLoginID, nil
}

// =============================================================================
// HandleCallback: completes the OIDC handshake and creates a session.
//
// Validates state, exchanges code for tokens (with PKCE verifier),
// validates ID token (alg pin, iss, aud, azp, at_hash, exp, iat,
// nonce), parses group claims, maps groups to roles, creates / updates
// the user record, mints a session.
//
// Every fail-closed branch returns one of the package-scoped sentinel
// errors so the handler can map to the right HTTP status without
// leaking which check failed (uniform 400 to the wire; specific
// reason in the audit row).
// =============================================================================

// CallbackResult is what HandleCallback returns to the handler. The
// handler sets cookieValue + csrfToken on the response and 302's to
// the GUI dashboard.
type CallbackResult struct {
	User        *userdomain.User
	RoleIDs     []string
	CookieValue string // post-login session cookie
	CSRFToken   string // CSRF token for the GUI to echo into X-CSRF-Token
}

// HandleCallback completes the OIDC flow.
//
// Audit 2026-05-10 MED-17 — `callbackIss` is the value of the `iss`
// query parameter on /auth/oidc/callback, exactly as sent by the IdP.
// When the matched provider's discovery doc advertises
// authorization_response_iss_parameter_supported=true (RFC 9207 §3),
// we require this parameter and verify it equals the provider's
// IssuerURL. When the provider doesn't advertise support (the default
// for most IdPs that haven't rolled RFC 9207 yet), the parameter is
// ignored — preserving back-compat with the pre-fix call path.
func (s *Service) HandleCallback(
	ctx context.Context,
	preLoginCookie, code, callbackState, callbackIss, ip, userAgent string,
) (*CallbackResult, error) {
	// Step 1: consume the pre-login row (single-use).
	providerID, storedState, storedNonce, verifier, err := s.preLogin.LookupAndConsume(ctx, preLoginCookie)
	if err != nil {
		return nil, ErrPreLoginNotFound
	}

	// Step 2: state constant-time compare.
	if subtle.ConstantTimeCompare([]byte(callbackState), []byte(storedState)) != 1 {
		return nil, ErrStateMismatch
	}

	entry, err := s.getOrLoad(ctx, providerID)
	if err != nil {
		return nil, err
	}

	// Step 2.5 — Audit 2026-05-10 MED-17 — RFC 9207 iss URL parameter
	// check. Only enforced when the provider advertised support in its
	// discovery doc. Compares against the matched provider's
	// IssuerURL (which is what go-oidc's gooidc.NewProvider verified
	// the discovery doc's own iss against during getOrLoad). Mismatch
	// is the load-bearing defense against mix-up attacks where the
	// honest IdP returns the auth code to the wrong endpoint because
	// of a malicious co-tenant relying-party.
	if entry.issParamSupported {
		if callbackIss == "" {
			return nil, ErrIssParamMissing
		}
		if subtle.ConstantTimeCompare([]byte(callbackIss), []byte(entry.cfgRow.IssuerURL)) != 1 {
			return nil, ErrIssParamMismatch
		}
	}

	// Step 3: exchange the auth code for tokens (with PKCE verifier).
	token, err := entry.oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange failed: %w", err)
	}

	// Step 4: extract + validate the ID token. NEVER log token here.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("oidc: token response missing id_token")
	}

	idToken, err := entry.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		// Map go-oidc's verify errors to ErrJWKSUnreachable when the
		// underlying cause is a JWKS fetch failure; otherwise return
		// the wrapped error for the handler to map to 400.
		if isJWKSFetchError(err) {
			return nil, ErrJWKSUnreachable
		}
		return nil, fmt.Errorf("oidc: id_token verify failed: %w", err)
	}

	// Step 5: alg pinning. go-oidc's verifier already enforces the
	// allow-list we set in the config, but we re-check the header alg
	// against our deny-list for belt-and-braces (defense vs an
	// upstream library regression).
	if rejected, alg := isDisallowedAlg(rawIDToken); rejected {
		_ = alg // do not log
		return nil, ErrAlgRejected
	}

	// Step 6: per-OIDC-core §3.1.3.7 claims checks beyond what
	// gooidc.Verify covers.
	now := s.clockNow().UTC()

	// iss is verified by gooidc.Verify against entry.cfgRow.IssuerURL;
	// re-check exactly to defend against a library regression.
	if idToken.Issuer != entry.cfgRow.IssuerURL {
		return nil, ErrIssuerMismatch
	}

	// aud must contain client_id.
	audOK := false
	for _, a := range idToken.Audience {
		if a == entry.cfgRow.ClientID {
			audOK = true
			break
		}
	}
	if !audOK {
		return nil, ErrAudienceMismatch
	}

	// azp required when aud is multi-valued; if present, must equal client_id.
	var extra struct {
		AZP    string `json:"azp"`
		ATHash string `json:"at_hash"`
		Nonce  string `json:"nonce"`
	}
	if err := idToken.Claims(&extra); err != nil {
		return nil, fmt.Errorf("oidc: id_token claims unmarshal: %w", err)
	}
	if len(idToken.Audience) > 1 {
		if extra.AZP == "" {
			return nil, ErrAZPRequired
		}
	}
	if extra.AZP != "" && extra.AZP != entry.cfgRow.ClientID {
		return nil, ErrAZPMismatch
	}

	// at_hash validation. When an access token is returned alongside the
	// ID token, OIDC core §3.1.3.6 + §3.2.2.9 require the ID token to
	// carry an at_hash claim that hashes the access token (alg-matching
	// hash family, left-half, base64url-no-pad). The Phase 3 spec lifts
	// this from the RFC's "MAY" to a "MUST" so a substituted access
	// token cannot ride a clean ID token through the verifier.
	if token.AccessToken != "" {
		if extra.ATHash == "" {
			return nil, ErrATHashRequired
		}
		if !atHashMatches(rawIDToken, token.AccessToken, extra.ATHash) {
			return nil, ErrATHashMismatch
		}
	}

	// exp + iat (60s clock skew tolerance).
	const skew = 60 * time.Second
	if idToken.Expiry.Add(skew).Before(now) {
		return nil, ErrTokenExpired
	}
	if idToken.IssuedAt.After(now.Add(skew)) {
		return nil, ErrIATInFuture
	}
	iatWindow := time.Duration(entry.cfgRow.IATWindowSeconds) * time.Second
	if idToken.IssuedAt.Add(iatWindow).Before(now) {
		return nil, ErrIATTooOld
	}

	// nonce constant-time compare.
	if subtle.ConstantTimeCompare([]byte(extra.Nonce), []byte(storedNonce)) != 1 {
		return nil, ErrNonceMismatch
	}

	// Step 7: extract claims for group resolution + user record.
	var profile struct {
		Email             string                 `json:"email"`
		Name              string                 `json:"name"`
		PreferredUsername string                 `json:"preferred_username"`
		Raw               map[string]interface{} `json:"-"`
	}
	if err := idToken.Claims(&profile); err != nil {
		return nil, fmt.Errorf("oidc: profile claims unmarshal: %w", err)
	}
	var raw map[string]interface{}
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("oidc: raw claims unmarshal: %w", err)
	}
	profile.Raw = raw

	// Step 7.5: email-domain allowlist enforcement. Audit 2026-05-10
	// CRIT-5 closure. When OIDCProvider.AllowedEmailDomains is non-
	// empty, the user's email-domain MUST be in the list (case-
	// insensitive exact match; subdomains are NOT auto-accepted — the
	// operator must list each subdomain explicitly).
	//
	// Empty list (default for new providers) = any email domain
	// accepted, matching the pre-fix behavior. Empty email claim with
	// a non-empty allowlist = ErrEmailMissingButRequired (operators
	// who set the allowlist explicitly expect email to be present).
	if len(entry.cfgRow.AllowedEmailDomains) > 0 {
		emailDomain, edErr := extractEmailDomain(profile.Email)
		if edErr != nil {
			return nil, ErrEmailMissingButRequired
		}
		matched := false
		for _, allowed := range entry.cfgRow.AllowedEmailDomains {
			if strings.EqualFold(strings.TrimSpace(allowed), emailDomain) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, ErrEmailDomainNotAllowed
		}
	}

	// Step 8: group claim resolution.
	groups, err := groupclaim.Resolve(profile.Raw, entry.cfgRow.GroupsClaimPath)
	if err != nil || len(groups) == 0 {
		// Try the userinfo endpoint fallback if the operator opted in.
		if entry.cfgRow.FetchUserinfo {
			groups2, uerr := s.fetchUserinfoGroups(ctx, entry, token, entry.cfgRow.GroupsClaimPath)
			if uerr == nil && len(groups2) > 0 {
				groups = groups2
			} else {
				return nil, ErrGroupsMissing
			}
		} else {
			return nil, ErrGroupsMissing
		}
	}

	// Step 9: map groups to role IDs. Phase 7 defers the empty-mapping
	// fail-closed check until after the bootstrap hook gets a chance to
	// grant r-admin (Step 11) — a fresh deployment with zero group_role_
	// mappings still needs to mint the first admin.
	roleIDs, err := s.mappings.Map(ctx, providerID, groups)
	if err != nil {
		return nil, fmt.Errorf("oidc: group-role mapping lookup: %w", err)
	}

	// Step 10: upsert the user record. Per Phase 1 contract, identity
	// is per-(provider, oidc_subject); a person logging in via a new
	// provider gets a new users row.
	user, err := s.upsertUser(ctx, entry.cfgRow, idToken.Subject, profile.Email, profile.Name, profile.PreferredUsername)
	if err != nil {
		return nil, fmt.Errorf("oidc: upsert user: %w", err)
	}

	// Step 11 — Phase 7: OIDC first-admin bootstrap hook. Optional;
	// runs after upsertUser. The hook checks AdminExists + group
	// intersection against CERTCTL_BOOTSTRAP_ADMIN_GROUPS; on first
	// match it grants r-admin to the user via ActorRoleRepository
	// + emits a bootstrap.oidc_first_admin audit row + returns
	// grantAdmin=true so we ensure r-admin lands in the role set.
	// Subsequent logins (admin-already-exists) silently skip via
	// grantAdmin=false.
	if s.adminBootstrapHook != nil {
		grantAdmin, herr := s.adminBootstrapHook(ctx, providerID, groups, user.ID)
		if herr != nil {
			return nil, fmt.Errorf("oidc: admin bootstrap: %w", herr)
		}
		if grantAdmin {
			roleIDs = appendIfMissing(roleIDs, "r-admin")
		}
	}

	// Step 12: empty-mapping fail-closed. Phase 3 contract preserved —
	// deferred from Step 9 only to give the bootstrap hook a chance.
	if len(roleIDs) == 0 {
		return nil, ErrGroupsUnmapped
	}

	// Step 13: mint a post-login session via Phase 4's SessionService.
	cookieValue, csrfToken, err := s.sessions.MintForUser(ctx, user, roleIDs, ip, userAgent)
	if err != nil {
		return nil, fmt.Errorf("oidc: session mint: %w", err)
	}

	return &CallbackResult{
		User:        user,
		RoleIDs:     roleIDs,
		CookieValue: cookieValue,
		CSRFToken:   csrfToken,
	}, nil
}

// upsertUser looks up by (provider, subject) and either updates the
// existing user or creates a new one. last_login_at is bumped on every
// login.
func (s *Service) upsertUser(
	ctx context.Context,
	provider *oidcdomain.OIDCProvider,
	subject, email, displayName, fallbackName string,
) (*userdomain.User, error) {
	if displayName == "" {
		displayName = fallbackName
	}
	if displayName == "" {
		displayName = email
	}

	existing, err := s.users.GetByOIDCSubject(ctx, provider.ID, subject)
	if err == nil {
		// Update last_login_at, email, display_name (per the Phase 1
		// mutable-field contract).
		existing.Email = email
		existing.DisplayName = displayName
		existing.LastLoginAt = s.clockNow().UTC()
		if uerr := s.users.Update(ctx, existing); uerr != nil {
			return nil, uerr
		}
		return existing, nil
	}
	if !errors.Is(err, repository.ErrUserNotFound) {
		return nil, err
	}

	// First login: create a new user record.
	id, err := randomB64URL(16)
	if err != nil {
		return nil, fmt.Errorf("oidc: user id generate: %w", err)
	}
	u := &userdomain.User{
		ID:                  "u-" + id,
		TenantID:            provider.TenantID,
		Email:               email,
		DisplayName:         displayName,
		OIDCSubject:         subject,
		OIDCProviderID:      provider.ID,
		LastLoginAt:         s.clockNow().UTC(),
		WebAuthnCredentials: []byte("[]"),
	}
	if verr := u.Validate(); verr != nil {
		return nil, fmt.Errorf("oidc: new user validate: %w", verr)
	}
	if cerr := s.users.Create(ctx, u); cerr != nil {
		return nil, cerr
	}
	return u, nil
}

// fetchUserinfoGroups falls back to the IdP userinfo endpoint when
// the operator opts in via fetch_userinfo=true AND the ID token
// didn't surface the groups claim. Returns the group list resolved
// against groups_claim_path.
func (s *Service) fetchUserinfoGroups(
	ctx context.Context,
	entry *providerEntry,
	token *oauth2.Token,
	path string,
) ([]string, error) {
	if entry.provider.UserInfoEndpoint() == "" {
		return nil, fmt.Errorf("oidc: userinfo fallback configured but provider has no userinfo endpoint")
	}
	ts := entry.oauthConfig.TokenSource(ctx, token)
	uinfo, err := entry.provider.UserInfo(ctx, ts)
	if err != nil {
		return nil, fmt.Errorf("oidc: userinfo fetch: %w", err)
	}
	var raw map[string]interface{}
	if err := uinfo.Claims(&raw); err != nil {
		return nil, fmt.Errorf("oidc: userinfo claims: %w", err)
	}
	return groupclaim.Resolve(raw, path)
}

// =============================================================================
// RefreshKeys: explicitly invalidate + refetch the cached provider.
//
// Used by the GUI's "Refresh discovery cache" button (Phase 8) when an
// operator knows the IdP rotated its keys mid-day and the JWKS cache
// is stale. Re-runs the IdP downgrade-attack defense too: if the IdP
// rotated in HS* / `none` advertisement, we catch it here.
// =============================================================================

// RefreshKeys evicts the cached provider entry and re-loads it from
// scratch. Invokes the discovery doc fetch + the downgrade defense.
func (s *Service) RefreshKeys(ctx context.Context, providerID string) error {
	s.mu.Lock()
	delete(s.cache, providerID)
	s.mu.Unlock()

	_, err := s.getOrLoad(ctx, providerID)
	return err
}

// =============================================================================
// Provider load + cache + IdP downgrade defense.
// =============================================================================

// getOrLoad returns a cached provider entry, loading from the repo +
// fetching the IdP discovery doc on miss. Cache uses a write-then-read
// pattern under sync.RWMutex; concurrent first-loads of the same
// provider may duplicate the discovery fetch but never produce
// divergent cache entries (the second-arriving entry overwrites and
// both entries are equivalent).
func (s *Service) getOrLoad(ctx context.Context, providerID string) (*providerEntry, error) {
	s.mu.RLock()
	entry, ok := s.cache[providerID]
	s.mu.RUnlock()
	if ok {
		return entry, nil
	}

	// Read the configured row.
	cfgRow, err := s.providers.Get(ctx, providerID)
	if err != nil {
		return nil, err
	}

	// Fetch + cache the discovery doc + JWKS via go-oidc.
	provider, err := gooidc.NewProvider(ctx, cfgRow.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery fetch failed for %s: %w", providerID, err)
	}

	// IdP downgrade-attack defense. The discovery doc's
	// id_token_signing_alg_values_supported MUST NOT include any
	// disallowed alg.
	//
	// Audit 2026-05-10 MED-17 — we also read
	// `authorization_response_iss_parameter_supported` from the same
	// claims call to drive the RFC 9207 iss-URL-parameter check in
	// HandleCallback.
	var advertised struct {
		IDTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported"`
		AuthorizationResponseIssParamSupported bool     `json:"authorization_response_iss_parameter_supported"`
	}
	if cerr := provider.Claims(&advertised); cerr != nil {
		return nil, fmt.Errorf("oidc: discovery claims: %w", cerr)
	}
	for _, a := range advertised.IDTokenSigningAlgValuesSupported {
		if _, deny := disallowedAlgs[a]; deny {
			return nil, fmt.Errorf("%w: %s", ErrIdPDowngradeAdvertised, a)
		}
	}

	// Compute the effective allow-list: intersection of the default
	// allow-list AND any operator-configured restriction (currently
	// the domain layer doesn't expose per-provider alg config beyond
	// the default; placeholder for a future Phase-3-extended config).
	allowed := DefaultAllowedAlgs

	// Decrypt the client secret. The plaintext is held in memory only;
	// never persisted, never logged.
	plaintext, err := decryptClientSecret(cfgRow.ClientSecretEncrypted, s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("oidc: client_secret decrypt: %w", err)
	}

	verifier := provider.Verifier(&gooidc.Config{
		ClientID:             cfgRow.ClientID,
		SupportedSigningAlgs: allowed,
	})

	oauthConfig := &oauth2.Config{
		ClientID:     cfgRow.ClientID,
		ClientSecret: string(plaintext),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfgRow.RedirectURI,
		Scopes:       cfgRow.Scopes,
	}

	entry = &providerEntry{
		cfgRow:            cfgRow,
		provider:          provider,
		verifier:          verifier,
		oauthConfig:       oauthConfig,
		allowedAlgs:       allowed,
		plaintext:         plaintext,
		issParamSupported: advertised.AuthorizationResponseIssParamSupported,
	}

	s.mu.Lock()
	s.cache[providerID] = entry
	s.mu.Unlock()

	return entry, nil
}

// =============================================================================
// Helpers (alg parsing, at_hash, random, JWKS-error detection,
// client_secret decrypt). Kept private; tests in service_test.go.
// =============================================================================

// randomB64URL returns nbytes of cryptographic randomness encoded as
// base64url-no-pad. Used for state, nonce, session IDs.
func randomB64URL(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := readRand(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// readRand is a package-level seam so tests can deterministically
// substitute crypto/rand. Production reads from crypto/rand.Reader.
var readRand = func(b []byte) (int, error) {
	return cryptorand.Read(b)
}

// isDisallowedAlg parses the JWS header alg and reports whether it's
// in the deny-list. NEVER returns or logs the alg; the caller maps
// the bool to ErrAlgRejected without surfacing details.
func isDisallowedAlg(rawJWT string) (bool, string) {
	// JWS Compact: <header>.<payload>.<signature>. Decode header,
	// extract `alg`. Defensive: catches bad input shapes too.
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return true, ""
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return true, ""
	}
	// Find the alg value. Extreme minimal parser: avoid pulling in
	// encoding/json so the path is allocation-tight on every login.
	// Format: {"alg":"RS256",...}; some libraries emit
	// {"alg" :  "RS256" ,...} so the parser tolerates whitespace
	// around both the colon and the value.
	hdr := string(headerJSON)
	idx := strings.Index(hdr, `"alg"`)
	if idx < 0 {
		return true, ""
	}
	rest := hdr[idx+5:] // skip "alg"
	rest = strings.TrimLeft(rest, " \t\r\n")
	if !strings.HasPrefix(rest, ":") {
		return true, ""
	}
	rest = rest[1:]
	rest = strings.TrimLeft(rest, " \t\r\n")
	if !strings.HasPrefix(rest, `"`) {
		return true, ""
	}
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return true, ""
	}
	alg := rest[:end]
	if _, deny := disallowedAlgs[alg]; deny {
		return true, alg
	}
	return false, alg
}

// atHashMatches recomputes at_hash per OIDC core §3.1.3.6 + §3.2.2.9
// and constant-time-compares against the claim. Algorithm matches the
// hash family of the ID token's signing alg (RS256 -> SHA-256, RS512
// -> SHA-512, ES256 -> SHA-256, ES384 -> SHA-384, EdDSA -> SHA-512).
// Returns true iff the recomputed half-hash equals the claim.
func atHashMatches(rawIDToken, accessToken, claimAtHash string) bool {
	_, alg := isDisallowedAlg(rawIDToken) // re-extracts alg
	var h hash.Hash
	switch alg {
	case "RS256", "ES256":
		h = sha256.New()
	case "ES384":
		h = sha512.New384()
	case "RS512", "EdDSA":
		h = sha512.New()
	default:
		// Unknown alg should already have been caught by the
		// alg-pin check; refuse to recompute here.
		return false
	}
	h.Write([]byte(accessToken))
	sum := h.Sum(nil)
	half := sum[:len(sum)/2]
	expected := base64.RawURLEncoding.EncodeToString(half)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(claimAtHash)) == 1
}

// isJWKSFetchError detects whether the underlying error from
// gooidc.IDTokenVerifier.Verify is a JWKS-fetch failure (network
// error talking to the IdP's jwks_uri during a key rotation event).
// Maps to ErrJWKSUnreachable so the handler returns 503 to the
// in-flight login attempt without auto-revoking existing sessions.
//
// Audit 2026-05-10 Nit-2 — pinned against go-oidc/v3 v3.18.0. As of
// that release, the only typed error exposed by the oidc package is
// `*oidc.TokenExpiredError`; JWKS-fetch failures bubble up as
// fmt.Errorf-wrapped strings from internal/keyset.go's `verify` path
// (`failed to verify signature: fetching keys: ...`,
// `oidc: fetching keys ...`, `oidc: failed to get keys for kid ...`).
// The regression test in service_test.go::TestIsJWKSFetchError_GoOIDCV318Strings
// pins the canonical substrings; a future go-oidc bump that changes
// the wording trips the test and forces this function to be re-derived.
// When go-oidc exposes a typed error (track at
// https://github.com/coreos/go-oidc/issues for the upstream RFE),
// switch to errors.As.
func isJWKSFetchError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "fetching keys") ||
		strings.Contains(msg, "jwks_uri") ||
		strings.Contains(msg, "key set") ||
		// go-oidc/v3 v3.18.0 jwks.go:260: `oidc: failed to decode keys`
		// — emitted when the IdP returns non-JSON at the jwks_uri
		// (broken proxy, gateway HTML error page, etc.). Audit
		// 2026-05-10 Nit-2 closure — was previously misclassified as
		// a generic 500 instead of 503 ErrJWKSUnreachable.
		strings.Contains(msg, "decode keys")
}

// decryptClientSecret runs the client_secret_encrypted blob through
// internal/crypto/encryption.go's v2 Decrypt path. The plaintext
// MUST NOT be logged or written anywhere except oauthConfig.ClientSecret.
func decryptClientSecret(blob []byte, key string) ([]byte, error) {
	if key == "" {
		// Test path / local dev: blob is already the plaintext (the
		// caller didn't run it through Encrypt). Return as-is.
		return blob, nil
	}
	plain, err := crypto.DecryptIfKeySet(blob, key)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// extractEmailDomain returns the lowercase domain portion of an RFC
// 5322-ish email address. Used by HandleCallback Step 7.5 (CRIT-5
// closure) to enforce OIDCProvider.AllowedEmailDomains. Rejects empty
// input, addresses with no '@', and addresses with empty local-part
// or domain-part. Does NOT validate the full RFC grammar — IdPs are
// upstream of this and have their own validation; we only need a
// stable domain-extraction for the allowlist comparison.
func extractEmailDomain(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", fmt.Errorf("empty email")
	}
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "", fmt.Errorf("invalid email shape: %q", email)
	}
	return strings.ToLower(email[at+1:]), nil
}
