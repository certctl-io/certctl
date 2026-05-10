package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
	userdomain "github.com/certctl-io/certctl/internal/auth/user/domain"
	cryptopkg "github.com/certctl-io/certctl/internal/crypto"
	"github.com/certctl-io/certctl/internal/repository"
)

// sha384New returns a SHA-384 hash via crypto/sha512 (Go stdlib).
func sha384New() hash.Hash { return sha512.New384() }

// sha512New returns a SHA-512 hash. Helper named to mirror sha384New.
func sha512New() hash.Hash { return sha512.New() }

// =============================================================================
// Mock IdP test fixture
//
// Spins up an httptest.Server that serves the OIDC discovery doc + JWKS
// + a token endpoint that returns server-signed ID tokens. Lets us
// drive the full OIDC service.HandleCallback path without a live IdP.
// Used by the audience / issuer / nonce / azp / at_hash / iat negative
// tests below.
// =============================================================================

type mockIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	signer jose.Signer
	keyID  string

	// Per-request token customization. Tests set these before calling
	// HandleCallback to inject the specific malformity.
	overrideAudience []string
	overrideIssuer   string
	overrideNonce    string
	overrideAZP      string
	overrideExp      time.Time
	overrideIAT      time.Time
	overrideSubject  string
	overrideEmail    string
	overrideGroups   []string
	overrideATHash   string // when set, injected as the id_token at_hash claim
	overrideName     string // when set to a sentinel "<empty>", emits empty name

	// advertisedAlgs controls what id_token_signing_alg_values_supported
	// reports in the discovery doc. Tests set ["HS256"] to trigger the
	// downgrade-attack defense.
	advertisedAlgs []string

	// omitUserinfoEndpoint suppresses listing the userinfo endpoint in
	// the discovery doc. Used to test the "userinfo fallback configured
	// but provider has no userinfo endpoint" branch in fetchUserinfoGroups.
	omitUserinfoEndpoint bool

	// userinfoGroups is what the /userinfo endpoint returns under the
	// `groups` claim. Empty (default) means the endpoint returns a
	// response without a `groups` claim at all.
	userinfoGroups []string

	// userinfoFails causes /userinfo to return HTTP 500. Used to
	// exercise fetchUserinfoGroups's UserInfo-fetch error wrap.
	userinfoFails bool

	// suppressIDToken causes /token to return a response WITHOUT an
	// id_token field. Used to test the "token response missing
	// id_token" branch in HandleCallback.
	suppressIDToken bool

	// Captured to assert the PKCE verifier round-trip + return a stub
	// access_token + id_token to the service.
	receivedCode     string
	receivedVerifier string
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	keyID := "test-key-1"
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}

	idp := &mockIdP{
		key:            key,
		signer:         signer,
		keyID:          keyID,
		advertisedAlgs: []string{"RS256"},
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		doc := map[string]interface{}{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"id_token_signing_alg_values_supported": idp.advertisedAlgs,
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		}
		if !idp.omitUserinfoEndpoint {
			doc["userinfo_endpoint"] = base + "/userinfo"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if idp.userinfoFails {
			http.Error(w, "userinfo simulated failure", http.StatusInternalServerError)
			return
		}
		// The OAuth2 client sends the access token as Bearer; we don't
		// validate the value (the test stub always returns
		// "test-access-token" from /token). Return a JSON body with the
		// claims the production fetchUserinfoGroups path consumes.
		body := map[string]interface{}{
			"sub":   "test-subject",
			"email": "user@example.com",
		}
		if idp.userinfoGroups != nil {
			body["groups"] = idp.userinfoGroups
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{Key: key.Public(), KeyID: keyID, Algorithm: "RS256", Use: "sig"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.receivedCode = r.PostFormValue("code")
		idp.receivedVerifier = r.PostFormValue("code_verifier")

		base := "http://" + r.Host
		now := time.Now().UTC()

		audience := []string{"certctl"}
		if idp.overrideAudience != nil {
			audience = idp.overrideAudience
		}
		issuer := base
		if idp.overrideIssuer != "" {
			issuer = idp.overrideIssuer
		}
		exp := now.Add(time.Hour)
		if !idp.overrideExp.IsZero() {
			exp = idp.overrideExp
		}
		iat := now
		if !idp.overrideIAT.IsZero() {
			iat = idp.overrideIAT
		}
		subject := "test-subject"
		if idp.overrideSubject != "" {
			subject = idp.overrideSubject
		}
		email := "user@example.com"
		if idp.overrideEmail == "<empty>" {
			email = ""
		} else if idp.overrideEmail != "" {
			email = idp.overrideEmail
		}
		groups := []string{"engineers"}
		if idp.overrideGroups != nil {
			groups = idp.overrideGroups
		}

		// "name" is included by default; "<empty>" sentinel suppresses it
		// (used to test the upsertUser display-name fallback chain).
		name := "Test User"
		if idp.overrideName == "<empty>" {
			name = ""
		} else if idp.overrideName != "" {
			name = idp.overrideName
		}
		claims := map[string]interface{}{
			"iss":    issuer,
			"aud":    audience,
			"sub":    subject,
			"exp":    exp.Unix(),
			"iat":    iat.Unix(),
			"email":  email,
			"name":   name,
			"groups": groups,
		}
		if idp.overrideNonce != "" {
			claims["nonce"] = idp.overrideNonce
		} else {
			// Echo back whatever nonce the test supplied via the
			// pre-login row. The test stub PreLoginStore generates a
			// fixed nonce; we mirror it here.
			claims["nonce"] = "test-nonce-fixed"
		}
		if idp.overrideAZP != "" {
			claims["azp"] = idp.overrideAZP
		}
		// Default: emit a correct at_hash computed from the canned
		// access_token under SHA-256 (matches the RS256 signing alg the
		// mockIdP uses). Tests that need to exercise the
		// at_hash-mismatch / at_hash-missing paths set overrideATHash
		// to "<wrong>" or "<empty>" respectively.
		switch idp.overrideATHash {
		case "":
			h := sha256.Sum256([]byte("test-access-token"))
			claims["at_hash"] = base64.RawURLEncoding.EncodeToString(h[:len(h)/2])
		case "<empty>":
			// Suppress at_hash entirely.
		default:
			claims["at_hash"] = idp.overrideATHash
		}

		raw, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		resp := map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		if !idp.suppressIDToken {
			resp["id_token"] = raw
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Tests call HandleCallback directly; this endpoint exists for
		// completeness but the test never round-trips through it.
		http.Error(w, "test fixture: not implemented", 501)
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (m *mockIdP) URL() string { return m.server.URL }

// =============================================================================
// Stubs for the Service's collaborators
// =============================================================================

type stubProviderLookup struct {
	provider *oidcdomain.OIDCProvider
}

func (s *stubProviderLookup) Get(_ context.Context, id string) (*oidcdomain.OIDCProvider, error) {
	if s.provider == nil || s.provider.ID != id {
		return nil, repository.ErrOIDCProviderNotFound
	}
	return s.provider, nil
}
func (s *stubProviderLookup) List(_ context.Context, _ string) ([]*oidcdomain.OIDCProvider, error) {
	if s.provider == nil {
		return nil, nil
	}
	return []*oidcdomain.OIDCProvider{s.provider}, nil
}

type stubMappings struct {
	roleIDs []string
	mapErr  error // when set, Map returns this error
}

func (s *stubMappings) ListByProvider(_ context.Context, _ string) ([]*oidcdomain.GroupRoleMapping, error) {
	return nil, nil
}
func (s *stubMappings) Get(_ context.Context, _ string) (*oidcdomain.GroupRoleMapping, error) {
	return nil, repository.ErrGroupRoleMappingNotFound
}
func (s *stubMappings) Add(_ context.Context, _ *oidcdomain.GroupRoleMapping) error { return nil }
func (s *stubMappings) Remove(_ context.Context, _ string) error                    { return nil }
func (s *stubMappings) Map(_ context.Context, _ string, _ []string) ([]string, error) {
	if s.mapErr != nil {
		return nil, s.mapErr
	}
	return s.roleIDs, nil
}

type stubUsers struct {
	byID      map[string]*userdomain.User
	bySubject map[string]*userdomain.User
	createErr error // when set, Create returns this error
	getErr    error // when set, GetByOIDCSubject returns this error (other than NotFound)
}

func newStubUsers() *stubUsers {
	return &stubUsers{
		byID:      make(map[string]*userdomain.User),
		bySubject: make(map[string]*userdomain.User),
	}
}
func (s *stubUsers) Get(_ context.Context, id string) (*userdomain.User, error) {
	u, ok := s.byID[id]
	if !ok {
		return nil, repository.ErrUserNotFound
	}
	return u, nil
}
func (s *stubUsers) GetByOIDCSubject(_ context.Context, providerID, subject string) (*userdomain.User, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	u, ok := s.bySubject[providerID+":"+subject]
	if !ok {
		return nil, repository.ErrUserNotFound
	}
	return u, nil
}
func (s *stubUsers) Create(_ context.Context, u *userdomain.User) error {
	if s.createErr != nil {
		return s.createErr
	}
	s.byID[u.ID] = u
	s.bySubject[u.OIDCProviderID+":"+u.OIDCSubject] = u
	return nil
}
func (s *stubUsers) Update(_ context.Context, u *userdomain.User) error {
	s.byID[u.ID] = u
	s.bySubject[u.OIDCProviderID+":"+u.OIDCSubject] = u
	return nil
}
func (s *stubUsers) ListAll(_ context.Context, _ string) ([]*userdomain.User, error) {
	out := make([]*userdomain.User, 0, len(s.byID))
	for _, u := range s.byID {
		out = append(out, u)
	}
	return out, nil
}

type stubSessions struct {
	cookieValue string
	csrfToken   string
	mintErr     error // when set, MintForUser returns this error
}

func (s *stubSessions) MintForUser(_ context.Context, _ *userdomain.User, _ []string, _, _ string) (string, string, error) {
	if s.mintErr != nil {
		return "", "", s.mintErr
	}
	if s.cookieValue == "" {
		s.cookieValue = "test-cookie"
	}
	if s.csrfToken == "" {
		s.csrfToken = "test-csrf"
	}
	return s.cookieValue, s.csrfToken, nil
}

// stubPreLogin is in-memory PreLoginStore. Single-use enforced via
// delete-on-LookupAndConsume.
type stubPreLogin struct {
	rows      map[string]preLoginRow
	createErr error // when set, CreatePreLogin returns this error
}

type preLoginRow struct {
	providerID, state, nonce, verifier string
}

func newStubPreLogin() *stubPreLogin {
	return &stubPreLogin{rows: make(map[string]preLoginRow)}
}
func (s *stubPreLogin) CreatePreLogin(_ context.Context, providerID, state, nonce, verifier string) (string, string, error) {
	if s.createErr != nil {
		return "", "", s.createErr
	}
	cookieVal := fmt.Sprintf("pl-%d", len(s.rows)+1)
	s.rows[cookieVal] = preLoginRow{providerID, state, nonce, verifier}
	return cookieVal, "ses-" + cookieVal, nil
}
func (s *stubPreLogin) LookupAndConsume(_ context.Context, cookie string) (string, string, string, string, error) {
	r, ok := s.rows[cookie]
	if !ok {
		return "", "", "", "", ErrPreLoginNotFound
	}
	delete(s.rows, cookie)
	return r.providerID, r.state, r.nonce, r.verifier, nil
}

// =============================================================================
// Standalone unit tests (no live IdP needed)
// =============================================================================

// Test 1: PKCE 'plain' is rejected. The Service NEVER generates a plain
// verifier (oauth2.GenerateVerifier + S256ChallengeOption are
// hard-coded), but we pin the deny-list constant exists so a future
// regression is caught.
func TestService_PKCEPlainRejectedSentinel(t *testing.T) {
	// The sentinel exists; that's the contract a future code path must
	// reference if it ever surfaces a plain-method path. Pin it.
	if ErrPKCEPlainRejected == nil {
		t.Fatalf("ErrPKCEPlainRejected sentinel must exist")
	}
	if !strings.Contains(ErrPKCEPlainRejected.Error(), "plain") {
		t.Errorf("sentinel message should reference 'plain'; got %q", ErrPKCEPlainRejected.Error())
	}
}

// Test 2: state replay (consume-once). After LookupAndConsume succeeds,
// a second call with the same cookie returns ErrPreLoginNotFound.
func TestService_StateReplayDeniedByConsumeOnce(t *testing.T) {
	pl := newStubPreLogin()
	cookie, _, err := pl.CreatePreLogin(context.Background(), "op-x", "the-state", "the-nonce", "verifier-xxx")
	if err != nil {
		t.Fatalf("CreatePreLogin: %v", err)
	}
	if _, _, _, _, err := pl.LookupAndConsume(context.Background(), cookie); err != nil {
		t.Fatalf("first LookupAndConsume: %v", err)
	}
	_, _, _, _, err = pl.LookupAndConsume(context.Background(), cookie)
	if !errors.Is(err, ErrPreLoginNotFound) {
		t.Errorf("second LookupAndConsume err = %v; want ErrPreLoginNotFound (single-use violated)", err)
	}
}

// Test 3: forged pre-login cookie returns ErrPreLoginNotFound.
func TestService_HandleCallback_RejectsForgedPreLoginCookie(t *testing.T) {
	svc := newServiceForUnitTest(t)
	_, err := svc.HandleCallback(context.Background(), "bogus-cookie", "any-code", "any-state", "ip", "ua")
	if !errors.Is(err, ErrPreLoginNotFound) {
		t.Errorf("err = %v; want ErrPreLoginNotFound", err)
	}
}

// Test 4: state mismatch (cookie matches but the callback state doesn't).
func TestService_HandleCallback_RejectsStateMismatch(t *testing.T) {
	svc, pl := newServiceForUnitTestWithPL(t)
	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-test", "real-state", "real-nonce", "verifier-xxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "wrong-state", "ip", "ua")
	if !errors.Is(err, ErrStateMismatch) {
		t.Errorf("err = %v; want ErrStateMismatch", err)
	}
}

// Test 5: alg pinning — direct unit test of isDisallowedAlg helper.
// Hand-builds a JWT header for each algorithm, asserts the deny-list
// catches HS* and `none`.
func TestService_AlgPinning_RejectsHSAlgsAndNone(t *testing.T) {
	for _, alg := range []string{"HS256", "HS384", "HS512", "none"} {
		header := fmt.Sprintf(`{"alg":%q,"typ":"JWT"}`, alg)
		token := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".body.sig"
		rejected, gotAlg := isDisallowedAlg(token)
		if !rejected {
			t.Errorf("alg=%q: not rejected; want rejected", alg)
		}
		if gotAlg != alg {
			t.Errorf("alg=%q: extracted %q; want %q", alg, gotAlg, alg)
		}
	}
}

// Test 6: alg pinning — allowed algs pass.
func TestService_AlgPinning_AllowsRSAndECAndEdDSA(t *testing.T) {
	for _, alg := range []string{"RS256", "RS512", "ES256", "ES384", "EdDSA"} {
		header := fmt.Sprintf(`{"alg":%q,"typ":"JWT"}`, alg)
		token := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".body.sig"
		rejected, gotAlg := isDisallowedAlg(token)
		if rejected {
			t.Errorf("alg=%q: rejected; want allowed", alg)
		}
		if gotAlg != alg {
			t.Errorf("alg=%q: extracted %q; want %q", alg, gotAlg, alg)
		}
	}
}

// Test 7: malformed JWT (wrong segment count) → rejected as if alg-bad.
func TestService_AlgPinning_RejectsMalformedJWT(t *testing.T) {
	for _, bad := range []string{"", "single-segment", "two.segments", "more.than.three.segments"} {
		rejected, _ := isDisallowedAlg(bad)
		if !rejected {
			t.Errorf("malformed JWT %q: not rejected", bad)
		}
	}
}

// Test 8: at_hash recomputation — happy path matches.
func TestService_ATHash_MatchesForRS256(t *testing.T) {
	accessToken := "test-access-token-value"
	h := sha256.Sum256([]byte(accessToken))
	half := h[:len(h)/2]
	expected := base64.RawURLEncoding.EncodeToString(half)

	header := `{"alg":"RS256","typ":"JWT"}`
	rawIDToken := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".body.sig"
	if !atHashMatches(rawIDToken, accessToken, expected) {
		t.Errorf("atHashMatches should accept correctly-computed at_hash")
	}
}

// Test 9: at_hash mismatch → rejected.
func TestService_ATHash_RejectsMismatch(t *testing.T) {
	header := `{"alg":"RS256","typ":"JWT"}`
	rawIDToken := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".body.sig"
	if atHashMatches(rawIDToken, "the-token", "wrong-hash-claim") {
		t.Errorf("atHashMatches accepted bad at_hash; should reject")
	}
}

// Test 10: at_hash for unknown alg returns false (defense vs an alg
// that escaped the alg-pin check).
func TestService_ATHash_UnknownAlgReturnsFalse(t *testing.T) {
	header := `{"alg":"unknown","typ":"JWT"}`
	rawIDToken := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".body.sig"
	if atHashMatches(rawIDToken, "any-access-token", "any-hash") {
		t.Errorf("atHashMatches with unknown alg should return false")
	}
}

// Test 11: IdP downgrade-attack defense. A provider whose discovery doc
// advertises HS256 in id_token_signing_alg_values_supported is REJECTED
// by the cache load with ErrIdPDowngradeAdvertised.
func TestService_IdPDowngradeDefense_RejectsHSAdvertised(t *testing.T) {
	idp := newMockIdP(t)
	idp.advertisedAlgs = []string{"RS256", "HS256"} // HS256 is the downgrade vector

	svc, _ := newServiceWithProvider(t, idp.URL(), "op-bad-idp")

	_, err := svc.getOrLoad(context.Background(), "op-bad-idp")
	if !errors.Is(err, ErrIdPDowngradeAdvertised) {
		t.Errorf("err = %v; want ErrIdPDowngradeAdvertised", err)
	}
}

// Test 12: IdP downgrade-attack defense — `none` advertisement also
// triggers rejection.
func TestService_IdPDowngradeDefense_RejectsNoneAdvertised(t *testing.T) {
	idp := newMockIdP(t)
	idp.advertisedAlgs = []string{"RS256", "none"}

	svc, _ := newServiceWithProvider(t, idp.URL(), "op-none-idp")

	_, err := svc.getOrLoad(context.Background(), "op-none-idp")
	if !errors.Is(err, ErrIdPDowngradeAdvertised) {
		t.Errorf("err = %v; want ErrIdPDowngradeAdvertised", err)
	}
}

// Test 13: clean RS256 IdP loads successfully.
func TestService_GetOrLoad_AcceptsCleanIdP(t *testing.T) {
	idp := newMockIdP(t) // default advertisedAlgs=["RS256"]
	svc, _ := newServiceWithProvider(t, idp.URL(), "op-good-idp")

	entry, err := svc.getOrLoad(context.Background(), "op-good-idp")
	if err != nil {
		t.Fatalf("getOrLoad: %v", err)
	}
	if entry.provider == nil {
		t.Errorf("entry.provider is nil")
	}
	if entry.verifier == nil {
		t.Errorf("entry.verifier is nil")
	}
}

// Test 14: RefreshKeys evicts the cache + re-fetches discovery, which
// re-runs the downgrade defense. If the IdP rotated to advertising
// HS256 between loads, RefreshKeys catches it.
func TestService_RefreshKeys_CatchesPostLoadDowngrade(t *testing.T) {
	idp := newMockIdP(t)
	svc, _ := newServiceWithProvider(t, idp.URL(), "op-rotate")

	if _, err := svc.getOrLoad(context.Background(), "op-rotate"); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	// IdP rotates to advertising HS256.
	idp.advertisedAlgs = []string{"RS256", "HS256"}
	err := svc.RefreshKeys(context.Background(), "op-rotate")
	if !errors.Is(err, ErrIdPDowngradeAdvertised) {
		t.Errorf("RefreshKeys err = %v; want ErrIdPDowngradeAdvertised", err)
	}
}

// Test 15: HandleCallback happy path against the mock IdP.
func TestService_HandleCallback_HappyPath(t *testing.T) {
	idp := newMockIdP(t)
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-happy")

	cookie, _, err := pl.CreatePreLogin(context.Background(), "op-happy", "happy-state", "test-nonce-fixed", "verifier-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if err != nil {
		t.Fatalf("CreatePreLogin: %v", err)
	}

	res, err := svc.HandleCallback(context.Background(), cookie, "test-code", "happy-state", "10.0.0.1", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if res.User == nil {
		t.Errorf("CallbackResult.User nil")
	}
	if len(res.RoleIDs) == 0 {
		t.Errorf("CallbackResult.RoleIDs empty")
	}
	if res.CookieValue == "" {
		t.Errorf("CallbackResult.CookieValue empty")
	}
}

// Test 16: HandleCallback rejects ID token with wrong audience.
func TestService_HandleCallback_RejectsWrongAudience(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideAudience = []string{"some-other-client"}
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-aud")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-aud", "s", "test-nonce-fixed", "v-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	// gooidc.Verify catches this first; its wrap reaches us as a wrapped error.
	// Either ErrAudienceMismatch (our re-check) OR a wrapped verify error is acceptable.
	if err == nil {
		t.Errorf("expected non-nil err for wrong-aud token")
	}
}

// Test 17: HandleCallback rejects an ID token whose nonce doesn't match
// the pre-login row.
func TestService_HandleCallback_RejectsNonceMismatch(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideNonce = "wrong-nonce-from-idp"
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-nonce")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-nonce", "s", "expected-nonce", "v-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrNonceMismatch) {
		t.Errorf("err = %v; want ErrNonceMismatch", err)
	}
}

// Test 18: HandleCallback rejects expired ID token.
func TestService_HandleCallback_RejectsExpiredToken(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideExp = time.Now().Add(-2 * time.Hour) // 2 hours past
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-exp")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-exp", "s", "test-nonce-fixed", "v-cccccccccccccccccccccccccccccccccccccccccc")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	// Either ErrTokenExpired (our re-check) or a wrapped verify error is fine.
	if err == nil {
		t.Errorf("expected non-nil err for expired token")
	}
}

// Test 19: HandleCallback rejects ID token whose iat is too old per the
// configured IATWindow.
func TestService_HandleCallback_RejectsIATTooOld(t *testing.T) {
	idp := newMockIdP(t)
	// Token was issued 20 minutes ago; default IATWindow is 5 minutes.
	idp.overrideIAT = time.Now().Add(-20 * time.Minute)
	idp.overrideExp = time.Now().Add(2 * time.Hour) // exp is fine
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-iat")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-iat", "s", "test-nonce-fixed", "v-dddddddddddddddddddddddddddddddddddddddddd")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrIATTooOld) {
		t.Errorf("err = %v; want ErrIATTooOld", err)
	}
}

// Test 20: HandleCallback rejects when group claim is missing.
func TestService_HandleCallback_RejectsGroupsMissing(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideGroups = []string{} // empty groups claim
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-grp")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-grp", "s", "test-nonce-fixed", "v-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrGroupsMissing) {
		t.Errorf("err = %v; want ErrGroupsMissing", err)
	}
}

// Test 21: HandleCallback rejects when groups don't match any
// configured mapping → ErrGroupsUnmapped.
func TestService_HandleCallback_RejectsGroupsUnmapped(t *testing.T) {
	idp := newMockIdP(t)
	svc, pl := newServiceWithProviderAndPLNoMappings(t, idp.URL(), "op-unmap")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-unmap", "s", "test-nonce-fixed", "v-ffffffffffffffffffffffffffffffffffffffffff")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrGroupsUnmapped) {
		t.Errorf("err = %v; want ErrGroupsUnmapped", err)
	}
}

// =============================================================================
// Test helpers
// =============================================================================

func makeProvider(idpURL, providerID string) *oidcdomain.OIDCProvider {
	return &oidcdomain.OIDCProvider{
		ID:                    providerID,
		TenantID:              "t-default",
		Name:                  "Test " + providerID,
		IssuerURL:             idpURL,
		ClientID:              "certctl",
		ClientSecretEncrypted: []byte("test-secret"),
		RedirectURI:           "https://certctl.example.com/auth/oidc/callback",
		GroupsClaimPath:       "groups",
		GroupsClaimFormat:     "string-array",
		Scopes:                []string{"openid", "profile", "email"},
		IATWindowSeconds:      300,
		JWKSCacheTTLSeconds:   3600,
	}
}

// newServiceWithProvider returns a Service wired against the given IdP
// URL + a provider already in the stub provider lookup.
func newServiceWithProvider(t *testing.T, idpURL, providerID string) (*Service, *stubPreLogin) {
	return newServiceWithProviderAndPL(t, idpURL, providerID)
}

func newServiceWithProviderAndPL(t *testing.T, idpURL, providerID string) (*Service, *stubPreLogin) {
	t.Helper()
	prov := makeProvider(idpURL, providerID)
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(
		&stubProviderLookup{provider: prov},
		mappings,
		users,
		sessions,
		pl,
		"", // no encryption key; client_secret already plaintext for test
	)
	return svc, pl
}

func newServiceWithProviderAndPLNoMappings(t *testing.T, idpURL, providerID string) (*Service, *stubPreLogin) {
	t.Helper()
	prov := makeProvider(idpURL, providerID)
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: nil} // empty mappings
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(
		&stubProviderLookup{provider: prov},
		mappings,
		users,
		sessions,
		pl,
		"",
	)
	return svc, pl
}

func newServiceForUnitTest(t *testing.T) *Service {
	t.Helper()
	pl := newStubPreLogin()
	return NewService(
		&stubProviderLookup{},
		&stubMappings{},
		newStubUsers(),
		&stubSessions{},
		pl,
		"",
	)
}

func newServiceForUnitTestWithPL(t *testing.T) (*Service, *stubPreLogin) {
	t.Helper()
	pl := newStubPreLogin()
	return NewService(
		&stubProviderLookup{},
		&stubMappings{},
		newStubUsers(),
		&stubSessions{},
		pl,
		"",
	), pl
}

// =============================================================================
// Additional coverage tests: HandleAuthRequest entry point, upsert
// update path, atHashMatches alg coverage, helpers.
// =============================================================================

// TestService_HandleAuthRequest_BuildsValidIdPRedirect covers the
// authz-request path end-to-end. Asserts the URL contains state +
// nonce + code_challenge_method=S256 + the operator-configured
// client_id.
func TestService_HandleAuthRequest_BuildsValidIdPRedirect(t *testing.T) {
	idp := newMockIdP(t)
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-har")

	authURL, cookieValue, preLoginID, err := svc.HandleAuthRequest(context.Background(), "op-har")
	if err != nil {
		t.Fatalf("HandleAuthRequest: %v", err)
	}
	if cookieValue == "" || preLoginID == "" {
		t.Errorf("empty cookieValue or preLoginID")
	}
	for _, want := range []string{
		"client_id=certctl",
		"code_challenge_method=S256",
		"code_challenge=",
		"state=",
		"nonce=",
		"redirect_uri=",
		"scope=",
	} {
		if !strings.Contains(authURL, want) {
			t.Errorf("authURL missing %q in %q", want, authURL)
		}
	}
	// Pin the pre-login row got persisted with a matching state value.
	if len(pl.rows) != 1 {
		t.Errorf("pl rows = %d; want 1", len(pl.rows))
	}
}

// TestService_HandleAuthRequest_UnknownProviderRejected pins the
// repo-not-found path through HandleAuthRequest.
func TestService_HandleAuthRequest_UnknownProviderRejected(t *testing.T) {
	svc := newServiceForUnitTest(t)
	_, _, _, err := svc.HandleAuthRequest(context.Background(), "op-nonexistent")
	if !errors.Is(err, repository.ErrOIDCProviderNotFound) {
		t.Errorf("err = %v; want ErrOIDCProviderNotFound", err)
	}
}

// TestService_UpsertUser_UpdateExistingPath: a second login by the
// same user updates last_login_at + email + display_name without
// creating a duplicate row.
func TestService_UpsertUser_UpdateExistingPath(t *testing.T) {
	idp := newMockIdP(t)
	users := newStubUsers()

	prov := makeProvider(idp.URL(), "op-upd")
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	// First login creates the user.
	cookie1, _, _ := pl.CreatePreLogin(context.Background(), "op-upd", "s1", "test-nonce-fixed", "v-1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	res1, err := svc.HandleCallback(context.Background(), cookie1, "code", "s1", "ip", "ua")
	if err != nil {
		t.Fatalf("first HandleCallback: %v", err)
	}
	if len(users.byID) != 1 {
		t.Errorf("first login: user count = %d; want 1", len(users.byID))
	}
	originalLogin := res1.User.LastLoginAt

	time.Sleep(10 * time.Millisecond) // ensure timestamps advance

	// Second login by same subject: update path, no new user row.
	cookie2, _, _ := pl.CreatePreLogin(context.Background(), "op-upd", "s2", "test-nonce-fixed", "v-2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	idp.overrideEmail = "user-renamed@example.com"
	res2, err := svc.HandleCallback(context.Background(), cookie2, "code2", "s2", "ip", "ua")
	if err != nil {
		t.Fatalf("second HandleCallback: %v", err)
	}
	if len(users.byID) != 1 {
		t.Errorf("second login: user count = %d; want 1 (Update path)", len(users.byID))
	}
	if !res2.User.LastLoginAt.After(originalLogin) {
		t.Errorf("LastLoginAt did not advance on second login: %v -> %v", originalLogin, res2.User.LastLoginAt)
	}
	if res2.User.Email != "user-renamed@example.com" {
		t.Errorf("Email did not update: %q", res2.User.Email)
	}
}

// TestService_ATHash_CoversAllAllowedAlgs pins the at_hash alg dispatch
// for every algorithm in DefaultAllowedAlgs.
func TestService_ATHash_CoversAllAllowedAlgs(t *testing.T) {
	cases := []struct {
		alg      string
		hashName string
	}{
		{"RS256", "sha256"},
		{"RS512", "sha512"},
		{"ES256", "sha256"},
		{"ES384", "sha384"},
		{"EdDSA", "sha512"},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			accessToken := "access-token-for-" + tc.alg
			// Compute the expected hash using the same logic as atHashMatches.
			var sum []byte
			switch tc.alg {
			case "RS256", "ES256":
				h := sha256.Sum256([]byte(accessToken))
				sum = h[:]
			case "ES384":
				// SHA-384 via crypto/sha512 (sha512.Sum384 returns [48]byte).
				// Avoid importing sha512 here; use the prod helper indirectly.
				ok := atHashMatches(makeJWTHeader(tc.alg), accessToken, computeATHashViaProd(t, tc.alg, accessToken))
				if !ok {
					t.Errorf("alg=%q: atHashMatches returned false on round-trip", tc.alg)
				}
				return
			case "RS512", "EdDSA":
				ok := atHashMatches(makeJWTHeader(tc.alg), accessToken, computeATHashViaProd(t, tc.alg, accessToken))
				if !ok {
					t.Errorf("alg=%q: atHashMatches returned false on round-trip", tc.alg)
				}
				return
			}
			half := sum[:len(sum)/2]
			expected := base64.RawURLEncoding.EncodeToString(half)
			if !atHashMatches(makeJWTHeader(tc.alg), accessToken, expected) {
				t.Errorf("alg=%q: at_hash mismatch", tc.alg)
			}
		})
	}
}

// computeATHashViaProd shims around atHashMatches by binary-searching
// for the at_hash value: we just call the production helper with each
// alg, and the test passes if the same value reproduces. Avoids
// duplicating the alg → hash dispatch in test code.
func computeATHashViaProd(_ *testing.T, alg, accessToken string) string {
	// Build a JWT with that alg, then use atHashMatches twice with
	// different claim values to find the matching one. Since we
	// can't easily do that without infinite test loops, the easier
	// path is to call the production code at the at_hash reflect
	// surface. But our service has no public at_hash compute helper —
	// only matches helper. So: use a trial-and-error with the empty
	// hash and check against the real recomputed hash via a helper
	// that doesn't exist. Instead, this function reaches into the
	// implementation by replicating it minimally.
	h := newHasherForAlg(alg)
	if h == nil {
		return ""
	}
	h.Write([]byte(accessToken))
	sum := h.Sum(nil)
	half := sum[:len(sum)/2]
	return base64.RawURLEncoding.EncodeToString(half)
}

// newHasherForAlg duplicates the dispatch in atHashMatches for the
// test helper. Kept in test code so the production path stays
// dependency-light.
func newHasherForAlg(alg string) interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
} {
	switch alg {
	case "RS256", "ES256":
		return sha256.New()
	case "ES384":
		return sha384New()
	case "RS512", "EdDSA":
		return sha512New()
	default:
		return nil
	}
}

// makeJWTHeader returns a minimal JWT-shape string with the given alg
// in the header. body + sig are dummy.
func makeJWTHeader(alg string) string {
	header := fmt.Sprintf(`{"alg":%q,"typ":"JWT"}`, alg)
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + ".body.sig"
}

// TestService_AlgPinning_HandlesWhitespaceInHeader pins the parser
// against headers with whitespace around the alg value (some libraries
// emit " :" instead of ":").
func TestService_AlgPinning_HandlesWhitespaceInHeader(t *testing.T) {
	header := `{"alg" :  "RS256" ,"typ":"JWT"}`
	token := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".body.sig"
	rejected, alg := isDisallowedAlg(token)
	if rejected {
		t.Errorf("RS256 with whitespace: rejected = true; want allowed")
	}
	if alg != "RS256" {
		t.Errorf("alg extraction failed: got %q", alg)
	}
}

// TestService_AlgPinning_HeaderWithBadBase64 returns rejected=true
// when the header isn't decodable.
func TestService_AlgPinning_HeaderWithBadBase64(t *testing.T) {
	rejected, _ := isDisallowedAlg("!!!not-base64.body.sig")
	if !rejected {
		t.Errorf("bad base64 header: rejected = false; want true")
	}
}

// TestService_AlgPinning_HeaderMissingAlgField returns rejected=true.
func TestService_AlgPinning_HeaderMissingAlgField(t *testing.T) {
	header := `{"typ":"JWT"}`
	token := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".body.sig"
	rejected, _ := isDisallowedAlg(token)
	if !rejected {
		t.Errorf("header missing alg: rejected = false; want true")
	}
}

// TestService_IsJWKSFetchError pins the error-string heuristic.
func TestService_IsJWKSFetchError(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"oidc: fetching keys oidc: get keys failed: timeout", true},
		{"failed to fetch jwks_uri", true},
		{"unable to load key set", true},
		{"some other unrelated error", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isJWKSFetchError(errors.New(tc.msg))
		if got != tc.want {
			t.Errorf("isJWKSFetchError(%q) = %v; want %v", tc.msg, got, tc.want)
		}
	}
	if isJWKSFetchError(nil) {
		t.Errorf("isJWKSFetchError(nil) = true; want false")
	}
}

// TestService_DecryptClientSecret_NoKeyReturnsBytesAsIs covers the
// empty-key short-circuit (used by tests with plaintext blobs).
func TestService_DecryptClientSecret_NoKeyReturnsBytesAsIs(t *testing.T) {
	plain := []byte("test-plaintext-secret")
	got, err := decryptClientSecret(plain, "")
	if err != nil {
		t.Fatalf("decryptClientSecret(no key): %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("decryptClientSecret returned %q; want %q", string(got), string(plain))
	}
}

// TestService_RandomB64URL_ProducesNonEmptyAndUnique pins the random
// generator's contract.
func TestService_RandomB64URL_ProducesNonEmptyAndUnique(t *testing.T) {
	a, err := randomB64URL(32)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := randomB64URL(32)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a == "" || b == "" {
		t.Errorf("got empty random value")
	}
	if a == b {
		t.Errorf("two random values were equal (RNG broken)")
	}
}

// =============================================================================
// Phase 7 — OIDC first-admin bootstrap hook tests.
// =============================================================================

// Phase 7 spec test #1: fresh DB + OIDC login matching bootstrap groups
// → user becomes admin. Pin: when the hook returns grantAdmin=true, the
// resolved roleIDs include r-admin even if mappings.Map returned empty.
func TestService_BootstrapHook_GrantsAdminOnMatch(t *testing.T) {
	idp := newMockIdP(t)
	prov := makeProvider(idp.URL(), "op-bootstrap")
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: nil} // intentionally empty — fresh deploy
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	hookCalled := false
	svc.SetAdminBootstrapHook(func(_ context.Context, providerID string, groups []string, userID string) (bool, error) {
		hookCalled = true
		// Verify the hook receives the right inputs.
		if providerID != "op-bootstrap" {
			t.Errorf("hook providerID = %q; want op-bootstrap", providerID)
		}
		if len(groups) == 0 {
			t.Errorf("hook groups empty; expected at least one")
		}
		if userID == "" {
			t.Errorf("hook userID empty; expected upserted user id")
		}
		return true, nil // grant admin
	})

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-bootstrap", "s", "test-nonce-fixed", "v-bootstrapxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	res, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "10.0.0.1", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if !hookCalled {
		t.Errorf("bootstrap hook never invoked")
	}
	if !sliceContains(res.RoleIDs, "r-admin") {
		t.Errorf("expected r-admin in RoleIDs after bootstrap; got %v", res.RoleIDs)
	}
}

// Phase 7 spec test #2: fresh DB + OIDC login NOT matching bootstrap
// groups → user upserted but mapping fails closed (no admin grant).
// The hook returns grantAdmin=false; mappings.Map empty → ErrGroupsUnmapped.
func TestService_BootstrapHook_NoMatchPreservesEmptyMappingFailClosed(t *testing.T) {
	idp := newMockIdP(t)
	svc, pl := newServiceWithProviderAndPLNoMappings(t, idp.URL(), "op-no-match")
	svc.SetAdminBootstrapHook(func(_ context.Context, _ string, _ []string, _ string) (bool, error) {
		return false, nil // not a bootstrap match
	})

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-no-match", "s", "test-nonce-fixed", "v-nomatchxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrGroupsUnmapped) {
		t.Errorf("err = %v; want ErrGroupsUnmapped (no bootstrap match + empty mappings)", err)
	}
}

// Phase 7 spec test #3: existing admin + OIDC login matching bootstrap
// groups → bootstrap mode disabled (hook returns grantAdmin=false), normal
// group-role mapping wins. Pin: the hook is ALWAYS called but its
// grantAdmin=false response means the user gets the ordinary mapped
// role set, not r-admin.
func TestService_BootstrapHook_AdminAlreadyExistsFallsThroughToNormalMapping(t *testing.T) {
	idp := newMockIdP(t)
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-existing-admin")
	// Hook says grantAdmin=false because (in production) an admin already
	// exists; the closure does the AdminExists probe.
	svc.SetAdminBootstrapHook(func(_ context.Context, _ string, _ []string, _ string) (bool, error) {
		return false, nil
	})

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-existing-admin", "s", "test-nonce-fixed", "v-existingxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	res, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	// stubMappings returns r-operator; the hook returned false; r-admin
	// MUST NOT appear in the role set.
	if sliceContains(res.RoleIDs, "r-admin") {
		t.Errorf("admin-already-exists path should not grant r-admin; got %v", res.RoleIDs)
	}
	if !sliceContains(res.RoleIDs, "r-operator") {
		t.Errorf("expected normal mapping (r-operator) to win; got %v", res.RoleIDs)
	}
}

// Phase 7 hook-error path: hook returns an error → HandleCallback wraps it.
func TestService_BootstrapHook_ErrorWraps(t *testing.T) {
	idp := newMockIdP(t)
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-hook-err")
	svc.SetAdminBootstrapHook(func(_ context.Context, _ string, _ []string, _ string) (bool, error) {
		return false, fmt.Errorf("simulated AdminExists probe failure")
	})
	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-hook-err", "s", "test-nonce-fixed", "v-errxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if err == nil || !strings.Contains(err.Error(), "admin bootstrap") {
		t.Errorf("err = %v; want admin bootstrap wrap", err)
	}
}

// Phase 7 idempotence: hook returns grantAdmin=true AND mappings.Map
// already includes r-admin → roleIDs has r-admin exactly once.
func TestService_BootstrapHook_IdempotentWhenAdminAlreadyMapped(t *testing.T) {
	idp := newMockIdP(t)
	prov := makeProvider(idp.URL(), "op-idem")
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-admin"}} // already mapped
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")
	svc.SetAdminBootstrapHook(func(_ context.Context, _ string, _ []string, _ string) (bool, error) {
		return true, nil
	})

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-idem", "s", "test-nonce-fixed", "v-idempxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	res, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	count := 0
	for _, rid := range res.RoleIDs {
		if rid == "r-admin" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected r-admin to appear exactly once; got %d (RoleIDs=%v)", count, res.RoleIDs)
	}
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestService_SetClockForTest_OverridesNow pins the test seam works.
func TestService_SetClockForTest_OverridesNow(t *testing.T) {
	svc := newServiceForUnitTest(t)
	frozen := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	svc.SetClockForTest(func() time.Time { return frozen })
	if got := svc.clockNow(); !got.Equal(frozen) {
		t.Errorf("clock = %v; want %v", got, frozen)
	}
}

// =============================================================================
// Coverage-lift batch: HandleCallback branch tests + fetchUserinfoGroups +
// upsertUser fallback chain + decryptClientSecret real-encrypt round trip +
// randomB64URL error path + HandleAuthRequest preLogin failure.
//
// These tests exist to lift the package above the 90% per-statement floor
// pinned by Phase 13 of the bundle prompt. Each one targets a specific
// uncovered branch in service.go; the test name announces which.
// =============================================================================

// TestService_HandleCallback_AZPRequired_OnMultiAud pins the OIDC core
// §3.1.3.7 step 5 enforcement: a multi-audience ID token MUST carry an
// `azp` claim equal to the relying-party client_id, otherwise the token
// is rejected.
func TestService_HandleCallback_AZPRequired_OnMultiAud(t *testing.T) {
	idp := newMockIdP(t)
	// Multi-aud, NO azp — Phase 3 requires azp in this case.
	idp.overrideAudience = []string{"certctl", "another-relying-party"}
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-azp-req")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-azp-req", "s", "test-nonce-fixed", "v-azpreqxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrAZPRequired) {
		t.Errorf("err = %v; want ErrAZPRequired", err)
	}
}

// TestService_HandleCallback_AZPMismatch pins the equal-to-client_id
// requirement when azp is present.
func TestService_HandleCallback_AZPMismatch(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideAZP = "some-other-client" // != "certctl"
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-azp-mis")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-azp-mis", "s", "test-nonce-fixed", "v-azpmisxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrAZPMismatch) {
		t.Errorf("err = %v; want ErrAZPMismatch", err)
	}
}

// TestService_HandleCallback_ATHashMismatch pins the at_hash recompute
// check: if the IdP returns at_hash that doesn't match SHA-256 of the
// access token's first half, reject.
func TestService_HandleCallback_ATHashMismatch(t *testing.T) {
	idp := newMockIdP(t)
	// Inject a wrong at_hash. The mockIdP returns access_token =
	// "test-access-token"; the real at_hash for that token under RS256
	// is sha256[:16] base64url. We overshoot with a known-wrong value.
	idp.overrideATHash = "not-the-real-at-hash"
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-ath-mis")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-ath-mis", "s", "test-nonce-fixed", "v-athmisxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrATHashMismatch) {
		t.Errorf("err = %v; want ErrATHashMismatch", err)
	}
}

// TestService_HandleCallback_ATHashRequired_WhenAccessTokenPresent pins
// the Phase 3 tightening of the OIDC core "MAY" to a service-level
// "MUST": when an access token is returned, the ID token MUST carry an
// at_hash claim. A substituted access token would otherwise ride a
// clean ID token through the verifier — fail closed at the service.
func TestService_HandleCallback_ATHashRequired_WhenAccessTokenPresent(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideATHash = "<empty>" // suppress at_hash even though access_token is returned
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-ath-req")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-ath-req", "s", "test-nonce-fixed", "v-athreqxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrATHashRequired) {
		t.Errorf("err = %v; want ErrATHashRequired", err)
	}
}

// TestService_HandleCallback_IATInFuture pins the iat-in-future rejection
// (60s clock-skew tolerance is the only allowance).
func TestService_HandleCallback_IATInFuture(t *testing.T) {
	idp := newMockIdP(t)
	// iat is 10 minutes in the future, well beyond 60s skew.
	idp.overrideIAT = time.Now().Add(10 * time.Minute)
	idp.overrideExp = time.Now().Add(2 * time.Hour)
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-iat-fut")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-iat-fut", "s", "test-nonce-fixed", "v-iatfutxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrIATInFuture) {
		t.Errorf("err = %v; want ErrIATInFuture", err)
	}
}

// TestService_HandleCallback_MappingsMapError pins the wrap on the
// mappings.Map repo-layer error.
func TestService_HandleCallback_MappingsMapError(t *testing.T) {
	idp := newMockIdP(t)
	prov := makeProvider(idp.URL(), "op-map-err")
	pl := newStubPreLogin()
	mappings := &stubMappings{mapErr: fmt.Errorf("simulated repo failure")}
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-map-err", "s", "test-nonce-fixed", "v-mapxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if err == nil || !strings.Contains(err.Error(), "group-role mapping") {
		t.Errorf("err = %v; want group-role mapping wrap", err)
	}
}

// TestService_HandleCallback_SessionMintError pins the wrap on the
// SessionService.MintForUser error.
func TestService_HandleCallback_SessionMintError(t *testing.T) {
	idp := newMockIdP(t)
	prov := makeProvider(idp.URL(), "op-mint-err")
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	users := newStubUsers()
	sessions := &stubSessions{mintErr: fmt.Errorf("simulated session minter failure")}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-mint-err", "s", "test-nonce-fixed", "v-mintxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if err == nil || !strings.Contains(err.Error(), "session mint") {
		t.Errorf("err = %v; want session mint wrap", err)
	}
}

// TestService_HandleCallback_UserCreateError pins the wrap on the
// users.Create repo-layer error.
func TestService_HandleCallback_UserCreateError(t *testing.T) {
	idp := newMockIdP(t)
	prov := makeProvider(idp.URL(), "op-uc-err")
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	users := newStubUsers()
	users.createErr = fmt.Errorf("simulated insert failure")
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-uc-err", "s", "test-nonce-fixed", "v-ucxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if err == nil || !strings.Contains(err.Error(), "upsert user") {
		t.Errorf("err = %v; want upsert user wrap", err)
	}
}

// TestService_HandleCallback_GetByOIDCSubjectNonNotFoundError pins the
// upsertUser early-return when the GetByOIDCSubject repo call fails for
// a reason OTHER than not-found (DB connection drop, query error, etc.).
func TestService_HandleCallback_GetByOIDCSubjectNonNotFoundError(t *testing.T) {
	idp := newMockIdP(t)
	prov := makeProvider(idp.URL(), "op-get-err")
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	users := newStubUsers()
	users.getErr = fmt.Errorf("simulated query failure")
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-get-err", "s", "test-nonce-fixed", "v-getxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if err == nil || !strings.Contains(err.Error(), "simulated query failure") {
		t.Errorf("err = %v; want simulated query failure unwrap", err)
	}
}

// TestService_UpsertUser_DisplayNameFallsBackToEmail covers the
// last-resort fallback: when both name and preferred_username are empty,
// the user record's display_name is set to the email.
func TestService_UpsertUser_DisplayNameFallsBackToEmail(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideName = "<empty>" // suppress name claim entirely
	// preferred_username isn't emitted by the mockIdP at all, so it's "".
	prov := makeProvider(idp.URL(), "op-name-fb")
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-name-fb", "s", "test-nonce-fixed", "v-namxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	res, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if res.User.DisplayName != "user@example.com" {
		t.Errorf("DisplayName = %q; want fallback to email %q", res.User.DisplayName, "user@example.com")
	}
}

// TestService_FetchUserinfoGroups_HappyPath_OnEmptyIDTokenGroups pins
// the userinfo fallback: if the ID token's groups claim is empty AND
// the operator opted in via FetchUserinfo, the userinfo endpoint is
// consulted and its groups feed the role-mapping step.
func TestService_FetchUserinfoGroups_HappyPath_OnEmptyIDTokenGroups(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideGroups = []string{}                        // ID token returns no groups
	idp.userinfoGroups = []string{"engineers", "platform"} // userinfo returns groups
	prov := makeProvider(idp.URL(), "op-ui-ok")
	prov.FetchUserinfo = true
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-ui-ok", "s", "test-nonce-fixed", "v-uioxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	res, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if len(res.RoleIDs) == 0 {
		t.Errorf("expected RoleIDs from userinfo-fallback path; got empty")
	}
}

// TestService_FetchUserinfoGroups_ReturnsErrGroupsMissing_WhenUserinfoAlsoEmpty
// pins the fail-closed semantics: even with FetchUserinfo=true, if the
// userinfo response also has no groups, the login fails closed.
func TestService_FetchUserinfoGroups_ReturnsErrGroupsMissing_WhenUserinfoAlsoEmpty(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideGroups = []string{} // ID token returns no groups
	idp.userinfoGroups = nil        // userinfo also returns no groups
	prov := makeProvider(idp.URL(), "op-ui-empty")
	prov.FetchUserinfo = true
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-ui-empty", "s", "test-nonce-fixed", "v-uixxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrGroupsMissing) {
		t.Errorf("err = %v; want ErrGroupsMissing", err)
	}
}

// TestService_FetchUserinfoGroups_ReturnsErrGroupsMissing_WhenEndpointMissing
// pins the "operator opted in but provider doesn't list a userinfo
// endpoint" branch in fetchUserinfoGroups.
func TestService_FetchUserinfoGroups_ReturnsErrGroupsMissing_WhenEndpointMissing(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideGroups = []string{}
	idp.omitUserinfoEndpoint = true // discovery doc lacks userinfo_endpoint
	prov := makeProvider(idp.URL(), "op-ui-noendpoint")
	prov.FetchUserinfo = true
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-ui-noendpoint", "s", "test-nonce-fixed", "v-uixxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrGroupsMissing) {
		t.Errorf("err = %v; want ErrGroupsMissing", err)
	}
}

// TestService_HandleAuthRequest_PreLoginStoreError pins the wrap on a
// PreLoginStore.CreatePreLogin failure (e.g. database unavailable
// during the GET /auth/oidc/start handler).
func TestService_HandleAuthRequest_PreLoginStoreError(t *testing.T) {
	idp := newMockIdP(t)
	prov := makeProvider(idp.URL(), "op-pl-err")
	pl := newStubPreLogin()
	pl.createErr = fmt.Errorf("simulated pre-login insert failure")
	svc := NewService(
		&stubProviderLookup{provider: prov},
		&stubMappings{roleIDs: []string{"r-operator"}},
		newStubUsers(),
		&stubSessions{},
		pl,
		"",
	)

	_, _, _, err := svc.HandleAuthRequest(context.Background(), "op-pl-err")
	if err == nil || !strings.Contains(err.Error(), "pre-login store") {
		t.Errorf("err = %v; want pre-login store wrap", err)
	}
}

// TestService_DecryptClientSecret_RealEncryptedRoundTrip pins that the
// production decrypt path works against a real
// internal/crypto.EncryptIfKeySet output. Catches future regressions
// where the v3 blob format changes without updating this consumer.
func TestService_DecryptClientSecret_RealEncryptedRoundTrip(t *testing.T) {
	plaintext := []byte("super-secret-client-secret-do-not-leak")
	passphrase := "test-passphrase-please-keep-secret"

	blob, _, err := cryptopkg.EncryptIfKeySet(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptIfKeySet: %v", err)
	}
	if len(blob) == 0 {
		t.Fatalf("EncryptIfKeySet returned empty blob")
	}

	got, err := decryptClientSecret(blob, passphrase)
	if err != nil {
		t.Fatalf("decryptClientSecret: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("decrypt round-trip: got %q; want %q", string(got), string(plaintext))
	}
}

// TestService_DecryptClientSecret_BadPassphraseFails pins that a wrong
// passphrase against a real encrypted blob returns an error (NOT the
// plaintext, NOT a panic).
func TestService_DecryptClientSecret_BadPassphraseFails(t *testing.T) {
	plaintext := []byte("super-secret-client-secret-do-not-leak")
	passphrase := "test-passphrase-correct"

	blob, _, err := cryptopkg.EncryptIfKeySet(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptIfKeySet: %v", err)
	}

	got, err := decryptClientSecret(blob, "wrong-passphrase-different")
	if err == nil {
		t.Errorf("decryptClientSecret with wrong passphrase: err = nil, got = %q; want non-nil err", string(got))
	}
}

// TestService_RandomB64URL_PropagatesReadError exercises the readRand
// seam by overriding it to return an error. Asserts the production code
// surfaces the error rather than silently returning an empty string.
func TestService_RandomB64URL_PropagatesReadError(t *testing.T) {
	original := readRand
	readRand = func(_ []byte) (int, error) {
		return 0, fmt.Errorf("simulated entropy starvation")
	}
	defer func() { readRand = original }()

	got, err := randomB64URL(32)
	if err == nil {
		t.Errorf("randomB64URL: err = nil; want non-nil")
	}
	if got != "" {
		t.Errorf("randomB64URL: returned %q on error path; want empty string", got)
	}
}

// TestService_HandleAuthRequest_RandomFailureSurfaces pins that a
// state-generation failure from the readRand seam surfaces through the
// HandleAuthRequest path as a wrapped "state generate" error.
func TestService_HandleAuthRequest_RandomFailureSurfaces(t *testing.T) {
	idp := newMockIdP(t)
	svc, _ := newServiceWithProviderAndPL(t, idp.URL(), "op-rand-fail")

	original := readRand
	readRand = func(_ []byte) (int, error) {
		return 0, fmt.Errorf("simulated rng exhaustion")
	}
	defer func() { readRand = original }()

	_, _, _, err := svc.HandleAuthRequest(context.Background(), "op-rand-fail")
	if err == nil || !strings.Contains(err.Error(), "state generate") {
		t.Errorf("err = %v; want state generate wrap", err)
	}
}

// TestService_HandleAuthRequest_NonceRandomFailureSurfaces lets the
// state-generation succeed on call 1 and fails the nonce-generation on
// call 2. Pins the second readRand call's error wrap.
func TestService_HandleAuthRequest_NonceRandomFailureSurfaces(t *testing.T) {
	idp := newMockIdP(t)
	svc, _ := newServiceWithProviderAndPL(t, idp.URL(), "op-nonce-rand-fail")

	original := readRand
	calls := 0
	readRand = func(b []byte) (int, error) {
		calls++
		if calls == 1 {
			return original(b) // state succeeds
		}
		return 0, fmt.Errorf("simulated rng exhaustion on nonce") // nonce fails
	}
	defer func() { readRand = original }()

	_, _, _, err := svc.HandleAuthRequest(context.Background(), "op-nonce-rand-fail")
	if err == nil || !strings.Contains(err.Error(), "nonce generate") {
		t.Errorf("err = %v; want nonce generate wrap", err)
	}
}

// TestService_HandleCallback_RejectsTokenResponseMissingIDToken pins
// the "token response missing id_token" branch — the IdP returned a
// 200 from /token but the response payload lacked the id_token field
// (a misconfigured IdP, or a OAuth2-only flow we shouldn't be hitting).
func TestService_HandleCallback_RejectsTokenResponseMissingIDToken(t *testing.T) {
	idp := newMockIdP(t)
	idp.suppressIDToken = true
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-no-idtok")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-no-idtok", "s", "test-nonce-fixed", "v-noidxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if err == nil || !strings.Contains(err.Error(), "missing id_token") {
		t.Errorf("err = %v; want missing id_token error", err)
	}
}

// TestService_FetchUserinfoGroups_ReturnsErrGroupsMissing_WhenUserinfoFails
// pins the UserInfo-fetch HTTP error wrap. With FetchUserinfo=true and
// /userinfo returning HTTP 500, the service surfaces ErrGroupsMissing
// to the caller (the inner error stays in the audit row, not the wire).
func TestService_FetchUserinfoGroups_ReturnsErrGroupsMissing_WhenUserinfoFails(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideGroups = []string{}
	idp.userinfoFails = true
	prov := makeProvider(idp.URL(), "op-ui-500")
	prov.FetchUserinfo = true
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-ui-500", "s", "test-nonce-fixed", "v-uifxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if !errors.Is(err, ErrGroupsMissing) {
		t.Errorf("err = %v; want ErrGroupsMissing", err)
	}
}

// TestService_AlgPinning_HeaderMissingColonAfterAlg covers the parser
// branch where the alg key appears but isn't followed by a colon (a
// malformed header that's still valid base64 + valid JSON outer shape).
func TestService_AlgPinning_HeaderMissingColonAfterAlg(t *testing.T) {
	// `"alg" "RS256"` — alg key but no colon between key and value.
	// Note: this is intentionally not valid JSON; the minimal parser
	// only checks for the colon and rejects this shape conservatively.
	header := `{"alg" "RS256"}`
	token := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".body.sig"
	rejected, _ := isDisallowedAlg(token)
	if !rejected {
		t.Errorf("header missing colon after alg: rejected = false; want true")
	}
}

// TestService_AlgPinning_HeaderAlgValueNotQuoted covers the parser
// branch where the value after the colon isn't a JSON string literal
// (e.g., a number or unquoted token).
func TestService_AlgPinning_HeaderAlgValueNotQuoted(t *testing.T) {
	header := `{"alg":42}`
	token := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".body.sig"
	rejected, _ := isDisallowedAlg(token)
	if !rejected {
		t.Errorf("header with non-string alg: rejected = false; want true")
	}
}

// TestService_AlgPinning_HeaderAlgValueUnterminatedString covers the
// parser branch where the value starts a JSON string but never closes
// it (truncated header).
func TestService_AlgPinning_HeaderAlgValueUnterminatedString(t *testing.T) {
	// Valid base64 of `{"alg":"RS256` (missing closing quote + brace).
	header := `{"alg":"RS256`
	token := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".body.sig"
	rejected, _ := isDisallowedAlg(token)
	if !rejected {
		t.Errorf("header with unterminated alg string: rejected = false; want true")
	}
}

// TestService_UpsertUser_ValidateErrorOnEmptyEmail pins the
// User.Validate failure path. The IdP returns an empty email (missing
// claim); the upsertUser display-name fallback resolves to "" too;
// User.Validate then trips ErrUserEmptyEmail.
func TestService_UpsertUser_ValidateErrorOnEmptyEmail(t *testing.T) {
	idp := newMockIdP(t)
	idp.overrideEmail = "<empty>" // sentinel — see /token handler patch below
	idp.overrideName = "<empty>"  // suppress name to force email fallback
	prov := makeProvider(idp.URL(), "op-validate-err")
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(&stubProviderLookup{provider: prov}, mappings, users, sessions, pl, "")

	cookie, _, _ := pl.CreatePreLogin(context.Background(), "op-validate-err", "s", "test-nonce-fixed", "v-valxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	_, err := svc.HandleCallback(context.Background(), cookie, "code", "s", "ip", "ua")
	if err == nil || !strings.Contains(err.Error(), "validate") {
		t.Errorf("err = %v; want validate wrap", err)
	}
}
