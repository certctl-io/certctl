package oidc

// Audit 2026-05-10 MED-5 closure — dry-run validator for OIDC provider
// configuration. Lets operators verify discovery + JWKS reachability +
// alg-downgrade defense BEFORE persisting a provider row. Mirrors the
// non-persistence-touching subset of getOrLoad.

import (
	"context"
	"fmt"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/certctl-io/certctl/internal/validation"
)

// oidcOutboundTimeout bounds every test-discovery HTTP call (discovery
// document fetch + JWKS reachability probe + userinfo if configured).
// Shared by the SSRF-safe transport dialer (Bundle 5 R6 closure) and
// the http.Client so the dial budget and the read/write budget land
// on the same wall-clock horizon.
const oidcOutboundTimeout = 10 * time.Second

// TestDiscoveryResult is the report TestDiscovery returns. The HTTP
// layer marshals this verbatim. Each field is independently observable
// so the GUI can render a per-check status row.
//
// `Errors` collects every leg that failed; a partial-success case
// (e.g. discovery OK but alg-downgrade tripped) returns
// DiscoverySucceeded=true + a non-empty Errors slice.
type TestDiscoveryResult struct {
	DiscoverySucceeded bool     `json:"discovery_succeeded"`
	JWKSReachable      bool     `json:"jwks_reachable"`
	SupportedAlgValues []string `json:"supported_alg_values"`
	IssParamSupported  bool     `json:"iss_param_supported"`
	IssuerEcho         string   `json:"issuer_echo,omitempty"` // the iss value the IdP advertised
	AuthorizationURL   string   `json:"authorization_url,omitempty"`
	TokenURL           string   `json:"token_url,omitempty"`
	JWKSURI            string   `json:"jwks_uri,omitempty"`
	UserInfoEndpoint   string   `json:"userinfo_endpoint,omitempty"`
	Errors             []string `json:"errors,omitempty"`
}

// TestDiscovery runs the read-only subset of getOrLoad against a
// candidate issuer URL: fetches the discovery doc, runs the
// alg-downgrade defense, parses the RFC 9207 iss-parameter advert,
// then fetches the JWKS once to confirm reachability.
//
// The function NEVER persists anything; the caller is the
// /api/v1/auth/oidc/test endpoint that the GUI uses for dry-runs.
//
// Service-layer entry point so the handler stays HTTP-shaped only.
func (s *Service) TestDiscovery(ctx context.Context, issuerURL string) (*TestDiscoveryResult, error) {
	res := &TestDiscoveryResult{}

	// Step 1 — discovery. gooidc.NewProvider fetches
	// `<issuer>/.well-known/openid-configuration` and runs the iss
	// match check internally; on failure it returns a fmt-style
	// wrapped error.
	provider, err := gooidc.NewProvider(ctx, issuerURL)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("discovery fetch failed: %v", err))
		return res, nil // Non-fatal at this layer; the response carries the per-leg failure.
	}
	res.DiscoverySucceeded = true
	res.IssuerEcho = issuerURL
	endpoint := provider.Endpoint()
	res.AuthorizationURL = endpoint.AuthURL
	res.TokenURL = endpoint.TokenURL

	// Step 2 — parse the claims we care about from the discovery doc.
	var advertised struct {
		IDTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported"`
		AuthorizationResponseIssParamSupported bool     `json:"authorization_response_iss_parameter_supported"`
		JWKSURI                                string   `json:"jwks_uri"`
		UserInfoEndpoint                       string   `json:"userinfo_endpoint"`
	}
	if cerr := provider.Claims(&advertised); cerr != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("discovery claims: %v", cerr))
		return res, nil
	}
	res.SupportedAlgValues = advertised.IDTokenSigningAlgValuesSupported
	res.IssParamSupported = advertised.AuthorizationResponseIssParamSupported
	res.JWKSURI = advertised.JWKSURI
	res.UserInfoEndpoint = advertised.UserInfoEndpoint

	// Step 3 — alg-downgrade defense (v2.1.0-relaxed semantics).
	// Pre-v2.1.0 this loop appended an error for ANY HS*/none in the
	// IdP's advertised list. That was strict-deny but incompatible with
	// real IdPs like Keycloak 26.x which list every alg they're capable
	// of, even though the realm only signs with RS256.
	// New semantics: only flag the IdP if the intersection of advertised
	// vs DefaultAllowedAlgs is empty (a pathological all-weak IdP). Each
	// HS*/none advertisement is still surfaced as an informational note
	// so operators can ask their IdP team to tighten the list, but it's
	// no longer a hard fail. The per-token alg check at sig-verify time
	// (isDisallowedAlg in service.go ~L1177) is the load-bearing defense.
	allowedSet := make(map[string]struct{}, len(DefaultAllowedAlgs))
	for _, a := range DefaultAllowedAlgs {
		allowedSet[a] = struct{}{}
	}
	hasAcceptable := false
	weak := []string{}
	for _, a := range advertised.IDTokenSigningAlgValuesSupported {
		if _, ok := allowedSet[a]; ok {
			hasAcceptable = true
		}
		if _, deny := disallowedAlgs[a]; deny {
			weak = append(weak, a)
		}
	}
	if len(advertised.IDTokenSigningAlgValuesSupported) > 0 && !hasAcceptable {
		res.Errors = append(res.Errors, fmt.Sprintf("alg-downgrade defense tripped: IdP advertises only weak algorithms (%v) — no acceptable alg from %v present", advertised.IDTokenSigningAlgValuesSupported, DefaultAllowedAlgs))
	} else if len(weak) > 0 {
		// Informational only — RS/ES present alongside HS, so the
		// IdP binds successfully but the operator should know.
		res.Errors = append(res.Errors, fmt.Sprintf("note: IdP advertises weak algorithms %v alongside acceptable ones — verifier-side alg pin prevents downgrade, but tightening the IdP's advertised list is recommended", weak))
	}

	// Step 4 — JWKS reachability. The go-oidc Verifier defers JWKS
	// fetch until first token-verify; for the dry-run we explicitly
	// HEAD/GET the JWKS endpoint to confirm network reachability.
	if advertised.JWKSURI == "" {
		res.Errors = append(res.Errors, "discovery doc omits jwks_uri")
	} else if ok, herr := jwksReachable(ctx, advertised.JWKSURI); !ok {
		if herr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("JWKS fetch failed: %v", herr))
		} else {
			res.Errors = append(res.Errors, "JWKS endpoint returned non-200")
		}
	} else {
		res.JWKSReachable = true
	}

	return res, nil
}

// jwksReachable issues a GET against the JWKS URI and returns ok=true
// when the response status is 2xx. Used by TestDiscovery for the
// reachability leg of the dry-run.
//
// Kept distinct from go-oidc's internal JWKS fetcher because we want
// to surface the HTTP status to the operator without requiring a
// token-verify round-trip.
//
// Bundle 5 closure (audit R6): the GET runs through an SSRF-safe
// http.Client whose transport's DialContext is wrapped in
// validation.SafeHTTPDialContext. Pre-Bundle-5 the discovery probe
// used http.DefaultClient and could be pointed at reserved-address
// ranges via DNS rebinding (operator pastes a JWKS URI from the
// dynamic-config GUI; admin RBAC for OIDC providers is sensitive but
// not a system-wide super-admin gate). Now the dial-time guard re-
// resolves the target host and rejects loopback / link-local /
// private + cloud-metadata before any HTTP byte goes out. The
// 10-second timeout matches the package-wide oidcOutboundTimeout
// budget so token endpoint + JWKS + userinfo probes share the same
// wall-clock horizon.
// jwksProbeClient is the *http.Client used by jwksReachable. Package-
// level var so the test suite can swap it for an SSRF-guard-bypassed
// client when exercising jwksReachable against httptest.NewServer
// (which binds to 127.0.0.1 and would otherwise be refused by
// validation.SafeHTTPDialContext). Mirrors the
// internal/connector/notifier/webhook + slack + teams test-seam
// pattern. Production code never reassigns this var.
var jwksProbeClient = &http.Client{
	Timeout: oidcOutboundTimeout,
	Transport: &http.Transport{
		DialContext:           validation.SafeHTTPDialContext(oidcOutboundTimeout),
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

var jwksReachable = func(ctx context.Context, jwksURI string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return false, err
	}
	resp, err := jwksProbeClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}
