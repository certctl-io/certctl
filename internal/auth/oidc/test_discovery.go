package oidc

// Audit 2026-05-10 MED-5 closure — dry-run validator for OIDC provider
// configuration. Lets operators verify discovery + JWKS reachability +
// alg-downgrade defense BEFORE persisting a provider row. Mirrors the
// non-persistence-touching subset of getOrLoad.

import (
	"context"
	"fmt"
	"net/http"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

// TestDiscoveryResult is the report TestDiscovery returns. The HTTP
// layer marshals this verbatim. Each field is independently observable
// so the GUI can render a per-check status row.
//
// `Errors` collects every leg that failed; a partial-success case
// (e.g. discovery OK but alg-downgrade tripped) returns
// DiscoverySucceeded=true + a non-empty Errors slice.
type TestDiscoveryResult struct {
	DiscoverySucceeded  bool     `json:"discovery_succeeded"`
	JWKSReachable       bool     `json:"jwks_reachable"`
	SupportedAlgValues  []string `json:"supported_alg_values"`
	IssParamSupported   bool     `json:"iss_param_supported"`
	IssuerEcho          string   `json:"issuer_echo,omitempty"` // the iss value the IdP advertised
	AuthorizationURL    string   `json:"authorization_url,omitempty"`
	TokenURL            string   `json:"token_url,omitempty"`
	JWKSURI             string   `json:"jwks_uri,omitempty"`
	UserInfoEndpoint    string   `json:"userinfo_endpoint,omitempty"`
	Errors              []string `json:"errors,omitempty"`
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

	// Step 3 — alg-downgrade defense. The IdP MUST NOT advertise HS*
	// or none in the signing-alg list (operators that bind certctl to
	// an IdP advertising these are at risk of a forged-token attack).
	// Same check applied in getOrLoad's production path.
	for _, a := range advertised.IDTokenSigningAlgValuesSupported {
		if _, deny := disallowedAlgs[a]; deny {
			res.Errors = append(res.Errors, fmt.Sprintf("alg-downgrade defense tripped: IdP advertises %s in id_token_signing_alg_values_supported", a))
		}
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
var jwksReachable = func(ctx context.Context, jwksURI string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return false, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}
