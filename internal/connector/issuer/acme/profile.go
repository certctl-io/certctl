package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	goacme "golang.org/x/crypto/acme"
)

// profileOrderRequest is the JSON body for a newOrder request with optional profile field.
// The profile field is an ACME extension for certificate profile selection
// (e.g., Let's Encrypt "shortlived" for 6-day certs, "tlsserver" for standard TLS).
type profileOrderRequest struct {
	Identifiers []wireAuthzID `json:"identifiers"`
	NotBefore   string        `json:"notBefore,omitempty"`
	NotAfter    string        `json:"notAfter,omitempty"`
	Profile     string        `json:"profile,omitempty"`
}

// wireAuthzID matches the ACME wire format for authorization identifiers.
type wireAuthzID struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// profileOrderResponse represents a parsed ACME order response.
type profileOrderResponse struct {
	Status      string        `json:"status"`
	Expires     string        `json:"expires,omitempty"`
	Identifiers []wireAuthzID `json:"identifiers"`
	AuthzURLs   []string      `json:"authorizations"`
	FinalizeURL string        `json:"finalize"`
	CertURL     string        `json:"certificate,omitempty"`
	Error       *goacme.Error `json:"error,omitempty"`
}

// authorizeOrderWithProfile creates a new ACME order with an optional certificate profile.
// This bypasses acme.Client.AuthorizeOrder() because the Go ACME library does not support
// the "profile" field in newOrder requests (as of golang.org/x/crypto v0.49.0).
//
// When profile is empty, this delegates to the standard acme.Client.AuthorizeOrder().
// When profile is set, it performs a custom JWS-signed POST to the newOrder endpoint
// with the profile field included in the request body.
func (c *Connector) authorizeOrderWithProfile(ctx context.Context, identifiers []goacme.AuthzID, profile string) (*goacme.Order, error) {
	// Fast path: no profile → use the standard library path
	if profile == "" {
		return c.client.AuthorizeOrder(ctx, identifiers)
	}

	c.logger.Info("creating ACME order with profile", "profile", profile)

	// Discover the directory to get the newOrder URL
	dir, err := c.client.Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("ACME directory discovery failed: %w", err)
	}

	if dir.OrderURL == "" {
		return nil, fmt.Errorf("ACME directory has no newOrder URL")
	}

	// Get the account URL (kid) for the JWS protected header
	acct, err := c.client.GetReg(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get ACME account for JWS signing: %w", err)
	}

	// Build the order request with profile
	var wireIDs []wireAuthzID
	for _, id := range identifiers {
		wireIDs = append(wireIDs, wireAuthzID{Type: id.Type, Value: id.Value})
	}

	orderReq := profileOrderRequest{
		Identifiers: wireIDs,
		Profile:     profile,
	}

	payload, err := json.Marshal(orderReq)
	if err != nil {
		return nil, fmt.Errorf("marshal order request: %w", err)
	}

	// Fetch a fresh nonce
	nonce, err := c.fetchNonce(ctx, dir.NonceURL)
	if err != nil {
		return nil, fmt.Errorf("fetch nonce: %w", err)
	}

	// Sign the request with JWS (ES256, kid mode)
	jwsBody, err := signJWS(c.accountKey, acct.URI, nonce, dir.OrderURL, payload)
	if err != nil {
		return nil, fmt.Errorf("JWS signing: %w", err)
	}

	// POST the JWS-signed request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dir.OrderURL, strings.NewReader(string(jwsBody)))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")

	httpClient := c.httpClient()
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("newOrder request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read newOrder response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("newOrder returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response into an acme.Order-compatible struct
	var orderResp profileOrderResponse
	if err := json.Unmarshal(body, &orderResp); err != nil {
		return nil, fmt.Errorf("parse newOrder response: %w", err)
	}

	// The order URI comes from the Location header
	orderURI := resp.Header.Get("Location")

	order := &goacme.Order{
		URI:         orderURI,
		Status:      orderResp.Status,
		AuthzURLs:   orderResp.AuthzURLs,
		FinalizeURL: orderResp.FinalizeURL,
		CertURL:     orderResp.CertURL,
	}

	// Parse identifiers back
	for _, wid := range orderResp.Identifiers {
		order.Identifiers = append(order.Identifiers, goacme.AuthzID{Type: wid.Type, Value: wid.Value})
	}

	c.logger.Info("ACME order created with profile",
		"profile", profile,
		"order_url", orderURI,
		"status", order.Status)

	return order, nil
}

// fetchNonce retrieves a fresh anti-replay nonce from the ACME server.
func (c *Connector) fetchNonce(ctx context.Context, nonceURL string) (string, error) {
	if nonceURL == "" {
		return "", fmt.Errorf("no nonce URL available")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, nonceURL, nil)
	if err != nil {
		return "", fmt.Errorf("create nonce request: %w", err)
	}

	httpClient := c.httpClient()
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("nonce request failed: %w", err)
	}
	defer resp.Body.Close()

	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("server did not return a Replay-Nonce header")
	}

	return nonce, nil
}

// signJWS creates a JWS (JSON Web Signature) in flattened JSON serialization
// using ES256 (ECDSA P-256 with SHA-256) in kid mode per RFC 8555.
//
// The JWS protected header contains:
//   - alg: ES256
//   - kid: account URL
//   - nonce: anti-replay nonce
//   - url: the target URL
func signJWS(key *ecdsa.PrivateKey, kid, nonce, targetURL string, payload []byte) ([]byte, error) {
	// Build protected header
	header := struct {
		Alg   string `json:"alg"`
		Kid   string `json:"kid"`
		Nonce string `json:"nonce"`
		URL   string `json:"url"`
	}{
		Alg:   "ES256",
		Kid:   kid,
		Nonce: nonce,
		URL:   targetURL,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("marshal JWS header: %w", err)
	}

	// Base64url encode protected header and payload
	protectedB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	// Create the signing input: ASCII(BASE64URL(header)) || '.' || ASCII(BASE64URL(payload))
	signingInput := protectedB64 + "." + payloadB64

	// Sign with ES256 (ECDSA P-256 + SHA-256)
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign: %w", err)
	}

	// Encode signature as fixed-size concatenation of r and s (32 bytes each for P-256)
	curveBits := key.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	sig := make([]byte, 2*keyBytes)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(sig[2*keyBytes-len(sBytes):], sBytes)

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	// Build flattened JWS JSON
	jws := struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{
		Protected: protectedB64,
		Payload:   payloadB64,
		Signature: sigB64,
	}

	return json.Marshal(jws)
}

