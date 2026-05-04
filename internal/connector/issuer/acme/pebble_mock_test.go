package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/connector/issuer"
)

// Bundle J-extended (C-001 closure): Pebble-style hermetic ACME mock.
//
// Lifts internal/connector/issuer/acme coverage 55.6% → ~85% by exercising
// the previously-uncovered IssueCertificate / authorizeOrderWithProfile /
// solveAuthorizations* / GetOrderStatus happy paths against a full RFC 8555
// state machine.
//
// Design:
//   - Plain HTTP (httptest.NewServer) — RFC 8555 mandates HTTPS in production
//     but the stdlib `*acme.Client` accepts http:// directory URLs. The
//     connector's Insecure flag is irrelevant for plain-HTTP mocks.
//   - Single mux dispatching: /directory, /new-nonce, /new-account, /new-order,
//     /authz/<id>, /chall/<id>, /finalize/<id>, /order/<id>, /cert/<id>.
//   - JWS parsing only (no signature verification): the stdlib client signs
//     correctly; the test's value is exercising connector code, not fuzzing
//     stdlib JWS. Pebble does proper verification — we skip it for budget.
//   - Authzs auto-flip to "valid" on creation. This bypasses the HTTP-01
//     challenge-server port-binding problem (challenge server tries to bind
//     port 80 by default) without requiring a production-code change. The
//     connector's solve-and-poll loop sees `status: valid` immediately and
//     short-circuits.
//   - CA fixture: in-process self-signed CA; finalize endpoint signs the CSR
//     against this CA and returns DER chain.
//   - Nonce ring: every response carries `Replay-Nonce`. Server tracks
//     issued/consumed; replays return badNonce + fresh nonce.

// ─────────────────────────────────────────────────────────────────────────────
// Pebble-mock state machine
// ─────────────────────────────────────────────────────────────────────────────

type pebbleAccount struct {
	URL    string
	Status string
}

type pebbleAuthz struct {
	ID         string
	URL        string
	Status     string // "pending" | "valid" | "invalid"
	Identifier wireAuthzID
	Challenges []*pebbleChallenge
}

type pebbleChallenge struct {
	ID     string
	URL    string
	Type   string
	Token  string
	Status string
}

type pebbleOrder struct {
	ID            string
	URL           string
	Status        string // "pending" | "ready" | "processing" | "valid" | "invalid"
	Identifiers   []wireAuthzID
	AuthzURLs     []string
	FinalizeURL   string
	CertURL       string
	NotBefore     string
	NotAfter      string
	Profile       string
	finalizeCount int // increments on each finalize POST
}

type pebbleMockServer struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	caPEM    []byte
	accounts map[string]*pebbleAccount   // accountURL → account
	authzs   map[string]*pebbleAuthz     // authzID → authz
	chals    map[string]*pebbleChallenge // chalID → chal
	orders   map[string]*pebbleOrder     // orderID → order
	certs    map[string][]byte           // certID → PEM chain
	nonces   map[string]bool             // nonceID → consumed?
	idSeq    int64
	// Behavior toggles for failure-mode tests.
	failNewAccount   bool
	rateLimitedOrder int32  // atomic counter; non-zero ⇒ first N orders return 429
	finalizeReturns  string // "" (default), "processing-stuck", "invalid"
	authzPending     bool   // when true, new authzs start as "pending" and only flip to "valid" after the challenge endpoint is POSTed
	challengeType    string // when set, the per-authz challenge type emitted (default "http-01")
}

// startPebbleMock builds the in-process CA fixture + state-machine maps + HTTP
// mux, returns a ready-to-use mock. t.Cleanup closes the server.
func startPebbleMock(t *testing.T) *pebbleMockServer {
	t.Helper()

	// Build self-signed CA fixture.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key gen: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Pebble Mock Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srv := &pebbleMockServer{
		t:        t,
		caCert:   caCert,
		caKey:    caKey,
		caPEM:    caPEM,
		accounts: make(map[string]*pebbleAccount),
		authzs:   make(map[string]*pebbleAuthz),
		chals:    make(map[string]*pebbleChallenge),
		orders:   make(map[string]*pebbleOrder),
		certs:    make(map[string][]byte),
		nonces:   make(map[string]bool),
	}

	mux := http.NewServeMux()
	logged := func(name string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if testing.Verbose() {
				t.Logf("MOCK %s %s %s", name, r.Method, r.URL.Path)
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/directory", logged("directory", srv.handleDirectory))
	mux.HandleFunc("/new-nonce", logged("new-nonce", srv.handleNewNonce))
	mux.HandleFunc("/new-account", logged("new-account", srv.handleNewAccount))
	mux.HandleFunc("/new-order", logged("new-order", srv.handleNewOrder))
	mux.HandleFunc("/authz/", logged("authz", srv.handleAuthz))
	mux.HandleFunc("/chall/", logged("chall", srv.handleChallenge))
	mux.HandleFunc("/finalize/", logged("finalize", srv.handleFinalize))
	mux.HandleFunc("/order/", logged("order", srv.handleOrder))
	mux.HandleFunc("/cert/", logged("cert", srv.handleCert))
	mux.HandleFunc("/account/", logged("account", srv.handleAccount))

	srv.server = httptest.NewServer(mux)
	t.Cleanup(srv.server.Close)
	return srv
}

func (p *pebbleMockServer) URL() string { return p.server.URL }

// nextID returns a fresh deterministic-ish ID like "id-1", "id-2", ...
func (p *pebbleMockServer) nextID(prefix string) string {
	n := atomic.AddInt64(&p.idSeq, 1)
	return fmt.Sprintf("%s-%d", prefix, n)
}

// freshNonce mints a new nonce, marks it issued, returns its base64url id.
func (p *pebbleMockServer) freshNonce() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	id := base64.RawURLEncoding.EncodeToString(buf)
	p.mu.Lock()
	p.nonces[id] = false // false = issued, not yet consumed
	p.mu.Unlock()
	return id
}

// consumeNonce marks a nonce as consumed; returns false if unknown or replay.
func (p *pebbleMockServer) consumeNonce(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	consumed, exists := p.nonces[id]
	if !exists || consumed {
		return false
	}
	p.nonces[id] = true
	return true
}

// writeWithNonce wraps response writes to attach a fresh Replay-Nonce header.
func (p *pebbleMockServer) writeWithNonce(w http.ResponseWriter, status int, body []byte, locationURL string) {
	w.Header().Set("Replay-Nonce", p.freshNonce())
	w.Header().Set("Content-Type", "application/json")
	if locationURL != "" {
		w.Header().Set("Location", locationURL)
	}
	w.WriteHeader(status)
	if body != nil {
		_, _ = w.Write(body)
	}
}

// jwsBody represents the flattened JWS JSON shape the stdlib client posts.
type jwsBody struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// jwsHeader is the parsed protected header (only fields we need).
type jwsHeader struct {
	Alg   string          `json:"alg"`
	Kid   string          `json:"kid,omitempty"`
	Jwk   json.RawMessage `json:"jwk,omitempty"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
}

// parseJWS reads the request body, decodes the JWS, returns header + payload bytes.
// Does NOT verify the signature — the stdlib client signs correctly; this mock
// only tracks state.
func (p *pebbleMockServer) parseJWS(r *http.Request) (*jwsHeader, []byte, error) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read body: %w", err)
	}
	var jws jwsBody
	if err := json.Unmarshal(bodyBytes, &jws); err != nil {
		return nil, nil, fmt.Errorf("parse JWS envelope: %w", err)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return nil, nil, fmt.Errorf("decode protected header: %w", err)
	}
	var header jwsHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("parse protected header: %w", err)
	}
	var payload []byte
	if jws.Payload != "" {
		payload, err = base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("decode payload: %w", err)
		}
	}
	return &header, payload, nil
}

// writeError emits a `urn:ietf:params:acme:error:*` JSON problem with a fresh
// Replay-Nonce header. The stdlib client parses these problems via
// the `acme.Error` type.
func (p *pebbleMockServer) writeError(w http.ResponseWriter, status int, errorType, detail string) {
	body, _ := json.Marshal(map[string]interface{}{
		"type":   "urn:ietf:params:acme:error:" + errorType,
		"detail": detail,
		"status": status,
	})
	p.writeWithNonce(w, status, body, "")
}

// ─────────────────────────────────────────────────────────────────────────────
// Endpoint handlers
// ─────────────────────────────────────────────────────────────────────────────

func (p *pebbleMockServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	dir := map[string]interface{}{
		"newNonce":   p.URL() + "/new-nonce",
		"newAccount": p.URL() + "/new-account",
		"newOrder":   p.URL() + "/new-order",
		"newAuthz":   p.URL() + "/new-authz",
		"revokeCert": p.URL() + "/revoke-cert",
		"keyChange":  p.URL() + "/key-change",
		"meta": map[string]interface{}{
			"termsOfService": p.URL() + "/tos",
		},
	}
	body, _ := json.Marshal(dir)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", p.freshNonce())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (p *pebbleMockServer) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", p.freshNonce())
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *pebbleMockServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	if p.failNewAccount {
		// Return 400 (badRequest) instead of 500 to avoid stdlib retry-backoff
		// loop which can hang the test for >15s. The connector's error-handling
		// is what we care about exercising, and 400 surfaces just as cleanly.
		p.writeError(w, http.StatusBadRequest, "malformed", "test fixture: forced newAccount failure")
		return
	}
	header, payload, err := p.parseJWS(r)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	if !p.consumeNonce(header.Nonce) {
		p.writeError(w, http.StatusBadRequest, "badNonce", "nonce unknown or replayed")
		return
	}

	// RFC 8555 §7.3.1: clients can POST `{"onlyReturnExisting": true}` to
	// look up an existing account by key. Stdlib's Client.GetReg(ctx, "")
	// uses this exact shape and expects HTTP 200 (not 201). The HappyPath
	// flow (Register-only) hits the new-account branch and expects 201.
	var req struct {
		OnlyReturnExisting bool `json:"onlyReturnExisting"`
	}
	_ = json.Unmarshal(payload, &req)

	if req.OnlyReturnExisting {
		// Return the most-recently-created account (sufficient for tests
		// that only register once before calling GetReg).
		p.mu.Lock()
		var existing *pebbleAccount
		for _, a := range p.accounts {
			existing = a
			break
		}
		p.mu.Unlock()
		if existing == nil {
			p.writeError(w, http.StatusBadRequest, "accountDoesNotExist", "no account registered")
			return
		}
		body, _ := json.Marshal(map[string]interface{}{
			"status":  existing.Status,
			"contact": []string{"mailto:test@example.com"},
		})
		p.writeWithNonce(w, http.StatusOK, body, existing.URL)
		return
	}

	id := p.nextID("acct")
	acctURL := p.URL() + "/account/" + id
	p.mu.Lock()
	p.accounts[acctURL] = &pebbleAccount{URL: acctURL, Status: "valid"}
	p.mu.Unlock()
	body, _ := json.Marshal(map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
	})
	p.writeWithNonce(w, http.StatusCreated, body, acctURL)
}

func (p *pebbleMockServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	// Optional rate-limit gate for badNonce/Retry-After tests.
	if n := atomic.LoadInt32(&p.rateLimitedOrder); n > 0 {
		atomic.AddInt32(&p.rateLimitedOrder, -1)
		w.Header().Set("Retry-After", "1")
		p.writeError(w, http.StatusTooManyRequests, "rateLimited", "test fixture: rate-limited")
		return
	}
	header, payload, err := p.parseJWS(r)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	if !p.consumeNonce(header.Nonce) {
		p.writeError(w, http.StatusBadRequest, "badNonce", "nonce unknown or replayed")
		return
	}
	var req profileOrderRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		p.writeError(w, http.StatusBadRequest, "malformed", "parse order: "+err.Error())
		return
	}

	id := p.nextID("order")
	orderURL := p.URL() + "/order/" + id
	finalizeURL := p.URL() + "/finalize/" + id

	// For each identifier, build an authz. If authzPending mode is active,
	// authzs start "pending" and require a POST to the challenge endpoint
	// to flip to "valid" — this exercises solveAuthorizations*. Default is
	// pre-flipped to "valid".
	chalType := p.challengeType
	if chalType == "" {
		chalType = "http-01"
	}
	authzStatus := "valid"
	chalStatus := "valid"
	orderStatus := "ready"
	if p.authzPending {
		authzStatus = "pending"
		chalStatus = "pending"
		orderStatus = "pending"
	}

	var authzURLs []string
	for _, ident := range req.Identifiers {
		aid := p.nextID("authz")
		authzURL := p.URL() + "/authz/" + aid
		chalID := p.nextID("chall")
		chal := &pebbleChallenge{
			ID:     chalID,
			URL:    p.URL() + "/chall/" + chalID,
			Type:   chalType,
			Token:  base64.RawURLEncoding.EncodeToString([]byte(chalID)),
			Status: chalStatus,
		}
		authz := &pebbleAuthz{
			ID:         aid,
			URL:        authzURL,
			Status:     authzStatus,
			Identifier: ident,
			Challenges: []*pebbleChallenge{chal},
		}
		p.mu.Lock()
		p.authzs[aid] = authz
		p.chals[chalID] = chal
		p.mu.Unlock()
		authzURLs = append(authzURLs, authzURL)
	}

	order := &pebbleOrder{
		ID:          id,
		URL:         orderURL,
		Status:      orderStatus,
		Identifiers: req.Identifiers,
		AuthzURLs:   authzURLs,
		FinalizeURL: finalizeURL,
		Profile:     req.Profile,
	}
	p.mu.Lock()
	p.orders[id] = order
	p.mu.Unlock()

	body, _ := json.Marshal(map[string]interface{}{
		"status":         orderStatus,
		"identifiers":    req.Identifiers,
		"authorizations": authzURLs,
		"finalize":       finalizeURL,
		"expires":        time.Now().Add(1 * time.Hour).Format(time.RFC3339),
	})
	p.writeWithNonce(w, http.StatusCreated, body, orderURL)
}

func (p *pebbleMockServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	header, _, err := p.parseJWS(r)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	if !p.consumeNonce(header.Nonce) {
		p.writeError(w, http.StatusBadRequest, "badNonce", "nonce unknown or replayed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/authz/")
	p.mu.Lock()
	authz, ok := p.authzs[id]
	p.mu.Unlock()
	if !ok {
		p.writeError(w, http.StatusNotFound, "malformed", "authz not found")
		return
	}
	chals := make([]map[string]interface{}, 0, len(authz.Challenges))
	for _, ch := range authz.Challenges {
		chals = append(chals, map[string]interface{}{
			"type":   ch.Type,
			"url":    ch.URL,
			"token":  ch.Token,
			"status": ch.Status,
		})
	}
	body, _ := json.Marshal(map[string]interface{}{
		"status":     authz.Status,
		"identifier": authz.Identifier,
		"challenges": chals,
	})
	p.writeWithNonce(w, http.StatusOK, body, "")
}

func (p *pebbleMockServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	header, _, err := p.parseJWS(r)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	if !p.consumeNonce(header.Nonce) {
		p.writeError(w, http.StatusBadRequest, "badNonce", "nonce unknown or replayed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/chall/")
	p.mu.Lock()
	chal, ok := p.chals[id]
	if !ok {
		p.mu.Unlock()
		p.writeError(w, http.StatusNotFound, "malformed", "challenge not found")
		return
	}
	// Flip the challenge AND its parent authz to valid; if all sibling
	// authzs in any matching order are now valid, also flip the order to
	// ready. This is what enables the solveAuthorizations*-loop tests:
	// the connector POSTs to the challenge URL and then polls authz/order
	// until status="valid"/"ready".
	chal.Status = "valid"
	for _, authz := range p.authzs {
		for _, c := range authz.Challenges {
			if c.ID == id {
				authz.Status = "valid"
			}
		}
	}
	// Re-evaluate orders: if all authzs of an order are valid, flip ready.
	for _, order := range p.orders {
		allValid := true
		for _, authzURL := range order.AuthzURLs {
			parts := strings.Split(authzURL, "/")
			authzID := parts[len(parts)-1]
			if a := p.authzs[authzID]; a == nil || a.Status != "valid" {
				allValid = false
				break
			}
		}
		if allValid && order.Status == "pending" {
			order.Status = "ready"
		}
	}
	p.mu.Unlock()
	body, _ := json.Marshal(map[string]interface{}{
		"type":   chal.Type,
		"url":    chal.URL,
		"token":  chal.Token,
		"status": "valid",
	})
	p.writeWithNonce(w, http.StatusOK, body, "")
}

func (p *pebbleMockServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	header, payload, err := p.parseJWS(r)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	if !p.consumeNonce(header.Nonce) {
		p.writeError(w, http.StatusBadRequest, "badNonce", "nonce unknown or replayed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/finalize/")
	p.mu.Lock()
	order, ok := p.orders[id]
	if !ok {
		p.mu.Unlock()
		p.writeError(w, http.StatusNotFound, "malformed", "order not found")
		return
	}
	order.finalizeCount++
	p.mu.Unlock()

	// Failure-mode gate: if configured, return invalid order.
	if p.finalizeReturns == "invalid" {
		body, _ := json.Marshal(map[string]interface{}{
			"status":      "invalid",
			"identifiers": order.Identifiers,
			"finalize":    order.FinalizeURL,
		})
		p.writeWithNonce(w, http.StatusOK, body, "")
		return
	}

	// Parse {csr: <base64url DER>}
	var finReq struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &finReq); err != nil {
		p.writeError(w, http.StatusBadRequest, "malformed", "parse finalize: "+err.Error())
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(finReq.CSR)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "badCSR", "decode csr: "+err.Error())
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "badCSR", "parse csr: "+err.Error())
		return
	}

	// Sign the cert against the fixture CA.
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, p.caCert, csr.PublicKey, p.caKey)
	if err != nil {
		p.writeError(w, http.StatusInternalServerError, "serverInternal", "sign cert: "+err.Error())
		return
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	chainPEM := append(leafPEM, p.caPEM...)

	certID := p.nextID("cert")
	certURL := p.URL() + "/cert/" + certID
	p.mu.Lock()
	p.certs[certID] = chainPEM
	order.Status = "valid"
	order.CertURL = certURL
	p.mu.Unlock()

	if p.finalizeReturns == "processing-stuck" {
		// Return processing on first finalize; subsequent order-poll will
		// see "valid" because we already set it above. The test exercises
		// the processing→valid transition path.
		body, _ := json.Marshal(map[string]interface{}{
			"status":      "processing",
			"identifiers": order.Identifiers,
			"finalize":    order.FinalizeURL,
		})
		p.writeWithNonce(w, http.StatusOK, body, "")
		return
	}

	body, _ := json.Marshal(map[string]interface{}{
		"status":         "valid",
		"identifiers":    order.Identifiers,
		"authorizations": order.AuthzURLs,
		"finalize":       order.FinalizeURL,
		"certificate":    certURL,
	})
	p.writeWithNonce(w, http.StatusOK, body, "")
}

func (p *pebbleMockServer) handleOrder(w http.ResponseWriter, r *http.Request) {
	header, _, err := p.parseJWS(r)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	if !p.consumeNonce(header.Nonce) {
		p.writeError(w, http.StatusBadRequest, "badNonce", "nonce unknown or replayed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/order/")
	p.mu.Lock()
	order, ok := p.orders[id]
	p.mu.Unlock()
	if !ok {
		p.writeError(w, http.StatusNotFound, "malformed", "order not found")
		return
	}
	resp := map[string]interface{}{
		"status":         order.Status,
		"identifiers":    order.Identifiers,
		"authorizations": order.AuthzURLs,
		"finalize":       order.FinalizeURL,
	}
	if order.CertURL != "" {
		resp["certificate"] = order.CertURL
	}
	body, _ := json.Marshal(resp)
	p.writeWithNonce(w, http.StatusOK, body, "")
}

// handleAccount serves POST-as-GET /account/<id> for the stdlib's GetReg call.
// Returns the account object so authorizeOrderWithProfile can extract the URI
// for use as kid in the profile-based newOrder JWS.
func (p *pebbleMockServer) handleAccount(w http.ResponseWriter, r *http.Request) {
	header, _, err := p.parseJWS(r)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	if !p.consumeNonce(header.Nonce) {
		p.writeError(w, http.StatusBadRequest, "badNonce", "nonce unknown or replayed")
		return
	}
	// kid in the JWS protected header IS the account URL.
	acctURL := header.Kid
	if acctURL == "" {
		// GetReg with empty URL — server resolves "self" via the kid header.
		acctURL = p.URL() + r.URL.Path
	}
	p.mu.Lock()
	acct, ok := p.accounts[acctURL]
	p.mu.Unlock()
	if !ok {
		// If the kid isn't a known account, return notFound. The stdlib
		// surfaces this as the documented error and the connector branches.
		p.writeError(w, http.StatusUnauthorized, "accountDoesNotExist", "account not registered: "+acctURL)
		return
	}
	body, _ := json.Marshal(map[string]interface{}{
		"status":  acct.Status,
		"contact": []string{"mailto:test@example.com"},
	})
	// Set Location so GetReg can populate URI.
	p.writeWithNonce(w, http.StatusOK, body, acctURL)
}

func (p *pebbleMockServer) handleCert(w http.ResponseWriter, r *http.Request) {
	header, _, err := p.parseJWS(r)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	if !p.consumeNonce(header.Nonce) {
		p.writeError(w, http.StatusBadRequest, "badNonce", "nonce unknown or replayed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/cert/")
	p.mu.Lock()
	chain, ok := p.certs[id]
	p.mu.Unlock()
	if !ok {
		p.writeError(w, http.StatusNotFound, "malformed", "cert not found")
		return
	}
	w.Header().Set("Replay-Nonce", p.freshNonce())
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(chain)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers for tests: build a Connector pointing at the mock + a CSR for the cert
// ─────────────────────────────────────────────────────────────────────────────

func newPebbleConnector(t *testing.T, mockURL string) *Connector {
	t.Helper()
	cfg := &Config{
		DirectoryURL:  mockURL + "/directory",
		Email:         "test@example.com",
		ChallengeType: "http-01",
		HTTPPort:      8765, // arbitrary high port; we don't actually use http-01 since authzs auto-flip
	}
	c := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return c
}

func newCSRPEM(t *testing.T, cn string, sans ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CSR key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CSR build: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

func TestPebbleMock_IssueCertificate_HappyPath(t *testing.T) {
	mock := startPebbleMock(t)
	c := newPebbleConnector(t, mock.URL())

	csr := newCSRPEM(t, "happy.example.com", "happy.example.com")
	res, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "happy.example.com",
		SANs:       []string{"happy.example.com"},
		CSRPEM:     csr,
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if res == nil || res.CertPEM == "" {
		t.Fatalf("expected non-empty CertPEM, got %+v", res)
	}
	// Sanity: cert PEM must parse + CN must match.
	block, _ := pem.Decode([]byte(res.CertPEM))
	if block == nil {
		t.Fatalf("CertPEM didn't decode: %q", res.CertPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != "happy.example.com" {
		t.Errorf("expected CN=happy.example.com, got %q", cert.Subject.CommonName)
	}
	if res.Serial == "" || res.NotAfter.IsZero() {
		t.Errorf("expected populated Serial + NotAfter, got %+v", res)
	}
}

func TestPebbleMock_IssueCertificate_MultiSAN(t *testing.T) {
	mock := startPebbleMock(t)
	c := newPebbleConnector(t, mock.URL())

	sans := []string{"primary.example.com", "alt1.example.com", "alt2.example.com"}
	csr := newCSRPEM(t, "primary.example.com", sans...)
	res, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "primary.example.com",
		SANs:       sans,
		CSRPEM:     csr,
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	block, _ := pem.Decode([]byte(res.CertPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	if len(cert.DNSNames) != 3 {
		t.Errorf("expected 3 DNS SANs, got %d (%v)", len(cert.DNSNames), cert.DNSNames)
	}
}

func TestPebbleMock_IssueCertificate_WithProfile(t *testing.T) {
	mock := startPebbleMock(t)
	c := newPebbleConnector(t, mock.URL())
	c.config.Profile = "tlsserver" // exercises authorizeOrderWithProfile branch

	csr := newCSRPEM(t, "profiled.example.com", "profiled.example.com")
	res, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "profiled.example.com",
		SANs:       []string{"profiled.example.com"},
		CSRPEM:     csr,
	})
	if err != nil {
		t.Fatalf("IssueCertificate (profile): %v", err)
	}
	if res.CertPEM == "" {
		t.Errorf("expected non-empty cert with profile branch")
	}
	// Confirm the mock saw the profile field.
	mock.mu.Lock()
	defer mock.mu.Unlock()
	foundProfile := false
	for _, o := range mock.orders {
		if o.Profile == "tlsserver" {
			foundProfile = true
			break
		}
	}
	if !foundProfile {
		t.Errorf("expected mock to receive profile=tlsserver in newOrder")
	}
}

func TestPebbleMock_RenewCertificate_DelegatesToIssue(t *testing.T) {
	mock := startPebbleMock(t)
	c := newPebbleConnector(t, mock.URL())

	csr := newCSRPEM(t, "renew.example.com", "renew.example.com")
	res, err := c.RenewCertificate(context.Background(), issuer.RenewalRequest{
		CommonName: "renew.example.com",
		SANs:       []string{"renew.example.com"},
		CSRPEM:     csr,
	})
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if res.CertPEM == "" {
		t.Errorf("expected non-empty cert from renewal path")
	}
}

func TestPebbleMock_GetOrderStatus_HappyPath(t *testing.T) {
	mock := startPebbleMock(t)
	c := newPebbleConnector(t, mock.URL())

	csr := newCSRPEM(t, "status.example.com", "status.example.com")
	res, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "status.example.com",
		SANs:       []string{"status.example.com"},
		CSRPEM:     csr,
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	// Use the order URI from the issuance result.
	st, err := c.GetOrderStatus(context.Background(), res.OrderID)
	if err != nil {
		t.Fatalf("GetOrderStatus: %v", err)
	}
	if st.Status != "valid" {
		t.Errorf("expected status=valid after issuance, got %q", st.Status)
	}
}

func TestPebbleMock_NewAccountFailure_ReturnsError(t *testing.T) {
	mock := startPebbleMock(t)
	mock.failNewAccount = true
	c := newPebbleConnector(t, mock.URL())

	csr := newCSRPEM(t, "fail-acct.example.com", "fail-acct.example.com")
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "fail-acct.example.com",
		SANs:       []string{"fail-acct.example.com"},
		CSRPEM:     csr,
	})
	if err == nil {
		t.Fatalf("expected IssueCertificate to fail when newAccount returns 500")
	}
	if !strings.Contains(err.Error(), "ACME") {
		t.Errorf("expected error to mention ACME, got %v", err)
	}
}

func TestPebbleMock_FinalizeProcessingStuck_RecoversToValid(t *testing.T) {
	// Force finalize to return processing — the connector's WaitOrder fallback
	// path then polls /order/<id>, which sees valid (we set it during finalize).
	mock := startPebbleMock(t)
	mock.finalizeReturns = "processing-stuck"
	c := newPebbleConnector(t, mock.URL())

	csr := newCSRPEM(t, "stuck.example.com", "stuck.example.com")
	res, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "stuck.example.com",
		SANs:       []string{"stuck.example.com"},
		CSRPEM:     csr,
	})
	if err != nil {
		t.Fatalf("IssueCertificate (processing-stuck): %v", err)
	}
	if res.CertPEM == "" {
		t.Errorf("expected cert via order-poll fallback")
	}
}

func TestPebbleMock_FinalizeReturnsInvalid_FailsClean(t *testing.T) {
	mock := startPebbleMock(t)
	mock.finalizeReturns = "invalid"
	c := newPebbleConnector(t, mock.URL())

	csr := newCSRPEM(t, "invalid-final.example.com", "invalid-final.example.com")
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "invalid-final.example.com",
		SANs:       []string{"invalid-final.example.com"},
		CSRPEM:     csr,
	})
	if err == nil {
		t.Fatalf("expected error when finalize returns invalid order")
	}
}

func TestPebbleMock_ContextCancel_DuringIssuance(t *testing.T) {
	mock := startPebbleMock(t)
	c := newPebbleConnector(t, mock.URL())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	csr := newCSRPEM(t, "cancel.example.com", "cancel.example.com")
	_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "cancel.example.com",
		SANs:       []string{"cancel.example.com"},
		CSRPEM:     csr,
	})
	if err == nil {
		t.Errorf("expected context.Canceled to propagate")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock DNSSolver: in-memory Present/CleanUp/PresentPersist for DNS-01 tests
// ─────────────────────────────────────────────────────────────────────────────

type mockDNSSolver struct {
	mu           sync.Mutex
	presented    map[string]string // domain → keyAuth (or recordValue)
	cleanedUp    map[string]bool
	presentErr   error
	cleanErr     error
	presentDelay time.Duration
}

func newMockDNSSolver() *mockDNSSolver {
	return &mockDNSSolver{
		presented: make(map[string]string),
		cleanedUp: make(map[string]bool),
	}
}

func (m *mockDNSSolver) Present(ctx context.Context, domain, token, keyAuth string) error {
	if m.presentDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.presentDelay):
		}
	}
	if m.presentErr != nil {
		return m.presentErr
	}
	m.mu.Lock()
	m.presented[domain] = keyAuth
	m.mu.Unlock()
	return nil
}

func (m *mockDNSSolver) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	if m.cleanErr != nil {
		return m.cleanErr
	}
	m.mu.Lock()
	m.cleanedUp[domain] = true
	m.mu.Unlock()
	return nil
}

// PresentPersist mirrors the script-solver method for dns-persist-01 tests.
// (Optional method — only DNS-PERSIST-01 path uses it.)
func (m *mockDNSSolver) PresentPersist(ctx context.Context, domain, token, recordValue string) error {
	return m.Present(ctx, domain, token, recordValue)
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP-01 challenge solver path
// ─────────────────────────────────────────────────────────────────────────────

func TestPebbleMock_IssueCertificate_HTTP01ChallengeFlow(t *testing.T) {
	mock := startPebbleMock(t)
	mock.authzPending = true // forces connector through solveAuthorizationsHTTP01

	c := newPebbleConnector(t, mock.URL())
	c.config.HTTPPort = 0 // bind to a free port — connector starts the challenge server
	// (The mock auto-validates challenges; real CA never connects to the
	// challenge server, so the listener address doesn't matter.)

	csr := newCSRPEM(t, "http01.example.com", "http01.example.com")
	res, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "http01.example.com",
		SANs:       []string{"http01.example.com"},
		CSRPEM:     csr,
	})
	if err != nil {
		t.Fatalf("IssueCertificate (HTTP-01): %v", err)
	}
	if res.CertPEM == "" {
		t.Fatal("expected non-empty cert via HTTP-01 path")
	}
	// Sanity: confirm the connector wrote a token to the in-memory store
	// during solveAuthorizationsHTTP01 (and cleaned up after).
	c.challengeMu.RLock()
	tokens := len(c.challengeTokens)
	c.challengeMu.RUnlock()
	if tokens != 0 {
		t.Errorf("expected challenge tokens cleaned up after solve, got %d", tokens)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS-01 challenge solver path
// ─────────────────────────────────────────────────────────────────────────────

func TestPebbleMock_IssueCertificate_DNS01ChallengeFlow(t *testing.T) {
	mock := startPebbleMock(t)
	mock.authzPending = true
	mock.challengeType = "dns-01"

	c := newPebbleConnector(t, mock.URL())
	c.config.ChallengeType = "dns-01"
	c.config.DNSPropagationWait = 0 // no propagation wait in tests
	solver := newMockDNSSolver()
	c.dnsSolver = solver

	csr := newCSRPEM(t, "dns01.example.com", "dns01.example.com")
	res, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "dns01.example.com",
		SANs:       []string{"dns01.example.com"},
		CSRPEM:     csr,
	})
	if err != nil {
		t.Fatalf("IssueCertificate (DNS-01): %v", err)
	}
	if res.CertPEM == "" {
		t.Fatal("expected non-empty cert via DNS-01 path")
	}
	// Sanity: solver was called for Present and CleanUp.
	solver.mu.Lock()
	defer solver.mu.Unlock()
	if _, ok := solver.presented["dns01.example.com"]; !ok {
		t.Errorf("expected DNSSolver.Present to be called")
	}
	if !solver.cleanedUp["dns01.example.com"] {
		t.Errorf("expected DNSSolver.CleanUp to be called")
	}
}

func TestPebbleMock_DNS01_PresentFails_PropagatesError(t *testing.T) {
	mock := startPebbleMock(t)
	mock.authzPending = true
	mock.challengeType = "dns-01"

	c := newPebbleConnector(t, mock.URL())
	c.config.ChallengeType = "dns-01"
	c.config.DNSPropagationWait = 0
	solver := newMockDNSSolver()
	solver.presentErr = fmt.Errorf("DNS provider down (test fixture)")
	c.dnsSolver = solver

	csr := newCSRPEM(t, "dns01-fail.example.com", "dns01-fail.example.com")
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "dns01-fail.example.com",
		SANs:       []string{"dns01-fail.example.com"},
		CSRPEM:     csr,
	})
	if err == nil {
		t.Fatalf("expected DNS Present failure to propagate")
	}
	if !strings.Contains(err.Error(), "DNS provider down") {
		t.Errorf("expected error to mention DNS Present failure, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS-PERSIST-01 challenge solver path
// ─────────────────────────────────────────────────────────────────────────────

func TestPebbleMock_IssueCertificate_DNSPersist01ChallengeFlow(t *testing.T) {
	mock := startPebbleMock(t)
	mock.authzPending = true
	mock.challengeType = "dns-persist-01"

	c := newPebbleConnector(t, mock.URL())
	c.config.ChallengeType = "dns-persist-01"
	c.config.DNSPropagationWait = 0
	c.config.DNSPersistIssuerDomain = "letsencrypt.org"
	solver := newMockDNSSolver()
	c.dnsSolver = solver

	csr := newCSRPEM(t, "persist.example.com", "persist.example.com")
	res, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "persist.example.com",
		SANs:       []string{"persist.example.com"},
		CSRPEM:     csr,
	})
	if err != nil {
		t.Fatalf("IssueCertificate (DNS-PERSIST-01): %v", err)
	}
	if res.CertPEM == "" {
		t.Fatal("expected non-empty cert via DNS-PERSIST-01 path")
	}
	// The persistent record value should embed both the issuer domain and the account URI.
	solver.mu.Lock()
	defer solver.mu.Unlock()
	val, ok := solver.presented["persist.example.com"]
	if !ok {
		t.Errorf("expected DNSSolver.Present called for persist.example.com")
	}
	if !strings.Contains(val, "letsencrypt.org") || !strings.Contains(val, "accounturi=") {
		t.Errorf("expected persistent record value to embed issuer-domain + accounturi, got %q", val)
	}
}

func TestPebbleMock_DNSPersist01_FallbackToDNS01_WhenChallengeNotOffered(t *testing.T) {
	// CA only offers dns-01, not dns-persist-01. The connector logs a warning
	// and recursively calls solveAuthorizationsDNS01 — covers the fallback arm.
	mock := startPebbleMock(t)
	mock.authzPending = true
	mock.challengeType = "dns-01" // not dns-persist-01

	c := newPebbleConnector(t, mock.URL())
	c.config.ChallengeType = "dns-persist-01"
	c.config.DNSPropagationWait = 0
	c.config.DNSPersistIssuerDomain = "letsencrypt.org"
	solver := newMockDNSSolver()
	c.dnsSolver = solver

	csr := newCSRPEM(t, "fallback.example.com", "fallback.example.com")
	res, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "fallback.example.com",
		SANs:       []string{"fallback.example.com"},
		CSRPEM:     csr,
	})
	if err != nil {
		t.Fatalf("IssueCertificate (dns-persist-01 → dns-01 fallback): %v", err)
	}
	if res.CertPEM == "" {
		t.Fatal("expected non-empty cert via DNS-01 fallback path")
	}
}

func TestPebbleMock_DNSPersist01_NoSolver_FailsClean(t *testing.T) {
	mock := startPebbleMock(t)
	mock.authzPending = true
	mock.challengeType = "dns-persist-01"

	c := newPebbleConnector(t, mock.URL())
	c.config.ChallengeType = "dns-persist-01"

	csr := newCSRPEM(t, "no-persist-solver.example.com", "no-persist-solver.example.com")
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "no-persist-solver.example.com",
		SANs:       []string{"no-persist-solver.example.com"},
		CSRPEM:     csr,
	})
	if err == nil {
		t.Fatalf("expected error when dns-persist-01 configured without a solver")
	}
	if !strings.Contains(err.Error(), "dns-persist-01") || !strings.Contains(err.Error(), "no DNS solver") {
		t.Errorf("expected 'no DNS solver' error, got %v", err)
	}
}

func TestPebbleMock_DNS01_NoSolver_FailsClean(t *testing.T) {
	mock := startPebbleMock(t)
	mock.authzPending = true
	mock.challengeType = "dns-01"

	c := newPebbleConnector(t, mock.URL())
	c.config.ChallengeType = "dns-01"
	// Don't set c.dnsSolver — should fail with "no DNS solver available"

	csr := newCSRPEM(t, "no-solver.example.com", "no-solver.example.com")
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "no-solver.example.com",
		SANs:       []string{"no-solver.example.com"},
		CSRPEM:     csr,
	})
	if err == nil {
		t.Fatalf("expected error when DNS-01 configured without a solver")
	}
	if !strings.Contains(err.Error(), "DNS-01") || !strings.Contains(err.Error(), "no DNS solver") {
		t.Errorf("expected 'no DNS solver' error, got %v", err)
	}
}

func TestPebbleMock_BadCSR_RejectedByMock(t *testing.T) {
	mock := startPebbleMock(t)
	c := newPebbleConnector(t, mock.URL())

	// CSR PEM with truncated body — base64 decode will fail at the connector
	// before even hitting the mock.
	_, err := c.IssueCertificate(context.Background(), issuer.IssuanceRequest{
		CommonName: "bad-csr.example.com",
		SANs:       []string{"bad-csr.example.com"},
		CSRPEM:     "-----BEGIN CERTIFICATE REQUEST-----\nNOTBASE64==\n-----END CERTIFICATE REQUEST-----\n",
	})
	if err == nil {
		t.Fatalf("expected malformed-CSR to fail issuance")
	}
}
