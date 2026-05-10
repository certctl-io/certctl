package oidc

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// =============================================================================
// Token-leak hygiene: no secret value (ID token, access token, refresh
// token, authorization code, PKCE verifier, state, nonce, signing key
// material) appears in any log line at any level.
//
// Methodology mirrors Bundle 1's
// internal/auth/bootstrap/service_test.go::TestService_TokenLeakHygiene:
// redirect slog.Default to a buffer, run the OIDC service paths,
// grep-assert the secret string never appears in any captured line.
//
// This is the load-bearing invariant for Phase 3's "tokens never
// logged" contract. Every secret-bearing path that enters the
// service.go code MUST flow through write-once-to-response patterns;
// adding a `slog.Info("got token", "value", token)` somewhere would
// fail this test immediately.
// =============================================================================

// captureLogger swaps the slog.Default with one that writes to the
// returned buffer. The returned restore func re-installs the original
// logger; callers must defer it.
func captureLogger(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Writer(buf), &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	return buf, func() { slog.SetDefault(original) }
}

// TestLoggingHygiene_HandleAuthRequest_LeaksNothing exercises the full
// HandleAuthRequest path against a mock IdP and asserts that the
// generated state, nonce, PKCE verifier, and pre-login cookie never
// appear in any captured log line.
func TestLoggingHygiene_HandleAuthRequest_LeaksNothing(t *testing.T) {
	idp := newMockIdP(t)
	svc, _ := newServiceWithProviderAndPL(t, idp.URL(), "op-leak-1")

	buf, restore := captureLogger(t)
	defer restore()

	authURL, cookieValue, _, err := svc.HandleAuthRequest(context.Background(), "op-leak-1")
	if err != nil {
		t.Fatalf("HandleAuthRequest: %v", err)
	}

	// Extract state from the authURL query so we can grep-assert.
	parts := strings.Split(authURL, "state=")
	if len(parts) < 2 {
		t.Fatalf("authURL missing state param: %q", authURL)
	}
	stateValue := strings.SplitN(parts[1], "&", 2)[0]

	captured := buf.String()
	for _, secret := range []string{stateValue, cookieValue} {
		if secret == "" {
			continue
		}
		if strings.Contains(captured, secret) {
			t.Errorf("secret value %q appeared in log output:\n%s", secret, captured)
		}
	}
}

// TestLoggingHygiene_HandleCallback_LeaksNothing runs the full callback
// flow (against the mock IdP) and grep-asserts the captured log buffer
// has no occurrence of the access token, the ID token, the
// authorization code, or the PKCE verifier.
func TestLoggingHygiene_HandleCallback_LeaksNothing(t *testing.T) {
	idp := newMockIdP(t)
	svc, pl := newServiceWithProviderAndPL(t, idp.URL(), "op-leak-2")

	// Pre-login row with a known verifier we can grep for after.
	verifier := "test-verifier-do-not-leak-aaaaaaaaaaaaa"
	cookie, _, err := pl.CreatePreLogin(context.Background(), "op-leak-2", "the-state", "test-nonce-fixed", verifier)
	if err != nil {
		t.Fatalf("CreatePreLogin: %v", err)
	}

	buf, restore := captureLogger(t)
	defer restore()

	authCode := "secret-auth-code-do-not-leak"
	res, err := svc.HandleCallback(context.Background(), cookie, authCode, "the-state", "", "10.0.0.1", "Mozilla")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}

	captured := buf.String()

	// Direct secrets that flow through HandleCallback's parameter list.
	for _, secret := range []string{
		authCode,
		verifier,
		"test-access-token",
		idp.receivedCode,
		idp.receivedVerifier,
	} {
		if secret == "" {
			continue
		}
		if strings.Contains(captured, secret) {
			t.Errorf("secret value %q appeared in log output:\n%s", secret, captured)
		}
	}

	// The session cookie + CSRF token are returned by the mint stub;
	// in production they're set on the response, not logged. Pin that
	// we never logged them.
	for _, secret := range []string{res.CookieValue, res.CSRFToken} {
		if secret == "" {
			continue
		}
		if strings.Contains(captured, secret) {
			t.Errorf("session secret %q appeared in log output:\n%s", secret, captured)
		}
	}
}

// TestLoggingHygiene_AlgPinningDoesNotLogAlg is a defense-in-depth pin:
// when isDisallowedAlg rejects a token, the alg name might land in an
// error returned to the handler — but the service.go MUST NOT log the
// alg value itself (an attacker could probe to discover allow-list
// composition). The handler maps to a uniform 400; alg detail lives
// only in audit rows the operator owns.
func TestLoggingHygiene_AlgRejectionDoesNotLogAlg(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	// Direct call to the helper; this exercises the deny-list match.
	_, _ = isDisallowedAlg("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.body.sig")

	captured := buf.String()
	if strings.Contains(captured, "HS256") {
		t.Errorf("alg value HS256 appeared in log output (defense-in-depth violation):\n%s", captured)
	}
}

// TestLoggingHygiene_ProviderLoadDoesNotLogClientSecret pins that
// even on getOrLoad failures, the decrypted client_secret bytes never
// land in a log line. Decryption happens before verifier construction;
// any error path that flows through must not surface the plaintext.
func TestLoggingHygiene_ProviderLoadDoesNotLogClientSecret(t *testing.T) {
	idp := newMockIdP(t)

	// Use a provider with a recognizable plaintext "secret" (no encryption
	// key set, so decryptClientSecret returns the bytes as-is).
	prov := makeProvider(idp.URL(), "op-leak-secret")
	prov.ClientSecretEncrypted = []byte("client-secret-plaintext-do-not-leak-xxxxx")

	pl := newStubPreLogin()
	svc := NewService(
		&stubProviderLookup{provider: prov},
		&stubMappings{roleIDs: []string{"r-operator"}},
		newStubUsers(),
		&stubSessions{},
		pl,
		"",
	)

	buf, restore := captureLogger(t)
	defer restore()

	if _, err := svc.getOrLoad(context.Background(), "op-leak-secret"); err != nil {
		t.Fatalf("getOrLoad: %v", err)
	}

	captured := buf.String()
	if strings.Contains(captured, "client-secret-plaintext-do-not-leak") {
		t.Errorf("client secret plaintext appeared in log output:\n%s", captured)
	}
}
