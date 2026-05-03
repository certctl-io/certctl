package googlecas_test

// Top-10 fix #4 of the 2026-05-03 issuer-coverage audit. GoogleCAS
// is typically the first-deployed issuer in GCP-anchored enterprise
// pilots — diligence reviews dig hard into IAM-error / cloud-error
// coverage. Pre-fix, googlecas_test.go covered the happy path plus a
// generic ServerError + InvalidResponse pair, but did not pin
// behaviour against the distinct operator-actionable error classes
// (PermissionDenied vs CAPoolNotFound vs OAuth2 token-refresh
// failure) that real production traffic surfaces.
//
// Adapter shape: googlecas.go uses stdlib net/http + crypto/rsa
// directly — there is NO Google Cloud Go SDK dependency. CAS errors
// arrive as JSON in the HTTP response body, with the canonical Google
// API error envelope:
//
//   {"error":{"code":403,"message":"...","status":"PERMISSION_DENIED"}}
//
// The connector decodes that body via extractAPIError and wraps the
// resulting message into the surfaced error. Because there is no SDK
// typed-error value to errors.As against (per the spec's "use what
// exists today" rule), each test below pins:
//
//   1. error non-nil,
//   2. operator-actionable substring present in the surfaced message
//      (resource path, missing-pool name, "token" vs "credential",
//      "503" / UNAVAILABLE for the retryable class),
//   3. the SDK-level status string ("PERMISSION_DENIED",
//      "NOT_FOUND", "UNAVAILABLE") survives through the wrap chain so
//      upstream classification logic can branch on it.
//
// Test-only commit. No production code changes.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/googlecas"
)

// failureTestLogger returns a debug-level slog logger writing to
// stdout. Mirrors the per-test logger in googlecas_test.go to keep
// failure logs grep-friendly when a test regresses.
func failureTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestGoogleCAS_Issue_PermissionDenied_OperatorActionableError pins
// the surfaced contract when the GCP service-account caller lacks
// privateca.certificates.create on the configured CA pool. Real
// traffic returns a 403 with the canonical PERMISSION_DENIED
// envelope; the surfaced error must (a) preserve the IAM resource
// path the operator needs to fix the binding, and (b) preserve the
// PERMISSION_DENIED status string so upstream classification can
// recognise the IAM-error class.
func TestGoogleCAS_Issue_PermissionDenied_OperatorActionableError(t *testing.T) {
	ctx := context.Background()
	credPath := createTestCredentialsFile(t)

	const resourcePath = "projects/test-project/locations/us-central1/caPools/test-pool"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
		case strings.Contains(r.URL.Path, "/certificates"):
			w.WriteHeader(http.StatusForbidden)
			body := fmt.Sprintf(`{"error":{"code":403,"message":"Permission 'privateca.certificates.create' denied on resource '%s' (or it may not exist).","status":"PERMISSION_DENIED"}}`, resourcePath)
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &googlecas.Config{
		Project:     "test-project",
		Location:    "us-central1",
		CAPool:      "test-pool",
		Credentials: credPath,
		TTL:         "8760h",
		BaseURL:     srv.URL,
		TokenURL:    srv.URL + "/token",
	}
	c := googlecas.New(cfg, failureTestLogger())

	_, csrPEM := generateTestCSR(t, "app.example.com")
	_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "app.example.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected error from PERMISSION_DENIED, got nil")
	}

	msg := err.Error()
	if !strings.Contains(msg, "PERMISSION_DENIED") {
		t.Errorf("status string PERMISSION_DENIED missing from surfaced error; got: %s", msg)
	}
	if !strings.Contains(msg, resourcePath) {
		t.Errorf("operator-actionable substring missing — message must name the IAM resource path %q; got: %s", resourcePath, msg)
	}
	if !strings.Contains(msg, "Permission") && !strings.Contains(msg, "permission") {
		t.Errorf("operator-actionable substring missing — message must mention 'permission'; got: %s", msg)
	}
}

// TestGoogleCAS_Issue_CAPoolNotFound_NamesTheMissingPool pins the
// surfaced contract when the configured CA pool does not exist (e.g.
// typo in CERTCTL_GOOGLE_CAS_CA_POOL, or the pool was deleted out
// from under certctl). Google CAS returns HTTP 404 with NOT_FOUND
// status; the surfaced error must name the missing pool resource so
// the operator can correct the config without grepping logs.
func TestGoogleCAS_Issue_CAPoolNotFound_NamesTheMissingPool(t *testing.T) {
	ctx := context.Background()
	credPath := createTestCredentialsFile(t)

	const missingPool = "projects/test-project/locations/us-central1/caPools/missing-pool"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
		case strings.Contains(r.URL.Path, "/certificates"):
			w.WriteHeader(http.StatusNotFound)
			body := fmt.Sprintf(`{"error":{"code":404,"message":"Resource '%s' was not found.","status":"NOT_FOUND"}}`, missingPool)
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &googlecas.Config{
		Project:     "test-project",
		Location:    "us-central1",
		CAPool:      "missing-pool",
		Credentials: credPath,
		TTL:         "8760h",
		BaseURL:     srv.URL,
		TokenURL:    srv.URL + "/token",
	}
	c := googlecas.New(cfg, failureTestLogger())

	_, csrPEM := generateTestCSR(t, "app.example.com")
	_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "app.example.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected error from NOT_FOUND, got nil")
	}

	msg := err.Error()
	if !strings.Contains(msg, "NOT_FOUND") {
		t.Errorf("status string NOT_FOUND missing from surfaced error; got: %s", msg)
	}
	if !strings.Contains(msg, missingPool) {
		t.Errorf("operator-actionable substring missing — message must name the missing CA pool %q; got: %s", missingPool, msg)
	}
}

// TestGoogleCAS_Issue_OAuth2TokenRefreshFailure_DistinguishedFromCAError
// pins the surfaced contract when the OAuth2 JWT-bearer exchange
// against oauth2.googleapis.com fails (e.g. service-account key has
// been disabled, JWT signature invalid, or token endpoint is reaching
// us through a misconfigured corp proxy). The surfaced error must
// mention "token" so an operator reading the log can immediately
// distinguish a credential failure from a CA-side error — the two
// are remediated very differently (rotate SA key vs. fix IAM
// binding).
func TestGoogleCAS_Issue_OAuth2TokenRefreshFailure_DistinguishedFromCAError(t *testing.T) {
	ctx := context.Background()
	credPath := createTestCredentialsFile(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`))
		default:
			// We should never reach the CAS endpoint if the token
			// exchange fails — assert that explicitly so a regression
			// that swallows the token error and proceeds to the CAS
			// call is caught by this test.
			t.Errorf("CAS endpoint reached despite token-refresh failure — path=%s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &googlecas.Config{
		Project:     "test-project",
		Location:    "us-central1",
		CAPool:      "test-pool",
		Credentials: credPath,
		TTL:         "8760h",
		BaseURL:     srv.URL,
		TokenURL:    srv.URL + "/token",
	}
	c := googlecas.New(cfg, failureTestLogger())

	_, csrPEM := generateTestCSR(t, "app.example.com")
	_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "app.example.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected error from token-refresh failure, got nil")
	}

	msg := err.Error()
	// The connector wraps the token failure as
	//   "failed to get access token: token exchange returned status 401: ..."
	// so "token" should always be present. If a future refactor renames
	// it to "credential", that is also acceptable — both let an
	// operator distinguish from a CA-side error.
	if !strings.Contains(msg, "token") && !strings.Contains(msg, "credential") {
		t.Errorf("operator-actionable substring missing — token-refresh failure must mention 'token' or 'credential' so it is distinguishable from a CA-side error; got: %s", msg)
	}
	// Surfaced message should name the upstream HTTP status.
	if !strings.Contains(msg, "401") {
		t.Errorf("expected token-refresh status 401 to be preserved through wrap chain; got: %s", msg)
	}
}

// TestGoogleCAS_Issue_RegionalAPIUnavailable_RetryableSurface pins
// the surfaced contract when a CAS regional endpoint returns 503
// UNAVAILABLE — typically a transient regional outage where the
// correct upstream behaviour is "retry with backoff" rather than
// "alert ops". The connector currently surfaces these to the caller
// without retrying internally (per spec's "no new retry logic" rule);
// the surfaced error must preserve the 503 / UNAVAILABLE markers so
// an upstream retry layer can recognise the retryable class.
func TestGoogleCAS_Issue_RegionalAPIUnavailable_RetryableSurface(t *testing.T) {
	ctx := context.Background()
	credPath := createTestCredentialsFile(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
		case strings.Contains(r.URL.Path, "/certificates"):
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":503,"message":"The service is currently unavailable.","status":"UNAVAILABLE"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &googlecas.Config{
		Project:     "test-project",
		Location:    "us-central1",
		CAPool:      "test-pool",
		Credentials: credPath,
		TTL:         "8760h",
		BaseURL:     srv.URL,
		TokenURL:    srv.URL + "/token",
	}
	c := googlecas.New(cfg, failureTestLogger())

	_, csrPEM := generateTestCSR(t, "app.example.com")
	_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "app.example.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected error from 503 UNAVAILABLE, got nil")
	}

	msg := err.Error()
	if !strings.Contains(msg, "503") {
		t.Errorf("expected HTTP status 503 to be preserved through wrap chain; got: %s", msg)
	}
	if !strings.Contains(msg, "UNAVAILABLE") {
		t.Errorf("expected canonical UNAVAILABLE status string for upstream retry classification; got: %s", msg)
	}
}

// TestGoogleCAS_Revoke_PermissionDenied_DoesNotSilentlySwallow pins
// the contract that PERMISSION_DENIED on a revoke call surfaces an
// error rather than being silently swallowed. The audit-row
// atomicity contract from Bundle G lives in service.RevocationSvc
// (which writes the local audit row inside the same DB tx as the
// adapter call); the adapter's only job here is "return non-nil so
// the service-layer wrapper rolls back". This test pins that
// contract.
//
// (We deliberately do NOT exercise the service-layer audit-row
// rollback here — that's an integration test owned by
// internal/service/revocation_svc_test.go. Mixing concerns would
// re-introduce the exact "lying field" footgun CLAUDE.md warns
// against. The adapter contract is the single thing under test.)
func TestGoogleCAS_Revoke_PermissionDenied_DoesNotSilentlySwallow(t *testing.T) {
	ctx := context.Background()
	credPath := createTestCredentialsFile(t)

	const certName = "projects/test-project/locations/us-central1/caPools/test-pool/certificates/cert-revoke-denied"

	var revokeCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
		case strings.Contains(r.URL.Path, ":revoke"):
			revokeCalled = true
			// Decode the request body to confirm the revoke reason was
			// actually serialised and sent — guards against a future
			// regression that silently no-ops the revoke before the
			// HTTP request.
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if _, ok := body["reason"]; !ok {
				t.Errorf("revoke request body missing 'reason' field — adapter constructed an empty payload")
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":403,"message":"Permission 'privateca.certificates.update' denied on certificate.","status":"PERMISSION_DENIED"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &googlecas.Config{
		Project:     "test-project",
		Location:    "us-central1",
		CAPool:      "test-pool",
		Credentials: credPath,
		TTL:         "8760h",
		BaseURL:     srv.URL,
		TokenURL:    srv.URL + "/token",
	}
	c := googlecas.New(cfg, failureTestLogger())

	reason := "keyCompromise"
	err := c.RevokeCertificate(ctx, issuer.RevocationRequest{
		Serial: certName,
		Reason: &reason,
	})

	// CONTRACT 1: adapter does NOT silently swallow the failure.
	if err == nil {
		t.Fatal("expected error from revoke PERMISSION_DENIED — adapter must surface, not swallow")
	}
	// CONTRACT 2: adapter actually attempted the revoke before
	// surfacing the error (regression guard against a future "fail
	// fast before the HTTP call" change that would skip the
	// short-circuit guarantee).
	if !revokeCalled {
		t.Error("revoke endpoint not reached — adapter short-circuited before sending the HTTP request")
	}

	msg := err.Error()
	if !strings.Contains(msg, "PERMISSION_DENIED") {
		t.Errorf("expected canonical PERMISSION_DENIED status string in surfaced error; got: %s", msg)
	}
	if !strings.Contains(msg, "Permission") && !strings.Contains(msg, "permission") {
		t.Errorf("operator-actionable substring missing — revoke error must mention 'permission'; got: %s", msg)
	}
}
