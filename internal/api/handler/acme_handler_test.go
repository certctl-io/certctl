// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/shankar0123/certctl/internal/api/acme"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/service"
)

// mockACMEService implements ACMEService for handler-level tests.
// Mirrors the mockSCEPService pattern at scep_handler_test.go (struct
// holding canned responses + an err field per method).
type mockACMEService struct {
	BuildDirectoryFn    func(ctx context.Context, profileID, baseURL string) (*acme.Directory, error)
	IssueNonceFn        func(ctx context.Context) (string, error)
	VerifyJWSFn         func(ctx context.Context, body []byte, requestURL string, expectNewAccount bool, accountKID func(string) string) (*acme.VerifiedRequest, error)
	NewAccountFn        func(ctx context.Context, profileID string, jwk *jose.JSONWebKey, contact []string, onlyReturnExisting bool, tosAgreed bool) (*domain.ACMEAccount, bool, error)
	LookupAccountFn     func(ctx context.Context, accountID string) (*domain.ACMEAccount, error)
	UpdateAccountFn     func(ctx context.Context, accountID string, contact []string) (*domain.ACMEAccount, error)
	DeactivateAccountFn func(ctx context.Context, accountID string) (*domain.ACMEAccount, error)
}

func (m *mockACMEService) BuildDirectory(ctx context.Context, profileID, baseURL string) (*acme.Directory, error) {
	if m.BuildDirectoryFn != nil {
		return m.BuildDirectoryFn(ctx, profileID, baseURL)
	}
	return acme.BuildDirectory(baseURL, "", "", nil, false, false), nil
}

func (m *mockACMEService) IssueNonce(ctx context.Context) (string, error) {
	if m.IssueNonceFn != nil {
		return m.IssueNonceFn(ctx)
	}
	return "test-nonce-12345", nil
}

func (m *mockACMEService) VerifyJWS(ctx context.Context, body []byte, requestURL string, expectNewAccount bool, accountKID func(string) string) (*acme.VerifiedRequest, error) {
	if m.VerifyJWSFn != nil {
		return m.VerifyJWSFn(ctx, body, requestURL, expectNewAccount, accountKID)
	}
	return nil, errors.New("VerifyJWS not stubbed")
}

func (m *mockACMEService) NewAccount(ctx context.Context, profileID string, jwk *jose.JSONWebKey, contact []string, onlyReturnExisting bool, tosAgreed bool) (*domain.ACMEAccount, bool, error) {
	if m.NewAccountFn != nil {
		return m.NewAccountFn(ctx, profileID, jwk, contact, onlyReturnExisting, tosAgreed)
	}
	return nil, false, errors.New("NewAccount not stubbed")
}

func (m *mockACMEService) LookupAccount(ctx context.Context, accountID string) (*domain.ACMEAccount, error) {
	if m.LookupAccountFn != nil {
		return m.LookupAccountFn(ctx, accountID)
	}
	return nil, errors.New("LookupAccount not stubbed")
}

func (m *mockACMEService) UpdateAccount(ctx context.Context, accountID string, contact []string) (*domain.ACMEAccount, error) {
	if m.UpdateAccountFn != nil {
		return m.UpdateAccountFn(ctx, accountID, contact)
	}
	return nil, errors.New("UpdateAccount not stubbed")
}

func (m *mockACMEService) DeactivateAccount(ctx context.Context, accountID string) (*domain.ACMEAccount, error) {
	if m.DeactivateAccountFn != nil {
		return m.DeactivateAccountFn(ctx, accountID)
	}
	return nil, errors.New("DeactivateAccount not stubbed")
}

// newACMETestServer wires the ACMEHandler against the mock + a stdlib
// ServeMux configured exactly the way internal/api/router/router.go
// does it in production. Routes:
//
//	GET  /acme/profile/{id}/directory
//	HEAD /acme/profile/{id}/new-nonce
//	GET  /acme/profile/{id}/new-nonce
//	GET  /acme/directory     (shorthand)
//	HEAD /acme/new-nonce     (shorthand)
//	GET  /acme/new-nonce     (shorthand)
func newACMETestServer(t *testing.T, mock *mockACMEService) *httptest.Server {
	t.Helper()
	h := NewACMEHandler(mock)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /acme/profile/{id}/directory", h.Directory)
	mux.HandleFunc("HEAD /acme/profile/{id}/new-nonce", h.NewNonce)
	mux.HandleFunc("GET /acme/profile/{id}/new-nonce", h.NewNonce)
	mux.HandleFunc("POST /acme/profile/{id}/new-account", h.NewAccount)
	mux.HandleFunc("POST /acme/profile/{id}/account/{acc_id}", h.Account)
	mux.HandleFunc("GET /acme/directory", h.Directory)
	mux.HandleFunc("HEAD /acme/new-nonce", h.NewNonce)
	mux.HandleFunc("GET /acme/new-nonce", h.NewNonce)
	mux.HandleFunc("POST /acme/new-account", h.NewAccount)
	mux.HandleFunc("POST /acme/account/{acc_id}", h.Account)
	return httptest.NewServer(mux)
}

func TestACMEHandler_Directory_HappyPath(t *testing.T) {
	mock := &mockACMEService{}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/acme/profile/prof-corp/directory")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type = %q", got)
	}
	if got := resp.Header.Get("Replay-Nonce"); got == "" {
		t.Error("Replay-Nonce header missing on directory response")
	}

	var dir acme.Directory
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(dir.NewNonce, "/acme/profile/prof-corp/new-nonce") {
		t.Errorf("NewNonce = %q", dir.NewNonce)
	}
}

func TestACMEHandler_Directory_UnknownProfile(t *testing.T) {
	mock := &mockACMEService{
		BuildDirectoryFn: func(ctx context.Context, profileID, baseURL string) (*acme.Directory, error) {
			return nil, service.ErrACMEProfileNotFound
		},
	}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/acme/profile/missing/directory")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != acme.ProblemContentType {
		t.Errorf("content-type = %q, want %q", got, acme.ProblemContentType)
	}
}

func TestACMEHandler_NewNonce_HEAD(t *testing.T) {
	mock := &mockACMEService{}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodHead, srv.URL+"/acme/profile/prof-corp/new-nonce", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (HEAD)", resp.StatusCode)
	}
	if got := resp.Header.Get("Replay-Nonce"); got != "test-nonce-12345" {
		t.Errorf("Replay-Nonce = %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if resp.ContentLength > 0 {
		t.Errorf("HEAD body should be zero-length; got Content-Length=%d", resp.ContentLength)
	}
}

func TestACMEHandler_NewNonce_GET(t *testing.T) {
	mock := &mockACMEService{}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/acme/profile/prof-corp/new-nonce")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (GET)", resp.StatusCode)
	}
	if got := resp.Header.Get("Replay-Nonce"); got != "test-nonce-12345" {
		t.Errorf("Replay-Nonce = %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
}

func TestACMEHandler_Shorthand_DefaultProfileSet(t *testing.T) {
	// Service-layer mock returns a directory; handler test asserts the
	// /acme/directory shorthand reaches the same handler path as the
	// per-profile directory.
	mock := &mockACMEService{}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/acme/directory")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var dir acme.Directory
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.HasSuffix(dir.NewNonce, "/acme/new-nonce") {
		t.Errorf("NewNonce = %q (shorthand path expected)", dir.NewNonce)
	}
}

func TestACMEHandler_Shorthand_DefaultProfileUnset(t *testing.T) {
	mock := &mockACMEService{
		BuildDirectoryFn: func(ctx context.Context, profileID, baseURL string) (*acme.Directory, error) {
			return nil, service.ErrACMEUserActionRequired
		},
	}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/acme/directory")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != acme.ProblemContentType {
		t.Errorf("content-type = %q, want %q", got, acme.ProblemContentType)
	}
	var p acme.Problem
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.Type != "urn:ietf:params:acme:error:userActionRequired" {
		t.Errorf("Problem.Type = %q", p.Type)
	}
}

func TestACMEHandler_NewNonce_ServiceError(t *testing.T) {
	mock := &mockACMEService{
		IssueNonceFn: func(ctx context.Context) (string, error) {
			return "", errors.New("disk full")
		},
	}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/acme/profile/prof-corp/new-nonce")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != acme.ProblemContentType {
		t.Errorf("content-type = %q", got)
	}
}

// --- Phase 1b — new-account + account update ---------------------------

// stubVerifiedReq returns a VerifiedRequest pre-baked with payload +
// the supplied Account / JWK for handler-level tests that don't go
// through the actual JWS verifier.
func stubVerifiedReq(payload interface{}, account *domain.ACMEAccount, jwk *jose.JSONWebKey) func(ctx context.Context, body []byte, requestURL string, expectNewAccount bool, accountKID func(string) string) (*acme.VerifiedRequest, error) {
	return func(ctx context.Context, body []byte, requestURL string, expectNewAccount bool, accountKID func(string) string) (*acme.VerifiedRequest, error) {
		raw, _ := json.Marshal(payload)
		return &acme.VerifiedRequest{
			Payload:   raw,
			Algorithm: "RS256",
			URL:       requestURL,
			Nonce:     "test-nonce",
			Account:   account,
			JWK:       jwk,
		}, nil
	}
}

func TestACMEHandler_NewAccount_HappyPath_New(t *testing.T) {
	mock := &mockACMEService{
		VerifyJWSFn: stubVerifiedReq(
			acme.NewAccountRequest{Contact: []string{"mailto:a@example.com"}, TermsOfServiceAgreed: true},
			nil, // jwk path → no Account
			&jose.JSONWebKey{},
		),
		NewAccountFn: func(ctx context.Context, profileID string, jwk *jose.JSONWebKey, contact []string, onlyReturnExisting bool, tosAgreed bool) (*domain.ACMEAccount, bool, error) {
			return &domain.ACMEAccount{
				AccountID: "acme-acc-fresh", JWKThumbprint: "thumb-x",
				Contact: contact, Status: domain.ACMEAccountStatusValid, ProfileID: profileID,
			}, true, nil
		},
	}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/acme/profile/prof-corp/new-account", "application/jose+json", bytes.NewReader([]byte("ignored-by-mock")))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
	if got := resp.Header.Get("Replay-Nonce"); got == "" {
		t.Error("Replay-Nonce header missing")
	}
	if got := resp.Header.Get("Location"); !strings.Contains(got, "/account/acme-acc-fresh") {
		t.Errorf("Location = %q (want suffix /account/acme-acc-fresh)", got)
	}
	var body acme.AccountResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "valid" {
		t.Errorf("status = %q", body.Status)
	}
	if !strings.HasSuffix(body.Orders, "/account/acme-acc-fresh/orders") {
		t.Errorf("orders URL = %q", body.Orders)
	}
}

func TestACMEHandler_NewAccount_Idempotent_ExistingReturns200(t *testing.T) {
	mock := &mockACMEService{
		VerifyJWSFn: stubVerifiedReq(acme.NewAccountRequest{}, nil, &jose.JSONWebKey{}),
		NewAccountFn: func(ctx context.Context, profileID string, jwk *jose.JSONWebKey, contact []string, onlyReturnExisting bool, tosAgreed bool) (*domain.ACMEAccount, bool, error) {
			return &domain.ACMEAccount{
				AccountID: "acme-acc-existing", Status: domain.ACMEAccountStatusValid, ProfileID: profileID,
			}, false /*isNew=false*/, nil
		},
	}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/acme/profile/prof-corp/new-account", "application/jose+json", bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (idempotent re-registration)", resp.StatusCode)
	}
}

func TestACMEHandler_NewAccount_OnlyReturnExisting_NoMatch(t *testing.T) {
	mock := &mockACMEService{
		VerifyJWSFn: stubVerifiedReq(acme.NewAccountRequest{OnlyReturnExisting: true}, nil, &jose.JSONWebKey{}),
		NewAccountFn: func(ctx context.Context, profileID string, jwk *jose.JSONWebKey, contact []string, onlyReturnExisting bool, tosAgreed bool) (*domain.ACMEAccount, bool, error) {
			return nil, false, service.ErrACMEAccountDoesNotExist
		},
	}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/acme/profile/prof-corp/new-account", "application/jose+json", bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	var p acme.Problem
	_ = json.NewDecoder(resp.Body).Decode(&p)
	if p.Type != "urn:ietf:params:acme:error:accountDoesNotExist" {
		t.Errorf("Problem.Type = %q", p.Type)
	}
}

func TestACMEHandler_NewAccount_JWSMalformed(t *testing.T) {
	mock := &mockACMEService{
		VerifyJWSFn: func(ctx context.Context, body []byte, requestURL string, expectNewAccount bool, accountKID func(string) string) (*acme.VerifiedRequest, error) {
			return nil, acme.ErrJWSMalformed
		},
	}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/acme/profile/prof-corp/new-account", "application/jose+json", bytes.NewReader([]byte("garbage")))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	var p acme.Problem
	_ = json.NewDecoder(resp.Body).Decode(&p)
	if p.Type != "urn:ietf:params:acme:error:malformed" {
		t.Errorf("Problem.Type = %q", p.Type)
	}
}

func TestACMEHandler_Account_KIDMismatch(t *testing.T) {
	mock := &mockACMEService{
		VerifyJWSFn: stubVerifiedReq(
			acme.AccountUpdateRequest{},
			&domain.ACMEAccount{
				AccountID: "acme-acc-A", Status: domain.ACMEAccountStatusValid, ProfileID: "prof-corp",
			},
			nil,
		),
	}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	// URL claims account B, JWS-verified account is A.
	resp, err := http.Post(srv.URL+"/acme/profile/prof-corp/account/acme-acc-B", "application/jose+json", bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestACMEHandler_Account_Deactivate(t *testing.T) {
	called := false
	mock := &mockACMEService{
		VerifyJWSFn: stubVerifiedReq(
			acme.AccountUpdateRequest{Status: "deactivated"},
			&domain.ACMEAccount{AccountID: "acme-acc-D", Status: domain.ACMEAccountStatusValid, ProfileID: "prof-corp"},
			nil,
		),
		DeactivateAccountFn: func(ctx context.Context, accountID string) (*domain.ACMEAccount, error) {
			called = true
			return &domain.ACMEAccount{AccountID: accountID, Status: domain.ACMEAccountStatusDeactivated, ProfileID: "prof-corp"}, nil
		},
	}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/acme/profile/prof-corp/account/acme-acc-D", "application/jose+json", bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !called {
		t.Error("DeactivateAccount was not invoked")
	}
	var body acme.AccountResponseJSON
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Status != "deactivated" {
		t.Errorf("status = %q", body.Status)
	}
}

func TestACMEHandler_Account_UpdateContact(t *testing.T) {
	mock := &mockACMEService{
		VerifyJWSFn: stubVerifiedReq(
			acme.AccountUpdateRequest{Contact: []string{"mailto:new@example.com"}},
			&domain.ACMEAccount{AccountID: "acme-acc-U", Status: domain.ACMEAccountStatusValid, ProfileID: "prof-corp"},
			nil,
		),
		UpdateAccountFn: func(ctx context.Context, accountID string, contact []string) (*domain.ACMEAccount, error) {
			return &domain.ACMEAccount{AccountID: accountID, Status: domain.ACMEAccountStatusValid, Contact: contact, ProfileID: "prof-corp"}, nil
		},
	}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/acme/profile/prof-corp/account/acme-acc-U", "application/jose+json", bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var body acme.AccountResponseJSON
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if len(body.Contact) != 1 || body.Contact[0] != "mailto:new@example.com" {
		t.Errorf("contact = %v", body.Contact)
	}
}

func TestACMEHandler_Account_PostAsGet(t *testing.T) {
	// Empty payload → POST-as-GET (RFC 8555 §6.3): handler returns
	// the unmodified account row.
	mock := &mockACMEService{
		VerifyJWSFn: stubVerifiedReq(
			struct{}{}, // empty payload
			&domain.ACMEAccount{AccountID: "acme-acc-G", Status: domain.ACMEAccountStatusValid, Contact: []string{"mailto:o@example.com"}, ProfileID: "prof-corp"},
			nil,
		),
	}
	srv := newACMETestServer(t, mock)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/acme/profile/prof-corp/account/acme-acc-G", "application/jose+json", bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (POST-as-GET)", resp.StatusCode)
	}
}
