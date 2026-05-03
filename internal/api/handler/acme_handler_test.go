// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/api/acme"
	"github.com/shankar0123/certctl/internal/service"
)

// mockACMEService implements ACMEService for handler-level tests.
// Mirrors the mockSCEPService pattern at scep_handler_test.go (struct
// holding canned responses + an err field per method).
type mockACMEService struct {
	BuildDirectoryFn func(ctx context.Context, profileID, baseURL string) (*acme.Directory, error)
	IssueNonceFn     func(ctx context.Context) (string, error)
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
	mux.HandleFunc("GET /acme/directory", h.Directory)
	mux.HandleFunc("HEAD /acme/new-nonce", h.NewNonce)
	mux.HandleFunc("GET /acme/new-nonce", h.NewNonce)
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
