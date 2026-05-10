package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/certctl-io/certctl/internal/auth/bootstrap"
	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
)

// =============================================================================
// In-memory fakes (copies of the bootstrap-package fakes; the package
// boundary keeps the bootstrap-package tests independent).
// =============================================================================

type stubMinter struct{ created []*authdomain.APIKey }

func (s *stubMinter) Create(_ context.Context, k *authdomain.APIKey) error {
	s.created = append(s.created, k)
	return nil
}
func (s *stubMinter) GetByName(_ context.Context, _ string) (*authdomain.APIKey, error) {
	return nil, nil
}

type stubGranter struct{ calls []*authdomain.ActorRole }

func (s *stubGranter) Grant(_ context.Context, ar *authdomain.ActorRole) error {
	s.calls = append(s.calls, ar)
	return nil
}

type stubAudit struct{ calls []map[string]interface{} }

func (s *stubAudit) RecordEventWithCategory(_ context.Context, _ string, _ domain.ActorType, _ string, _ string, _ string, _ string, details map[string]interface{}) error {
	s.calls = append(s.calls, details)
	return nil
}

type stubKeyStore struct {
	mu   sync.Mutex
	rows []string
}

func (s *stubKeyStore) AddHashed(name, hash string, _ bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, name+":"+hash)
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func newBootstrapHandlerWith(token string, probe bootstrap.AdminExistenceProbe) (BootstrapHandler, *stubMinter, *stubGranter, *stubAudit, *stubKeyStore) {
	strategy := bootstrap.NewEnvTokenStrategy(token, probe)
	minter := &stubMinter{}
	granter := &stubGranter{}
	audit := &stubAudit{}
	store := &stubKeyStore{}
	svc := bootstrap.NewService(strategy, minter, granter, audit, store, sha)
	return NewBootstrapHandler(svc), minter, granter, audit, store
}

// =============================================================================
// Handler tests
// =============================================================================

// TestBootstrapHandler_Mint_ValidTokenReturns201 is the happy path.
// Plaintext key value present in the response body; only the hash is
// persisted via the minter.
func TestBootstrapHandler_Mint_ValidTokenReturns201(t *testing.T) {
	h, minter, granter, audit, store := newBootstrapHandlerWith("the-token", nil)

	body, _ := json.Marshal(map[string]string{"token": "the-token", "actor_name": "first-admin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Mint(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp bootstrapResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ActorID != "first-admin" {
		t.Errorf("actor_id = %q, want first-admin", resp.ActorID)
	}
	if resp.KeyValue == "" {
		t.Errorf("key_value missing from response")
	}
	if len(minter.created) != 1 || len(granter.calls) != 1 || len(audit.calls) != 1 || len(store.rows) != 1 {
		t.Errorf("side effects mismatch: minter=%d grants=%d audit=%d keystore=%d",
			len(minter.created), len(granter.calls), len(audit.calls), len(store.rows))
	}
}

// TestBootstrapHandler_Mint_WrongToken_401 pins the wrong-token mapping.
func TestBootstrapHandler_Mint_WrongToken_401(t *testing.T) {
	h, _, _, _, _ := newBootstrapHandlerWith("the-token", nil)
	body, _ := json.Marshal(map[string]string{"token": "wrong", "actor_name": "first-admin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Mint(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestBootstrapHandler_Mint_TwiceReturns410 pins the one-shot
// invariant. Second call after a successful first call returns 410
// Gone, NOT 401 (which would suggest "wrong token, retry").
func TestBootstrapHandler_Mint_TwiceReturns410(t *testing.T) {
	h, _, _, _, _ := newBootstrapHandlerWith("the-token", nil)

	body, _ := json.Marshal(map[string]string{"token": "the-token", "actor_name": "first-admin"})
	rec1 := httptest.NewRecorder()
	h.Mint(rec1, httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body)))
	if rec1.Code != http.StatusCreated {
		t.Fatalf("first call status = %d, want 201", rec1.Code)
	}
	rec2 := httptest.NewRecorder()
	h.Mint(rec2, httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body)))
	if rec2.Code != http.StatusGone {
		t.Errorf("second call status = %d, want 410 Gone", rec2.Code)
	}
}

// TestBootstrapHandler_Mint_AdminExists410 pins that the admin-
// existence probe gates the endpoint. Operator forgets to unset
// CERTCTL_BOOTSTRAP_TOKEN after onboarding → endpoint stays 410.
func TestBootstrapHandler_Mint_AdminExists410(t *testing.T) {
	probe := func(_ context.Context) (bool, error) { return true, nil }
	h, _, _, _, _ := newBootstrapHandlerWith("the-token", probe)

	body, _ := json.Marshal(map[string]string{"token": "the-token", "actor_name": "first-admin"})
	rec := httptest.NewRecorder()
	h.Mint(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body)))
	if rec.Code != http.StatusGone {
		t.Errorf("status = %d, want 410 Gone (admin already exists)", rec.Code)
	}
}

// TestBootstrapHandler_Mint_NoTokenConfigured410 pins that an unset
// CERTCTL_BOOTSTRAP_TOKEN closes the path (410), matching the
// "endpoint disabled" semantics the prompt requires.
func TestBootstrapHandler_Mint_NoTokenConfigured410(t *testing.T) {
	h, _, _, _, _ := newBootstrapHandlerWith("", nil)

	body, _ := json.Marshal(map[string]string{"token": "anything", "actor_name": "first-admin"})
	rec := httptest.NewRecorder()
	h.Mint(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body)))
	if rec.Code != http.StatusGone {
		t.Errorf("status = %d, want 410 Gone (no token configured)", rec.Code)
	}
}

// TestBootstrapHandler_Mint_BadActorName_400 pins the actor-name
// validation surface (charset, length).
func TestBootstrapHandler_Mint_BadActorName_400(t *testing.T) {
	h, _, _, _, _ := newBootstrapHandlerWith("the-token", nil)
	cases := []string{"", "AB", "has space", "Has-Caps"}
	for _, name := range cases {
		body, _ := json.Marshal(map[string]string{"token": "the-token", "actor_name": name})
		rec := httptest.NewRecorder()
		// Each request consumes the strategy on success so we rebuild
		// per case.
		h2, _, _, _, _ := newBootstrapHandlerWith("the-token", nil)
		h2.Mint(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("name=%q status = %d, want 400", name, rec.Code)
		}
	}
	_ = h
}

// TestBootstrapHandler_Available_NoTokenSet pins the GET probe shape:
// {available:false} when the token is unset.
func TestBootstrapHandler_Available_NoTokenSet(t *testing.T) {
	h, _, _, _, _ := newBootstrapHandlerWith("", nil)
	rec := httptest.NewRecorder()
	h.Available(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/bootstrap", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp bootstrapAvailableResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Available {
		t.Errorf("available=true with no token, want false")
	}
}

// TestBootstrapHandler_Available_TokenSetNoAdmin returns true.
func TestBootstrapHandler_Available_TokenSetNoAdmin(t *testing.T) {
	probe := func(_ context.Context) (bool, error) { return false, nil }
	h, _, _, _, _ := newBootstrapHandlerWith("the-token", probe)
	rec := httptest.NewRecorder()
	h.Available(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/bootstrap", nil))
	var resp bootstrapAvailableResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if !resp.Available {
		t.Errorf("available=false with token set + no admin, want true")
	}
}

// TestBootstrapHandler_TokenLeakHygiene scans the slog logger output
// after a happy-path mint. The bootstrap token MUST NOT appear in any
// log line. Audit details, app logs, error wrappers — none of them
// can contain the token.
func TestBootstrapHandler_TokenLeakHygiene(t *testing.T) {
	const token = "extremely-secret-bootstrap-token-do-not-leak"

	// Capture every slog write. Tests in this package (and the
	// upstream service package) currently use the global slog
	// default; we redirect it for the duration of this test.
	var logBuf bytes.Buffer
	origLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(origLogger)

	h, _, _, audit, _ := newBootstrapHandlerWith(token, nil)

	body, _ := json.Marshal(map[string]string{"token": token, "actor_name": "first-admin"})
	rec := httptest.NewRecorder()
	h.Mint(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d", rec.Code)
	}

	if strings.Contains(logBuf.String(), token) {
		t.Errorf("bootstrap token leaked into slog output")
	}
	for i, c := range audit.calls {
		blob, _ := json.Marshal(c)
		if strings.Contains(string(blob), token) {
			t.Errorf("bootstrap token leaked into audit details[%d]: %s", i, blob)
		}
	}
	if strings.Contains(rec.Header().Get("Location"), token) {
		t.Errorf("bootstrap token leaked into Location header")
	}
}

// TestBootstrapHandler_Mint_BodyReadCapped guards against a bad-faith
// caller posting a 1MB token field. The handler caps the request body
// at 4KB; a 5KB body should fail to decode.
func TestBootstrapHandler_Mint_BodyReadCapped(t *testing.T) {
	h, _, _, _, _ := newBootstrapHandlerWith("t", nil)
	huge := strings.Repeat("a", 5000)
	body := []byte(`{"token":"t","actor_name":"first-admin","filler":"` + huge + `"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	h.Mint(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized body should yield 400, got %d", rec.Code)
	}
}

// keep io reachable (some compiler runs strip unused imports during
// AST refactors; explicit ref guards against that without producing a
// real test side effect).
var _ = io.Discard
