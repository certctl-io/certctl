package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Audit L-004 (CWE-924) — auth-middleware side of the dual-key rotation
// contract. ParseNamedAPIKeys allows two entries to share a name during
// the overlap window; NewAuthWithNamedKeys must accept either bearer
// token and produce the same UserKey + Admin context value either way.

func TestL004_AuthMiddleware_BothKeysValidate(t *testing.T) {
	mw := NewAuthWithNamedKeys([]NamedAPIKey{
		{Name: "alice", Key: "OLDKEY", Admin: true},
		{Name: "alice", Key: "NEWKEY", Admin: true},
	})

	makeReq := func(token string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		return req
	}

	for _, tok := range []string{"OLDKEY", "NEWKEY"} {
		t.Run("token="+tok, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := GetUser(r.Context()); got != "alice" {
					t.Errorf("UserKey = %q, want alice (rotation must preserve identity across both keys)", got)
				}
				if !IsAdmin(r.Context()) {
					t.Errorf("Admin flag lost — both rotation entries carry admin=true, context must reflect that")
				}
				w.WriteHeader(http.StatusOK)
			}))
			handler.ServeHTTP(rec, makeReq(tok))
			if rec.Code != http.StatusOK {
				t.Fatalf("token %s should validate during rotation overlap; got %d", tok, rec.Code)
			}
		})
	}
}

func TestL004_AuthMiddleware_PostRotationOldKeyRejected(t *testing.T) {
	// Operator has completed the rotation: old key removed from
	// CERTCTL_API_KEYS_NAMED, only new key remains. Old bearer must
	// now fail.
	mw := NewAuthWithNamedKeys([]NamedAPIKey{
		{Name: "alice", Key: "NEWKEY", Admin: true},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
	req.Header.Set("Authorization", "Bearer OLDKEY")
	rec := httptest.NewRecorder()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("OLDKEY post-rotation should be rejected; got %d", rec.Code)
	}
}

func TestL004_AuthMiddleware_DualUserKeyedRateLimit(t *testing.T) {
	// Bundle B's rate limiter keys on the UserKey. Both rotation
	// entries must produce the SAME UserKey value so the per-user
	// bucket stays consistent across the overlap window — otherwise
	// a client rotating its key would get a fresh bucket and bypass
	// the rate limit. Pin the invariant.
	mw := NewAuthWithNamedKeys([]NamedAPIKey{
		{Name: "alice", Key: "OLDKEY", Admin: false},
		{Name: "alice", Key: "NEWKEY", Admin: false},
	})

	captured := []string{}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = append(captured, GetUser(r.Context()))
		w.WriteHeader(http.StatusOK)
	}))

	for _, tok := range []string{"OLDKEY", "NEWKEY"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	if len(captured) != 2 {
		t.Fatalf("expected 2 captured UserKey values, got %d", len(captured))
	}
	if captured[0] != captured[1] {
		t.Errorf("UserKey diverged across rotation: OLDKEY=%q NEWKEY=%q — rate-limit bucket would split",
			captured[0], captured[1])
	}
}
