package handler

// Audit 2026-05-11 A-2 closure — federated-user admin handler test
// surface. Covers the self-deactivate guard, reactivate happy-path /
// idempotent / 404 branches, and the audit-event shape.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	userdomain "github.com/certctl-io/certctl/internal/auth/user/domain"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// stubFullUserRepo is a richer in-memory UserRepository than the one
// in auth_session_oidc_test.go (which always returns ErrUserNotFound
// from Get). The auth-users handler tests need round-trip semantics
// across Get / Update.
type stubFullUserRepo struct {
	rows      map[string]*userdomain.User
	updateErr error
	getErr    error
}

func newStubFullUserRepo() *stubFullUserRepo {
	return &stubFullUserRepo{rows: make(map[string]*userdomain.User)}
}

func (s *stubFullUserRepo) Get(_ context.Context, id string) (*userdomain.User, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	if u, ok := s.rows[id]; ok {
		// Defensive copy — Update path mutates the struct.
		c := *u
		if u.DeactivatedAt != nil {
			t := *u.DeactivatedAt
			c.DeactivatedAt = &t
		}
		return &c, nil
	}
	return nil, repository.ErrUserNotFound
}

func (s *stubFullUserRepo) GetByOIDCSubject(_ context.Context, _, _ string) (*userdomain.User, error) {
	return nil, repository.ErrUserNotFound
}

func (s *stubFullUserRepo) Create(_ context.Context, u *userdomain.User) error {
	s.rows[u.ID] = u
	return nil
}

func (s *stubFullUserRepo) Update(_ context.Context, u *userdomain.User) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	if _, ok := s.rows[u.ID]; !ok {
		return repository.ErrUserNotFound
	}
	// Persist the struct (defensive copy of nullable timestamp).
	c := *u
	if u.DeactivatedAt != nil {
		t := *u.DeactivatedAt
		c.DeactivatedAt = &t
	}
	s.rows[u.ID] = &c
	return nil
}

func (s *stubFullUserRepo) ListAll(_ context.Context, tenantID string) ([]*userdomain.User, error) {
	out := make([]*userdomain.User, 0, len(s.rows))
	for _, u := range s.rows {
		if tenantID == "" || u.TenantID == tenantID {
			out = append(out, u)
		}
	}
	return out, nil
}

// stubRevoker records cascade-revoke calls.
type stubRevoker struct {
	called    bool
	actorID   string
	actorType string
	revokeErr error
}

func (s *stubRevoker) RevokeAllForActor(_ context.Context, actorID, actorType string) error {
	s.called = true
	s.actorID = actorID
	s.actorType = actorType
	return s.revokeErr
}

// stubAuditRecorder collects event actions for assertion.
type stubAuditRecorder struct {
	events []string
	last   map[string]interface{}
}

func (s *stubAuditRecorder) RecordEventWithCategory(_ context.Context, _ string, _ domain.ActorType, action, _, _, _ string, details map[string]interface{}) error {
	s.events = append(s.events, action)
	s.last = details
	return nil
}

func newSeededUser(id string, deactivatedAt *time.Time) *userdomain.User {
	return &userdomain.User{
		ID:                  id,
		TenantID:            "t-default",
		Email:               id + "@example.test",
		DisplayName:         id,
		OIDCSubject:         "sub-" + id,
		OIDCProviderID:      "op-x",
		LastLoginAt:         time.Now().UTC(),
		WebAuthnCredentials: []byte("[]"),
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
		DeactivatedAt:       deactivatedAt,
	}
}

// =============================================================================
// Self-deactivate guard (Audit 2026-05-11 A-2)
// =============================================================================

func TestAuthUsers_Deactivate_RejectsSelfDeactivate(t *testing.T) {
	users := newStubFullUserRepo()
	users.rows["u-admin"] = newSeededUser("u-admin", nil)
	rev := &stubRevoker{}
	audit := &stubAuditRecorder{}
	h := NewAuthUsersHandler(users, rev, audit, "t-default")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/users/u-admin", nil)
	req.SetPathValue("id", "u-admin")
	req = withActor(req, "u-admin", string(domain.ActorTypeUser))
	w := httptest.NewRecorder()
	h.Deactivate(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d; want 409", w.Code)
	}
	// Cascade-revoke must NOT have fired.
	if rev.called {
		t.Error("RevokeAllForActor was called on a self-deactivate; the guard must short-circuit before cascade")
	}
	// Row must still be active.
	row, _ := users.Get(context.Background(), "u-admin")
	if row.DeactivatedAt != nil {
		t.Error("user row was deactivated despite the self-deactivate guard")
	}
	// Audit row must record the rejection.
	found := false
	for _, e := range audit.events {
		if e == "auth.user_deactivate_self_rejected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("audit events missing self-reject marker: %v", audit.events)
	}
}

func TestAuthUsers_Deactivate_OtherUser_HappyPath(t *testing.T) {
	users := newStubFullUserRepo()
	users.rows["u-admin"] = newSeededUser("u-admin", nil)
	users.rows["u-target"] = newSeededUser("u-target", nil)
	rev := &stubRevoker{}
	audit := &stubAuditRecorder{}
	h := NewAuthUsersHandler(users, rev, audit, "t-default")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/users/u-target", nil)
	req.SetPathValue("id", "u-target")
	req = withActor(req, "u-admin", string(domain.ActorTypeUser))
	w := httptest.NewRecorder()
	h.Deactivate(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d; want 204", w.Code)
	}
	if !rev.called || rev.actorID != "u-target" || rev.actorType != string(domain.ActorTypeUser) {
		t.Errorf("cascade-revoke did not fire correctly: called=%v id=%q type=%q",
			rev.called, rev.actorID, rev.actorType)
	}
	row, _ := users.Get(context.Background(), "u-target")
	if row.DeactivatedAt == nil {
		t.Error("user row was not soft-deleted")
	}
}

// =============================================================================
// Reactivate (Audit 2026-05-11 A-2)
// =============================================================================

func TestAuthUsers_Reactivate_HappyPath(t *testing.T) {
	now := time.Now().UTC()
	users := newStubFullUserRepo()
	users.rows["u-target"] = newSeededUser("u-target", &now)
	audit := &stubAuditRecorder{}
	h := NewAuthUsersHandler(users, &stubRevoker{}, audit, "t-default")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/users/u-target/reactivate", nil)
	req.SetPathValue("id", "u-target")
	req = withActor(req, "u-admin", string(domain.ActorTypeUser))
	w := httptest.NewRecorder()
	h.Reactivate(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d; want 204", w.Code)
	}
	row, _ := users.Get(context.Background(), "u-target")
	if row.DeactivatedAt != nil {
		t.Errorf("user row still deactivated after reactivate: %v", row.DeactivatedAt)
	}
	// Audit row.
	if len(audit.events) == 0 || audit.events[len(audit.events)-1] != "auth.user_reactivated" {
		t.Errorf("audit events missing reactivate marker: %v", audit.events)
	}
}

func TestAuthUsers_Reactivate_IdempotentOnActiveUser(t *testing.T) {
	users := newStubFullUserRepo()
	users.rows["u-target"] = newSeededUser("u-target", nil) // already active
	audit := &stubAuditRecorder{}
	h := NewAuthUsersHandler(users, &stubRevoker{}, audit, "t-default")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/users/u-target/reactivate", nil)
	req.SetPathValue("id", "u-target")
	req = withActor(req, "u-admin", string(domain.ActorTypeUser))
	w := httptest.NewRecorder()
	h.Reactivate(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d; want 204", w.Code)
	}
	// Idempotent — no audit event for the no-op.
	for _, e := range audit.events {
		if e == "auth.user_reactivated" {
			t.Errorf("reactivate emitted audit row on an already-active user (no-op should be silent)")
		}
	}
}

func TestAuthUsers_Reactivate_UnknownID(t *testing.T) {
	users := newStubFullUserRepo()
	audit := &stubAuditRecorder{}
	h := NewAuthUsersHandler(users, &stubRevoker{}, audit, "t-default")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/users/u-missing/reactivate", nil)
	req.SetPathValue("id", "u-missing")
	req = withActor(req, "u-admin", string(domain.ActorTypeUser))
	w := httptest.NewRecorder()
	h.Reactivate(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

func TestAuthUsers_Reactivate_MissingID(t *testing.T) {
	h := NewAuthUsersHandler(newStubFullUserRepo(), &stubRevoker{}, &stubAuditRecorder{}, "t-default")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/users//reactivate", nil)
	// Intentionally do not SetPathValue — handler must reject the empty
	// id with 400.
	req = withActor(req, "u-admin", string(domain.ActorTypeUser))
	w := httptest.NewRecorder()
	h.Reactivate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestAuthUsers_Reactivate_UpdateError(t *testing.T) {
	now := time.Now().UTC()
	users := newStubFullUserRepo()
	users.rows["u-target"] = newSeededUser("u-target", &now)
	users.updateErr = errors.New("postgres exploded")
	h := NewAuthUsersHandler(users, &stubRevoker{}, &stubAuditRecorder{}, "t-default")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/users/u-target/reactivate", nil)
	req.SetPathValue("id", "u-target")
	req = withActor(req, "u-admin", string(domain.ActorTypeUser))
	w := httptest.NewRecorder()
	h.Reactivate(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", w.Code)
	}
}
