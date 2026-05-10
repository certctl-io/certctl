// Package auth holds the RBAC service layer: PermissionService,
// RoleService, ActorRoleService, and the Authorizer primitive that
// Phase 3 middleware (auth.RequirePermission) calls on every gated
// request.
//
// All mutating operations record an audit event via the existing
// AuditService.RecordEvent path. Bundle 1 Phase 8 introduces an
// `event_category` parameter and back-fills the existing callers; until
// then auth-related events go in with the default category.
//
// Privilege-escalation guard: every mutation that affects role
// assignment requires the caller to hold `auth.role.assign` (or the
// equivalent role-level permission) on the target role. The system
// pathway (bootstrap, migrations, scheduler) bypasses this check via
// AsSystemCaller(), which records `actor=system, actorType=System` in
// the audit row so the bypass is observable.
package auth

import (
	"context"
	"errors"

	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
)

// Sentinel errors for the service layer. Handler / middleware code
// branches via errors.Is and maps to HTTP status codes.
var (
	// ErrForbidden is returned when the caller lacks the required
	// permission for the operation. Maps to HTTP 403.
	ErrForbidden = errors.New("auth: caller lacks required permission")

	// ErrUnauthenticated is returned when the request has no actor in
	// context (no Bearer, no session). Phase 3 RequirePermission emits
	// this; handler code typically returns 401.
	ErrUnauthenticated = errors.New("auth: no actor in context")

	// ErrInvalidPermission is returned when a Create / AddPermission
	// references a permission name not in the canonical catalogue.
	// Maps to HTTP 400.
	ErrInvalidPermission = errors.New("auth: permission not in canonical catalogue")

	// ErrSelfRoleAssignment guards privilege escalation: a caller
	// without `auth.role.assign` on a role cannot grant that role
	// (including to themselves). Maps to HTTP 403.
	ErrSelfRoleAssignment = errors.New("auth: caller lacks auth.role.assign on target role")
)

// AuditService is the audit-recording dependency the service layer
// expects. Mirrors the existing service.AuditService interface so
// Bundle 1 doesn't introduce a parallel concept. Bundle 1 Phase 8
// adds RecordEventWithCategory; the auth service uses the
// categorized variant exclusively (event_category=auth) so the
// auditor role can filter to authentication / authorization events.
type AuditService interface {
	RecordEvent(
		ctx context.Context,
		actor string,
		actorType domain.ActorType,
		action, resourceType, resourceID string,
		details map[string]interface{},
	) error
	RecordEventWithCategory(
		ctx context.Context,
		actor string,
		actorType domain.ActorType,
		action, eventCategory, resourceType, resourceID string,
		details map[string]interface{},
	) error
	// RecordEventWithCategoryWithTx records the audit row using the
	// supplied repository.Querier so it commits atomically with the
	// caller's transaction. Audit 2026-05-10 HIGH-6 closure — closes
	// the gap where auth-mutation paths used a non-transactional audit
	// emit, leaving orphan action rows on partial failure.
	RecordEventWithCategoryWithTx(
		ctx context.Context,
		q repository.Querier,
		actor string,
		actorType domain.ActorType,
		action, eventCategory, resourceType, resourceID string,
		details map[string]interface{},
	) error
}

// Caller describes the actor performing a service operation. Bundle 1
// Phase 3 populates this from the auth-middleware context (ActorIDKey,
// ActorTypeKey). Bootstrap, migrations, and scheduler-initiated work
// pass AsSystemCaller() to bypass the permission check while still
// recording an audit row.
type Caller struct {
	ActorID   string
	ActorType domain.ActorType
	TenantID  string

	// IsSystem skips the privilege-escalation guard. Reserved for
	// bootstrap / migration / scheduler paths.
	IsSystem bool
}

// AsSystemCaller returns a Caller that bypasses RBAC checks. Used by
// the migration backfill, bootstrap path, scheduler-initiated grants,
// and tests that need to seed state without simulating an admin.
func AsSystemCaller() *Caller {
	return &Caller{
		ActorID:   "system",
		ActorType: domain.ActorTypeSystem,
		TenantID:  authdomain.DefaultTenantID,
		IsSystem:  true,
	}
}

// CallerFromContext is a helper that builds a Caller from auth context
// values. Phase 3 middleware populates the keys; tests can use the
// internal/auth.WithActor / WithAdmin helpers to build contexts.
//
// Returns nil + ErrUnauthenticated when no actor is present.
func CallerFromContext(ctx context.Context) (*Caller, error) {
	// Avoid coupling internal/service/auth to internal/auth at the
	// type level: read the keys via package-public helpers exposed by
	// internal/auth (ActorID, ActorType, TenantID). Phase 3 wires
	// these up. For Phase 2, rely on the explicit Caller arg passed
	// by handler / test code instead — direct context-key reads can
	// land in Phase 3 alongside the middleware.
	return nil, ErrUnauthenticated
}
