package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
)

// ActorRoleService grants / revokes roles to actors and exposes the
// effective-permissions query the Phase 3 middleware uses on the hot
// path.
type ActorRoleService struct {
	repo       repository.ActorRoleRepository
	roleRepo   repository.RoleRepository
	authorizer *Authorizer
	audit      AuditService
}

// NewActorRoleService constructs an ActorRoleService.
func NewActorRoleService(
	repo repository.ActorRoleRepository,
	roleRepo repository.RoleRepository,
	authorizer *Authorizer,
	audit AuditService,
) *ActorRoleService {
	return &ActorRoleService{
		repo:       repo,
		roleRepo:   roleRepo,
		authorizer: authorizer,
		audit:      audit,
	}
}

// Grant assigns a role to an actor. Privilege-escalation guard: the
// caller must hold `auth.role.assign` (globally). System callers
// bypass. Reserved actor `actor-demo-anon` is rejected.
func (s *ActorRoleService) Grant(ctx context.Context, caller *Caller, ar *authdomain.ActorRole) error {
	if caller == nil {
		return ErrUnauthenticated
	}
	if !caller.IsSystem {
		ok, err := s.authorizer.HoldsAnyOf(ctx, caller.ActorID, authdomain.ActorTypeValue(caller.ActorType), s.tenantOf(caller), "auth.role.assign")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: auth.role.assign required", ErrSelfRoleAssignment)
		}
	}
	if ar.ActorID == authdomain.DemoAnonActorID {
		return fmt.Errorf("%w: actor-demo-anon is reserved", repository.ErrAuthReservedActor)
	}
	if ar.TenantID == "" {
		ar.TenantID = authdomain.DefaultTenantID
	}
	if err := s.repo.Grant(ctx, ar); err != nil {
		return err
	}
	s.recordAudit(ctx, caller, "actor_role.grant", "actor_role", ar.ID, map[string]interface{}{
		"actor_id":   ar.ActorID,
		"actor_type": string(ar.ActorType),
		"role_id":    ar.RoleID,
	})
	return nil
}

// Revoke removes a previously-granted role from an actor. Same
// privilege guard as Grant: caller needs `auth.role.assign` to mutate
// role membership. Reserved actor `actor-demo-anon` is rejected so the
// demo path stays alive even after a misclick.
func (s *ActorRoleService) Revoke(ctx context.Context, caller *Caller, actorID string, actorType domain.ActorType, roleID string) error {
	if caller == nil {
		return ErrUnauthenticated
	}
	if !caller.IsSystem {
		ok, err := s.authorizer.HoldsAnyOf(ctx, caller.ActorID, authdomain.ActorTypeValue(caller.ActorType), s.tenantOf(caller), "auth.role.assign")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: auth.role.assign required", ErrSelfRoleAssignment)
		}
	}
	if actorID == authdomain.DemoAnonActorID {
		return fmt.Errorf("%w: actor-demo-anon is reserved", repository.ErrAuthReservedActor)
	}
	tenantID := s.tenantOf(caller)
	if err := s.repo.Revoke(ctx, actorID, authdomain.ActorTypeValue(actorType), roleID, tenantID); err != nil {
		return err
	}
	s.recordAudit(ctx, caller, "actor_role.revoke", "actor_role", roleID, map[string]interface{}{
		"actor_id":   actorID,
		"actor_type": string(actorType),
		"role_id":    roleID,
	})
	return nil
}

// ListForActor returns the roles held by the named actor.
func (s *ActorRoleService) ListForActor(ctx context.Context, caller *Caller, actorID string, actorType domain.ActorType) ([]*authdomain.ActorRole, error) {
	if caller == nil {
		return nil, ErrUnauthenticated
	}
	if !caller.IsSystem && caller.ActorID != actorID {
		ok, err := s.authorizer.HoldsAnyOf(ctx, caller.ActorID, authdomain.ActorTypeValue(caller.ActorType), s.tenantOf(caller), "auth.role.list")
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: auth.role.list required to view another actor's roles", ErrForbidden)
		}
	}
	return s.repo.ListByActor(ctx, actorID, authdomain.ActorTypeValue(actorType), s.tenantOf(caller))
}

// EffectivePermissions returns the deduplicated (permission, scope)
// pairs granted to the actor across all roles. Phase 3 middleware
// (auth.RequirePermission) calls this on every gated request via the
// Authorizer; that hot path skips RBAC self-checks. The service-level
// method here is for handler / GUI callers (the /v1/auth/me endpoint).
func (s *ActorRoleService) EffectivePermissions(ctx context.Context, caller *Caller, actorID string, actorType domain.ActorType) ([]repository.EffectivePermission, error) {
	if caller == nil {
		return nil, ErrUnauthenticated
	}
	if !caller.IsSystem && caller.ActorID != actorID {
		ok, err := s.authorizer.HoldsAnyOf(ctx, caller.ActorID, authdomain.ActorTypeValue(caller.ActorType), s.tenantOf(caller), "auth.role.list")
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: auth.role.list required to view another actor's permissions", ErrForbidden)
		}
	}
	return s.repo.EffectivePermissions(ctx, actorID, authdomain.ActorTypeValue(actorType), s.tenantOf(caller))
}

// ListKeys (Bundle 1 Phase 7) returns every actor in the tenant that
// holds at least one role grant. Permission `auth.role.list` is
// required (or the caller must be system). The CLI's `auth keys list`
// + scope-down helper consume this to enumerate the operator-key
// population without a separate /v1/auth/keys-by-name surface.
func (s *ActorRoleService) ListKeys(ctx context.Context, caller *Caller) ([]repository.ActorWithRoles, error) {
	if caller == nil {
		return nil, ErrUnauthenticated
	}
	if !caller.IsSystem {
		ok, err := s.authorizer.HoldsAnyOf(ctx, caller.ActorID, authdomain.ActorTypeValue(caller.ActorType), s.tenantOf(caller), "auth.role.list")
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: auth.role.list required to list keys", ErrForbidden)
		}
	}
	return s.repo.ListDistinctActors(ctx, s.tenantOf(caller))
}

func (s *ActorRoleService) tenantOf(caller *Caller) string {
	if caller != nil && caller.TenantID != "" {
		return caller.TenantID
	}
	return authdomain.DefaultTenantID
}

func (s *ActorRoleService) recordAudit(ctx context.Context, caller *Caller, action, resourceType, resourceID string, details map[string]interface{}) {
	if s.audit == nil || caller == nil {
		return
	}
	// Bundle 1 Phase 8: every actor-role grant/revoke is an
	// authentication / authorization event. The auditor role queries
	// /v1/audit?category=auth to surface this slice without
	// also pulling in cert.* events.
	//
	// Audit 2026-05-10 HIGH-6 partial closure: the audit emit is still
	// best-effort relative to the action transaction (the transactional-
	// leg WithinTx refactor is a v3 follow-on; see
	// cowork/auth-bundles-fixes-2026-05-10/10-high-6-atomic-audit-commit.md).
	// What this commit closes is the *silence* leg — swap the discarded
	// `_ = ...` pattern for an explicit WARN log so a DB hiccup or
	// connection reset between action and audit is observable to the
	// operator instead of going unnoticed (CWE-778).
	if err := s.audit.RecordEventWithCategory(ctx, caller.ActorID, caller.ActorType, action, domain.EventCategoryAuth, resourceType, resourceID, details); err != nil {
		slog.WarnContext(ctx, "audit write failed (action committed; audit row may be missing)",
			"action", action,
			"resource_type", resourceType,
			"resource_id", resourceID,
			"actor_id", caller.ActorID,
			"err", err)
	}
}
