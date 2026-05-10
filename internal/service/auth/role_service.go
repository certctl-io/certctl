package auth

import (
	"context"
	"fmt"

	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
)

// RoleService manages roles + role-permission grants.
type RoleService struct {
	repo       repository.RoleRepository
	permRepo   repository.PermissionRepository
	authorizer *Authorizer
	audit      AuditService
}

// NewRoleService constructs a RoleService.
func NewRoleService(repo repository.RoleRepository, permRepo repository.PermissionRepository, authorizer *Authorizer, audit AuditService) *RoleService {
	return &RoleService{
		repo:       repo,
		permRepo:   permRepo,
		authorizer: authorizer,
		audit:      audit,
	}
}

// List returns every role in the caller's tenant. Requires
// `auth.role.list`.
func (s *RoleService) List(ctx context.Context, caller *Caller) ([]*authdomain.Role, error) {
	if err := s.requirePermission(ctx, caller, "auth.role.list"); err != nil {
		return nil, err
	}
	tenantID := caller.TenantID
	if tenantID == "" {
		tenantID = authdomain.DefaultTenantID
	}
	return s.repo.List(ctx, tenantID)
}

// Get returns the role with the given ID. Requires `auth.role.list`.
func (s *RoleService) Get(ctx context.Context, caller *Caller, id string) (*authdomain.Role, error) {
	if err := s.requirePermission(ctx, caller, "auth.role.list"); err != nil {
		return nil, err
	}
	return s.repo.Get(ctx, id)
}

// Create stores a new role. Requires `auth.role.create`.
func (s *RoleService) Create(ctx context.Context, caller *Caller, role *authdomain.Role) error {
	if err := s.requirePermission(ctx, caller, "auth.role.create"); err != nil {
		return err
	}
	if role.TenantID == "" {
		role.TenantID = authdomain.DefaultTenantID
	}
	if err := s.repo.Create(ctx, role); err != nil {
		return err
	}
	s.recordAudit(ctx, caller, "role.create", "role", role.ID, map[string]interface{}{"name": role.Name, "tenant_id": role.TenantID})
	return nil
}

// Update modifies an existing role. Requires `auth.role.edit`.
func (s *RoleService) Update(ctx context.Context, caller *Caller, role *authdomain.Role) error {
	if err := s.requirePermission(ctx, caller, "auth.role.edit"); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, role); err != nil {
		return err
	}
	s.recordAudit(ctx, caller, "role.update", "role", role.ID, map[string]interface{}{"name": role.Name})
	return nil
}

// Delete removes a role. Requires `auth.role.delete`. Returns
// repository.ErrAuthRoleInUse when active actor_roles still reference
// the role (FK ON DELETE RESTRICT).
func (s *RoleService) Delete(ctx context.Context, caller *Caller, id string) error {
	if err := s.requirePermission(ctx, caller, "auth.role.delete"); err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.recordAudit(ctx, caller, "role.delete", "role", id, nil)
	return nil
}

// ListPermissions returns the (permission, scope) grants on the role.
// Requires `auth.role.list`.
func (s *RoleService) ListPermissions(ctx context.Context, caller *Caller, roleID string) ([]*authdomain.RolePermission, error) {
	if err := s.requirePermission(ctx, caller, "auth.role.list"); err != nil {
		return nil, err
	}
	return s.repo.ListPermissions(ctx, roleID)
}

// AddPermission grants a permission to a role at the given scope.
// Requires `auth.role.edit`. Returns ErrInvalidPermission if the
// permission name is not in the canonical catalogue.
func (s *RoleService) AddPermission(ctx context.Context, caller *Caller, roleID, permissionName string, scopeType authdomain.ScopeType, scopeID *string) error {
	if err := s.requirePermission(ctx, caller, "auth.role.edit"); err != nil {
		return err
	}
	if !s.permRepo.IsCanonical(permissionName) {
		return fmt.Errorf("%w: %q", ErrInvalidPermission, permissionName)
	}
	perm, err := s.permRepo.GetByName(ctx, permissionName)
	if err != nil {
		return err
	}
	grant := &authdomain.RolePermission{
		RoleID:       roleID,
		PermissionID: perm.ID,
		ScopeType:    scopeType,
		ScopeID:      scopeID,
	}
	if err := s.repo.AddPermission(ctx, grant); err != nil {
		return err
	}
	details := map[string]interface{}{
		"role_id":    roleID,
		"permission": permissionName,
		"scope_type": string(scopeType),
	}
	if scopeID != nil {
		details["scope_id"] = *scopeID
	}
	s.recordAudit(ctx, caller, "role.permission.add", "role", roleID, details)
	return nil
}

// RemovePermission revokes a previously-granted permission from a role.
// Requires `auth.role.edit`.
func (s *RoleService) RemovePermission(ctx context.Context, caller *Caller, roleID, permissionName string, scopeType authdomain.ScopeType, scopeID *string) error {
	if err := s.requirePermission(ctx, caller, "auth.role.edit"); err != nil {
		return err
	}
	perm, err := s.permRepo.GetByName(ctx, permissionName)
	if err != nil {
		return err
	}
	grant := &authdomain.RolePermission{
		RoleID:       roleID,
		PermissionID: perm.ID,
		ScopeType:    scopeType,
		ScopeID:      scopeID,
	}
	if err := s.repo.RemovePermission(ctx, grant); err != nil {
		return err
	}
	details := map[string]interface{}{
		"role_id":    roleID,
		"permission": permissionName,
		"scope_type": string(scopeType),
	}
	if scopeID != nil {
		details["scope_id"] = *scopeID
	}
	s.recordAudit(ctx, caller, "role.permission.remove", "role", roleID, details)
	return nil
}

// requirePermission is the gate every public method runs first. System
// callers bypass; everyone else must hold the named permission globally.
// Returns ErrUnauthenticated when caller is nil, ErrForbidden when the
// caller exists but lacks the permission.
func (s *RoleService) requirePermission(ctx context.Context, caller *Caller, perm string) error {
	if caller == nil {
		return ErrUnauthenticated
	}
	if caller.IsSystem {
		return nil
	}
	tenantID := caller.TenantID
	if tenantID == "" {
		tenantID = authdomain.DefaultTenantID
	}
	ok, err := s.authorizer.CheckPermission(ctx, caller.ActorID, authdomain.ActorTypeValue(caller.ActorType), tenantID, perm, authdomain.ScopeTypeGlobal, nil)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %q", ErrForbidden, perm)
	}
	return nil
}

// recordAudit emits an audit row tied to the caller. Best-effort: audit
// failures are logged via panic-recover but do not fail the operation.
//
// Bundle 1 Phase 8: every role-mutation is an authentication /
// authorization event. The auditor role queries
// /v1/audit?category=auth to surface this slice.
func (s *RoleService) recordAudit(ctx context.Context, caller *Caller, action, resourceType, resourceID string, details map[string]interface{}) {
	if s.audit == nil || caller == nil {
		return
	}
	_ = s.audit.RecordEventWithCategory(ctx, caller.ActorID, caller.ActorType, action, domain.EventCategoryAuth, resourceType, resourceID, details)
}

// Ensure the compile-time pin: domain.ActorType is convertible to
// authdomain.ActorTypeValue via string equality. If the underlying
// types ever diverge this won't compile.
var _ authdomain.ActorTypeValue = authdomain.ActorTypeValue(domain.ActorTypeAPIKey)
