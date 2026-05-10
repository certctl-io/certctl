package auth

import (
	"context"

	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
)

// PermissionService exposes the canonical permission catalogue. It is
// thin (read-only) because Bundle 1 ships permissions as immutable
// migration-seeded rows; callers cannot define new permissions at
// runtime. Bundle 2 extends the catalogue with auth.session.* and
// auth.oidc.* permissions via a new migration.
type PermissionService struct {
	repo repository.PermissionRepository
}

// NewPermissionService constructs a PermissionService.
func NewPermissionService(repo repository.PermissionRepository) *PermissionService {
	return &PermissionService{repo: repo}
}

// List returns every permission in the catalogue.
func (s *PermissionService) List(ctx context.Context) ([]*authdomain.Permission, error) {
	return s.repo.List(ctx)
}

// GetByName returns the permission with the given canonical name, or
// repository.ErrAuthNotFound if no row matches.
func (s *PermissionService) GetByName(ctx context.Context, name string) (*authdomain.Permission, error) {
	return s.repo.GetByName(ctx, name)
}

// IsRegistered reports whether the named permission exists in the
// canonical catalogue. Cheap in-memory lookup; used by RoleService
// before issuing a DB write to fail-fast on typos.
func (s *PermissionService) IsRegistered(name string) bool {
	return s.repo.IsCanonical(name)
}
