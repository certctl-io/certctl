package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	userdomain "github.com/certctl-io/certctl/internal/auth/user/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// UserRepository is the postgres implementation of
// repository.UserRepository (Auth Bundle 2 Phase 2).
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository constructs a UserRepository.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

const userColumns = `id, tenant_id, email, display_name, oidc_subject,
		oidc_provider_id, last_login_at, webauthn_credentials,
		created_at, updated_at`

func scanUser(row interface{ Scan(...interface{}) error }) (*userdomain.User, error) {
	var u userdomain.User
	if err := row.Scan(
		&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.OIDCSubject,
		&u.OIDCProviderID, &u.LastLoginAt, &u.WebAuthnCredentials,
		&u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &u, nil
}

// Get returns one user by id.
func (r *UserRepository) Get(ctx context.Context, id string) (*userdomain.User, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrUserNotFound
		}
		return nil, fmt.Errorf("users get: %w", err)
	}
	return u, nil
}

// GetByOIDCSubject is the Phase 3 hot-path lookup at login time.
// Returns ErrUserNotFound if no row matches the (provider, subject)
// tuple — Phase 3's HandleCallback then creates the row via Create.
func (r *UserRepository) GetByOIDCSubject(ctx context.Context, providerID, subject string) (*userdomain.User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+userColumns+`
		FROM users
		WHERE oidc_provider_id = $1 AND oidc_subject = $2`,
		providerID, subject)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrUserNotFound
		}
		return nil, fmt.Errorf("users get_by_oidc_subject: %w", err)
	}
	return u, nil
}

// Create persists a new user. Translates SQLSTATE 23505 into
// ErrUserDuplicateOIDCSubject (the unique constraint on
// (oidc_provider_id, oidc_subject)).
func (r *UserRepository) Create(ctx context.Context, u *userdomain.User) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (
			id, tenant_id, email, display_name, oidc_subject,
			oidc_provider_id, last_login_at, webauthn_credentials
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		u.ID, u.TenantID, u.Email, u.DisplayName, u.OIDCSubject,
		u.OIDCProviderID, u.LastLoginAt, u.WebAuthnCredentials)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return repository.ErrUserDuplicateOIDCSubject
		}
		return fmt.Errorf("users create: %w", err)
	}
	return nil
}

// Update writes the mutable fields (email, display_name, last_login_at,
// webauthn_credentials) back to the row. Immutable: id, tenant_id,
// oidc_subject, oidc_provider_id, created_at. updated_at = NOW().
func (r *UserRepository) Update(ctx context.Context, u *userdomain.User) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE users SET
			email = $2,
			display_name = $3,
			last_login_at = $4,
			webauthn_credentials = $5,
			updated_at = NOW()
		WHERE id = $1`,
		u.ID, u.Email, u.DisplayName, u.LastLoginAt, u.WebAuthnCredentials)
	if err != nil {
		return fmt.Errorf("users update: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrUserNotFound
	}
	return nil
}

// ListAll returns every user in the tenant, ordered by created_at ASC.
func (r *UserRepository) ListAll(ctx context.Context, tenantID string) ([]*userdomain.User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE tenant_id = $1 ORDER BY created_at ASC`,
		tenantID)
	if err != nil {
		return nil, fmt.Errorf("users list_all: %w", err)
	}
	defer rows.Close()

	var out []*userdomain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("users scan: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
