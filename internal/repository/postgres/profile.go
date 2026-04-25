package postgres

import (
	"github.com/shankar0123/certctl/internal/repository"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shankar0123/certctl/internal/domain"
)

// ProfileRepository implements repository.CertificateProfileRepository
type ProfileRepository struct {
	db *sql.DB
}

// NewProfileRepository creates a new ProfileRepository
func NewProfileRepository(db *sql.DB) *ProfileRepository {
	return &ProfileRepository{db: db}
}

// List returns all certificate profiles
func (r *ProfileRepository) List(ctx context.Context) ([]*domain.CertificateProfile, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, description, allowed_key_algorithms, max_ttl_seconds,
		       allowed_ekus, required_san_patterns, spiffe_uri_pattern,
		       allow_short_lived, enabled, created_at, updated_at
		FROM certificate_profiles
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query profiles: %w", err)
	}
	defer rows.Close()

	var profiles []*domain.CertificateProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating profile rows: %w", err)
	}

	return profiles, nil
}

// Get retrieves a certificate profile by ID
func (r *ProfileRepository) Get(ctx context.Context, id string) (*domain.CertificateProfile, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, description, allowed_key_algorithms, max_ttl_seconds,
		       allowed_ekus, required_san_patterns, spiffe_uri_pattern,
		       allow_short_lived, enabled, created_at, updated_at
		FROM certificate_profiles
		WHERE id = $1
	`, id)

	p, err := scanProfile(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("profile not found: %w", repository.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to query profile: %w", err)
	}

	return p, nil
}

// Create stores a new certificate profile
func (r *ProfileRepository) Create(ctx context.Context, profile *domain.CertificateProfile) error {
	if profile.ID == "" {
		profile.ID = uuid.New().String()
	}
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = time.Now()
	}
	if profile.UpdatedAt.IsZero() {
		profile.UpdatedAt = time.Now()
	}

	algJSON, err := json.Marshal(profile.AllowedKeyAlgorithms)
	if err != nil {
		return fmt.Errorf("failed to marshal allowed_key_algorithms: %w", err)
	}
	ekuJSON, err := json.Marshal(profile.AllowedEKUs)
	if err != nil {
		return fmt.Errorf("failed to marshal allowed_ekus: %w", err)
	}
	sanJSON, err := json.Marshal(profile.RequiredSANPatterns)
	if err != nil {
		return fmt.Errorf("failed to marshal required_san_patterns: %w", err)
	}

	err = r.db.QueryRowContext(ctx, `
		INSERT INTO certificate_profiles (
			id, name, description, allowed_key_algorithms, max_ttl_seconds,
			allowed_ekus, required_san_patterns, spiffe_uri_pattern,
			allow_short_lived, enabled, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id
	`, profile.ID, profile.Name, profile.Description, algJSON, profile.MaxTTLSeconds,
		ekuJSON, sanJSON, profile.SPIFFEURIPattern,
		profile.AllowShortLived, profile.Enabled, profile.CreatedAt, profile.UpdatedAt).Scan(&profile.ID)

	if err != nil {
		return fmt.Errorf("failed to create profile: %w", err)
	}

	return nil
}

// Update modifies an existing certificate profile
func (r *ProfileRepository) Update(ctx context.Context, profile *domain.CertificateProfile) error {
	profile.UpdatedAt = time.Now()

	algJSON, err := json.Marshal(profile.AllowedKeyAlgorithms)
	if err != nil {
		return fmt.Errorf("failed to marshal allowed_key_algorithms: %w", err)
	}
	ekuJSON, err := json.Marshal(profile.AllowedEKUs)
	if err != nil {
		return fmt.Errorf("failed to marshal allowed_ekus: %w", err)
	}
	sanJSON, err := json.Marshal(profile.RequiredSANPatterns)
	if err != nil {
		return fmt.Errorf("failed to marshal required_san_patterns: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE certificate_profiles SET
			name = $1,
			description = $2,
			allowed_key_algorithms = $3,
			max_ttl_seconds = $4,
			allowed_ekus = $5,
			required_san_patterns = $6,
			spiffe_uri_pattern = $7,
			allow_short_lived = $8,
			enabled = $9,
			updated_at = $10
		WHERE id = $11
	`, profile.Name, profile.Description, algJSON, profile.MaxTTLSeconds,
		ekuJSON, sanJSON, profile.SPIFFEURIPattern,
		profile.AllowShortLived, profile.Enabled, profile.UpdatedAt, profile.ID)

	if err != nil {
		return fmt.Errorf("failed to update profile: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("profile not found: %w", repository.ErrNotFound)
	}

	return nil
}

// Delete removes a certificate profile
func (r *ProfileRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM certificate_profiles WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete profile: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("profile not found: %w", repository.ErrNotFound)
	}

	return nil
}

// scanProfile scans a certificate profile from a row or rows
func scanProfile(scanner interface {
	Scan(...interface{}) error
}) (*domain.CertificateProfile, error) {
	var p domain.CertificateProfile
	var algJSON, ekuJSON, sanJSON []byte

	err := scanner.Scan(
		&p.ID, &p.Name, &p.Description, &algJSON, &p.MaxTTLSeconds,
		&ekuJSON, &sanJSON, &p.SPIFFEURIPattern,
		&p.AllowShortLived, &p.Enabled, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan profile: %w", err)
	}

	if len(algJSON) > 0 {
		if err := json.Unmarshal(algJSON, &p.AllowedKeyAlgorithms); err != nil {
			return nil, fmt.Errorf("failed to unmarshal allowed_key_algorithms: %w", err)
		}
	} else {
		p.AllowedKeyAlgorithms = domain.DefaultKeyAlgorithms()
	}

	if len(ekuJSON) > 0 {
		if err := json.Unmarshal(ekuJSON, &p.AllowedEKUs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal allowed_ekus: %w", err)
		}
	} else {
		p.AllowedEKUs = domain.DefaultEKUs()
	}

	if len(sanJSON) > 0 {
		if err := json.Unmarshal(sanJSON, &p.RequiredSANPatterns); err != nil {
			return nil, fmt.Errorf("failed to unmarshal required_san_patterns: %w", err)
		}
	}

	return &p, nil
}
