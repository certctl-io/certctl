package service

import (
	"context"
	"errors"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
)

// mockProfileRepo is a test implementation of CertificateProfileRepository
type mockProfileRepo struct {
	profiles  map[string]*domain.CertificateProfile
	ListErr   error
	GetErr    error
	CreateErr error
	UpdateErr error
	DeleteErr error
}

func newMockProfileRepository() *mockProfileRepo {
	return &mockProfileRepo{
		profiles: make(map[string]*domain.CertificateProfile),
	}
}

func (m *mockProfileRepo) List(ctx context.Context) ([]*domain.CertificateProfile, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var profiles []*domain.CertificateProfile
	for _, p := range m.profiles {
		profiles = append(profiles, p)
	}
	return profiles, nil
}

func (m *mockProfileRepo) Get(ctx context.Context, id string) (*domain.CertificateProfile, error) {
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	p, ok := m.profiles[id]
	if !ok {
		return nil, errNotFound
	}
	return p, nil
}

func (m *mockProfileRepo) Create(ctx context.Context, profile *domain.CertificateProfile) error {
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.profiles[profile.ID] = profile
	return nil
}

func (m *mockProfileRepo) Update(ctx context.Context, profile *domain.CertificateProfile) error {
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.profiles[profile.ID] = profile
	return nil
}

func (m *mockProfileRepo) Delete(ctx context.Context, id string) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.profiles, id)
	return nil
}

func (m *mockProfileRepo) AddProfile(p *domain.CertificateProfile) {
	m.profiles[p.ID] = p
}

// --- ProfileService Tests ---

func TestProfileService_ListProfiles(t *testing.T) {
	repo := newMockProfileRepository()
	repo.AddProfile(&domain.CertificateProfile{ID: "prof-1", Name: "Standard TLS", Enabled: true})
	repo.AddProfile(&domain.CertificateProfile{ID: "prof-2", Name: "Internal mTLS", Enabled: true})

	svc := NewProfileService(repo, nil)
	profiles, total, err := svc.ListProfiles(context.Background(), 1, 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
	if len(profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(profiles))
	}
}

func TestProfileService_ListProfiles_Empty(t *testing.T) {
	repo := newMockProfileRepository()
	svc := NewProfileService(repo, nil)

	profiles, total, err := svc.ListProfiles(context.Background(), 1, 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles, got %d", len(profiles))
	}
}

func TestProfileService_ListProfiles_RepoError(t *testing.T) {
	repo := newMockProfileRepository()
	repo.ListErr = errors.New("db error")
	svc := NewProfileService(repo, nil)

	_, _, err := svc.ListProfiles(context.Background(), 1, 50)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestProfileService_GetProfile(t *testing.T) {
	repo := newMockProfileRepository()
	repo.AddProfile(&domain.CertificateProfile{ID: "prof-1", Name: "Standard TLS"})
	svc := NewProfileService(repo, nil)

	profile, err := svc.GetProfile(context.Background(), "prof-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile.Name != "Standard TLS" {
		t.Errorf("expected 'Standard TLS', got '%s'", profile.Name)
	}
}

func TestProfileService_GetProfile_NotFound(t *testing.T) {
	repo := newMockProfileRepository()
	svc := NewProfileService(repo, nil)

	_, err := svc.GetProfile(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestProfileService_CreateProfile_Defaults(t *testing.T) {
	repo := newMockProfileRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewProfileService(repo, auditSvc)

	profile := domain.CertificateProfile{
		Name:          "New Profile",
		MaxTTLSeconds: 86400,
	}

	created, err := svc.CreateProfile(context.Background(), profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.ID == "" {
		t.Error("expected generated ID, got empty")
	}
	if len(created.AllowedKeyAlgorithms) == 0 {
		t.Error("expected default key algorithms, got empty")
	}
	if len(created.AllowedEKUs) == 0 {
		t.Error("expected default EKUs, got empty")
	}
	if created.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
	// Verify audit event recorded
	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}
}

func TestProfileService_CreateProfile_ValidationErrors(t *testing.T) {
	repo := newMockProfileRepository()
	svc := NewProfileService(repo, nil)

	tests := []struct {
		name    string
		profile domain.CertificateProfile
		errMsg  string
	}{
		{
			name:    "empty name",
			profile: domain.CertificateProfile{},
			errMsg:  "profile name is required",
		},
		{
			name: "name too long",
			profile: domain.CertificateProfile{
				Name: string(make([]byte, 256)),
			},
			errMsg: "exceeds 255 characters",
		},
		{
			name: "invalid key algorithm",
			profile: domain.CertificateProfile{
				Name: "Bad Algo",
				AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
					{Algorithm: "DES", MinSize: 56},
				},
			},
			errMsg: "invalid key algorithm",
		},
		{
			name: "RSA key too small",
			profile: domain.CertificateProfile{
				Name: "Weak RSA",
				AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
					{Algorithm: "RSA", MinSize: 1024},
				},
			},
			errMsg: "RSA minimum key size must be at least 2048",
		},
		{
			name: "ECDSA key too small",
			profile: domain.CertificateProfile{
				Name: "Weak ECDSA",
				AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
					{Algorithm: "ECDSA", MinSize: 128},
				},
			},
			errMsg: "ECDSA minimum key size must be at least 256",
		},
		{
			name: "invalid EKU",
			profile: domain.CertificateProfile{
				Name:        "Bad EKU",
				AllowedEKUs: []string{"invalidEKU"},
			},
			errMsg: "invalid EKU",
		},
		{
			name: "negative TTL",
			profile: domain.CertificateProfile{
				Name:          "Negative TTL",
				MaxTTLSeconds: -1,
			},
			errMsg: "cannot be negative",
		},
		{
			name: "short-lived with long TTL",
			profile: domain.CertificateProfile{
				Name:            "Inconsistent Short-Lived",
				AllowShortLived: true,
				MaxTTLSeconds:   7200,
			},
			errMsg: "short-lived certs must have TTL under 1 hour",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateProfile(context.Background(), tt.profile)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errMsg)
			}
			if !contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestProfileService_CreateProfile_RepoError(t *testing.T) {
	repo := newMockProfileRepository()
	repo.CreateErr = errors.New("db create failed")
	svc := NewProfileService(repo, nil)

	_, err := svc.CreateProfile(context.Background(), domain.CertificateProfile{Name: "Valid"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestProfileService_UpdateProfile(t *testing.T) {
	repo := newMockProfileRepository()
	repo.AddProfile(&domain.CertificateProfile{ID: "prof-1", Name: "Original"})
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewProfileService(repo, auditSvc)

	updated, err := svc.UpdateProfile(context.Background(), "prof-1", domain.CertificateProfile{
		Name:          "Updated",
		MaxTTLSeconds: 43200,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.ID != "prof-1" {
		t.Errorf("expected ID 'prof-1', got '%s'", updated.ID)
	}
	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}
}

func TestProfileService_UpdateProfile_ValidationError(t *testing.T) {
	repo := newMockProfileRepository()
	svc := NewProfileService(repo, nil)

	_, err := svc.UpdateProfile(context.Background(), "prof-1", domain.CertificateProfile{Name: ""})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestProfileService_DeleteProfile(t *testing.T) {
	repo := newMockProfileRepository()
	repo.AddProfile(&domain.CertificateProfile{ID: "prof-1", Name: "To Delete"})
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewProfileService(repo, auditSvc)

	err := svc.DeleteProfile(context.Background(), "prof-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}
}

func TestProfileService_DeleteProfile_RepoError(t *testing.T) {
	repo := newMockProfileRepository()
	repo.DeleteErr = errors.New("db delete failed")
	svc := NewProfileService(repo, nil)

	err := svc.DeleteProfile(context.Background(), "prof-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestProfileService_CreateProfile_ValidShortLived(t *testing.T) {
	repo := newMockProfileRepository()
	svc := NewProfileService(repo, nil)

	// Short-lived with TTL under 1 hour should succeed
	created, err := svc.CreateProfile(context.Background(), domain.CertificateProfile{
		Name:            "CI Ephemeral",
		AllowShortLived: true,
		MaxTTLSeconds:   300, // 5 minutes
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !created.AllowShortLived {
		t.Error("expected AllowShortLived to be true")
	}
}

func TestIsShortLived(t *testing.T) {
	tests := []struct {
		name     string
		profile  domain.CertificateProfile
		expected bool
	}{
		{
			name:     "short-lived with 5 min TTL",
			profile:  domain.CertificateProfile{AllowShortLived: true, MaxTTLSeconds: 300},
			expected: true,
		},
		{
			name:     "short-lived flag false",
			profile:  domain.CertificateProfile{AllowShortLived: false, MaxTTLSeconds: 300},
			expected: false,
		},
		{
			name:     "zero TTL with flag",
			profile:  domain.CertificateProfile{AllowShortLived: true, MaxTTLSeconds: 0},
			expected: false,
		},
		{
			name:     "TTL at 1 hour boundary",
			profile:  domain.CertificateProfile{AllowShortLived: true, MaxTTLSeconds: 3600},
			expected: false,
		},
		{
			name:     "standard long-lived",
			profile:  domain.CertificateProfile{AllowShortLived: false, MaxTTLSeconds: 7776000},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.profile.IsShortLived()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// contains checks if a string contains a substring (helper for test assertions).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
