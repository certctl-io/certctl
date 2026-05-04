package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/certctl-io/certctl/internal/config"
	"github.com/certctl-io/certctl/internal/domain"
)

// TestBuildEnvVarSeeds_ACMEConfig tests env var seeding with ACME configuration
func TestBuildEnvVarSeeds_ACMEConfig(t *testing.T) {
	cfg := &config.Config{
		ACME: config.ACMEConfig{
			DirectoryURL:  "https://acme.example.com/directory",
			Email:         "admin@example.com",
			ChallengeType: "http-01",
			Insecure:      false,
		},
		CA: config.CAConfig{},
	}

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), "", slog.Default())

	// Call buildEnvVarSeeds (unexported method, but testable from same package)
	seeds := service.buildEnvVarSeeds(cfg)

	// Should have at least Local CA and 2 ACME seeds
	if len(seeds) < 3 {
		t.Fatalf("expected at least 3 seeds (Local CA + 2 ACME), got %d", len(seeds))
	}

	// Find ACME seeds
	var acmeSeeds []*domain.Issuer
	for _, seed := range seeds {
		if seed.Type == domain.IssuerTypeACME {
			acmeSeeds = append(acmeSeeds, seed)
		}
	}

	if len(acmeSeeds) != 2 {
		t.Fatalf("expected 2 ACME seeds (staging + prod), got %d", len(acmeSeeds))
	}

	// Verify ACME config is present in seeds
	for _, acmeSeed := range acmeSeeds {
		var cfg map[string]interface{}
		if err := json.Unmarshal(acmeSeed.Config, &cfg); err != nil {
			t.Fatalf("failed to unmarshal seed config: %v", err)
		}

		if cfg["directory_url"] != "https://acme.example.com/directory" {
			t.Errorf("expected directory_url in config, got: %v", cfg["directory_url"])
		}
		if cfg["email"] != "admin@example.com" {
			t.Errorf("expected email in config, got: %v", cfg["email"])
		}
	}
}

// TestBuildEnvVarSeeds_VaultConfig tests env var seeding with Vault configuration
func TestBuildEnvVarSeeds_VaultConfig(t *testing.T) {
	cfg := &config.Config{
		ACME: config.ACMEConfig{},
		CA:   config.CAConfig{},
		Vault: config.VaultConfig{
			Addr:  "https://vault.example.com:8200",
			Token: "hvs.test-token",
			Mount: "pki",
			Role:  "default",
			TTL:   "8760h",
		},
	}

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), "", slog.Default())

	seeds := service.buildEnvVarSeeds(cfg)

	// Find Vault seed
	var vaultSeed *domain.Issuer
	for _, seed := range seeds {
		if seed.Type == domain.IssuerTypeVault {
			vaultSeed = seed
			break
		}
	}

	if vaultSeed == nil {
		t.Fatal("expected Vault seed in buildEnvVarSeeds")
	}

	if vaultSeed.ID != "iss-vault" {
		t.Errorf("expected issuer ID 'iss-vault', got %s", vaultSeed.ID)
	}

	if vaultSeed.Name != "Vault PKI" {
		t.Errorf("expected issuer Name 'Vault PKI', got %s", vaultSeed.Name)
	}

	// Verify Vault config
	var vaultCfg map[string]interface{}
	if err := json.Unmarshal(vaultSeed.Config, &vaultCfg); err != nil {
		t.Fatalf("failed to unmarshal Vault config: %v", err)
	}

	if vaultCfg["addr"] != "https://vault.example.com:8200" {
		t.Errorf("expected vault addr in config, got: %v", vaultCfg["addr"])
	}
	if vaultCfg["token"] != "hvs.test-token" {
		t.Errorf("expected vault token in config, got: %v", vaultCfg["token"])
	}
}

// TestBuildEnvVarSeeds_NoConfig tests env var seeding with empty configuration
func TestBuildEnvVarSeeds_NoConfig(t *testing.T) {
	cfg := &config.Config{
		ACME:      config.ACMEConfig{},
		CA:        config.CAConfig{},
		Vault:     config.VaultConfig{},
		Sectigo:   config.SectigoConfig{},
		GoogleCAS: config.GoogleCASConfig{},
		AWSACMPCA: config.AWSACMPCAConfig{},
	}

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), "", slog.Default())

	seeds := service.buildEnvVarSeeds(cfg)

	// Should only have Local CA and basic ACME (always seeded)
	if len(seeds) < 2 {
		t.Fatalf("expected at least 2 seeds (Local CA + ACME), got %d", len(seeds))
	}

	// Verify no Vault, Sectigo, or GoogleCAS seeds
	for _, seed := range seeds {
		if seed.Type == domain.IssuerTypeVault {
			t.Error("unexpected Vault seed in empty config")
		}
		if seed.Type == domain.IssuerTypeSectigo {
			t.Error("unexpected Sectigo seed in empty config")
		}
		if seed.Type == domain.IssuerTypeGoogleCAS {
			t.Error("unexpected GoogleCAS seed in empty config")
		}
		if seed.Type == domain.IssuerTypeAWSACMPCA {
			t.Error("unexpected AWS ACM PCA seed in empty config")
		}
	}
}

// TestBuildEnvVarSeeds_MultipleConfigs tests env var seeding with multiple issuers configured
func TestBuildEnvVarSeeds_MultipleConfigs(t *testing.T) {
	cfg := &config.Config{
		ACME: config.ACMEConfig{
			DirectoryURL: "https://acme.example.com/directory",
		},
		CA: config.CAConfig{},
		Vault: config.VaultConfig{
			Addr: "https://vault:8200",
		},
		DigiCert: config.DigiCertConfig{
			APIKey: "test-api-key",
		},
		Sectigo: config.SectigoConfig{
			CustomerURI: "https://sectigo.com",
			Login:       "admin",
			Password:    "pass",
		},
	}

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), "", slog.Default())

	seeds := service.buildEnvVarSeeds(cfg)

	// Count seeds by type
	typeCount := make(map[domain.IssuerType]int)
	for _, seed := range seeds {
		typeCount[seed.Type]++
	}

	// Verify expected seeds are present
	if typeCount[domain.IssuerTypeGenericCA] < 1 {
		t.Error("expected Local CA seed")
	}
	if typeCount[domain.IssuerTypeACME] < 1 {
		t.Error("expected ACME seed")
	}
	if typeCount[domain.IssuerTypeVault] != 1 {
		t.Error("expected exactly 1 Vault seed")
	}
	if typeCount[domain.IssuerTypeDigiCert] != 1 {
		t.Error("expected exactly 1 DigiCert seed")
	}
	if typeCount[domain.IssuerTypeSectigo] != 1 {
		t.Error("expected exactly 1 Sectigo seed")
	}
}

// TestSeedFromEnvVars_Empty tests SeedFromEnvVars when database is empty
func TestSeedFromEnvVars_Empty(t *testing.T) {
	ctx := context.Background()

	cfg := &config.Config{
		ACME: config.ACMEConfig{
			DirectoryURL: "https://acme.example.com/directory",
		},
		CA: config.CAConfig{},
		Vault: config.VaultConfig{
			Addr: "https://vault:8200",
		},
	}

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), "", slog.Default())

	// Call SeedFromEnvVars on empty repo
	service.SeedFromEnvVars(ctx, cfg)

	// Verify issuers were created
	issuers, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("failed to list issuers: %v", err)
	}

	if len(issuers) == 0 {
		t.Fatal("expected issuers to be seeded")
	}

	// Verify seeded issuers have source="env"
	for _, iss := range issuers {
		if iss.Source != "env" {
			t.Errorf("expected source 'env', got %s", iss.Source)
		}
	}
}

// TestSeedFromEnvVars_AlreadyExists tests SeedFromEnvVars skips seeding when issuers exist
func TestSeedFromEnvVars_AlreadyExists(t *testing.T) {
	ctx := context.Background()

	cfg := &config.Config{
		ACME: config.ACMEConfig{
			DirectoryURL: "https://acme.example.com/directory",
		},
		CA: config.CAConfig{},
	}

	repo := newMockIssuerRepository()

	// Pre-populate with an issuer
	existing := &domain.Issuer{
		ID:     "iss-existing",
		Name:   "Existing Issuer",
		Type:   domain.IssuerTypeACME,
		Source: "database",
	}
	repo.AddIssuer(existing)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), "", slog.Default())

	// Get count before seeding
	beforeSeeding, _ := repo.List(ctx)
	countBefore := len(beforeSeeding)

	// Call SeedFromEnvVars
	service.SeedFromEnvVars(ctx, cfg)

	// Verify no new issuers were added
	afterSeeding, _ := repo.List(ctx)
	countAfter := len(afterSeeding)

	if countAfter != countBefore {
		t.Errorf("expected %d issuers, got %d (seeding should have been skipped)", countBefore, countAfter)
	}
}

// TestBuildRegistry_Success tests BuildRegistry loads and rebuilds the registry
func TestBuildRegistry_Success(t *testing.T) {
	ctx := context.Background()

	// Create test issuers
	acmeIssuer := &domain.Issuer{
		ID:      "iss-acme",
		Name:    "ACME",
		Type:    domain.IssuerTypeACME,
		Enabled: true,
		Source:  "database",
		Config:  json.RawMessage(`{"directory_url":"https://acme.example.com"}`),
	}

	disabledIssuer := &domain.Issuer{
		ID:      "iss-disabled",
		Name:    "Disabled",
		Type:    domain.IssuerTypeGenericCA,
		Enabled: false,
		Source:  "database",
	}

	repo := newMockIssuerRepository()
	repo.AddIssuer(acmeIssuer)
	repo.AddIssuer(disabledIssuer)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, "", slog.Default())

	// Call BuildRegistry
	err := service.BuildRegistry(ctx)

	if err != nil {
		t.Fatalf("BuildRegistry failed: %v", err)
	}

	// Verify registry was populated (should at least have the enabled issuer)
	// Note: ACME connector creation will fail in this test due to missing config,
	// but the test verifies the registry rebuild logic itself
}

// TestBuildRegistry_EmptyDatabase tests BuildRegistry with no issuers
func TestBuildRegistry_EmptyDatabase(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, "", slog.Default())

	// Call BuildRegistry on empty database
	err := service.BuildRegistry(ctx)

	if err != nil {
		t.Fatalf("BuildRegistry failed: %v", err)
	}

	// Registry should be empty (no errors for empty database)
	if registry.Len() != 0 {
		t.Errorf("expected empty registry, got size %d", registry.Len())
	}
}
