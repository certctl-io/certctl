package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/config"
	"github.com/shankar0123/certctl/internal/connector/issuerfactory"
	"github.com/shankar0123/certctl/internal/crypto"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// IssuerService provides business logic for certificate issuer management.
//
// The encryptionKey field holds the raw passphrase (not a pre-derived 32-byte
// key). Per-ciphertext salt derivation is performed inside
// [crypto.EncryptIfKeySet] / [crypto.DecryptIfKeySet] on each call. See M-8
// in certctl-audit-report.md.
type IssuerService struct {
	issuerRepo    repository.IssuerRepository
	auditService  *AuditService
	registry      *IssuerRegistry
	encryptionKey string
	logger        *slog.Logger
}

// NewIssuerService creates a new issuer service. The encryptionKey is the raw
// passphrase; it MUST NOT be pre-derived via crypto.DeriveKey (that was the
// v1 behavior, replaced in M-8 with per-ciphertext random salt).
func NewIssuerService(
	issuerRepo repository.IssuerRepository,
	auditService *AuditService,
	registry *IssuerRegistry,
	encryptionKey string,
	logger *slog.Logger,
) *IssuerService {
	return &IssuerService{
		issuerRepo:    issuerRepo,
		auditService:  auditService,
		registry:      registry,
		encryptionKey: encryptionKey,
		logger:        logger,
	}
}

// GetRegistry returns the dynamic issuer registry.
func (s *IssuerService) GetRegistry() *IssuerRegistry {
	return s.registry
}

// List returns a paginated list of issuers.
func (s *IssuerService) List(ctx context.Context, page, perPage int) ([]*domain.Issuer, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	issuers, err := s.issuerRepo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list issuers: %w", err)
	}
	total := int64(len(issuers))
	start := (page - 1) * perPage
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + perPage
	if end > int(total) {
		end = int(total)
	}
	return issuers[start:end], total, nil
}

// Get retrieves an issuer by ID.
func (s *IssuerService) Get(ctx context.Context, id string) (*domain.Issuer, error) {
	issuer, err := s.issuerRepo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer %s: %w", id, err)
	}
	return issuer, nil
}

// validIssuerTypes is the set of allowed issuer types for validation.
var validIssuerTypes = map[domain.IssuerType]bool{
	domain.IssuerTypeACME:       true,
	domain.IssuerTypeGenericCA:  true,
	domain.IssuerTypeStepCA:     true,
	domain.IssuerTypeOpenSSL:    true,
	domain.IssuerTypeVault:      true,
	domain.IssuerTypeDigiCert:   true,
	domain.IssuerTypeSectigo:    true,
	domain.IssuerTypeGoogleCAS:  true,
	domain.IssuerTypeAWSACMPCA:  true,
	domain.IssuerTypeEntrust:    true,
	domain.IssuerTypeGlobalSign: true,
	domain.IssuerTypeEJBCA:      true,
}

// issuerTypeAliases maps lowercase and legacy type strings to their canonical
// domain.IssuerType constants. This allows older frontends and curl users to
// send case-insensitive type strings (e.g., "acme" instead of "ACME").
var issuerTypeAliases = map[string]domain.IssuerType{
	"acme":       domain.IssuerTypeACME,
	"local":      domain.IssuerTypeGenericCA,
	"local_ca":   domain.IssuerTypeGenericCA,
	"genericca":  domain.IssuerTypeGenericCA,
	"stepca":     domain.IssuerTypeStepCA,
	"openssl":    domain.IssuerTypeOpenSSL,
	"vaultpki":   domain.IssuerTypeVault,
	"digicert":   domain.IssuerTypeDigiCert,
	"sectigo":    domain.IssuerTypeSectigo,
	"googlecas":  domain.IssuerTypeGoogleCAS,
	"awsacmpca":  domain.IssuerTypeAWSACMPCA,
	"entrust":    domain.IssuerTypeEntrust,
	"globalsign": domain.IssuerTypeGlobalSign,
	"ejbca":      domain.IssuerTypeEJBCA,
}

// normalizeIssuerType maps a raw type string to its canonical domain.IssuerType.
// It first checks exact match in validIssuerTypes (fast path for correctly-cased
// input), then falls back to case-insensitive alias lookup.
func normalizeIssuerType(t domain.IssuerType) domain.IssuerType {
	// Fast path: already canonical
	if validIssuerTypes[t] {
		return t
	}
	// Slow path: case-insensitive lookup
	if canonical, ok := issuerTypeAliases[strings.ToLower(string(t))]; ok {
		return canonical
	}
	return t // Return as-is; validation will reject it
}

// isValidIssuerType checks if a type string is a known issuer type.
func isValidIssuerType(t domain.IssuerType) bool {
	return validIssuerTypes[t]
}

// Create validates and stores a new issuer, encrypting sensitive config.
func (s *IssuerService) Create(ctx context.Context, iss *domain.Issuer, actor string) error {
	if iss.Name == "" {
		return fmt.Errorf("issuer name is required")
	}
	iss.Type = normalizeIssuerType(iss.Type)
	if !isValidIssuerType(iss.Type) {
		return fmt.Errorf("unsupported issuer type: %s", iss.Type)
	}

	if iss.ID == "" {
		iss.ID = generateID("issuer")
	}
	now := time.Now()
	if iss.CreatedAt.IsZero() {
		iss.CreatedAt = now
	}
	if iss.UpdatedAt.IsZero() {
		iss.UpdatedAt = now
	}
	if iss.TestStatus == "" {
		iss.TestStatus = "untested"
	}
	if iss.Source == "" {
		iss.Source = "database"
	}

	// Encrypt the full config and store redacted version in config column
	if len(iss.Config) > 0 {
		encrypted, _, err := crypto.EncryptIfKeySet([]byte(iss.Config), s.encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt config: %w", err)
		}
		iss.EncryptedConfig = encrypted
		iss.Config = redactConfigJSON(iss.Config)
	}

	if err := s.issuerRepo.Create(ctx, iss); err != nil {
		return fmt.Errorf("failed to create issuer: %w", err)
	}

	// Add to dynamic registry
	if iss.Enabled {
		s.rebuildRegistryQuiet(ctx)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "create_issuer", "issuer", iss.ID, nil); auditErr != nil {
			s.logger.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// Update modifies an existing issuer. Handles "********" preservation for sensitive fields.
func (s *IssuerService) Update(ctx context.Context, id string, iss *domain.Issuer, actor string) error {
	if iss.Name == "" {
		return fmt.Errorf("issuer name is required")
	}

	iss.ID = id
	iss.UpdatedAt = time.Now()

	// If config contains "********" values, merge with existing decrypted config
	if len(iss.Config) > 0 {
		mergedConfig, err := s.mergeRedactedConfig(ctx, id, iss.Config)
		if err != nil {
			return fmt.Errorf("failed to merge config: %w", err)
		}

		// Encrypt the merged config
		encrypted, _, encErr := crypto.EncryptIfKeySet(mergedConfig, s.encryptionKey)
		if encErr != nil {
			return fmt.Errorf("failed to encrypt config: %w", encErr)
		}
		iss.EncryptedConfig = encrypted
		iss.Config = redactConfigJSON(json.RawMessage(mergedConfig))
	}

	if err := s.issuerRepo.Update(ctx, iss); err != nil {
		return fmt.Errorf("failed to update issuer %s: %w", id, err)
	}

	// Rebuild registry after update
	s.rebuildRegistryQuiet(ctx)

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "update_issuer", "issuer", id, nil); auditErr != nil {
			s.logger.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// Delete removes an issuer.
func (s *IssuerService) Delete(ctx context.Context, id string, actor string) error {
	if err := s.issuerRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete issuer %s: %w", id, err)
	}

	// Remove from registry
	if s.registry != nil {
		s.registry.Remove(id)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "delete_issuer", "issuer", id, nil); auditErr != nil {
			s.logger.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// TestConnectionWithContext tests the connection to an issuer by instantiating a throwaway
// connector and calling ValidateConfig. Records the result in the database.
func (s *IssuerService) TestConnectionWithContext(ctx context.Context, id string) error {
	iss, err := s.issuerRepo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("issuer not found: %w", err)
	}

	// Get the decrypted config
	configJSON, err := s.getDecryptedConfig(iss)
	if err != nil {
		s.updateTestStatus(ctx, iss, "failed")
		return fmt.Errorf("failed to decrypt config: %w", err)
	}

	// Instantiate a throwaway connector and validate
	connector, err := issuerfactory.NewFromConfig(string(iss.Type), configJSON, s.logger)
	if err != nil {
		s.updateTestStatus(ctx, iss, "failed")
		return fmt.Errorf("failed to create connector: %w", err)
	}

	if err := connector.ValidateConfig(ctx, configJSON); err != nil {
		s.updateTestStatus(ctx, iss, "failed")
		return fmt.Errorf("connection test failed: %w", err)
	}

	s.updateTestStatus(ctx, iss, "success")
	return nil
}

// TestConnection verifies the issuer connection (handler interface method).
func (s *IssuerService) TestConnection(id string) error {
	return s.TestConnectionWithContext(context.Background(), id)
}

// BuildRegistry loads all enabled issuers from the database and rebuilds the dynamic registry.
// Called at server startup. Partial failures (individual issuers failing to load) are logged
// as warnings but don't prevent the server from starting.
func (s *IssuerService) BuildRegistry(ctx context.Context) error {
	issuers, err := s.issuerRepo.List(ctx)
	if err != nil {
		return fmt.Errorf("failed to load issuers from database: %w", err)
	}

	if err := s.registry.Rebuild(issuers, s.encryptionKey); err != nil {
		// Log the error but don't fail — some issuers loaded successfully.
		s.logger.Warn("issuer registry rebuilt with errors", "error", err)
	}

	s.logger.Info("issuer registry built from database", "total_issuers", len(issuers), "registry_size", s.registry.Len())
	return nil
}

// SeedFromEnvVars creates issuer records from environment variables if the database is empty.
// Uses ON CONFLICT DO NOTHING so GUI-created configs are never overwritten.
func (s *IssuerService) SeedFromEnvVars(ctx context.Context, cfg *config.Config) {
	// Check if any issuers already exist
	existing, err := s.issuerRepo.List(ctx)
	if err != nil {
		s.logger.Error("failed to check existing issuers for env var seeding", "error", err)
		return
	}

	if len(existing) > 0 {
		s.logger.Info("issuers already exist in database, skipping env var seeding", "count", len(existing))
		return
	}

	s.logger.Info("no issuers in database, seeding from environment variables")

	seeds := s.buildEnvVarSeeds(cfg)
	seeded := 0
	for _, seed := range seeds {
		// Encrypt the config only when an encryption key is configured.
		//
		// Env-seeded issuers carry Source="env" and are reconstructable on every
		// boot from process environment, so persisting their config in plaintext
		// adds no new exposure: the same bytes already live in the operator's
		// deployment manifest. When no key is configured we therefore leave
		// EncryptedConfig nil and keep the raw JSON in the `config` column —
		// IssuerRegistry.Rebuild falls through to `cfg.Config` when there is no
		// ciphertext to decrypt, so registry load still works.
		//
		// Database-sourced rows (Source="database") never reach this branch:
		// they are created through the GUI/API write paths, which require the
		// encryption key and fail closed via crypto.ErrEncryptionKeyRequired.
		if len(seed.Config) > 0 && len(s.encryptionKey) > 0 {
			encrypted, _, encErr := crypto.EncryptIfKeySet([]byte(seed.Config), s.encryptionKey)
			if encErr != nil {
				s.logger.Error("failed to encrypt seed config", "id", seed.ID, "error", encErr)
				continue
			}
			seed.EncryptedConfig = encrypted
			seed.Config = redactConfigJSON(seed.Config)
		}

		if err := s.issuerRepo.Create(ctx, seed); err != nil {
			s.logger.Warn("failed to seed issuer from env var", "id", seed.ID, "error", err)
			continue
		}
		seeded++
		s.logger.Info("seeded issuer from env vars", "id", seed.ID, "type", seed.Type)
	}

	s.logger.Info("env var seeding complete", "seeded", seeded, "total_seeds", len(seeds))
}

// buildEnvVarSeeds constructs issuer domain objects from the config's env var values.
func (s *IssuerService) buildEnvVarSeeds(cfg *config.Config) []*domain.Issuer {
	now := time.Now()
	var seeds []*domain.Issuer

	// Local CA (always seeded)
	seeds = append(seeds, &domain.Issuer{
		ID:        "iss-local",
		Name:      "Local CA",
		Type:      domain.IssuerTypeGenericCA,
		Config:    mustJSON(map[string]interface{}{"ca_cert_path": cfg.CA.CertPath, "ca_key_path": cfg.CA.KeyPath}),
		Enabled:   true,
		Source:    "env",
		CreatedAt: now,
		UpdatedAt: now,
	})

	// ACME (always seeded — even with empty directory URL, for demo mode)
	seeds = append(seeds, &domain.Issuer{
		ID:   "iss-acme-staging",
		Name: "ACME Staging",
		Type: domain.IssuerTypeACME,
		Config: mustJSON(map[string]interface{}{
			"directory_url":  cfg.ACME.DirectoryURL,
			"email":          cfg.ACME.Email,
			"challenge_type": cfg.ACME.ChallengeType,
			"profile":        cfg.ACME.Profile,
			"insecure":       cfg.ACME.Insecure,
			"ari_enabled":    cfg.ACME.ARIEnabled,
		}),
		Enabled:   true,
		Source:    "env",
		CreatedAt: now,
		UpdatedAt: now,
	})

	// ACME prod (same config, different ID for backward compat)
	seeds = append(seeds, &domain.Issuer{
		ID:   "iss-acme-prod",
		Name: "ACME Production",
		Type: domain.IssuerTypeACME,
		Config: mustJSON(map[string]interface{}{
			"directory_url":  cfg.ACME.DirectoryURL,
			"email":          cfg.ACME.Email,
			"challenge_type": cfg.ACME.ChallengeType,
			"profile":        cfg.ACME.Profile,
			"insecure":       cfg.ACME.Insecure,
			"ari_enabled":    cfg.ACME.ARIEnabled,
		}),
		Enabled:   true,
		Source:    "env",
		CreatedAt: now,
		UpdatedAt: now,
	})

	// Conditional: step-ca — only seed if CERTCTL_STEPCA_URL is set
	if stepcaURL := getEnvForSeed("CERTCTL_STEPCA_URL"); stepcaURL != "" {
		seeds = append(seeds, &domain.Issuer{
			ID:   "iss-stepca",
			Name: "step-ca",
			Type: domain.IssuerTypeStepCA,
			Config: mustJSON(map[string]interface{}{
				"ca_url":               stepcaURL,
				"root_cert_path":       getEnvForSeed("CERTCTL_STEPCA_ROOT_CERT"),
				"provisioner_name":     getEnvForSeed("CERTCTL_STEPCA_PROVISIONER"),
				"provisioner_key_path": getEnvForSeed("CERTCTL_STEPCA_KEY_PATH"),
				"provisioner_password": getEnvForSeed("CERTCTL_STEPCA_PASSWORD"),
			}),
			Enabled:   true,
			Source:    "env",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	// Conditional: OpenSSL — only seed if sign script is set
	if signScript := getEnvForSeed("CERTCTL_OPENSSL_SIGN_SCRIPT"); signScript != "" {
		seeds = append(seeds, &domain.Issuer{
			ID:   "iss-openssl",
			Name: "OpenSSL/Custom CA",
			Type: domain.IssuerTypeOpenSSL,
			Config: mustJSON(map[string]interface{}{
				"sign_script":   signScript,
				"revoke_script": getEnvForSeed("CERTCTL_OPENSSL_REVOKE_SCRIPT"),
				"crl_script":    getEnvForSeed("CERTCTL_OPENSSL_CRL_SCRIPT"),
			}),
			Enabled:   true,
			Source:    "env",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	// Conditional: Vault PKI
	if cfg.Vault.Addr != "" {
		seeds = append(seeds, &domain.Issuer{
			ID:   "iss-vault",
			Name: "Vault PKI",
			Type: domain.IssuerTypeVault,
			Config: mustJSON(map[string]interface{}{
				"addr":  cfg.Vault.Addr,
				"token": cfg.Vault.Token,
				"mount": cfg.Vault.Mount,
				"role":  cfg.Vault.Role,
				"ttl":   cfg.Vault.TTL,
			}),
			Enabled:   true,
			Source:    "env",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	// Conditional: DigiCert
	if cfg.DigiCert.APIKey != "" {
		seeds = append(seeds, &domain.Issuer{
			ID:   "iss-digicert",
			Name: "DigiCert CertCentral",
			Type: domain.IssuerTypeDigiCert,
			Config: mustJSON(map[string]interface{}{
				"api_key":      cfg.DigiCert.APIKey,
				"org_id":       cfg.DigiCert.OrgID,
				"product_type": cfg.DigiCert.ProductType,
				"base_url":     cfg.DigiCert.BaseURL,
			}),
			Enabled:   true,
			Source:    "env",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	// Conditional: Sectigo
	if cfg.Sectigo.CustomerURI != "" && cfg.Sectigo.Login != "" && cfg.Sectigo.Password != "" {
		seeds = append(seeds, &domain.Issuer{
			ID:   "iss-sectigo",
			Name: "Sectigo SCM",
			Type: domain.IssuerTypeSectigo,
			Config: mustJSON(map[string]interface{}{
				"customer_uri": cfg.Sectigo.CustomerURI,
				"login":        cfg.Sectigo.Login,
				"password":     cfg.Sectigo.Password,
				"org_id":       cfg.Sectigo.OrgID,
				"cert_type":    cfg.Sectigo.CertType,
				"term":         cfg.Sectigo.Term,
				"base_url":     cfg.Sectigo.BaseURL,
			}),
			Enabled:   true,
			Source:    "env",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	// Conditional: Google CAS
	if cfg.GoogleCAS.Project != "" && cfg.GoogleCAS.Credentials != "" {
		seeds = append(seeds, &domain.Issuer{
			ID:   "iss-googlecas",
			Name: "Google CAS",
			Type: domain.IssuerTypeGoogleCAS,
			Config: mustJSON(map[string]interface{}{
				"project":     cfg.GoogleCAS.Project,
				"location":    cfg.GoogleCAS.Location,
				"ca_pool":     cfg.GoogleCAS.CAPool,
				"credentials": cfg.GoogleCAS.Credentials,
				"ttl":         cfg.GoogleCAS.TTL,
			}),
			Enabled:   true,
			Source:    "env",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	// Conditional: AWS ACM PCA
	if cfg.AWSACMPCA.CAArn != "" {
		seeds = append(seeds, &domain.Issuer{
			ID:   "iss-awsacmpca",
			Name: "AWS ACM Private CA",
			Type: domain.IssuerTypeAWSACMPCA,
			Config: mustJSON(map[string]interface{}{
				"region":            cfg.AWSACMPCA.Region,
				"ca_arn":            cfg.AWSACMPCA.CAArn,
				"signing_algorithm": cfg.AWSACMPCA.SigningAlgorithm,
				"validity_days":     cfg.AWSACMPCA.ValidityDays,
				"template_arn":      cfg.AWSACMPCA.TemplateArn,
			}),
			Enabled:   true,
			Source:    "env",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	// Conditional: Entrust — only seed if API URL is set
	if cfg.Entrust.APIUrl != "" {
		seeds = append(seeds, &domain.Issuer{
			ID:   "iss-entrust",
			Name: "Entrust",
			Type: domain.IssuerTypeEntrust,
			Config: mustJSON(map[string]interface{}{
				"api_url":          cfg.Entrust.APIUrl,
				"client_cert_path": cfg.Entrust.ClientCertPath,
				"client_key_path":  cfg.Entrust.ClientKeyPath,
				"ca_id":            cfg.Entrust.CAId,
				"profile_id":       cfg.Entrust.ProfileId,
			}),
			Enabled:   true,
			Source:    "env",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	// Conditional: GlobalSign — only seed if API URL and API key are set
	if cfg.GlobalSign.APIUrl != "" && cfg.GlobalSign.APIKey != "" {
		globalSignConfig := map[string]interface{}{
			"api_url":          cfg.GlobalSign.APIUrl,
			"api_key":          cfg.GlobalSign.APIKey,
			"api_secret":       cfg.GlobalSign.APISecret,
			"client_cert_path": cfg.GlobalSign.ClientCertPath,
			"client_key_path":  cfg.GlobalSign.ClientKeyPath,
		}
		if cfg.GlobalSign.ServerCAPath != "" {
			globalSignConfig["server_ca_path"] = cfg.GlobalSign.ServerCAPath
		}
		seeds = append(seeds, &domain.Issuer{
			ID:        "iss-globalsign",
			Name:      "GlobalSign Atlas",
			Type:      domain.IssuerTypeGlobalSign,
			Config:    mustJSON(globalSignConfig),
			Enabled:   true,
			Source:    "env",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	// Conditional: EJBCA — only seed if API URL and CA name are set
	if cfg.EJBCA.APIUrl != "" && cfg.EJBCA.CAName != "" {
		seeds = append(seeds, &domain.Issuer{
			ID:   "iss-ejbca",
			Name: "EJBCA",
			Type: domain.IssuerTypeEJBCA,
			Config: mustJSON(map[string]interface{}{
				"api_url":          cfg.EJBCA.APIUrl,
				"auth_mode":        cfg.EJBCA.AuthMode,
				"client_cert_path": cfg.EJBCA.ClientCertPath,
				"client_key_path":  cfg.EJBCA.ClientKeyPath,
				"token":            cfg.EJBCA.Token,
				"ca_name":          cfg.EJBCA.CAName,
				"cert_profile":     cfg.EJBCA.CertProfile,
				"ee_profile":       cfg.EJBCA.EEProfile,
			}),
			Enabled:   true,
			Source:    "env",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	return seeds
}

// ListIssuers returns paginated issuers (handler interface method).
func (s *IssuerService) ListIssuers(page, perPage int) ([]domain.Issuer, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	issuers, err := s.issuerRepo.List(context.Background())
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list issuers: %w", err)
	}
	total := int64(len(issuers))

	var result []domain.Issuer
	for _, i := range issuers {
		if i != nil {
			result = append(result, *i)
		}
	}

	return result, total, nil
}

// GetIssuer returns a single issuer (handler interface method).
func (s *IssuerService) GetIssuer(id string) (*domain.Issuer, error) {
	return s.issuerRepo.Get(context.Background(), id)
}

// CreateIssuer creates a new issuer (handler interface method).
func (s *IssuerService) CreateIssuer(iss domain.Issuer) (*domain.Issuer, error) {
	iss.Type = normalizeIssuerType(iss.Type)
	if !isValidIssuerType(iss.Type) {
		return nil, fmt.Errorf("unsupported issuer type: %s", iss.Type)
	}
	if iss.ID == "" {
		iss.ID = generateID("issuer")
	}
	now := time.Now()
	if iss.CreatedAt.IsZero() {
		iss.CreatedAt = now
	}
	if iss.UpdatedAt.IsZero() {
		iss.UpdatedAt = now
	}
	if iss.TestStatus == "" {
		iss.TestStatus = "untested"
	}
	if iss.Source == "" {
		iss.Source = "database"
	}
	// GUI-created issuers should be enabled by default.
	// Go's bool zero value is false, which overrides the DB default when explicitly inserted.
	if iss.Source == "database" && !iss.Enabled {
		iss.Enabled = true
	}

	// Encrypt config
	if len(iss.Config) > 0 {
		encrypted, _, err := crypto.EncryptIfKeySet([]byte(iss.Config), s.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt config: %w", err)
		}
		iss.EncryptedConfig = encrypted
		iss.Config = redactConfigJSON(iss.Config)
	}

	if err := s.issuerRepo.Create(context.Background(), &iss); err != nil {
		return nil, fmt.Errorf("failed to create issuer: %w", err)
	}

	// Rebuild registry
	if iss.Enabled {
		s.rebuildRegistryQuiet(context.Background())
	}

	return &iss, nil
}

// UpdateIssuer modifies an issuer (handler interface method).
func (s *IssuerService) UpdateIssuer(id string, iss domain.Issuer) (*domain.Issuer, error) {
	iss.ID = id
	iss.UpdatedAt = time.Now()

	// Merge redacted fields with existing config
	if len(iss.Config) > 0 {
		mergedConfig, err := s.mergeRedactedConfig(context.Background(), id, iss.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to merge config: %w", err)
		}

		encrypted, _, encErr := crypto.EncryptIfKeySet(mergedConfig, s.encryptionKey)
		if encErr != nil {
			return nil, fmt.Errorf("failed to encrypt config: %w", encErr)
		}
		iss.EncryptedConfig = encrypted
		iss.Config = redactConfigJSON(json.RawMessage(mergedConfig))
	}

	if err := s.issuerRepo.Update(context.Background(), &iss); err != nil {
		return nil, fmt.Errorf("failed to update issuer: %w", err)
	}

	s.rebuildRegistryQuiet(context.Background())

	return &iss, nil
}

// DeleteIssuer removes an issuer (handler interface method).
func (s *IssuerService) DeleteIssuer(id string) error {
	if err := s.issuerRepo.Delete(context.Background(), id); err != nil {
		return err
	}
	if s.registry != nil {
		s.registry.Remove(id)
	}
	return nil
}

// --- Internal helpers ---

// rebuildRegistryQuiet rebuilds the registry, logging errors instead of returning them.
func (s *IssuerService) rebuildRegistryQuiet(ctx context.Context) {
	if s.registry == nil {
		return
	}
	if err := s.BuildRegistry(ctx); err != nil {
		s.logger.Error("failed to rebuild issuer registry after change", "error", err)
	}
}

// getDecryptedConfig returns the decrypted config JSON for an issuer.
func (s *IssuerService) getDecryptedConfig(iss *domain.Issuer) (json.RawMessage, error) {
	if len(iss.EncryptedConfig) > 0 {
		decrypted, err := crypto.DecryptIfKeySet(iss.EncryptedConfig, s.encryptionKey)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(decrypted), nil
	}
	if len(iss.Config) > 0 {
		return iss.Config, nil
	}
	return json.RawMessage("{}"), nil
}

// mergeRedactedConfig merges incoming config (which may have "********" values)
// with the existing decrypted config so sensitive fields are preserved.
func (s *IssuerService) mergeRedactedConfig(ctx context.Context, id string, incoming json.RawMessage) ([]byte, error) {
	// Parse incoming config
	var incomingMap map[string]interface{}
	if err := json.Unmarshal(incoming, &incomingMap); err != nil {
		s.logger.Warn("mergeRedactedConfig: incoming config is not a JSON object, using as-is", "issuer", id, "error", err)
		return incoming, nil
	}

	// Check if any values are "********"
	hasRedacted := false
	for _, v := range incomingMap {
		if str, ok := v.(string); ok && str == "********" {
			hasRedacted = true
			break
		}
	}

	if !hasRedacted {
		return incoming, nil // No redacted values, use incoming as-is
	}

	// Load existing config to get real values
	existing, err := s.issuerRepo.Get(ctx, id)
	if err != nil {
		s.logger.Warn("mergeRedactedConfig: could not load existing issuer, redacted values will be lost", "issuer", id, "error", err)
		return incoming, nil
	}

	existingConfig, err := s.getDecryptedConfig(existing)
	if err != nil {
		s.logger.Warn("mergeRedactedConfig: could not decrypt existing config, redacted values will be lost", "issuer", id, "error", err)
		return incoming, nil
	}

	var existingMap map[string]interface{}
	if err := json.Unmarshal(existingConfig, &existingMap); err != nil {
		s.logger.Warn("mergeRedactedConfig: existing config is not a JSON object, redacted values will be lost", "issuer", id, "error", err)
		return incoming, nil
	}

	// Merge: for each "********" value in incoming, use existing value
	for k, v := range incomingMap {
		if str, ok := v.(string); ok && str == "********" {
			if existingVal, exists := existingMap[k]; exists {
				incomingMap[k] = existingVal
			}
		}
	}

	return json.Marshal(incomingMap)
}

// updateTestStatus updates the test_status and last_tested_at fields in the database
// and records an audit event.
func (s *IssuerService) updateTestStatus(ctx context.Context, iss *domain.Issuer, status string) {
	now := time.Now()
	iss.TestStatus = status
	iss.LastTestedAt = &now
	iss.UpdatedAt = now
	if err := s.issuerRepo.Update(ctx, iss); err != nil {
		s.logger.Error("failed to update test status", "issuer", iss.ID, "status", status, "error", err)
	}

	// Record audit event for connection test
	if s.auditService != nil {
		action := "issuer_test_connection_" + status
		details := map[string]interface{}{"issuer_type": string(iss.Type), "result": status}
		if auditErr := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem, action, "issuer", iss.ID, details); auditErr != nil {
			s.logger.Error("failed to record test connection audit event", "error", auditErr)
		}
	}
}

// getEnvForSeed reads an environment variable for seed data construction.
func getEnvForSeed(key string) string {
	return os.Getenv(key)
}

// mustJSON marshals a value to json.RawMessage, panicking on error (for seed data only).
func mustJSON(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("mustJSON: %v", err))
	}
	return json.RawMessage(b)
}
