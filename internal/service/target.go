package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/crypto"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// ErrAgentNotFound is returned by [TargetService.CreateTarget] when the caller
// references an agent_id that is empty or does not correspond to a registered
// agent. The handler layer maps this to HTTP 400 via [errors.Is]. See C-002 in
// cowork/certctl-coverage-gap-audit.md — this sentinel replaces a silent
// Postgres FK violation (23503 → HTTP 500) with a deterministic 400.
var ErrAgentNotFound = errors.New("referenced agent does not exist")

// validTargetTypes is the set of allowed target types for validation.
var validTargetTypes = map[domain.TargetType]bool{
	domain.TargetTypeNGINX:             true,
	domain.TargetTypeApache:            true,
	domain.TargetTypeHAProxy:           true,
	domain.TargetTypeF5:                true,
	domain.TargetTypeIIS:               true,
	domain.TargetTypeTraefik:           true,
	domain.TargetTypeCaddy:             true,
	domain.TargetTypeEnvoy:             true,
	domain.TargetTypePostfix:           true,
	domain.TargetTypeDovecot:           true,
	domain.TargetTypeSSH:               true,
	domain.TargetTypeWinCertStore:      true,
	domain.TargetTypeJavaKeystore:      true,
	domain.TargetTypeKubernetesSecrets: true,
}

// isValidTargetType checks if a type string is a known target type.
func isValidTargetType(t domain.TargetType) bool {
	return validTargetTypes[t]
}

// TargetService provides business logic for deployment target management.
//
// The encryptionKey field holds the raw passphrase (not a pre-derived 32-byte
// key). Per-ciphertext salt derivation is performed inside
// [crypto.EncryptIfKeySet] / [crypto.DecryptIfKeySet] on each call. See M-8
// in certctl-audit-report.md.
type TargetService struct {
	targetRepo    repository.TargetRepository
	agentRepo     repository.AgentRepository
	auditService  *AuditService
	encryptionKey string
	logger        *slog.Logger
}

// NewTargetService creates a new target service. The encryptionKey is the raw
// passphrase; it MUST NOT be pre-derived via crypto.DeriveKey (that was the
// v1 behavior, replaced in M-8 with per-ciphertext random salt).
func NewTargetService(
	targetRepo repository.TargetRepository,
	auditService *AuditService,
	agentRepo repository.AgentRepository,
	encryptionKey string,
	logger *slog.Logger,
) *TargetService {
	return &TargetService{
		targetRepo:    targetRepo,
		agentRepo:     agentRepo,
		auditService:  auditService,
		encryptionKey: encryptionKey,
		logger:        logger,
	}
}

// List returns a paginated list of deployment targets.
func (s *TargetService) List(ctx context.Context, page, perPage int) ([]*domain.DeploymentTarget, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	targets, err := s.targetRepo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list targets: %w", err)
	}
	total := int64(len(targets))
	start := (page - 1) * perPage
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + perPage
	if end > int(total) {
		end = int(total)
	}
	return targets[start:end], total, nil
}

// Get retrieves a deployment target by ID.
func (s *TargetService) Get(ctx context.Context, id string) (*domain.DeploymentTarget, error) {
	target, err := s.targetRepo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get target %s: %w", id, err)
	}
	return target, nil
}

// Create validates and stores a new deployment target, encrypting sensitive config.
func (s *TargetService) Create(ctx context.Context, target *domain.DeploymentTarget, actor string) error {
	if target.Name == "" {
		return fmt.Errorf("target name is required")
	}
	if !isValidTargetType(target.Type) {
		return fmt.Errorf("unsupported target type: %s", target.Type)
	}

	if target.ID == "" {
		target.ID = generateID("target")
	}
	now := time.Now()
	if target.CreatedAt.IsZero() {
		target.CreatedAt = now
	}
	if target.UpdatedAt.IsZero() {
		target.UpdatedAt = now
	}
	if target.TestStatus == "" {
		target.TestStatus = "untested"
	}
	if target.Source == "" {
		target.Source = "database"
	}

	// Encrypt the full config and store redacted version in config column
	if len(target.Config) > 0 {
		encrypted, _, err := crypto.EncryptIfKeySet([]byte(target.Config), s.encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt config: %w", err)
		}
		target.EncryptedConfig = encrypted
		target.Config = redactConfigJSON(target.Config)
	}

	if err := s.targetRepo.Create(ctx, target); err != nil {
		return fmt.Errorf("failed to create target: %w", err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "create_target", "target", target.ID, nil); auditErr != nil {
			s.logger.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// Update modifies an existing deployment target. Handles "********" preservation for sensitive fields.
func (s *TargetService) Update(ctx context.Context, id string, target *domain.DeploymentTarget, actor string) error {
	if target.Name == "" {
		return fmt.Errorf("target name is required")
	}

	target.ID = id
	target.UpdatedAt = time.Now()

	// If config contains "********" values, merge with existing decrypted config
	if len(target.Config) > 0 {
		mergedConfig, err := s.mergeRedactedConfig(ctx, id, target.Config)
		if err != nil {
			return fmt.Errorf("failed to merge config: %w", err)
		}

		// Encrypt the merged config
		encrypted, _, encErr := crypto.EncryptIfKeySet(mergedConfig, s.encryptionKey)
		if encErr != nil {
			return fmt.Errorf("failed to encrypt config: %w", encErr)
		}
		target.EncryptedConfig = encrypted
		target.Config = redactConfigJSON(json.RawMessage(mergedConfig))
	}

	if err := s.targetRepo.Update(ctx, target); err != nil {
		return fmt.Errorf("failed to update target %s: %w", id, err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "update_target", "target", id, nil); auditErr != nil {
			s.logger.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// Delete removes a deployment target.
func (s *TargetService) Delete(ctx context.Context, id string, actor string) error {
	if err := s.targetRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete target %s: %w", id, err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "delete_target", "target", id, nil); auditErr != nil {
			s.logger.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// TestConnection tests a target's connectivity by checking the assigned agent's heartbeat status.
// Target connectors run on agents, not on the server, so we can't instantiate a connector here.
// Instead, we verify the agent is online and reachable.
func (s *TargetService) TestConnection(ctx context.Context, id string) error {
	target, err := s.targetRepo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("target not found: %w", err)
	}

	if target.AgentID == "" {
		s.updateTestStatus(ctx, target, "failed")
		return fmt.Errorf("target has no assigned agent")
	}

	agent, err := s.agentRepo.Get(ctx, target.AgentID)
	if err != nil {
		s.updateTestStatus(ctx, target, "failed")
		return fmt.Errorf("assigned agent not found: %w", err)
	}

	// I-004: AgentRepository.Get intentionally surfaces retired rows (the banner
	// + 410 Gone paths need to see them). A test against a retired agent can
	// never succeed — the agent is tombstoned, will never heartbeat again, and
	// any active targets have already been cascade-retired alongside it. Fail
	// fast with an explicit message instead of falling through to the Status /
	// heartbeat checks, which would produce a misleading "agent is Offline" or
	// "heartbeat stale" diagnostic.
	if agent.IsRetired() {
		s.updateTestStatus(ctx, target, "failed")
		return fmt.Errorf("assigned agent %s is retired", agent.ID)
	}

	if agent.Status != domain.AgentStatusOnline {
		s.updateTestStatus(ctx, target, "failed")
		return fmt.Errorf("assigned agent %s is %s (expected Online)", agent.ID, agent.Status)
	}

	// Check heartbeat freshness (agent must have heartbeated within the last 5 minutes)
	if agent.LastHeartbeatAt != nil {
		if time.Since(*agent.LastHeartbeatAt) > 5*time.Minute {
			s.updateTestStatus(ctx, target, "failed")
			return fmt.Errorf("assigned agent %s last heartbeat was %s ago (stale)", agent.ID, time.Since(*agent.LastHeartbeatAt).Round(time.Second))
		}
	}

	s.updateTestStatus(ctx, target, "success")
	return nil
}

// ListTargets returns paginated targets (handler interface method).
func (s *TargetService) ListTargets(ctx context.Context, page, perPage int) ([]domain.DeploymentTarget, int64, error) {
	// Bundle E / Audit L-020: page/perPage are unused; the underlying repo
	// List() does not yet take pagination params. Marked explicitly so
	// ineffassign sees no dead store and future maintainers see the
	// vestigial params rather than a misleading default-applied clamp.
	_ = page
	_ = perPage

	targets, err := s.targetRepo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list targets: %w", err)
	}
	total := int64(len(targets))

	var result []domain.DeploymentTarget
	for _, t := range targets {
		if t != nil {
			result = append(result, *t)
		}
	}

	return result, total, nil
}

// GetTarget returns a single target (handler interface method).
func (s *TargetService) GetTarget(ctx context.Context, id string) (*domain.DeploymentTarget, error) {
	return s.targetRepo.Get(ctx, id)
}

// CreateTarget creates a new target (handler interface method).
func (s *TargetService) CreateTarget(ctx context.Context, target domain.DeploymentTarget) (*domain.DeploymentTarget, error) {
	if !isValidTargetType(target.Type) {
		return nil, fmt.Errorf("unsupported target type: %s", target.Type)
	}

	// C-002: enforce agent_id FK at service layer so we return a clean 400
	// instead of bubbling a Postgres 23503 foreign-key violation out as 500.
	// The schema (migrations/000001 line 104) declares agent_id TEXT NOT NULL
	// with a FK to agents(id); we mirror that contract here for deterministic
	// error mapping.
	if target.AgentID == "" {
		return nil, fmt.Errorf("%w: agent_id is required", ErrAgentNotFound)
	}
	agent, err := s.agentRepo.Get(ctx, target.AgentID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrAgentNotFound, target.AgentID)
	}
	// I-004: refuse to attach new targets to a retired agent. The agent is
	// tombstoned and no deployments would ever succeed against it; letting a
	// row slip past here would immediately be cascade-retired on the next
	// dependency sweep and confuse operators ("why is this brand-new target
	// already retired?"). Treating retired agents as "not found" for creation
	// purposes keeps the error surface tight and matches the default-list
	// contract established by repository.AgentRepository.List.
	if agent.IsRetired() {
		return nil, fmt.Errorf("%w: %s (retired)", ErrAgentNotFound, target.AgentID)
	}

	if target.ID == "" {
		target.ID = generateID("target")
	}
	now := time.Now()
	if target.CreatedAt.IsZero() {
		target.CreatedAt = now
	}
	if target.UpdatedAt.IsZero() {
		target.UpdatedAt = now
	}
	if target.TestStatus == "" {
		target.TestStatus = "untested"
	}
	if target.Source == "" {
		target.Source = "database"
	}
	// GUI-created targets should be enabled by default.
	// Go's bool zero value is false, which overrides the DB default when explicitly inserted.
	if target.Source == "database" && !target.Enabled {
		target.Enabled = true
	}

	// Encrypt config
	if len(target.Config) > 0 {
		encrypted, _, err := crypto.EncryptIfKeySet([]byte(target.Config), s.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt config: %w", err)
		}
		target.EncryptedConfig = encrypted
		target.Config = redactConfigJSON(target.Config)
	}

	if err := s.targetRepo.Create(ctx, &target); err != nil {
		return nil, fmt.Errorf("failed to create target: %w", err)
	}
	return &target, nil
}

// UpdateTarget modifies a target (handler interface method).
func (s *TargetService) UpdateTarget(ctx context.Context, id string, target domain.DeploymentTarget) (*domain.DeploymentTarget, error) {
	target.ID = id
	target.UpdatedAt = time.Now()

	// Merge redacted fields with existing config
	if len(target.Config) > 0 {
		mergedConfig, err := s.mergeRedactedConfig(ctx, id, target.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to merge config: %w", err)
		}

		encrypted, _, encErr := crypto.EncryptIfKeySet(mergedConfig, s.encryptionKey)
		if encErr != nil {
			return nil, fmt.Errorf("failed to encrypt config: %w", encErr)
		}
		target.EncryptedConfig = encrypted
		target.Config = redactConfigJSON(json.RawMessage(mergedConfig))
	}

	if err := s.targetRepo.Update(ctx, &target); err != nil {
		return nil, fmt.Errorf("failed to update target: %w", err)
	}
	return &target, nil
}

// DeleteTarget removes a target (handler interface method).
func (s *TargetService) DeleteTarget(ctx context.Context, id string) error {
	return s.targetRepo.Delete(ctx, id)
}

// --- Internal helpers ---

// getDecryptedConfig returns the decrypted config JSON for a target.
func (s *TargetService) getDecryptedConfig(target *domain.DeploymentTarget) (json.RawMessage, error) {
	if len(target.EncryptedConfig) > 0 {
		decrypted, err := crypto.DecryptIfKeySet(target.EncryptedConfig, s.encryptionKey)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(decrypted), nil
	}
	if len(target.Config) > 0 {
		return target.Config, nil
	}
	return json.RawMessage("{}"), nil
}

// mergeRedactedConfig merges incoming config (which may have "********" values)
// with the existing decrypted config so sensitive fields are preserved.
func (s *TargetService) mergeRedactedConfig(ctx context.Context, id string, incoming json.RawMessage) ([]byte, error) {
	// Parse incoming config
	var incomingMap map[string]interface{}
	if err := json.Unmarshal(incoming, &incomingMap); err != nil {
		s.logger.Warn("mergeRedactedConfig: incoming config is not a JSON object, using as-is", "target", id, "error", err)
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

	// Load existing target to get real values
	existing, err := s.targetRepo.Get(ctx, id)
	if err != nil {
		s.logger.Warn("mergeRedactedConfig: could not load existing target, redacted values will be lost", "target", id, "error", err)
		return incoming, nil
	}

	existingConfig, err := s.getDecryptedConfig(existing)
	if err != nil {
		s.logger.Warn("mergeRedactedConfig: could not decrypt existing config, redacted values will be lost", "target", id, "error", err)
		return incoming, nil
	}

	var existingMap map[string]interface{}
	if err := json.Unmarshal(existingConfig, &existingMap); err != nil {
		s.logger.Warn("mergeRedactedConfig: existing config is not a JSON object, redacted values will be lost", "target", id, "error", err)
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
func (s *TargetService) updateTestStatus(ctx context.Context, target *domain.DeploymentTarget, status string) {
	now := time.Now()
	target.TestStatus = status
	target.LastTestedAt = &now
	target.UpdatedAt = now
	if err := s.targetRepo.Update(ctx, target); err != nil {
		s.logger.Error("failed to update test status", "target", target.ID, "status", status, "error", err)
	}

	// Record audit event for connection test
	if s.auditService != nil {
		action := "target_test_connection_" + status
		details := map[string]interface{}{"target_type": string(target.Type), "result": status, "agent_id": target.AgentID}
		if auditErr := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem, action, "target", target.ID, details); auditErr != nil {
			s.logger.Error("failed to record test connection audit event", "error", auditErr)
		}
	}
}
