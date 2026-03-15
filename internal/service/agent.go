package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// AgentService provides business logic for managing and coordinating with agents.
type AgentService struct {
	agentRepo       repository.AgentRepository
	certRepo        repository.CertificateRepository
	jobRepo         repository.JobRepository
	auditService    *AuditService
	issuerRegistry  map[string]IssuerConnector
}

// NewAgentService creates a new agent service.
func NewAgentService(
	agentRepo repository.AgentRepository,
	certRepo repository.CertificateRepository,
	jobRepo repository.JobRepository,
	auditService *AuditService,
	issuerRegistry map[string]IssuerConnector,
) *AgentService {
	return &AgentService{
		agentRepo:      agentRepo,
		certRepo:       certRepo,
		jobRepo:        jobRepo,
		auditService:   auditService,
		issuerRegistry: issuerRegistry,
	}
}

// Register creates a new agent and returns its API key (only once).
func (s *AgentService) Register(ctx context.Context, name string, hostname string) (*domain.Agent, string, error) {
	if name == "" || hostname == "" {
		return nil, "", fmt.Errorf("agent name and hostname are required")
	}

	// Generate API key
	apiKey := generateAPIKey()
	apiKeyHash := hashAPIKey(apiKey)

	now := time.Now()
	agent := &domain.Agent{
		ID:              generateID("agent"),
		Name:            name,
		Hostname:        hostname,
		APIKeyHash:      apiKeyHash,
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now,
		LastHeartbeatAt: &now,
	}

	if err := s.agentRepo.Create(ctx, agent); err != nil {
		return nil, "", fmt.Errorf("failed to create agent: %w", err)
	}

	// Record audit event
	if err := s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
		"agent_registered", "agent", agent.ID,
		map[string]interface{}{"name": name, "hostname": hostname}); err != nil {
		fmt.Printf("failed to record audit event: %v\n", err)
	}

	// Return the API key only once; the agent must save it securely
	return agent, apiKey, nil
}

// HeartbeatWithContext updates an agent's last seen time and status.
func (s *AgentService) HeartbeatWithContext(ctx context.Context, agentID string) error {
	agent, err := s.agentRepo.Get(ctx, agentID)
	if err != nil {
		return fmt.Errorf("failed to fetch agent: %w", err)
	}

	// Update heartbeat
	if err := s.agentRepo.UpdateHeartbeat(ctx, agentID); err != nil {
		return fmt.Errorf("failed to update heartbeat: %w", err)
	}

	// Update status if previously offline
	if agent.Status != domain.AgentStatusOnline {
		agent.Status = domain.AgentStatusOnline
		if err := s.agentRepo.Update(ctx, agent); err != nil {
			fmt.Printf("failed to update agent status: %v\n", err)
		}
	}

	return nil
}

// Heartbeat updates agent heartbeat (handler interface method).
func (s *AgentService) Heartbeat(agentID string) error {
	return s.HeartbeatWithContext(context.Background(), agentID)
}

// SubmitCSR validates and processes a Certificate Signing Request from an agent.
func (s *AgentService) SubmitCSR(ctx context.Context, agentID string, certID string, csrPEM []byte) error {
	// Fetch agent
	agent, err := s.agentRepo.Get(ctx, agentID)
	if err != nil {
		return fmt.Errorf("failed to fetch agent: %w", err)
	}

	// Validate CSR format (basic check)
	if len(csrPEM) == 0 {
		return fmt.Errorf("invalid CSR: empty")
	}

	// In production, parse and validate the CSR signature and CN here
	// For now, accept and proceed

	// In a production system, we'd store the CSR in a certificate version or metadata
	// For now, we just validate and accept it

	// Record audit event
	if err := s.auditService.RecordEvent(ctx, agent.ID, domain.ActorTypeAgent,
		"csr_submitted", "certificate", certID,
		map[string]interface{}{"agent_hostname": agent.Hostname}); err != nil {
		fmt.Printf("failed to record audit event: %v\n", err)
	}

	return nil
}

// GetCertificateForAgent returns the latest public certificate material for an agent.
func (s *AgentService) GetCertificateForAgent(ctx context.Context, agentID string, certID string) ([]byte, error) {
	// Fetch agent
	_, err := s.agentRepo.Get(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch agent: %w", err)
	}

	// Get latest version
	versions, err := s.certRepo.ListVersions(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate versions: %w", err)
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no certificate versions found")
	}

	// Return the most recent version (latest CreatedAt timestamp)
	latestVersion := versions[0]
	for _, v := range versions {
		if v.CreatedAt.After(latestVersion.CreatedAt) {
			latestVersion = v
		}
	}

	// Record audit event
	if err := s.auditService.RecordEvent(ctx, agentID, domain.ActorTypeAgent,
		"certificate_retrieved", "certificate", certID,
		map[string]interface{}{"version": latestVersion.SerialNumber}); err != nil {
		fmt.Printf("failed to record audit event: %v\n", err)
	}

	return []byte(latestVersion.PEMChain), nil
}

// GetPendingWork returns deployment jobs assigned to an agent.
func (s *AgentService) GetPendingWork(ctx context.Context, agentID string) ([]*domain.Job, error) {
	// Fetch agent to verify it exists
	_, err := s.agentRepo.Get(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch agent: %w", err)
	}

	// Get all deployment jobs
	jobs, err := s.jobRepo.ListByStatus(ctx, domain.JobStatusPending)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending jobs: %w", err)
	}

	var workForAgent []*domain.Job

	// Filter to only jobs assigned to this agent
	// Note: In this implementation, agents don't filter jobs by assignment
	// All deployment jobs are returned for the agent to process
	for _, job := range jobs {
		if job.Type == domain.JobTypeDeployment {
			workForAgent = append(workForAgent, job)
		}
	}

	return workForAgent, nil
}

// ReportJobStatus updates a job's status based on agent feedback.
func (s *AgentService) ReportJobStatus(ctx context.Context, agentID string, jobID string, status domain.JobStatus, errMsg string) error {
	// Fetch job to verify it exists
	_, err := s.jobRepo.Get(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to fetch job: %w", err)
	}

	// Update job status
	if err := s.jobRepo.UpdateStatus(ctx, jobID, status, errMsg); err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Record audit event
	if err := s.auditService.RecordEvent(ctx, agentID, domain.ActorTypeAgent,
		"job_status_reported", "job", jobID,
		map[string]interface{}{"status": status, "error": errMsg}); err != nil {
		fmt.Printf("failed to record audit event: %v\n", err)
	}

	return nil
}

// MarkStaleAgentsOffline marks agents as offline if they haven't sent a heartbeat
// within the given threshold duration.
func (s *AgentService) MarkStaleAgentsOffline(ctx context.Context, threshold time.Duration) error {
	agents, err := s.agentRepo.List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list agents: %w", err)
	}

	cutoff := time.Now().Add(-threshold)
	for _, agent := range agents {
		if agent.Status == domain.AgentStatusOnline && agent.LastHeartbeatAt != nil && agent.LastHeartbeatAt.Before(cutoff) {
			agent.Status = domain.AgentStatusOffline
			if err := s.agentRepo.Update(ctx, agent); err != nil {
				fmt.Printf("failed to mark agent %s offline: %v\n", agent.ID, err)
				continue
			}
		}
	}
	return nil
}

// GetAgentByAPIKey retrieves an agent by hashed API key.
func (s *AgentService) GetAgentByAPIKey(ctx context.Context, apiKey string) (*domain.Agent, error) {
	apiKeyHash := hashAPIKey(apiKey)
	agent, err := s.agentRepo.GetByAPIKey(ctx, apiKeyHash)
	if err != nil {
		return nil, fmt.Errorf("invalid API key: %w", err)
	}
	return agent, nil
}

// ListAgents returns paginated agents (handler interface method).
func (s *AgentService) ListAgents(page, perPage int) ([]domain.Agent, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	agents, err := s.agentRepo.List(context.Background())
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list agents: %w", err)
	}

	total := int64(len(agents))
	start := (page - 1) * perPage
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + perPage
	if end > int(total) {
		end = int(total)
	}

	var result []domain.Agent
	for _, a := range agents[start:end] {
		if a != nil {
			result = append(result, *a)
		}
	}

	return result, total, nil
}

// GetAgent returns a single agent (handler interface method).
func (s *AgentService) GetAgent(id string) (*domain.Agent, error) {
	return s.agentRepo.Get(context.Background(), id)
}

// RegisterAgent creates and registers a new agent (handler interface method).
func (s *AgentService) RegisterAgent(agent domain.Agent) (*domain.Agent, error) {
	agent.ID = generateID("agent")
	apiKey := generateAPIKey()
	agent.APIKeyHash = hashAPIKey(apiKey)
	agent.Status = domain.AgentStatusOnline
	now := time.Now()
	agent.RegisteredAt = now
	agent.LastHeartbeatAt = &now

	if err := s.agentRepo.Create(context.Background(), &agent); err != nil {
		return nil, fmt.Errorf("failed to register agent: %w", err)
	}
	return &agent, nil
}

// CSRSubmit processes a CSR submission from an agent (handler interface method).
func (s *AgentService) CSRSubmit(agentID string, csrPEM string) (string, error) {
	// For the handler interface, we accept the CSR as a string
	err := s.SubmitCSR(context.Background(), agentID, "", []byte(csrPEM))
	if err != nil {
		return "", err
	}
	// Return the CSR as acknowledgment
	return csrPEM, nil
}

// CertificatePickup retrieves a certificate for an agent (handler interface method).
func (s *AgentService) CertificatePickup(agentID, certID string) (string, error) {
	certPEM, err := s.GetCertificateForAgent(context.Background(), agentID, certID)
	if err != nil {
		return "", err
	}
	return string(certPEM), nil
}

// generateAPIKey creates a random API key for an agent.
func generateAPIKey() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// hashAPIKey hashes an API key using SHA256.
func hashAPIKey(apiKey string) string {
	hash := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(hash[:])
}
