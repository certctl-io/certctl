package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// AgentService provides business logic for managing and coordinating with agents.
type AgentService struct {
	agentRepo      repository.AgentRepository
	certRepo       repository.CertificateRepository
	jobRepo        repository.JobRepository
	targetRepo     repository.TargetRepository
	auditService   *AuditService
	issuerRegistry map[string]IssuerConnector
	renewalService *RenewalService
}

// NewAgentService creates a new agent service.
func NewAgentService(
	agentRepo repository.AgentRepository,
	certRepo repository.CertificateRepository,
	jobRepo repository.JobRepository,
	targetRepo repository.TargetRepository,
	auditService *AuditService,
	issuerRegistry map[string]IssuerConnector,
	renewalService *RenewalService,
) *AgentService {
	return &AgentService{
		agentRepo:      agentRepo,
		certRepo:       certRepo,
		jobRepo:        jobRepo,
		targetRepo:     targetRepo,
		auditService:   auditService,
		issuerRegistry: issuerRegistry,
		renewalService: renewalService,
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
		slog.Error("failed to record audit event", "error", err)
	}

	// Return the API key only once; the agent must save it securely
	return agent, apiKey, nil
}

// HeartbeatWithContext updates an agent's last seen time, status, and metadata.
func (s *AgentService) HeartbeatWithContext(ctx context.Context, agentID string, metadata *domain.AgentMetadata) error {
	agent, err := s.agentRepo.Get(ctx, agentID)
	if err != nil {
		return fmt.Errorf("failed to fetch agent: %w", err)
	}

	// Update heartbeat and metadata
	if err := s.agentRepo.UpdateHeartbeat(ctx, agentID, metadata); err != nil {
		return fmt.Errorf("failed to update heartbeat: %w", err)
	}

	// Update status if previously offline
	if agent.Status != domain.AgentStatusOnline {
		agent.Status = domain.AgentStatusOnline
		if err := s.agentRepo.Update(ctx, agent); err != nil {
			slog.Error("failed to update agent status", "error", err)
		}
	}

	return nil
}

// Heartbeat updates agent heartbeat (handler interface method).
func (s *AgentService) Heartbeat(agentID string, metadata *domain.AgentMetadata) error {
	return s.HeartbeatWithContext(context.Background(), agentID, metadata)
}

// SubmitCSR validates and processes a Certificate Signing Request from an agent.
// In agent keygen mode, this completes an AwaitingCSR renewal job by signing the CSR
// and storing the cert version. The private key stays on the agent — only the CSR
// (public key) reaches the server.
func (s *AgentService) SubmitCSR(ctx context.Context, agentID string, certID string, csrPEM []byte) error {
	// Fetch agent
	agent, err := s.agentRepo.Get(ctx, agentID)
	if err != nil {
		return fmt.Errorf("failed to fetch agent: %w", err)
	}

	// Validate CSR format
	if len(csrPEM) == 0 {
		return fmt.Errorf("invalid CSR: empty")
	}

	if certID != "" {
		cert, err := s.certRepo.Get(ctx, certID)
		if err != nil {
			return fmt.Errorf("failed to fetch certificate: %w", err)
		}

		// Check for AwaitingCSR jobs first (agent keygen mode)
		if s.renewalService != nil {
			awaitingJobs, err := s.renewalService.GetAwaitingCSRJobs(ctx, certID)
			if err == nil && len(awaitingJobs) > 0 {
				// Complete the renewal via the renewal service (signs CSR, stores version, creates deploy jobs)
				if err := s.renewalService.CompleteAgentCSRRenewal(ctx, awaitingJobs[0], cert, string(csrPEM)); err != nil {
					return fmt.Errorf("failed to complete agent CSR renewal: %w", err)
				}

				// Record audit event
				if auditErr := s.auditService.RecordEvent(ctx, agent.ID, domain.ActorTypeAgent,
					"csr_submitted", "certificate", certID,
					map[string]interface{}{
						"agent_hostname": agent.Hostname,
						"keygen_mode":    "agent",
						"job_id":         awaitingJobs[0].ID,
					}); auditErr != nil {
					slog.Error("failed to record audit event", "error", auditErr)
				}

				return nil
			}
		}

		// Fallback: direct issuer signing (no AwaitingCSR job — ad-hoc CSR submission)
		connector, ok := s.issuerRegistry[cert.IssuerID]
		if ok {
			result, err := connector.IssueCertificate(ctx, cert.CommonName, cert.SANs, string(csrPEM))
			if err != nil {
				return fmt.Errorf("issuer signing failed: %w", err)
			}

			version := &domain.CertificateVersion{
				ID:            generateID("certver"),
				CertificateID: certID,
				SerialNumber:  result.Serial,
				NotBefore:     result.NotBefore,
				NotAfter:      result.NotAfter,
				PEMChain:      result.CertPEM + "\n" + result.ChainPEM,
				CSRPEM:        string(csrPEM),
				CreatedAt:     time.Now(),
			}

			if err := s.certRepo.CreateVersion(ctx, version); err != nil {
				return fmt.Errorf("failed to store certificate version: %w", err)
			}

			cert.Status = domain.CertificateStatusActive
			cert.ExpiresAt = result.NotAfter
			now := time.Now()
			cert.LastRenewalAt = &now
			cert.UpdatedAt = now
			if err := s.certRepo.Update(ctx, cert); err != nil {
				slog.Error("failed to update certificate", "error", err)
			}
		}
	}

	// Record audit event
	if auditErr := s.auditService.RecordEvent(ctx, agent.ID, domain.ActorTypeAgent,
		"csr_submitted", "certificate", certID,
		map[string]interface{}{"agent_hostname": agent.Hostname}); auditErr != nil {
		slog.Error("failed to record audit event", "error", auditErr)
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
		slog.Error("failed to record audit event", "error", err)
	}

	return []byte(latestVersion.PEMChain), nil
}

// GetPendingWork returns actionable jobs for an agent: deployment jobs (Pending) and
// renewal/issuance jobs awaiting CSR submission (AwaitingCSR).
func (s *AgentService) GetPendingWork(ctx context.Context, agentID string) ([]*domain.Job, error) {
	// Fetch agent to verify it exists
	_, err := s.agentRepo.Get(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch agent: %w", err)
	}

	var workForAgent []*domain.Job

	// Get pending deployment jobs
	pendingJobs, err := s.jobRepo.ListByStatus(ctx, domain.JobStatusPending)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending jobs: %w", err)
	}
	for _, job := range pendingJobs {
		if job.Type == domain.JobTypeDeployment {
			workForAgent = append(workForAgent, job)
		}
	}

	// Get AwaitingCSR jobs (agent keygen mode — agent needs to generate key + submit CSR)
	awaitingJobs, err := s.jobRepo.ListByStatus(ctx, domain.JobStatusAwaitingCSR)
	if err != nil {
		return nil, fmt.Errorf("failed to list awaiting CSR jobs: %w", err)
	}
	for _, job := range awaitingJobs {
		if job.Type == domain.JobTypeRenewal || job.Type == domain.JobTypeIssuance {
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
		slog.Error("failed to record audit event", "error", err)
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
				slog.Error("failed to mark agent offline", "agent_id", agent.ID, "error", err)
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
// The csrPEM parameter contains "certID:csrPEM" or just the CSR PEM.
func (s *AgentService) CSRSubmit(agentID string, csrPEM string) (string, error) {
	err := s.SubmitCSR(context.Background(), agentID, "", []byte(csrPEM))
	if err != nil {
		return "", err
	}
	return "csr_accepted", nil
}

// CSRSubmitForCert processes a CSR submission for a specific certificate (handler interface method).
func (s *AgentService) CSRSubmitForCert(agentID string, certID string, csrPEM string) (string, error) {
	err := s.SubmitCSR(context.Background(), agentID, certID, []byte(csrPEM))
	if err != nil {
		return "", err
	}
	return "csr_signed", nil
}

// GetWork returns pending deployment jobs for an agent (handler interface method).
func (s *AgentService) GetWork(agentID string) ([]domain.Job, error) {
	jobs, err := s.GetPendingWork(context.Background(), agentID)
	if err != nil {
		return nil, err
	}
	var result []domain.Job
	for _, j := range jobs {
		if j != nil {
			result = append(result, *j)
		}
	}
	return result, nil
}

// GetWorkWithTargets returns actionable jobs enriched with target/certificate details.
// Deployment jobs include target type + config. AwaitingCSR jobs include common name + SANs
// so the agent knows what CSR to generate.
func (s *AgentService) GetWorkWithTargets(agentID string) ([]domain.WorkItem, error) {
	jobs, err := s.GetPendingWork(context.Background(), agentID)
	if err != nil {
		return nil, err
	}

	var items []domain.WorkItem
	for _, j := range jobs {
		if j == nil {
			continue
		}
		item := domain.WorkItem{
			ID:            j.ID,
			Type:          j.Type,
			CertificateID: j.CertificateID,
			TargetID:      j.TargetID,
			Status:        j.Status,
		}

		// Enrich with target details for deployment jobs
		if j.TargetID != nil && *j.TargetID != "" {
			target, err := s.targetRepo.Get(context.Background(), *j.TargetID)
			if err == nil {
				item.TargetType = string(target.Type)
				item.TargetConfig = target.Config
			}
		}

		// Enrich with certificate details for AwaitingCSR jobs (agent needs CN + SANs for CSR)
		if j.Status == domain.JobStatusAwaitingCSR {
			cert, err := s.certRepo.Get(context.Background(), j.CertificateID)
			if err == nil {
				item.CommonName = cert.CommonName
				item.SANs = cert.SANs
			}
		}

		items = append(items, item)
	}

	return items, nil
}

// UpdateJobStatus reports a job's status from an agent (handler interface method).
func (s *AgentService) UpdateJobStatus(agentID string, jobID string, status string, errMsg string) error {
	return s.ReportJobStatus(context.Background(), agentID, jobID, domain.JobStatus(status), errMsg)
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
