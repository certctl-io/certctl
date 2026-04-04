package service

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

var errNotFound = errors.New("not found")

// mockCertRepo is a test implementation of CertificateRepository
type mockCertRepo struct {
	Certs              map[string]*domain.ManagedCertificate
	Versions           map[string][]*domain.CertificateVersion
	CreateErr          error
	UpdateErr          error
	GetErr             error
	ListErr            error
	ListVersionsErr    error
	ListVersionsResult []*domain.CertificateVersion
	CreateVersionErr   error
	ArchiveErr         error
}

func (m *mockCertRepo) List(ctx context.Context, filter *repository.CertificateFilter) ([]*domain.ManagedCertificate, int, error) {
	if m.ListErr != nil {
		return nil, 0, m.ListErr
	}
	var certs []*domain.ManagedCertificate
	for _, c := range m.Certs {
		certs = append(certs, c)
	}
	return certs, len(certs), nil
}

func (m *mockCertRepo) Get(ctx context.Context, id string) (*domain.ManagedCertificate, error) {
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	cert, ok := m.Certs[id]
	if !ok {
		return nil, errNotFound
	}
	return cert, nil
}

func (m *mockCertRepo) Create(ctx context.Context, cert *domain.ManagedCertificate) error {
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.Certs[cert.ID] = cert
	return nil
}

func (m *mockCertRepo) Update(ctx context.Context, cert *domain.ManagedCertificate) error {
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.Certs[cert.ID] = cert
	return nil
}

func (m *mockCertRepo) Archive(ctx context.Context, id string) error {
	if m.ArchiveErr != nil {
		return m.ArchiveErr
	}
	cert, ok := m.Certs[id]
	if !ok {
		return errNotFound
	}
	cert.Status = domain.CertificateStatusArchived
	return nil
}

func (m *mockCertRepo) ListVersions(ctx context.Context, certID string) ([]*domain.CertificateVersion, error) {
	if m.ListVersionsErr != nil {
		return nil, m.ListVersionsErr
	}
	if m.ListVersionsResult != nil {
		return m.ListVersionsResult, nil
	}
	return m.Versions[certID], nil
}

func (m *mockCertRepo) CreateVersion(ctx context.Context, version *domain.CertificateVersion) error {
	if m.CreateVersionErr != nil {
		return m.CreateVersionErr
	}
	m.Versions[version.CertificateID] = append(m.Versions[version.CertificateID], version)
	return nil
}

func (m *mockCertRepo) GetExpiringCertificates(ctx context.Context, before time.Time) ([]*domain.ManagedCertificate, error) {
	var expiring []*domain.ManagedCertificate
	for _, c := range m.Certs {
		if c.ExpiresAt.Before(before) {
			expiring = append(expiring, c)
		}
	}
	return expiring, nil
}

func (m *mockCertRepo) GetLatestVersion(ctx context.Context, certID string) (*domain.CertificateVersion, error) {
	versions := m.Versions[certID]
	if len(versions) == 0 {
		return nil, errNotFound
	}
	return versions[len(versions)-1], nil
}

func (m *mockCertRepo) AddCert(cert *domain.ManagedCertificate) {
	m.Certs[cert.ID] = cert
}

// mockJobRepo is a test implementation of JobRepository
type mockJobRepo struct {
	mu              sync.Mutex
	Jobs            map[string]*domain.Job
	StatusUpdates   map[string]domain.JobStatus
	CreateErr       error
	UpdateErr       error
	UpdateStatusErr error
	GetErr          error
	ListErr         error
	ListByStatusErr error
	DeleteErr       error
}

func (m *mockJobRepo) List(ctx context.Context) ([]*domain.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var jobs []*domain.Job
	for _, j := range m.Jobs {
		jobs = append(jobs, j)
	}
	return jobs, nil
}

func (m *mockJobRepo) Get(ctx context.Context, id string) (*domain.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	job, ok := m.Jobs[id]
	if !ok {
		return nil, errNotFound
	}
	return job, nil
}

func (m *mockJobRepo) Create(ctx context.Context, job *domain.Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.Jobs[job.ID] = job
	return nil
}

func (m *mockJobRepo) Update(ctx context.Context, job *domain.Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.Jobs[job.ID] = job
	return nil
}

func (m *mockJobRepo) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.Jobs, id)
	return nil
}

func (m *mockJobRepo) ListByStatus(ctx context.Context, status domain.JobStatus) ([]*domain.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListByStatusErr != nil {
		return nil, m.ListByStatusErr
	}
	var jobs []*domain.Job
	for _, j := range m.Jobs {
		if j.Status == status {
			jobs = append(jobs, j)
		}
	}
	return jobs, nil
}

func (m *mockJobRepo) ListByCertificate(ctx context.Context, certID string) ([]*domain.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var jobs []*domain.Job
	for _, j := range m.Jobs {
		if j.CertificateID == certID {
			jobs = append(jobs, j)
		}
	}
	return jobs, nil
}

func (m *mockJobRepo) UpdateStatus(ctx context.Context, id string, status domain.JobStatus, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.UpdateStatusErr != nil {
		return m.UpdateStatusErr
	}
	job, ok := m.Jobs[id]
	if !ok {
		return errNotFound
	}
	job.Status = status
	if errMsg != "" {
		job.LastError = &errMsg
	}
	m.StatusUpdates[id] = status
	return nil
}

func (m *mockJobRepo) GetPendingJobs(ctx context.Context, jobType domain.JobType) ([]*domain.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var jobs []*domain.Job
	for _, j := range m.Jobs {
		if j.Type == jobType && j.Status == domain.JobStatusPending {
			jobs = append(jobs, j)
		}
	}
	return jobs, nil
}

func (m *mockJobRepo) ListPendingByAgentID(ctx context.Context, agentID string) ([]*domain.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var result []*domain.Job
	for _, j := range m.Jobs {
		if j.AgentID != nil && *j.AgentID == agentID {
			if j.Status == domain.JobStatusPending && j.Type == domain.JobTypeDeployment {
				result = append(result, j)
			} else if j.Status == domain.JobStatusAwaitingCSR {
				result = append(result, j)
			}
		}
	}
	return result, nil
}

func (m *mockJobRepo) AddJob(job *domain.Job) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Jobs[job.ID] = job
}

// mockNotifRepo is a test implementation of NotificationRepository
type mockNotifRepo struct {
	mu            sync.Mutex
	Notifications []*domain.NotificationEvent
	CreateErr     error
	ListErr       error
	UpdateErr     error
}

func (m *mockNotifRepo) Create(ctx context.Context, notif *domain.NotificationEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.Notifications = append(m.Notifications, notif)
	return nil
}

func (m *mockNotifRepo) List(ctx context.Context, filter *repository.NotificationFilter) ([]*domain.NotificationEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	return m.Notifications, nil
}

func (m *mockNotifRepo) UpdateStatus(ctx context.Context, id string, status string, sentAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	for _, n := range m.Notifications {
		if n.ID == id {
			n.Status = status
			return nil
		}
	}
	return errNotFound
}

func (m *mockNotifRepo) AddNotification(notif *domain.NotificationEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Notifications = append(m.Notifications, notif)
}

// mockAuditRepo is a test implementation of AuditRepository
type mockAuditRepo struct {
	mu        sync.Mutex
	Events    []*domain.AuditEvent
	CreateErr error
	ListErr   error
}

func (m *mockAuditRepo) Create(ctx context.Context, event *domain.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.Events = append(m.Events, event)
	return nil
}

func (m *mockAuditRepo) List(ctx context.Context, filter *repository.AuditFilter) ([]*domain.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	// Apply filtering like the real repo
	var filtered []*domain.AuditEvent
	for _, e := range m.Events {
		if filter != nil {
			if filter.ResourceType != "" && e.ResourceType != filter.ResourceType {
				continue
			}
			if filter.ResourceID != "" && e.ResourceID != filter.ResourceID {
				continue
			}
			if filter.Actor != "" && e.Actor != filter.Actor {
				continue
			}
			if !filter.From.IsZero() && e.Timestamp.Before(filter.From) {
				continue
			}
			if !filter.To.IsZero() && e.Timestamp.After(filter.To) {
				continue
			}
		}
		filtered = append(filtered, e)
	}
	return filtered, nil
}

func (m *mockAuditRepo) AddEvent(event *domain.AuditEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, event)
}

// mockPolicyRepo is a test implementation of PolicyRepository
type mockPolicyRepo struct {
	Rules              map[string]*domain.PolicyRule
	Violations         []*domain.PolicyViolation
	CreateRuleErr      error
	UpdateRuleErr      error
	DeleteRuleErr      error
	GetRuleErr         error
	ListRulesErr       error
	CreateViolationErr error
	ListViolationsErr  error
}

func (m *mockPolicyRepo) ListRules(ctx context.Context) ([]*domain.PolicyRule, error) {
	if m.ListRulesErr != nil {
		return nil, m.ListRulesErr
	}
	var rules []*domain.PolicyRule
	for _, r := range m.Rules {
		rules = append(rules, r)
	}
	return rules, nil
}

func (m *mockPolicyRepo) GetRule(ctx context.Context, id string) (*domain.PolicyRule, error) {
	if m.GetRuleErr != nil {
		return nil, m.GetRuleErr
	}
	rule, ok := m.Rules[id]
	if !ok {
		return nil, errNotFound
	}
	return rule, nil
}

func (m *mockPolicyRepo) CreateRule(ctx context.Context, rule *domain.PolicyRule) error {
	if m.CreateRuleErr != nil {
		return m.CreateRuleErr
	}
	m.Rules[rule.ID] = rule
	return nil
}

func (m *mockPolicyRepo) UpdateRule(ctx context.Context, rule *domain.PolicyRule) error {
	if m.UpdateRuleErr != nil {
		return m.UpdateRuleErr
	}
	m.Rules[rule.ID] = rule
	return nil
}

func (m *mockPolicyRepo) DeleteRule(ctx context.Context, id string) error {
	if m.DeleteRuleErr != nil {
		return m.DeleteRuleErr
	}
	delete(m.Rules, id)
	return nil
}

func (m *mockPolicyRepo) CreateViolation(ctx context.Context, violation *domain.PolicyViolation) error {
	if m.CreateViolationErr != nil {
		return m.CreateViolationErr
	}
	m.Violations = append(m.Violations, violation)
	return nil
}

func (m *mockPolicyRepo) ListViolations(ctx context.Context, filter *repository.AuditFilter) ([]*domain.PolicyViolation, error) {
	if m.ListViolationsErr != nil {
		return nil, m.ListViolationsErr
	}
	return m.Violations, nil
}

func (m *mockPolicyRepo) AddRule(rule *domain.PolicyRule) {
	m.Rules[rule.ID] = rule
}

// mockRenewalPolicyRepo is a test implementation of RenewalPolicyRepository
type mockRenewalPolicyRepo struct {
	Policies map[string]*domain.RenewalPolicy
	GetErr   error
	ListErr  error
}

func (m *mockRenewalPolicyRepo) Get(ctx context.Context, id string) (*domain.RenewalPolicy, error) {
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	policy, ok := m.Policies[id]
	if !ok {
		return nil, errNotFound
	}
	return policy, nil
}

func (m *mockRenewalPolicyRepo) List(ctx context.Context) ([]*domain.RenewalPolicy, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var policies []*domain.RenewalPolicy
	for _, p := range m.Policies {
		policies = append(policies, p)
	}
	return policies, nil
}

func (m *mockRenewalPolicyRepo) AddPolicy(policy *domain.RenewalPolicy) {
	m.Policies[policy.ID] = policy
}

// mockAgentRepo is a test implementation of AgentRepository
type mockAgentRepo struct {
	mu                 sync.Mutex
	Agents             map[string]*domain.Agent
	HeartbeatUpdates   map[string]time.Time
	CreateErr          error
	UpdateErr          error
	DeleteErr          error
	GetErr             error
	ListErr            error
	UpdateHeartbeatErr error
	GetByAPIKeyErr     error
}

func (m *mockAgentRepo) List(ctx context.Context) ([]*domain.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var agents []*domain.Agent
	for _, a := range m.Agents {
		agents = append(agents, a)
	}
	return agents, nil
}

func (m *mockAgentRepo) Get(ctx context.Context, id string) (*domain.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	agent, ok := m.Agents[id]
	if !ok {
		return nil, errNotFound
	}
	return agent, nil
}

func (m *mockAgentRepo) Create(ctx context.Context, agent *domain.Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.Agents[agent.ID] = agent
	return nil
}

func (m *mockAgentRepo) Update(ctx context.Context, agent *domain.Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.Agents[agent.ID] = agent
	return nil
}

func (m *mockAgentRepo) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.Agents, id)
	return nil
}

func (m *mockAgentRepo) UpdateHeartbeat(ctx context.Context, id string, metadata *domain.AgentMetadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.UpdateHeartbeatErr != nil {
		return m.UpdateHeartbeatErr
	}
	agent, ok := m.Agents[id]
	if !ok {
		return errNotFound
	}
	now := time.Now()
	agent.LastHeartbeatAt = &now
	m.HeartbeatUpdates[id] = now
	return nil
}

func (m *mockAgentRepo) GetByAPIKey(ctx context.Context, keyHash string) (*domain.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.GetByAPIKeyErr != nil {
		return nil, m.GetByAPIKeyErr
	}
	for _, a := range m.Agents {
		if a.APIKeyHash == keyHash {
			return a, nil
		}
	}
	return nil, errNotFound
}

func (m *mockAgentRepo) AddAgent(agent *domain.Agent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Agents[agent.ID] = agent
}

// mockTargetRepo is a test implementation of TargetRepository
type mockTargetRepo struct {
	mu            sync.Mutex
	Targets       map[string]*domain.DeploymentTarget
	CreateErr     error
	UpdateErr     error
	DeleteErr     error
	GetErr        error
	ListErr       error
	ListByCertErr error
}

func (m *mockTargetRepo) List(ctx context.Context) ([]*domain.DeploymentTarget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var targets []*domain.DeploymentTarget
	for _, t := range m.Targets {
		targets = append(targets, t)
	}
	return targets, nil
}

func (m *mockTargetRepo) Get(ctx context.Context, id string) (*domain.DeploymentTarget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	target, ok := m.Targets[id]
	if !ok {
		return nil, errNotFound
	}
	return target, nil
}

func (m *mockTargetRepo) Create(ctx context.Context, target *domain.DeploymentTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.Targets[target.ID] = target
	return nil
}

func (m *mockTargetRepo) Update(ctx context.Context, target *domain.DeploymentTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.Targets[target.ID] = target
	return nil
}

func (m *mockTargetRepo) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.Targets, id)
	return nil
}

func (m *mockTargetRepo) ListByCertificate(ctx context.Context, certID string) ([]*domain.DeploymentTarget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListByCertErr != nil {
		return nil, m.ListByCertErr
	}
	// Don't call List again to avoid double-locking
	var targets []*domain.DeploymentTarget
	for _, t := range m.Targets {
		targets = append(targets, t)
	}
	return targets, nil
}

func (m *mockTargetRepo) AddTarget(target *domain.DeploymentTarget) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Targets[target.ID] = target
}

// mockIssuerConnector is a test implementation of IssuerConnector
type mockIssuerConnector struct {
	Result             *IssuanceResult
	Err                error
	getRenewalInfoResult *RenewalInfoResult
	getRenewalInfoErr    error
}

func (m *mockIssuerConnector) IssueCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string) (*IssuanceResult, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	if m.Result != nil {
		return m.Result, nil
	}
	now := time.Now()
	return &IssuanceResult{
		Serial:    "test-serial-123",
		CertPEM:   "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		ChainPEM:  "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
		NotBefore: now,
		NotAfter:  now.AddDate(1, 0, 0),
	}, nil
}

func (m *mockIssuerConnector) RenewCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string) (*IssuanceResult, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.IssueCertificate(ctx, commonName, sans, csrPEM, ekus)
}

func (m *mockIssuerConnector) RevokeCertificate(ctx context.Context, serial string, reason string) error {
	if m.Err != nil {
		return m.Err
	}
	return nil
}

func (m *mockIssuerConnector) GenerateCRL(ctx context.Context, entries []CRLEntry) ([]byte, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return []byte("-----BEGIN X509 CRL-----\nmock-crl-data\n-----END X509 CRL-----"), nil
}

func (m *mockIssuerConnector) SignOCSPResponse(ctx context.Context, req OCSPSignRequest) ([]byte, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return []byte("mock-ocsp-response"), nil
}

func (m *mockIssuerConnector) GetCACertPEM(ctx context.Context) (string, error) {
	if m.Err != nil {
		return "", m.Err
	}
	return "-----BEGIN CERTIFICATE-----\nmock-ca-cert\n-----END CERTIFICATE-----", nil
}

func (m *mockIssuerConnector) GetRenewalInfo(ctx context.Context, certPEM string) (*RenewalInfoResult, error) {
	if m.getRenewalInfoErr != nil {
		return nil, m.getRenewalInfoErr
	}
	if m.getRenewalInfoResult != nil {
		return m.getRenewalInfoResult, nil
	}
	// Default: return nil, nil (issuer does not support ARI)
	return nil, nil
}

// Constructor functions for mocks

func newMockCertificateRepository() *mockCertRepo {
	return &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
}

func newMockJobRepository() *mockJobRepo {
	return &mockJobRepo{
		Jobs:          make(map[string]*domain.Job),
		StatusUpdates: make(map[string]domain.JobStatus),
	}
}

func newMockNotificationRepository() *mockNotifRepo {
	return &mockNotifRepo{
		Notifications: make([]*domain.NotificationEvent, 0),
	}
}

func newMockAuditRepository() *mockAuditRepo {
	return &mockAuditRepo{
		Events: make([]*domain.AuditEvent, 0),
	}
}

func newMockPolicyRepository() *mockPolicyRepo {
	return &mockPolicyRepo{
		Rules:      make(map[string]*domain.PolicyRule),
		Violations: make([]*domain.PolicyViolation, 0),
	}
}

func newMockRenewalPolicyRepository() *mockRenewalPolicyRepo {
	return &mockRenewalPolicyRepo{
		Policies: make(map[string]*domain.RenewalPolicy),
	}
}

func newMockAgentRepository() *mockAgentRepo {
	return &mockAgentRepo{
		Agents:           make(map[string]*domain.Agent),
		HeartbeatUpdates: make(map[string]time.Time),
	}
}

var _ = func() *mockTargetRepo {
	return &mockTargetRepo{
		Targets: make(map[string]*domain.DeploymentTarget),
	}
}

func newMockIssuerRepository() *mockIssuerRepository {
	return &mockIssuerRepository{
		issuers: make(map[string]*domain.Issuer),
	}
}

// mockIssuerRepository is a test implementation of IssuerRepository
type mockIssuerRepository struct {
	issuers   map[string]*domain.Issuer
	GetErr    error
	ListErr   error
	CreateErr error
	UpdateErr error
	DeleteErr error
}

func (m *mockIssuerRepository) List(ctx context.Context) ([]*domain.Issuer, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var issuers []*domain.Issuer
	for _, i := range m.issuers {
		issuers = append(issuers, i)
	}
	return issuers, nil
}

func (m *mockIssuerRepository) Get(ctx context.Context, id string) (*domain.Issuer, error) {
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	issuer, ok := m.issuers[id]
	if !ok {
		return nil, errNotFound
	}
	return issuer, nil
}

func (m *mockIssuerRepository) Create(ctx context.Context, issuer *domain.Issuer) error {
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.issuers[issuer.ID] = issuer
	return nil
}

func (m *mockIssuerRepository) Update(ctx context.Context, issuer *domain.Issuer) error {
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.issuers[issuer.ID] = issuer
	return nil
}

func (m *mockIssuerRepository) CreateIfNotExists(ctx context.Context, issuer *domain.Issuer) (bool, error) {
	if m.CreateErr != nil {
		return false, m.CreateErr
	}
	if _, exists := m.issuers[issuer.ID]; exists {
		return false, nil
	}
	m.issuers[issuer.ID] = issuer
	return true, nil
}

func (m *mockIssuerRepository) Delete(ctx context.Context, id string) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.issuers, id)
	return nil
}

func (m *mockIssuerRepository) AddIssuer(issuer *domain.Issuer) {
	m.issuers[issuer.ID] = issuer
}

// mockRevocationRepo is a test implementation of RevocationRepository
type mockRevocationRepo struct {
	Revocations []*domain.CertificateRevocation
	CreateErr   error
	ListErr     error
}

func (m *mockRevocationRepo) Create(ctx context.Context, revocation *domain.CertificateRevocation) error {
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.Revocations = append(m.Revocations, revocation)
	return nil
}

func (m *mockRevocationRepo) GetBySerial(ctx context.Context, serial string) (*domain.CertificateRevocation, error) {
	for _, r := range m.Revocations {
		if r.SerialNumber == serial {
			return r, nil
		}
	}
	return nil, errNotFound
}

func (m *mockRevocationRepo) ListAll(ctx context.Context) ([]*domain.CertificateRevocation, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	return m.Revocations, nil
}

func (m *mockRevocationRepo) ListByCertificate(ctx context.Context, certID string) ([]*domain.CertificateRevocation, error) {
	var result []*domain.CertificateRevocation
	for _, r := range m.Revocations {
		if r.CertificateID == certID {
			result = append(result, r)
		}
	}
	return result, nil
}

func (m *mockRevocationRepo) MarkIssuerNotified(ctx context.Context, id string) error {
	for _, r := range m.Revocations {
		if r.ID == id {
			r.IssuerNotified = true
			return nil
		}
	}
	return errNotFound
}

func newMockRevocationRepository() *mockRevocationRepo {
	return &mockRevocationRepo{
		Revocations: make([]*domain.CertificateRevocation, 0),
	}
}

// mockNotifier is a simple notifier for testing
type mockNotifier struct {
	mu       sync.Mutex
	messages []*mockNotifierMessage
	SendErr  error
}

type mockNotifierMessage struct {
	Recipient string
	Subject   string
	Body      string
}

func newMockNotifier() *mockNotifier {
	return &mockNotifier{
		messages: make([]*mockNotifierMessage, 0),
	}
}

func (m *mockNotifier) Send(ctx context.Context, recipient string, subject string, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.SendErr != nil {
		return m.SendErr
	}
	m.messages = append(m.messages, &mockNotifierMessage{
		Recipient: recipient,
		Subject:   subject,
		Body:      body,
	})
	return nil
}

func (m *mockNotifier) Channel() string {
	return "Email"
}

func (m *mockNotifier) getSentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.messages)
}

var _ = func(m *mockNotifier) *mockNotifierMessage {
	if len(m.messages) == 0 {
		return nil
	}
	return m.messages[len(m.messages)-1]
}
