package repository

import (
	"context"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// CertificateRepository defines operations for managing certificates.
type CertificateRepository interface {
	// List returns a paginated list of certificates matching the filter criteria.
	List(ctx context.Context, filter *CertificateFilter) ([]*domain.ManagedCertificate, int, error)
	// Get retrieves a certificate by ID.
	Get(ctx context.Context, id string) (*domain.ManagedCertificate, error)
	// Create stores a new certificate.
	Create(ctx context.Context, cert *domain.ManagedCertificate) error
	// Update modifies an existing certificate.
	Update(ctx context.Context, cert *domain.ManagedCertificate) error
	// Archive marks a certificate as archived.
	Archive(ctx context.Context, id string) error
	// ListVersions returns all versions of a certificate.
	ListVersions(ctx context.Context, certID string) ([]*domain.CertificateVersion, error)
	// CreateVersion stores a new certificate version.
	CreateVersion(ctx context.Context, version *domain.CertificateVersion) error
	// GetExpiringCertificates returns certificates expiring before the given time.
	GetExpiringCertificates(ctx context.Context, before time.Time) ([]*domain.ManagedCertificate, error)
	// GetLatestVersion returns the most recent certificate version for a certificate.
	GetLatestVersion(ctx context.Context, certID string) (*domain.CertificateVersion, error)
}

// RevocationRepository defines operations for managing certificate revocations.
type RevocationRepository interface {
	// Create records a new certificate revocation. Uniqueness is scoped to
	// (issuer_id, serial_number) per RFC 5280 §5.2.3, so duplicate serials
	// across different issuers are permitted.
	Create(ctx context.Context, revocation *domain.CertificateRevocation) error
	// GetByIssuerAndSerial retrieves a revocation by the (issuer_id, serial_number)
	// pair. Callers (OCSP, CRL generation) always know the issuer because
	// protocol endpoints carry it in the request path; RFC 5280 §5.2.3 guarantees
	// uniqueness only within a single issuer.
	GetByIssuerAndSerial(ctx context.Context, issuerID, serial string) (*domain.CertificateRevocation, error)
	// ListAll returns all revocations, ordered by revocation time (for CRL generation).
	ListAll(ctx context.Context) ([]*domain.CertificateRevocation, error)
	// ListByCertificate returns all revocations for a certificate.
	ListByCertificate(ctx context.Context, certID string) ([]*domain.CertificateRevocation, error)
	// MarkIssuerNotified updates the issuer_notified flag for a revocation.
	MarkIssuerNotified(ctx context.Context, id string) error
}

// IssuerRepository defines operations for managing certificate issuers.
type IssuerRepository interface {
	// List returns all issuers, optionally filtered.
	List(ctx context.Context) ([]*domain.Issuer, error)
	// Get retrieves an issuer by ID.
	Get(ctx context.Context, id string) (*domain.Issuer, error)
	// Create stores a new issuer.
	Create(ctx context.Context, issuer *domain.Issuer) error
	// CreateIfNotExists creates an issuer only if the ID doesn't already exist (ON CONFLICT DO NOTHING).
	// Returns true if created, false if already existed.
	CreateIfNotExists(ctx context.Context, issuer *domain.Issuer) (bool, error)
	// Update modifies an existing issuer.
	Update(ctx context.Context, issuer *domain.Issuer) error
	// Delete removes an issuer.
	Delete(ctx context.Context, id string) error
}

// TargetRepository defines operations for managing deployment targets.
type TargetRepository interface {
	// List returns all targets, optionally filtered.
	List(ctx context.Context) ([]*domain.DeploymentTarget, error)
	// Get retrieves a target by ID.
	Get(ctx context.Context, id string) (*domain.DeploymentTarget, error)
	// Create stores a new target.
	Create(ctx context.Context, target *domain.DeploymentTarget) error
	// CreateIfNotExists creates a target only if the ID doesn't already exist (ON CONFLICT DO NOTHING).
	// Returns true if created, false if already existed.
	CreateIfNotExists(ctx context.Context, target *domain.DeploymentTarget) (bool, error)
	// Update modifies an existing target.
	Update(ctx context.Context, target *domain.DeploymentTarget) error
	// Delete removes a target.
	Delete(ctx context.Context, id string) error
	// ListByCertificate returns all targets for a given certificate.
	ListByCertificate(ctx context.Context, certID string) ([]*domain.DeploymentTarget, error)
}

// AgentRepository defines operations for managing control plane agents.
type AgentRepository interface {
	// List returns all agents.
	List(ctx context.Context) ([]*domain.Agent, error)
	// Get retrieves an agent by ID.
	Get(ctx context.Context, id string) (*domain.Agent, error)
	// Create stores a new agent. Callers that want duplicate-key errors surfaced
	// (e.g. real-agent registration) must use this method; sentinel/bootstrap
	// paths that expect the row to already exist on restart should call
	// CreateIfNotExists instead (M-6, CWE-662).
	Create(ctx context.Context, agent *domain.Agent) error
	// CreateIfNotExists creates an agent only if the ID doesn't already exist
	// (INSERT ... ON CONFLICT (id) DO NOTHING). Returns true if the row was
	// newly inserted, false if a row with the same ID already existed. Used
	// by the sentinel-agent bootstrap path in cmd/server/main.go so restarts
	// and upgrades are idempotent without swallowing unrelated database
	// failures (M-6, CWE-662).
	CreateIfNotExists(ctx context.Context, agent *domain.Agent) (bool, error)
	// Update modifies an existing agent.
	Update(ctx context.Context, agent *domain.Agent) error
	// Delete removes an agent.
	Delete(ctx context.Context, id string) error
	// UpdateHeartbeat updates the agent's last heartbeat timestamp and metadata.
	UpdateHeartbeat(ctx context.Context, id string, metadata *domain.AgentMetadata) error
	// GetByAPIKey retrieves an agent by hashed API key.
	GetByAPIKey(ctx context.Context, keyHash string) (*domain.Agent, error)
}

// JobRepository defines operations for managing renewal and deployment jobs.
type JobRepository interface {
	// List returns all jobs.
	List(ctx context.Context) ([]*domain.Job, error)
	// Get retrieves a job by ID.
	Get(ctx context.Context, id string) (*domain.Job, error)
	// Create stores a new job.
	Create(ctx context.Context, job *domain.Job) error
	// Update modifies an existing job.
	Update(ctx context.Context, job *domain.Job) error
	// Delete removes a job.
	Delete(ctx context.Context, id string) error
	// ListByStatus returns jobs with a specific status.
	ListByStatus(ctx context.Context, status domain.JobStatus) ([]*domain.Job, error)
	// ListByCertificate returns all jobs for a certificate.
	ListByCertificate(ctx context.Context, certID string) ([]*domain.Job, error)
	// UpdateStatus updates a job's status and optional error message.
	UpdateStatus(ctx context.Context, id string, status domain.JobStatus, errMsg string) error
	// GetPendingJobs returns jobs not yet processed of a specific type. Prefer ClaimPendingJobs in
	// production paths where concurrent schedulers may race — see H-6 (CWE-362) remediation.
	GetPendingJobs(ctx context.Context, jobType domain.JobType) ([]*domain.Job, error)
	// ListPendingByAgentID returns pending deployment jobs and AwaitingCSR jobs for a specific agent.
	// Prefer ClaimPendingByAgentID in production paths — see H-6 (CWE-362) remediation.
	ListPendingByAgentID(ctx context.Context, agentID string) ([]*domain.Job, error)
	// ClaimPendingJobs atomically claims up to `limit` Pending jobs and transitions them to Running
	// using SELECT FOR UPDATE SKIP LOCKED inside a transaction. An empty jobType matches any type;
	// limit <= 0 means no limit. H-6 (CWE-362) race remediation.
	ClaimPendingJobs(ctx context.Context, jobType domain.JobType, limit int) ([]*domain.Job, error)
	// ClaimPendingByAgentID atomically claims pending deployment jobs for an agent (flipping them
	// to Running) and locks AwaitingCSR jobs against concurrent observers (leaving state intact,
	// since the CSR-submission path drives the next transition). H-6 (CWE-362) race remediation.
	ClaimPendingByAgentID(ctx context.Context, agentID string) ([]*domain.Job, error)
}

// RenewalPolicyRepository defines operations for managing renewal policies.
type RenewalPolicyRepository interface {
	// Get retrieves a renewal policy by ID.
	Get(ctx context.Context, id string) (*domain.RenewalPolicy, error)
	// List returns all renewal policies.
	List(ctx context.Context) ([]*domain.RenewalPolicy, error)
}

// PolicyRepository defines operations for managing compliance policies and violations.
type PolicyRepository interface {
	// ListRules returns all policy rules.
	ListRules(ctx context.Context) ([]*domain.PolicyRule, error)
	// GetRule retrieves a policy rule by ID.
	GetRule(ctx context.Context, id string) (*domain.PolicyRule, error)
	// CreateRule stores a new policy rule.
	CreateRule(ctx context.Context, rule *domain.PolicyRule) error
	// UpdateRule modifies an existing policy rule.
	UpdateRule(ctx context.Context, rule *domain.PolicyRule) error
	// DeleteRule removes a policy rule.
	DeleteRule(ctx context.Context, id string) error
	// CreateViolation records a policy violation.
	CreateViolation(ctx context.Context, violation *domain.PolicyViolation) error
	// ListViolations returns policy violations, optionally filtered.
	ListViolations(ctx context.Context, filter *AuditFilter) ([]*domain.PolicyViolation, error)
}

// AuditRepository defines operations for recording and retrieving audit logs.
type AuditRepository interface {
	// Create stores a new audit event.
	Create(ctx context.Context, event *domain.AuditEvent) error
	// List returns audit events matching the filter criteria.
	List(ctx context.Context, filter *AuditFilter) ([]*domain.AuditEvent, error)
}

// NotificationRepository defines operations for managing notifications.
type NotificationRepository interface {
	// Create stores a new notification.
	Create(ctx context.Context, notif *domain.NotificationEvent) error
	// List returns notifications matching the filter criteria.
	List(ctx context.Context, filter *NotificationFilter) ([]*domain.NotificationEvent, error)
	// UpdateStatus updates a notification's delivery status.
	UpdateStatus(ctx context.Context, id string, status string, sentAt time.Time) error
}

// TeamRepository defines operations for managing teams.
type TeamRepository interface {
	// List returns all teams.
	List(ctx context.Context) ([]*domain.Team, error)
	// Get retrieves a team by ID.
	Get(ctx context.Context, id string) (*domain.Team, error)
	// Create stores a new team.
	Create(ctx context.Context, team *domain.Team) error
	// Update modifies an existing team.
	Update(ctx context.Context, team *domain.Team) error
	// Delete removes a team.
	Delete(ctx context.Context, id string) error
}

// CertificateProfileRepository defines operations for managing certificate profiles.
type CertificateProfileRepository interface {
	// List returns all certificate profiles.
	List(ctx context.Context) ([]*domain.CertificateProfile, error)
	// Get retrieves a certificate profile by ID.
	Get(ctx context.Context, id string) (*domain.CertificateProfile, error)
	// Create stores a new certificate profile.
	Create(ctx context.Context, profile *domain.CertificateProfile) error
	// Update modifies an existing certificate profile.
	Update(ctx context.Context, profile *domain.CertificateProfile) error
	// Delete removes a certificate profile.
	Delete(ctx context.Context, id string) error
}

// AgentGroupRepository defines operations for managing agent groups.
type AgentGroupRepository interface {
	// List returns all agent groups.
	List(ctx context.Context) ([]*domain.AgentGroup, error)
	// Get retrieves an agent group by ID.
	Get(ctx context.Context, id string) (*domain.AgentGroup, error)
	// Create stores a new agent group.
	Create(ctx context.Context, group *domain.AgentGroup) error
	// Update modifies an existing agent group.
	Update(ctx context.Context, group *domain.AgentGroup) error
	// Delete removes an agent group.
	Delete(ctx context.Context, id string) error
	// ListMembers returns agents in a group (both dynamic matches and manual includes).
	ListMembers(ctx context.Context, groupID string) ([]*domain.Agent, error)
	// AddMember adds a manual membership.
	AddMember(ctx context.Context, groupID, agentID, membershipType string) error
	// RemoveMember removes a manual membership.
	RemoveMember(ctx context.Context, groupID, agentID string) error
}

// DiscoveryRepository defines operations for managing certificate discovery.
type DiscoveryRepository interface {
	// CreateScan stores a new discovery scan record.
	CreateScan(ctx context.Context, scan *domain.DiscoveryScan) error
	// GetScan retrieves a discovery scan by ID.
	GetScan(ctx context.Context, id string) (*domain.DiscoveryScan, error)
	// ListScans returns discovery scans, optionally filtered by agent ID.
	ListScans(ctx context.Context, agentID string, page, perPage int) ([]*domain.DiscoveryScan, int, error)
	// CreateDiscovered stores a new discovered certificate (upserts by fingerprint+agent+path).
	// Returns true if the certificate was newly inserted (not just updated).
	CreateDiscovered(ctx context.Context, cert *domain.DiscoveredCertificate) (bool, error)
	// GetDiscovered retrieves a discovered certificate by ID.
	GetDiscovered(ctx context.Context, id string) (*domain.DiscoveredCertificate, error)
	// ListDiscovered returns discovered certificates matching the filter.
	ListDiscovered(ctx context.Context, filter *DiscoveryFilter) ([]*domain.DiscoveredCertificate, int, error)
	// UpdateDiscoveredStatus updates the status and optional managed certificate link.
	UpdateDiscoveredStatus(ctx context.Context, id string, status domain.DiscoveryStatus, managedCertID string) error
	// GetByFingerprint retrieves discovered certificates by SHA-256 fingerprint.
	GetByFingerprint(ctx context.Context, fingerprint string) ([]*domain.DiscoveredCertificate, error)
	// CountByStatus returns counts of discovered certificates grouped by status.
	CountByStatus(ctx context.Context) (map[string]int, error)
}

// DiscoveryFilter defines filters for listing discovered certificates.
type DiscoveryFilter struct {
	AgentID   string
	Status    string
	IsExpired bool
	IsCA      bool
	Page      int
	PerPage   int
}

// NetworkScanRepository defines operations for managing network scan targets.
type NetworkScanRepository interface {
	// List returns all network scan targets.
	List(ctx context.Context) ([]*domain.NetworkScanTarget, error)
	// ListEnabled returns only enabled scan targets.
	ListEnabled(ctx context.Context) ([]*domain.NetworkScanTarget, error)
	// Get retrieves a network scan target by ID.
	Get(ctx context.Context, id string) (*domain.NetworkScanTarget, error)
	// Create stores a new network scan target.
	Create(ctx context.Context, target *domain.NetworkScanTarget) error
	// Update modifies an existing network scan target.
	Update(ctx context.Context, target *domain.NetworkScanTarget) error
	// Delete removes a network scan target.
	Delete(ctx context.Context, id string) error
	// UpdateScanResults records the outcome of the last scan for a target.
	UpdateScanResults(ctx context.Context, id string, scanAt time.Time, durationMs int, certsFound int) error
}

// OwnerRepository defines operations for managing certificate owners.
type OwnerRepository interface {
	// List returns all owners.
	List(ctx context.Context) ([]*domain.Owner, error)
	// Get retrieves an owner by ID.
	Get(ctx context.Context, id string) (*domain.Owner, error)
	// Create stores a new owner.
	Create(ctx context.Context, owner *domain.Owner) error
	// Update modifies an existing owner.
	Update(ctx context.Context, owner *domain.Owner) error
	// Delete removes an owner.
	Delete(ctx context.Context, id string) error
}

// HealthCheckRepository manages endpoint health check persistence.
type HealthCheckRepository interface {
	// Create stores a new health check.
	Create(ctx context.Context, check *domain.EndpointHealthCheck) error
	// Update modifies an existing health check.
	Update(ctx context.Context, check *domain.EndpointHealthCheck) error
	// Get retrieves a health check by ID.
	Get(ctx context.Context, id string) (*domain.EndpointHealthCheck, error)
	// Delete removes a health check.
	Delete(ctx context.Context, id string) error
	// List returns health checks matching the filter with pagination.
	List(ctx context.Context, filter *HealthCheckFilter) ([]*domain.EndpointHealthCheck, int, error)
	// ListDueForCheck returns health checks that need to be probed (interval exceeded).
	ListDueForCheck(ctx context.Context) ([]*domain.EndpointHealthCheck, error)
	// GetByEndpoint retrieves a health check by endpoint address.
	GetByEndpoint(ctx context.Context, endpoint string) (*domain.EndpointHealthCheck, error)
	// RecordHistory records a single probe result in history.
	RecordHistory(ctx context.Context, entry *domain.HealthHistoryEntry) error
	// GetHistory retrieves recent probe history for a health check.
	GetHistory(ctx context.Context, healthCheckID string, limit int) ([]*domain.HealthHistoryEntry, error)
	// PurgeHistory deletes history entries older than the specified time.
	PurgeHistory(ctx context.Context, olderThan time.Time) (int64, error)
	// GetSummary returns aggregate counts by health status.
	GetSummary(ctx context.Context) (*domain.HealthCheckSummary, error)
}

// HealthCheckFilter contains filter parameters for health check queries.
type HealthCheckFilter struct {
	// Status filters by health status (healthy, degraded, down, cert_mismatch, unknown).
	Status string
	// CertificateID filters by managed certificate ID.
	CertificateID string
	// NetworkScanTargetID filters by network scan target ID.
	NetworkScanTargetID string
	// Enabled filters by enabled/disabled status (nil = all).
	Enabled *bool
	// Page is the page number (1-indexed).
	Page int
	// PerPage is the number of results per page.
	PerPage int
}
