package service

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

var errNotFound = errors.New("not found")

// testEncryptionKey is a deterministic passphrase for unit tests that
// exercise IssuerService/TargetService write paths. After the C-2 remediation
// these services fail closed when no key is configured, so happy-path tests
// must supply a real passphrase. M-8 reshaped the type from []byte to string
// because services now hold the raw passphrase and delegate PBKDF2 to
// crypto.EncryptIfKeySet / crypto.DecryptIfKeySet (which apply a fresh random
// salt per ciphertext). Using a constant keeps wire-format assertions stable
// across runs.
var testEncryptionKey = "0123456789abcdef0123456789abcdef"

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
	Updated            []*domain.ManagedCertificate
	MockGetExpiring    []*domain.ManagedCertificate
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

// CreateWithTx mirrors Create — mocks have no DB, so the Querier
// argument is ignored. Production behavior comes from postgres.WithTx
// path; mocks just exercise the in-memory state.
func (m *mockCertRepo) CreateWithTx(ctx context.Context, q repository.Querier, cert *domain.ManagedCertificate) error {
	return m.Create(ctx, cert)
}

func (m *mockCertRepo) Update(ctx context.Context, cert *domain.ManagedCertificate) error {
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.Certs[cert.ID] = cert
	m.Updated = append(m.Updated, cert)
	return nil
}

// UpdateWithTx mirrors Update — see CreateWithTx note.
func (m *mockCertRepo) UpdateWithTx(ctx context.Context, q repository.Querier, cert *domain.ManagedCertificate) error {
	return m.Update(ctx, cert)
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

// CreateVersionWithTx mirrors CreateVersion.
func (m *mockCertRepo) CreateVersionWithTx(ctx context.Context, q repository.Querier, version *domain.CertificateVersion) error {
	return m.CreateVersion(ctx, version)
}

func (m *mockCertRepo) GetExpiringCertificates(ctx context.Context, before time.Time) ([]*domain.ManagedCertificate, error) {
	// Return MockGetExpiring if set, for test control
	if m.MockGetExpiring != nil {
		return m.MockGetExpiring, nil
	}
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

// GetByIssuerAndSerial emulates the PostgreSQL JOIN:
// SELECT mc.* FROM managed_certificates mc JOIN certificate_versions cv
// ON cv.certificate_id = mc.id WHERE mc.issuer_id = $1 AND cv.serial_number = $2.
// Returns sql.ErrNoRows (the sentinel the real repo surfaces) when no match
// exists, so callers that branch on errors.Is(err, sql.ErrNoRows) behave the
// same in-memory as they do against PostgreSQL.
func (m *mockCertRepo) GetByIssuerAndSerial(ctx context.Context, issuerID, serial string) (*domain.ManagedCertificate, error) {
	for _, cert := range m.Certs {
		if cert.IssuerID != issuerID {
			continue
		}
		for _, v := range m.Versions[cert.ID] {
			if v.SerialNumber == serial {
				return cert, nil
			}
		}
	}
	return nil, sql.ErrNoRows
}

// GetVersionBySerial mirrors GetByIssuerAndSerial but returns the version
// row — exists to support the ACME serial-only revoke path tests.
func (m *mockCertRepo) GetVersionBySerial(ctx context.Context, issuerID, serial string) (*domain.CertificateVersion, error) {
	for _, cert := range m.Certs {
		if cert.IssuerID != issuerID {
			continue
		}
		for _, v := range m.Versions[cert.ID] {
			if v.SerialNumber == serial {
				return v, nil
			}
		}
	}
	return nil, sql.ErrNoRows
}

func (m *mockCertRepo) AddCert(cert *domain.ManagedCertificate) {
	m.Certs[cert.ID] = cert
}

// mockJobRepo is a test implementation of JobRepository
type mockJobRepo struct {
	mu                      sync.Mutex
	Jobs                    map[string]*domain.Job
	Agents                  map[string]*domain.Agent
	StatusUpdates           map[string]domain.JobStatus
	CreateErr               error
	UpdateErr               error
	UpdateErrorByID         map[string]error
	UpdateErrorByIDMu       sync.Mutex
	UpdateStatusErr         error
	GetErr                  error
	ListErr                 error
	ListByStatusErr         error
	DeleteErr               error
	ListTimedOutErr         error
	ListOfflineAgentJobsErr error
	Updated                 []*domain.Job
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
	// Check per-ID error injection
	m.UpdateErrorByIDMu.Lock()
	idErr, ok := m.UpdateErrorByID[job.ID]
	m.UpdateErrorByIDMu.Unlock()
	if ok && idErr != nil {
		return idErr
	}
	m.Jobs[job.ID] = job
	m.Updated = append(m.Updated, job)
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

// ClaimPendingJobs simulates the H-6 atomic claim semantics: matching rows are transitioned
// Pending → Running before being returned. The in-memory mock has no concurrency primitives
// beyond the existing mutex, which is sufficient for single-goroutine service tests.
func (m *mockJobRepo) ClaimPendingJobs(ctx context.Context, jobType domain.JobType, limit int) ([]*domain.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var claimed []*domain.Job
	for _, j := range m.Jobs {
		if j.Status != domain.JobStatusPending {
			continue
		}
		if jobType != "" && j.Type != jobType {
			continue
		}
		j.Status = domain.JobStatusRunning
		claimed = append(claimed, j)
		if limit > 0 && len(claimed) >= limit {
			break
		}
	}
	return claimed, nil
}

// ClaimPendingByAgentID simulates the H-6 per-agent claim: Pending deployment rows scoped
// to the agent flip to Running; AwaitingCSR rows are returned but keep their state.
func (m *mockJobRepo) ClaimPendingByAgentID(ctx context.Context, agentID string) ([]*domain.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var result []*domain.Job
	for _, j := range m.Jobs {
		if j.AgentID == nil || *j.AgentID != agentID {
			continue
		}
		switch {
		case j.Status == domain.JobStatusPending && j.Type == domain.JobTypeDeployment:
			j.Status = domain.JobStatusRunning
			result = append(result, j)
		case j.Status == domain.JobStatusAwaitingCSR:
			result = append(result, j)
		}
	}
	return result, nil
}

// ListTimedOutAwaitingJobs returns jobs stuck in AwaitingCSR/AwaitingApproval past the
// respective cutoffs. I-003 coverage-gap closure.
func (m *mockJobRepo) ListTimedOutAwaitingJobs(ctx context.Context, csrCutoff, approvalCutoff time.Time) ([]*domain.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListTimedOutErr != nil {
		return nil, m.ListTimedOutErr
	}
	var jobs []*domain.Job
	for _, j := range m.Jobs {
		switch j.Status {
		case domain.JobStatusAwaitingCSR:
			if j.CreatedAt.Before(csrCutoff) {
				jobs = append(jobs, j)
			}
		case domain.JobStatusAwaitingApproval:
			if j.CreatedAt.Before(approvalCutoff) {
				jobs = append(jobs, j)
			}
		}
	}
	return jobs, nil
}

// ListJobsWithOfflineAgents returns Running jobs whose owning agent's
// last_heartbeat_at is older than agentCutoff. The mock walks Jobs +
// Agents the same way the real repo does. Bundle C / Audit M-016.
func (m *mockJobRepo) ListJobsWithOfflineAgents(ctx context.Context, agentCutoff time.Time) ([]*domain.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListOfflineAgentJobsErr != nil {
		return nil, m.ListOfflineAgentJobsErr
	}
	var jobs []*domain.Job
	for _, j := range m.Jobs {
		if j.Status != domain.JobStatusRunning {
			continue
		}
		if j.AgentID == nil || *j.AgentID == "" {
			continue
		}
		ag, ok := m.Agents[*j.AgentID]
		if !ok || ag.LastHeartbeatAt == nil {
			continue
		}
		if ag.LastHeartbeatAt.Before(agentCutoff) {
			jobs = append(jobs, j)
		}
	}
	return jobs, nil
}

func (m *mockJobRepo) AddJob(job *domain.Job) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Jobs[job.ID] = job
}

// mockNotifRepo is a test implementation of NotificationRepository.
//
// I-005 extensions (ListRetryEligible / RecordFailedAttempt / MarkAsDead /
// Requeue) mutate the seeded *domain.NotificationEvent pointers in place.
// The service tests in notification_test.go assert against those same
// pointers (via notifRepo.Notifications or the local `row` handle), so
// in-place mutation is the contract — not a copy-and-replace pattern.
//
// Error fields are layered:
//   - Per-method errors (ListRetryEligibleErr, RecordFailedAttemptErr, etc.)
//     for fine-grained failure injection when a test targets exactly one
//     method.
//   - Shared legacy errors (ListErr for list-shaped reads, UpdateErr for
//     update-shaped writes) so the pre-I-005 tests that configure ListErr
//     or UpdateErr continue to short-circuit the new methods too. The
//     RequeueNotification_RepoError test deliberately relies on this by
//     setting UpdateErr rather than RequeueErr.
type mockNotifRepo struct {
	mu            sync.Mutex
	Notifications []*domain.NotificationEvent
	CreateErr     error
	ListErr       error
	UpdateErr     error

	// I-005 per-method failure injection.
	ListRetryEligibleErr   error
	RecordFailedAttemptErr error
	MarkAsDeadErr          error
	RequeueErr             error
	CountByStatusErr       error
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
	if filter == nil {
		out := make([]*domain.NotificationEvent, len(m.Notifications))
		copy(out, m.Notifications)
		return out, nil
	}
	// Apply each non-zero filter field. Mirror the postgres notification
	// repo's WHERE-clause shape (CertificateID, Type, Status, Channel,
	// MessageLike) so the multi-channel expiry-alert tests
	// (renewal_expiry_alerts_test.go, Rank 4 of the 2026-05-03 Infisical
	// deep-research deliverable) get the same per-(cert, threshold,
	// channel) dedup behaviour they'd see in production. Pre-Rank 4 the
	// mock returned all rows regardless of filter; legacy callers
	// happened to work because their assertions were "any notification
	// fired" rather than "this specific (cert,threshold,channel) one".
	out := make([]*domain.NotificationEvent, 0, len(m.Notifications))
	msgSubstring := strings.Trim(filter.MessageLike, "%")
	for _, n := range m.Notifications {
		if filter.CertificateID != "" {
			if n.CertificateID == nil || *n.CertificateID != filter.CertificateID {
				continue
			}
		}
		if filter.Type != "" && string(n.Type) != filter.Type {
			continue
		}
		if filter.Status != "" && n.Status != filter.Status {
			continue
		}
		if filter.Channel != "" && string(n.Channel) != filter.Channel {
			continue
		}
		if msgSubstring != "" && !strings.Contains(n.Message, msgSubstring) {
			continue
		}
		out = append(out, n)
	}
	return out, nil
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

// ListRetryEligible returns failed rows whose NextRetryAt is non-nil, at or
// before beforeTime, AND whose RetryCount is strictly less than maxAttempts,
// ordered oldest-due first, capped at limit. Signature matches the postgres-
// canonical shape pinned by notification_test.go:118 ("repo.ListRetryEligible
// (ctx, now, 5, 100)") and the NotificationRepository interface at
// interfaces.go:308 — a row at retry_count == maxAttempts is NOT returned
// because the service has already exhausted its attempt budget and the row
// must be MarkAsDead'd by whichever tick last touched it, not re-swept here.
// Mirrors the partial-index predicate
// `WHERE status='failed' AND next_retry_at IS NOT NULL AND next_retry_at <= $1`
// that migration 000016's retry-sweep index makes cheap to scan; the
// retry_count filter is an extra Go-side guard so the mock behaves
// identically to the postgres `AND retry_count < $2` clause.
func (m *mockNotifRepo) ListRetryEligible(ctx context.Context, beforeTime time.Time, maxAttempts, limit int) ([]*domain.NotificationEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListRetryEligibleErr != nil {
		return nil, m.ListRetryEligibleErr
	}
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	eligible := make([]*domain.NotificationEvent, 0)
	for _, n := range m.Notifications {
		if n.Status != string(domain.NotificationStatusFailed) {
			continue
		}
		if n.NextRetryAt == nil {
			continue
		}
		if n.NextRetryAt.After(beforeTime) {
			continue
		}
		if n.RetryCount >= maxAttempts {
			continue
		}
		eligible = append(eligible, n)
	}
	// Oldest-due first so the service processes the most-overdue row first,
	// matching how an ORDER BY next_retry_at ASC query would behave.
	sort.Slice(eligible, func(i, j int) bool {
		return eligible[i].NextRetryAt.Before(*eligible[j].NextRetryAt)
	})
	if limit > 0 && len(eligible) > limit {
		eligible = eligible[:limit]
	}
	return eligible, nil
}

// RecordFailedAttempt mutates the matched row in place: increments
// retry_count, pins next_retry_at, stores last_error, and keeps the row in
// 'failed' state so the next retry-sweep tick picks it up again. Service-
// level backoff math happens before the call; the repo is a dumb setter.
// Signature matches the postgres-canonical shape pinned by
// notification_test.go:184 ("repo.RecordFailedAttempt(ctx, 'notif-attempt-1',
// 'connection refused', nextTry)") and the NotificationRepository interface
// at interfaces.go:315 — id, then lastError, then nextRetryAt. The earlier
// (id, nextRetryAt, lastError) ordering from the Phase 1 Red seed was wrong
// and is corrected here in Phase 2 Green.
func (m *mockNotifRepo) RecordFailedAttempt(ctx context.Context, id string, lastError string, nextRetryAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.RecordFailedAttemptErr != nil {
		return m.RecordFailedAttemptErr
	}
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	for _, n := range m.Notifications {
		if n.ID == id {
			n.RetryCount++
			next := nextRetryAt
			n.NextRetryAt = &next
			le := lastError
			n.LastError = &le
			n.Status = string(domain.NotificationStatusFailed)
			return nil
		}
	}
	return errNotFound
}

// MarkAsDead flips the row into the terminal DLQ state. next_retry_at is
// cleared so the partial retry-sweep index no longer touches this row —
// otherwise RetryFailedNotifications would loop over it forever without
// making any state change.
func (m *mockNotifRepo) MarkAsDead(ctx context.Context, id string, lastError string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.MarkAsDeadErr != nil {
		return m.MarkAsDeadErr
	}
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	for _, n := range m.Notifications {
		if n.ID == id {
			n.Status = string(domain.NotificationStatusDead)
			n.NextRetryAt = nil
			le := lastError
			n.LastError = &le
			return nil
		}
	}
	return errNotFound
}

// Requeue is the operator-driven escape hatch from 'dead' back to 'pending'.
// Clears retry bookkeeping entirely so ProcessPendingNotifications treats
// the requeued row as a fresh attempt — identical on the wire to a freshly-
// created notification.
func (m *mockNotifRepo) Requeue(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.RequeueErr != nil {
		return m.RequeueErr
	}
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	for _, n := range m.Notifications {
		if n.ID == id {
			n.Status = string(domain.NotificationStatusPending)
			n.RetryCount = 0
			n.NextRetryAt = nil
			n.LastError = nil
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

// CountByStatus counts in-memory rows whose Status field matches exactly.
// Dedicated error injection via CountByStatusErr so a test can assert the
// StatsService wrap-path ("failed to count dead notifications: …") without
// also tripping ListErr or other shared fields. I-005 Phase 2 Green.
func (m *mockNotifRepo) CountByStatus(ctx context.Context, status string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CountByStatusErr != nil {
		return 0, m.CountByStatusErr
	}
	var count int64
	for _, n := range m.Notifications {
		if n.Status == status {
			count++
		}
	}
	return count, nil
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

// CreateWithTx mirrors Create — mocks have no DB; the Querier is ignored.
func (m *mockAuditRepo) CreateWithTx(ctx context.Context, q repository.Querier, event *domain.AuditEvent) error {
	return m.Create(ctx, event)
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

// mockRenewalPolicyRepo is a test implementation of RenewalPolicyRepository.
//
// G-1: repo contract extended with Create/Update/Delete to support the
// /api/v1/renewal-policies CRUD endpoints. Per-method *Err fields let tests
// force specific repo failures (duplicate name → 23505, FK RESTRICT on Delete
// → 23503) without standing up a real Postgres connection. The sentinel
// errors `ErrRenewalPolicyDuplicateName` and `ErrRenewalPolicyInUse` are the
// typed envelopes the service / handler layers translate into 409 Conflict.
type mockRenewalPolicyRepo struct {
	Policies  map[string]*domain.RenewalPolicy
	GetErr    error
	ListErr   error
	CreateErr error
	UpdateErr error
	DeleteErr error
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
	// Deterministic ordering mirrors the production repo's ORDER BY name,
	// so pagination-boundary assertions don't become flaky under map
	// iteration randomness.
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Name < policies[j].Name
	})
	return policies, nil
}

func (m *mockRenewalPolicyRepo) Create(ctx context.Context, policy *domain.RenewalPolicy) error {
	if m.CreateErr != nil {
		return m.CreateErr
	}
	if _, exists := m.Policies[policy.ID]; exists {
		return m.CreateErr
	}
	m.Policies[policy.ID] = policy
	return nil
}

func (m *mockRenewalPolicyRepo) Update(ctx context.Context, id string, policy *domain.RenewalPolicy) error {
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	if _, exists := m.Policies[id]; !exists {
		return errNotFound
	}
	policy.ID = id
	m.Policies[id] = policy
	return nil
}

func (m *mockRenewalPolicyRepo) Delete(ctx context.Context, id string) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	if _, exists := m.Policies[id]; !exists {
		return errNotFound
	}
	delete(m.Policies, id)
	return nil
}

func (m *mockRenewalPolicyRepo) AddPolicy(policy *domain.RenewalPolicy) {
	m.Policies[policy.ID] = policy
}

// mockAgentRepo is a test implementation of AgentRepository.
//
// I-004: ActiveTargetCounts / ActiveCertCounts / PendingJobCounts are keyed by
// agent ID and read back verbatim by the Count* methods — the retirement
// service's preflight pokes these maps to simulate "agent has N active
// deployments / M deployed certs / K pending jobs" without having to seed
// real target/cert/job rows across multiple mock repos. An unset key means
// zero, matching the production repo behavior on an agent with no deps.
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
	// I-004 preflight count seeds (read by CountActiveTargets etc.).
	ActiveTargetCounts map[string]int
	ActiveCertCounts   map[string]int
	PendingJobCounts   map[string]int
	// I-004 retirement write-path error seams. Let tests force a SoftRetire
	// or RetireAgentWithCascade failure after preflight passed, so the
	// service's error surfacing (wrap+return, skip audit, etc.) can be
	// exercised without having to stand up a real PG connection.
	SoftRetireErr    error
	RetireCascadeErr error
	CountErr         error
	ListRetiredErr   error
}

// List mirrors the production repo contract post-I-004: it returns only
// ACTIVE agents (RetiredAt == nil). Tests that seed a retired agent via
// AddAgent and then call a List-driven service method (e.g. ListAgents,
// MarkStaleAgentsOffline, stats dashboards) must not see the retired row
// here — otherwise the mock would pass while the real planner filters it
// out at the WHERE clause level. ListRetired is the companion method for
// explicit retired-only listing.
func (m *mockAgentRepo) List(ctx context.Context) ([]*domain.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var agents []*domain.Agent
	for _, a := range m.Agents {
		if a.RetiredAt != nil {
			continue
		}
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

func (m *mockAgentRepo) CreateIfNotExists(ctx context.Context, agent *domain.Agent) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CreateErr != nil {
		return false, m.CreateErr
	}
	if _, exists := m.Agents[agent.ID]; exists {
		return false, nil
	}
	m.Agents[agent.ID] = agent
	return true, nil
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

// ListRetired returns the paginated retired-agents slice + total count.
// Matches the production repo contract: RetiredAt != nil, sorted by
// RetiredAt DESC, page<1 → 1, perPage<1 → 50. Sort is done in-memory over
// the keyed map so the mock stays dependency-free. I-004.
func (m *mockAgentRepo) ListRetired(ctx context.Context, page, perPage int) ([]*domain.Agent, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListRetiredErr != nil {
		return nil, 0, m.ListRetiredErr
	}
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}
	var retired []*domain.Agent
	for _, a := range m.Agents {
		if a.RetiredAt != nil {
			retired = append(retired, a)
		}
	}
	total := len(retired)
	// Sort by RetiredAt DESC — most recent first. The real query uses the
	// partial idx_agents_retired_at index; here we sort in Go.
	sort.SliceStable(retired, func(i, j int) bool {
		return retired[i].RetiredAt.After(*retired[j].RetiredAt)
	})
	// Apply page/perPage window.
	offset := (page - 1) * perPage
	if offset >= total {
		return nil, total, nil
	}
	end := offset + perPage
	if end > total {
		end = total
	}
	return retired[offset:end], total, nil
}

// SoftRetire stamps RetiredAt + RetiredReason on the agent row. Mirrors
// the real repo's idempotent semantics: a row already retired is left
// untouched (zero-rows-affected is not an error). I-004 preserves
// retirement metadata across re-retire attempts — whoever retired it
// first owns the audit trail.
func (m *mockAgentRepo) SoftRetire(ctx context.Context, id string, retiredAt time.Time, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.SoftRetireErr != nil {
		return m.SoftRetireErr
	}
	agent, ok := m.Agents[id]
	if !ok {
		return errNotFound
	}
	if agent.RetiredAt != nil {
		return nil // already retired — no-op
	}
	stamped := retiredAt
	agent.RetiredAt = &stamped
	stampedReason := reason
	agent.RetiredReason = &stampedReason
	return nil
}

// RetireAgentWithCascade stamps the agent row the same way SoftRetire
// does. The real repo also stamps every active deployment_targets row
// in the same transaction; the mock can't do that because targets live
// in mockTargetRepo, which the retirement service doesn't write to
// through this repo interface. Tests that need to assert cascade
// semantics on targets should seed mockTargetRepo directly and verify
// the service-layer audit event captured the cascade count. I-004.
func (m *mockAgentRepo) RetireAgentWithCascade(ctx context.Context, id string, retiredAt time.Time, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.RetireCascadeErr != nil {
		return m.RetireCascadeErr
	}
	agent, ok := m.Agents[id]
	if !ok {
		return errNotFound
	}
	if agent.RetiredAt != nil {
		return nil // already retired — no-op (same as production transaction)
	}
	stamped := retiredAt
	agent.RetiredAt = &stamped
	stampedReason := reason
	agent.RetiredReason = &stampedReason
	return nil
}

// CountActiveTargets returns the seeded ActiveTargetCounts value (0 if
// unset). Matches the real repo signature: COUNT of non-retired
// deployment_targets with agent_id=$1. I-004 preflight.
func (m *mockAgentRepo) CountActiveTargets(ctx context.Context, agentID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CountErr != nil {
		return 0, m.CountErr
	}
	return m.ActiveTargetCounts[agentID], nil
}

// CountActiveCertificates returns the seeded ActiveCertCounts value.
// Real query: COUNT(DISTINCT certificate_id) across
// certificate_target_mappings ↔ deployment_targets on agent_id. I-004.
func (m *mockAgentRepo) CountActiveCertificates(ctx context.Context, agentID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CountErr != nil {
		return 0, m.CountErr
	}
	return m.ActiveCertCounts[agentID], nil
}

// CountPendingJobs returns the seeded PendingJobCounts value. Real
// query: COUNT of jobs with agent_id=$1 AND status IN (Pending,
// AwaitingCSR, AwaitingApproval, Running). I-004.
func (m *mockAgentRepo) CountPendingJobs(ctx context.Context, agentID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CountErr != nil {
		return 0, m.CountErr
	}
	return m.PendingJobCounts[agentID], nil
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

func (m *mockTargetRepo) CreateIfNotExists(ctx context.Context, target *domain.DeploymentTarget) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CreateErr != nil {
		return false, m.CreateErr
	}
	if _, exists := m.Targets[target.ID]; exists {
		return false, nil
	}
	m.Targets[target.ID] = target
	return true, nil
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

func newMockTargetRepository() *mockTargetRepo {
	return &mockTargetRepo{
		Targets: make(map[string]*domain.DeploymentTarget),
	}
}

// mockIssuerConnector is a test implementation of IssuerConnector
type mockIssuerConnector struct {
	Result               *IssuanceResult
	Err                  error
	getRenewalInfoResult *RenewalInfoResult
	getRenewalInfoErr    error
	// LastOCSPSignRequest captures the last request passed to SignOCSPResponse.
	// Tests use this to assert CertStatus (0=good, 1=revoked, 2=unknown).
	LastOCSPSignRequest *OCSPSignRequest

	// LastMustStaple records the must-staple bool from the most recent
	// Issue/Renew call so tests can assert the service-layer wire from
	// CertificateProfile.MustStaple → IssuerConnector reaches the
	// connector. SCEP RFC 8894 + Intune master bundle Phase 5.6 follow-up.
	LastMustStaple bool
}

// LastMustStaple records the must-staple bool from the most recent
// IssueCertificate / RenewCertificate call. Set by both methods so tests
// can assert the wire from CertificateProfile.MustStaple → service →
// IssuerConnector reaches the connector. SCEP RFC 8894 + Intune master
// bundle Phase 5.6 follow-up.
//
// (Field added to mockIssuerConnector struct above; declared via the
// pointer receiver so existing test fixtures don't need re-zeroing.)

func (m *mockIssuerConnector) IssueCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string, maxTTLSeconds int, mustStaple bool) (*IssuanceResult, error) {
	m.LastMustStaple = mustStaple
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

func (m *mockIssuerConnector) RenewCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string, maxTTLSeconds int, mustStaple bool) (*IssuanceResult, error) {
	m.LastMustStaple = mustStaple
	if m.Err != nil {
		return nil, m.Err
	}
	return m.IssueCertificate(ctx, commonName, sans, csrPEM, ekus, maxTTLSeconds, mustStaple)
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
	// Capture the request for test assertions (e.g., CertStatus verification)
	reqCopy := req
	m.LastOCSPSignRequest = &reqCopy
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

// mockTransactor is a no-op repository.Transactor for tests. It runs fn
// synchronously without any DB; the Querier passed to fn is nil because
// the mock repo *WithTx methods ignore it. If fn returns an error, the
// "transaction" is not committed — but since mocks share state, in-memory
// rollback isn't simulated. Tests that need rollback semantics use
// mockTransactor with WantRollbackOnErr=true to assert fn's error
// propagated correctly.
type mockTransactor struct {
	WantRollbackOnErr bool
	BeginTxErr        error
	CommitErr         error
}

func (m *mockTransactor) WithinTx(ctx context.Context, fn func(q repository.Querier) error) error {
	if m.BeginTxErr != nil {
		return m.BeginTxErr
	}
	if err := fn(nil); err != nil {
		return err
	}
	return m.CommitErr
}

func newMockTransactor() *mockTransactor { return &mockTransactor{} }

func newMockAgentRepository() *mockAgentRepo {
	return &mockAgentRepo{
		Agents:           make(map[string]*domain.Agent),
		HeartbeatUpdates: make(map[string]time.Time),
		// I-004 preflight count maps. Tests seed these directly via
		// agentRepo.ActiveTargetCounts["agent-id"] = N — unset keys
		// read back as zero from CountActiveTargets etc., matching
		// the production repo behavior for agents with no deps.
		ActiveTargetCounts: make(map[string]int),
		ActiveCertCounts:   make(map[string]int),
		PendingJobCounts:   make(map[string]int),
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
	// F-001 regression instrumentation: track which list method was invoked
	// so tests can assert that the CRL generation hot path uses the scoped
	// ListByIssuer query (migration 000012 composite index) rather than
	// ListAll followed by in-Go filtering.
	ListAllCalls      int
	ListByIssuerCalls int
	LastListIssuerID  string
}

// CreateWithTx mirrors Create — mocks have no DB; the Querier is ignored.
func (m *mockRevocationRepo) CreateWithTx(ctx context.Context, q repository.Querier, revocation *domain.CertificateRevocation) error {
	return m.Create(ctx, revocation)
}

func (m *mockRevocationRepo) Create(ctx context.Context, revocation *domain.CertificateRevocation) error {
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.Revocations = append(m.Revocations, revocation)
	return nil
}

func (m *mockRevocationRepo) GetByIssuerAndSerial(ctx context.Context, issuerID, serial string) (*domain.CertificateRevocation, error) {
	for _, r := range m.Revocations {
		if r.IssuerID == issuerID && r.SerialNumber == serial {
			return r, nil
		}
	}
	return nil, errNotFound
}

func (m *mockRevocationRepo) ListAll(ctx context.Context) ([]*domain.CertificateRevocation, error) {
	m.ListAllCalls++
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	return m.Revocations, nil
}

func (m *mockRevocationRepo) ListByIssuer(ctx context.Context, issuerID string) ([]*domain.CertificateRevocation, error) {
	m.ListByIssuerCalls++
	m.LastListIssuerID = issuerID
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var result []*domain.CertificateRevocation
	for _, r := range m.Revocations {
		if r.IssuerID == issuerID {
			result = append(result, r)
		}
	}
	return result, nil
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
