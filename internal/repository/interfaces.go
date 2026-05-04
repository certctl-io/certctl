package repository

import (
	"context"
	"errors"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

// Repository-level sentinel errors. Repositories (primarily the postgres
// implementation) translate RDBMS-specific errors into these typed envelopes
// so the service/handler layers can branch with errors.Is without importing
// lib/pq or care about SQLSTATE codes.
//
// G-1: renewal-policy sentinels — DuplicateName → HTTP 409 (pg 23505 on
// renewal_policies.name UNIQUE), InUse → HTTP 409 (pg 23503 on the FK from
// managed_certificates.renewal_policy_id to renewal_policies.id with ON
// DELETE RESTRICT). Both map onto the same 409 status but with distinct
// messages so operators can tell them apart.
var (
	ErrRenewalPolicyDuplicateName = errors.New("renewal policy name already exists")
	ErrRenewalPolicyInUse         = errors.New("renewal policy is still referenced by managed certificates")
)

// CertificateRepository defines operations for managing certificates.
//
// The *WithTx variants on Create / Update / CreateVersion exist so
// service-layer code can run those writes in a single transaction with
// the audit row insert (postgres.WithinTx). Use the bare methods for
// stand-alone operations that do not need transactional semantics; the
// concrete postgres implementation has the bare methods delegate to
// the *WithTx variant using the package-level *sql.DB.
type CertificateRepository interface {
	// List returns a paginated list of certificates matching the filter criteria.
	List(ctx context.Context, filter *CertificateFilter) ([]*domain.ManagedCertificate, int, error)
	// Get retrieves a certificate by ID.
	Get(ctx context.Context, id string) (*domain.ManagedCertificate, error)
	// Create stores a new certificate.
	Create(ctx context.Context, cert *domain.ManagedCertificate) error
	// CreateWithTx stores a new certificate using the supplied Querier
	// (typically *sql.Tx from postgres.WithinTx). Closes the audit-
	// atomicity blocker for the issuance path.
	CreateWithTx(ctx context.Context, q Querier, cert *domain.ManagedCertificate) error
	// Update modifies an existing certificate.
	Update(ctx context.Context, cert *domain.ManagedCertificate) error
	// UpdateWithTx modifies an existing certificate using the supplied
	// Querier. Closes the audit-atomicity blocker for the revocation
	// path (cert status update must be atomic with the revocation row +
	// audit row insert).
	UpdateWithTx(ctx context.Context, q Querier, cert *domain.ManagedCertificate) error
	// Archive marks a certificate as archived.
	Archive(ctx context.Context, id string) error
	// ListVersions returns all versions of a certificate.
	ListVersions(ctx context.Context, certID string) ([]*domain.CertificateVersion, error)
	// CreateVersion stores a new certificate version.
	CreateVersion(ctx context.Context, version *domain.CertificateVersion) error
	// CreateVersionWithTx stores a new certificate version using the
	// supplied Querier. Closes the audit-atomicity blocker for the
	// renewal path (version row must be atomic with the audit row
	// insert).
	CreateVersionWithTx(ctx context.Context, q Querier, version *domain.CertificateVersion) error
	// GetExpiringCertificates returns certificates expiring before the given time.
	GetExpiringCertificates(ctx context.Context, before time.Time) ([]*domain.ManagedCertificate, error)
	// GetLatestVersion returns the most recent certificate version for a certificate.
	GetLatestVersion(ctx context.Context, certID string) (*domain.CertificateVersion, error)
	// GetByIssuerAndSerial retrieves a certificate by the (issuer_id, serial_number)
	// pair via a JOIN on certificate_versions. Callers (OCSP, revocation lookup)
	// always know the issuer because protocol endpoints carry it in the request
	// path; RFC 5280 §5.2.3 guarantees serial uniqueness only within a single
	// issuer. Returns sql.ErrNoRows when no match exists so callers can
	// distinguish "unknown cert" from a real repository error.
	GetByIssuerAndSerial(ctx context.Context, issuerID, serial string) (*domain.ManagedCertificate, error)
	// GetVersionBySerial retrieves the certificate_versions row whose
	// serial_number matches, scoped to the issuer via a JOIN on
	// managed_certificates. Returns the version (PEMChain, NotBefore,
	// NotAfter, etc.) — used by the ACME serial-only revoke path to
	// recover the leaf-cert DER when the operator no longer has the
	// PEM in hand. Returns sql.ErrNoRows when no match exists.
	GetVersionBySerial(ctx context.Context, issuerID, serial string) (*domain.CertificateVersion, error)
}

// RevocationRepository defines operations for managing certificate revocations.
type RevocationRepository interface {
	// Create records a new certificate revocation. Uniqueness is scoped to
	// (issuer_id, serial_number) per RFC 5280 §5.2.3, so duplicate serials
	// across different issuers are permitted.
	Create(ctx context.Context, revocation *domain.CertificateRevocation) error
	// CreateWithTx records a revocation using the supplied Querier
	// (typically *sql.Tx from postgres.WithinTx). Closes the audit-
	// atomicity blocker for the revocation path: the
	// certificate_revocations row must be atomic with the
	// managed_certificates status update + audit row insert.
	CreateWithTx(ctx context.Context, q Querier, revocation *domain.CertificateRevocation) error
	// GetByIssuerAndSerial retrieves a revocation by the (issuer_id, serial_number)
	// pair. Callers (OCSP, CRL generation) always know the issuer because
	// protocol endpoints carry it in the request path; RFC 5280 §5.2.3 guarantees
	// uniqueness only within a single issuer.
	GetByIssuerAndSerial(ctx context.Context, issuerID, serial string) (*domain.CertificateRevocation, error)
	// ListAll returns all revocations, ordered by revocation time (for global
	// revocation admin views). CRL generation should prefer ListByIssuer to
	// avoid loading and discarding rows that belong to other issuers.
	ListAll(ctx context.Context) ([]*domain.CertificateRevocation, error)
	// ListByIssuer returns revocations for a single issuer, ordered by revocation
	// time (for CRL generation). Pushing the issuer filter into the query lets
	// the migration 000012 composite index (issuer_id, serial_number) drive a
	// prefix scan instead of a full table read + in-memory filter.
	ListByIssuer(ctx context.Context, issuerID string) ([]*domain.CertificateRevocation, error)
	// ListByCertificate returns all revocations for a certificate.
	ListByCertificate(ctx context.Context, certID string) ([]*domain.CertificateRevocation, error)
	// MarkIssuerNotified updates the issuer_notified flag for a revocation.
	MarkIssuerNotified(ctx context.Context, id string) error
}

// CRLCacheRepository persists pre-generated CRLs so the
// /.well-known/pki/crl/{issuer_id} endpoint can serve from cache rather
// than regenerating per request. Populated by the scheduler's
// crlGenerationLoop (internal/scheduler) and read by the
// CRLCacheService (internal/service/crl_cache.go) on every CRL fetch.
//
// Schema lives in migrations/000019_crl_cache.up.sql.
type CRLCacheRepository interface {
	// Get returns the cached CRL for an issuer, or a nil entry +
	// nil error when no cache row exists yet (caller treats this as a
	// miss and triggers an immediate generation).
	Get(ctx context.Context, issuerID string) (*domain.CRLCacheEntry, error)

	// Put inserts or replaces the cache row for an issuer. The DB's
	// PRIMARY KEY on issuer_id collapses the upsert to a single
	// statement (ON CONFLICT DO UPDATE).
	Put(ctx context.Context, entry *domain.CRLCacheEntry) error

	// NextCRLNumber atomically returns the next CRL number for an
	// issuer (1 if the issuer has never had a CRL, else max+1). RFC
	// 5280 §5.2.3 requires CRL numbers be monotonically increasing
	// within an issuer; the atomic-fetch-then-store happens inside a
	// single SQL statement so concurrent generations of the same
	// issuer can't produce duplicate numbers.
	NextCRLNumber(ctx context.Context, issuerID string) (int64, error)

	// RecordGenerationEvent appends a row to crl_generation_events.
	// Both successful and failed generations get an event so operators
	// can grep for "why isn't this issuer's CRL refreshing." Event ID
	// is set by the DB (BIGSERIAL); callers do not pre-assign it.
	RecordGenerationEvent(ctx context.Context, evt *domain.CRLGenerationEvent) error

	// ListGenerationEvents returns the most recent N events for an
	// issuer, newest first. Used by the GUI's per-issuer "recent
	// generations" panel.
	ListGenerationEvents(ctx context.Context, issuerID string, limit int) ([]*domain.CRLGenerationEvent, error)
}

// OCSPResponseCacheRepository persists pre-signed OCSP responses so the
// /.well-known/pki/ocsp/{issuer_id}/{serial_hex} endpoint can serve
// from cache rather than triggering a fresh signature per request.
// Populated by the scheduler's ocspCacheRefreshLoop and read by the
// OCSPResponseCacheService (internal/service/ocsp_response_cache.go) on
// every OCSP fetch via a read-through facade.
//
// Schema lives in migrations/000024_ocsp_response_cache.up.sql.
// Production hardening II Phase 2.
type OCSPResponseCacheRepository interface {
	// Get returns the cached response for (issuer, serial), or
	// (nil, nil) on miss so the caller falls through to live signing.
	Get(ctx context.Context, issuerID, serialHex string) (*domain.OCSPResponseCacheEntry, error)

	// Put upserts the cache row. ON CONFLICT replaces every field so
	// a re-sign atomically swaps without a window where the row is
	// stale.
	Put(ctx context.Context, entry *domain.OCSPResponseCacheEntry) error

	// Delete removes a single cache row. Called by
	// InvalidateOnRevoke after a successful revocation so the next
	// fetch triggers a fresh signature with the updated status. The
	// load-bearing security wire — without it, a revoked cert keeps
	// returning the stale "good" cached response until the next
	// scheduler tick.
	Delete(ctx context.Context, issuerID, serialHex string) error

	// CountByIssuer returns the per-issuer cached entry count for the
	// admin observability endpoint.
	CountByIssuer(ctx context.Context) (map[string]int, error)
}

// OCSPResponderRepository persists per-issuer OCSP-responder cert + key
// pointers for the dedicated-responder-cert flow (RFC 6960 §2.6 +
// §4.2.2.2). One row per issuer; rotation overwrites in place.
//
// Schema lives in migrations/000020_ocsp_responder.up.sql.
type OCSPResponderRepository interface {
	// Get returns the current responder for an issuer, or (nil, nil)
	// when no row exists yet (caller treats as "needs bootstrap").
	Get(ctx context.Context, issuerID string) (*domain.OCSPResponder, error)

	// Put inserts or replaces the responder row for an issuer. ON
	// CONFLICT updates every field so a rotation atomically replaces
	// the prior cert without a window where the row is missing.
	Put(ctx context.Context, responder *domain.OCSPResponder) error

	// ListExpiring returns responders whose not_after is within the
	// given grace window (used by the rotation scheduler to find
	// responders due for rotation).
	ListExpiring(ctx context.Context, grace time.Duration, now time.Time) ([]*domain.OCSPResponder, error)
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
	// List returns all ACTIVE agents — rows with retired_at IS NULL.
	//
	// I-004: The default listing MUST NOT surface retired agents. The
	// handler-facing ListAgents call, the stats dashboard, and the stale-offline
	// sweeper all iterate this list and would otherwise re-surface decommissioned
	// hardware in operational UI. Callers that genuinely want retired rows (the
	// audit tab, compliance exports) must use ListRetired instead.
	//
	// The partial index idx_agents_retired_at (migration 000015) keeps retired
	// rows cheap to exclude — the planner uses it to skip the retired segment
	// of the table entirely.
	List(ctx context.Context) ([]*domain.Agent, error)
	// ListRetired returns a paginated list of retired agents (retired_at IS NOT NULL),
	// ordered by retired_at DESC so the most recent retirements appear first. Used
	// by the GUI's Retired tab and the audit export path. Returns the slice plus
	// the total count (for pagination). A page<1 or perPage<1 is clamped to sensible
	// defaults (page=1, perPage=50) in the repo implementation rather than erroring —
	// this matches the ListAgents pagination behavior in the service layer.
	// I-004 coverage-gap closure, migration 000015.
	ListRetired(ctx context.Context, page, perPage int) ([]*domain.Agent, int, error)
	// Get retrieves an agent by ID.
	//
	// I-004 note: Get returns retired rows (retired_at IS NOT NULL) because
	// callers that need to check "has this agent been retired?" — the heartbeat
	// handler returning 410 Gone, the retirement service's idempotent-retire
	// branch, the detail page rendering a retirement banner — must see the
	// retired_at/retired_reason fields. Only the default List path default-
	// excludes retired; individual Get lookups surface them.
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
	//
	// I-004: callers should prefer SoftRetire / RetireAgentWithCascade for the
	// operator-facing retirement path; hard Delete remains available for test
	// cleanup and repository-level administrative tasks. The deployment_targets
	// FK flipped to ON DELETE RESTRICT in migration 000015, so hard-deleting an
	// agent that still owns active targets will now fail at the DB layer — which
	// is intentional: the fail-closed guardrail prevents audit-trail destruction.
	Delete(ctx context.Context, id string) error
	// UpdateHeartbeat updates the agent's last heartbeat timestamp and metadata.
	//
	// I-004: UpdateHeartbeat is a no-op on retired agents — the UPDATE clause
	// includes AND retired_at IS NULL so a stale agent process that keeps polling
	// after retirement cannot resurrect its heartbeat. The service layer already
	// short-circuits with ErrAgentRetired before calling this method; the WHERE
	// filter here is belt-and-braces for anyone who skips the service path.
	UpdateHeartbeat(ctx context.Context, id string, metadata *domain.AgentMetadata) error
	// GetByAPIKey retrieves an agent by hashed API key.
	//
	// I-004: GetByAPIKey returns retired rows so the auth middleware can detect
	// "this API key belongs to a retired agent" and fail the request with
	// 410 Gone. If retired rows were hidden, auth would return a plain 401 and
	// leak no signal — which is wrong: the operator needs the retired state
	// made explicit so they can clean up the agent process.
	GetByAPIKey(ctx context.Context, keyHash string) (*domain.Agent, error)
	// SoftRetire stamps retired_at + retired_reason on the agent row with no
	// cascade. Used on the happy path where preflight confirmed the agent has
	// zero active dependencies (no active deployment_targets, no pending jobs).
	// The UPDATE is scoped to WHERE id=$1 AND retired_at IS NULL so re-retiring
	// an already-retired row is a no-op (zero rows affected is NOT returned as
	// an error — the service layer detects this via its own idempotent-retire
	// branch before calling SoftRetire). Callers supply retiredAt so the service
	// can pin a single consistent timestamp across audit + DB writes.
	// I-004 coverage-gap closure.
	SoftRetire(ctx context.Context, id string, retiredAt time.Time, reason string) error
	// RetireAgentWithCascade performs a transactional retire + cascade. In one
	// transaction it: (1) stamps retired_at + retired_reason on the agent row,
	// and (2) stamps the SAME retired_at + retired_reason on every active
	// deployment_targets row whose agent_id matches. Only rows with
	// retired_at IS NULL are touched in (2) — already-retired targets keep their
	// original retirement metadata (whoever retired them first, whenever). Used
	// exclusively on the force=true path from the retirement handler; callers
	// supply retiredAt so the agent row and every cascaded target row share an
	// exact retirement instant (helps forensic analysis trace the cascade back
	// to a single operator action). If the agent row is already retired, the
	// whole operation is a no-op — the transaction commits without touching
	// either table. I-004 coverage-gap closure, migration 000015.
	RetireAgentWithCascade(ctx context.Context, id string, retiredAt time.Time, reason string) error
	// CountActiveTargets returns the number of deployment_targets rows where
	// agent_id=id AND retired_at IS NULL. The COUNT query hits the existing
	// idx_deployment_targets_agent_id index (migration 000001 line 111); the
	// additional retired_at IS NULL predicate is cheap because the partial
	// idx_deployment_targets_retired_at index (migration 000015) lets the
	// planner skip the retired-row segment entirely. Preflight uses this to
	// decide 200 (soft-retire) vs 409 (blocked-by-deps). I-004.
	CountActiveTargets(ctx context.Context, agentID string) (int, error)
	// CountActiveCertificates returns the count of managed_certificates currently
	// deployed through one of this agent's ACTIVE (non-retired) deployment_targets.
	// The query joins certificate_target_mappings (migration 000001 line 116) →
	// deployment_targets filtering on deployment_targets.agent_id=$1 AND
	// deployment_targets.retired_at IS NULL, then COUNT(DISTINCT certificate_id)
	// so the same cert deployed to multiple targets on one agent counts once.
	// The primary key (certificate_id, target_id) on certificate_target_mappings
	// plus idx_certificate_target_mappings_target_id (line 122) cover the join.
	// Used purely for the preflight 409 body — the number is informational. I-004.
	CountActiveCertificates(ctx context.Context, agentID string) (int, error)
	// CountPendingJobs returns the number of jobs belonging to this agent whose
	// status is in (Pending, AwaitingCSR, AwaitingApproval, Running) — the four
	// statuses that indicate work the agent would still be expected to pick up.
	// Completed/Failed/Cancelled jobs do not count. The filter agent_id=$1 hits
	// the idx_jobs_agent_id index (migration 000001 line 161). Used for the
	// preflight 409 body. I-004.
	CountPendingJobs(ctx context.Context, agentID string) (int, error)
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
	// ListTimedOutAwaitingJobs returns jobs stuck in AwaitingCSR (created before csrCutoff) or
	// AwaitingApproval (created before approvalCutoff). The reaper loop transitions them to
	// Failed; I-001's retry loop then auto-promotes eligible Failed jobs back to Pending.
	// I-003 coverage-gap closure.
	ListTimedOutAwaitingJobs(ctx context.Context, csrCutoff, approvalCutoff time.Time) ([]*domain.Job, error)

	// ListJobsWithOfflineAgents returns jobs in Running status whose owning
	// agent's last_heartbeat_at is older than agentCutoff. Bundle C / Audit
	// M-016 (CWE-754): the existing ListTimedOutAwaitingJobs scope only
	// covers AwaitingCSR / AwaitingApproval — jobs that were claimed by an
	// agent and then stalled because the agent itself died (host crash,
	// container OOM, network partition) sit in Running indefinitely with
	// no recovery path. The reaper loop transitions these to Failed with
	// reason "agent_offline" so I-001's retry loop can re-queue them on
	// a healthy agent.
	ListJobsWithOfflineAgents(ctx context.Context, agentCutoff time.Time) ([]*domain.Job, error)
}

// RenewalPolicyRepository defines operations for managing renewal policies.
//
// G-1: extended with Create/Update/Delete so the new /api/v1/renewal-policies
// CRUD surface has a repo contract to lean on. Delete must map the PostgreSQL
// 23503 (foreign_key_violation on managed_certificates.renewal_policy_id
// REFERENCES renewal_policies(id) ON DELETE RESTRICT) onto the typed
// ErrRenewalPolicyInUse sentinel so the handler can emit a 409 Conflict
// instead of an opaque 500. Create/Update map PostgreSQL 23505
// (unique_violation on renewal_policies.name) onto ErrRenewalPolicyDuplicateName
// for the same 409 Conflict reason.
//
// List stays single-shot (no pagination params) because the production row
// count is in the single digits — the service layer paginates/sorts in Go.
// Changing the signature would churn every mock without functional benefit.
type RenewalPolicyRepository interface {
	// Get retrieves a renewal policy by ID.
	Get(ctx context.Context, id string) (*domain.RenewalPolicy, error)
	// List returns all renewal policies, ordered by name.
	List(ctx context.Context) ([]*domain.RenewalPolicy, error)
	// Create inserts a new renewal policy. The caller is responsible for
	// populating Name; Create auto-generates ID (as rp-<slug(name)>) if empty.
	// Returns ErrRenewalPolicyDuplicateName on pg 23505.
	Create(ctx context.Context, policy *domain.RenewalPolicy) error
	// Update modifies an existing renewal policy in-place. Returns
	// sql.ErrNoRows-wrapped error when id is unknown, or
	// ErrRenewalPolicyDuplicateName on pg 23505 (name collision with another row).
	Update(ctx context.Context, id string, policy *domain.RenewalPolicy) error
	// Delete removes a renewal policy. Returns ErrRenewalPolicyInUse when the
	// policy is still referenced by rows in managed_certificates (pg 23503).
	Delete(ctx context.Context, id string) error
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
//
// Atomicity contract (closes the #3 acquisition-readiness blocker from the
// 2026-05-01 issuer coverage audit, Part 1.5 finding #1): callers that
// emit an audit row as part of a logical operation (issuance, renewal,
// revocation) MUST use CreateWithTx and pass the same *sql.Tx that wraps
// the operation's other writes. The bare Create method exists only for
// stand-alone admin operations that do not have a paired state change
// (manual audit entry, system events that are themselves the only
// state change). Callers using the bare method MUST NOT rely on its
// behavior for compliance-relevant audit trails — those go through
// CreateWithTx + WithinTx.
//
// SOX §404 over IT general controls, PCI-DSS §10 audit logging, HIPAA
// §164.312(b) audit controls, and CA/B Forum Baseline Requirements
// §5.4.1 audit log records all presume audit-with-operation atomicity.
type AuditRepository interface {
	// Create stores a new audit event using the repository's package-
	// level *sql.DB. Use CreateWithTx when the audit event must be
	// atomic with another database operation in a service-layer
	// transaction.
	Create(ctx context.Context, event *domain.AuditEvent) error
	// CreateWithTx stores a new audit event using the supplied Querier.
	// Pass *sql.Tx (typically from postgres.WithinTx) to participate in
	// a caller's transaction. Closes the audit-atomicity blocker.
	CreateWithTx(ctx context.Context, q Querier, event *domain.AuditEvent) error
	// List returns audit events matching the filter criteria.
	List(ctx context.Context, filter *AuditFilter) ([]*domain.AuditEvent, error)
}

// NotificationRepository defines operations for managing notifications.
//
// I-005 extends the interface with four retry/DLQ methods. The retry scheduler
// loop calls ListRetryEligible on every tick to pull overdue failed rows, then
// either RecordFailedAttempt (still-retrying) or MarkAsDead (exhausted). The
// operator-facing dead-letter tab calls Requeue to move a row from 'dead' (or
// 'failed') back to 'pending' so ProcessPendingNotifications picks it up again.
type NotificationRepository interface {
	// Create stores a new notification.
	Create(ctx context.Context, notif *domain.NotificationEvent) error
	// List returns notifications matching the filter criteria.
	List(ctx context.Context, filter *NotificationFilter) ([]*domain.NotificationEvent, error)
	// UpdateStatus updates a notification's delivery status.
	UpdateStatus(ctx context.Context, id string, status string, sentAt time.Time) error
	// ListRetryEligible returns failed notification rows whose next_retry_at
	// is <= now AND retry_count < maxAttempts, ordered by next_retry_at ASC
	// (oldest overdue first — same fairness as I-001's RetryFailedJobs). The
	// WHERE clause mirrors the partial retry-sweep index predicate from
	// migration 000016 so the planner uses it. A limit<=0 is normalised to
	// a sane default in the repo implementation to avoid accidental unbounded
	// sweeps. I-005 coverage-gap closure.
	ListRetryEligible(ctx context.Context, now time.Time, maxAttempts, limit int) ([]*domain.NotificationEvent, error)
	// RecordFailedAttempt is called by the retry sweep after a notifier.Send
	// transient failure. The UPDATE increments retry_count by exactly 1,
	// overwrites last_error, overwrites next_retry_at, and KEEPS status='failed'
	// so the row remains a candidate for ListRetryEligible on the next sweep.
	// Returns "not found" when no row matches the id (mirrors UpdateStatus).
	// I-005 coverage-gap closure.
	RecordFailedAttempt(ctx context.Context, id string, lastError string, nextRetryAt time.Time) error
	// MarkAsDead performs the DLQ transition when retry_count reaches
	// max_attempts. Flips status='dead', clears next_retry_at so the partial
	// retry-sweep index drops the row, writes the final last_error, and
	// PRESERVES retry_count as historical evidence of how many attempts were
	// burned. Returns "not found" when no row matches.
	// I-005 coverage-gap closure.
	MarkAsDead(ctx context.Context, id string, lastError string) error
	// Requeue is the operator "try again" action from the UI's Dead letter
	// tab. Flips status='pending' (so ProcessPendingNotifications picks it
	// up), resets retry_count to 0 (otherwise the operator's first retry
	// would already be at hour-long waits), clears next_retry_at, and clears
	// last_error. Valid from both 'dead' and 'failed'. Returns "not found"
	// when no row matches. I-005 coverage-gap closure.
	Requeue(ctx context.Context, id string) error
	// CountByStatus returns the number of notification_events rows whose
	// status column matches the given string exactly. Used by StatsService
	// to populate DashboardSummary.NotificationsDead which in turn drives
	// the Prometheus counter certctl_notification_dead_total (I-005 Phase 2
	// observability gate). A dedicated SQL COUNT(*) is used instead of
	// List(filter{Status: ...}) because List silently resets PerPage>500 to
	// 50 — a latent scale bug for any status-filtered count. I-005
	// coverage-gap closure.
	CountByStatus(ctx context.Context, status string) (int64, error)
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

// SCEPProbeResultRepository persists per-run SCEP probe snapshots.
//
// SCEP RFC 8894 + Intune master bundle Phase 11.5. The probe is a
// pre-migration / compliance-posture tool — operators run it ad-hoc
// against arbitrary SCEP server URLs and the GUI shows recent history.
// No FK to network_scan_targets — probe targets are URLs, not necessarily
// network-scan-target rows.
type SCEPProbeResultRepository interface {
	// Insert persists a single probe outcome.
	Insert(ctx context.Context, result *domain.SCEPProbeResult) error
	// ListRecent returns the most recent N probe results across any URL,
	// ordered by probed_at descending. Used by the GUI's "recent probes"
	// table on the Network Scan page.
	ListRecent(ctx context.Context, limit int) ([]*domain.SCEPProbeResult, error)
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

// ApprovalRepository defines operations for managing issuance approval requests.
// Rank 7 of the 2026-05-03 Infisical deep-research deliverable — closes the
// two-person integrity / four-eyes principle procurement gap for PCI-DSS
// Level 1, FedRAMP Moderate / High, SOC 2 Type II, HIPAA-regulated PHI.
//
// Lifecycle: Create inserts a row at state=pending; UpdateState transitions
// to one of (approved, rejected, expired) with the decider identity +
// timestamp + optional note; ExpireStale is the bulk reaper called from
// the scheduler. Once terminal, rows are immutable via the
// approval_decision_consistency CHECK constraint at the schema layer.
type ApprovalRepository interface {
	// Create inserts a new ApprovalRequest at state=pending. Returns
	// ErrAlreadyExists if a pending request already exists for the
	// job_id (the partial-unique index enforces at most one pending
	// per job).
	Create(ctx context.Context, req *domain.ApprovalRequest) error

	// Get returns the request by ID or ErrNotFound.
	Get(ctx context.Context, id string) (*domain.ApprovalRequest, error)

	// GetByJobID returns the most-recently-created request for the
	// given job_id, regardless of state. Used by the renewal entry
	// point to detect "is there already a pending approval for this
	// job?" and avoid creating a duplicate.
	GetByJobID(ctx context.Context, jobID string) (*domain.ApprovalRequest, error)

	// List returns approval requests filtered by ApprovalFilter.
	// Supports paginated dashboard queries.
	List(ctx context.Context, filter *ApprovalFilter) ([]*domain.ApprovalRequest, error)

	// UpdateState transitions a row from state=pending to one of
	// (approved, rejected, expired). Returns ErrNotFound if the ID
	// does not exist; returns the schema's CHECK-violation as a
	// repository error if the row is already terminal.
	UpdateState(ctx context.Context, id string, state domain.ApprovalState,
		decidedBy string, decidedAt time.Time, note string) error

	// ExpireStale transitions every row with state=pending and
	// created_at <= before to state=expired. Returns the number of
	// rows transitioned. Called from the scheduler reaper loop.
	ExpireStale(ctx context.Context, before time.Time) (int, error)
}

// ApprovalFilter filters approval-request queries.
type ApprovalFilter struct {
	// State filters by lifecycle state (pending, approved, rejected, expired).
	State string
	// CertificateID filters by managed certificate ID.
	CertificateID string
	// RequestedBy filters to requests created by the given actor.
	RequestedBy string
	// Page is the page number (1-indexed).
	Page int
	// PerPage is the number of results per page.
	PerPage int
}

// IntermediateCARepository defines operations for managing first-class
// CA hierarchies (Rank 8). Every non-root CA is a row, parent_ca_id
// encodes the tree, WalkAncestry returns the leaf-to-root chain via
// a recursive CTE.
//
// Defense in depth: NEVER persist CA private key bytes. The
// implementation stores key_driver_id (a signer.Driver reference) only.
type IntermediateCARepository interface {
	Create(ctx context.Context, ca *domain.IntermediateCA) error
	Get(ctx context.Context, id string) (*domain.IntermediateCA, error)
	ListByIssuer(ctx context.Context, issuerID string) ([]*domain.IntermediateCA, error)
	ListChildren(ctx context.Context, parentCAID string) ([]*domain.IntermediateCA, error)
	UpdateState(ctx context.Context, id string, state domain.IntermediateCAState) error
	GetActiveRoot(ctx context.Context, issuerID string) (*domain.IntermediateCA, error)
	// WalkAncestry returns the chain from leafID up to (and including)
	// the root via a postgres recursive CTE. The slice is ordered
	// leaf-first; caller verifies the last element has parent_ca_id
	// IS NULL (i.e., it's a root). Returns ErrNotFound if leafID does
	// not exist.
	WalkAncestry(ctx context.Context, leafID string) ([]*domain.IntermediateCA, error)
}
