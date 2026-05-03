package domain

import (
	"time"
)

// ManagedCertificate represents a certificate managed by the control plane.
type ManagedCertificate struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	CommonName           string            `json:"common_name"`
	SANs                 []string          `json:"sans"`
	Environment          string            `json:"environment"`
	OwnerID              string            `json:"owner_id"`
	TeamID               string            `json:"team_id"`
	IssuerID             string            `json:"issuer_id"`
	TargetIDs            []string          `json:"target_ids"`
	RenewalPolicyID      string            `json:"renewal_policy_id"`
	CertificateProfileID string            `json:"certificate_profile_id,omitempty"`
	Status               CertificateStatus `json:"status"`
	ExpiresAt            time.Time         `json:"expires_at"`
	Tags                 map[string]string `json:"tags"`
	LastRenewalAt        *time.Time        `json:"last_renewal_at,omitempty"`
	LastDeploymentAt     *time.Time        `json:"last_deployment_at,omitempty"`
	RevokedAt            *time.Time        `json:"revoked_at,omitempty"`
	RevocationReason     string            `json:"revocation_reason,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`

	// Source tags how this managed certificate was created. EST RFC 7030
	// hardening master bundle Phase 11.1 — operators bulk-revoke
	// EST-issued certs by filtering on Source=EST. Empty value preserves
	// the v2.X.0 behavior (the bulk-revoke handler treats empty as
	// equivalent to legacy/manual; new EST issuances stamp Source=EST,
	// new SCEP issuances will eventually stamp Source=SCEP under a
	// future bundle).
	Source CertificateSource `json:"source,omitempty"`
}

// CertificateSource is the enum of provenance values stamped on each
// managed-certificate row when it's created. The empty string is the
// back-compat default — pre-Phase-11 rows have it set to "" by the
// migration's DEFAULT clause; the bulk-revoke filter treats empty as
// "any source" so existing call paths see no behavior change.
//
// EST RFC 7030 hardening master bundle Phase 11.1.
type CertificateSource string

const (
	// CertificateSourceUnspecified preserves the v2.X.0 default ("").
	CertificateSourceUnspecified CertificateSource = ""
	// CertificateSourceEST stamps every cert issued through one of the
	// EST endpoints (simpleenroll / simplereenroll / serverkeygen).
	CertificateSourceEST CertificateSource = "EST"
	// CertificateSourceSCEP / API / Agent reserve future provenance
	// values — not stamped today; SCEP-issued certs continue to land
	// with Source="" until a follow-up bundle wires the stamp at the
	// SCEP service layer.
	CertificateSourceSCEP  CertificateSource = "SCEP"
	CertificateSourceAPI   CertificateSource = "API"
	CertificateSourceAgent CertificateSource = "Agent"
	// CertificateSourceACME stamps every cert issued through the
	// built-in ACME server endpoint (RFC 8555 finalize → cert
	// download). The ACME service (internal/service/acme.go)
	// pins this on every managed_certificates row it inserts at
	// finalize time. Operators bulk-revoke ACME-issued certs by
	// filtering on Source=ACME.
	CertificateSourceACME CertificateSource = "ACME"
)

// CertificateVersion represents a specific version of a certificate.
type CertificateVersion struct {
	ID                string    `json:"id"`
	CertificateID     string    `json:"certificate_id"`
	SerialNumber      string    `json:"serial_number"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	PEMChain          string    `json:"pem_chain"`
	CSRPEM            string    `json:"csr_pem"`
	KeyAlgorithm      string    `json:"key_algorithm,omitempty"`
	KeySize           int       `json:"key_size,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

// CertificateStatus represents the lifecycle status of a managed certificate.
type CertificateStatus string

const (
	CertificateStatusPending           CertificateStatus = "Pending"
	CertificateStatusActive            CertificateStatus = "Active"
	CertificateStatusExpiring          CertificateStatus = "Expiring"
	CertificateStatusExpired           CertificateStatus = "Expired"
	CertificateStatusRenewalInProgress CertificateStatus = "RenewalInProgress"
	CertificateStatusFailed            CertificateStatus = "Failed"
	CertificateStatusRevoked           CertificateStatus = "Revoked"
	CertificateStatusArchived          CertificateStatus = "Archived"
)

// RenewalPolicy defines renewal parameters for a managed certificate.
type RenewalPolicy struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	RenewalWindowDays    int       `json:"renewal_window_days"`
	AutoRenew            bool      `json:"auto_renew"`
	MaxRetries           int       `json:"max_retries"`
	RetryInterval        int       `json:"retry_interval_seconds"`
	AlertThresholdsDays  []int     `json:"alert_thresholds_days"`
	CertificateProfileID string    `json:"certificate_profile_id,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`

	// AlertChannels is the per-policy channel-matrix that maps each
	// severity tier ("informational" / "warning" / "critical") to the
	// set of NotificationChannel values that receive expiry alerts at
	// that tier. Values are slices of channel-name strings matching
	// the NotificationChannel constants ("Email", "Slack", "Teams",
	// "PagerDuty", "OpsGenie", "Webhook"). nil or empty falls back to
	// DefaultAlertChannels (Email-only across all tiers, the pre-2026-05-03
	// behaviour preserved as the safe default for operators who have
	// not yet opted into multi-channel routing).
	//
	// Off-enum severity keys or channel values are silently dropped at
	// the dispatch site (closed-enum discipline; we do NOT dynamically
	// grow Prometheus cardinality on a typo).
	//
	// Rank 4 of the 2026-05-03 Infisical deep-research deliverable
	// (cowork/infisical-deep-research-results.md Part 5).
	AlertChannels map[string][]string `json:"alert_channels,omitempty"`

	// AlertSeverityMap maps each threshold-day value to its severity
	// tier. Off-map thresholds default to "informational". Operators
	// with non-default AlertThresholdsDays values supply their own
	// severity mapping; operators on the canonical 30/14/7/0 thresholds
	// can leave this empty to inherit DefaultAlertSeverityMap which
	// maps:
	//
	//   30 → informational
	//   14 → warning
	//    7 → warning
	//    0 → critical
	AlertSeverityMap map[int]string `json:"alert_severity_map,omitempty"`
}

// DefaultAlertThresholds returns the standard alert thresholds when none are configured.
func DefaultAlertThresholds() []int {
	return []int{30, 14, 7, 0}
}

// EffectiveAlertThresholds returns the configured thresholds or defaults if empty.
func (p *RenewalPolicy) EffectiveAlertThresholds() []int {
	if len(p.AlertThresholdsDays) > 0 {
		return p.AlertThresholdsDays
	}
	return DefaultAlertThresholds()
}

// Severity-tier names for the channel matrix. Closed-enum to keep
// Prometheus cardinality bounded and operator typos surfaceable in
// audit logs (off-enum tier values are dropped at dispatch).
const (
	AlertSeverityInformational = "informational"
	AlertSeverityWarning       = "warning"
	AlertSeverityCritical      = "critical"
)

// DefaultAlertChannels returns the back-compat default channel matrix
// — Email only at every tier. This preserves the pre-2026-05-03
// behaviour for operators who have not yet opted into multi-channel
// routing. Nil or empty AlertChannels on a RenewalPolicy is read as
// "use this default."
func DefaultAlertChannels() map[string][]string {
	return map[string][]string{
		AlertSeverityInformational: {string(NotificationChannelEmail)},
		AlertSeverityWarning:       {string(NotificationChannelEmail)},
		AlertSeverityCritical:      {string(NotificationChannelEmail)},
	}
}

// DefaultAlertSeverityMap returns the canonical threshold-to-tier
// mapping for the standard 30/14/7/0 thresholds. Operators with
// custom thresholds supply their own mapping.
func DefaultAlertSeverityMap() map[int]string {
	return map[int]string{
		30: AlertSeverityInformational,
		14: AlertSeverityWarning,
		7:  AlertSeverityWarning,
		0:  AlertSeverityCritical,
	}
}

// EffectiveAlertChannels returns the configured channel matrix on
// the policy, or the default if unset. Used by the dispatch site in
// RenewalService.sendThresholdAlerts to resolve the channel set for
// a given tier.
//
// A returned map is safe to mutate by the caller — the default-path
// branch returns a fresh map; the configured-path branch returns the
// caller-supplied map (which the caller already owns).
func (p *RenewalPolicy) EffectiveAlertChannels() map[string][]string {
	if p == nil || len(p.AlertChannels) == 0 {
		return DefaultAlertChannels()
	}
	return p.AlertChannels
}

// EffectiveAlertSeverity returns the severity tier for a given
// threshold. Off-map thresholds resolve to "informational" so a
// custom-thresholds policy without an explicit severity map still
// gets dispatch (just at the lowest tier).
func (p *RenewalPolicy) EffectiveAlertSeverity(threshold int) string {
	if p != nil {
		if tier, ok := p.AlertSeverityMap[threshold]; ok {
			return tier
		}
	}
	if tier, ok := DefaultAlertSeverityMap()[threshold]; ok {
		return tier
	}
	return AlertSeverityInformational
}

// IsValidAlertSeverityTier reports whether tier is one of the closed-enum
// severity values. Used by the policy validation path in
// service.RenewalPolicyService to reject typos at write time.
func IsValidAlertSeverityTier(tier string) bool {
	switch tier {
	case AlertSeverityInformational, AlertSeverityWarning, AlertSeverityCritical:
		return true
	}
	return false
}

// IsValidNotificationChannel reports whether channel is one of the
// closed-enum NotificationChannel values. Used by the policy
// validation path to reject typos at write time AND by the dispatch
// site to defensively drop off-enum values that survived a migration.
func IsValidNotificationChannel(channel string) bool {
	switch NotificationChannel(channel) {
	case NotificationChannelEmail, NotificationChannelWebhook,
		NotificationChannelSlack, NotificationChannelTeams,
		NotificationChannelPagerDuty, NotificationChannelOpsGenie:
		return true
	}
	return false
}
