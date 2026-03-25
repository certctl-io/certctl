package repository

import "time"

// CertificateFilter defines filtering criteria for certificate queries.
type CertificateFilter struct {
	Status      string // e.g., "active", "expiring", "expired", "archived"
	Environment string // e.g., "production", "staging", "development"
	OwnerID     string
	TeamID      string
	IssuerID    string
	AgentID     string // filter by agent_id (via deployment targets)
	ProfileID   string // filter by certificate_profile_id
	Page        int    // 1-indexed; default 1
	PerPage     int    // default 50, max 500

	// Time-range filters
	ExpiresBefore *time.Time // certs expiring before this date
	ExpiresAfter  *time.Time // certs expiring after this date
	CreatedAfter  *time.Time // certs created after this date
	UpdatedAfter  *time.Time // certs updated after this date

	// Sorting
	Sort     string // field name to sort by (e.g., "notAfter", "createdAt", "commonName")
	SortDesc bool   // true = DESC, false = ASC

	// Cursor pagination (alternative to page-based)
	Cursor   string // opaque cursor token (base64-encoded "created_at:id")
	PageSize int    // for cursor-based pagination (alias for PerPage)

	// Sparse fields
	Fields []string // if non-empty, only return these JSON field names
}

// JobFilter defines filtering criteria for job queries.
type JobFilter struct {
	Status        string // e.g., "pending", "in-progress", "completed", "failed"
	Type          string // e.g., "renewal", "deployment"
	CertificateID string
	Page          int
	PerPage       int
}

// AuditFilter defines filtering criteria for audit event queries.
type AuditFilter struct {
	Actor        string // username or service ID
	ActorType    string // "user", "agent", "system"
	ResourceType string // e.g., "certificate", "policy", "agent"
	ResourceID   string
	From         time.Time
	To           time.Time
	Page         int
	PerPage      int
}

// NotificationFilter defines filtering criteria for notification queries.
type NotificationFilter struct {
	CertificateID string // optional: filter by certificate
	Type          string // optional: filter by notification type (e.g., "ExpirationWarning")
	Status        string // e.g., "pending", "sent", "failed"
	Channel       string // e.g., "email", "slack", "webhook"
	MessageLike   string // optional: LIKE match on message content (for threshold dedup)
	Page          int
	PerPage       int
}
