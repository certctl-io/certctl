package domain

import (
	"time"
)

// NotificationEvent records a notification sent to users about certificate events.
//
// I-005 extends the event with a retry counter, a nullable next-retry timestamp
// that drives the retry-sweep partial index, and a nullable last-error string
// preserving the most recent transient failure so operators triaging the dead
// letter queue can see *why* a notification died without chasing server logs.
// Status stays a plain `string` (not retyped to NotificationStatus) because the
// repo layer materialises it directly from PostgreSQL's VARCHAR column and the
// service layer compares against the NotificationStatus* constants via
// `string(...)` casts at call sites — see service.RetryFailedNotifications.
type NotificationEvent struct {
	ID            string              `json:"id"`
	Type          NotificationType    `json:"type"`
	CertificateID *string             `json:"certificate_id,omitempty"`
	Channel       NotificationChannel `json:"channel"`
	Recipient     string              `json:"recipient"`
	Message       string              `json:"message"`
	SentAt        *time.Time          `json:"sent_at,omitempty"`
	Status        string              `json:"status"`
	Error         *string             `json:"error,omitempty"`
	RetryCount    int                 `json:"retry_count"`
	NextRetryAt   *time.Time          `json:"next_retry_at,omitempty"`
	LastError     *string             `json:"last_error,omitempty"`
	CreatedAt     time.Time           `json:"created_at"`
}

// NotificationStatus is the typed string alias for the lifecycle status of a
// NotificationEvent. It mirrors the VARCHAR(50) column on notification_events
// and the status values used by the I-005 retry/DLQ machinery.
//
// Status transitions:
//
//	pending → sent                 (delivery succeeded)
//	pending → failed → pending     (transient failure, re-armed by retry sweep)
//	pending → failed → dead        (retry_count reached max_attempts; DLQ)
//	pending → read                 (operator acknowledged, no delivery needed)
//
// Values are lowercase to match the pre-I-005 on-wire representation used by
// existing UpdateStatus calls and the seed_demo.sql fixtures; retyping
// NotificationEvent.Status to NotificationStatus would be a breaking DB scan
// change, so the type is kept additive and consumed via `string(const)` casts.
type NotificationStatus string

const (
	NotificationStatusPending NotificationStatus = "pending"
	NotificationStatusSent    NotificationStatus = "sent"
	NotificationStatusFailed  NotificationStatus = "failed"
	NotificationStatusDead    NotificationStatus = "dead"
	NotificationStatusRead    NotificationStatus = "read"
)

// NotificationType represents the event that triggered a notification.
type NotificationType string

const (
	NotificationTypeExpirationWarning NotificationType = "ExpirationWarning"
	NotificationTypeRenewalSuccess    NotificationType = "RenewalSuccess"
	NotificationTypeRenewalFailure    NotificationType = "RenewalFailure"
	NotificationTypeDeploymentSuccess NotificationType = "DeploymentSuccess"
	NotificationTypeDeploymentFailure NotificationType = "DeploymentFailure"
	NotificationTypePolicyViolation   NotificationType = "PolicyViolation"
	NotificationTypeRevocation        NotificationType = "Revocation"
)

// NotificationChannel represents the communication medium for a notification.
type NotificationChannel string

const (
	NotificationChannelEmail     NotificationChannel = "Email"
	NotificationChannelWebhook   NotificationChannel = "Webhook"
	NotificationChannelSlack     NotificationChannel = "Slack"
	NotificationChannelTeams     NotificationChannel = "Teams"
	NotificationChannelPagerDuty NotificationChannel = "PagerDuty"
	NotificationChannelOpsGenie  NotificationChannel = "OpsGenie"
)
