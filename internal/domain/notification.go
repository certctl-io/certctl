package domain

import (
	"time"
)

// NotificationEvent records a notification sent to users about certificate events.
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
	CreatedAt     time.Time           `json:"created_at"`
}

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
	NotificationChannelEmail   NotificationChannel = "Email"
	NotificationChannelWebhook NotificationChannel = "Webhook"
	NotificationChannelSlack   NotificationChannel = "Slack"
)
