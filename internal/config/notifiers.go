// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package config

// Phase 9 ARCH-M2 closure (2026-05-14): extracted from config.go to
// reduce the change-risk hotspot footprint of the giant config file
// (config.go pre-Phase-9 was 3,403 LOC, exceeding the < 500 LOC
// target). This file contains the NotifierConfig struct unchanged —
// every field, doc-comment, and exported name is byte-identical to
// the pre-split form. The struct lives in the same `config` package
// so every caller's `config.NotifierConfig` import path is preserved
// without modification.
//
// Public-surface invariant: any code importing
// `github.com/certctl-io/certctl/internal/config` reads
// `NotifierConfig` the same way before and after this split. The
// `go doc internal/config NotifierConfig` output is identical.

// NotifierConfig contains configuration for notification connectors.
// Each notifier is enabled by setting its required env var (webhook URL or API key).
type NotifierConfig struct {
	// SlackWebhookURL is the incoming webhook URL for Slack notifications.
	// Format: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
	// Optional: leave empty to disable Slack notifications.
	SlackWebhookURL string

	// SlackChannel optionally overrides the default channel in the Slack webhook.
	// Example: "#alerts" or "@user". Leave empty to use webhook's default channel.
	SlackChannel string

	// SlackUsername sets the display name for Slack bot messages.
	// Default: "certctl". Used in webhook message formatting.
	SlackUsername string

	// TeamsWebhookURL is the incoming webhook URL for Microsoft Teams notifications.
	// Format: https://outlook.webhook.office.com/webhookb2/...
	// Optional: leave empty to disable Teams notifications.
	TeamsWebhookURL string

	// PagerDutyRoutingKey is the integration key for PagerDuty Events API v2.
	// Obtain from PagerDuty integration settings.
	// Optional: leave empty to disable PagerDuty notifications.
	PagerDutyRoutingKey string

	// PagerDutySeverity sets the default severity level for PagerDuty events.
	// Valid values: "info", "warning", "error", "critical". Default: "warning".
	PagerDutySeverity string

	// OpsGenieAPIKey is the API key for OpsGenie Alert API v2.
	// Obtain from OpsGenie organization settings.
	// Optional: leave empty to disable OpsGenie notifications.
	OpsGenieAPIKey string

	// OpsGeniePriority sets the default priority for OpsGenie alerts.
	// Valid values: "P1", "P2", "P3", "P4", "P5". Default: "P3".
	OpsGeniePriority string

	// SMTPHost is the SMTP server hostname for sending email notifications.
	// Example: "smtp.gmail.com", "smtp.sendgrid.net". Required for email notifications.
	// Setting: CERTCTL_SMTP_HOST environment variable.
	SMTPHost string

	// SMTPPort is the SMTP server port. Default: 587 (STARTTLS).
	// Common values: 25 (plain), 465 (implicit TLS), 587 (STARTTLS).
	// Setting: CERTCTL_SMTP_PORT environment variable.
	SMTPPort int

	// SMTPUsername is the SMTP authentication username.
	// Setting: CERTCTL_SMTP_USERNAME environment variable.
	SMTPUsername string

	// SMTPPassword is the SMTP authentication password or app-specific password.
	// Setting: CERTCTL_SMTP_PASSWORD environment variable.
	SMTPPassword string

	// SMTPFromAddress is the sender email address for outbound notifications.
	// Example: "certctl@example.com", "noreply@company.com".
	// Setting: CERTCTL_SMTP_FROM_ADDRESS environment variable.
	SMTPFromAddress string

	// SMTPUseTLS enables TLS for the SMTP connection.
	// Default: true. Set to false for plain SMTP (not recommended).
	// Setting: CERTCTL_SMTP_USE_TLS environment variable.
	SMTPUseTLS bool

	// WebhookURL is the HTTP(S) endpoint for the generic webhook
	// notifier. Acquisition-audit DOC-001 closure (Sprint 7 ACQ,
	// 2026-05-16). When set, the cmd/server/main.go boot path
	// constructs an internal/connector/notifier/webhook.Connector
	// (full SafeHTTPDialContext SSRF guard + ValidateSafeURL pre-
	// flight + HMAC-SHA256 signing) wrapped in NotifierAdapter so
	// the simpler service.Notifier (Send + Channel) interface used
	// by the notification service receives a "webhook" channel
	// registration. Pre-Sprint-7 the impl existed in the tree but
	// was unwired — README claimed "6 notifiers" while only 5
	// were registered. Optional: leave empty to disable.
	// Setting: CERTCTL_WEBHOOK_URL environment variable.
	WebhookURL string

	// WebhookSecret is the HMAC-SHA256 shared secret used by the
	// webhook notifier to sign every outbound HTTP POST in the
	// X-Webhook-Signature header. The receiver verifies the signature
	// against the SAME secret before trusting the payload — without
	// this guard, any host that can reach the operator's webhook
	// endpoint could spoof certctl notifications. Optional but
	// strongly recommended; empty disables signing (operator-
	// acknowledged unsigned mode). Setting: CERTCTL_WEBHOOK_SECRET.
	WebhookSecret string
}
