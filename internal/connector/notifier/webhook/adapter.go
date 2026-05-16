// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package webhook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/certctl-io/certctl/internal/connector/notifier"
)

// NotifierAdapter bridges the rich notifier.Connector interface
// (SendAlert / SendEvent / ValidateConfig) to the simpler service-
// layer service.Notifier interface (Send + Channel) used by the
// notification service for per-recipient expiry alerts + threshold
// notifications.
//
// Acquisition-audit DOC-001 closure (Sprint 7 ACQ, 2026-05-16).
// Pre-Sprint-7 the webhook notifier was a complete impl with full
// SSRF guard + HMAC-SHA256 signing + tests, but it was never wired
// in cmd/server/main.go — README claimed "6 notifiers" while only 5
// were actually registered. This adapter closes the wire gap so the
// "6 notifiers" claim is accurate. Mirrors the
// notifyemail.NotifierAdapter pattern.
//
// Method semantics:
//
//	Send(ctx, recipient, subject, body) — constructs a
//	notifier.Event with the three fields populated + a fresh
//	random ID + the current UTC timestamp, then delegates to
//	the underlying Connector's SendEvent. The webhook payload
//	the recipient sees is the canonical {id, type, recipient,
//	subject, body, metadata, created_at} JSON shape — same
//	shape ValidateConfig probes for.
//
//	Channel() — returns "webhook" so the notification service's
//	per-channel routing matches the operator's
//	CERTCTL_WEBHOOK_URL configuration.
//
// The Connector's per-request HMAC-SHA256 signing + SafeHTTPDialContext
// SSRF guard apply transitively — every Send call routes through
// SendEvent which routes through postWebhook which applies both
// defenses. No defense duplication is needed at the adapter layer.
type NotifierAdapter struct {
	c *Connector
}

// NewNotifierAdapter wraps a fully-configured webhook Connector for
// use as a service.Notifier. The Connector MUST be constructed via
// webhook.New (production) — newForTest is rejected by Go's package
// visibility from outside the webhook package, so production callers
// cannot accidentally adapt a permissive-validator connector.
func NewNotifierAdapter(c *Connector) *NotifierAdapter {
	return &NotifierAdapter{c: c}
}

// Channel returns the channel identifier used by the notification
// service's per-channel routing map.
func (a *NotifierAdapter) Channel() string {
	return "webhook"
}

// Send delivers a notification by translating the service-layer
// {recipient, subject, body} tuple into a notifier.Event and
// delegating to the underlying Connector's SendEvent. The Event
// carries a fresh 16-hex random ID (NOT a UUID — no extra dep
// needed; 128 bits of entropy is enough for de-dup at the receiver
// without colliding) and the current UTC time.
//
// The webhook recipient sees a JSON body like:
//
//	{
//	  "id": "...",
//	  "type": "notification",
//	  "recipient": "<recipient>",
//	  "subject": "<subject>",
//	  "body": "<body>",
//	  "created_at": "<RFC3339>"
//	}
//
// signed with HMAC-SHA256 in the X-Webhook-Signature header (when
// CERTCTL_WEBHOOK_SECRET is set).
func (a *NotifierAdapter) Send(ctx context.Context, recipient string, subject string, body string) error {
	event := notifier.Event{
		ID:        adapterEventID(),
		Type:      "notification",
		Recipient: recipient,
		Subject:   subject,
		Body:      body,
		CreatedAt: time.Now().UTC(),
	}
	return a.c.SendEvent(ctx, event)
}

// adapterEventID returns a 32-character hex random ID for the
// adapter-side event. 16 bytes from crypto/rand is enough for de-
// duplication at the webhook recipient without adding a UUID
// dependency (we already use crypto/rand transitively).
func adapterEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
