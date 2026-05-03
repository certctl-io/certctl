package service

// Rank 4 of the 2026-05-03 Infisical deep-research deliverable
// (cowork/infisical-deep-research-results.md Part 5). Pins every leg of
// the per-policy multi-channel expiry-alert fan-out matrix:
//
//   1. Default matrix → Email-only at every tier (back-compat).
//   2. Per-tier fan-out — informational/warning/critical each route to
//      a different channel set; cert at 0 days remaining crosses all
//      four canonical thresholds; assert the exact recipient calls per
//      channel.
//   3. Per-(cert, threshold, channel) dedup — second loop tick produces
//      zero sends; deduped counter increments instead.
//   4. One-channel fails → others still fire; failure metric increments;
//      success metric increments for the channels that succeeded.
//   5. Off-enum channel typo dropped at dispatch + audit-row trail.
//   6. Metric counter increments for every (channel, threshold, result)
//      combination the loop produces.
//   7. Nil policy → default matrix (cert with no RenewalPolicy
//      attached).
//   8. Operator opt-out of a tier (empty list) — that tier fires zero
//      alerts; other tiers unaffected.

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// channelMockNotifier records (recipient, subject, body) per Send call.
// Replaces the simple mockNotifier from testutil_test.go for tests that
// need to verify which channel got which message — channelMockNotifier
// stamps every recorded message with its channel name so tests can
// distinguish Slack-vs-PagerDuty-vs-Email after a single fan-out.
type channelMockNotifier struct {
	mu       sync.Mutex
	channel  string
	messages []channelNotifierMsg
	sendErr  error
}

type channelNotifierMsg struct {
	Channel   string
	Recipient string
	Subject   string
	Body      string
}

func newChannelMockNotifier(channel string) *channelMockNotifier {
	return &channelMockNotifier{channel: channel}
}

func (m *channelMockNotifier) Send(ctx context.Context, recipient string, subject string, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.messages = append(m.messages, channelNotifierMsg{
		Channel:   m.channel,
		Recipient: recipient,
		Subject:   subject,
		Body:      body,
	})
	return nil
}

func (m *channelMockNotifier) Channel() string { return m.channel }

func (m *channelMockNotifier) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.messages)
}

// matrixFixture wires the full set of objects each per-tier-matrix test
// needs — six channel-aware notifiers, the metric recorder, the
// notification service, and the renewal service. Tests vary only the
// policy and the cert.
type matrixFixture struct {
	notifSvc   *NotificationService
	metrics    *ExpiryAlertMetrics
	rs         *RenewalService
	notifs     map[string]*channelMockNotifier
	notifRepo  *mockNotifRepo
	policyRepo *mockRenewalPolicyRepo
	certRepo   *mockCertRepo
	auditRepo  *mockAuditRepo
}

func newMatrixFixture(t *testing.T) *matrixFixture {
	t.Helper()

	notifs := map[string]*channelMockNotifier{
		"Email":     newChannelMockNotifier("Email"),
		"Slack":     newChannelMockNotifier("Slack"),
		"Teams":     newChannelMockNotifier("Teams"),
		"PagerDuty": newChannelMockNotifier("PagerDuty"),
		"OpsGenie":  newChannelMockNotifier("OpsGenie"),
		"Webhook":   newChannelMockNotifier("Webhook"),
	}

	registry := map[string]Notifier{}
	for k, n := range notifs {
		registry[k] = n
	}

	notifRepo := newMockNotificationRepository()
	notifSvc := NewNotificationService(notifRepo, registry)
	metrics := NewExpiryAlertMetrics()
	notifSvc.SetExpiryAlertMetrics(metrics)

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	policyRepo := newMockRenewalPolicyRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)

	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-test", &mockIssuerConnector{})

	rs := NewRenewalService(certRepo, jobRepo, policyRepo, nil, auditSvc, notifSvc, issuerRegistry, "server")

	return &matrixFixture{
		notifSvc:   notifSvc,
		metrics:    metrics,
		rs:         rs,
		notifs:     notifs,
		notifRepo:  notifRepo,
		policyRepo: policyRepo,
		certRepo:   certRepo,
		auditRepo:  auditRepo,
	}
}

func newExpiringCert(id string, daysFromNow int, policyID string) *domain.ManagedCertificate {
	return &domain.ManagedCertificate{
		ID:              id,
		Name:            "Test Cert " + id,
		CommonName:      id + ".example.com",
		SANs:            []string{},
		OwnerID:         "owner-1",
		TeamID:          "team-1",
		IssuerID:        "iss-test",
		RenewalPolicyID: policyID,
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       time.Now().AddDate(0, 0, daysFromNow),
		Tags:            map[string]string{},
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

// totalEntries sums Count across every snapshot entry that matches the
// given filter func. Useful for "all-success", "all-failure" assertions
// without listing every (channel, threshold) tuple.
func totalEntries(metrics *ExpiryAlertMetrics, want func(ExpiryAlertSnapshotEntry) bool) uint64 {
	var sum uint64
	for _, e := range metrics.SnapshotExpiryAlerts() {
		if want(e) {
			sum += e.Count
		}
	}
	return sum
}

// TestExpiryAlerts_DefaultMatrix_EmailOnly pins the back-compat
// contract: a policy with no AlertChannels matrix → the runtime falls
// through to DefaultAlertChannels (Email-only at every tier).
// PagerDuty / Slack / Teams / OpsGenie / Webhook receive ZERO alerts
// regardless of how many thresholds the cert has crossed.
func TestExpiryAlerts_DefaultMatrix_EmailOnly(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t)

	// Policy with no AlertChannels — fall through to default.
	policy := &domain.RenewalPolicy{
		ID:                  "rp-default-matrix",
		Name:                "Default Matrix",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		// AlertChannels intentionally nil
		// AlertSeverityMap intentionally nil
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	f.policyRepo.AddPolicy(policy)

	cert := newExpiringCert("mc-default", 0, "rp-default-matrix")
	f.certRepo.AddCert(cert)

	if err := f.rs.CheckExpiringCertificates(ctx); err != nil {
		t.Fatalf("CheckExpiringCertificates: %v", err)
	}

	if got := f.notifs["Email"].count(); got != 4 {
		t.Errorf("expected 4 Email alerts (one per threshold), got %d", got)
	}
	for _, ch := range []string{"Slack", "Teams", "PagerDuty", "OpsGenie", "Webhook"} {
		if got := f.notifs[ch].count(); got != 0 {
			t.Errorf("expected 0 %s alerts in default-matrix mode, got %d", ch, got)
		}
	}
}

// TestExpiryAlerts_PerTierFanOut pins the operator-supplied matrix:
//
//	informational  → [Slack]
//	warning        → [Slack, Email]
//	critical       → [PagerDuty, OpsGenie, Email]
//
// With the canonical 30/14/7/0 thresholds and a cert at 0 days
// remaining (crosses all four), the dispatch loop should produce:
//
//	Slack:     3  (informational T-30, warning T-14, warning T-7)
//	Email:     3  (warning T-14, warning T-7, critical T-0)
//	PagerDuty: 1  (critical T-0 only)
//	OpsGenie:  1  (critical T-0 only)
//	Teams:     0
//	Webhook:   0
func TestExpiryAlerts_PerTierFanOut(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t)

	policy := &domain.RenewalPolicy{
		ID:                  "rp-fanout",
		Name:                "Fan-out Matrix",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		AlertChannels: map[string][]string{
			domain.AlertSeverityInformational: {"Slack"},
			domain.AlertSeverityWarning:       {"Slack", "Email"},
			domain.AlertSeverityCritical:      {"PagerDuty", "OpsGenie", "Email"},
		},
		// AlertSeverityMap nil → falls through to DefaultAlertSeverityMap
		// (30→informational, 14→warning, 7→warning, 0→critical) which is
		// what we want here.
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	f.policyRepo.AddPolicy(policy)

	cert := newExpiringCert("mc-fanout", 0, "rp-fanout")
	f.certRepo.AddCert(cert)

	if err := f.rs.CheckExpiringCertificates(ctx); err != nil {
		t.Fatalf("CheckExpiringCertificates: %v", err)
	}

	expected := map[string]int{
		"Slack":     3,
		"Email":     3,
		"PagerDuty": 1,
		"OpsGenie":  1,
		"Teams":     0,
		"Webhook":   0,
	}
	for ch, want := range expected {
		if got := f.notifs[ch].count(); got != want {
			t.Errorf("channel %s: expected %d alerts, got %d", ch, want, got)
		}
	}

	// Spot-check the metric: PagerDuty should have exactly one
	// {threshold=0, result=success} entry.
	pdSuccess := totalEntries(f.metrics, func(e ExpiryAlertSnapshotEntry) bool {
		return e.Channel == "PagerDuty" && e.Threshold == 0 && e.Result == "success"
	})
	if pdSuccess != 1 {
		t.Errorf("expected exactly 1 PagerDuty success at threshold=0, got %d", pdSuccess)
	}
}

// TestExpiryAlerts_PerChannelDedup pins that running the loop twice in
// a row at the same daysUntil produces ZERO new sends — every
// (cert, threshold, channel) row is in persistence already, so each
// channel deduplicates.
func TestExpiryAlerts_PerChannelDedup(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t)

	policy := &domain.RenewalPolicy{
		ID:                  "rp-dedup",
		Name:                "Dedup Test",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 7, 0},
		AlertChannels: map[string][]string{
			domain.AlertSeverityInformational: {"Slack"},
			domain.AlertSeverityWarning:       {"Email"},
			domain.AlertSeverityCritical:      {"PagerDuty"},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	f.policyRepo.AddPolicy(policy)

	cert := newExpiringCert("mc-dedup", 0, "rp-dedup")
	f.certRepo.AddCert(cert)

	// First pass — every threshold should fire.
	if err := f.rs.CheckExpiringCertificates(ctx); err != nil {
		t.Fatalf("first CheckExpiringCertificates: %v", err)
	}
	totalAfterFirst := f.notifs["Slack"].count() + f.notifs["Email"].count() + f.notifs["PagerDuty"].count()
	if totalAfterFirst == 0 {
		t.Fatal("first pass produced zero alerts; matrix wiring broken")
	}

	// Reset the cert's RenewalInProgress status so the second pass
	// re-evaluates the thresholds (CheckExpiringCertificates skips
	// RenewalInProgress certs after the first pass).
	cert.Status = domain.CertificateStatusActive
	_ = f.certRepo.Update(ctx, cert)

	// Second pass — every (cert, threshold, channel) row already in
	// persistence; expect ZERO new sends.
	if err := f.rs.CheckExpiringCertificates(ctx); err != nil {
		t.Fatalf("second CheckExpiringCertificates: %v", err)
	}
	totalAfterSecond := f.notifs["Slack"].count() + f.notifs["Email"].count() + f.notifs["PagerDuty"].count()
	if totalAfterSecond != totalAfterFirst {
		t.Errorf("dedup failed: total alerts grew from %d to %d on second pass", totalAfterFirst, totalAfterSecond)
	}

	// Deduped counter should be non-zero.
	dedupedCount := totalEntries(f.metrics, func(e ExpiryAlertSnapshotEntry) bool {
		return e.Result == "deduped"
	})
	if dedupedCount == 0 {
		t.Errorf("expected deduped counter to increment on second pass; got 0")
	}
}

// TestExpiryAlerts_OneChannelFails_OthersStillFire pins that one
// channel's failure does NOT suppress the others. PagerDuty rejects
// every send; Slack and Email succeed; the dispatch loop reports a
// failure-metric increment for PagerDuty, success for the others, and
// keeps the other channels' deliveries.
func TestExpiryAlerts_OneChannelFails_OthersStillFire(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t)

	// PagerDuty mock returns error on every Send.
	f.notifs["PagerDuty"].sendErr = errors.New("pagerduty 503: incident api down")

	policy := &domain.RenewalPolicy{
		ID:                  "rp-pdfail",
		Name:                "PagerDuty Fail",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{0},
		AlertChannels: map[string][]string{
			domain.AlertSeverityCritical: {"PagerDuty", "Slack", "Email"},
		},
		AlertSeverityMap: map[int]string{0: domain.AlertSeverityCritical},
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	f.policyRepo.AddPolicy(policy)

	cert := newExpiringCert("mc-pdfail", 0, "rp-pdfail")
	f.certRepo.AddCert(cert)

	if err := f.rs.CheckExpiringCertificates(ctx); err != nil {
		t.Fatalf("CheckExpiringCertificates: %v", err)
	}

	// Slack and Email got their messages.
	if got := f.notifs["Slack"].count(); got != 1 {
		t.Errorf("Slack expected 1 message even though PagerDuty failed, got %d", got)
	}
	if got := f.notifs["Email"].count(); got != 1 {
		t.Errorf("Email expected 1 message even though PagerDuty failed, got %d", got)
	}
	if got := f.notifs["PagerDuty"].count(); got != 0 {
		t.Errorf("PagerDuty failed; expected 0 stored messages, got %d", got)
	}

	// Metric: PagerDuty should record failure; Slack + Email success.
	pdFailure := totalEntries(f.metrics, func(e ExpiryAlertSnapshotEntry) bool {
		return e.Channel == "PagerDuty" && e.Result == "failure"
	})
	if pdFailure != 1 {
		t.Errorf("expected 1 PagerDuty failure metric increment, got %d", pdFailure)
	}
	slackSuccess := totalEntries(f.metrics, func(e ExpiryAlertSnapshotEntry) bool {
		return e.Channel == "Slack" && e.Result == "success"
	})
	if slackSuccess != 1 {
		t.Errorf("expected 1 Slack success metric increment, got %d", slackSuccess)
	}
}

// TestExpiryAlerts_OffEnumChannelDropped pins that an off-enum channel
// (operator typo: "PagerD") is silently dropped at the dispatch site
// without growing Prometheus cardinality. The drop is recorded in the
// audit log so an operator can grep + fix.
func TestExpiryAlerts_OffEnumChannelDropped(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t)

	policy := &domain.RenewalPolicy{
		ID:                  "rp-typo",
		Name:                "Typo Test",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{0},
		AlertChannels: map[string][]string{
			// "PagerD" is a typo — the real channel name is "PagerDuty".
			// Slack is valid; should still fire.
			domain.AlertSeverityCritical: {"PagerD", "Slack"},
		},
		AlertSeverityMap: map[int]string{0: domain.AlertSeverityCritical},
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	f.policyRepo.AddPolicy(policy)

	cert := newExpiringCert("mc-typo", 0, "rp-typo")
	f.certRepo.AddCert(cert)

	if err := f.rs.CheckExpiringCertificates(ctx); err != nil {
		t.Fatalf("CheckExpiringCertificates: %v", err)
	}

	// Slack still fires.
	if got := f.notifs["Slack"].count(); got != 1 {
		t.Errorf("Slack expected 1 message; off-enum sibling should not block it; got %d", got)
	}

	// Off-enum value never reached a notifier.
	if got := f.notifs["PagerDuty"].count(); got != 0 {
		t.Errorf("PagerDuty should be untouched (typo was 'PagerD'), got %d", got)
	}

	// The metric does NOT have a "PagerD" entry — closed-enum
	// discipline keeps cardinality bounded.
	for _, e := range f.metrics.SnapshotExpiryAlerts() {
		if e.Channel == "PagerD" {
			t.Errorf("metric grew on off-enum channel typo: entry=%+v", e)
		}
	}

	// Audit log should record the drop. Look for the typed
	// expiration_alert_skipped_invalid_channel event.
	foundDropAudit := false
	for _, ev := range f.auditRepo.Events {
		if ev.Action == "expiration_alert_skipped_invalid_channel" {
			foundDropAudit = true
			break
		}
	}
	if !foundDropAudit {
		t.Errorf("expected expiration_alert_skipped_invalid_channel audit row for off-enum typo; not found")
	}
}

// TestExpiryAlerts_MetricCounterIncrements pins that every
// (channel, threshold, result) combination the dispatch loop produces
// shows up in the snapshot. Three tiers fire on a single cert with
// distinct channel sets per tier — the snapshot should carry one
// entry per (channel, threshold, "success") triple.
func TestExpiryAlerts_MetricCounterIncrements(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t)

	policy := &domain.RenewalPolicy{
		ID:                  "rp-metric",
		Name:                "Metric Test",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 0},
		AlertChannels: map[string][]string{
			domain.AlertSeverityInformational: {"Slack"},
			domain.AlertSeverityWarning:       {"Email"},
			domain.AlertSeverityCritical:      {"PagerDuty"},
		},
		AlertSeverityMap: map[int]string{
			30: domain.AlertSeverityInformational,
			14: domain.AlertSeverityWarning,
			0:  domain.AlertSeverityCritical,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	f.policyRepo.AddPolicy(policy)

	cert := newExpiringCert("mc-metric", 0, "rp-metric")
	f.certRepo.AddCert(cert)

	if err := f.rs.CheckExpiringCertificates(ctx); err != nil {
		t.Fatalf("CheckExpiringCertificates: %v", err)
	}

	snap := f.metrics.SnapshotExpiryAlerts()

	// Expect three (channel, threshold, success) entries.
	want := map[string]bool{
		"Slack/30/success":    false,
		"Email/14/success":    false,
		"PagerDuty/0/success": false,
	}
	for _, e := range snap {
		if e.Result != "success" {
			continue
		}
		key := keyFromEntry(e)
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("metric snapshot missing expected entry: %s", k)
		}
	}
}

func keyFromEntry(e ExpiryAlertSnapshotEntry) string {
	return e.Channel + "/" + intStr(e.Threshold) + "/" + e.Result
}

func intStr(i int) string {
	if i == 0 {
		return "0"
	}
	negate := i < 0
	if negate {
		i = -i
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	if negate {
		digits = append([]byte("-"), digits...)
	}
	return string(digits)
}

// TestExpiryAlerts_NilPolicy_FallsToDefault pins that a cert with no
// RenewalPolicy attached (RenewalPolicyID == "") gets the default
// Email-only matrix at every threshold tier. Same as
// TestExpiryAlerts_DefaultMatrix_EmailOnly but with a missing policy
// rather than a policy that has nil AlertChannels.
func TestExpiryAlerts_NilPolicy_FallsToDefault(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t)

	cert := newExpiringCert("mc-nopolicy", 0, "") // empty RenewalPolicyID
	f.certRepo.AddCert(cert)

	if err := f.rs.CheckExpiringCertificates(ctx); err != nil {
		t.Fatalf("CheckExpiringCertificates: %v", err)
	}

	if got := f.notifs["Email"].count(); got != 4 {
		t.Errorf("expected 4 Email alerts (default thresholds, default matrix), got %d", got)
	}
	for _, ch := range []string{"Slack", "Teams", "PagerDuty", "OpsGenie", "Webhook"} {
		if got := f.notifs[ch].count(); got != 0 {
			t.Errorf("expected 0 %s alerts when policy is missing, got %d", ch, got)
		}
	}
}

// TestExpiryAlerts_OperatorOptOutOfTier pins that an explicit empty
// list at a tier causes the dispatch loop to fire ZERO alerts for
// that tier, while other tiers continue to work. Operators use this
// to opt out of T-30 informational alerts (e.g. "we don't want to
// hear about a cert until it's a real warning").
func TestExpiryAlerts_OperatorOptOutOfTier(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t)

	policy := &domain.RenewalPolicy{
		ID:                  "rp-optout",
		Name:                "Opt-out Test",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: []int{30, 14, 0},
		AlertChannels: map[string][]string{
			// Operator opted out of informational entirely.
			domain.AlertSeverityInformational: {},
			domain.AlertSeverityWarning:       {"Email"},
			domain.AlertSeverityCritical:      {"PagerDuty", "Email"},
		},
		AlertSeverityMap: map[int]string{
			30: domain.AlertSeverityInformational,
			14: domain.AlertSeverityWarning,
			0:  domain.AlertSeverityCritical,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	f.policyRepo.AddPolicy(policy)

	cert := newExpiringCert("mc-optout", 0, "rp-optout")
	f.certRepo.AddCert(cert)

	if err := f.rs.CheckExpiringCertificates(ctx); err != nil {
		t.Fatalf("CheckExpiringCertificates: %v", err)
	}

	// Email: 1 warning (T-14) + 1 critical (T-0) = 2.
	if got := f.notifs["Email"].count(); got != 2 {
		t.Errorf("Email expected 2 alerts (warning + critical), got %d", got)
	}
	// PagerDuty: 1 critical only.
	if got := f.notifs["PagerDuty"].count(); got != 1 {
		t.Errorf("PagerDuty expected 1 alert (critical), got %d", got)
	}
	// Slack/Teams/OpsGenie/Webhook: 0.
	for _, ch := range []string{"Slack", "Teams", "OpsGenie", "Webhook"} {
		if got := f.notifs[ch].count(); got != 0 {
			t.Errorf("expected 0 %s alerts (informational opt-out), got %d", ch, got)
		}
	}

	// Audit row for the opt-out tier (informational @ threshold=30).
	foundSkipAudit := false
	for _, ev := range f.auditRepo.Events {
		if ev.Action == "expiration_alert_skipped_no_channels" {
			foundSkipAudit = true
			break
		}
	}
	if !foundSkipAudit {
		t.Errorf("expected expiration_alert_skipped_no_channels audit row for opted-out tier; not found")
	}
}
