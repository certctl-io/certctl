package service

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/repository"
)

// DigestService generates and sends periodic certificate digest emails.
// It aggregates statistics from StatsService and sends HTML-formatted
// summary emails to configured recipients.
type DigestService struct {
	statsService *StatsService
	certRepo     repository.CertificateRepository
	ownerRepo    repository.OwnerRepository
	emailSender  HTMLEmailSender
	recipients   []string
	logger       *slog.Logger
}

// HTMLEmailSender defines the interface for sending HTML emails.
// Implemented by the email notifier adapter.
type HTMLEmailSender interface {
	SendHTML(ctx context.Context, recipient string, subject string, htmlBody string) error
}

// DigestData holds the aggregated data for a digest email.
type DigestData struct {
	GeneratedAt          time.Time           `json:"generated_at"`
	TotalCertificates    int64               `json:"total_certificates"`
	ExpiringCertificates int64               `json:"expiring_certificates"`
	ExpiredCertificates  int64               `json:"expired_certificates"`
	RevokedCertificates  int64               `json:"revoked_certificates"`
	ActiveAgents         int64               `json:"active_agents"`
	OfflineAgents        int64               `json:"offline_agents"`
	TotalAgents          int64               `json:"total_agents"`
	PendingJobs          int64               `json:"pending_jobs"`
	FailedJobs           int64               `json:"failed_jobs"`
	CompletedJobs        int64               `json:"completed_jobs"`
	ExpiringCerts        []DigestCertEntry   `json:"expiring_certs"`
	RecentFailures       []DigestJobEntry    `json:"recent_failures"`
	StatusCounts         []DigestStatusCount `json:"status_counts"`
}

// DigestCertEntry represents a certificate entry in the digest.
type DigestCertEntry struct {
	ID         string    `json:"id"`
	CommonName string    `json:"common_name"`
	ExpiresAt  time.Time `json:"expires_at"`
	DaysLeft   int       `json:"days_left"`
	OwnerID    string    `json:"owner_id"`
}

// DigestJobEntry represents a failed job entry in the digest.
type DigestJobEntry struct {
	ID            string `json:"id"`
	CertificateID string `json:"certificate_id"`
	Type          string `json:"type"`
	Error         string `json:"error"`
}

// DigestStatusCount represents certificate counts by status for the digest.
type DigestStatusCount struct {
	Status string `json:"status"`
	Count  int64  `json:"count"`
}

// NewDigestService creates a new digest service.
func NewDigestService(
	statsService *StatsService,
	certRepo repository.CertificateRepository,
	ownerRepo repository.OwnerRepository,
	emailSender HTMLEmailSender,
	recipients []string,
	logger *slog.Logger,
) *DigestService {
	if logger == nil {
		logger = slog.Default()
	}
	return &DigestService{
		statsService: statsService,
		certRepo:     certRepo,
		ownerRepo:    ownerRepo,
		emailSender:  emailSender,
		recipients:   recipients,
		logger:       logger,
	}
}

// GenerateDigest aggregates current system statistics into a DigestData struct.
func (s *DigestService) GenerateDigest(ctx context.Context) (*DigestData, error) {
	digest := &DigestData{
		GeneratedAt: time.Now(),
	}

	// Get dashboard summary
	summaryRaw, err := s.statsService.GetDashboardSummary(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get dashboard summary: %w", err)
	}
	if summary, ok := summaryRaw.(*DashboardSummary); ok {
		digest.TotalCertificates = summary.TotalCertificates
		digest.ExpiringCertificates = summary.ExpiringCertificates
		digest.ExpiredCertificates = summary.ExpiredCertificates
		digest.RevokedCertificates = summary.RevokedCertificates
		digest.ActiveAgents = summary.ActiveAgents
		digest.OfflineAgents = summary.OfflineAgents
		digest.TotalAgents = summary.TotalAgents
		digest.PendingJobs = summary.PendingJobs
		digest.FailedJobs = summary.FailedJobs
		digest.CompletedJobs = summary.CompleteJobs
	}

	// Get certificates by status
	statusRaw, err := s.statsService.GetCertificatesByStatus(ctx)
	if err != nil {
		s.logger.Warn("failed to get status counts for digest", "error", err)
	} else if counts, ok := statusRaw.([]CertificateStatusCount); ok {
		for _, c := range counts {
			digest.StatusCounts = append(digest.StatusCounts, DigestStatusCount(c))
		}
	}

	// Get expiring certificates (next 30 days)
	now := time.Now()
	thirtyDaysFromNow := now.AddDate(0, 0, 30)
	allCerts, _, err := s.certRepo.List(ctx, &repository.CertificateFilter{Page: 1, PerPage: 10000})
	if err != nil {
		s.logger.Warn("failed to list certs for digest", "error", err)
	} else {
		for _, cert := range allCerts {
			if !cert.ExpiresAt.IsZero() && cert.ExpiresAt.After(now) && cert.ExpiresAt.Before(thirtyDaysFromNow) {
				daysLeft := int(time.Until(cert.ExpiresAt).Hours() / 24)
				digest.ExpiringCerts = append(digest.ExpiringCerts, DigestCertEntry{
					ID:         cert.ID,
					CommonName: cert.CommonName,
					ExpiresAt:  cert.ExpiresAt,
					DaysLeft:   daysLeft,
					OwnerID:    cert.OwnerID,
				})
			}
		}
	}

	return digest, nil
}

// SendDigest generates a digest and sends it to all configured recipients.
func (s *DigestService) SendDigest(ctx context.Context) error {
	if s.emailSender == nil {
		return fmt.Errorf("email sender not configured — set CERTCTL_SMTP_HOST and CERTCTL_SMTP_FROM_ADDRESS")
	}

	digest, err := s.GenerateDigest(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate digest: %w", err)
	}

	htmlBody, err := s.RenderDigestHTML(digest)
	if err != nil {
		return fmt.Errorf("failed to render digest HTML: %w", err)
	}

	subject := fmt.Sprintf("certctl Certificate Digest — %s", digest.GeneratedAt.Format("2006-01-02"))

	recipients := s.recipients
	if len(recipients) == 0 {
		// Fall back to owner emails
		recipients = s.resolveOwnerEmails(ctx)
	}

	if len(recipients) == 0 {
		s.logger.Warn("no digest recipients configured and no owner emails found")
		return nil
	}

	var sendErrors int
	for _, recipient := range recipients {
		if err := s.emailSender.SendHTML(ctx, recipient, subject, htmlBody); err != nil {
			s.logger.Error("failed to send digest to recipient",
				"recipient", recipient,
				"error", err)
			sendErrors++
		} else {
			s.logger.Info("digest email sent", "recipient", recipient)
		}
	}

	if sendErrors > 0 {
		return fmt.Errorf("failed to send digest to %d of %d recipients", sendErrors, len(recipients))
	}

	return nil
}

// ProcessDigest is the scheduler-facing method. It generates and sends the digest,
// logging errors rather than propagating them to match the scheduler pattern.
func (s *DigestService) ProcessDigest(ctx context.Context) error {
	return s.SendDigest(ctx)
}

// RenderDigestHTML renders the digest data into an HTML email body.
func (s *DigestService) RenderDigestHTML(data *DigestData) (string, error) {
	tmpl, err := template.New("digest").Parse(digestHTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse digest template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute digest template: %w", err)
	}

	return buf.String(), nil
}

// PreviewDigest generates and renders a digest without sending it.
// Used by the API handler for preview endpoints.
func (s *DigestService) PreviewDigest(ctx context.Context) (string, error) {
	digest, err := s.GenerateDigest(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to generate digest: %w", err)
	}

	return s.RenderDigestHTML(digest)
}

// resolveOwnerEmails collects unique email addresses from all certificate owners.
func (s *DigestService) resolveOwnerEmails(ctx context.Context) []string {
	if s.ownerRepo == nil {
		return nil
	}

	owners, err := s.ownerRepo.List(ctx)
	if err != nil {
		s.logger.Warn("failed to list owners for digest recipients", "error", err)
		return nil
	}

	seen := make(map[string]bool)
	var emails []string
	for _, owner := range owners {
		if owner.Email != "" && !seen[owner.Email] {
			seen[owner.Email] = true
			emails = append(emails, owner.Email)
		}
	}

	return emails
}

// digestHTMLTemplate is the HTML template for the certificate digest email.
const digestHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>certctl Certificate Digest</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background: #f5f5f5; color: #333; }
  .container { max-width: 640px; margin: 0 auto; background: #fff; }
  .header { background: #1a1a2e; color: #fff; padding: 24px 32px; }
  .header h1 { margin: 0; font-size: 22px; font-weight: 600; }
  .header .date { color: #a0a0b0; font-size: 13px; margin-top: 4px; }
  .section { padding: 24px 32px; border-bottom: 1px solid #eee; }
  .section h2 { font-size: 16px; font-weight: 600; margin: 0 0 16px 0; color: #1a1a2e; }
  .stats-grid { display: flex; flex-wrap: wrap; gap: 12px; }
  .stat-card { flex: 1; min-width: 120px; background: #f8f9fa; border-radius: 8px; padding: 16px; text-align: center; }
  .stat-value { font-size: 28px; font-weight: 700; color: #1a1a2e; }
  .stat-label { font-size: 12px; color: #666; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-warn .stat-value { color: #e67e22; }
  .stat-danger .stat-value { color: #e74c3c; }
  .stat-success .stat-value { color: #27ae60; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 12px; background: #f8f9fa; color: #666; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-warn { background: #fef3e2; color: #e67e22; }
  .badge-danger { background: #fde8e8; color: #e74c3c; }
  .badge-ok { background: #e8f8ef; color: #27ae60; }
  .footer { padding: 20px 32px; text-align: center; color: #999; font-size: 12px; background: #f8f9fa; }
  .empty-state { text-align: center; padding: 24px; color: #999; font-size: 14px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>certctl Certificate Digest</h1>
    <div class="date">Generated: {{.GeneratedAt.Format "January 2, 2006 3:04 PM"}}</div>
  </div>

  <div class="section">
    <h2>System Overview</h2>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">{{.TotalCertificates}}</div>
        <div class="stat-label">Total Certs</div>
      </div>
      <div class="stat-card stat-warn">
        <div class="stat-value">{{.ExpiringCertificates}}</div>
        <div class="stat-label">Expiring</div>
      </div>
      <div class="stat-card stat-danger">
        <div class="stat-value">{{.ExpiredCertificates}}</div>
        <div class="stat-label">Expired</div>
      </div>
      <div class="stat-card stat-success">
        <div class="stat-value">{{.ActiveAgents}}</div>
        <div class="stat-label">Active Agents</div>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>Jobs Summary</h2>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">{{.PendingJobs}}</div>
        <div class="stat-label">Pending</div>
      </div>
      <div class="stat-card stat-danger">
        <div class="stat-value">{{.FailedJobs}}</div>
        <div class="stat-label">Failed</div>
      </div>
      <div class="stat-card stat-success">
        <div class="stat-value">{{.CompletedJobs}}</div>
        <div class="stat-label">Completed</div>
      </div>
    </div>
  </div>

  {{if .ExpiringCerts}}
  <div class="section">
    <h2>Certificates Expiring Soon</h2>
    <table>
      <thead>
        <tr><th>Common Name</th><th>Expires</th><th>Days Left</th></tr>
      </thead>
      <tbody>
        {{range .ExpiringCerts}}
        <tr>
          <td>{{.CommonName}}</td>
          <td>{{.ExpiresAt.Format "Jan 2, 2006"}}</td>
          <td>
            {{if le .DaysLeft 7}}<span class="badge badge-danger">{{.DaysLeft}} days</span>
            {{else if le .DaysLeft 14}}<span class="badge badge-warn">{{.DaysLeft}} days</span>
            {{else}}<span class="badge badge-ok">{{.DaysLeft}} days</span>
            {{end}}
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
  {{else}}
  <div class="section">
    <h2>Certificates Expiring Soon</h2>
    <div class="empty-state">No certificates expiring in the next 30 days.</div>
  </div>
  {{end}}

  <div class="footer">
    This digest was automatically generated by certctl.<br>
    Configure digest settings with CERTCTL_DIGEST_* environment variables.
  </div>
</div>
</body>
</html>`
