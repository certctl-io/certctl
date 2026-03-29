package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// mockHTMLEmailSender implements HTMLEmailSender for testing.
type mockHTMLEmailSender struct {
	sentEmails []sentHTMLEmail
	sendErr    error
}

type sentHTMLEmail struct {
	recipient string
	subject   string
	body      string
}

func (m *mockHTMLEmailSender) SendHTML(ctx context.Context, recipient string, subject string, htmlBody string) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sentEmails = append(m.sentEmails, sentHTMLEmail{
		recipient: recipient,
		subject:   subject,
		body:      htmlBody,
	})
	return nil
}

func TestDigestService_GenerateDigest(t *testing.T) {
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}

	// Add test certificates
	now := time.Now()
	certRepo.Certs["cert-1"] = &domain.ManagedCertificate{
		ID:         "cert-1",
		CommonName: "example.com",
		ExpiresAt:  now.AddDate(0, 0, 10),
		OwnerID:    "owner-1",
	}
	certRepo.Certs["cert-2"] = &domain.ManagedCertificate{
		ID:         "cert-2",
		CommonName: "api.example.com",
		ExpiresAt:  now.AddDate(0, 0, 25),
		OwnerID:    "owner-2",
	}
	certRepo.Certs["cert-3"] = &domain.ManagedCertificate{
		ID:         "cert-3",
		CommonName: "old.example.com",
		ExpiresAt:  now.AddDate(0, 0, -5), // expired
		OwnerID:    "owner-1",
	}

	jobRepo := &mockJobRepo{Jobs: make(map[string]*domain.Job)}
	agentRepo := &mockAgentRepo{Agents: make(map[string]*domain.Agent)}
	statsService := NewStatsService(certRepo, jobRepo, agentRepo)

	sender := &mockHTMLEmailSender{}
	digestService := NewDigestService(statsService, certRepo, nil, sender, []string{"admin@example.com"}, nil)

	digest, err := digestService.GenerateDigest(context.Background())
	if err != nil {
		t.Fatalf("GenerateDigest failed: %v", err)
	}

	if digest.TotalCertificates != 3 {
		t.Errorf("expected 3 total certs, got %d", digest.TotalCertificates)
	}

	if len(digest.ExpiringCerts) != 2 {
		t.Errorf("expected 2 expiring certs (10d and 25d), got %d", len(digest.ExpiringCerts))
	}
}

func TestDigestService_GenerateDigest_Empty(t *testing.T) {
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	jobRepo := &mockJobRepo{Jobs: make(map[string]*domain.Job)}
	agentRepo := &mockAgentRepo{Agents: make(map[string]*domain.Agent)}
	statsService := NewStatsService(certRepo, jobRepo, agentRepo)

	sender := &mockHTMLEmailSender{}
	digestService := NewDigestService(statsService, certRepo, nil, sender, nil, nil)

	digest, err := digestService.GenerateDigest(context.Background())
	if err != nil {
		t.Fatalf("GenerateDigest failed: %v", err)
	}

	if digest.TotalCertificates != 0 {
		t.Errorf("expected 0 total certs, got %d", digest.TotalCertificates)
	}

	if len(digest.ExpiringCerts) != 0 {
		t.Errorf("expected 0 expiring certs, got %d", len(digest.ExpiringCerts))
	}
}

func TestDigestService_RenderDigestHTML(t *testing.T) {
	digestService := &DigestService{}

	data := &DigestData{
		GeneratedAt:          time.Now(),
		TotalCertificates:    42,
		ExpiringCertificates: 5,
		ExpiredCertificates:  2,
		ActiveAgents:         3,
		PendingJobs:          1,
		ExpiringCerts: []DigestCertEntry{
			{ID: "c1", CommonName: "example.com", ExpiresAt: time.Now().AddDate(0, 0, 5), DaysLeft: 5},
		},
	}

	html, err := digestService.RenderDigestHTML(data)
	if err != nil {
		t.Fatalf("RenderDigestHTML failed: %v", err)
	}

	if !strings.Contains(html, "certctl Certificate Digest") {
		t.Error("expected HTML to contain 'certctl Certificate Digest'")
	}

	if !strings.Contains(html, "42") {
		t.Error("expected HTML to contain total certificate count '42'")
	}

	if !strings.Contains(html, "example.com") {
		t.Error("expected HTML to contain 'example.com'")
	}

	if !strings.Contains(html, "5 days") {
		t.Error("expected HTML to contain '5 days'")
	}
}

func TestDigestService_RenderDigestHTML_Empty(t *testing.T) {
	digestService := &DigestService{}

	data := &DigestData{
		GeneratedAt: time.Now(),
	}

	html, err := digestService.RenderDigestHTML(data)
	if err != nil {
		t.Fatalf("RenderDigestHTML failed: %v", err)
	}

	if !strings.Contains(html, "No certificates expiring in the next 30 days") {
		t.Error("expected empty state message in HTML")
	}
}

func TestDigestService_SendDigest_Success(t *testing.T) {
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	jobRepo := &mockJobRepo{Jobs: make(map[string]*domain.Job)}
	agentRepo := &mockAgentRepo{Agents: make(map[string]*domain.Agent)}
	statsService := NewStatsService(certRepo, jobRepo, agentRepo)

	sender := &mockHTMLEmailSender{}
	recipients := []string{"admin@example.com", "ops@example.com"}
	digestService := NewDigestService(statsService, certRepo, nil, sender, recipients, nil)

	err := digestService.SendDigest(context.Background())
	if err != nil {
		t.Fatalf("SendDigest failed: %v", err)
	}

	if len(sender.sentEmails) != 2 {
		t.Fatalf("expected 2 emails sent, got %d", len(sender.sentEmails))
	}

	if sender.sentEmails[0].recipient != "admin@example.com" {
		t.Errorf("expected first recipient admin@example.com, got %s", sender.sentEmails[0].recipient)
	}

	if !strings.Contains(sender.sentEmails[0].subject, "certctl Certificate Digest") {
		t.Errorf("expected subject to contain 'certctl Certificate Digest', got %s", sender.sentEmails[0].subject)
	}
}

func TestDigestService_SendDigest_NoSender(t *testing.T) {
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	jobRepo := &mockJobRepo{Jobs: make(map[string]*domain.Job)}
	agentRepo := &mockAgentRepo{Agents: make(map[string]*domain.Agent)}
	statsService := NewStatsService(certRepo, jobRepo, agentRepo)

	digestService := NewDigestService(statsService, certRepo, nil, nil, []string{"admin@example.com"}, nil)

	err := digestService.SendDigest(context.Background())
	if err == nil {
		t.Fatal("expected error when sender is nil")
	}

	if !strings.Contains(err.Error(), "email sender not configured") {
		t.Errorf("expected 'email sender not configured' error, got: %v", err)
	}
}

func TestDigestService_SendDigest_SendError(t *testing.T) {
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	jobRepo := &mockJobRepo{Jobs: make(map[string]*domain.Job)}
	agentRepo := &mockAgentRepo{Agents: make(map[string]*domain.Agent)}
	statsService := NewStatsService(certRepo, jobRepo, agentRepo)

	sender := &mockHTMLEmailSender{sendErr: errors.New("SMTP connection refused")}
	digestService := NewDigestService(statsService, certRepo, nil, sender, []string{"admin@example.com"}, nil)

	err := digestService.SendDigest(context.Background())
	if err == nil {
		t.Fatal("expected error when send fails")
	}

	if !strings.Contains(err.Error(), "failed to send digest") {
		t.Errorf("expected 'failed to send digest' error, got: %v", err)
	}
}

func TestDigestService_SendDigest_NoRecipients(t *testing.T) {
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	jobRepo := &mockJobRepo{Jobs: make(map[string]*domain.Job)}
	agentRepo := &mockAgentRepo{Agents: make(map[string]*domain.Agent)}
	statsService := NewStatsService(certRepo, jobRepo, agentRepo)

	sender := &mockHTMLEmailSender{}
	// No explicit recipients and no owner repo
	digestService := NewDigestService(statsService, certRepo, nil, sender, nil, nil)

	err := digestService.SendDigest(context.Background())
	// Should succeed without error (just no recipients)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sender.sentEmails) != 0 {
		t.Errorf("expected 0 emails sent, got %d", len(sender.sentEmails))
	}
}

func TestDigestService_PreviewDigest(t *testing.T) {
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	jobRepo := &mockJobRepo{Jobs: make(map[string]*domain.Job)}
	agentRepo := &mockAgentRepo{Agents: make(map[string]*domain.Agent)}
	statsService := NewStatsService(certRepo, jobRepo, agentRepo)

	sender := &mockHTMLEmailSender{}
	digestService := NewDigestService(statsService, certRepo, nil, sender, nil, nil)

	html, err := digestService.PreviewDigest(context.Background())
	if err != nil {
		t.Fatalf("PreviewDigest failed: %v", err)
	}

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("expected valid HTML document")
	}

	if !strings.Contains(html, "certctl Certificate Digest") {
		t.Error("expected HTML to contain 'certctl Certificate Digest'")
	}
}

func TestDigestService_ProcessDigest(t *testing.T) {
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	jobRepo := &mockJobRepo{Jobs: make(map[string]*domain.Job)}
	agentRepo := &mockAgentRepo{Agents: make(map[string]*domain.Agent)}
	statsService := NewStatsService(certRepo, jobRepo, agentRepo)

	sender := &mockHTMLEmailSender{}
	digestService := NewDigestService(statsService, certRepo, nil, sender, []string{"test@example.com"}, nil)

	err := digestService.ProcessDigest(context.Background())
	if err != nil {
		t.Fatalf("ProcessDigest failed: %v", err)
	}

	if len(sender.sentEmails) != 1 {
		t.Errorf("expected 1 email sent, got %d", len(sender.sentEmails))
	}
}
