package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// StatsService provides statistics and observability data for dashboards and monitoring.
type StatsService struct {
	certRepo  repository.CertificateRepository
	jobRepo   repository.JobRepository
	agentRepo repository.AgentRepository
	// notifRepo is injected post-construction via SetNotifRepo so that
	// NewStatsService's nine call sites (main.go + stats_test.go + 8 digest
	// tests) keep their existing signatures. When nil, the dead-letter count
	// falls through to zero — see GetDashboardSummary. I-005 coverage-gap
	// closure.
	notifRepo repository.NotificationRepository
}

// NewStatsService creates a new stats service.
func NewStatsService(
	certRepo repository.CertificateRepository,
	jobRepo repository.JobRepository,
	agentRepo repository.AgentRepository,
) *StatsService {
	return &StatsService{
		certRepo:  certRepo,
		jobRepo:   jobRepo,
		agentRepo: agentRepo,
	}
}

// SetNotifRepo injects the notification repository used to populate
// DashboardSummary.NotificationsDead. Setter pattern (matching the
// certificateService.SetTargetRepo / SetProfileRepo / SetDigestService
// precedent) keeps the NewStatsService signature stable across its
// pre-existing call sites. I-005 coverage-gap closure.
func (s *StatsService) SetNotifRepo(notifRepo repository.NotificationRepository) {
	s.notifRepo = notifRepo
}

// DashboardSummary represents a high-level summary of system state.
type DashboardSummary struct {
	TotalCertificates    int64 `json:"total_certificates"`
	ExpiringCertificates int64 `json:"expiring_certificates"`
	ExpiredCertificates  int64 `json:"expired_certificates"`
	RevokedCertificates  int64 `json:"revoked_certificates"`
	ActiveAgents         int64 `json:"active_agents"`
	OfflineAgents        int64 `json:"offline_agents"`
	TotalAgents          int64 `json:"total_agents"`
	PendingJobs          int64 `json:"pending_jobs"`
	FailedJobs           int64 `json:"failed_jobs"`
	CompleteJobs         int64 `json:"complete_jobs"`
	// NotificationsDead is the number of notification_events rows currently
	// in the terminal "dead" status (I-005 dead-letter queue). Exposed here
	// so the metrics handler can derive the Prometheus counter
	// certctl_notification_dead_total from the same snapshot used by the
	// dashboard. DB-COUNT rather than in-memory — notifications can grow
	// without bound, and filter-based List() is PerPage-capped to 50.
	NotificationsDead int64     `json:"notifications_dead"`
	CompletedAt       time.Time `json:"completed_at"`
}

// GetDashboardSummary returns a summary of key metrics.
func (s *StatsService) GetDashboardSummary(ctx context.Context) (interface{}, error) {
	summary := &DashboardSummary{
		CompletedAt: time.Now(),
	}

	// Get all certificates
	allCerts, total, err := s.certRepo.List(ctx, &repository.CertificateFilter{Page: 1, PerPage: 10000})
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}
	summary.TotalCertificates = int64(total)

	now := time.Now()
	thirtyDaysFromNow := now.AddDate(0, 0, 30)

	for _, cert := range allCerts {
		normalizedStatus := strings.ToLower(string(cert.Status))
		if normalizedStatus == "revoked" {
			summary.RevokedCertificates++
		} else if normalizedStatus == "expired" || (!cert.ExpiresAt.IsZero() && cert.ExpiresAt.Before(now)) {
			summary.ExpiredCertificates++
		} else if !cert.ExpiresAt.IsZero() && cert.ExpiresAt.Before(thirtyDaysFromNow) && cert.ExpiresAt.After(now) {
			summary.ExpiringCertificates++
		}
	}

	// Get all agents
	allAgents, err := s.agentRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list agents: %w", err)
	}
	summary.TotalAgents = int64(len(allAgents))

	// Count active agents (heartbeat within last 5 minutes)
	fiveMinutesAgo := now.Add(-5 * time.Minute)
	for _, agent := range allAgents {
		if agent.LastHeartbeatAt != nil && agent.LastHeartbeatAt.After(fiveMinutesAgo) {
			summary.ActiveAgents++
		} else {
			summary.OfflineAgents++
		}
	}

	// Get all jobs
	allJobs, err := s.jobRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}

	for _, job := range allJobs {
		switch job.Status {
		case domain.JobStatusPending, domain.JobStatusAwaitingCSR, domain.JobStatusAwaitingApproval, domain.JobStatusRunning:
			summary.PendingJobs++
		case domain.JobStatusFailed:
			summary.FailedJobs++
		case domain.JobStatusCompleted:
			summary.CompleteJobs++
		}
	}

	// I-005: dead-letter count for certctl_notification_dead_total. nil-safe
	// so the nine existing NewStatsService call sites that haven't yet been
	// updated to call SetNotifRepo keep working — they'll simply report
	// NotificationsDead=0, which is the correct value on a system without a
	// notification repository wired in. A CountByStatus error is non-fatal:
	// the dashboard summary is best-effort for this field.
	if s.notifRepo != nil {
		deadCount, err := s.notifRepo.CountByStatus(ctx, string(domain.NotificationStatusDead))
		if err == nil {
			summary.NotificationsDead = deadCount
		}
	}

	return summary, nil
}

// CertificateStatusCount represents count of certificates by status.
type CertificateStatusCount struct {
	Status string `json:"status"`
	Count  int64  `json:"count"`
}

// GetCertificatesByStatus returns certificate counts grouped by status.
func (s *StatsService) GetCertificatesByStatus(ctx context.Context) (interface{}, error) {
	allCerts, _, err := s.certRepo.List(ctx, &repository.CertificateFilter{Page: 1, PerPage: 10000})
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	counts := make(map[string]int64)
	now := time.Now()
	thirtyDaysFromNow := now.AddDate(0, 0, 30)

	for _, cert := range allCerts {
		status := string(cert.Status)
		// Normalize status to PascalCase to handle legacy lowercase values in the database
		switch strings.ToLower(status) {
		case "", "active":
			if !cert.ExpiresAt.IsZero() {
				if cert.ExpiresAt.Before(now) {
					status = "Expired"
				} else if cert.ExpiresAt.Before(thirtyDaysFromNow) {
					status = "Expiring"
				} else {
					status = "Active"
				}
			} else {
				status = "Active"
			}
		case "expiring":
			status = "Expiring"
		case "expired":
			status = "Expired"
		case "renewalinprogress", "renewal_in_progress":
			status = "RenewalInProgress"
		case "failed":
			status = "Failed"
		case "revoked":
			status = "Revoked"
		case "archived":
			status = "Archived"
		case "pending":
			status = "Pending"
		}
		counts[status]++
	}

	result := make([]CertificateStatusCount, 0, len(counts))
	for status, count := range counts {
		result = append(result, CertificateStatusCount{Status: status, Count: count})
	}

	return result, nil
}

// ExpirationBucket represents certificates expiring on a specific date.
type ExpirationBucket struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// GetExpirationTimeline returns certificates expiring over the next N days, bucketed by day.
func (s *StatsService) GetExpirationTimeline(ctx context.Context, days int) (interface{}, error) {
	if days <= 0 {
		days = 30
	}

	allCerts, _, err := s.certRepo.List(ctx, &repository.CertificateFilter{Page: 1, PerPage: 10000})
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	buckets := make(map[string]int64)
	now := time.Now()
	endDate := now.AddDate(0, 0, days)

	for _, cert := range allCerts {
		if cert.ExpiresAt.IsZero() {
			continue
		}
		if cert.ExpiresAt.After(now) && cert.ExpiresAt.Before(endDate) {
			dateStr := cert.ExpiresAt.Format("2006-01-02")
			buckets[dateStr]++
		}
	}

	result := make([]ExpirationBucket, 0, days)
	for i := 0; i < days; i++ {
		date := now.AddDate(0, 0, i)
		dateStr := date.Format("2006-01-02")
		if count, exists := buckets[dateStr]; exists {
			result = append(result, ExpirationBucket{Date: dateStr, Count: count})
		} else {
			result = append(result, ExpirationBucket{Date: dateStr, Count: 0})
		}
	}

	return result, nil
}

// JobTrendDataPoint represents success/failure counts for a specific day.
type JobTrendDataPoint struct {
	Date           string  `json:"date"`
	CompletedCount int64   `json:"completed_count"`
	FailedCount    int64   `json:"failed_count"`
	SuccessRate    float64 `json:"success_rate"`
}

// GetJobStats returns job success/failure trends over the past N days.
func (s *StatsService) GetJobStats(ctx context.Context, days int) (interface{}, error) {
	if days <= 0 {
		days = 30
	}

	allJobs, err := s.jobRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}

	type dayData struct {
		completed int64
		failed    int64
	}
	buckets := make(map[string]*dayData)
	now := time.Now()

	for _, job := range allJobs {
		if job.Status != domain.JobStatusCompleted && job.Status != domain.JobStatusFailed {
			continue
		}
		if job.CompletedAt == nil {
			continue
		}
		if job.CompletedAt.Before(now.AddDate(0, 0, -days)) {
			continue
		}

		dateStr := job.CompletedAt.Format("2006-01-02")
		if _, exists := buckets[dateStr]; !exists {
			buckets[dateStr] = &dayData{}
		}

		if job.Status == domain.JobStatusCompleted {
			buckets[dateStr].completed++
		} else {
			buckets[dateStr].failed++
		}
	}

	result := make([]JobTrendDataPoint, 0, days)
	for i := 0; i < days; i++ {
		date := now.AddDate(0, 0, -days+i+1)
		dateStr := date.Format("2006-01-02")
		point := JobTrendDataPoint{Date: dateStr}

		if data, exists := buckets[dateStr]; exists {
			point.CompletedCount = data.completed
			point.FailedCount = data.failed
			total := data.completed + data.failed
			if total > 0 {
				point.SuccessRate = (float64(data.completed) / float64(total)) * 100
			}
		}
		result = append(result, point)
	}

	return result, nil
}

// IssuanceRateDataPoint represents new certificates issued on a specific day.
type IssuanceRateDataPoint struct {
	Date        string `json:"date"`
	IssuedCount int64  `json:"issued_count"`
}

// GetIssuanceRate returns the rate of new certificate issuance over the past N days.
func (s *StatsService) GetIssuanceRate(ctx context.Context, days int) (interface{}, error) {
	if days <= 0 {
		days = 30
	}

	allCerts, _, err := s.certRepo.List(ctx, &repository.CertificateFilter{Page: 1, PerPage: 10000})
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	buckets := make(map[string]int64)
	now := time.Now()

	for _, cert := range allCerts {
		if cert.CreatedAt.IsZero() {
			continue
		}
		if cert.CreatedAt.Before(now.AddDate(0, 0, -days)) {
			continue
		}

		dateStr := cert.CreatedAt.Format("2006-01-02")
		buckets[dateStr]++
	}

	result := make([]IssuanceRateDataPoint, 0, days)
	for i := 0; i < days; i++ {
		date := now.AddDate(0, 0, -days+i+1)
		dateStr := date.Format("2006-01-02")
		point := IssuanceRateDataPoint{Date: dateStr}

		if count, exists := buckets[dateStr]; exists {
			point.IssuedCount = count
		}
		result = append(result, point)
	}

	return result, nil
}
