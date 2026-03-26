package service

import (
	"context"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

func newTestStatsService() (*StatsService, *mockCertRepo, *mockJobRepo, *mockAgentRepo) {
	certRepo := &mockCertRepo{Certs: make(map[string]*domain.ManagedCertificate)}
	jobRepo := newMockJobRepository()
	agentRepo := newMockAgentRepository()
	svc := NewStatsService(certRepo, jobRepo, agentRepo)
	return svc, certRepo, jobRepo, agentRepo
}

func TestGetDashboardSummary_Empty(t *testing.T) {
	svc, _, _, _ := newTestStatsService()
	result, err := svc.GetDashboardSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	summary, ok := result.(*DashboardSummary)
	if !ok {
		t.Fatal("expected *DashboardSummary")
	}
	if summary.TotalCertificates != 0 {
		t.Errorf("expected 0 total certs, got %d", summary.TotalCertificates)
	}
	if summary.TotalAgents != 0 {
		t.Errorf("expected 0 total agents, got %d", summary.TotalAgents)
	}
}

func TestGetDashboardSummary_WithData(t *testing.T) {
	svc, certRepo, jobRepo, agentRepo := newTestStatsService()

	now := time.Now()
	tenDays := now.AddDate(0, 0, 10)
	pastDate := now.AddDate(0, 0, -5)
	futureDate := now.AddDate(0, 0, 60)

	// Add certificates
	certRepo.Certs["mc-active"] = &domain.ManagedCertificate{ID: "mc-active", Status: domain.CertificateStatusActive, ExpiresAt: futureDate}
	certRepo.Certs["mc-expiring"] = &domain.ManagedCertificate{ID: "mc-expiring", Status: domain.CertificateStatusActive, ExpiresAt: tenDays}
	certRepo.Certs["mc-expired"] = &domain.ManagedCertificate{ID: "mc-expired", Status: domain.CertificateStatusExpired, ExpiresAt: pastDate}
	certRepo.Certs["mc-revoked"] = &domain.ManagedCertificate{ID: "mc-revoked", Status: domain.CertificateStatusRevoked}

	// Add agents
	recentHeartbeat := now.Add(-2 * time.Minute)
	oldHeartbeat := now.Add(-10 * time.Minute)
	agentRepo.AddAgent(&domain.Agent{ID: "a-1", LastHeartbeatAt: &recentHeartbeat})
	agentRepo.AddAgent(&domain.Agent{ID: "a-2", LastHeartbeatAt: &oldHeartbeat})
	agentRepo.AddAgent(&domain.Agent{ID: "a-3"}) // no heartbeat

	// Add jobs
	jobRepo.AddJob(&domain.Job{ID: "j-1", Status: domain.JobStatusPending})
	jobRepo.AddJob(&domain.Job{ID: "j-2", Status: domain.JobStatusCompleted})
	jobRepo.AddJob(&domain.Job{ID: "j-3", Status: domain.JobStatusFailed})

	result, err := svc.GetDashboardSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	summary := result.(*DashboardSummary)

	if summary.TotalCertificates != 4 {
		t.Errorf("expected 4 total certs, got %d", summary.TotalCertificates)
	}
	if summary.ExpiringCertificates != 1 {
		t.Errorf("expected 1 expiring, got %d", summary.ExpiringCertificates)
	}
	if summary.ExpiredCertificates != 1 {
		t.Errorf("expected 1 expired, got %d", summary.ExpiredCertificates)
	}
	if summary.RevokedCertificates != 1 {
		t.Errorf("expected 1 revoked, got %d", summary.RevokedCertificates)
	}
	if summary.TotalAgents != 3 {
		t.Errorf("expected 3 total agents, got %d", summary.TotalAgents)
	}
	if summary.ActiveAgents != 1 {
		t.Errorf("expected 1 active agent, got %d", summary.ActiveAgents)
	}
	if summary.OfflineAgents != 2 {
		t.Errorf("expected 2 offline agents, got %d", summary.OfflineAgents)
	}
	if summary.PendingJobs != 1 {
		t.Errorf("expected 1 pending job, got %d", summary.PendingJobs)
	}
	if summary.CompleteJobs != 1 {
		t.Errorf("expected 1 complete job, got %d", summary.CompleteJobs)
	}
	if summary.FailedJobs != 1 {
		t.Errorf("expected 1 failed job, got %d", summary.FailedJobs)
	}
}

func TestGetDashboardSummary_CertRepoError(t *testing.T) {
	svc, certRepo, _, _ := newTestStatsService()
	certRepo.ListErr = errNotFound
	_, err := svc.GetDashboardSummary(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetCertificatesByStatus_Empty(t *testing.T) {
	svc, _, _, _ := newTestStatsService()
	result, err := svc.GetCertificatesByStatus(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	counts := result.([]CertificateStatusCount)
	if len(counts) != 0 {
		t.Errorf("expected 0 status counts, got %d", len(counts))
	}
}

func TestGetCertificatesByStatus_WithData(t *testing.T) {
	svc, certRepo, _, _ := newTestStatsService()
	future := time.Now().AddDate(0, 0, 60)
	certRepo.Certs["mc-1"] = &domain.ManagedCertificate{ID: "mc-1", Status: domain.CertificateStatusActive, ExpiresAt: future}
	certRepo.Certs["mc-2"] = &domain.ManagedCertificate{ID: "mc-2", Status: domain.CertificateStatusRevoked}

	result, err := svc.GetCertificatesByStatus(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	counts := result.([]CertificateStatusCount)
	if len(counts) < 2 {
		t.Errorf("expected at least 2 status counts, got %d", len(counts))
	}
}

func TestGetExpirationTimeline_Default(t *testing.T) {
	svc, certRepo, _, _ := newTestStatsService()
	expiresIn10d := time.Now().AddDate(0, 0, 10)
	certRepo.Certs["mc-1"] = &domain.ManagedCertificate{ID: "mc-1", ExpiresAt: expiresIn10d}

	result, err := svc.GetExpirationTimeline(context.Background(), 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	buckets := result.([]ExpirationBucket)
	if len(buckets) != 30 {
		t.Errorf("expected 30 buckets, got %d", len(buckets))
	}
	// At least one bucket should have count > 0
	hasNonZero := false
	for _, b := range buckets {
		if b.Count > 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Error("expected at least one non-zero bucket")
	}
}

func TestGetExpirationTimeline_InvalidDays(t *testing.T) {
	svc, _, _, _ := newTestStatsService()
	result, err := svc.GetExpirationTimeline(context.Background(), -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	buckets := result.([]ExpirationBucket)
	if len(buckets) != 30 {
		t.Errorf("expected default 30 buckets for invalid days, got %d", len(buckets))
	}
}

func TestGetJobStats_Empty(t *testing.T) {
	svc, _, _, _ := newTestStatsService()
	result, err := svc.GetJobStats(context.Background(), 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	points := result.([]JobTrendDataPoint)
	if len(points) != 7 {
		t.Errorf("expected 7 data points, got %d", len(points))
	}
}

func TestGetJobStats_WithData(t *testing.T) {
	svc, _, jobRepo, _ := newTestStatsService()
	completedAt := time.Now()
	jobRepo.AddJob(&domain.Job{ID: "j-1", Status: domain.JobStatusCompleted, CompletedAt: &completedAt})
	jobRepo.AddJob(&domain.Job{ID: "j-2", Status: domain.JobStatusFailed, CompletedAt: &completedAt})

	result, err := svc.GetJobStats(context.Background(), 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	points := result.([]JobTrendDataPoint)

	// The last data point should have today's data
	todayPoint := points[len(points)-1]
	if todayPoint.CompletedCount != 1 {
		t.Errorf("expected 1 completed today, got %d", todayPoint.CompletedCount)
	}
	if todayPoint.FailedCount != 1 {
		t.Errorf("expected 1 failed today, got %d", todayPoint.FailedCount)
	}
	if todayPoint.SuccessRate != 50.0 {
		t.Errorf("expected 50%% success rate, got %.1f%%", todayPoint.SuccessRate)
	}
}

func TestGetIssuanceRate_Empty(t *testing.T) {
	svc, _, _, _ := newTestStatsService()
	result, err := svc.GetIssuanceRate(context.Background(), 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	points := result.([]IssuanceRateDataPoint)
	if len(points) != 7 {
		t.Errorf("expected 7 data points, got %d", len(points))
	}
}

func TestGetIssuanceRate_WithData(t *testing.T) {
	svc, certRepo, _, _ := newTestStatsService()
	certRepo.Certs["mc-1"] = &domain.ManagedCertificate{ID: "mc-1", CreatedAt: time.Now()}
	certRepo.Certs["mc-2"] = &domain.ManagedCertificate{ID: "mc-2", CreatedAt: time.Now()}

	result, err := svc.GetIssuanceRate(context.Background(), 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	points := result.([]IssuanceRateDataPoint)

	todayPoint := points[len(points)-1]
	if todayPoint.IssuedCount != 2 {
		t.Errorf("expected 2 issued today, got %d", todayPoint.IssuedCount)
	}
}

func TestGetIssuanceRate_RepoError(t *testing.T) {
	svc, certRepo, _, _ := newTestStatsService()
	certRepo.ListErr = errNotFound
	_, err := svc.GetIssuanceRate(context.Background(), 7)
	if err == nil {
		t.Fatal("expected error")
	}
}
