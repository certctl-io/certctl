package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// mockHealthCheckRepo implements the HealthCheckRepository interface for testing.
type mockHealthCheckRepo struct {
	checks           map[string]*domain.EndpointHealthCheck
	history          []*domain.HealthHistoryEntry
	createErr        error
	getErr           error
	updateErr        error
	deleteErr        error
	listErr          error
	listDueErr       error
	getHistoryErr    error
	recordHistoryErr error
	purgeHistoryErr  error
	getSummaryErr    error
	getSummaryResult *domain.HealthCheckSummary
}

func newMockHealthCheckRepo() *mockHealthCheckRepo {
	return &mockHealthCheckRepo{
		checks:  make(map[string]*domain.EndpointHealthCheck),
		history: []*domain.HealthHistoryEntry{},
		getSummaryResult: &domain.HealthCheckSummary{
			Healthy:      0,
			Degraded:     0,
			Down:         0,
			CertMismatch: 0,
			Unknown:      0,
		},
	}
}

func (m *mockHealthCheckRepo) Create(ctx context.Context, check *domain.EndpointHealthCheck) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.checks[check.ID] = check
	return nil
}

func (m *mockHealthCheckRepo) Get(ctx context.Context, id string) (*domain.EndpointHealthCheck, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if check, ok := m.checks[id]; ok {
		return check, nil
	}
	return nil, errors.New("not found")
}

func (m *mockHealthCheckRepo) GetByEndpoint(ctx context.Context, endpoint string) (*domain.EndpointHealthCheck, error) {
	for _, check := range m.checks {
		if check.Endpoint == endpoint {
			return check, nil
		}
	}
	return nil, errors.New("not found")
}

func (m *mockHealthCheckRepo) Update(ctx context.Context, check *domain.EndpointHealthCheck) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.checks[check.ID] = check
	return nil
}

func (m *mockHealthCheckRepo) Delete(ctx context.Context, id string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.checks, id)
	return nil
}

func (m *mockHealthCheckRepo) List(ctx context.Context, filter *repository.HealthCheckFilter) ([]*domain.EndpointHealthCheck, int, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	checks := make([]*domain.EndpointHealthCheck, 0, len(m.checks))
	for _, check := range m.checks {
		checks = append(checks, check)
	}
	return checks, len(checks), nil
}

func (m *mockHealthCheckRepo) ListDueForCheck(ctx context.Context) ([]*domain.EndpointHealthCheck, error) {
	if m.listDueErr != nil {
		return nil, m.listDueErr
	}
	checks := make([]*domain.EndpointHealthCheck, 0, len(m.checks))
	for _, check := range m.checks {
		if check.Enabled {
			checks = append(checks, check)
		}
	}
	return checks, nil
}

func (m *mockHealthCheckRepo) GetHistory(ctx context.Context, healthCheckID string, limit int) ([]*domain.HealthHistoryEntry, error) {
	if m.getHistoryErr != nil {
		return nil, m.getHistoryErr
	}
	return m.history, nil
}

func (m *mockHealthCheckRepo) RecordHistory(ctx context.Context, entry *domain.HealthHistoryEntry) error {
	if m.recordHistoryErr != nil {
		return m.recordHistoryErr
	}
	m.history = append(m.history, entry)
	return nil
}

func (m *mockHealthCheckRepo) PurgeHistory(ctx context.Context, before time.Time) (int64, error) {
	if m.purgeHistoryErr != nil {
		return 0, m.purgeHistoryErr
	}
	return 0, nil
}

func (m *mockHealthCheckRepo) GetSummary(ctx context.Context) (*domain.HealthCheckSummary, error) {
	if m.getSummaryErr != nil {
		return nil, m.getSummaryErr
	}
	return m.getSummaryResult, nil
}

// Tests

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestHealthCheckService_Create_Success(t *testing.T) {
	repo := newMockHealthCheckRepo()
	logger := newTestLogger()
	svc := NewHealthCheckService(repo, nil, logger, 10, 5*time.Second, 30*24*time.Hour, false)

	check := &domain.EndpointHealthCheck{
		Endpoint:          "example.com:443",
		Status:            domain.HealthStatusUnknown,
		Enabled:           true,
		CheckIntervalSecs: 300,
	}

	err := svc.Create(context.Background(), check)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if check.ID == "" {
		t.Fatal("Expected ID to be set")
	}

	retrieved, _ := repo.Get(context.Background(), check.ID)
	if retrieved == nil {
		t.Fatal("Expected check to be in repo")
	}
	if retrieved.Endpoint != "example.com:443" {
		t.Errorf("Expected endpoint example.com:443, got %s", retrieved.Endpoint)
	}
}

func TestHealthCheckService_Create_RepoError(t *testing.T) {
	repo := newMockHealthCheckRepo()
	repo.createErr = errors.New("db error")
	logger := newTestLogger()
	svc := NewHealthCheckService(repo, nil, logger, 10, 5*time.Second, 30*24*time.Hour, false)

	check := &domain.EndpointHealthCheck{
		Endpoint: "example.com:443",
		Enabled:  true,
	}

	err := svc.Create(context.Background(), check)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

func TestHealthCheckService_Get_Success(t *testing.T) {
	repo := newMockHealthCheckRepo()
	logger := newTestLogger()
	svc := NewHealthCheckService(repo, nil, logger, 10, 5*time.Second, 30*24*time.Hour, false)

	check := &domain.EndpointHealthCheck{
		ID:       "hc-test-1",
		Endpoint: "example.com:443",
		Status:   domain.HealthStatusHealthy,
	}
	repo.checks["hc-test-1"] = check

	retrieved, err := svc.Get(context.Background(), "hc-test-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if retrieved.Endpoint != "example.com:443" {
		t.Errorf("Expected endpoint example.com:443, got %s", retrieved.Endpoint)
	}
}

func TestHealthCheckService_Get_NotFound(t *testing.T) {
	repo := newMockHealthCheckRepo()
	logger := newTestLogger()
	svc := NewHealthCheckService(repo, nil, logger, 10, 5*time.Second, 30*24*time.Hour, false)

	_, err := svc.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("Expected error for nonexistent check")
	}
}

func TestHealthCheckService_List_Success(t *testing.T) {
	repo := newMockHealthCheckRepo()
	logger := newTestLogger()
	svc := NewHealthCheckService(repo, nil, logger, 10, 5*time.Second, 30*24*time.Hour, false)

	check1 := &domain.EndpointHealthCheck{
		ID:       "hc-1",
		Endpoint: "api.example.com:443",
		Status:   domain.HealthStatusHealthy,
	}
	check2 := &domain.EndpointHealthCheck{
		ID:       "hc-2",
		Endpoint: "web.example.com:443",
		Status:   domain.HealthStatusDegraded,
	}
	repo.checks["hc-1"] = check1
	repo.checks["hc-2"] = check2

	checks, total, err := svc.List(context.Background(), nil)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(checks) != 2 {
		t.Errorf("Expected 2 checks, got %d", len(checks))
	}
	if total != 2 {
		t.Errorf("Expected total 2, got %d", total)
	}
}

func TestHealthCheckService_Delete_Success(t *testing.T) {
	repo := newMockHealthCheckRepo()
	logger := newTestLogger()
	svc := NewHealthCheckService(repo, nil, logger, 10, 5*time.Second, 30*24*time.Hour, false)

	check := &domain.EndpointHealthCheck{
		ID:       "hc-test-1",
		Endpoint: "example.com:443",
	}
	repo.checks["hc-test-1"] = check

	err := svc.Delete(context.Background(), "hc-test-1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if _, ok := repo.checks["hc-test-1"]; ok {
		t.Fatal("Expected check to be deleted")
	}
}

func TestHealthCheckService_AcknowledgeIncident_Success(t *testing.T) {
	repo := newMockHealthCheckRepo()
	logger := newTestLogger()
	svc := NewHealthCheckService(repo, nil, logger, 10, 5*time.Second, 30*24*time.Hour, false)

	check := &domain.EndpointHealthCheck{
		ID:           "hc-test-1",
		Endpoint:     "example.com:443",
		Status:       domain.HealthStatusDown,
		Acknowledged: false,
	}
	repo.checks["hc-test-1"] = check

	err := svc.AcknowledgeIncident(context.Background(), "hc-test-1", "user@example.com")
	if err != nil {
		t.Fatalf("AcknowledgeIncident failed: %v", err)
	}

	retrieved := repo.checks["hc-test-1"]
	if !retrieved.Acknowledged {
		t.Fatal("Expected Acknowledged to be true")
	}
	if retrieved.AcknowledgedBy != "user@example.com" {
		t.Errorf("Expected AcknowledgedBy to be user@example.com, got %s", retrieved.AcknowledgedBy)
	}
	if retrieved.AcknowledgedAt == nil {
		t.Fatal("Expected AcknowledgedAt to be set")
	}
}

func TestHealthCheckService_GetSummary_Success(t *testing.T) {
	repo := newMockHealthCheckRepo()
	logger := newTestLogger()
	svc := NewHealthCheckService(repo, nil, logger, 10, 5*time.Second, 30*24*time.Hour, false)

	repo.getSummaryResult = &domain.HealthCheckSummary{
		Healthy:      5,
		Degraded:     2,
		Down:         1,
		CertMismatch: 1,
		Unknown:      0,
	}

	summary, err := svc.GetSummary(context.Background())
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}
	if summary.Healthy != 5 {
		t.Errorf("Expected 5 healthy, got %d", summary.Healthy)
	}
}

func TestHealthCheckService_RunHealthChecks_NoEndpoints(t *testing.T) {
	repo := newMockHealthCheckRepo()
	logger := newTestLogger()
	svc := NewHealthCheckService(repo, nil, logger, 10, 5*time.Second, 30*24*time.Hour, false)

	err := svc.RunHealthChecks(context.Background())
	if err != nil {
		t.Fatalf("RunHealthChecks failed: %v", err)
	}
}

func TestHealthCheckService_PurgeOldHistory_Success(t *testing.T) {
	repo := newMockHealthCheckRepo()
	logger := newTestLogger()
	svc := NewHealthCheckService(repo, nil, logger, 10, 5*time.Second, 30*24*time.Hour, false)

	err := svc.PurgeOldHistory(context.Background())
	if err != nil {
		t.Fatalf("PurgeOldHistory failed: %v", err)
	}
}
