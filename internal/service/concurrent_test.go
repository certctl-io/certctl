package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// TestConcurrentCertificateList tests that 10 goroutines can safely list certificates simultaneously
func TestConcurrentCertificateList(t *testing.T) {
	mockCertRepo := newMockCertificateRepository()

	// Add test certificates
	for i := 0; i < 20; i++ {
		mockCertRepo.AddCert(&domain.ManagedCertificate{
			ID:         fmt.Sprintf("mc-test-%d", i),
			CommonName: fmt.Sprintf("test-%d.example.com", i),
		})
	}

	certSvc := NewCertificateService(mockCertRepo, nil, nil)

	var wg sync.WaitGroup
	const goroutines = 10
	errChan := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()

			certs, total, err := certSvc.List(ctx, &repository.CertificateFilter{})
			if err != nil {
				errChan <- fmt.Errorf("goroutine %d: failed to list: %w", idx, err)
				return
			}

			if certs == nil {
				errChan <- fmt.Errorf("goroutine %d: returned nil certs slice", idx)
				return
			}

			if total != 20 {
				errChan <- fmt.Errorf("goroutine %d: expected 20 certs, got %d", idx, total)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Verify no errors occurred
	for err := range errChan {
		t.Errorf("concurrent list error: %v", err)
	}
}

// TestConcurrentJobStatusUpdates tests that 10 goroutines can safely update different jobs simultaneously
func TestConcurrentJobStatusUpdates(t *testing.T) {
	mockJobRepo := newMockJobRepository()

	// Create 10 jobs
	for i := 0; i < 10; i++ {
		job := &domain.Job{
			ID:     fmt.Sprintf("job-%d", i),
			Status: domain.JobStatusPending,
		}
		mockJobRepo.AddJob(job)
	}

	var wg sync.WaitGroup
	const goroutines = 10
	errChan := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()

			jobID := fmt.Sprintf("job-%d", idx)
			newStatus := domain.JobStatusRunning

			err := mockJobRepo.UpdateStatus(ctx, jobID, newStatus, "")
			if err != nil {
				errChan <- fmt.Errorf("goroutine %d: failed to update job %s: %w", idx, jobID, err)
				return
			}

			// Verify the update
			job, err := mockJobRepo.Get(ctx, jobID)
			if err != nil {
				errChan <- fmt.Errorf("goroutine %d: failed to get job %s: %w", idx, jobID, err)
				return
			}

			if job.Status != newStatus {
				errChan <- fmt.Errorf("goroutine %d: job %s status is %s, expected %s", idx, jobID, job.Status, newStatus)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Verify no errors occurred
	for err := range errChan {
		t.Errorf("concurrent job update error: %v", err)
	}
}

// TestConcurrentAgentHeartbeats tests that 10 goroutines can safely send heartbeats for different agents simultaneously
func TestConcurrentAgentHeartbeats(t *testing.T) {
	mockAgentRepo := newMockAgentRepository()

	// Create 10 agents
	for i := 0; i < 10; i++ {
		agent := &domain.Agent{
			ID:       fmt.Sprintf("agent-%d", i),
			Name:     fmt.Sprintf("agent-%d", i),
			Hostname: fmt.Sprintf("host-%d", i),
		}
		mockAgentRepo.AddAgent(agent)
	}

	issuerRegistry := NewIssuerRegistry(slog.Default())
	agentSvc := NewAgentService(
		mockAgentRepo,
		nil, // certRepo
		nil, // jobRepo
		nil, // targetRepo
		nil, // auditService
		issuerRegistry,
		nil, // renewalService
	)

	var wg sync.WaitGroup
	const goroutines = 10
	errChan := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()

			agentID := fmt.Sprintf("agent-%d", idx)
			metadata := &domain.AgentMetadata{
				OS:           "linux",
				Architecture: "x86_64",
			}

			err := agentSvc.HeartbeatWithContext(ctx, agentID, metadata)
			if err != nil {
				errChan <- fmt.Errorf("goroutine %d: failed heartbeat for agent %s: %w", idx, agentID, err)
				return
			}

			// Verify the heartbeat was recorded
			agent, err := mockAgentRepo.Get(ctx, agentID)
			if err != nil {
				errChan <- fmt.Errorf("goroutine %d: failed to get agent %s: %w", idx, agentID, err)
				return
			}

			if agent.LastHeartbeatAt == nil {
				errChan <- fmt.Errorf("goroutine %d: agent %s has no heartbeat", idx, agentID)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Verify no errors occurred
	for err := range errChan {
		t.Errorf("concurrent heartbeat error: %v", err)
	}
}

// TestConcurrentTargetCRUD tests concurrent create/list/delete operations on targets
func TestConcurrentTargetCRUD(t *testing.T) {
	mockTargetRepo := &mockTargetRepo{
		Targets: make(map[string]*domain.DeploymentTarget),
	}

	targetSvc := NewTargetService(mockTargetRepo, nil, nil, nil, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	var mu sync.Mutex
	createdTargets := make([]string, 0)

	var wg sync.WaitGroup

	// Phase 1: Create 5 targets in parallel
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()

			target := &domain.DeploymentTarget{
				ID:   fmt.Sprintf("target-create-%d", idx),
				Name: fmt.Sprintf("target-%d", idx),
				Type: domain.TargetTypeNGINX,
			}

			err := targetSvc.Create(ctx, target, "test-user")
			if err != nil {
				t.Errorf("concurrent create error: %v", err)
				return
			}

			mu.Lock()
			createdTargets = append(createdTargets, target.ID)
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// Phase 2: List targets in parallel
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()

			_, _, err := targetSvc.List(ctx, 1, 50)
			if err != nil {
				t.Errorf("goroutine %d: concurrent list error: %v", idx, err)
				return
			}
		}(i)
	}

	wg.Wait()

	// Phase 3: Delete created targets in parallel
	for _, targetID := range createdTargets {
		targetIDCopy := targetID // Capture for closure
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()

			err := targetSvc.Delete(ctx, targetIDCopy, "test-user")
			if err != nil {
				t.Errorf("concurrent delete error: %v", err)
				return
			}
		}()
	}

	wg.Wait()

	// Verify all targets were deleted
	targets, err := mockTargetRepo.List(context.Background())
	if err != nil {
		t.Fatalf("failed to list targets: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets after deletion, got %d", len(targets))
	}
}

// TestConcurrentNotificationProcessing tests concurrent notification sends
func TestConcurrentNotificationProcessing(t *testing.T) {
	mockNotifRepo := newMockNotificationRepository()
	mockNotifier := newMockNotifier()

	var wg sync.WaitGroup
	const goroutines = 10
	errChan := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()

			notif := &domain.NotificationEvent{
				ID:        fmt.Sprintf("notif-%d", idx),
				Type:      domain.NotificationTypeExpirationWarning,
				Recipient: fmt.Sprintf("user-%d@example.com", idx),
				Message:   fmt.Sprintf("Notification message %d", idx),
				Status:    "pending",
			}

			err := mockNotifRepo.Create(ctx, notif)
			if err != nil {
				errChan <- fmt.Errorf("goroutine %d: failed to create notification: %w", idx, err)
				return
			}

			// Simulate sending notification
			err = mockNotifier.Send(ctx, notif.Recipient, "Certificate Expiring", notif.Message)
			if err != nil {
				errChan <- fmt.Errorf("goroutine %d: failed to send notification: %w", idx, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Verify no errors occurred
	for err := range errChan {
		t.Errorf("concurrent notification error: %v", err)
	}

	// Verify all notifications were processed
	if len(mockNotifRepo.Notifications) != goroutines {
		t.Errorf("expected %d notifications, got %d", goroutines, len(mockNotifRepo.Notifications))
	}

	if len(mockNotifier.messages) != goroutines {
		t.Errorf("expected %d sent messages, got %d", goroutines, len(mockNotifier.messages))
	}
}

// TestConcurrentAuditRecording tests concurrent audit event recording
func TestConcurrentAuditRecording(t *testing.T) {
	mockAuditRepo := newMockAuditRepository()
	auditSvc := &AuditService{auditRepo: mockAuditRepo}

	var wg sync.WaitGroup
	const goroutines = 10
	errChan := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()

			actor := fmt.Sprintf("user-%d", idx)
			eventType := "create_certificate"
			resourceID := fmt.Sprintf("cert-%d", idx)

			err := auditSvc.RecordEvent(
				ctx,
				actor,
				domain.ActorTypeUser,
				eventType,
				"certificate",
				resourceID,
				map[string]interface{}{"index": idx},
			)
			if err != nil {
				errChan <- fmt.Errorf("goroutine %d: failed to record audit event: %w", idx, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Verify no errors occurred
	for err := range errChan {
		t.Errorf("concurrent audit error: %v", err)
	}

	// Verify all audit events were recorded
	if len(mockAuditRepo.Events) != goroutines {
		t.Errorf("expected %d audit events, got %d", goroutines, len(mockAuditRepo.Events))
	}
}

// TestConcurrentMixedOperations tests mixed concurrent operations on multiple services
func TestConcurrentMixedOperations(t *testing.T) {
	// Setup repositories
	mockCertRepo := newMockCertificateRepository()
	mockJobRepo := newMockJobRepository()
	mockAuditRepo := newMockAuditRepository()
	mockTargetRepo := &mockTargetRepo{
		Targets: make(map[string]*domain.DeploymentTarget),
	}

	// Add initial test data
	for i := 0; i < 5; i++ {
		mockCertRepo.AddCert(&domain.ManagedCertificate{
			ID:         fmt.Sprintf("mc-mixed-%d", i),
			CommonName: fmt.Sprintf("mixed-%d.example.com", i),
		})
		mockJobRepo.AddJob(&domain.Job{
			ID:     fmt.Sprintf("job-mixed-%d", i),
			Status: domain.JobStatusPending,
		})
	}

	// Setup services
	auditSvc := &AuditService{auditRepo: mockAuditRepo}
	certSvc := NewCertificateService(mockCertRepo, nil, auditSvc)
	targetSvc := NewTargetService(mockTargetRepo, auditSvc, nil, nil, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	var wg sync.WaitGroup
	errChan := make(chan error, 30)

	// Launch mixed concurrent operations
	for i := 0; i < 10; i++ {
		// Certificate operations
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()

			_, _, err := certSvc.List(ctx, &repository.CertificateFilter{})
			if err != nil {
				errChan <- fmt.Errorf("cert list %d: %w", idx, err)
			}
		}(i)

		// Target operations
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()

			_, _, err := targetSvc.List(ctx, 1, 50)
			if err != nil {
				errChan <- fmt.Errorf("target list %d: %w", idx, err)
			}
		}(i)

		// Audit operations
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()

			err := auditSvc.RecordEvent(
				ctx,
				fmt.Sprintf("user-%d", idx),
				domain.ActorTypeUser,
				"test_event",
				"test",
				fmt.Sprintf("test-%d", idx),
				nil,
			)
			if err != nil {
				errChan <- fmt.Errorf("audit record %d: %w", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Verify no errors occurred
	errorCount := 0
	for err := range errChan {
		t.Logf("concurrent mixed error: %v", err)
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("had %d concurrent operation errors", errorCount)
	}
}
