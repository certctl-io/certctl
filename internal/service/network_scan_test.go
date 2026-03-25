package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// mockNetworkScanRepo for testing
type mockNetworkScanRepo struct {
	targets []*domain.NetworkScanTarget
}

func (m *mockNetworkScanRepo) List(ctx context.Context) ([]*domain.NetworkScanTarget, error) {
	return m.targets, nil
}

func (m *mockNetworkScanRepo) ListEnabled(ctx context.Context) ([]*domain.NetworkScanTarget, error) {
	var enabled []*domain.NetworkScanTarget
	for _, t := range m.targets {
		if t.Enabled {
			enabled = append(enabled, t)
		}
	}
	return enabled, nil
}

func (m *mockNetworkScanRepo) Get(ctx context.Context, id string) (*domain.NetworkScanTarget, error) {
	for _, t := range m.targets {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, fmt.Errorf("not found: %s", id)
}

func (m *mockNetworkScanRepo) Create(ctx context.Context, target *domain.NetworkScanTarget) error {
	m.targets = append(m.targets, target)
	return nil
}

func (m *mockNetworkScanRepo) Update(ctx context.Context, target *domain.NetworkScanTarget) error {
	for i, t := range m.targets {
		if t.ID == target.ID {
			m.targets[i] = target
			return nil
		}
	}
	return fmt.Errorf("not found: %s", target.ID)
}

func (m *mockNetworkScanRepo) Delete(ctx context.Context, id string) error {
	for i, t := range m.targets {
		if t.ID == id {
			m.targets = append(m.targets[:i], m.targets[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("not found: %s", id)
}

func (m *mockNetworkScanRepo) UpdateScanResults(ctx context.Context, id string, scanAt time.Time, durationMs int, certsFound int) error {
	for _, t := range m.targets {
		if t.ID == id {
			t.LastScanAt = &scanAt
			d := durationMs
			t.LastScanDurationMs = &d
			c := certsFound
			t.LastScanCertsFound = &c
			return nil
		}
	}
	return fmt.Errorf("not found: %s", id)
}

func TestExpandCIDR_SingleIP(t *testing.T) {
	ips := expandCIDR("192.168.1.1")
	if len(ips) != 1 || ips[0] != "192.168.1.1" {
		t.Errorf("expected [192.168.1.1], got %v", ips)
	}
}

func TestExpandCIDR_Slash30(t *testing.T) {
	// /30 = 4 total addresses, 2 usable (remove network + broadcast)
	ips := expandCIDR("10.0.0.0/30")
	if len(ips) != 2 {
		t.Errorf("expected 2 usable IPs for /30, got %d: %v", len(ips), ips)
	}
}

func TestExpandCIDR_Slash24(t *testing.T) {
	ips := expandCIDR("10.0.0.0/24")
	if len(ips) != 254 {
		t.Errorf("expected 254 usable IPs for /24, got %d", len(ips))
	}
}

func TestExpandCIDR_TooLarge(t *testing.T) {
	// /16 = 65536 IPs, exceeds /20 cap
	ips := expandCIDR("10.0.0.0/16")
	if len(ips) != 0 {
		t.Errorf("expected empty for /16 (too large), got %d", len(ips))
	}
}

func TestExpandCIDR_InvalidInput(t *testing.T) {
	ips := expandCIDR("not-a-cidr")
	if len(ips) != 0 {
		t.Errorf("expected empty for invalid input, got %v", ips)
	}
}

func TestNetworkScanService_CreateTarget(t *testing.T) {
	repo := &mockNetworkScanRepo{}
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	svc := NewNetworkScanService(repo, nil, auditService, nil)

	target, err := svc.CreateTarget(context.Background(), &domain.NetworkScanTarget{
		Name:  "Test Network",
		CIDRs: []string{"10.0.0.0/24"},
		Ports: []int{443, 8443},
	})
	if err != nil {
		t.Fatalf("CreateTarget failed: %v", err)
	}
	if target.ID == "" {
		t.Error("expected non-empty ID")
	}
	if !target.Enabled {
		t.Error("expected target to be enabled by default")
	}
	if target.ScanIntervalHours != 6 {
		t.Errorf("expected default interval 6h, got %d", target.ScanIntervalHours)
	}
	if target.TimeoutMs != 5000 {
		t.Errorf("expected default timeout 5000ms, got %d", target.TimeoutMs)
	}
}

func TestNetworkScanService_CreateTarget_ValidationErrors(t *testing.T) {
	repo := &mockNetworkScanRepo{}
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)
	svc := NewNetworkScanService(repo, nil, auditService, nil)

	tests := []struct {
		name   string
		target *domain.NetworkScanTarget
		errMsg string
	}{
		{
			name:   "missing name",
			target: &domain.NetworkScanTarget{CIDRs: []string{"10.0.0.0/24"}},
			errMsg: "name is required",
		},
		{
			name:   "missing cidrs",
			target: &domain.NetworkScanTarget{Name: "test"},
			errMsg: "at least one CIDR is required",
		},
		{
			name:   "invalid cidr",
			target: &domain.NetworkScanTarget{Name: "test", CIDRs: []string{"not-valid"}},
			errMsg: "invalid CIDR or IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateTarget(context.Background(), tt.target)
			if err == nil {
				t.Fatal("expected error")
			}
			if !containsSubstring(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestNetworkScanService_DeleteTarget(t *testing.T) {
	repo := &mockNetworkScanRepo{
		targets: []*domain.NetworkScanTarget{
			{ID: "nst-1", Name: "test"},
		},
	}
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)
	svc := NewNetworkScanService(repo, nil, auditService, nil)

	if err := svc.DeleteTarget(context.Background(), "nst-1"); err != nil {
		t.Fatalf("DeleteTarget failed: %v", err)
	}
	if len(repo.targets) != 0 {
		t.Error("expected target to be deleted")
	}
}

func TestNetworkScanService_ListTargets(t *testing.T) {
	repo := &mockNetworkScanRepo{
		targets: []*domain.NetworkScanTarget{
			{ID: "nst-1", Name: "target1"},
			{ID: "nst-2", Name: "target2"},
		},
	}
	svc := NewNetworkScanService(repo, nil, nil, nil)

	targets, err := svc.ListTargets(context.Background())
	if err != nil {
		t.Fatalf("ListTargets failed: %v", err)
	}
	if len(targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(targets))
	}
}

func TestExpandEndpoints(t *testing.T) {
	svc := &NetworkScanService{}
	endpoints := svc.expandEndpoints([]string{"192.168.1.1"}, []int{443, 8443})
	if len(endpoints) != 2 {
		t.Errorf("expected 2 endpoints, got %d: %v", len(endpoints), endpoints)
	}
	if endpoints[0] != "192.168.1.1:443" {
		t.Errorf("expected 192.168.1.1:443, got %s", endpoints[0])
	}
	if endpoints[1] != "192.168.1.1:8443" {
		t.Errorf("expected 192.168.1.1:8443, got %s", endpoints[1])
	}
}
