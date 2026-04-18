package service

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/validation"
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
		Ports: []int64{443, 8443},
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
	endpoints := svc.expandEndpoints([]string{"192.168.1.1"}, []int64{443, 8443})
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

// SSRF Protection Tests

func TestIsReservedIP_Loopback(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		{"127.0.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := validation.IsReservedIP(net.ParseIP(tt.ip))
			if result != tt.expected {
				t.Errorf("validation.IsReservedIP(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsReservedIP_LinkLocal(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"169.254.0.1", true},
		{"169.254.169.254", true}, // AWS cloud metadata
		{"169.254.255.255", true},
		{"169.254.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := validation.IsReservedIP(net.ParseIP(tt.ip))
			if result != tt.expected {
				t.Errorf("validation.IsReservedIP(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsReservedIP_Multicast(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"224.0.0.1", true},
		{"239.255.255.255", true},
		{"224.0.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := validation.IsReservedIP(net.ParseIP(tt.ip))
			if result != tt.expected {
				t.Errorf("validation.IsReservedIP(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsReservedIP_Broadcast(t *testing.T) {
	result := validation.IsReservedIP(net.ParseIP("255.255.255.255"))
	if !result {
		t.Errorf("validation.IsReservedIP(255.255.255.255) = %v, expected true", result)
	}
}

func TestIsReservedIP_AllowsPrivateRanges(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
		desc     string
	}{
		{"10.0.0.1", false, "RFC1918 10/8"},
		{"10.255.255.255", false, "RFC1918 10/8 end"},
		{"172.16.0.1", false, "RFC1918 172.16/12"},
		{"172.31.255.255", false, "RFC1918 172.16/12 end"},
		{"192.168.1.1", false, "RFC1918 192.168/16"},
		{"192.168.255.255", false, "RFC1918 192.168/16 end"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := validation.IsReservedIP(net.ParseIP(tt.ip))
			if result != tt.expected {
				t.Errorf("validation.IsReservedIP(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsReservedIP_AllowsPublic(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"208.67.222.222", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := validation.IsReservedIP(net.ParseIP(tt.ip))
			if result != tt.expected {
				t.Errorf("validation.IsReservedIP(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestExpandCIDR_FiltersLoopback(t *testing.T) {
	ips := expandCIDR("127.0.0.0/8")
	if len(ips) != 0 {
		t.Errorf("expected empty for loopback CIDR, got %d IPs", len(ips))
	}
}

func TestExpandCIDR_FiltersLinkLocal(t *testing.T) {
	ips := expandCIDR("169.254.0.0/16")
	if len(ips) != 0 {
		t.Errorf("expected empty for link-local CIDR, got %d IPs", len(ips))
	}
}

func TestExpandCIDR_FiltersMulticast(t *testing.T) {
	ips := expandCIDR("224.0.0.0/4")
	if len(ips) != 0 {
		t.Errorf("expected empty for multicast CIDR, got %d IPs", len(ips))
	}
}

func TestExpandCIDR_AllowsPrivateRanges(t *testing.T) {
	// Should NOT filter RFC1918 ranges
	tests := []struct {
		name string
		cidr string
		min  int
	}{
		{"10/8 sample", "10.0.0.0/30", 2},         // 2 usable (after removing network/broadcast)
		{"172.16/12 sample", "172.16.0.0/30", 2}, // 2 usable
		{"192.168/16 sample", "192.168.1.1/32", 1}, // Single IP
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := expandCIDR(tt.cidr)
			if len(ips) < tt.min {
				t.Errorf("expected at least %d IPs for %s, got %d", tt.min, tt.cidr, len(ips))
			}
		})
	}
}

// AUDIT-003: CIDR size validation at API level

func TestValidateCIDRs_AcceptsValidSizes(t *testing.T) {
	tests := []struct {
		name  string
		cidrs []string
	}{
		{"single IP", []string{"192.168.1.1"}},
		{"/24 network", []string{"10.0.0.0/24"}},
		{"/20 network (max)", []string{"10.0.0.0/20"}},
		{"/30 tiny network", []string{"10.0.0.0/30"}},
		{"multiple valid", []string{"10.0.0.0/24", "192.168.1.0/24"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCIDRs(tt.cidrs)
			if err != nil {
				t.Errorf("expected valid CIDRs to be accepted, got error: %v", err)
			}
		})
	}
}

func TestValidateCIDRs_RejectsOversized(t *testing.T) {
	tests := []struct {
		name  string
		cidrs []string
	}{
		{"/19 too large", []string{"10.0.0.0/19"}},
		{"/16 way too large", []string{"10.0.0.0/16"}},
		{"/8 massive", []string{"10.0.0.0/8"}},
		{"/0 everything", []string{"0.0.0.0/0"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCIDRs(tt.cidrs)
			if err == nil {
				t.Errorf("expected oversized CIDR %v to be rejected", tt.cidrs)
			}
		})
	}
}

func TestValidateCIDRs_RejectsInvalid(t *testing.T) {
	err := validateCIDRs([]string{"not-a-cidr"})
	if err == nil {
		t.Error("expected invalid CIDR to be rejected")
	}
}

func TestNetworkScanService_CreateTarget_RejectsOversizedCIDR(t *testing.T) {
	repo := &mockNetworkScanRepo{}
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)
	svc := NewNetworkScanService(repo, nil, auditService, nil)

	_, err := svc.CreateTarget(context.Background(), &domain.NetworkScanTarget{
		Name:  "Test",
		CIDRs: []string{"10.0.0.0/8"},
	})
	if err == nil {
		t.Fatal("expected CreateTarget to reject /8 CIDR")
	}
}

func TestNetworkScanService_UpdateTarget_RejectsOversizedCIDR(t *testing.T) {
	repo := &mockNetworkScanRepo{
		targets: []*domain.NetworkScanTarget{
			{ID: "nst-1", Name: "Original", CIDRs: []string{"10.0.0.0/24"}, Enabled: true},
		},
	}
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)
	svc := NewNetworkScanService(repo, nil, auditService, nil)

	// Try to update from /24 to /8 — should be rejected
	_, err := svc.UpdateTarget(context.Background(), "nst-1", &domain.NetworkScanTarget{
		CIDRs: []string{"10.0.0.0/8"},
	})
	if err == nil {
		t.Fatal("expected UpdateTarget to reject /8 CIDR update (bypass attempt)")
	}
}

func TestExpandCIDR_SingleLoopbackIP(t *testing.T) {
	ips := expandCIDR("127.0.0.1")
	if len(ips) != 0 {
		t.Errorf("expected empty for loopback IP, got %v", ips)
	}
}

func TestExpandCIDR_SingleLinkLocalIP(t *testing.T) {
	ips := expandCIDR("169.254.169.254")
	if len(ips) != 0 {
		t.Errorf("expected empty for cloud metadata IP, got %v", ips)
	}
}

// TestCollectScanResults_AggregatesErrors is the M-9 regression guard:
// per-endpoint probe failures must accumulate into the errors slice so the
// summary Info log and the DiscoveryReport reflect the true failure count.
// Before the M-9 fix, scanErrors was declared but never appended to, so the
// aggregate count was always zero and the scan record's Errors field was
// always nil — silently hiding per-endpoint failures from operators.
func TestCollectScanResults_AggregatesErrors(t *testing.T) {
	svc := &NetworkScanService{}
	results := []domain.NetworkScanResult{
		{Address: "203.0.113.1:443", Error: "connection refused"},
		{Address: "203.0.113.2:443", Certs: []domain.DiscoveredCertEntry{
			{CommonName: "example.com"},
		}},
		{Address: "203.0.113.3:443", Error: "tls handshake failure"},
		{Address: "203.0.113.4:443", Certs: []domain.DiscoveredCertEntry{
			{CommonName: "internal.example.com"},
		}},
		{Address: "203.0.113.5:443", Error: "i/o timeout"},
	}

	entries, errs := svc.collectScanResults(results)

	if len(entries) != 2 {
		t.Errorf("expected 2 entries (one per successful probe), got %d", len(entries))
	}
	if len(errs) != 3 {
		t.Fatalf("expected 3 error strings (one per failed probe), got %d: %v", len(errs), errs)
	}

	// Each error string must be non-empty and include the endpoint address so
	// the scan record lets operators correlate failures back to endpoints
	// without needing Debug logging enabled.
	for i, e := range errs {
		if e == "" {
			t.Errorf("error[%d]: expected non-empty error string", i)
		}
	}

	// Spot-check that address is threaded through the error strings.
	if want := "203.0.113.1:443"; errs[0] == "" || errs[0][:len(want)] != want {
		t.Errorf("errs[0] should start with %q, got %q", want, errs[0])
	}
	if want := "203.0.113.3:443"; errs[1] == "" || errs[1][:len(want)] != want {
		t.Errorf("errs[1] should start with %q, got %q", want, errs[1])
	}
	if want := "203.0.113.5:443"; errs[2] == "" || errs[2][:len(want)] != want {
		t.Errorf("errs[2] should start with %q, got %q", want, errs[2])
	}
}

// TestCollectScanResults_AllSuccess exercises the happy path: a scan where
// every endpoint returned certificates. The errors slice must be nil (not an
// empty non-nil slice) so the downstream DiscoveryReport.Errors field stays
// nil as well, preserving the JSON-omitempty behavior that callers rely on.
func TestCollectScanResults_AllSuccess(t *testing.T) {
	svc := &NetworkScanService{}
	results := []domain.NetworkScanResult{
		{Address: "203.0.113.10:443", Certs: []domain.DiscoveredCertEntry{
			{CommonName: "a.example.com"},
		}},
		{Address: "203.0.113.11:443", Certs: []domain.DiscoveredCertEntry{
			{CommonName: "b.example.com"},
		}},
	}

	entries, errs := svc.collectScanResults(results)

	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
	if errs != nil {
		t.Errorf("expected nil errors slice on all-success, got %v", errs)
	}
}

// TestCollectScanResults_AllFailed exercises the worst-case sweep: every
// endpoint failed to probe. Entries must be nil, and every failure must be
// recorded in the errors slice so the scan record is complete.
func TestCollectScanResults_AllFailed(t *testing.T) {
	svc := &NetworkScanService{}
	results := []domain.NetworkScanResult{
		{Address: "203.0.113.20:443", Error: "connection refused"},
		{Address: "203.0.113.21:443", Error: "connection refused"},
		{Address: "203.0.113.22:443", Error: "connection refused"},
	}

	entries, errs := svc.collectScanResults(results)

	if entries != nil {
		t.Errorf("expected nil entries on all-failed, got %v", entries)
	}
	if len(errs) != 3 {
		t.Errorf("expected 3 error strings, got %d: %v", len(errs), errs)
	}
}

// TestCollectScanResults_Empty guards against a degenerate empty-input case
// (scanEndpoints returns no results, e.g. if ctx was cancelled before the
// first probe ran). Both return slices must be nil.
func TestCollectScanResults_Empty(t *testing.T) {
	svc := &NetworkScanService{}
	entries, errs := svc.collectScanResults(nil)
	if entries != nil {
		t.Errorf("expected nil entries for empty input, got %v", entries)
	}
	if errs != nil {
		t.Errorf("expected nil errors for empty input, got %v", errs)
	}
}
