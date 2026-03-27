package domain

import (
	"testing"
	"time"
)

func TestNetworkScanTarget_Defaults(t *testing.T) {
	target := NetworkScanTarget{
		ID:                "nst-test",
		Name:              "Test Target",
		CIDRs:             []string{"10.0.0.0/24"},
		Ports:             []int64{443},
		Enabled:           true,
		ScanIntervalHours: 6,
		TimeoutMs:         5000,
	}

	if target.ID != "nst-test" {
		t.Errorf("expected ID nst-test, got %s", target.ID)
	}
	if len(target.CIDRs) != 1 || target.CIDRs[0] != "10.0.0.0/24" {
		t.Errorf("unexpected CIDRs: %v", target.CIDRs)
	}
	if target.LastScanAt != nil {
		t.Error("expected nil LastScanAt for new target")
	}
}

func TestNetworkScanTarget_WithScanResults(t *testing.T) {
	now := time.Now()
	duration := 1500
	found := 12
	target := NetworkScanTarget{
		ID:                 "nst-prod",
		Name:               "Production Network",
		CIDRs:              []string{"192.168.1.0/24", "10.0.0.0/16"},
		Ports:              []int64{443, 8443, 636},
		Enabled:            true,
		ScanIntervalHours:  1,
		TimeoutMs:          3000,
		LastScanAt:         &now,
		LastScanDurationMs: &duration,
		LastScanCertsFound: &found,
	}

	if len(target.Ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(target.Ports))
	}
	if *target.LastScanCertsFound != 12 {
		t.Errorf("expected 12 certs found, got %d", *target.LastScanCertsFound)
	}
}

func TestNetworkScanResult_Fields(t *testing.T) {
	result := NetworkScanResult{
		Address:   "192.168.1.1:443",
		Error:     "",
		LatencyMs: 45,
	}
	if result.Address != "192.168.1.1:443" {
		t.Errorf("expected address 192.168.1.1:443, got %s", result.Address)
	}
	if result.LatencyMs != 45 {
		t.Errorf("expected latency 45ms, got %d", result.LatencyMs)
	}
}
