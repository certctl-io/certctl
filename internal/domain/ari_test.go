package domain

import (
	"testing"
	"time"
)

func TestRenewalInfo_ShouldRenewNow_BeforeWindow(t *testing.T) {
	now := time.Now()
	windowStart := now.Add(1 * time.Hour)
	windowEnd := now.Add(2 * time.Hour)

	ri := &RenewalInfo{
		SuggestedWindowStart: windowStart,
		SuggestedWindowEnd:   windowEnd,
	}

	if ri.ShouldRenewNow() {
		t.Error("ShouldRenewNow should be false before window start")
	}
}

func TestRenewalInfo_ShouldRenewNow_AtWindowStart(t *testing.T) {
	now := time.Now()
	windowStart := now
	windowEnd := now.Add(1 * time.Hour)

	ri := &RenewalInfo{
		SuggestedWindowStart: windowStart,
		SuggestedWindowEnd:   windowEnd,
	}

	if !ri.ShouldRenewNow() {
		t.Error("ShouldRenewNow should be true at window start")
	}
}

func TestRenewalInfo_ShouldRenewNow_DuringWindow(t *testing.T) {
	now := time.Now()
	windowStart := now.Add(-30 * time.Minute)
	windowEnd := now.Add(30 * time.Minute)

	ri := &RenewalInfo{
		SuggestedWindowStart: windowStart,
		SuggestedWindowEnd:   windowEnd,
	}

	if !ri.ShouldRenewNow() {
		t.Error("ShouldRenewNow should be true during window")
	}
}

func TestRenewalInfo_ShouldRenewNow_AfterWindowEnd(t *testing.T) {
	now := time.Now()
	windowStart := now.Add(-2 * time.Hour)
	windowEnd := now.Add(-1 * time.Hour)

	ri := &RenewalInfo{
		SuggestedWindowStart: windowStart,
		SuggestedWindowEnd:   windowEnd,
	}

	if !ri.ShouldRenewNow() {
		t.Error("ShouldRenewNow should be true after window end")
	}
}

func TestRenewalInfo_OptimalRenewalTime_Midpoint(t *testing.T) {
	windowStart := time.Unix(1000, 0)
	windowEnd := time.Unix(3000, 0)

	ri := &RenewalInfo{
		SuggestedWindowStart: windowStart,
		SuggestedWindowEnd:   windowEnd,
	}

	optimal := ri.OptimalRenewalTime()
	expected := time.Unix(2000, 0) // (1000 + 3000) / 2

	if !optimal.Equal(expected) {
		t.Errorf("OptimalRenewalTime: expected %v, got %v", expected, optimal)
	}
}

func TestRenewalInfo_OptimalRenewalTime_AsymmetricWindow(t *testing.T) {
	windowStart := time.Unix(1000, 0)
	windowEnd := time.Unix(1300, 0) // 300 second window

	ri := &RenewalInfo{
		SuggestedWindowStart: windowStart,
		SuggestedWindowEnd:   windowEnd,
	}

	optimal := ri.OptimalRenewalTime()
	expected := time.Unix(1150, 0) // start + 150 seconds

	if !optimal.Equal(expected) {
		t.Errorf("OptimalRenewalTime: expected %v, got %v", expected, optimal)
	}
}
