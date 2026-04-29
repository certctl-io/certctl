package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// EST RFC 7030 hardening master bundle Phase 7.3 — per-profile counter
// isolation regression test. Mirrors the SCEP equivalent at
// internal/api/handler/scep_profile_counter_isolation_test.go.
//
// Why this test exists: the future-bug class it guards against is a
// cmd/server/main.go refactor that constructs a SINGLE shared
// *estCounterTab and injects it into every per-profile ESTService —
// that would compile cleanly, pass every existing route-level test,
// and silently inflate one profile's counters with another's traffic.

func TestESTService_PerProfileCountersIsolated(t *testing.T) {
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10}))

	// Two services with separate issuers + counter tabs. NewESTService
	// allocates a fresh estCounterTab per instance (Phase 7.1 contract);
	// this test pins that contract.
	corpSvc := NewESTService("iss-corp", &mockIssuerConnector{}, nil, silent)
	iotSvc := NewESTService("iss-iot", &mockIssuerConnector{Err: errors.New("issuer down")}, nil, silent)

	ctx := context.Background()

	// CORP: drive 3 successful enrollments. Each ticks
	// success_simpleenroll on CORP's tab; IOT's tab MUST stay zero
	// for that label.
	for i := 0; i < 3; i++ {
		csrPEM := generateCSRPEM(t, "device-corp.example.com", []string{"device-corp.example.com"})
		if _, err := corpSvc.SimpleEnroll(ctx, csrPEM); err != nil {
			t.Fatalf("corp enroll #%d: %v", i, err)
		}
	}
	// IOT: drive 2 enrollments. Each fails issuance (mock returns err
	// from IssueCertificate); each ticks issuer_error on IOT's tab.
	for i := 0; i < 2; i++ {
		csrPEM := generateCSRPEM(t, "device-iot.example.com", []string{"device-iot.example.com"})
		if _, err := iotSvc.SimpleEnroll(ctx, csrPEM); err == nil {
			t.Fatalf("iot enroll #%d: expected issuer error", i)
		}
	}

	// CORP snapshot: success=3, issuer_error=0.
	corpSnap := corpSvc.Stats(time.Now()).Counters
	if got := corpSnap[estCounterSuccessSimpleEnroll]; got != 3 {
		t.Errorf("corp success_simpleenroll = %d, want 3", got)
	}
	if got := corpSnap[estCounterIssuerError]; got != 0 {
		t.Errorf("corp issuer_error = %d, want 0 (no IOT bleed)", got)
	}

	// IOT snapshot: success=0, issuer_error=2.
	iotSnap := iotSvc.Stats(time.Now()).Counters
	if got := iotSnap[estCounterSuccessSimpleEnroll]; got != 0 {
		t.Errorf("iot success_simpleenroll = %d, want 0 (no CORP bleed)", got)
	}
	if got := iotSnap[estCounterIssuerError]; got != 2 {
		t.Errorf("iot issuer_error = %d, want 2", got)
	}

	// Sanity: the two services' counter tabs MUST be distinct *estCounterTab
	// pointers. If a future refactor introduces a shared tab, this assertion
	// catches it before the snapshot bleed becomes silent.
	if corpSvc.counters == iotSvc.counters {
		t.Fatal("corp + iot share the same *estCounterTab — per-profile isolation broken")
	}
}
