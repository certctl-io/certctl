package oidc

import (
	"context"
	"errors"
	"testing"
)

// Audit 2026-05-10 MED-9 closure — pin the disabled-provider behavior.
// HandleAuthRequest must reject pre-login creation with
// ErrProviderDisabled when the operator has flipped Enabled=false. The
// LoginPage's AuthInfo provider list filters disabled providers at the
// adapter (cmd/server/main.go::oidcProvidersListAdapter.List) so the
// button doesn't render in the first place; ErrProviderDisabled is the
// defense-in-depth guard for direct API / MCP / CLI callers.

func TestService_HandleAuthRequest_DisabledProvider_RejectsWithErrProviderDisabled(t *testing.T) {
	mockIdP := newMockIdP(t)
	svc, _ := newServiceWithProvider(t, mockIdP.URL(), "op-disabled")

	// Warm the entry cache via a successful HandleAuthRequest (this runs
	// real discovery against mockIdP), then flip cfgRow.Enabled to false
	// to simulate the operator toggling the provider offline. The next
	// HandleAuthRequest hits the disabled-check before the cached entry
	// is reused.
	if _, _, _, err := svc.HandleAuthRequest(context.Background(), "op-disabled", "", ""); err != nil {
		t.Fatalf("warm HandleAuthRequest: %v", err)
	}
	if entry, ok := svc.cache["op-disabled"]; ok && entry.cfgRow != nil {
		entry.cfgRow.Enabled = false
	} else {
		t.Fatal("expected cache entry for op-disabled after warmup")
	}

	_, _, _, err := svc.HandleAuthRequest(context.Background(), "op-disabled", "", "")
	if !errors.Is(err, ErrProviderDisabled) {
		t.Errorf("HandleAuthRequest(disabled provider) err = %v; want ErrProviderDisabled", err)
	}
}
