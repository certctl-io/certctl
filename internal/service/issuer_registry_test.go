package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/shankar0123/certctl/internal/crypto"
	"github.com/shankar0123/certctl/internal/domain"
)

func registryTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestIssuerRegistry_GetSet(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())

	mock := &mockIssuerConnector{}
	reg.Set("iss-test", mock)

	conn, ok := reg.Get("iss-test")
	if !ok {
		t.Fatal("expected to find iss-test in registry")
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestIssuerRegistry_GetNotFound(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())

	_, ok := reg.Get("nonexistent")
	if ok {
		t.Fatal("expected not to find nonexistent issuer")
	}
}

func TestIssuerRegistry_Remove(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())

	reg.Set("iss-test", &mockIssuerConnector{})
	reg.Remove("iss-test")

	_, ok := reg.Get("iss-test")
	if ok {
		t.Fatal("expected issuer to be removed")
	}
}

func TestIssuerRegistry_List(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())

	reg.Set("iss-a", &mockIssuerConnector{})
	reg.Set("iss-b", &mockIssuerConnector{})

	list := reg.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 issuers, got %d", len(list))
	}

	// Verify List returns a copy (modifying it doesn't affect registry)
	delete(list, "iss-a")
	if reg.Len() != 2 {
		t.Fatal("deleting from List() copy should not affect registry")
	}
}

func TestIssuerRegistry_Len(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())
	if reg.Len() != 0 {
		t.Fatalf("expected empty registry, got %d", reg.Len())
	}

	reg.Set("iss-a", &mockIssuerConnector{})
	if reg.Len() != 1 {
		t.Fatalf("expected 1 issuer, got %d", reg.Len())
	}
}

func TestIssuerRegistry_Rebuild_Enabled(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())

	configs := []*domain.Issuer{
		{
			ID:      "iss-local",
			Name:    "Local CA",
			Type:    "local",
			Config:  json.RawMessage(`{}`),
			Enabled: true,
		},
		{
			ID:      "iss-disabled",
			Name:    "Disabled",
			Type:    "local",
			Config:  json.RawMessage(`{}`),
			Enabled: false,
		},
	}

	err := reg.Rebuild(context.Background(), configs, "")
	if err != nil {
		t.Fatalf("Rebuild failed: %v", err)
	}

	if reg.Len() != 1 {
		t.Fatalf("expected 1 enabled issuer, got %d", reg.Len())
	}

	_, ok := reg.Get("iss-local")
	if !ok {
		t.Fatal("expected iss-local in registry")
	}

	_, ok = reg.Get("iss-disabled")
	if ok {
		t.Fatal("disabled issuer should not be in registry")
	}
}

func TestIssuerRegistry_Rebuild_WithEncryption(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())

	configJSON := []byte(`{"ca_common_name":"Encrypted CA"}`)
	// M-8: EncryptIfKeySet now emits v2 (magic 0x02 || per-ciphertext salt || sealed).
	// IssuerRegistry.Rebuild accepts the raw passphrase and delegates PBKDF2 to crypto.DecryptIfKeySet.
	encrypted, _, err := crypto.EncryptIfKeySet(configJSON, "test-key")
	if err != nil {
		t.Fatalf("EncryptIfKeySet failed: %v", err)
	}

	configs := []*domain.Issuer{
		{
			ID:              "iss-encrypted",
			Name:            "Encrypted Local CA",
			Type:            "local",
			EncryptedConfig: encrypted,
			Enabled:         true,
		},
	}

	err = reg.Rebuild(context.Background(), configs, "test-key")
	if err != nil {
		t.Fatalf("Rebuild with encryption failed: %v", err)
	}

	_, ok := reg.Get("iss-encrypted")
	if !ok {
		t.Fatal("expected iss-encrypted in registry")
	}
}

func TestIssuerRegistry_Rebuild_NilKeyFallback(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())

	configs := []*domain.Issuer{
		{
			ID:      "iss-plain",
			Name:    "Plain Config",
			Type:    "local",
			Config:  json.RawMessage(`{}`),
			Enabled: true,
		},
	}

	// Empty passphrase is safe when no EncryptedConfig is present — falls back to config column.
	// The C-2 fail-closed sentinel only fires when EncryptedConfig is non-empty.
	err := reg.Rebuild(context.Background(), configs, "")
	if err != nil {
		t.Fatalf("Rebuild with empty key failed: %v", err)
	}

	_, ok := reg.Get("iss-plain")
	if !ok {
		t.Fatal("expected iss-plain in registry")
	}
}

func TestIssuerRegistry_Rebuild_InvalidConfig(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())

	configs := []*domain.Issuer{
		{
			ID:      "iss-bad",
			Name:    "Bad Config",
			Type:    "UnknownType",
			Config:  json.RawMessage(`{}`),
			Enabled: true,
		},
		{
			ID:      "iss-good",
			Name:    "Good Config",
			Type:    "local",
			Config:  json.RawMessage(`{}`),
			Enabled: true,
		},
	}

	// Should return an error indicating partial failure, but still load valid issuers
	err := reg.Rebuild(context.Background(), configs, "")
	if err == nil {
		t.Fatal("Rebuild should return error when some issuers fail to load")
	}

	// Despite the error, valid issuers should be loaded
	if reg.Len() != 1 {
		t.Fatalf("expected 1 valid issuer, got %d", reg.Len())
	}

	_, ok := reg.Get("iss-good")
	if !ok {
		t.Fatal("expected iss-good in registry")
	}
}

func TestIssuerRegistry_Rebuild_ReplacesExisting(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())

	// Set up initial state
	reg.Set("iss-old", &mockIssuerConnector{})

	configs := []*domain.Issuer{
		{
			ID:      "iss-new",
			Name:    "New Issuer",
			Type:    "local",
			Config:  json.RawMessage(`{}`),
			Enabled: true,
		},
	}

	err := reg.Rebuild(context.Background(), configs, "")
	if err != nil {
		t.Fatalf("Rebuild failed: %v", err)
	}

	_, ok := reg.Get("iss-old")
	if ok {
		t.Fatal("old issuer should have been replaced")
	}

	_, ok = reg.Get("iss-new")
	if !ok {
		t.Fatal("new issuer should be present")
	}
}

func TestIssuerRegistry_ConcurrentAccess(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		id := "iss-concurrent"
		go func() {
			defer wg.Done()
			reg.Set(id, &mockIssuerConnector{})
		}()
		go func() {
			defer wg.Done()
			reg.Get(id)
		}()
		go func() {
			defer wg.Done()
			reg.List()
		}()
	}
	wg.Wait()
	// No race detector panics = success
}

func TestIssuerRegistry_Rebuild_Empty(t *testing.T) {
	reg := NewIssuerRegistry(registryTestLogger())

	reg.Set("iss-existing", &mockIssuerConnector{})

	err := reg.Rebuild(context.Background(), []*domain.Issuer{}, "")
	if err != nil {
		t.Fatalf("Rebuild with empty configs failed: %v", err)
	}

	if reg.Len() != 0 {
		t.Fatalf("expected empty registry after rebuild with no configs, got %d", reg.Len())
	}
}
