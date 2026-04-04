package issuerfactory

import (
	"encoding/json"
	"log/slog"
	"os"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNewFromConfig_LocalCA(t *testing.T) {
	cfg := json.RawMessage(`{"ca_common_name":"Test CA"}`)
	conn, err := NewFromConfig("local", cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFromConfig(local) failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestNewFromConfig_GenericCA_Alias(t *testing.T) {
	cfg := json.RawMessage(`{}`)
	conn, err := NewFromConfig("GenericCA", cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFromConfig(GenericCA) failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestNewFromConfig_ACME(t *testing.T) {
	cfg := json.RawMessage(`{"directory_url":"https://acme-staging-v02.api.letsencrypt.org/directory","email":"test@example.com"}`)
	conn, err := NewFromConfig("ACME", cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFromConfig(ACME) failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestNewFromConfig_StepCA(t *testing.T) {
	cfg := json.RawMessage(`{"ca_url":"https://ca.internal:9000","provisioner_name":"test"}`)
	conn, err := NewFromConfig("StepCA", cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFromConfig(StepCA) failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestNewFromConfig_OpenSSL(t *testing.T) {
	cfg := json.RawMessage(`{"sign_script":"/path/to/sign.sh"}`)
	conn, err := NewFromConfig("OpenSSL", cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFromConfig(OpenSSL) failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestNewFromConfig_VaultPKI(t *testing.T) {
	cfg := json.RawMessage(`{"addr":"https://vault:8200","token":"hvs.test","mount":"pki","role":"web","ttl":"8760h"}`)
	conn, err := NewFromConfig("VaultPKI", cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFromConfig(VaultPKI) failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestNewFromConfig_DigiCert(t *testing.T) {
	cfg := json.RawMessage(`{"api_key":"test-key","org_id":"123","product_type":"ssl_basic"}`)
	conn, err := NewFromConfig("DigiCert", cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFromConfig(DigiCert) failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestNewFromConfig_Sectigo(t *testing.T) {
	cfg := json.RawMessage(`{"customer_uri":"test-org","login":"api-user","password":"secret","org_id":1}`)
	conn, err := NewFromConfig("Sectigo", cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFromConfig(Sectigo) failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestNewFromConfig_GoogleCAS(t *testing.T) {
	cfg := json.RawMessage(`{"project":"my-project","location":"us-central1","ca_pool":"my-pool","credentials":"/path/to/creds.json"}`)
	conn, err := NewFromConfig("GoogleCAS", cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFromConfig(GoogleCAS) failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestNewFromConfig_UnknownType(t *testing.T) {
	cfg := json.RawMessage(`{}`)
	_, err := NewFromConfig("UnknownCA", cfg, testLogger())
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestNewFromConfig_MalformedJSON(t *testing.T) {
	cfg := json.RawMessage(`{invalid json}`)
	_, err := NewFromConfig("ACME", cfg, testLogger())
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestNewFromConfig_EmptyConfig(t *testing.T) {
	// Empty config should work — connectors have defaults
	conn, err := NewFromConfig("local", nil, testLogger())
	if err != nil {
		t.Fatalf("NewFromConfig with nil config failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}
