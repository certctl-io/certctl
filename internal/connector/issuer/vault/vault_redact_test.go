package vault_test

// Phase 3 of the secret.Ref migration (audit fix #6 → 2026-05-03 Top-10
// fix #2). Pins the operator-visible contract: GET /api/v1/issuers
// responses for type=vault marshal Token as "[redacted]" rather than
// the plaintext value. Regression guard for any future refactor that
// changes the field type back to string.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/issuer/vault"
	"github.com/shankar0123/certctl/internal/secret"
)

func TestVault_Config_TokenMarshalsAsRedacted(t *testing.T) {
	cfg := vault.Config{
		Addr:  "https://vault.example.com:8200",
		Token: secret.NewRefFromString("hvs.real-token-bytes-must-not-leak"),
		Mount: "pki",
		Role:  "web",
		TTL:   "8760h",
	}

	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, `"token":"[redacted]"`) {
		t.Errorf("expected token redacted, got: %s", got)
	}
	if strings.Contains(got, "hvs.real-token-bytes-must-not-leak") {
		t.Fatalf("plaintext token leaked into marshaled JSON: %s", got)
	}
}
