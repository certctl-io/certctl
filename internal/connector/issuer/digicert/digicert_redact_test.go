package digicert_test

// Phase 3 of the secret.Ref migration (audit fix #6 → 2026-05-03 Top-10
// fix #2). Pins the operator-visible contract: GET /api/v1/issuers
// responses for type=digicert marshal APIKey as "[redacted]" rather
// than the plaintext value. Regression guard for any future refactor
// that changes the field type back to string.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/issuer/digicert"
	"github.com/shankar0123/certctl/internal/secret"
)

func TestDigiCert_Config_APIKeyMarshalsAsRedacted(t *testing.T) {
	cfg := digicert.Config{
		APIKey:      secret.NewRefFromString("dc-real-api-key-must-not-leak"),
		OrgID:       "12345",
		ProductType: "ssl_basic",
		BaseURL:     "https://www.digicert.com/services/v2",
	}

	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, `"api_key":"[redacted]"`) {
		t.Errorf("expected api_key redacted, got: %s", got)
	}
	if strings.Contains(got, "dc-real-api-key-must-not-leak") {
		t.Fatalf("plaintext api_key leaked into marshaled JSON: %s", got)
	}
}
