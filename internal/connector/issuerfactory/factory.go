package issuerfactory

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/acme"
	"github.com/shankar0123/certctl/internal/connector/issuer/digicert"
	"github.com/shankar0123/certctl/internal/connector/issuer/googlecas"
	"github.com/shankar0123/certctl/internal/connector/issuer/local"
	"github.com/shankar0123/certctl/internal/connector/issuer/openssl"
	"github.com/shankar0123/certctl/internal/connector/issuer/sectigo"
	"github.com/shankar0123/certctl/internal/connector/issuer/stepca"
	"github.com/shankar0123/certctl/internal/connector/issuer/vault"
)

// NewFromConfig instantiates an issuer connector from its type string and config JSON.
// The config JSON keys use snake_case matching the connector Config struct json tags.
// This replaces the manual wiring in cmd/server/main.go.
func NewFromConfig(issuerType string, configJSON json.RawMessage, logger *slog.Logger) (issuer.Connector, error) {
	if len(configJSON) == 0 {
		configJSON = []byte("{}")
	}

	switch issuerType {
	case "local", "GenericCA":
		var cfg local.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid Local CA config: %w", err)
		}
		return local.New(&cfg, logger), nil

	case "ACME":
		var cfg acme.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid ACME config: %w", err)
		}
		return acme.New(&cfg, logger), nil

	case "StepCA":
		var cfg stepca.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid step-ca config: %w", err)
		}
		return stepca.New(&cfg, logger), nil

	case "OpenSSL":
		var cfg openssl.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid OpenSSL config: %w", err)
		}
		return openssl.New(&cfg, logger), nil

	case "VaultPKI":
		var cfg vault.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid Vault PKI config: %w", err)
		}
		return vault.New(&cfg, logger), nil

	case "DigiCert":
		var cfg digicert.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid DigiCert config: %w", err)
		}
		return digicert.New(&cfg, logger), nil

	case "Sectigo":
		var cfg sectigo.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid Sectigo config: %w", err)
		}
		return sectigo.New(&cfg, logger), nil

	case "GoogleCAS":
		var cfg googlecas.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid Google CAS config: %w", err)
		}
		return googlecas.New(&cfg, logger), nil

	default:
		return nil, fmt.Errorf("unknown issuer type: %q", issuerType)
	}
}
