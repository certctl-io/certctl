package issuerfactory

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/certctl-io/certctl/internal/connector/issuer"
	"github.com/certctl-io/certctl/internal/connector/issuer/acme"
	"github.com/certctl-io/certctl/internal/connector/issuer/awsacmpca"
	"github.com/certctl-io/certctl/internal/connector/issuer/digicert"
	"github.com/certctl-io/certctl/internal/connector/issuer/ejbca"
	"github.com/certctl-io/certctl/internal/connector/issuer/entrust"
	"github.com/certctl-io/certctl/internal/connector/issuer/globalsign"
	"github.com/certctl-io/certctl/internal/connector/issuer/googlecas"
	"github.com/certctl-io/certctl/internal/connector/issuer/local"
	"github.com/certctl-io/certctl/internal/connector/issuer/openssl"
	"github.com/certctl-io/certctl/internal/connector/issuer/sectigo"
	"github.com/certctl-io/certctl/internal/connector/issuer/stepca"
	"github.com/certctl-io/certctl/internal/connector/issuer/vault"
)

// NewFromConfig instantiates an issuer connector from its type string and config JSON.
// The config JSON keys use snake_case matching the connector Config struct json tags.
// This replaces the manual wiring in cmd/server/main.go.
//
// ctx is currently used only by the AWSACMPCA branch (passed to
// awsconfig.LoadDefaultConfig for SDK credential chain resolution). Other
// connectors take no context at construction; the parameter is kept on the
// signature so callers that have a ctx in scope thread it through cleanly
// (contextcheck linter).
func NewFromConfig(ctx context.Context, issuerType string, configJSON json.RawMessage, logger *slog.Logger) (issuer.Connector, error) {
	if len(configJSON) == 0 {
		configJSON = []byte("{}")
	}

	switch issuerType {
	case "local", "local_ca", "GenericCA", "genericca":
		var cfg local.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid Local CA config: %w", err)
		}
		return local.New(&cfg, logger), nil

	case "ACME", "acme":
		var cfg acme.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid ACME config: %w", err)
		}
		return acme.New(&cfg, logger), nil

	case "StepCA", "stepca":
		var cfg stepca.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid step-ca config: %w", err)
		}
		return stepca.New(&cfg, logger), nil

	case "OpenSSL", "openssl":
		var cfg openssl.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid OpenSSL config: %w", err)
		}
		return openssl.New(&cfg, logger), nil

	case "VaultPKI", "vaultpki":
		var cfg vault.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid Vault PKI config: %w", err)
		}
		return vault.New(&cfg, logger), nil

	case "DigiCert", "digicert":
		var cfg digicert.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid DigiCert config: %w", err)
		}
		return digicert.New(&cfg, logger), nil

	case "Sectigo", "sectigo":
		var cfg sectigo.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid Sectigo config: %w", err)
		}
		return sectigo.New(&cfg, logger), nil

	case "GoogleCAS", "googlecas":
		var cfg googlecas.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid Google CAS config: %w", err)
		}
		return googlecas.New(&cfg, logger), nil

	case "AWSACMPCA", "awsacmpca":
		var cfg awsacmpca.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid AWS ACM PCA config: %w", err)
		}
		conn, err := awsacmpca.New(ctx, &cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("AWS ACM PCA init: %w", err)
		}
		return conn, nil

	case "Entrust", "entrust":
		var cfg entrust.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid Entrust config: %w", err)
		}
		return entrust.New(&cfg, logger), nil

	case "GlobalSign", "globalsign":
		var cfg globalsign.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid GlobalSign config: %w", err)
		}
		return globalsign.New(&cfg, logger), nil

	case "EJBCA", "ejbca":
		var cfg ejbca.Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("invalid EJBCA config: %w", err)
		}
		conn, err := ejbca.New(&cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("EJBCA init: %w", err)
		}
		return conn, nil

	default:
		return nil, fmt.Errorf("unknown issuer type: %q", issuerType)
	}
}
