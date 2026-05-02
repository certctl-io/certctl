package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer/local"
	"github.com/shankar0123/certctl/internal/connector/issuerfactory"
	"github.com/shankar0123/certctl/internal/crypto"
	"github.com/shankar0123/certctl/internal/crypto/signer"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// IssuerRegistry is a thread-safe registry of issuer connectors.
// It replaces the static map[string]IssuerConnector that was built at startup.
// Consumers call Get() to look up a connector by issuer ID.
type IssuerRegistry struct {
	mu      sync.RWMutex
	issuers map[string]IssuerConnector
	logger  *slog.Logger

	// localDeps, when set, is injected into every *local.Connector
	// constructed by Rebuild via SetOCSPResponderRepo + SetSignerDriver
	// + SetIssuerID + SetOCSPResponderKeyDir. Wires the dedicated OCSP
	// responder cert flow (RFC 6960 §2.6); see Bundle CRL/OCSP-Responder
	// Phase 2. When unset, local connectors fall back to signing OCSP
	// with the CA key directly (the historical behaviour, preserved for
	// callers that don't supply these deps).
	localDeps *LocalIssuerDeps

	// metrics — when set, every adapter constructed by Rebuild is
	// wired with SetMetrics so issuance / renewal calls flow through
	// the per-issuer-type counter + histogram + failure tables.
	// Closes the #4 audit-readiness blocker (per-issuer-type metrics).
	metrics *IssuanceMetrics
}

// LocalIssuerDeps groups the optional dependencies that the local
// issuer needs for the dedicated OCSP responder cert flow. All fields
// are required when localDeps is set on the registry; nil-checking
// individual fields would partially-initialize the responder path
// which is worse than the all-or-nothing fallback to direct CA-key
// signing.
type LocalIssuerDeps struct {
	OCSPResponderRepo repository.OCSPResponderRepository
	SignerDriver      signer.Driver
	KeyDir            string        // where FileDriver-backed responder keys land
	RotationGrace     time.Duration // optional override; default 7d if zero
	Validity          time.Duration // optional override; default 30d if zero
}

// NewIssuerRegistry creates a new empty issuer registry.
func NewIssuerRegistry(logger *slog.Logger) *IssuerRegistry {
	return &IssuerRegistry{
		issuers: make(map[string]IssuerConnector),
		logger:  logger,
	}
}

// SetLocalIssuerDeps configures the per-local-connector dependencies
// applied by Rebuild. Must be called before BuildRegistry / Rebuild
// so the deps are in place when local connectors are constructed.
//
// Bundle CRL/OCSP-Responder Phase 2.
func (r *IssuerRegistry) SetLocalIssuerDeps(deps *LocalIssuerDeps) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.localDeps = deps
}

// SetIssuanceMetrics wires per-issuer-type issuance metrics. Every
// adapter constructed by Rebuild after this call records issuance /
// renewal calls into the supplied metrics tables. Closes the #4
// audit-readiness blocker (per-issuer-type metrics).
func (r *IssuerRegistry) SetIssuanceMetrics(m *IssuanceMetrics) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metrics = m
}

// Get returns the issuer connector for the given ID and whether it exists.
func (r *IssuerRegistry) Get(id string) (IssuerConnector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	conn, ok := r.issuers[id]
	return conn, ok
}

// Set adds or replaces an issuer connector in the registry.
func (r *IssuerRegistry) Set(id string, conn IssuerConnector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.issuers[id] = conn
}

// Remove removes an issuer connector from the registry.
func (r *IssuerRegistry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.issuers, id)
}

// List returns a copy of all registered issuers.
func (r *IssuerRegistry) List() map[string]IssuerConnector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]IssuerConnector, len(r.issuers))
	for k, v := range r.issuers {
		result[k] = v
	}
	return result
}

// Len returns the number of registered issuers.
func (r *IssuerRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.issuers)
}

// Rebuild reconstructs the registry from a list of issuer configs.
// For each enabled issuer, it decrypts the config (if encryption key is set),
// instantiates a connector via the factory, wraps it in an adapter, and
// atomically swaps the entire map.
//
// The encryption passphrase is passed as a string; per-ciphertext salt derivation
// for v2 blobs is performed inside [crypto.DecryptIfKeySet]. Empty passphrase
// fails closed via [crypto.ErrEncryptionKeyRequired] when encrypted configs
// are encountered. See M-8 in certctl-audit-report.md.
func (r *IssuerRegistry) Rebuild(ctx context.Context, configs []*domain.Issuer, encryptionKey string) error {
	newIssuers := make(map[string]IssuerConnector)
	var errors []string

	for _, cfg := range configs {
		if !cfg.Enabled {
			r.logger.Debug("skipping disabled issuer", "id", cfg.ID, "type", cfg.Type)
			continue
		}

		// Determine the config JSON to use for connector instantiation.
		// Prefer encrypted_config (decrypted) if available; fall back to config.
		var configJSON json.RawMessage
		if len(cfg.EncryptedConfig) > 0 {
			decrypted, err := crypto.DecryptIfKeySet(cfg.EncryptedConfig, encryptionKey)
			if err != nil {
				errors = append(errors, fmt.Sprintf("issuer %s: decrypt failed: %v", cfg.ID, err))
				continue
			}
			configJSON = json.RawMessage(decrypted)
		} else if len(cfg.Config) > 0 {
			configJSON = cfg.Config
		} else {
			configJSON = json.RawMessage("{}")
		}

		connector, err := issuerfactory.NewFromConfig(ctx, string(cfg.Type), configJSON, r.logger)
		if err != nil {
			errors = append(errors, fmt.Sprintf("issuer %s: factory error: %v", cfg.ID, err))
			continue
		}

		// Bundle CRL/OCSP-Responder Phase 2: when local deps are
		// configured on the registry, inject them into every freshly-
		// constructed *local.Connector so its SignOCSPResponse takes
		// the dedicated responder cert path. Type-assert is the
		// pragmatic seam — the factory returns issuer.Connector so
		// this is the only place that knows what concrete type was
		// just built.
		if localConn, ok := connector.(*local.Connector); ok && r.localDeps != nil {
			localConn.SetIssuerID(cfg.ID)
			localConn.SetOCSPResponderRepo(r.localDeps.OCSPResponderRepo)
			localConn.SetSignerDriver(r.localDeps.SignerDriver)
			if r.localDeps.KeyDir != "" {
				localConn.SetOCSPResponderKeyDir(r.localDeps.KeyDir)
			}
			if r.localDeps.RotationGrace > 0 {
				localConn.SetOCSPResponderRotationGrace(r.localDeps.RotationGrace)
			}
			if r.localDeps.Validity > 0 {
				localConn.SetOCSPResponderValidity(r.localDeps.Validity)
			}
			r.logger.Info("local issuer wired with dedicated OCSP responder deps",
				"id", cfg.ID,
				"key_dir", r.localDeps.KeyDir)
		}

		adapter := NewIssuerConnectorAdapter(connector)
		// Wire per-issuer-type metrics (audit fix #4) when SetIssuanceMetrics
		// was called. The adapter is the IssuerConnector interface; type-
		// assert to the concrete *IssuerConnectorAdapter so we can call
		// SetMetrics. Tests that hand-construct adapters via the bare
		// NewIssuerConnectorAdapter constructor get nil metrics — the
		// adapter no-ops the recording in that case.
		if r.metrics != nil {
			if a, ok := adapter.(*IssuerConnectorAdapter); ok {
				a.SetMetrics(string(cfg.Type), r.metrics)
			}
		}
		newIssuers[cfg.ID] = adapter
		r.logger.Info("issuer loaded into registry", "id", cfg.ID, "type", cfg.Type)
	}

	// Atomic swap
	r.mu.Lock()
	old := r.issuers
	r.issuers = newIssuers
	r.mu.Unlock()

	// Log changes
	for id := range newIssuers {
		if _, existed := old[id]; !existed {
			r.logger.Info("issuer added to registry", "id", id)
		}
	}
	for id := range old {
		if _, exists := newIssuers[id]; !exists {
			r.logger.Info("issuer removed from registry", "id", id)
		}
	}

	r.logger.Info("issuer registry rebuilt", "loaded", len(newIssuers), "failed", len(errors))

	if len(errors) > 0 {
		for _, e := range errors {
			r.logger.Warn("issuer load failure", "detail", e)
		}
		return fmt.Errorf("%d issuer(s) failed to load: %s", len(errors), errors[0])
	}

	return nil
}
