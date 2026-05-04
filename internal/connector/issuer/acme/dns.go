package acme

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/certctl-io/certctl/internal/validation"
)

// DNSSolver defines the interface for DNS-01 challenge provisioning.
// Implementations create and clean up DNS TXT records for ACME validation.
type DNSSolver interface {
	// Present creates a DNS TXT record for the given domain with the given value.
	// The FQDN will be _acme-challenge.<domain>.
	Present(ctx context.Context, domain, token, keyAuth string) error

	// CleanUp removes the DNS TXT record created by Present.
	CleanUp(ctx context.Context, domain, token, keyAuth string) error
}

// ScriptDNSSolver implements DNSSolver by executing external scripts.
// This provides maximum flexibility: users supply their own scripts for
// whatever DNS provider they use (Cloudflare, Route53, Azure DNS, etc.).
//
// The scripts receive these environment variables:
//
//	CERTCTL_DNS_DOMAIN   — the domain being validated (e.g., "example.com")
//	CERTCTL_DNS_FQDN     — the full record name (e.g., "_acme-challenge.example.com")
//	CERTCTL_DNS_VALUE    — the TXT record value (key authorization digest)
//	CERTCTL_DNS_TOKEN    — the ACME challenge token
//
// The present script must create the TXT record and exit 0.
// The cleanup script must remove the TXT record and exit 0.
type ScriptDNSSolver struct {
	PresentScript string // Path to script that creates the TXT record
	CleanUpScript string // Path to script that removes the TXT record
	Timeout       time.Duration
	Logger        *slog.Logger
}

// NewScriptDNSSolver creates a script-based DNS solver.
func NewScriptDNSSolver(presentScript, cleanUpScript string, logger *slog.Logger) *ScriptDNSSolver {
	return &ScriptDNSSolver{
		PresentScript: presentScript,
		CleanUpScript: cleanUpScript,
		Timeout:       120 * time.Second,
		Logger:        logger,
	}
}

// Present executes the present script to create a DNS TXT record.
func (s *ScriptDNSSolver) Present(ctx context.Context, domain, token, keyAuth string) error {
	if s.PresentScript == "" {
		return fmt.Errorf("DNS present script not configured")
	}

	// Validate domain name to prevent injection attacks
	if err := validation.ValidateDomainName(domain); err != nil {
		return fmt.Errorf("invalid domain name: %w", err)
	}

	// Validate ACME token to prevent injection attacks
	if err := validation.ValidateACMEToken(token); err != nil {
		return fmt.Errorf("invalid ACME token: %w", err)
	}

	fqdn := "_acme-challenge." + domain

	s.Logger.Info("creating DNS TXT record via script",
		"domain", domain,
		"fqdn", fqdn,
		"script", s.PresentScript)

	return s.runScript(ctx, s.PresentScript, domain, fqdn, token, keyAuth)
}

// CleanUp executes the cleanup script to remove a DNS TXT record.
func (s *ScriptDNSSolver) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	if s.CleanUpScript == "" {
		s.Logger.Warn("DNS cleanup script not configured, skipping cleanup", "domain", domain)
		return nil
	}

	// Validate domain name to prevent injection attacks
	if err := validation.ValidateDomainName(domain); err != nil {
		return fmt.Errorf("invalid domain name: %w", err)
	}

	// Validate ACME token to prevent injection attacks
	if err := validation.ValidateACMEToken(token); err != nil {
		return fmt.Errorf("invalid ACME token: %w", err)
	}

	fqdn := "_acme-challenge." + domain

	s.Logger.Info("removing DNS TXT record via script",
		"domain", domain,
		"fqdn", fqdn,
		"script", s.CleanUpScript)

	return s.runScript(ctx, s.CleanUpScript, domain, fqdn, token, keyAuth)
}

// PresentPersist creates a persistent DNS TXT record at _validation-persist.<domain>.
// Used by dns-persist-01 (draft-ietf-acme-dns-persist). Unlike Present (which targets
// _acme-challenge), this targets _validation-persist and the record is intended to be permanent.
func (s *ScriptDNSSolver) PresentPersist(ctx context.Context, domain, token, recordValue string) error {
	if s.PresentScript == "" {
		return fmt.Errorf("DNS present script not configured")
	}

	// Validate domain name to prevent injection attacks
	if err := validation.ValidateDomainName(domain); err != nil {
		return fmt.Errorf("invalid domain name: %w", err)
	}

	// Validate ACME token to prevent injection attacks
	if err := validation.ValidateACMEToken(token); err != nil {
		return fmt.Errorf("invalid ACME token: %w", err)
	}

	fqdn := "_validation-persist." + domain

	s.Logger.Info("creating persistent DNS TXT record via script",
		"domain", domain,
		"fqdn", fqdn,
		"script", s.PresentScript)

	return s.runScript(ctx, s.PresentScript, domain, fqdn, token, recordValue)
}

// runScript executes a DNS hook script with the appropriate environment variables.
func (s *ScriptDNSSolver) runScript(ctx context.Context, script, domain, fqdn, token, keyAuth string) error {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 120 * time.Second
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, script)
	cmd.Env = append(cmd.Environ(),
		"CERTCTL_DNS_DOMAIN="+domain,
		"CERTCTL_DNS_FQDN="+fqdn,
		"CERTCTL_DNS_VALUE="+keyAuth,
		"CERTCTL_DNS_TOKEN="+token,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("DNS script %s failed: %w (output: %s)", script, err, string(output))
	}

	s.Logger.Debug("DNS script completed", "script", script, "output", string(output))
	return nil
}
