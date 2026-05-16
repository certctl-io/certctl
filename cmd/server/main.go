// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	acmepkg "github.com/certctl-io/certctl/internal/api/acme"
	"github.com/certctl-io/certctl/internal/api/handler"
	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/api/router"
	"github.com/certctl-io/certctl/internal/auth"
	"github.com/certctl-io/certctl/internal/auth/bootstrap"
	"github.com/certctl-io/certctl/internal/auth/breakglass"
	oidcsvc "github.com/certctl-io/certctl/internal/auth/oidc"
	"github.com/certctl-io/certctl/internal/auth/session"
	"github.com/certctl-io/certctl/internal/config"
	discoveryawssm "github.com/certctl-io/certctl/internal/connector/discovery/awssm"
	discoveryazurekv "github.com/certctl-io/certctl/internal/connector/discovery/azurekv"
	discoverygcpsm "github.com/certctl-io/certctl/internal/connector/discovery/gcpsm"
	"github.com/certctl-io/certctl/internal/connector/issuer/asyncpoll"
	notifyemail "github.com/certctl-io/certctl/internal/connector/notifier/email"
	notifyopsgenie "github.com/certctl-io/certctl/internal/connector/notifier/opsgenie"
	notifypagerduty "github.com/certctl-io/certctl/internal/connector/notifier/pagerduty"
	notifyslack "github.com/certctl-io/certctl/internal/connector/notifier/slack"
	notifyteams "github.com/certctl-io/certctl/internal/connector/notifier/teams"
	"github.com/certctl-io/certctl/internal/crypto/signer"
	"github.com/certctl-io/certctl/internal/domain"
	authdomainAlias "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/ratelimit"
	"github.com/certctl-io/certctl/internal/repository/postgres"
	"github.com/certctl-io/certctl/internal/scep/intune"
	"github.com/certctl-io/certctl/internal/scheduler"
	"github.com/certctl-io/certctl/internal/service"
	authsvc "github.com/certctl-io/certctl/internal/service/auth"
	"github.com/certctl-io/certctl/internal/trustanchor"
)

func main() {
	// Phase 4 DEPL-M1 closure (2026-05-14): --migrate-only flag for
	// the Helm pre-install/pre-upgrade hook. Phase 9 Sprint 8b
	// (2026-05-14) extracted the flag-parse + the migration-execution
	// block to cmd/server/migrations.go; see that file's doc-comment
	// for the full Phase 4 lifecycle rationale.
	migrateOnly := parseMigrateOnlyFlag()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Defense-in-depth runtime guard for the auth-type discriminator.
	//
	// G-1 (P1): config.Load() already runs Validate() which rejects "jwt"
	// and any value outside config.ValidAuthTypes() with a dedicated
	// diagnostic. This switch is belt-and-braces — if a future refactor
	// bypasses the validator (test harness, alt config loader, env-var
	// rebinding after Load) the server must not silently boot with an
	// unsupported auth shape. The error path uses fmt.Fprintf because
	// the slog logger is constructed from cfg below this point; we want
	// the failure to be visible regardless of log-level configuration.
	//
	// Auth Bundle 2 Phase 0: AuthTypeOIDC is in ValidAuthTypes() but the
	// session middleware + OIDC handler chain ship in later phases. An
	// operator who sets CERTCTL_AUTH_TYPE=oidc on a Bundle-2-incomplete
	// deployment must NOT silently fall back to api-key (the silent
	// auth-downgrade failure mode that drove G-1 in the first place).
	// The OIDC case below refuses-to-start with an actionable message.
	// Phase 6 of Bundle 2 (session middleware wiring) relaxes this case
	// to fall through alongside the api-key + none cases.
	switch config.AuthType(cfg.Auth.Type) {
	case config.AuthTypeAPIKey, config.AuthTypeNone:
		// ok — fall through
	case config.AuthTypeOIDC:
		fmt.Fprintf(os.Stderr,
			"CERTCTL_AUTH_TYPE=oidc: the OIDC auth chain is not yet wired in this build (Auth Bundle 2 Phase 6 ships the session middleware that consumes this auth-type literal). Set CERTCTL_AUTH_TYPE=api-key or run an authenticating gateway with CERTCTL_AUTH_TYPE=none until Bundle 2 lands. See cowork/auth-bundle-2-prompt.md.\n")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr,
			"unsupported auth type at runtime: %q (valid: %v) — config validation should have caught this; refusing to start\n",
			cfg.Auth.Type, config.ValidAuthTypes())
		os.Exit(1)
	}

	// Set up structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.GetLogLevel(),
	}))

	logger.Info("certctl server starting",
		"version", "2.0.9",
		"server_host", cfg.Server.Host,
		"server_port", cfg.Server.Port)

	// Bundle 2 (2026-05-12) — visible demo-mode banner at boot.
	//
	// When CERTCTL_DEMO_MODE_ACK=true the HIGH-12 startup guard already
	// passed and the server is about to serve every request as the
	// synthetic admin actor `actor-demo-anon`. Operators have lost
	// production deploys to this posture more than once (last incident:
	// 2026-04-19, a screenshot run that kept running for three days);
	// the per-startup banner makes the posture unmissable in any log
	// scraper, dashboard, or `journalctl --since boot` review.
	if cfg.Auth.DemoModeAck {
		logger.Warn("⚠ DEMO MODE ACTIVE — CERTCTL_DEMO_MODE_ACK=true is set; every request is served as the synthetic admin actor `actor-demo-anon` (no authentication enforced). This deployment MUST NOT hold production keys, certificates, or audit history. To promote to production: (1) unset CERTCTL_DEMO_MODE_ACK; (2) set CERTCTL_AUTH_TYPE=api-key or oidc; (3) set CERTCTL_AUTH_SECRET to a fresh `openssl rand -base64 32`; (4) set CERTCTL_KEYGEN_MODE=agent; (5) rotate CERTCTL_CONFIG_ENCRYPTION_KEY to a fresh `openssl rand -base64 32` (≥ 32 bytes, not the change-me placeholder); (6) restart the server. See docs/operator/security.md for the full posture.")
	}

	// Bundle-5 / Audit H-007: deprecation WARN when the agent bootstrap
	// token is unset. Pre-Bundle-5 there was no token at all; the v2.0.x
	// default keeps the warn-mode pass-through so existing demo deploys
	// keep working, but operators must set CERTCTL_AGENT_BOOTSTRAP_TOKEN
	// before v2.2.0 lands. This is a one-shot startup line — the
	// per-request path stays silent so a busy registration endpoint
	// doesn't flood the log.
	if cfg.Auth.AgentBootstrapToken == "" {
		logger.Warn("agent bootstrap token unset (CERTCTL_AGENT_BOOTSTRAP_TOKEN) — agents may self-register without authentication; this default will become deny-by-default in v2.2.0; generate one with: openssl rand -hex 32")
	} else {
		logger.Info("agent bootstrap token configured (length redacted; constant-time compare on POST /api/v1/agents)")
	}

	// Phase 6 SCALE-M3 closure (2026-05-14): operator-overridable
	// package-level default for the asyncpoll MaxWait fallback.
	// Per-connector overrides (CERTCTL_DIGICERT_POLL_MAX_WAIT_SECONDS,
	// CERTCTL_ENTRUST_POLL_MAX_WAIT_SECONDS, etc.) still win when set;
	// this global env is the middle of the priority chain (above the
	// 10-minute package default const, below per-connector overrides).
	// See internal/connector/issuer/asyncpoll/asyncpoll.go for the
	// SetDefaultMaxWait contract.
	if v, _ := strconv.Atoi(os.Getenv("CERTCTL_ASYNC_POLL_MAX_WAIT_SECONDS")); v > 0 {
		asyncpoll.SetDefaultMaxWait(time.Duration(v) * time.Second)
		logger.Info("asyncpoll default max-wait override", "seconds", v)
	}

	// Initialize database connection pool.
	//
	// Bundle 3 closure (D12): pre-Bundle-3 the operator-facing
	// CERTCTL_DATABASE_MAX_CONNS was a lying-field — config loaded the
	// value and Validate() checked the floor, but the pool was hard-
	// coded to SetMaxOpenConns(25). Post-Bundle-3 NewDBWithMaxConns
	// threads the operator setting through to the connection pool.
	db, err := postgres.NewDBWithMaxConns(cfg.Database.URL, cfg.Database.MaxConnections)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	logger.Info("connected to database")

	// Phase 4 DEPL-M1 + Phase 9 Sprint 8b — the migration-via-hook
	// posture (Compose / Helm-with-hook / bare --migrate-only) lives
	// in runBootMigrations (cmd/server/migrations.go). Returns true
	// when --migrate-only was set so we can return from main()
	// cleanly (deferred db.Close runs vs the pre-Sprint-8b os.Exit(0)
	// which skipped defers — see migrations.go for the rationale).
	if exitAfterMigrations := runBootMigrations(cfg, db, logger, migrateOnly); exitAfterMigrations {
		return
	}

	// Initialize repositories with real PostgreSQL connection
	auditRepo := postgres.NewAuditRepository(db)
	certificateRepo := postgres.NewCertificateRepository(db)
	issuerRepo := postgres.NewIssuerRepository(db)
	targetRepo := postgres.NewTargetRepository(db)
	agentRepo := postgres.NewAgentRepository(db)
	jobRepo := postgres.NewJobRepository(db)
	policyRepo := postgres.NewPolicyRepository(db)
	notificationRepo := postgres.NewNotificationRepository(db)
	renewalPolicyRepo := postgres.NewRenewalPolicyRepository(db)
	profileRepo := postgres.NewProfileRepository(db)
	teamRepo := postgres.NewTeamRepository(db)
	ownerRepo := postgres.NewOwnerRepository(db)
	// ACME server (RFC 8555 + RFC 9773 ARI) — Phase 1a foundation.
	// Repo wires nonce ops only; Phases 1b-4 extend with account /
	// order / authz / challenge CRUD.
	acmeRepo := postgres.NewACMERepository(db)
	logger.Info("initialized all repositories")

	// Initialize dynamic issuer registry.
	// Issuers are loaded from the database (with AES-256-GCM encrypted config).
	// On first boot with an empty database, env var issuers are seeded automatically.
	//
	// M-8 (CWE-916 / CWE-329): the encryption passphrase is passed as a raw
	// string into IssuerService / TargetService / IssuerRegistry. Each call to
	// crypto.EncryptIfKeySet generates a fresh 16-byte PBKDF2 salt and emits a
	// v2 blob (magic 0x02 || salt || nonce || sealed). Decryption auto-detects
	// v1 legacy blobs (no magic) and falls back to the fixed v1 salt for
	// backward compatibility; v1 blobs transparently upgrade to v2 on next
	// write. DO NOT pre-derive the key here with crypto.DeriveKey — that was
	// the v1 fixed-salt behaviour that M-8 removes.
	encryptionKey := cfg.Encryption.ConfigEncryptionKey
	if encryptionKey != "" {
		logger.Info("config encryption enabled (AES-256-GCM, per-ciphertext PBKDF2 salt)")
	} else {
		// C-2 fix: fail closed at startup when database-sourced issuer or target
		// rows exist without a configured encryption key. Previously the server
		// would emit a one-line warning and silently persist new GUI-created
		// configs as plaintext (CWE-311). Refuse to start instead: the operator
		// must either configure CERTCTL_CONFIG_ENCRYPTION_KEY or remove the
		// vulnerable rows before the control plane can boot.
		ctx := context.Background()
		dbIssuers, ierr := issuerRepo.List(ctx)
		if ierr != nil {
			logger.Error("startup check: failed to list issuers", "error", ierr)
			os.Exit(1)
		}
		dbTargets, terr := targetRepo.List(ctx)
		if terr != nil {
			logger.Error("startup check: failed to list targets", "error", terr)
			os.Exit(1)
		}
		var dbIssuerCount, dbTargetCount int
		for _, iss := range dbIssuers {
			if iss != nil && iss.Source == "database" {
				dbIssuerCount++
			}
		}
		for _, tgt := range dbTargets {
			if tgt != nil && tgt.Source == "database" {
				dbTargetCount++
			}
		}
		if dbIssuerCount > 0 || dbTargetCount > 0 {
			logger.Error(
				"startup refused: CERTCTL_CONFIG_ENCRYPTION_KEY is not set but database-sourced configs exist "+
					"(would expose sensitive fields as plaintext, CWE-311). "+
					"Set the encryption key or remove the affected rows before restarting.",
				"database_sourced_issuers", dbIssuerCount,
				"database_sourced_targets", dbTargetCount,
			)
			os.Exit(1)
		}
		logger.Warn("CERTCTL_CONFIG_ENCRYPTION_KEY not set — env-seeded issuers will be stored in plaintext; GUI-created issuers and targets will be rejected until a key is configured")
	}

	issuerRegistry := service.NewIssuerRegistry(logger)
	// Per-issuer-type issuance metrics (audit fix #4: closes the
	// per-issuer-type observability gap). Same instance is wired into
	// the registry (so adapters record issuance/renewal calls) AND
	// into the metrics handler (so the Prometheus exposer emits
	// certctl_issuance_total / _duration_seconds / _failures_total).
	issuanceMetrics := service.NewIssuanceMetrics(service.DefaultIssuanceBucketBoundaries)
	issuerRegistry.SetIssuanceMetrics(issuanceMetrics)

	// Top-10 fix #5 (2026-05-03 audit): Vault PKI token-renewal
	// metrics. Same instance is wired into the registry (so each
	// *vault.Connector built by Rebuild gets a recorder) AND into
	// the metrics handler (so the Prometheus exposer emits
	// certctl_vault_token_renewals_total). The renewal goroutine
	// itself is kicked off below by issuerRegistry.StartLifecycles
	// after Rebuild has populated the registry.
	vaultRenewalMetrics := service.NewVaultRenewalMetrics()
	issuerRegistry.SetVaultRenewalMetrics(vaultRenewalMetrics)

	// Audit fix #7: wire the cert-version lookup so ACME connectors
	// built by Rebuild can recover the leaf-cert DER from a serial-
	// only revoke request. The postgres CertificateRepository
	// satisfies acme.CertificateLookupRepo via its GetVersionBySerial
	// method. Without this, ACME RevokeCertificate falls back to the
	// legacy V1 "not supported" error.
	issuerRegistry.SetACMECertLookup(certificateRepo)

	// Initialize revocation repository
	revocationRepo := postgres.NewRevocationRepository(db)

	// Initialize services (following the dependency graph)
	auditService := service.NewAuditService(auditRepo)

	// Audit 2026-05-11 A-8 closure: detect residual actor-demo-anon
	// grants under non-`none` auth types. Defaults to WARN-only; flip
	// CERTCTL_DEMO_MODE_RESIDUAL_STRICT=true to fail-closed. Closes
	// the deferred Phase 2 leg of the 2026-05-10 HIGH-12 closure.
	{
		preflightCtx, preflightCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := preflightDemoModeResidual(preflightCtx, cfg, db, auditService, logger); err != nil {
			preflightCancel()
			logger.Error("startup refused: actor-demo-anon residual grants present + CERTCTL_DEMO_MODE_RESIDUAL_STRICT=true",
				"error", err)
			os.Exit(1)
		}
		preflightCancel()
	}

	// RBAC primitive (Bundle 1 Phase 4). Wires the postgres auth repos
	// + service-layer Authorizer that the AuthHandler / RequirePermission
	// middleware uses. Migration 000029_rbac.up.sql provides the schema
	// and seeds the seven default roles + canonical permission catalogue
	// + actor-demo-anon synthetic admin (CERTCTL_AUTH_TYPE=none demo path).
	authRoleRepo := postgres.NewRoleRepository(db)
	authPermRepo := postgres.NewPermissionRepository(db)
	authActorRoleRepo := postgres.NewActorRoleRepository(db)
	authAPIKeyRepo := postgres.NewAPIKeyRepository(db)
	authAuthorizer := authsvc.NewAuthorizer(authActorRoleRepo)
	// authCheckerAdapter bridges authsvc.Authorizer (typed-string args)
	// to the auth.PermissionChecker interface (plain-string args) so
	// internal/auth doesn't have to import internal/service/auth.
	authCheckerAdapter := authPermissionCheckerAdapter{a: authAuthorizer}

	// Bundle 1 Phase 6 — parse env-var named API keys + assemble the
	// runtime keystore + wire the bootstrap service. The keystore +
	// bootstrap handler must exist before the HandlerRegistry is
	// constructed below; the auth middleware that reads from the same
	// keystore is wired further down (next to the rest of the
	// middleware stack) but holds a reference to the same keystore so
	// runtime additions from bootstrap propagate without restart.
	//
	// boot-path operations use context.Background() because the long-
	// lived request context isn't constructed until later in main();
	// this matches the convention used by other one-shot setup calls
	// in this section (issuerService.SeedFromEnvVars, etc.).
	bootCtx := context.Background()
	namedKeys := assembleNamedAPIKeys(cfg, logger)
	backfillNamedKeyActorRoles(bootCtx, authActorRoleRepo, namedKeys, logger)
	authKeyStore := auth.NewMutableKeyStore(namedKeys)
	if persistedKeys, err := authAPIKeyRepo.List(bootCtx, authdomainAlias.DefaultTenantID); err == nil {
		for _, pk := range persistedKeys {
			authKeyStore.AddHashed(pk.Name, pk.KeyHash, pk.Admin)
		}
		if len(persistedKeys) > 0 {
			logger.Info("loaded persisted api_keys into runtime keystore",
				"count", len(persistedKeys))
		}
	} else {
		logger.Warn("api_keys boot loader failed; bootstrap-minted keys will not authenticate until next restart that succeeds",
			"err", err)
	}
	bootstrapStrategy := bootstrap.NewEnvTokenStrategy(
		cfg.Auth.BootstrapToken,
		func(ctx context.Context) (bool, error) {
			return authActorRoleRepo.AdminExists(ctx, authdomainAlias.DefaultTenantID)
		},
	)
	bootstrapService := bootstrap.NewService(
		bootstrapStrategy,
		authAPIKeyRepo,
		authActorRoleRepo,
		auditService,
		authKeyStore,
		auth.HashAPIKey,
	)
	if cfg.Auth.BootstrapToken != "" {
		// Honour the prompt's "warn at startup if token set + admin
		// exists" requirement. The strategy re-probes on every Validate
		// so this boot-time warning is purely informational.
		if exists, probeErr := authActorRoleRepo.AdminExists(bootCtx, authdomainAlias.DefaultTenantID); probeErr == nil && exists {
			logger.Warn("CERTCTL_BOOTSTRAP_TOKEN set but admin actors already exist; bootstrap endpoint will return 410 Gone — unset the env var to silence this warning")
		} else if probeErr != nil {
			logger.Warn("CERTCTL_BOOTSTRAP_TOKEN admin-existence probe failed at startup; behaviour will be determined by the live probe at request time", "err", probeErr)
		} else {
			logger.Info("bootstrap endpoint enabled — POST /api/v1/auth/bootstrap to mint the first admin key (one-shot)")
		}
	}
	bootstrapHandler := handler.NewBootstrapHandler(bootstrapService)

	// =========================================================================
	// Auth Bundle 2 Phase 4 — session service.
	//
	// Wired AFTER migrations + RBAC backfill, BEFORE the HTTP listener
	// binds (per the prompt's "fail-fatal on bootstrap key mint failure"
	// requirement). EnsureInitialSigningKey is idempotent: if a non-
	// retired signing key already exists for the tenant the call is a
	// no-op; otherwise it mints a fresh 32-byte HMAC key, persists it,
	// and emits an auth.session_signing_key_bootstrap audit row with
	// event_category=auth.
	//
	// Failure here is fatal — the server refuses to boot rather than
	// serve session-less.
	//
	// The session service is wired into the scheduler below (sessionGCLoop)
	// so the GC sweep runs every CERTCTL_SESSION_GC_INTERVAL tick. The
	// HTTP middleware that consumes ValidateInput / ValidateCSRF lands
	// in Phase 5; pre-Phase-5 deployments boot the service so the GC
	// sweep can keep the sessions + signing-keys tables tidy.
	sessionRepo := postgres.NewSessionRepository(db)
	sessionKeyRepo := postgres.NewSessionSigningKeyRepository(db)
	// Audit 2026-05-10 LOW-5 closure — install the trusted-proxy CIDR
	// allowlist from CERTCTL_TRUSTED_PROXIES. Empty disables XFF trust.
	session.SetTrustedProxies(cfg.Auth.TrustedProxies)
	sessionService := session.NewService(
		sessionRepo,
		sessionKeyRepo,
		auditService,
		authdomainAlias.DefaultTenantID,
		session.Config{
			IdleTimeout:         cfg.Auth.Session.IdleTimeout,
			AbsoluteTimeout:     cfg.Auth.Session.AbsoluteTimeout,
			SigningKeyRetention: cfg.Auth.Session.SigningKeyRetention,
			BindIP:              cfg.Auth.Session.BindIP,
			BindUserAgent:       cfg.Auth.Session.BindUserAgent,
		},
		cfg.Encryption.ConfigEncryptionKey,
	)
	if err := sessionService.EnsureInitialSigningKey(bootCtx); err != nil {
		logger.Error("FATAL: session signing key bootstrap failed; refusing to boot", "err", err)
		os.Exit(1)
	}

	// =========================================================================
	// Auth Bundle 2 Phase 5 — OIDC service + pre-login store + Phase 5 handler.
	//
	// Wired AFTER sessionService (Phase 4) so the OIDC PreLoginAdapter
	// can sign pre-login cookies under the active SessionSigningKey.
	// =========================================================================
	oidcProviderRepo := postgres.NewOIDCProviderRepository(db)
	oidcMappingRepo := postgres.NewGroupRoleMappingRepository(db)
	oidcUserRepo := postgres.NewUserRepository(db)
	// Audit 2026-05-10 HIGH-5: thread CERTCTL_CONFIG_ENCRYPTION_KEY into the
	// pre-login repo so state/nonce/PKCE-verifier are encrypted at rest. Same
	// key already protects OIDC client secrets and session signing keys.
	oidcPreLoginRepo := postgres.NewPreLoginRepository(db, cfg.Encryption.ConfigEncryptionKey)
	preLoginAdapter := oidcsvc.NewPreLoginAdapter(
		oidcPreLoginRepo,
		sessionKeyRepo, // Phase 4 SessionSigningKeyRepository
		authdomainAlias.DefaultTenantID,
		cfg.Encryption.ConfigEncryptionKey,
	)
	// SessionMinter port for the OIDC service. The OIDC HandleCallback
	// uses this to mint the post-login session after successful token
	// validation + group→role mapping.
	oidcSessionMinter := &sessionMinterAdapter{svc: sessionService}
	oidcService := oidcsvc.NewService(
		oidcProviderRepo,
		oidcMappingRepo,
		oidcUserRepo,
		oidcSessionMinter,
		preLoginAdapter,
		cfg.Encryption.ConfigEncryptionKey,
	)
	// Audit 2026-05-10 MED-16 — apply per-leg pre-login UA / IP
	// binding enforcement toggles from config.
	oidcService.SetPreLoginBindingRequirements(
		cfg.Auth.OIDCPreLoginRequireUA,
		cfg.Auth.OIDCPreLoginRequireIP,
	)
	// SameSite resolution from CERTCTL_SESSION_SAMESITE (default Lax;
	// "Strict" for high-security environments at the cost of breaking
	// inbound deep-links from external apps).
	sameSiteMode := http.SameSiteLaxMode
	if strings.EqualFold(cfg.Auth.Session.SameSite, "Strict") {
		sameSiteMode = http.SameSiteStrictMode
	}
	// Audit 2026-05-10 HIGH-3 — BCL iat-skew window + jti consumed-set.
	bclMaxAge := time.Duration(cfg.Auth.OIDCBCLMaxAgeSeconds) * time.Second
	if bclMaxAge <= 0 {
		bclMaxAge = handler.DefaultBCLVerifierMaxAge
	}
	bclReplayRepo := postgres.NewBCLReplayRepository(db)
	authSessionOIDCHandler := handler.NewAuthSessionOIDCHandler(
		oidcService,
		sessionService,
		handler.NewDefaultBCLVerifier(oidcProviderRepo, authdomainAlias.DefaultTenantID, nil).WithMaxAge(bclMaxAge),
		oidcProviderRepo,
		oidcMappingRepo,
		sessionRepo,
		oidcUserRepo, // CRIT-2: BCL sub→actor_id lookup via users.GetByOIDCSubject
		auditService,
		cfg.Encryption.ConfigEncryptionKey,
		authdomainAlias.DefaultTenantID,
		"/", // post-login redirect target; GUI dashboard
		handler.SessionCookieAttrs{
			SameSite: sameSiteMode,
			Secure:   true,
		},
	).WithBCLReplayConsumer(bclReplayRepo, bclMaxAge). // HIGH-3 jti consumed-set.
								WithPermissionChecker(authCheckerAdapter) // MED-2 auth.session.list.all gate.

	// =========================================================================
	// Auth Bundle 2 Phase 7 — OIDC first-admin bootstrap hook.
	//
	// Wired AFTER oidcService is constructed. The hook closure consults
	// the configured CERTCTL_BOOTSTRAP_ADMIN_GROUPS + the AdminExists
	// probe; on first match it grants r-admin via the ActorRoleRepository
	// + emits a bootstrap.oidc_first_admin audit row. Subsequent
	// admin-already-exists logins return grantAdmin=false silently.
	// Disabled (no-op) when CERTCTL_BOOTSTRAP_ADMIN_GROUPS is empty.
	if len(cfg.Auth.BootstrapAdminGroups) > 0 {
		bootstrapGroups := make(map[string]struct{}, len(cfg.Auth.BootstrapAdminGroups))
		for _, g := range cfg.Auth.BootstrapAdminGroups {
			bootstrapGroups[strings.TrimSpace(g)] = struct{}{}
		}
		bootstrapProviderID := cfg.Auth.BootstrapOIDCProviderID
		oidcService.SetAdminBootstrapHook(func(ctx context.Context, providerID string, groups []string, userID string) (bool, error) {
			// Provider-specificity: when configured, only the named
			// provider is eligible for bootstrap.
			if bootstrapProviderID != "" && providerID != bootstrapProviderID {
				return false, nil
			}
			// Admin-already-exists: bootstrap mode is disabled once
			// any actor in the tenant holds r-admin.
			adminExists, probeErr := authActorRoleRepo.AdminExists(ctx, authdomainAlias.DefaultTenantID)
			if probeErr != nil {
				return false, fmt.Errorf("admin existence probe: %w", probeErr)
			}
			if adminExists {
				return false, nil
			}
			// Group intersection check.
			matched := false
			for _, g := range groups {
				if _, ok := bootstrapGroups[g]; ok {
					matched = true
					break
				}
			}
			if !matched {
				return false, nil
			}
			// Match. Grant r-admin via the actor-role repo.
			grant := &authdomainAlias.ActorRole{
				ActorID:   userID,
				ActorType: authdomainAlias.ActorTypeValue("User"),
				RoleID:    authdomainAlias.RoleIDAdmin,
				TenantID:  authdomainAlias.DefaultTenantID,
				GrantedBy: "oidc-bootstrap",
			}
			if gerr := authActorRoleRepo.Grant(ctx, grant); gerr != nil {
				return false, fmt.Errorf("grant r-admin: %w", gerr)
			}
			// Emit audit row with event_category=auth.
			_ = auditService.RecordEventWithCategory(ctx, userID, domain.ActorTypeUser,
				"bootstrap.oidc_first_admin", domain.EventCategoryAuth,
				"users", userID,
				map[string]interface{}{
					"user_id":     userID,
					"provider_id": providerID,
					"trigger":     "oidc_group_match",
				})
			logger.Info("OIDC first-admin bootstrap fired — user granted r-admin",
				"user_id", userID, "provider_id", providerID)
			return true, nil
		})
		logger.Info("OIDC first-admin bootstrap enabled",
			"groups", cfg.Auth.BootstrapAdminGroups,
			"provider_id_filter", bootstrapProviderID)
	}

	// =========================================================================
	// Auth Bundle 2 Phase 7.5 — break-glass admin service + handler.
	// =========================================================================
	breakglassRepo := postgres.NewBreakglassCredentialRepository(db)
	breakglassService := breakglass.NewService(
		breakglassRepo,
		auditService,
		breakglassSessionMinterAdapter{svc: sessionService},
		breakglass.Config{
			Enabled:              cfg.Auth.Breakglass.Enabled,
			LockoutThreshold:     cfg.Auth.Breakglass.LockoutThreshold,
			LockoutDuration:      cfg.Auth.Breakglass.LockoutDuration,
			LockoutResetInterval: cfg.Auth.Breakglass.LockoutResetInterval,
		},
		authdomainAlias.DefaultTenantID,
	)
	breakglassHandler := handler.NewAuthBreakglassHandler(breakglassService, handler.SessionCookieAttrs{
		SameSite: sameSiteMode,
		Secure:   true,
	})
	// Bundle 5 closure (audit S1): wire the per-source-IP rate limiter
	// for POST /auth/breakglass/login. 5 attempts / minute / IP, 50 000
	// key cap. Pre-Bundle-5 the handler docstring claimed this rate
	// limit but no limiter was installed; the route bypasses the global
	// RPS middleware because it's mounted via r.mux.Handle in the
	// AuthExemptRouterRoutes path. The service-layer Argon2id lockout
	// state machine remains the second line of defense.
	breakglassHandler.SetLoginRateLimiter(
		ratelimit.NewLimiter(cfg.RateLimit.SlidingWindowBackend, db, 5, time.Minute, 50_000),
	)
	if cfg.Auth.Breakglass.Enabled {
		logger.Warn("CERTCTL_BREAKGLASS_ENABLED=true — break-glass admin path is ACTIVE; this bypasses SSO. Disable in steady-state.",
			"lockout_threshold", cfg.Auth.Breakglass.LockoutThreshold,
			"lockout_duration", cfg.Auth.Breakglass.LockoutDuration.String())
	}

	// Bundle 5 closure (audit RT-L2): operator-visible startup warning
	// when CERTCTL_ACME_INSECURE=true disables ACME directory TLS
	// verification. Pre-Bundle-5 this knob silently disabled TLS
	// verification for every ACME issuance call without surfacing any
	// signal at boot; the only mention lived in a values.yaml comment.
	// Pebble / step-ca / dev ACME proxies use self-signed certs so the
	// knob has legitimate dev uses, but a production deploy that flips
	// it (typically copy-pasting from a Pebble integration runbook)
	// gets MITM exposure on every CA round-trip. Loud at boot now.
	if cfg.ACME.Insecure {
		logger.Warn("CERTCTL_ACME_INSECURE=true — ACME directory TLS verification is DISABLED. Every ACME round-trip skips certificate chain validation; production deploys MUST unset this. Acceptable only for dev / Pebble / step-ca with operator-supplied self-signed roots.")
	}

	policyService := service.NewPolicyService(policyRepo, auditService)
	policyService.SetCertRepo(certificateRepo) // D-008: CertificateLifetime arm needs CertificateVersion.NotBefore/NotAfter
	// G-1: RenewalPolicyService — distinct from PolicyService (compliance rules).
	// Drives /api/v1/renewal-policies CRUD; the service layer owns slugify + validation,
	// the repo layer owns sentinel translation for 23505 (name UNIQUE) and 23503
	// (FK-RESTRICT against managed_certificates.renewal_policy_id).
	renewalPolicyService := service.NewRenewalPolicyService(renewalPolicyRepo)
	certificateService := service.NewCertificateService(certificateRepo, policyService, auditService)
	// Atomic audit-row plumbing (closes the #3 acquisition-readiness
	// blocker from the 2026-05-01 issuer coverage audit). The same
	// transactor instance is shared across CertificateService /
	// RevocationSvc / RenewalService so all three audit-emitting
	// service paths run their writes in transactions backed by the
	// same *sql.DB handle.
	transactor := postgres.NewTransactor(db)
	certificateService.SetTransactor(transactor)

	// Rank 7 of the 2026-05-03 Infisical deep-research deliverable —
	// issuance approval-workflow primitive. ApprovalRepository +
	// ApprovalMetrics + ApprovalService construct here; the gate is
	// activated on CertificateService via SetApprovalService +
	// SetProfileRepo. Inactive when CertificateProfile.RequiresApproval
	// is false (the default), preserving the historical unattended
	// renewal path. See docs/approval-workflow.md.
	approvalRepo := postgres.NewApprovalRepository(db)
	approvalMetrics := service.NewApprovalMetrics()
	approvalService := service.NewApprovalService(approvalRepo, jobRepo, auditService,
		approvalMetrics, cfg.Approval.BypassEnabled)
	if cfg.Approval.BypassEnabled {
		logger.Warn("CERTCTL_APPROVAL_BYPASS=true — every approval auto-approves with actor=system-bypass; production deploys must leave this unset")
	}
	certificateService.SetApprovalService(approvalService)
	certificateService.SetProfileRepo(profileRepo)
	approvalHandler := handler.NewApprovalHandler(approvalService)

	// Rank 8 of the 2026-05-03 deep-research deliverable — first-class
	// CA hierarchy management (intermediate_cas table + admin-gated
	// hierarchy endpoints). The service receives the issuerRepo so
	// future surface area (issuer-row hierarchy_mode validation) can
	// query the issuer config; for the commit-4 wiring it carries
	// only the fields used today. The signer.FileDriver shared with
	// the OCSP responder bootstrap path is reused here — operators
	// can plug in PKCS#11 / cloud-KMS drivers via the same Driver
	// interface without touching the service. See
	// docs/intermediate-ca-hierarchy.md.
	intermediateCARepo := postgres.NewIntermediateCARepository(db)
	intermediateCAMetrics := service.NewIntermediateCAMetrics()
	// Defer wiring the service + handler — signerDriver is constructed
	// further down in this function alongside the OCSP responder
	// bootstrap path. The service holds a reference to issuerRepo for
	// future hierarchy_mode validation surface area.
	_ = intermediateCAMetrics // service constructed below alongside signerDriver

	notifierRegistry := make(map[string]service.Notifier)

	// Wire notifier connectors from config
	if cfg.Notifiers.SlackWebhookURL != "" {
		slackNotifier := notifyslack.New(notifyslack.Config{
			WebhookURL:      cfg.Notifiers.SlackWebhookURL,
			ChannelOverride: cfg.Notifiers.SlackChannel,
			Username:        cfg.Notifiers.SlackUsername,
		})
		notifierRegistry["Slack"] = slackNotifier
		logger.Info("Slack notifier enabled")
	}
	if cfg.Notifiers.TeamsWebhookURL != "" {
		teamsNotifier := notifyteams.New(notifyteams.Config{
			WebhookURL: cfg.Notifiers.TeamsWebhookURL,
		})
		notifierRegistry["Teams"] = teamsNotifier
		logger.Info("Teams notifier enabled")
	}
	if cfg.Notifiers.PagerDutyRoutingKey != "" {
		pdNotifier := notifypagerduty.New(notifypagerduty.Config{
			RoutingKey: cfg.Notifiers.PagerDutyRoutingKey,
			Severity:   cfg.Notifiers.PagerDutySeverity,
		})
		notifierRegistry["PagerDuty"] = pdNotifier
		logger.Info("PagerDuty notifier enabled")
	}
	if cfg.Notifiers.OpsGenieAPIKey != "" {
		ogNotifier := notifyopsgenie.New(notifyopsgenie.Config{
			APIKey:   cfg.Notifiers.OpsGenieAPIKey,
			Priority: cfg.Notifiers.OpsGeniePriority,
		})
		notifierRegistry["OpsGenie"] = ogNotifier
		logger.Info("OpsGenie notifier enabled")
	}

	// Wire email notifier if SMTP is configured
	var emailAdapter *notifyemail.NotifierAdapter
	if cfg.Notifiers.SMTPHost != "" && cfg.Notifiers.SMTPFromAddress != "" {
		emailConnector := notifyemail.New(&notifyemail.Config{
			SMTPHost:    cfg.Notifiers.SMTPHost,
			SMTPPort:    cfg.Notifiers.SMTPPort,
			Username:    cfg.Notifiers.SMTPUsername,
			Password:    cfg.Notifiers.SMTPPassword,
			FromAddress: cfg.Notifiers.SMTPFromAddress,
			UseTLS:      cfg.Notifiers.SMTPUseTLS,
		}, logger)
		emailAdapter = notifyemail.NewNotifierAdapter(emailConnector)
		notifierRegistry["Email"] = emailAdapter
		logger.Info("Email notifier enabled",
			"smtp_host", cfg.Notifiers.SMTPHost,
			"smtp_port", cfg.Notifiers.SMTPPort,
			"from", cfg.Notifiers.SMTPFromAddress)
	}

	notificationService := service.NewNotificationService(notificationRepo, notifierRegistry)
	notificationService.SetOwnerRepo(ownerRepo)

	// Rank 4 of the 2026-05-03 Infisical deep-research deliverable
	// (per the project's deep-research deliverable, Part 5). Per-policy
	// multi-channel expiry-alert metrics. Same instance is wired into
	// the notification service (recording side, every
	// SendThresholdAlertOnChannel call reports its outcome) AND into
	// the metrics handler below (exposing side, Prometheus emitter
	// reads the counters). Mirrors the VaultRenewalMetrics wiring
	// pattern from the 2026-05-03 audit fix #5 — single instance,
	// shared between recorder and exposer.
	expiryAlertMetrics := service.NewExpiryAlertMetrics()
	notificationService.SetExpiryAlertMetrics(expiryAlertMetrics)

	// Create RevocationSvc with its dependencies
	revocationSvc := service.NewRevocationSvc(certificateRepo, revocationRepo, auditService)
	revocationSvc.SetTransactor(transactor)
	revocationSvc.SetIssuerRegistry(issuerRegistry)
	revocationSvc.SetNotificationService(notificationService)

	// Create CAOperationsSvc with its dependencies
	caOperationsSvc := service.NewCAOperationsSvc(revocationRepo, certificateRepo, profileRepo)
	caOperationsSvc.SetIssuerRegistry(issuerRegistry)

	// Bundle CRL/OCSP-Responder: wire CRL cache + OCSP responder
	// repositories. The CRL cache lets the HTTP CRL endpoint serve from
	// pre-generated bytes (Phase 3). The OCSP responder repo lets the
	// local issuer bootstrap a dedicated responder cert per RFC 6960
	// §2.6 instead of signing OCSP with the CA key directly (Phase 2).
	//
	// The signer.FileDriver is the production driver; it provides keys
	// to the responder bootstrap path. Future drivers (PKCS#11, cloud
	// KMS) plug in via the same Driver interface without changing this
	// wiring. The DirHardener / Marshaler hooks stay nil here — the
	// bootstrap path's GenerateOutPath sets the destination per
	// responder; the local issuer's existing keystore.ensureKeyDirSecure
	// equivalent is invoked by FileDriver.Generate when DirHardener is
	// supplied at the call site.
	crlCacheRepo := postgres.NewCRLCacheRepository(db)
	ocspResponderRepo := postgres.NewOCSPResponderRepository(db)
	signerDriver := &signer.FileDriver{}
	issuerRegistry.SetLocalIssuerDeps(&service.LocalIssuerDeps{
		OCSPResponderRepo: ocspResponderRepo,
		SignerDriver:      signerDriver,
		KeyDir:            cfg.OCSPResponder.KeyDir,
		RotationGrace:     cfg.OCSPResponder.RotationGrace,
		Validity:          cfg.OCSPResponder.Validity,
	})

	// Rank 8 service + handler — wired here so signerDriver is in
	// scope. The same FileDriver instance feeds both the OCSP
	// responder bootstrap path and the intermediate-CA hierarchy.
	// Operators that swap to PKCS#11 / cloud-KMS drivers reuse the
	// single Driver instance across both surfaces.
	intermediateCAService := service.NewIntermediateCAService(
		intermediateCARepo, issuerRepo, signerDriver, auditService, intermediateCAMetrics)
	intermediateCAHandler := handler.NewIntermediateCAHandler(intermediateCAService)
	crlCacheService := service.NewCRLCacheService(crlCacheRepo, caOperationsSvc, issuerRegistry, logger)

	// Production hardening II Phase 2: OCSP response cache. Mirrors the
	// CRL cache wire above. The cache service consults
	// caOperationsSvc.LiveSignOCSPResponse on miss (via the bypass-
	// cache entry point that breaks the recursion); the responder
	// counters get wired in Phase 8 when the Prometheus exposer reads
	// them.
	ocspResponseCacheRepo := postgres.NewOCSPResponseCacheRepository(db)
	// Production hardening II Phase 8: share a single OCSPCounters
	// instance between the cache service (Phase 2) and the Prometheus
	// exposer (Phase 8) so the metrics endpoint reflects every counter
	// tick that happens inside the cache service's hot path.
	ocspCounters := service.NewOCSPCounters()
	ocspResponseCacheService := service.NewOCSPResponseCacheService(ocspResponseCacheRepo, caOperationsSvc, ocspCounters, logger)
	caOperationsSvc.SetOCSPCacheSvc(ocspResponseCacheService)
	// Load-bearing security wire: invalidate the cache after a successful
	// revocation so the next OCSP fetch returns "revoked" (not the stale
	// "good" cached blob). Without this the cache would serve stale-
	// good for up to CERTCTL_OCSP_CACHE_REFRESH_INTERVAL after a revoke.
	revocationSvc.SetOCSPCacheInvalidator(ocspResponseCacheService)

	// Wire sub-services into CertificateService
	certificateService.SetRevocationSvc(revocationSvc)
	certificateService.SetCAOperationsSvc(caOperationsSvc)
	// CRL cache makes GenerateDERCRL serve from the pre-generated cache
	// instead of regenerating per request (CRL/OCSP-Responder Phase 4).
	certificateService.SetCRLCacheSvc(crlCacheService)
	certificateService.SetTargetRepo(targetRepo)
	certificateService.SetJobRepo(jobRepo)
	certificateService.SetKeygenMode(cfg.Keygen.Mode)
	renewalService := service.NewRenewalService(certificateRepo, jobRepo, renewalPolicyRepo, profileRepo, auditService, notificationService, issuerRegistry, cfg.Keygen.Mode)
	renewalService.SetTransactor(transactor)
	renewalService.SetTargetRepo(targetRepo)
	deploymentService := service.NewDeploymentService(jobRepo, targetRepo, agentRepo, certificateRepo, auditService, notificationService)
	jobService := service.NewJobService(jobRepo, certificateRepo, ownerRepo, renewalService, deploymentService, logger)
	// I-001: emit "job_retry" audit events when the scheduler resets Failed→Pending.
	// SetAuditService is optional — JobService falls back to nil-guarded no-op if unwired.
	jobService.SetAuditService(auditService)
	// Audit fix #9: bound the per-tick goroutine fan-out so a 5k-cert
	// sweep doesn't trip upstream-CA rate limits. Default 25 from
	// CERTCTL_RENEWAL_CONCURRENCY; ≤0 normalised to 1 (sequential)
	// inside the setter.
	jobService.SetRenewalConcurrency(cfg.Scheduler.RenewalConcurrency)
	// SCALE-001 closure (Sprint 2, 2026-05-16): per-tick ClaimPendingJobs
	// cap so 100K-job bursts don't materialise the full queue into
	// memory before the bounded fan-out engages. Setting normalises ≤0
	// to 1000 (fail-safe vs. legacy unlimited semantics).
	jobService.SetClaimLimit(cfg.Scheduler.JobClaimLimit)
	agentService := service.NewAgentService(agentRepo, certificateRepo, jobRepo, targetRepo, auditService, issuerRegistry, renewalService)
	agentService.SetProfileRepo(profileRepo)
	issuerService := service.NewIssuerService(issuerRepo, auditService, issuerRegistry, encryptionKey, logger)

	// Seed issuers from env vars on first boot (empty database only), then build registry
	issuerService.SeedFromEnvVars(context.Background(), cfg)
	if err := issuerService.BuildRegistry(context.Background()); err != nil {
		logger.Error("failed to build issuer registry from database", "error", err)
	}
	logger.Info("issuer registry loaded", "issuers", issuerRegistry.Len())

	// Top-10 fix #5 (2026-05-03 audit): kick off any optional
	// long-running background work bound to issuer connectors. Today
	// only Vault PKI implements issuer.Lifecycle (renew-self loop);
	// other connectors are silently skipped. Per-connector Start
	// failures are logged, not fatal — a misconfigured Vault doesn't
	// block server startup. Stop is wired to the deferred shutdown
	// path below so the goroutines exit cleanly on signal.
	issuerRegistry.StartLifecycles(context.Background())
	defer issuerRegistry.StopLifecycles()
	targetService := service.NewTargetService(targetRepo, auditService, agentRepo, encryptionKey, logger)
	profileService := service.NewProfileService(profileRepo, auditService)
	// Bundle 1 Phase 9 — approval-bypass closure. Wire the profile
	// service's gate to the existing ApprovalService so edits to a
	// RequiresApproval=true profile route through the four-eyes
	// workflow. The profile-edit-apply callback registered on the
	// ApprovalService closes the loop: when an approver decides,
	// the callback deserializes req.Payload and persists the diff.
	profileService.SetApprovalService(approvalService)
	approvalService.SetProfileEditApply(func(ctx context.Context, req *domain.ApprovalRequest) error {
		var pendingProfile domain.CertificateProfile
		if err := json.Unmarshal(req.Payload, &pendingProfile); err != nil {
			return fmt.Errorf("decode profile-edit payload: %w", err)
		}
		pendingProfile.ID = req.ProfileID
		if err := profileRepo.Update(ctx, &pendingProfile); err != nil {
			return fmt.Errorf("apply profile-edit diff: %w", err)
		}
		// Audit row category=auth so the auditor surface keeps the
		// approval-decision history grouped with the request side.
		if auditService != nil {
			_ = auditService.RecordEventWithCategory(ctx, "approval-system",
				domain.ActorTypeSystem, "profile.edit_applied",
				domain.EventCategoryAuth, "certificate_profile",
				req.ProfileID,
				map[string]interface{}{
					"approval_id":  req.ID,
					"requested_by": req.RequestedBy,
				})
		}
		return nil
	})
	teamService := service.NewTeamService(teamRepo, auditService)
	ownerService := service.NewOwnerService(ownerRepo, auditService)
	agentGroupRepo := postgres.NewAgentGroupRepository(db)
	agentGroupService := service.NewAgentGroupService(agentGroupRepo, auditService)
	discoveryRepo := postgres.NewDiscoveryRepository(db)
	discoveryService := service.NewDiscoveryService(discoveryRepo, certificateRepo, auditService)
	networkScanRepo := postgres.NewNetworkScanRepository(db)
	networkScanService := service.NewNetworkScanService(networkScanRepo, discoveryService, auditService, logger)
	// SCEP RFC 8894 + Intune master bundle Phase 11.5 — wire the SCEP
	// probe persistence repo onto the network scan service so the new
	// /api/v1/network-scan/scep-probe endpoint can persist results to
	// scep_probe_results (migration 000021).
	scepProbeRepo := postgres.NewSCEPProbeResultRepository(db)
	networkScanService.SetSCEPProbeRepo(scepProbeRepo)
	logger.Info("initialized network scan service")

	// Ensure the sentinel "server-scanner" agent exists for network discovery dedup.
	// This agent ID is used as the agent_id in discovered_certificates for network-scanned certs.
	if cfg.NetworkScan.Enabled {
		sentinelAgent := &domain.Agent{
			ID:     service.SentinelAgentID,
			Name:   "Network Scanner (Server-Side)",
			Status: domain.AgentStatusOnline,
		}
		// M-6: use CreateIfNotExists so duplicate rows on restart/upgrade are
		// idempotent without swallowing unrelated DB failures (CWE-662).
		created, err := agentRepo.CreateIfNotExists(context.Background(), sentinelAgent)
		if err != nil {
			logger.Error("sentinel agent creation failed", "id", service.SentinelAgentID, "error", err)
		} else if created {
			logger.Info("sentinel agent created", "id", service.SentinelAgentID)
		} else {
			logger.Debug("sentinel agent already exists", "id", service.SentinelAgentID)
		}
	}

	// Initialize cloud discovery sources (M50)
	var cloudDiscoveryService *service.CloudDiscoveryService
	if cfg.CloudDiscovery.Enabled {
		cloudDiscoveryService = service.NewCloudDiscoveryService(discoveryService, logger)

		// AWS Secrets Manager
		if cfg.CloudDiscovery.AWSSM.Enabled {
			awsSource := discoveryawssm.New(&cfg.CloudDiscovery.AWSSM, logger)
			cloudDiscoveryService.RegisterSource(awsSource)
			// Create sentinel agent for AWS SM
			sentinelAWS := &domain.Agent{
				ID:     service.SentinelAWSSecretsMgr,
				Name:   "AWS Secrets Manager Discovery",
				Status: domain.AgentStatusOnline,
			}
			// M-6: idempotent create (CWE-662).
			created, err := agentRepo.CreateIfNotExists(context.Background(), sentinelAWS)
			if err != nil {
				logger.Error("sentinel agent creation failed", "id", service.SentinelAWSSecretsMgr, "error", err)
			} else if created {
				logger.Info("sentinel agent created", "id", service.SentinelAWSSecretsMgr)
			} else {
				logger.Debug("sentinel agent already exists", "id", service.SentinelAWSSecretsMgr)
			}
		}

		// Azure Key Vault
		if cfg.CloudDiscovery.AzureKV.Enabled {
			azureSource := discoveryazurekv.New(discoveryazurekv.Config{
				VaultURL:     cfg.CloudDiscovery.AzureKV.VaultURL,
				TenantID:     cfg.CloudDiscovery.AzureKV.TenantID,
				ClientID:     cfg.CloudDiscovery.AzureKV.ClientID,
				ClientSecret: cfg.CloudDiscovery.AzureKV.ClientSecret,
			}, logger)
			cloudDiscoveryService.RegisterSource(azureSource)
			sentinelAzure := &domain.Agent{
				ID:     service.SentinelAzureKeyVault,
				Name:   "Azure Key Vault Discovery",
				Status: domain.AgentStatusOnline,
			}
			// M-6: idempotent create (CWE-662).
			created, err := agentRepo.CreateIfNotExists(context.Background(), sentinelAzure)
			if err != nil {
				logger.Error("sentinel agent creation failed", "id", service.SentinelAzureKeyVault, "error", err)
			} else if created {
				logger.Info("sentinel agent created", "id", service.SentinelAzureKeyVault)
			} else {
				logger.Debug("sentinel agent already exists", "id", service.SentinelAzureKeyVault)
			}
		}

		// GCP Secret Manager
		if cfg.CloudDiscovery.GCPSM.Enabled {
			gcpSource := discoverygcpsm.New(&cfg.CloudDiscovery.GCPSM, logger)
			cloudDiscoveryService.RegisterSource(gcpSource)
			sentinelGCP := &domain.Agent{
				ID:     service.SentinelGCPSecretMgr,
				Name:   "GCP Secret Manager Discovery",
				Status: domain.AgentStatusOnline,
			}
			// M-6: idempotent create (CWE-662).
			created, err := agentRepo.CreateIfNotExists(context.Background(), sentinelGCP)
			if err != nil {
				logger.Error("sentinel agent creation failed", "id", service.SentinelGCPSecretMgr, "error", err)
			} else if created {
				logger.Info("sentinel agent created", "id", service.SentinelGCPSecretMgr)
			} else {
				logger.Debug("sentinel agent already exists", "id", service.SentinelGCPSecretMgr)
			}
		}

		logger.Info("cloud discovery enabled",
			"sources", cloudDiscoveryService.SourceCount(),
			"interval", cfg.CloudDiscovery.Interval.String())
	}

	logger.Info("initialized all services")

	// Initialize bulk revocation service
	bulkRevocationService := service.NewBulkRevocationService(revocationSvc, certificateRepo, auditService, logger)

	// L-1 master (cat-l-fa0c1ac07ab5 + cat-l-8a1fb258a38a): bulk-renew
	// and bulk-reassign services. Mirror BulkRevocationService wiring so
	// the construction site is co-located with the existing bulk endpoint.
	// keygenMode is threaded so bulk-renew jobs land in the same initial
	// status (AwaitingCSR vs Pending) as single-cert TriggerRenewal.
	bulkRenewalService := service.NewBulkRenewalService(certificateRepo, jobRepo, auditService, logger, cfg.Keygen.Mode)
	bulkReassignmentService := service.NewBulkReassignmentService(certificateRepo, ownerRepo, auditService, logger)

	// Initialize stats and metrics services
	statsService := service.NewStatsService(certificateRepo, jobRepo, agentRepo)
	// I-005: wire the notification repository so DashboardSummary.NotificationsDead
	// is populated, which in turn drives the Prometheus counter
	// certctl_notification_dead_total in GetPrometheusMetrics. Setter
	// pattern keeps NewStatsService's nine call sites (main.go + stats_test.go
	// + 8 digest_test.go sites) untouched.
	statsService.SetNotifRepo(notificationRepo)
	logger.Info("initialized stats service")

	// Initialize API handlers
	certificateHandler := handler.NewCertificateHandler(certificateService)
	// Production hardening II Phase 3: per-source-IP OCSP rate limit.
	// Window 1m so the cap counts requests per minute. Map cap 50k
	// matches the SCEP/Intune replay cache cap. Zero disables.
	ocspLimiter := ratelimit.NewLimiter(cfg.RateLimit.SlidingWindowBackend, db, cfg.Scheduler.OCSPRateLimitPerIPMin, time.Minute, 50_000)
	certificateHandler.SetOCSPRateLimiter(ocspLimiter)
	issuerHandler := handler.NewIssuerHandler(issuerService)
	targetHandler := handler.NewTargetHandler(targetService)
	agentHandler := handler.NewAgentHandler(agentService, cfg.Auth.AgentBootstrapToken)
	jobHandler := handler.NewJobHandler(jobService)
	policyHandler := handler.NewPolicyHandler(policyService)
	// G-1: RenewalPolicyHandler — /api/v1/renewal-policies CRUD. Value-returning
	// constructor matches the house pattern (PolicyHandler, IssuerHandler etc.);
	// the registry stores it by value in HandlerRegistry.RenewalPolicies.
	renewalPolicyHandler := handler.NewRenewalPolicyHandler(renewalPolicyService)
	profileHandler := handler.NewProfileHandler(profileService)
	teamHandler := handler.NewTeamHandler(teamService)
	ownerHandler := handler.NewOwnerHandler(ownerService)
	agentGroupHandler := handler.NewAgentGroupHandler(agentGroupService)
	auditHandler := handler.NewAuditHandler(auditService)
	notificationHandler := handler.NewNotificationHandler(notificationService)
	statsHandler := handler.NewStatsHandler(statsService)
	metricsHandler := handler.NewMetricsHandler(statsService, time.Now())
	// Production hardening II Phase 8: wire the per-area counter
	// snapshotters so the Prometheus exposer surfaces them. Operators
	// alert on certctl_ocsp_counter_total{label="rate_limited"},
	// {label="nonce_malformed"}, etc.
	metricsHandler.SetOCSPCounters(ocspCounters)
	// Audit fix #4: wire the per-issuer-type issuance metrics so the
	// /api/v1/metrics/prometheus exposer emits the new series.
	metricsHandler.SetIssuanceCounters(issuanceMetrics)
	// Top-10 fix #5 (2026-05-03 audit): Vault PKI token-renewal counter.
	// Same instance the registry uses to record per-tick results.
	metricsHandler.SetVaultRenewals(vaultRenewalMetrics)
	// Rank 4 of the 2026-05-03 Infisical deep-research deliverable:
	// per-policy multi-channel expiry-alert counter. Same instance the
	// notification service uses to record per-(channel, threshold,
	// result) outcomes.
	metricsHandler.SetExpiryAlerts(expiryAlertMetrics)
	// Bundle-5 / H-006: pass the *sql.DB pool so /ready can probe DB
	// connectivity via PingContext. /health stays shallow (liveness signal).
	healthHandler := handler.NewHealthHandler(cfg.Auth.Type, db)
	// Bundle 1 Phase 3 closure (M1): wire the AuthCheckResolver so
	// /v1/auth/check returns the caller's standing roles + effective
	// permissions in the same response. The shim is tiny — just a type-
	// erasure wrap around the repo so the handler layer doesn't have to
	// import internal/domain/auth or internal/repository/postgres.
	healthHandler.Resolver = authCheckResolverAdapter{repo: authActorRoleRepo}
	// Bundle 2 Phase 6 / Category E — wire the OIDC providers resolver
	// so GET /api/v1/auth/info returns the configured provider list
	// (id + display_name + login_url) for the GUI's Login page button
	// rendering. The shim adapts the postgres OIDCProviderRepository
	// to the handler's narrow OIDCProvidersListResolver projection.
	healthHandler.OIDCProvidersResolver = oidcProvidersListAdapter{repo: oidcProviderRepo}
	// U-3 ride-along (cat-u-no_version_endpoint, P2): the version handler
	// answers GET /api/v1/version with build identity (ldflags Version,
	// VCS commit/dirty/timestamp, Go runtime version). Wired through the
	// no-auth dispatch + audit ExcludePaths below so probes and rollout
	// systems can read it without Bearer credentials and without flooding
	// the audit trail.
	versionHandler := handler.NewVersionHandler()
	discoveryHandler := handler.NewDiscoveryHandler(discoveryService)
	networkScanHandler := handler.NewNetworkScanHandler(networkScanService)
	verificationService := service.NewVerificationService(jobRepo, auditService, logger)
	verificationHandler := handler.NewVerificationHandler(verificationService)
	exportService := service.NewExportService(certificateRepo, auditService)
	exportHandler := handler.NewExportHandler(exportService)
	// Production hardening II Phase 3: per-actor cert-export rate limit.
	// Window 1h so the cap counts exports per hour. Zero disables.
	exportLimiter := ratelimit.NewLimiter(cfg.RateLimit.SlidingWindowBackend, db, cfg.Scheduler.CertExportRateLimitPerActorHr, time.Hour, 50_000)
	exportHandler.SetExportRateLimiter(exportLimiter)

	bulkRevocationHandler := handler.NewBulkRevocationHandler(bulkRevocationService)
	// L-1 master closure: handlers for the new bulk-renew + bulk-reassign
	// endpoints. Both registered via HandlerRegistry below; dispatched
	// through the standard authed middleware chain (no admin gate).
	bulkRenewalHandler := handler.NewBulkRenewalHandler(bulkRenewalService)
	bulkReassignmentHandler := handler.NewBulkReassignmentHandler(bulkReassignmentService)

	// Initialize digest service (requires email notifier)
	var digestService *service.DigestService
	var digestHandler *handler.DigestHandler
	if cfg.Digest.Enabled && emailAdapter != nil {
		digestService = service.NewDigestService(
			statsService, certificateRepo, ownerRepo, emailAdapter, cfg.Digest.Recipients, logger,
		)
		digestHandler = handler.NewDigestHandler(digestService)
		logger.Info("digest service enabled",
			"interval", cfg.Digest.Interval.String(),
			"recipients", len(cfg.Digest.Recipients))
	} else {
		// Create a no-op digest handler for route registration
		digestHandler = handler.NewDigestHandler(nil)
		if cfg.Digest.Enabled && emailAdapter == nil {
			logger.Warn("digest enabled but SMTP not configured — digest emails will not be sent")
		}
	}

	// Initialize health check service (M48)
	var healthCheckService *service.HealthCheckService
	var healthCheckHandler *handler.HealthCheckHandler
	if cfg.HealthCheck.Enabled {
		healthCheckRepo := postgres.NewHealthCheckRepository(db)
		healthCheckService = service.NewHealthCheckService(
			healthCheckRepo,
			auditService,
			logger,
			cfg.HealthCheck.MaxConcurrent,
			time.Duration(cfg.HealthCheck.DefaultTimeout)*time.Millisecond,
			cfg.HealthCheck.HistoryRetention,
			cfg.HealthCheck.AutoCreate,
		)
		healthCheckHandler = handler.NewHealthCheckHandler(healthCheckService)
		logger.Info("health check service enabled",
			"interval", cfg.HealthCheck.CheckInterval.String(),
			"max_concurrent", cfg.HealthCheck.MaxConcurrent)
	} else {
		// Create a no-op health check handler for route registration
		healthCheckHandler = handler.NewHealthCheckHandler(nil)
	}

	logger.Info("initialized all handlers")

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize scheduler
	sched := scheduler.NewScheduler(
		renewalService,
		jobService,
		agentService,
		notificationService,
		networkScanService,
		logger,
	)

	// Configure scheduler intervals from config
	sched.SetRenewalCheckInterval(cfg.Scheduler.RenewalCheckInterval)
	sched.SetJobProcessorInterval(cfg.Scheduler.JobProcessorInterval)
	// I-001: drive the failed-job retry loop. Runs on start + every RetryInterval
	// (default 5m, CERTCTL_SCHEDULER_RETRY_INTERVAL). Kept adjacent to the job
	// processor setter because they share the JobServicer dependency.
	sched.SetJobRetryInterval(cfg.Scheduler.RetryInterval)
	sched.SetAgentHealthCheckInterval(cfg.Scheduler.AgentHealthCheckInterval)
	sched.SetNotificationProcessInterval(cfg.Scheduler.NotificationProcessInterval)
	// I-005: drive the failed-notification retry sweep. Runs every
	// NotificationRetryInterval (default 2m, CERTCTL_NOTIFICATION_RETRY_INTERVAL)
	// and transitions eligible Failed notifications whose next_retry_at has
	// arrived back to Pending so the notification processor picks them up on
	// its next tick. Kept adjacent to the notification processor setter
	// because they share the NotificationServicer dependency (same placement
	// pattern as I-001's SetJobRetryInterval above).
	sched.SetNotificationRetryInterval(cfg.Scheduler.NotificationRetryInterval)
	// C-1 closure (cat-g-7e38f9708e20 + diff-10xmain-2bf4a0a60388): pre-C-1
	// the SetShortLivedExpiryCheckInterval setter was defined + tested but
	// never called from main.go, so the 30-second hardcoded default in
	// scheduler.NewScheduler was effectively the only value. Operators
	// running short-lived cert workloads with high churn (or low-churn
	// workloads wanting to relax the cadence) had no working knob despite
	// CERTCTL_SHORT_LIVED_EXPIRY_CHECK_INTERVAL being documented. Wire it
	// here alongside the other scheduler-interval setters so the
	// documented env var actually takes effect.
	sched.SetShortLivedExpiryCheckInterval(cfg.Scheduler.ShortLivedExpiryCheckInterval)

	// CRL/OCSP-Responder Phase 3: drive the crlGenerationLoop. The cache
	// service walks every issuer in the registry, regenerates the CRL,
	// and persists into crl_cache. The HTTP /.well-known/pki/crl/ handler
	// reads from the cache via certificateService.GenerateDERCRL (which
	// consults crlCacheService when wired). The loop is gated on the
	// service being non-nil, mirroring how digestService and others are
	// wired conditionally below.
	sched.SetCRLCacheService(crlCacheService)
	sched.SetCRLGenerationInterval(cfg.Scheduler.CRLGenerationInterval)
	logger.Info("CRL pre-generation scheduler enabled",
		"interval", cfg.Scheduler.CRLGenerationInterval.String())

	if cfg.NetworkScan.Enabled {
		sched.SetNetworkScanInterval(cfg.NetworkScan.ScanInterval)
		logger.Info("network scanning enabled", "interval", cfg.NetworkScan.ScanInterval.String())
	}
	if digestService != nil {
		sched.SetDigestService(digestService)
		sched.SetDigestInterval(cfg.Digest.Interval)
		logger.Info("digest scheduler enabled", "interval", cfg.Digest.Interval.String())
	}
	if healthCheckService != nil {
		sched.SetHealthCheckService(healthCheckService)
		sched.SetHealthCheckInterval(cfg.HealthCheck.CheckInterval)
		logger.Info("health check scheduler enabled", "interval", cfg.HealthCheck.CheckInterval.String())
	}
	if cloudDiscoveryService != nil && cloudDiscoveryService.SourceCount() > 0 {
		sched.SetCloudDiscoveryService(cloudDiscoveryService)
		sched.SetCloudDiscoveryInterval(cfg.CloudDiscovery.Interval)
		logger.Info("cloud discovery scheduler enabled",
			"interval", cfg.CloudDiscovery.Interval.String(),
			"sources", cloudDiscoveryService.SourceCount())
	}

	// Wire job timeout reaper (I-003)
	sched.SetJobReaperService(jobService)
	sched.SetJobTimeoutInterval(cfg.Scheduler.JobTimeoutInterval)
	sched.SetAwaitingCSRTimeout(cfg.Scheduler.AwaitingCSRTimeout)
	sched.SetAwaitingApprovalTimeout(cfg.Scheduler.AwaitingApprovalTimeout)

	// Auth Bundle 2 Phase 4 — wire the session-GC sweep. The service
	// itself was constructed (with the EnsureInitialSigningKey fail-
	// fatal call) above the policy/cert-service block; here we just
	// register it with the scheduler so the loop fires every
	// CERTCTL_SESSION_GC_INTERVAL.
	sched.SetSessionGarbageCollector(sessionService)
	sched.SetBCLReplayGarbageCollector(bclReplayRepo) // Audit 2026-05-10 HIGH-3.
	sched.SetSessionGCInterval(cfg.Auth.Session.GCInterval)

	// Phase 13 Sprint 13.3 closure (ARCH-M1): when the operator selected
	// CERTCTL_RATE_LIMIT_BACKEND=postgres, wire the bucket janitor so
	// stale rows from rate_limit_buckets get swept on the configured
	// interval. The in-memory backend's prune-on-Allow path keeps
	// buckets short-lived without a separate sweep, so we skip the
	// loop entirely for backend=memory.
	//
	// maxWindow = 24h: the EST per-principal limiter is the longest
	// window any current caller configures (the breakglass / OCSP /
	// export / EST failed-basic limiters use shorter windows). Bump
	// this if a new caller introduces a longer window — rows pruned
	// inside their window aren't deletable.
	if cfg.RateLimit.SlidingWindowBackend == "postgres" {
		rateLimitGC := ratelimit.NewPostgresGC(db, 24*time.Hour)
		sched.SetRateLimitGarbageCollector(rateLimitGC)
		sched.SetRateLimitGCInterval(cfg.RateLimit.SlidingWindowJanitorInterval)
		logger.Info("rate-limit GC sweep enabled (postgres backend)",
			"interval", cfg.RateLimit.SlidingWindowJanitorInterval.String(),
			"max_window", "24h")
	} else {
		logger.Info("rate-limit backend = memory; postgres GC sweep not wired (in-memory backend self-prunes)")
	}
	logger.Info("session GC sweep enabled",
		"interval", cfg.Auth.Session.GCInterval.String(),
		"absolute_timeout", cfg.Auth.Session.AbsoluteTimeout.String(),
		"signing_key_retention", cfg.Auth.Session.SigningKeyRetention.String())
	logger.Info("job timeout reaper enabled",
		"interval", cfg.Scheduler.JobTimeoutInterval.String(),
		"csr_timeout", cfg.Scheduler.AwaitingCSRTimeout.String(),
		"approval_timeout", cfg.Scheduler.AwaitingApprovalTimeout.String())

	// Start scheduler
	logger.Info("starting scheduler")
	startedChan := sched.Start(ctx)
	<-startedChan
	logger.Info("scheduler started")

	// SCEP RFC 8894 + Intune master bundle Phase 9: per-profile SCEPService
	// map shared between the SCEP startup loop (which populates it) and the
	// AdminSCEPIntune handler (which reads from it). We declare it here so
	// the HandlerRegistry below can hand the same map to the admin
	// handler — the SCEP loop adds entries later by reference, and the
	// admin endpoint observes the populated state at request time.
	scepServices := map[string]*service.SCEPService{}

	// EST RFC 7030 hardening master bundle Phase 7.2: same shape for
	// the EST admin endpoint. The EST startup loop populates this map
	// by PathID; the AdminEST handler reads it at request time.
	estServices := map[string]*service.ESTService{}

	// ACME server (RFC 8555 + RFC 9773 ARI). Phase 1a wired the
	// directory + new-nonce surface against acmeRepo + profileRepo;
	// Phase 1b adds the JWS-authenticated POST surface (new-account +
	// account/<id>), which requires the transactor + audit service
	// for per-op atomic-audit rows. SetTransactor mirrors the
	// CertificateService.SetTransactor wiring at line 254 — same
	// transactor instance shared across services.
	acmeService := service.NewACMEService(acmeRepo, profileRepo, cfg.ACMEServer)
	acmeService.SetTransactor(transactor)
	acmeService.SetAuditService(auditService)
	// Phase 2 — finalize plumbing. The finalize handler routes
	// through CertificateService.Create + certRepo.CreateVersionWithTx
	// + IssuerRegistry.Get for the bound profile's issuer. Same
	// pipeline EST/SCEP/agent/renewal use, so policy + audit + per-
	// issuer-type metrics apply uniformly to ACME-issued certs.
	acmeService.SetIssuancePipeline(certificateService, certificateRepo, issuerRegistry)
	// Phase 3 — challenge validator pool. The 3 per-type semaphores
	// (HTTP-01 / DNS-01 / TLS-ALPN-01) bound concurrent validations
	// so a flood of pending authorizations can't fan out unboundedly.
	// Defaults: 10 weight per type, 30s per-challenge timeout,
	// 8.8.8.8:53 DNS resolver. Operators tune via
	// CERTCTL_ACME_SERVER_*_CONCURRENCY + DNS01_RESOLVER.
	acmeValidatorPool := acmepkg.NewPool(acmepkg.PoolConfig{
		HTTP01Weight:    int64(cfg.ACMEServer.HTTP01ConcurrencyMax),
		DNS01Weight:     int64(cfg.ACMEServer.DNS01ConcurrencyMax),
		TLSALPN01Weight: int64(cfg.ACMEServer.TLSALPN01ConcurrencyMax),
		DNS01Resolver:   cfg.ACMEServer.DNS01Resolver,
	})
	acmeService.SetValidatorPool(acmeValidatorPool)
	// Phase 4 — revocation pipeline + renewal-policy lookup. The same
	// revocationSvc instance shared across the rest of the platform
	// covers ACME revoke-cert; the renewalPolicyRepo backs ARI window
	// math (when present, ComputeRenewalWindow uses RenewalWindowDays;
	// when absent, falls back to last-33%-of-validity).
	acmeService.SetRevocationDelegate(revocationSvc)
	acmeService.SetRenewalPolicyLookup(renewalPolicyRepo)
	// Phase 5 — per-account rate limiter. In-memory token-buckets,
	// shared across all entry points (CreateOrder / RotateAccountKey /
	// RespondToChallenge). Restart wipes counters; orders/hour caps are
	// eventual-consistency anyway. Persistent rate limiting is a
	// follow-up if production telemetry shows abuse patterns we can't
	// catch in a single restart cycle.
	acmeRateLimiter := acmepkg.NewRateLimiter()
	acmeService.SetRateLimiter(acmeRateLimiter)
	// Phase 5 — ACME GC sweeper. Disabled when GCInterval <= 0; the
	// scheduler.SetACMEGarbageCollector(nil) leg short-circuits in
	// scheduler.Start (the loopCount + go-routine launch are gated on
	// non-nil acmeGC). Wired here (not earlier with the other scheduler
	// loops) because the GC service needs a fully-constructed acmeService.
	if cfg.ACMEServer.Enabled && cfg.ACMEServer.GCInterval > 0 {
		sched.SetACMEGarbageCollector(acmeService)
		sched.SetACMEGCInterval(cfg.ACMEServer.GCInterval)
		logger.Info("ACME GC scheduler enabled",
			"interval", cfg.ACMEServer.GCInterval.String())
	}
	acmeHandler := handler.NewACMEHandler(acmeService)

	// Build the API router with all handlers
	apiRouter := router.New()
	apiRouter.RegisterHandlers(router.HandlerRegistry{
		Certificates:     certificateHandler,
		Issuers:          issuerHandler,
		Targets:          targetHandler,
		Agents:           agentHandler,
		Jobs:             jobHandler,
		Policies:         policyHandler,
		RenewalPolicies:  renewalPolicyHandler,
		Profiles:         profileHandler,
		Teams:            teamHandler,
		Owners:           ownerHandler,
		AgentGroups:      agentGroupHandler,
		Audit:            auditHandler,
		Notifications:    notificationHandler,
		Stats:            statsHandler,
		Metrics:          metricsHandler,
		Health:           healthHandler,
		Discovery:        discoveryHandler,
		NetworkScan:      networkScanHandler,
		Verification:     verificationHandler,
		Export:           exportHandler,
		Digest:           *digestHandler,
		HealthChecks:     healthCheckHandler,
		BulkRevocation:   bulkRevocationHandler,
		BulkRenewal:      bulkRenewalHandler,
		BulkReassignment: bulkReassignmentHandler,
		Version:          versionHandler,
		// CRL/OCSP-Responder Phase 5: admin observability endpoint
		// for the scheduler-driven CRL pre-generation cache.
		AdminCRLCache: handler.NewAdminCRLCacheHandler(
			handler.NewAdminCRLCacheServiceImpl(crlCacheRepo, func() []string {
				ids := make([]string, 0, issuerRegistry.Len())
				for id := range issuerRegistry.List() {
					ids = append(ids, id)
				}
				return ids
			}),
		),
		// SCEP RFC 8894 + Intune master bundle Phase 9.2: admin endpoint
		// for the per-profile Intune Monitoring tab. The implementation
		// holds a reference to scepServices declared above; the SCEP
		// startup loop populates the map by PathID during boot, so the
		// handler observes whatever profiles exist at request time. On a
		// deploy without SCEP enabled the map stays empty and the GET
		// stats endpoint returns an empty profiles array.
		AdminSCEPIntune: handler.NewAdminSCEPIntuneHandler(
			handler.NewAdminSCEPIntuneServiceImpl(scepServices),
		),
		// EST RFC 7030 hardening Phase 7.2: admin endpoint backing the
		// EST Administration GUI. Same shape as AdminSCEPIntune.
		AdminEST: handler.NewAdminESTHandler(
			handler.NewAdminESTServiceImpl(estServices),
		),
		// ACME server (RFC 8555 + RFC 9773 ARI) — Phase 1a foundation.
		// Phase 1a wires directory + new-nonce; subsequent phases extend
		// with the JWS-authenticated POST surface (new-account,
		// new-order, finalize, challenges, revoke, ARI). See
		// docs/acme-server.md for the operator-facing reference.
		ACME: acmeHandler,
		// Approvals — issuance approval-workflow primitive. Rank 7 of
		// the 2026-05-03 Infisical deep-research deliverable. See
		// docs/approval-workflow.md.
		Approvals: approvalHandler,
		// IntermediateCAs — first-class CA hierarchy management.
		// Rank 8 of the 2026-05-03 deep-research deliverable. See
		// docs/intermediate-ca-hierarchy.md.
		IntermediateCAs: intermediateCAHandler,
		// AuthSessionOIDC — Auth Bundle 2 Phase 5 OIDC + session HTTP
		// surface. 13 endpoints across login flow + session management
		// + OIDC provider CRUD + group-mapping CRUD.
		AuthSessionOIDC: authSessionOIDCHandler,

		// AuthBreakglass — Auth Bundle 2 Phase 7.5 break-glass admin
		// HTTP surface. 4 endpoints (1 public login + 3 admin CRUD).
		// All endpoints return 404 when CERTCTL_BREAKGLASS_ENABLED=false.
		AuthBreakglass: breakglassHandler,

		// Audit 2026-05-10 MED-11 — federated-user admin surface.
		AuthUsers: handler.NewAuthUsersHandler(
			oidcUserRepo,
			sessionService, // satisfies UserSessionsRevoker via RevokeAllForActor
			auditService,
			authdomainAlias.DefaultTenantID,
		),

		// Audit 2026-05-10 MED-12 — runtime config read endpoint.
		AuthRuntimeConfig: handler.NewAuthRuntimeConfigHandler(
			func() map[string]string {
				// Lazy build — re-read cfg.Auth.* values on every call so
				// post-startup re-evaluation reflects any (future) mutation.
				return map[string]string{
					"CERTCTL_AUTH_TYPE":                    string(cfg.Auth.Type),
					"CERTCTL_SESSION_SAMESITE":             cfg.Auth.Session.SameSite,
					"CERTCTL_OIDC_BCL_MAX_AGE_SECONDS":     strconv.Itoa(cfg.Auth.OIDCBCLMaxAgeSeconds),
					"CERTCTL_OIDC_PRELOGIN_REQUIRE_UA":     strconv.FormatBool(cfg.Auth.OIDCPreLoginRequireUA),
					"CERTCTL_OIDC_PRELOGIN_REQUIRE_IP":     strconv.FormatBool(cfg.Auth.OIDCPreLoginRequireIP),
					"CERTCTL_BREAKGLASS_ENABLED":           strconv.FormatBool(cfg.Auth.Breakglass.Enabled),
					"CERTCTL_BREAKGLASS_LOCKOUT_THRESHOLD": strconv.Itoa(cfg.Auth.Breakglass.LockoutThreshold),
					"CERTCTL_DEMO_MODE_ACK":                strconv.FormatBool(cfg.Auth.DemoModeAck),
					"CERTCTL_TRUSTED_PROXIES_COUNT":        strconv.Itoa(len(cfg.Auth.TrustedProxies)),
					"CERTCTL_BOOTSTRAP_TOKEN_SET":          strconv.FormatBool(cfg.Auth.BootstrapToken != ""),
					"CERTCTL_BOOTSTRAP_OIDC_PROVIDER_ID":   cfg.Auth.BootstrapOIDCProviderID,
					"CERTCTL_BOOTSTRAP_ADMIN_GROUPS_COUNT": strconv.Itoa(len(cfg.Auth.BootstrapAdminGroups)),
				}
			},
			auditService,
		),

		// Audit 2026-05-10 MED-7 — per-provider JWKS health surface.
		AuthOIDCJWKSStatus: handler.NewAuthOIDCJWKSStatusHandler(oidcService, auditService),
		// Auth — RBAC primitive (Bundle 1 Phase 4). Wires the postgres
		// auth repos + service-layer Authorizer / RoleService /
		// ActorRoleService / PermissionService into the HTTP surface
		// under /api/v1/auth/*. The service layer enforces every
		// permission gate (auth.role.* + auth.role.assign privilege-
		// escalation guard); the Phase 3 RequirePermission middleware
		// is currently used by these RBAC routes via the in-handler
		// callerFromRequest path. Phase 3.5 router-wrapping conversion
		// of the legacy admin handlers (bulk_revocation, admin_*,
		// intermediate_ca) is the remaining sweep.
		Auth: handler.NewAuthHandler(
			authsvc.NewRoleService(authRoleRepo, authPermRepo, authAuthorizer, auditService),
			authsvc.NewPermissionService(authPermRepo),
			authsvc.NewActorRoleService(authActorRoleRepo, authRoleRepo, authAuthorizer, auditService),
			authCheckerAdapter,
		).WithCSRFRotator(sessionService), // Audit 2026-05-10 HIGH-2 — CSRF rotation on role mutation.
		// Bundle 1 Phase 6 — bootstrap day-0 admin endpoint. The
		// service is wired above; handler is auth-exempt at the
		// router (gated by the bootstrap.Strategy itself).
		Bootstrap: bootstrapHandler,
		// Audit 2026-05-11 A-8 closure — demo-mode residual cleanup.
		// The cleanup closure captures the live *sql.DB pool so the
		// handler doesn't pull repository.* / database/sql into the
		// internal/api/handler import set. authType is a closure over
		// cfg so the live config value is always read at request time.
		DemoResidual: handler.NewDemoResidualHandler(
			func(ctx context.Context) (int64, error) { return deleteDemoAnonResidue(ctx, db) },
			func() string { return cfg.Auth.Type },
			auditService,
		),
		// Checker is the load-bearing auth.PermissionChecker that
		// auth.RequirePermission middleware uses to gate the legacy admin
		// handlers (Bundle 1 Phase 3.5: bulk_revocation, admin_crl_cache,
		// admin_scep_intune, admin_est, intermediate_ca). Wraps live in
		// router.go via rbacGate(reg.Checker, perm, handler).
		Checker: authCheckerAdapter,
		// Audit 2026-05-10 CRIT-3 closure — operator-configured CORS
		// applied to the credentialed auth-exempt routes (OIDC handshake,
		// BCL, logout, bootstrap, breakglass-login). Health probes
		// continue to use middleware.CORSWildcard.
		CorsCfg: middleware.CORSConfig{AllowedOrigins: cfg.CORS.AllowedOrigins},
	})
	// Register EST (RFC 7030) handlers if enabled.
	//
	// EST RFC 7030 hardening master bundle Phase 1: multi-profile dispatch.
	// Config.Validate() guarantees cfg.EST.Profiles is non-empty when
	// cfg.EST.Enabled is true (the legacy single-issuer flat fields are
	// merged into Profiles[0] by mergeESTLegacyIntoProfiles in Load()).
	// Each profile gets its own service + handler instance, registered at
	// /.well-known/est/ (PathID="") or /.well-known/est/<PathID>/.
	//
	// Per-profile preflight gates (issuer reachable, CA serves cacerts)
	// run inside the loop. Failures log the offending PathID so a
	// multi-profile deploy can pinpoint which profile broke startup —
	// mirrors the SCEP audit-closure pattern (cmd/server/main.go::
	// preflightSCEPIntuneTrustAnchor signature took pathID for exactly
	// this reason).
	// EST RFC 7030 hardening master bundle Phase 2 + SCEP RFC 8894 +
	// Intune master bundle Phase 6.5 SHARED union pool: every protocol's
	// mTLS profiles contribute their trust certs here so a single TLS
	// listener accepts client certs from EITHER protocol's profiles, and
	// the per-handler gate re-verifies that the cert chains to THIS
	// profile's bundle. Allocated lazily by whichever protocol first
	// opts in (left nil when no profile opted in across both protocols
	// — buildServerTLSConfigWithMTLS treats nil as 'no mTLS').
	var mtlsUnionPoolForTLS *x509.CertPool
	// estMTLSStopWatchers collects every per-profile trust-anchor
	// SIGHUP-watcher stop func so we can shut them down on server exit
	// (mirrors intuneStopWatchers below).
	var estMTLSStopWatchers []func()

	if cfg.EST.Enabled {
		estHandlers := make(map[string]handler.ESTHandler, len(cfg.EST.Profiles))
		estMTLSHandlers := make(map[string]handler.ESTHandler)
		estMTLSAnyEnabled := false
		for i, profile := range cfg.EST.Profiles {
			profile := profile // shadow for closure-safety
			profileLog := logger.With(
				"est_profile_index", i,
				"est_profile_pathid", profile.PathID,
				"est_profile_issuer", profile.IssuerID,
			)

			issuerConn, ok := issuerRegistry.Get(profile.IssuerID)
			if !ok {
				profileLog.Error("startup refused: EST profile issuer not found in registry",
					"hint", "EST profile must reference a configured issuer ID; check CERTCTL_ISSUERS_ENABLED + the issuer factory")
				os.Exit(1)
			}
			// Bundle-4 / L-005: validate the issuer can actually serve a CA certificate
			// at startup, not at first request time. ACME / DigiCert / Sectigo etc.
			// return an error from GetCACertPEM because they don't expose a static
			// CA chain; binding EST to one of those would silently degrade enrollment.
			preflightCtx, preflightCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := preflightEnrollmentIssuer(preflightCtx, "EST", profile.IssuerID, issuerConn); err != nil {
				preflightCancel()
				profileLog.Error("startup refused: EST profile issuer cannot serve CA certificate", "error", err)
				os.Exit(1)
			}
			preflightCancel()

			estService := service.NewESTService(profile.IssuerID, issuerConn, auditService, profileLog)
			estService.SetProfileRepo(profileRepo)
			if profile.ProfileID != "" {
				estService.SetProfileID(profile.ProfileID)
			}
			estHandler := handler.NewESTHandler(estService)
			estHandler.SetLabelForLog(fmt.Sprintf("est (PathID=%q)", profile.PathID))
			// Phase 5: server-keygen endpoint per profile. The per-profile gate
			// stays off by default so existing v2.X.0 deploys see no behavior
			// change unless the operator explicitly opts in via
			// CERTCTL_EST_PROFILE_<NAME>_SERVER_KEYGEN_ENABLED=true.
			estHandler.SetServerKeygenEnabled(profile.ServerKeygenEnabled)

			// Phase 3.1: HTTP Basic enrollment password. Only takes effect
			// on the standard /.well-known/est/<PathID>/ route — the mTLS
			// sibling skips it because the client cert IS the auth signal.
			if profile.EnrollmentPassword != "" {
				estHandler.SetEnrollmentPassword(profile.EnrollmentPassword)
				// Phase 3.3: per-source-IP failed-auth rate limit.
				// Defaults: 10 failed attempts / 1 hour / 50k tracked IPs.
				// Hard-coded for now (no env var); a tuning bundle can lift
				// these once we've watched real production deploys for a
				// release. The shared SlidingWindowLimiter applies the same
				// math the SCEP/Intune limiter uses — extracted in Phase 4.1
				// of this bundle so both call sites share the implementation.
				failed := ratelimit.NewLimiter(cfg.RateLimit.SlidingWindowBackend, db, 10, time.Hour, 50_000)
				estHandler.SetSourceIPRateLimiter(failed)
			}
			// Phase 2.1: mTLS sibling route. When MTLSEnabled=true, build a
			// per-profile SIGHUP-reloadable trust-anchor holder, splice the
			// bundle's certs into the EST mTLS union pool, and clone the
			// handler with the per-profile trust + channel-binding policy
			// so SimpleEnrollMTLS / SimpleReEnrollMTLS verify against just
			// THIS profile's bundle.
			if profile.MTLSEnabled {
				holder, err := preflightESTMTLSClientCATrustBundle(true, profile.PathID, profile.MTLSClientCATrustBundlePath, profileLog)
				if err != nil {
					profileLog.Error(
						"startup refused: EST profile MTLS trust bundle preflight failed "+
							"(EST hardening Phase 2: required when MTLS_ENABLED=true). "+
							"Verify the bundle file exists at MTLS_CLIENT_CA_TRUST_BUNDLE_PATH, "+
							"is readable, parses as PEM, contains ≥1 CERTIFICATE block, "+
							"and none of the bundled certs are past NotAfter.",
						"error", err,
					)
					os.Exit(1)
				}
				// Merge this profile's certs into the union pool the TLS
				// layer uses for VerifyClientCertIfGiven. Walk the bundle
				// directly so the union pool gets exactly the same certs
				// as the per-profile pool (mirrors SCEP's pattern at the
				// equivalent loop iteration).
				if mtlsUnionPoolForTLS == nil {
					mtlsUnionPoolForTLS = x509.NewCertPool()
				}
				bundleBytes, _ := os.ReadFile(profile.MTLSClientCATrustBundlePath)
				rest := bundleBytes
				for {
					var block *pem.Block
					block, rest = pem.Decode(rest)
					if block == nil {
						break
					}
					if block.Type != "CERTIFICATE" {
						continue
					}
					if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
						mtlsUnionPoolForTLS.AddCert(cert)
					}
				}
				estMTLSAnyEnabled = true

				// Build the mTLS sibling-route handler with the per-profile
				// trust pool, channel-binding policy, and (if configured)
				// per-principal rate limiter.
				mtlsHandler := handler.NewESTHandler(estService)
				mtlsHandler.SetLabelForLog(fmt.Sprintf("est-mtls (PathID=%q)", profile.PathID))
				mtlsHandler.SetMTLSTrust(holder)
				mtlsHandler.SetChannelBindingRequired(profile.ChannelBindingRequired)
				mtlsHandler.SetServerKeygenEnabled(profile.ServerKeygenEnabled)
				if profile.RateLimitPerPrincipal24h > 0 {
					perPrincipal := ratelimit.NewLimiter(cfg.RateLimit.SlidingWindowBackend, db, profile.RateLimitPerPrincipal24h, 24*time.Hour, 100_000)
					mtlsHandler.SetPerPrincipalRateLimiter(perPrincipal)
				}
				estMTLSHandlers[profile.PathID] = mtlsHandler

				// Install the SIGHUP watcher so an operator that rotates
				// the mTLS trust bundle file gets the new pool live without
				// a server restart. Watcher stop func is collected for
				// orderly shutdown via the defer below.
				estMTLSStopWatchers = append(estMTLSStopWatchers, holder.WatchSIGHUP())

				profileLog.Info("EST mTLS sibling route enabled",
					"endpoint", "/.well-known/est-mtls/"+profile.PathID,
					"client_ca_trust_bundle", profile.MTLSClientCATrustBundlePath,
					"channel_binding_required", profile.ChannelBindingRequired,
				)
			}
			// Phase 4.2: per-principal rate limiter on the standard route
			// too (additive — both routes share the same per-(CN, IP) cap
			// when configured). The mTLS handler above gets its own
			// limiter instance so the two routes don't share a bucket.
			if profile.RateLimitPerPrincipal24h > 0 {
				perPrincipal := ratelimit.NewLimiter(cfg.RateLimit.SlidingWindowBackend, db, profile.RateLimitPerPrincipal24h, 24*time.Hour, 100_000)
				estHandler.SetPerPrincipalRateLimiter(perPrincipal)
			}
			estHandlers[profile.PathID] = estHandler

			// Phase 7.2: publish service into the shared estServices map +
			// wire the per-profile observability metadata so the AdminEST
			// handler can render the Profiles tab. This MUST happen after
			// every per-profile setter so Stats() snapshot reads stable
			// state.
			//
			// trustHolderForAdmin: the EST mTLS branch above declares a
			// local `holder` variable when MTLSEnabled=true. We rebuild
			// the lookup here so the metadata setter sees the same
			// holder. Non-mTLS profiles see nil — Stats() handles that.
			var trustHolderForAdmin *trustanchor.Holder
			if profile.MTLSEnabled && estMTLSHandlers[profile.PathID].HasMTLSTrust() {
				trustHolderForAdmin = estMTLSHandlers[profile.PathID].MTLSTrust()
			}
			estService.SetESTAdminMetadata(profile.PathID, profile.MTLSEnabled,
				profile.EnrollmentPassword != "", profile.ServerKeygenEnabled,
				trustHolderForAdmin)
			estServices[profile.PathID] = estService

			endpoint := "/.well-known/est"
			if profile.PathID != "" {
				endpoint = "/.well-known/est/" + profile.PathID
			}
			profileLog.Info("EST profile enabled",
				"endpoints", endpoint+"/{cacerts,simpleenroll,simplereenroll,csrattrs}",
				"server_keygen_enabled", profile.ServerKeygenEnabled,
				"mtls_enabled", profile.MTLSEnabled,
				"basic_auth_configured", profile.EnrollmentPassword != "",
				"allowed_auth_modes", profile.AllowedAuthModes,
				"rate_limit_per_principal_24h", profile.RateLimitPerPrincipal24h,
			)
		}
		apiRouter.RegisterESTHandlers(estHandlers)
		if estMTLSAnyEnabled {
			apiRouter.RegisterESTMTLSHandlers(estMTLSHandlers)
			logger.Info("EST mTLS sibling route enabled (Phase 2)",
				"mtls_profile_count", len(estMTLSHandlers),
			)
		}
		logger.Info("EST server enabled",
			"profile_count", len(cfg.EST.Profiles),
			"mtls_profile_count", len(estMTLSHandlers),
		)
		// Stop SIGHUP watchers in LIFO on server shutdown.
		if len(estMTLSStopWatchers) > 0 {
			defer func() {
				for _, stop := range estMTLSStopWatchers {
					stop()
				}
			}()
		}
	}

	// SCEP RFC 8894 Phase 6.5: union pool of every enabled mTLS profile's
	// EST RFC 7030 hardening master bundle Phase 2: SCEP's mTLS union pool
	// merged into the SHARED mtlsUnionPoolForTLS variable declared above.
	// Variables here intentionally renamed to make the merge explicit.

	// Register SCEP (RFC 8894) handlers if enabled.
	//
	// SCEP RFC 8894 Phase 1.5: multi-profile dispatch. Config.Validate()
	// guarantees cfg.SCEP.Profiles is non-empty when cfg.SCEP.Enabled is true
	// (the legacy single-profile flat fields are merged into Profiles[0] by
	// the backward-compat shim in Load()). Each profile gets its own service
	// + handler instance, registered at /scep (PathID="") or /scep/<PathID>.
	if cfg.SCEP.Enabled {
		// Iterate the profiles and build a {pathID -> handler} map for the
		// router. Each profile triggers the same per-profile preflight gates
		// (challenge password presence, RA pair validity, issuer reachability).
		// Failures log the offending PathID so a multi-profile deploy can
		// pinpoint which profile broke startup.
		//
		// SCEP RFC 8894 + Intune master bundle Phase 6.5: profiles that
		// opt into mTLS via CERTCTL_SCEP_PROFILE_<NAME>_MTLS_ENABLED=true
		// get a parallel sibling-route handler registered at /scep-mtls/
		// <pathID>. The per-profile trust pool gates the inbound client
		// cert chain (verified at the TLS layer against the union pool +
		// re-verified at the handler layer against just THIS profile's
		// bundle to prevent cross-profile bleed-through).
		scepHandlers := make(map[string]handler.SCEPHandler, len(cfg.SCEP.Profiles))
		scepMTLSHandlers := make(map[string]handler.SCEPHandler)
		scepMTLSAnyEnabled := false
		// SCEP RFC 8894 + Intune master bundle Phase 8: per-profile Intune
		// trust anchor holders. We track them here so a single SIGHUP
		// reload-watcher set spans every profile, AND so the deferred
		// stop-watcher cleanup runs once at server shutdown.
		intuneTrustHolders := []*intune.TrustAnchorHolder{}
		intuneStopWatchers := []func(){}
		for i, profile := range cfg.SCEP.Profiles {
			profile := profile // shadow for closure-safety even though no closures escape
			profileLog := logger.With(
				"scep_profile_index", i,
				"scep_profile_pathid", profile.PathID,
				"scep_profile_issuer_id", profile.IssuerID,
			)
			// H-2 fix per profile: fail closed at startup when this profile has
			// no challenge password. preflightSCEPChallengePassword stays
			// unchanged; we just call it once per profile.
			if err := preflightSCEPChallengePassword(true, profile.ChallengePassword); err != nil {
				profileLog.Error(
					"startup refused: SCEP profile has empty challenge password "+
						"(would allow unauthenticated certificate enrollment, CWE-306). "+
						"Set CERTCTL_SCEP_PROFILE_<NAME>_CHALLENGE_PASSWORD or remove the profile.",
					"error", err,
				)
				os.Exit(1)
			}
			// SCEP RFC 8894 Phase 1: per-profile RA cert/key preflight. Same
			// six checks as the legacy single-profile path; reports the
			// offending PathID via the profile-scoped logger.
			if err := preflightSCEPRACertKey(true, profile.RACertPath, profile.RAKeyPath); err != nil {
				profileLog.Error(
					"startup refused: SCEP profile RA cert/key preflight failed "+
						"(RFC 8894 §3.2.2 EnvelopedData + §3.3.2 CertRep require a per-profile RA pair). "+
						"Generate the RA pair per docs/legacy-est-scep.md and set "+
						"CERTCTL_SCEP_PROFILE_<NAME>_RA_CERT_PATH + _RA_KEY_PATH for this profile.",
					"error", err,
				)
				os.Exit(1)
			}
			issuerConn, ok := issuerRegistry.Get(profile.IssuerID)
			if !ok {
				profileLog.Error("SCEP profile issuer not found in registry")
				os.Exit(1)
			}
			// Bundle-4 / L-005: validate the issuer can actually serve a CA
			// certificate. Per profile, in case different profiles bind
			// different issuers.
			preflightCtx, preflightCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := preflightEnrollmentIssuer(preflightCtx, "SCEP", profile.IssuerID, issuerConn); err != nil {
				preflightCancel()
				profileLog.Error("startup refused: SCEP profile issuer cannot serve CA certificate", "error", err)
				os.Exit(1)
			}
			preflightCancel()
			scepService := service.NewSCEPService(profile.IssuerID, issuerConn, auditService, profileLog, profile.ChallengePassword)
			scepService.SetProfileRepo(profileRepo)
			scepService.SetPathID(profile.PathID)
			// SCEP RFC 8894 + Intune master bundle Phase 9 follow-up:
			// surface mTLS sibling-route status in the per-profile snapshot
			// the new /admin/scep/profiles endpoint emits. The actual mTLS
			// trust pool wiring lives further down in the if profile.MTLSEnabled
			// block; this just records the flag + bundle path for observability.
			scepService.SetMTLSConfig(profile.MTLSEnabled, profile.MTLSClientCATrustBundlePath)
			if profile.ProfileID != "" {
				scepService.SetProfileID(profile.ProfileID)
			}
			// SCEP RFC 8894 + Intune master bundle Phase 9.3: publish this
			// service into the shared scepServices map so the AdminSCEPIntune
			// handler can find it by PathID. The map was declared above
			// HandlerRegistry construction; the admin handler holds the
			// same map by reference, so adding here makes the new profile
			// visible at the next admin GET.
			scepServices[profile.PathID] = scepService
			scepHandler := handler.NewSCEPHandler(scepService)
			// SCEP RFC 8894 Phase 2.3: load the per-profile RA pair so the
			// handler can run the new RFC 8894 PKIMessage path. Preflight
			// already validated the pair (file mode 0600 + cert/key match
			// + non-expired + RSA-or-ECDSA). Failure here is a deploy bug
			// the operator needs to know about — fail loud at startup.
			raCert, raKey, err := loadSCEPRAPair(profile.RACertPath, profile.RAKeyPath)
			if err != nil {
				profileLog.Error("startup refused: SCEP profile RA pair load failed despite preflight pass — likely a TOCTOU between preflight + here, or filesystem changed mid-boot", "error", err)
				os.Exit(1)
			}
			scepHandler.SetRAPair(raCert, raKey)
			// SCEP RFC 8894 + Intune master bundle Phase 9 follow-up:
			// surface RA cert metadata (subject + NotBefore + NotAfter) in
			// the per-profile snapshot so the new /admin/scep/profiles
			// endpoint can drive the GUI's RA expiry countdown badge.
			scepService.SetRACert(raCert)

			// SCEP RFC 8894 + Intune master bundle Phase 8: per-profile Intune
			// dispatcher wire-in. Builds the trust-anchor holder, replay cache,
			// and per-device rate limiter; injects them into the SCEPService;
			// starts the SIGHUP reload watcher (one per holder, all responding
			// to the same signal as the existing TLS-cert watcher). Profiles
			// with INTUNE_ENABLED=false skip the entire block, so the cost on
			// non-Intune deploys is exactly one bool check per profile.
			if profile.Intune.Enabled {
				intuneHolder, err := preflightSCEPIntuneTrustAnchor(true, profile.PathID, profile.Intune.ConnectorCertPath, profileLog)
				if err != nil {
					profileLog.Error(
						"startup refused: SCEP profile INTUNE trust anchor preflight failed "+
							"(Phase 8.2: required when INTUNE_ENABLED=true). "+
							"Verify the bundle file exists at INTUNE_CONNECTOR_CERT_PATH, "+
							"is readable, parses as PEM, contains ≥1 CERTIFICATE block, "+
							"and none of the bundled certs are past NotAfter (operator-rotated).",
						"error", err,
					)
					os.Exit(1)
				}
				intuneTrustHolders = append(intuneTrustHolders, intuneHolder)
				intuneStopWatchers = append(intuneStopWatchers, intuneHolder.WatchSIGHUP())

				// Replay cache TTL = ChallengeValidity (defaults to 60m via
				// config.go's getEnvDuration default). The cache is sized
				// for the documented 100k-entry production default; smaller
				// is fine, larger tightens the operator's escape hatch.
				replayCache := intune.NewReplayCache(profile.Intune.ChallengeValidity, 0)

				// Per-device rate limiter: honor the per-profile cap
				// (INTUNE_PER_DEVICE_RATE_LIMIT_24H, default 3). The cap can
				// be 0 to disable (limiter then short-circuits all Allow calls
				// to nil). Map cap stays at the 100k default.
				rateLimiter := intune.NewPerDeviceRateLimiter(
					profile.Intune.PerDeviceRateLimit24h,
					24*time.Hour,
					0,
				)

				scepService.SetIntuneIntegration(
					intuneHolder,
					profile.Intune.Audience,
					profile.Intune.ChallengeValidity,
					profile.Intune.ClockSkewTolerance,
					replayCache,
					rateLimiter,
				)
				profileLog.Info("SCEP profile Intune dispatcher enabled",
					"trust_anchor_path", profile.Intune.ConnectorCertPath,
					"audience", profile.Intune.Audience,
					"challenge_validity", profile.Intune.ChallengeValidity,
					"clock_skew_tolerance", profile.Intune.ClockSkewTolerance,
					"per_device_rate_limit_24h", profile.Intune.PerDeviceRateLimit24h,
				)
			}

			scepHandlers[profile.PathID] = scepHandler
			endpoint := "/scep"
			if profile.PathID != "" {
				endpoint = "/scep/" + profile.PathID
			}
			profileLog.Info("SCEP profile enabled",
				"endpoint", endpoint+"?operation={GetCACaps,GetCACert,PKIOperation}",
				"challenge_password_set", profile.ChallengePassword != "",
				"ra_cert_path", profile.RACertPath,
				"intune_enabled", profile.Intune.Enabled,
			)

			// SCEP RFC 8894 Phase 6.5: register the mTLS sibling route
			// when this profile opted in. Build a per-profile trust pool
			// from the bundle, share its certs into the union pool the
			// TLS layer uses, and clone the handler with the per-profile
			// pool injected so HandleSCEPMTLS can re-verify the inbound
			// client cert against just THIS profile's bundle.
			if profile.MTLSEnabled {
				perProfilePool, err := preflightSCEPMTLSTrustBundle(true, profile.MTLSClientCATrustBundlePath)
				if err != nil {
					profileLog.Error(
						"startup refused: SCEP profile MTLS trust bundle preflight failed "+
							"(Phase 6.5: required when MTLS_ENABLED=true). "+
							"Verify the bundle file exists at MTLS_CLIENT_CA_TRUST_BUNDLE_PATH, "+
							"is readable, parses as PEM, contains ≥1 CERTIFICATE block, "+
							"and none of the bundled certs are past NotAfter.",
						"error", err,
					)
					os.Exit(1)
				}
				// Add this profile's certs to the union pool the TLS
				// layer uses for VerifyClientCertIfGiven. We re-walk the
				// bundle so the union pool gets exactly the same certs
				// as the per-profile pool (defensive against future
				// pool-mutation refactors).
				bundleBytes, _ := os.ReadFile(profile.MTLSClientCATrustBundlePath)
				rest := bundleBytes
				for {
					var block *pem.Block
					block, rest = pem.Decode(rest)
					if block == nil {
						break
					}
					if block.Type != "CERTIFICATE" {
						continue
					}
					if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
						if mtlsUnionPoolForTLS == nil {
							mtlsUnionPoolForTLS = x509.NewCertPool()
						}
						mtlsUnionPoolForTLS.AddCert(cert)
					}
				}
				scepMTLSAnyEnabled = true

				// Build the parallel sibling-route handler. Same SCEP
				// service + RA pair as the standard route — mTLS is
				// additive, not a replacement.
				mtlsHandler := handler.NewSCEPHandler(scepService)
				mtlsHandler.SetRAPair(raCert, raKey)
				mtlsHandler.SetMTLSTrustPool(perProfilePool)
				scepMTLSHandlers[profile.PathID] = mtlsHandler

				mtlsEndpoint := "/scep-mtls"
				if profile.PathID != "" {
					mtlsEndpoint = "/scep-mtls/" + profile.PathID
				}
				profileLog.Info("SCEP mTLS sibling route enabled",
					"endpoint", mtlsEndpoint,
					"client_ca_trust_bundle", profile.MTLSClientCATrustBundlePath,
				)
			}
		}
		apiRouter.RegisterSCEPHandlers(scepHandlers)
		// SCEP RFC 8894 + Intune master bundle Phase 6.5: register the
		// /scep-mtls sibling routes when at least one profile opted in.
		// scepMTLSHandlers is non-empty only when scepMTLSAnyEnabled is
		// true (the per-profile branch only adds to the map when the
		// profile flag is set), but the explicit gate makes the
		// no-op-when-disabled case obvious in logs.
		if scepMTLSAnyEnabled {
			apiRouter.RegisterSCEPMTLSHandlers(scepMTLSHandlers)
			logger.Info("SCEP mTLS sibling route enabled (Phase 6.5)",
				"mtls_profile_count", len(scepMTLSHandlers),
			)
		}
		logger.Info("SCEP server enabled",
			"profile_count", len(scepHandlers),
			"mtls_profile_count", len(scepMTLSHandlers),
			"intune_profile_count", len(intuneTrustHolders),
		)

		// SCEP RFC 8894 + Intune master bundle Phase 8.5: clean up the
		// SIGHUP watcher goroutines when the server shuts down. We register
		// the stop functions on a deferred sweep so the cleanup runs in
		// LIFO order even if a downstream init step os.Exit(1)s.
		if len(intuneStopWatchers) > 0 {
			defer func() {
				for _, stop := range intuneStopWatchers {
					stop()
				}
			}()
		}
	}

	// Register RFC 5280 CRL and RFC 6960 OCSP handlers under /.well-known/pki/.
	// These are always enabled (no config gate) — revocation data must be
	// reachable to relying parties for any cert certctl issues. The finalHandler
	// routing gate below strips auth middleware for this prefix so browsers,
	// OpenSSL, OCSP stapling sidecars, and mTLS clients can fetch without
	// presenting certctl Bearer tokens.
	apiRouter.RegisterPKIHandlers(certificateHandler)
	logger.Info("PKI endpoints registered",
		"endpoints", "/.well-known/pki/{crl/{issuer_id},ocsp/{issuer_id}/{serial}}")

	logger.Info("registered all API handlers")

	// Build middleware stack.
	//
	// Bundle 1 Phase 6: namedKeys + authKeyStore + bootstrap service
	// are now constructed earlier (right after the auth repos) so the
	// HandlerRegistry can wire the bootstrap handler. The auth
	// middleware below reads from the same authKeyStore reference, so
	// runtime additions from bootstrap propagate without restart.
	var bearerMiddleware func(http.Handler) http.Handler
	switch config.AuthType(cfg.Auth.Type) {
	case config.AuthTypeNone:
		bearerMiddleware = auth.NewDemoModeAuth()
	default:
		bearerMiddleware = auth.NewAuthWithKeyStore(authKeyStore)
	}
	// Auth Bundle 2 Phase 6 — chained-auth middleware. Tries the
	// `certctl_session` cookie first (sessionMW); on miss / invalid,
	// falls back to the API-key Bearer middleware. If neither
	// authenticates, 401. The session middleware is a pass-through
	// when sessionService is nil (pre-Bundle-2 builds).
	sessionMW := session.NewSessionMiddleware(sessionService)
	authMiddleware := session.ChainAuthSessionThenBearer(sessionMW, bearerMiddleware)
	// CSRF middleware — gates state-changing methods (POST/PUT/DELETE/
	// PATCH) for session-authenticated requests. API-key actors are
	// CSRF-exempt (not browser-driven). Pass-through when
	// sessionService is nil.
	csrfMiddleware := session.NewCSRFMiddleware(sessionService)
	_ = bootstrapHandler // referenced by HandlerRegistry above
	corsMiddleware := middleware.NewCORS(middleware.CORSConfig{
		AllowedOrigins: cfg.CORS.AllowedOrigins,
	})

	structuredLogger := middleware.NewLogging(logger)

	// Request body size limit middleware — prevents memory exhaustion attacks (CWE-400)
	bodyLimitMiddleware := middleware.NewBodyLimit(middleware.BodyLimitConfig{
		MaxBytes: cfg.Server.MaxBodySize,
	})
	logger.Info("request body size limit enabled", "max_bytes", cfg.Server.MaxBodySize)

	// Security headers middleware — applies HSTS, X-Frame-Options,
	// X-Content-Type-Options, Referrer-Policy, and a conservative CSP
	// on every response. H-1 closure (cat-s11-missing_security_headers):
	// pre-H-1 the server emitted zero security headers; an attacker
	// could clickjack the dashboard, sniff MIME types on JSON/PEM
	// responses, or load resources from arbitrary origins via inline
	// scripts. Defaults are conservative — see internal/api/middleware/
	// securityheaders.go::SecurityHeadersDefaults() for the rationale
	// per header.
	securityHeadersMiddleware := middleware.SecurityHeaders(middleware.SecurityHeadersDefaults())

	// API audit log middleware — records every API call to the audit trail
	auditAdapter := middleware.NewAuditServiceAdapter(
		func(ctx context.Context, actor string, actorType string, action string, resourceType string, resourceID string, details map[string]interface{}) error {
			return auditService.RecordEvent(ctx, actor, domain.ActorType(actorType), action, resourceType, resourceID, details)
		},
	)
	auditMiddleware := middleware.NewAuditLog(auditAdapter, middleware.AuditConfig{
		// /api/v1/version is excluded for the same reason /health and /ready
		// are: rollout systems and blackbox probes hammer it on a tight
		// interval, and the audit trail's value comes from rare,
		// operator-authored mutations — not from sub-second readonly polls.
		// U-3 ride-along (cat-u-no_version_endpoint, P2).
		ExcludePaths: []string{"/health", "/ready", "/api/v1/version"},
		Logger:       logger,
	})
	logger.Info("API audit logging enabled (excluding /health, /ready, /api/v1/version)")

	middlewareStack := []func(http.Handler) http.Handler{
		middleware.RequestID,
		structuredLogger,
		middleware.Recovery,
		bodyLimitMiddleware,
		securityHeadersMiddleware,
		corsMiddleware,
		// Phase 6 chain: Auth (session-then-Bearer fallback) → CSRF
		// (state-changing only; API-key actors exempt) → Audit.
		authMiddleware,
		csrfMiddleware,
		auditMiddleware.Middleware,
	}

	// Add rate limiter if enabled
	if cfg.RateLimit.Enabled {
		// Bundle B / Audit M-025: per-user / per-IP keying. PerUser{RPS,Burst}
		// fall back to RPS / BurstSize when zero; see middleware.NewRateLimiter
		// for the bucket-creation contract.
		rateLimiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
			RPS:              cfg.RateLimit.RPS,
			BurstSize:        cfg.RateLimit.BurstSize,
			PerUserRPS:       cfg.RateLimit.PerUserRPS,
			PerUserBurstSize: cfg.RateLimit.PerUserBurstSize,
			// SEC-006 (Sprint 2): bounded bucket TTL so a long-running
			// server with high-cardinality unauthenticated traffic
			// (CGNAT churn, Tor exits, scanners) doesn't grow the map
			// indefinitely.
			BucketTTL: cfg.RateLimit.BucketTTL,
		})
		// SEC-003 closure (Sprint 1, 2026-05-16). Pre-fix the
		// rate-limit-enabled stack was rebuilt without
		// securityHeadersMiddleware, silently dropping HSTS,
		// X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
		// and Content-Security-Policy across every response when an
		// operator flipped CERTCTL_RATE_LIMIT_ENABLED=true — a
		// defensive-config toggle weakened browser-side security.
		// The fixed stack keeps securityHeadersMiddleware at the same
		// position as the default and inserts rateLimiter right after
		// so a 429 response still carries the same headers as a 200.
		middlewareStack = []func(http.Handler) http.Handler{
			middleware.RequestID,
			structuredLogger,
			middleware.Recovery,
			bodyLimitMiddleware,
			securityHeadersMiddleware,
			rateLimiter,
			corsMiddleware,
			// Phase 6 chain: Auth (session-then-Bearer fallback) → CSRF
			// (state-changing only; API-key actors exempt) → Audit.
			authMiddleware,
			csrfMiddleware,
			auditMiddleware.Middleware,
		}
		logger.Info("rate limiting enabled", "rps", cfg.RateLimit.RPS, "burst", cfg.RateLimit.BurstSize)
	}

	if config.AuthType(cfg.Auth.Type) == config.AuthTypeNone {
		logger.Warn("authentication disabled (CERTCTL_AUTH_TYPE=none) — not suitable for production except behind an authenticating gateway (oauth2-proxy / Envoy ext_authz / Traefik ForwardAuth / Pomerium)")
	} else {
		logger.Info("authentication enabled", "type", cfg.Auth.Type)
	}

	if cfg.Keygen.Mode == "server" {
		logger.Warn("server-side key generation enabled (CERTCTL_KEYGEN_MODE=server) — private keys touch control plane, demo only")
	} else {
		logger.Info("agent-side key generation enabled — private keys never leave agent infrastructure")
	}

	// Apply middleware to API router
	apiHandler := middleware.Chain(apiRouter, middlewareStack...)

	// Wrap with dashboard static file serving
	// Vite builds to web/dist/; fall back to web/ for legacy single-file SPA
	var finalHandler http.Handler
	webDir := "./web/dist"
	if _, err := os.Stat(webDir + "/index.html"); err != nil {
		webDir = "./web"
	}
	// Health/ready routes + EST/SCEP/PKI unauth surface bypass the full
	// middleware stack (no auth required). These are registered on the
	// inner router without auth, but the outer middleware chain wraps
	// everything. Route them directly to the inner router.
	//
	// H-1 closure (cat-s5-4936a1cf0118): pre-H-1 the noAuthHandler chain
	// was RequestID → structuredLogger → Recovery only — missing
	// bodyLimitMiddleware that the authed apiHandler chain has. The
	// unauth surface includes EST simpleenroll/simplereenroll (RFC 7030),
	// SCEP, PKI CRL/OCSP (/.well-known/pki/*), and /health|/ready —
	// every one of which accepts a request body. Without a body-size
	// cap, an unauthenticated client can send arbitrary-size payloads
	// (CSRs, CRL/OCSP requests) and trigger memory pressure on the
	// server before the handler ever rejects the input. Post-H-1 the
	// same bodyLimitMiddleware that wraps the authed surface also wraps
	// the unauth surface — same default cap (CERTCTL_MAX_BODY_SIZE,
	// default 1MB), same 413 response on overflow.
	//
	// Bundle C / Audit M-020 (CWE-770): rate limiter added to the noAuth
	// chain. Pre-bundle the unauth surface had NO rate limit — an attacker
	// could DoS the OCSP responder, which for fail-open relying parties
	// constitutes a revocation bypass (every cert appears valid when the
	// responder is unreachable). The same per-key keyed bucket from
	// Bundle B / M-025 is reused; the per-source-IP keying applies because
	// none of these endpoints are authenticated.
	noAuthMiddleware := []func(http.Handler) http.Handler{
		middleware.RequestID,
		structuredLogger,
		middleware.Recovery,
		bodyLimitMiddleware,
		securityHeadersMiddleware,
	}
	if cfg.RateLimit.Enabled {
		noAuthRateLimiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
			RPS:       cfg.RateLimit.RPS,
			BurstSize: cfg.RateLimit.BurstSize,
			// SEC-006 closure (Sprint 2): same bucket-TTL eviction for the
			// no-auth limiter — this one's the higher exposure since every
			// unauthenticated probe gets a fresh IP-keyed bucket.
			BucketTTL: cfg.RateLimit.BucketTTL,
		})
		noAuthMiddleware = append(noAuthMiddleware, noAuthRateLimiter)
	}
	noAuthHandler := middleware.Chain(apiRouter, noAuthMiddleware...)

	dashboardEnabled := false
	if _, err := os.Stat(webDir + "/index.html"); err == nil {
		dashboardEnabled = true
	}
	finalHandler = buildFinalHandler(apiHandler, noAuthHandler, webDir, dashboardEnabled)
	if dashboardEnabled {
		logger.Info("dashboard available at /", "web_dir", webDir)
	} else {
		logger.Info("dashboard directory not found, serving API only")
	}

	// HTTPS-everywhere milestone §2.1: fail-loud if the TLS configuration is
	// missing or malformed. Duplicates config.Validate() for defense in depth
	// (same pattern as preflightSCEPChallengePassword).
	if err := preflightServerTLS(cfg.Server.TLS.CertPath, cfg.Server.TLS.KeyPath); err != nil {
		logger.Error("startup refused: HTTPS cert unusable; control plane is HTTPS-only",
			"error", err,
			"cert_path", cfg.Server.TLS.CertPath,
			"key_path", cfg.Server.TLS.KeyPath)
		os.Exit(1)
	}

	// Load the cert+key into a SIGHUP-reloadable holder. Any subsequent
	// SIGHUP triggers a fresh read and atomic swap so rotations do not need
	// a restart. Reload failures keep the previous cert and log a warning.
	tlsCertHolder, err := newCertHolder(cfg.Server.TLS.CertPath, cfg.Server.TLS.KeyPath)
	if err != nil {
		logger.Error("startup refused: failed to load TLS cert holder",
			"error", err,
			"cert_path", cfg.Server.TLS.CertPath,
			"key_path", cfg.Server.TLS.KeyPath)
		os.Exit(1)
	}
	stopTLSWatcher := tlsCertHolder.watchSIGHUP(logger)
	defer stopTLSWatcher()

	// Server configuration
	addr := net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port))
	httpServer := &http.Server{
		Addr:    addr,
		Handler: finalHandler,
		// SCEP RFC 8894 + Intune master bundle Phase 6.5: when at least
		// one SCEP profile opted into mTLS, the listener carries the
		// union of every enabled profile's client-CA trust bundle and
		// negotiates VerifyClientCertIfGiven on the handshake. The
		// /scep route stays challenge-password-only; the /scep-mtls
		// sibling route gates additionally on the verified client cert.
		// nil pool = no profile opted in = identical TLS shape to the
		// pre-Phase-6.5 buildServerTLSConfig path.
		TLSConfig:         buildServerTLSConfigWithMTLS(tlsCertHolder, mtlsUnionPoolForTLS),
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      120 * time.Second, // Must accommodate ACME issuance (order + challenge + finalize)
		IdleTimeout:       60 * time.Second,
	}

	// Start HTTPS server in background. ListenAndServeTLS is called with
	// empty cert+key arguments because the cert is sourced through
	// TLSConfig.GetCertificate (the SIGHUP-reloadable holder). Passing file
	// paths here would pin the first-loaded cert and defeat hot reload.
	logger.Info("HTTPS server listening",
		"address", addr,
		"cert_path", cfg.Server.TLS.CertPath,
		"min_version", "TLS1.3")
	go func() {
		if err := httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTPS server error", "error", err)
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	logger.Info("received shutdown signal", "signal", sig.String())

	// Graceful shutdown.
	//
	// Bundle-5 / Audit M-011: pre-Bundle-5 the timeout was hard-coded
	// 30s, so high-volume operators couldn't extend the audit-flush
	// window without forking the binary. Now configurable via
	// CERTCTL_AUDIT_FLUSH_TIMEOUT_SECONDS (default 30s preserves prior
	// behaviour). The same context governs HTTP server shutdown +
	// scheduler completion + audit flush. WARN-log on deadline exceeded;
	// never exit hard — operator gets visibility, server still completes
	// shutdown.
	shutdownTimeout := time.Duration(cfg.Server.AuditFlushTimeoutSeconds) * time.Second
	if shutdownTimeout <= 0 {
		shutdownTimeout = 30 * time.Second
	}
	logger.Info("graceful shutdown budget", "timeout_seconds", int(shutdownTimeout/time.Second))
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	cancel() // Stop scheduler

	// Wait for in-flight scheduler work to complete (up to 30 seconds)
	logger.Info("waiting for scheduler to complete in-flight work")
	if err := sched.WaitForCompletion(30 * time.Second); err != nil {
		logger.Warn("scheduler work did not complete in time", "error", err)
	}

	logger.Info("shutting down HTTPS server")
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTPS server shutdown error", "error", err)
	}

	// Drain in-flight audit-recording goroutines before closing the DB pool.
	// The audit middleware spawns one goroutine per non-excluded request; those
	// goroutines run detached from the request context and write to the
	// audit_events table via the same *sql.DB. Without this drain, SIGTERM
	// would close the DB pool while recordings were mid-flight, silently
	// dropping audit events (M-1, CWE-662 / CWE-400).
	logger.Info("flushing audit middleware in-flight recordings")
	if err := auditMiddleware.Flush(shutdownCtx); err != nil {
		logger.Warn("audit middleware flush did not complete in time", "error", err)
	}

	// Close database connection
	if err := db.Close(); err != nil {
		logger.Error("error closing database connection", "error", err)
	}

	logger.Info("certctl server stopped")
}
