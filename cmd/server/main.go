package main

import (
	"context"
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

	"github.com/shankar0123/certctl/internal/api/handler"
	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/api/router"
	"github.com/shankar0123/certctl/internal/config"
	discoveryawssm "github.com/shankar0123/certctl/internal/connector/discovery/awssm"
	discoveryazurekv "github.com/shankar0123/certctl/internal/connector/discovery/azurekv"
	discoverygcpsm "github.com/shankar0123/certctl/internal/connector/discovery/gcpsm"
	notifyemail "github.com/shankar0123/certctl/internal/connector/notifier/email"
	notifyopsgenie "github.com/shankar0123/certctl/internal/connector/notifier/opsgenie"
	notifypagerduty "github.com/shankar0123/certctl/internal/connector/notifier/pagerduty"
	notifyslack "github.com/shankar0123/certctl/internal/connector/notifier/slack"
	notifyteams "github.com/shankar0123/certctl/internal/connector/notifier/teams"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository/postgres"
	"github.com/shankar0123/certctl/internal/scheduler"
	"github.com/shankar0123/certctl/internal/service"
)

func main() {
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
	switch config.AuthType(cfg.Auth.Type) {
	case config.AuthTypeAPIKey, config.AuthTypeNone:
		// ok — fall through
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

	// Initialize database connection pool
	db, err := postgres.NewDB(cfg.Database.URL)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	logger.Info("connected to database")

	// Run migrations
	logger.Info("running migrations", "path", cfg.Database.MigrationsPath)
	if err := postgres.RunMigrations(db, cfg.Database.MigrationsPath); err != nil {
		logger.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}
	logger.Info("migrations completed")

	// Apply baseline seed data.
	//
	// U-3 (P1, cat-u-seed_initdb_schema_drift): pre-U-3 seed.sql was mounted
	// into postgres `/docker-entrypoint-initdb.d/` alongside a hand-curated
	// subset of migrations. Adding a migration that introduced a new column
	// referenced by seed.sql (cat-o-retry_interval_unit_mismatch /
	// policy_rules.severity / etc.) without also updating the compose volume
	// mounts caused initdb to crash on first up. Post-U-3 the compose stack
	// drops all initdb mounts; postgres comes up with empty schema, the
	// server runs RunMigrations above, then this RunSeed call lands the
	// baseline data — all from a single source of truth (this binary).
	// See internal/repository/postgres/db.go::RunSeed for the contract.
	logger.Info("applying baseline seed", "path", cfg.Database.MigrationsPath)
	if err := postgres.RunSeed(db, cfg.Database.MigrationsPath); err != nil {
		logger.Error("failed to apply seed data", "error", err)
		os.Exit(1)
	}
	logger.Info("seed completed")

	// Apply demo overlay seed when CERTCTL_DEMO_SEED=true. Pre-U-3 the demo
	// overlay (deploy/docker-compose.demo.yml) mounted seed_demo.sql into
	// postgres `/docker-entrypoint-initdb.d/`; that broke once U-3 dropped
	// the initdb migration mounts (the demo seed references tables that
	// wouldn't exist at initdb time). The runtime path here is the
	// post-U-3 replacement. Default-off so a vanilla deploy never lands
	// fake-history rows. See postgres.RunDemoSeed for the contract.
	if cfg.Database.DemoSeed {
		logger.Info("applying demo seed (CERTCTL_DEMO_SEED=true)", "path", cfg.Database.MigrationsPath)
		if err := postgres.RunDemoSeed(db, cfg.Database.MigrationsPath); err != nil {
			logger.Error("failed to apply demo seed data", "error", err)
			os.Exit(1)
		}
		logger.Info("demo seed completed")
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

	// Initialize revocation repository
	revocationRepo := postgres.NewRevocationRepository(db)

	// Initialize services (following the dependency graph)
	auditService := service.NewAuditService(auditRepo)
	policyService := service.NewPolicyService(policyRepo, auditService)
	policyService.SetCertRepo(certificateRepo) // D-008: CertificateLifetime arm needs CertificateVersion.NotBefore/NotAfter
	// G-1: RenewalPolicyService — distinct from PolicyService (compliance rules).
	// Drives /api/v1/renewal-policies CRUD; the service layer owns slugify + validation,
	// the repo layer owns sentinel translation for 23505 (name UNIQUE) and 23503
	// (FK-RESTRICT against managed_certificates.renewal_policy_id).
	renewalPolicyService := service.NewRenewalPolicyService(renewalPolicyRepo)
	certificateService := service.NewCertificateService(certificateRepo, policyService, auditService)
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

	// Create RevocationSvc with its dependencies
	revocationSvc := service.NewRevocationSvc(certificateRepo, revocationRepo, auditService)
	revocationSvc.SetIssuerRegistry(issuerRegistry)
	revocationSvc.SetNotificationService(notificationService)

	// Create CAOperationsSvc with its dependencies
	caOperationsSvc := service.NewCAOperationsSvc(revocationRepo, certificateRepo, profileRepo)
	caOperationsSvc.SetIssuerRegistry(issuerRegistry)

	// Wire sub-services into CertificateService
	certificateService.SetRevocationSvc(revocationSvc)
	certificateService.SetCAOperationsSvc(caOperationsSvc)
	certificateService.SetTargetRepo(targetRepo)
	certificateService.SetJobRepo(jobRepo)
	certificateService.SetKeygenMode(cfg.Keygen.Mode)
	renewalService := service.NewRenewalService(certificateRepo, jobRepo, renewalPolicyRepo, profileRepo, auditService, notificationService, issuerRegistry, cfg.Keygen.Mode)
	renewalService.SetTargetRepo(targetRepo)
	deploymentService := service.NewDeploymentService(jobRepo, targetRepo, agentRepo, certificateRepo, auditService, notificationService)
	jobService := service.NewJobService(jobRepo, certificateRepo, ownerRepo, renewalService, deploymentService, logger)
	// I-001: emit "job_retry" audit events when the scheduler resets Failed→Pending.
	// SetAuditService is optional — JobService falls back to nil-guarded no-op if unwired.
	jobService.SetAuditService(auditService)
	agentService := service.NewAgentService(agentRepo, certificateRepo, jobRepo, targetRepo, auditService, issuerRegistry, renewalService)
	agentService.SetProfileRepo(profileRepo)
	issuerService := service.NewIssuerService(issuerRepo, auditService, issuerRegistry, encryptionKey, logger)

	// Seed issuers from env vars on first boot (empty database only), then build registry
	issuerService.SeedFromEnvVars(context.Background(), cfg)
	if err := issuerService.BuildRegistry(context.Background()); err != nil {
		logger.Error("failed to build issuer registry from database", "error", err)
	}
	logger.Info("issuer registry loaded", "issuers", issuerRegistry.Len())
	targetService := service.NewTargetService(targetRepo, auditService, agentRepo, encryptionKey, logger)
	profileService := service.NewProfileService(profileRepo, auditService)
	teamService := service.NewTeamService(teamRepo, auditService)
	ownerService := service.NewOwnerService(ownerRepo, auditService)
	agentGroupRepo := postgres.NewAgentGroupRepository(db)
	agentGroupService := service.NewAgentGroupService(agentGroupRepo, auditService)
	discoveryRepo := postgres.NewDiscoveryRepository(db)
	discoveryService := service.NewDiscoveryService(discoveryRepo, certificateRepo, auditService)
	networkScanRepo := postgres.NewNetworkScanRepository(db)
	networkScanService := service.NewNetworkScanService(networkScanRepo, discoveryService, auditService, logger)
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
	issuerHandler := handler.NewIssuerHandler(issuerService)
	targetHandler := handler.NewTargetHandler(targetService)
	agentHandler := handler.NewAgentHandler(agentService)
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
	healthHandler := handler.NewHealthHandler(cfg.Auth.Type)
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

	bulkRevocationHandler := handler.NewBulkRevocationHandler(bulkRevocationService)

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
	logger.Info("job timeout reaper enabled",
		"interval", cfg.Scheduler.JobTimeoutInterval.String(),
		"csr_timeout", cfg.Scheduler.AwaitingCSRTimeout.String(),
		"approval_timeout", cfg.Scheduler.AwaitingApprovalTimeout.String())

	// Start scheduler
	logger.Info("starting scheduler")
	startedChan := sched.Start(ctx)
	<-startedChan
	logger.Info("scheduler started")

	// Build the API router with all handlers
	apiRouter := router.New()
	apiRouter.RegisterHandlers(router.HandlerRegistry{
		Certificates:   certificateHandler,
		Issuers:        issuerHandler,
		Targets:        targetHandler,
		Agents:         agentHandler,
		Jobs:           jobHandler,
		Policies:       policyHandler,
		RenewalPolicies: renewalPolicyHandler,
		Profiles:       profileHandler,
		Teams:          teamHandler,
		Owners:         ownerHandler,
		AgentGroups:    agentGroupHandler,
		Audit:          auditHandler,
		Notifications:  notificationHandler,
		Stats:          statsHandler,
		Metrics:        metricsHandler,
		Health:         healthHandler,
		Discovery:      discoveryHandler,
		NetworkScan:    networkScanHandler,
		Verification:   verificationHandler,
		Export:         exportHandler,
		Digest:         *digestHandler,
		HealthChecks:   healthCheckHandler,
		BulkRevocation: bulkRevocationHandler,
		Version:        versionHandler,
	})
	// Register EST (RFC 7030) handlers if enabled
	if cfg.EST.Enabled {
		issuerConn, ok := issuerRegistry.Get(cfg.EST.IssuerID)
		if !ok {
			logger.Error("EST issuer not found in registry", "issuer_id", cfg.EST.IssuerID)
			os.Exit(1)
		}
		estService := service.NewESTService(cfg.EST.IssuerID, issuerConn, auditService, logger)
		estService.SetProfileRepo(profileRepo)
		if cfg.EST.ProfileID != "" {
			estService.SetProfileID(cfg.EST.ProfileID)
		}
		estHandler := handler.NewESTHandler(estService)
		apiRouter.RegisterESTHandlers(estHandler)
		logger.Info("EST server enabled",
			"issuer_id", cfg.EST.IssuerID,
			"profile_id", cfg.EST.ProfileID,
			"endpoints", "/.well-known/est/{cacerts,simpleenroll,simplereenroll,csrattrs}")
	}

	// Register SCEP (RFC 8894) handlers if enabled
	if cfg.SCEP.Enabled {
		// H-2 fix: fail closed at startup when SCEP is enabled without a
		// challenge password configured. Previously the service-layer guard
		// at internal/service/scep.go:72-79 skipped the password check when
		// s.challengePassword == "", meaning any client that could reach the
		// /scep endpoint could enroll an arbitrary CSR against the configured
		// issuer (CWE-306, missing authentication for a critical function).
		// Refuse to start instead: the operator must set
		// CERTCTL_SCEP_CHALLENGE_PASSWORD (or disable SCEP) before the control
		// plane can boot.
		if err := preflightSCEPChallengePassword(cfg.SCEP.Enabled, cfg.SCEP.ChallengePassword); err != nil {
			logger.Error(
				"startup refused: SCEP is enabled but CERTCTL_SCEP_CHALLENGE_PASSWORD is not set "+
					"(would allow unauthenticated certificate enrollment, CWE-306). "+
					"Set a non-empty challenge password or disable SCEP before restarting.",
				"error", err,
			)
			os.Exit(1)
		}
		issuerConn, ok := issuerRegistry.Get(cfg.SCEP.IssuerID)
		if !ok {
			logger.Error("SCEP issuer not found in registry", "issuer_id", cfg.SCEP.IssuerID)
			os.Exit(1)
		}
		scepService := service.NewSCEPService(cfg.SCEP.IssuerID, issuerConn, auditService, logger, cfg.SCEP.ChallengePassword)
		scepService.SetProfileRepo(profileRepo)
		if cfg.SCEP.ProfileID != "" {
			scepService.SetProfileID(cfg.SCEP.ProfileID)
		}
		scepHandler := handler.NewSCEPHandler(scepService)
		apiRouter.RegisterSCEPHandlers(scepHandler)
		logger.Info("SCEP server enabled",
			"issuer_id", cfg.SCEP.IssuerID,
			"profile_id", cfg.SCEP.ProfileID,
			"challenge_password_set", cfg.SCEP.ChallengePassword != "",
			"endpoints", "/scep?operation={GetCACaps,GetCACert,PKIOperation}")
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
	// Authentication unification (M-002): every authenticated request now
	// carries a named actor in the request context so audit events record
	// the real key identity instead of the hardcoded "api-key-user" string.
	// Named keys come from CERTCTL_API_KEYS_NAMED (preferred). For backward
	// compatibility CERTCTL_AUTH_SECRET is synthesized into legacy-key-N
	// entries with Admin=false.
	var namedKeys []middleware.NamedAPIKey
	if config.AuthType(cfg.Auth.Type) != config.AuthTypeNone {
		// Translate typed config.NamedAPIKey -> middleware.NamedAPIKey. The
		// two structs are field-compatible but live in different packages to
		// preserve the config→middleware dependency direction.
		for _, nk := range cfg.Auth.NamedKeys {
			namedKeys = append(namedKeys, middleware.NamedAPIKey{
				Name:  nk.Name,
				Key:   nk.Key,
				Admin: nk.Admin,
			})
		}
		// Back-compat: if no named keys but legacy Secret is configured,
		// synthesize named entries so the audit trail still attributes the
		// action (instead of falling back to "api-key-user" / "anonymous").
		if len(namedKeys) == 0 && cfg.Auth.Secret != "" {
			parts := strings.Split(cfg.Auth.Secret, ",")
			idx := 0
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				namedKeys = append(namedKeys, middleware.NamedAPIKey{
					Name:  fmt.Sprintf("legacy-key-%d", idx),
					Key:   p,
					Admin: false,
				})
				idx++
			}
			if len(namedKeys) > 0 {
				logger.Warn("CERTCTL_AUTH_SECRET is deprecated — set CERTCTL_API_KEYS_NAMED for named actor attribution and admin gating",
					"synthesized_keys", len(namedKeys))
			}
		}
	}
	authMiddleware := middleware.NewAuthWithNamedKeys(namedKeys)
	corsMiddleware := middleware.NewCORS(middleware.CORSConfig{
		AllowedOrigins: cfg.CORS.AllowedOrigins,
	})

	structuredLogger := middleware.NewLogging(logger)

	// Request body size limit middleware — prevents memory exhaustion attacks (CWE-400)
	bodyLimitMiddleware := middleware.NewBodyLimit(middleware.BodyLimitConfig{
		MaxBytes: cfg.Server.MaxBodySize,
	})
	logger.Info("request body size limit enabled", "max_bytes", cfg.Server.MaxBodySize)

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
		corsMiddleware,
		authMiddleware,
		auditMiddleware.Middleware,
	}

	// Add rate limiter if enabled
	if cfg.RateLimit.Enabled {
		rateLimiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
			RPS:       cfg.RateLimit.RPS,
			BurstSize: cfg.RateLimit.BurstSize,
		})
		middlewareStack = []func(http.Handler) http.Handler{
			middleware.RequestID,
			structuredLogger,
			middleware.Recovery,
			bodyLimitMiddleware,
			rateLimiter,
			corsMiddleware,
			authMiddleware,
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
	// Health/ready routes bypass the full middleware stack (no auth required).
	// These are registered on the inner router without auth, but the outer
	// middleware chain wraps everything. Route them directly to the inner router.
	noAuthHandler := middleware.Chain(apiRouter,
		middleware.RequestID,
		structuredLogger,
		middleware.Recovery,
	)

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
		Addr:              addr,
		Handler:           finalHandler,
		TLSConfig:         buildServerTLSConfig(tlsCertHolder),
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

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
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

// preflightSCEPChallengePassword enforces the H-2 fix: if SCEP is enabled, a
// non-empty challenge password MUST be configured. Returns a non-nil error
// otherwise so the caller can refuse to start the control plane (CWE-306,
// missing authentication for a critical function).
//
// This helper is extracted so the check can be unit tested without booting
// the full server. The caller (main) is responsible for translating the
// returned error into a structured log line and os.Exit(1).
func preflightSCEPChallengePassword(enabled bool, challengePassword string) error {
	if !enabled {
		return nil
	}
	if challengePassword == "" {
		return fmt.Errorf("SCEP enabled but CERTCTL_SCEP_CHALLENGE_PASSWORD is empty: " +
			"SCEP enrollment would accept any client (CWE-306); " +
			"configure a non-empty shared secret or set CERTCTL_SCEP_ENABLED=false")
	}
	return nil
}

// buildFinalHandler builds the outer HTTP dispatch handler that routes incoming
// requests to either the authenticated apiHandler chain or the unauthenticated
// noAuthHandler chain based on URL path prefix. Extracted from main() so the
// dispatch logic can be unit tested without booting the full server stack
// (see cmd/server/finalhandler_test.go).
//
// Dispatch rules (M-001, audit 2026-04-19, option D):
//
//   - /health, /ready, /api/v1/auth/info           → no-auth (probes + login detection)
//   - /api/v1/version                              → no-auth (U-3 ride-along: build identity for rollout/probes)
//   - /.well-known/pki/*                           → no-auth (RFC 5280 CRL, RFC 6960 OCSP)
//   - /.well-known/est/*                           → no-auth (RFC 7030 §3.2.3)
//   - /scep, /scep/*                               → no-auth (RFC 8894 §3.2, CSR challengePassword)
//   - /api/v1/*                                    → auth (Bearer token required)
//   - /assets/*                                    → static file server (dashboard only)
//   - anything else                                → SPA index.html fallback (dashboard only)
//                                                    OR apiHandler (no dashboard)
//
// EST/SCEP clients (IoT devices, 802.1X supplicants, MDM endpoints, network
// appliances) cannot present certctl Bearer tokens, so those endpoints must be
// reachable without the Auth middleware. Authentication is instead enforced by
// CSR signature verification, profile policy gates, and for SCEP the
// challengePassword shared secret (fail-loud gated by preflightSCEPChallengePassword
// above).
//
// webDir must point to a directory containing index.html + assets/ when
// dashboardEnabled is true; it is ignored otherwise.
func buildFinalHandler(apiHandler, noAuthHandler http.Handler, webDir string, dashboardEnabled bool) http.Handler {
	var fileServer http.Handler
	if dashboardEnabled {
		fileServer = http.FileServer(http.Dir(webDir))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Health/ready, auth/info, and version bypass auth middleware.
		// Health/ready: Docker/K8s health probes don't carry Bearer tokens.
		// auth/info: React app calls this before login to detect auth mode.
		// version: U-3 ride-along (cat-u-no_version_endpoint) — rollout
		// systems and blackbox probes need build identity without a key.
		if path == "/health" || path == "/ready" || path == "/api/v1/auth/info" || path == "/api/v1/version" {
			noAuthHandler.ServeHTTP(w, r)
			return
		}

		// RFC 5280 CRL and RFC 6960 OCSP live under /.well-known/pki/ and MUST
		// be served unauthenticated — relying parties (browsers, OpenSSL, OCSP
		// stapling sidecars, mTLS clients) cannot present certctl Bearer tokens.
		if strings.HasPrefix(path, "/.well-known/pki") {
			noAuthHandler.ServeHTTP(w, r)
			return
		}

		// RFC 7030 EST endpoints ride the no-auth middleware chain (M-001,
		// option D, audit 2026-04-19). Trust boundary is CSR signature + profile
		// policy, not HTTP Bearer. /.well-known/est/cacerts is explicitly
		// anonymous per RFC 7030 §4.1.1.
		if strings.HasPrefix(path, "/.well-known/est") {
			noAuthHandler.ServeHTTP(w, r)
			return
		}

		// RFC 8894 SCEP rides the no-auth chain (M-001, option D). SCEP clients
		// authenticate via the challengePassword attribute in the PKCS#10 CSR,
		// not via HTTP Bearer tokens. preflightSCEPChallengePassword refuses to
		// start the server if SCEP is enabled without a non-empty shared secret.
		if path == "/scep" || strings.HasPrefix(path, "/scep/") {
			noAuthHandler.ServeHTTP(w, r)
			return
		}

		// Authenticated API routes — full middleware stack including Auth.
		if strings.HasPrefix(path, "/api/v1/") {
			apiHandler.ServeHTTP(w, r)
			return
		}

		if !dashboardEnabled {
			// No dashboard: everything non-special falls through to the
			// authenticated handler (preserves pre-M-001 behavior for API-only
			// deployments).
			apiHandler.ServeHTTP(w, r)
			return
		}

		// Dashboard-present: serve static assets directly, SPA fallback for
		// everything else.
		if strings.HasPrefix(path, "/assets/") {
			fileServer.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, webDir+"/index.html")
	})
}
