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
	"syscall"
	"time"

	"github.com/shankar0123/certctl/internal/api/handler"
	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/api/router"
	"github.com/shankar0123/certctl/internal/config"
	"github.com/shankar0123/certctl/internal/domain"
	acmeissuer "github.com/shankar0123/certctl/internal/connector/issuer/acme"
	"github.com/shankar0123/certctl/internal/connector/issuer/local"
	digicertissuer "github.com/shankar0123/certctl/internal/connector/issuer/digicert"
	opensslissuer "github.com/shankar0123/certctl/internal/connector/issuer/openssl"
	stepcaissuer "github.com/shankar0123/certctl/internal/connector/issuer/stepca"
	googlecasissuer "github.com/shankar0123/certctl/internal/connector/issuer/googlecas"
	sectigoissuer "github.com/shankar0123/certctl/internal/connector/issuer/sectigo"
	vaultissuer "github.com/shankar0123/certctl/internal/connector/issuer/vault"
	notifyemail "github.com/shankar0123/certctl/internal/connector/notifier/email"
	notifyopsgenie "github.com/shankar0123/certctl/internal/connector/notifier/opsgenie"
	notifypagerduty "github.com/shankar0123/certctl/internal/connector/notifier/pagerduty"
	notifyslack "github.com/shankar0123/certctl/internal/connector/notifier/slack"
	notifyteams "github.com/shankar0123/certctl/internal/connector/notifier/teams"
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

	// Initialize Local CA issuer connector.
	// In sub-CA mode (CERTCTL_CA_CERT_PATH + CERTCTL_CA_KEY_PATH set), loads a pre-signed
	// CA cert+key from disk. All issued certs chain to the upstream root (e.g., ADCS).
	// Otherwise, generates an ephemeral self-signed CA for development/demo.
	localCAConfig := &local.Config{}
	if cfg.CA.CertPath != "" && cfg.CA.KeyPath != "" {
		localCAConfig.CACertPath = cfg.CA.CertPath
		localCAConfig.CAKeyPath = cfg.CA.KeyPath
		logger.Info("Local CA configured in sub-CA mode",
			"cert_path", cfg.CA.CertPath,
			"key_path", cfg.CA.KeyPath)
	} else {
		logger.Info("Local CA configured in self-signed mode (ephemeral)")
	}
	localCA := local.New(localCAConfig, logger)
	logger.Info("initialized Local CA issuer connector")

	// Initialize ACME issuer connector (for Let's Encrypt, ZeroSSL, Sectigo, Google Trust Services, etc.)
	// Supports HTTP-01 (default), DNS-01 (for wildcards), and DNS-PERSIST-01 (standing record) challenge types.
	// EAB (External Account Binding) required by ZeroSSL, Google Trust Services, SSL.com.
	acmeConnector := acmeissuer.New(&acmeissuer.Config{
		DirectoryURL:           os.Getenv("CERTCTL_ACME_DIRECTORY_URL"),
		Email:                  os.Getenv("CERTCTL_ACME_EMAIL"),
		EABKid:                 os.Getenv("CERTCTL_ACME_EAB_KID"),
		EABHmac:                os.Getenv("CERTCTL_ACME_EAB_HMAC"),
		ChallengeType:          os.Getenv("CERTCTL_ACME_CHALLENGE_TYPE"),
		DNSPresentScript:       os.Getenv("CERTCTL_ACME_DNS_PRESENT_SCRIPT"),
		DNSCleanUpScript:       os.Getenv("CERTCTL_ACME_DNS_CLEANUP_SCRIPT"),
		DNSPersistIssuerDomain: os.Getenv("CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN"),
		Insecure:               cfg.ACME.Insecure,
	}, logger)
	logger.Info("initialized ACME issuer connector")

	// Initialize step-ca issuer connector (for Smallstep private CA).
	// Uses the native /sign API with JWK provisioner authentication.
	stepcaConnector := stepcaissuer.New(&stepcaissuer.Config{
		CAURL:               os.Getenv("CERTCTL_STEPCA_URL"),
		RootCertPath:        os.Getenv("CERTCTL_STEPCA_ROOT_CERT"),
		ProvisionerName:     os.Getenv("CERTCTL_STEPCA_PROVISIONER"),
		ProvisionerKeyPath:  os.Getenv("CERTCTL_STEPCA_KEY_PATH"),
		ProvisionerPassword: os.Getenv("CERTCTL_STEPCA_PASSWORD"),
	}, logger)
	logger.Info("initialized step-ca issuer connector")

	// Initialize OpenSSL/Custom CA issuer connector (for script-based CA integrations).
	// Delegates certificate signing to user-provided scripts.
	opensslConnector := opensslissuer.New(&opensslissuer.Config{
		SignScript:     os.Getenv("CERTCTL_OPENSSL_SIGN_SCRIPT"),
		RevokeScript:   os.Getenv("CERTCTL_OPENSSL_REVOKE_SCRIPT"),
		CRLScript:      os.Getenv("CERTCTL_OPENSSL_CRL_SCRIPT"),
		TimeoutSeconds: getEnvIntDefault(os.Getenv("CERTCTL_OPENSSL_TIMEOUT_SECONDS"), 30),
	}, logger)
	logger.Info("initialized OpenSSL/Custom CA issuer connector")

	// Initialize Vault PKI issuer connector (for HashiCorp Vault internal PKI).
	// Uses the Vault HTTP API with token authentication.
	vaultConnector := vaultissuer.New(&vaultissuer.Config{
		Addr:  os.Getenv("CERTCTL_VAULT_ADDR"),
		Token: os.Getenv("CERTCTL_VAULT_TOKEN"),
		Mount: getEnvDefault("CERTCTL_VAULT_MOUNT", "pki"),
		Role:  os.Getenv("CERTCTL_VAULT_ROLE"),
		TTL:   getEnvDefault("CERTCTL_VAULT_TTL", "8760h"),
	}, logger)
	logger.Info("initialized Vault PKI issuer connector")

	// Initialize DigiCert CertCentral issuer connector (for enterprise public CA).
	// Uses the DigiCert REST API with async order model.
	digicertConnector := digicertissuer.New(&digicertissuer.Config{
		APIKey:      os.Getenv("CERTCTL_DIGICERT_API_KEY"),
		OrgID:       os.Getenv("CERTCTL_DIGICERT_ORG_ID"),
		ProductType: getEnvDefault("CERTCTL_DIGICERT_PRODUCT_TYPE", "ssl_basic"),
		BaseURL:     getEnvDefault("CERTCTL_DIGICERT_BASE_URL", "https://www.digicert.com/services/v2"),
	}, logger)
	logger.Info("initialized DigiCert CertCentral issuer connector")

	// Initialize Sectigo SCM issuer connector (for enterprise public CA).
	// Uses the Sectigo SCM REST API with async order model.
	sectigoConnector := sectigoissuer.New(&sectigoissuer.Config{
		CustomerURI: cfg.Sectigo.CustomerURI,
		Login:       cfg.Sectigo.Login,
		Password:    cfg.Sectigo.Password,
		OrgID:       cfg.Sectigo.OrgID,
		CertType:    cfg.Sectigo.CertType,
		Term:        cfg.Sectigo.Term,
		BaseURL:     cfg.Sectigo.BaseURL,
	}, logger)
	logger.Info("initialized Sectigo SCM issuer connector")

	// Initialize Google CAS issuer connector (for GCP private CA).
	// Uses the Google CAS REST API with OAuth2 service account auth.
	googlecasConnector := googlecasissuer.New(&googlecasissuer.Config{
		Project:     cfg.GoogleCAS.Project,
		Location:    cfg.GoogleCAS.Location,
		CAPool:      cfg.GoogleCAS.CAPool,
		Credentials: cfg.GoogleCAS.Credentials,
		TTL:         cfg.GoogleCAS.TTL,
	}, logger)
	logger.Info("initialized Google CAS issuer connector")

	// Build issuer registry: maps issuer IDs (from database) to connector implementations.
	// "iss-local" matches the seed data issuer ID for the Local CA.
	// "iss-acme-staging" and "iss-acme-prod" are conventional IDs for ACME issuers.
	// "iss-stepca" is the step-ca private CA connector.
	// "iss-openssl" is the custom CA/OpenSSL connector.
	issuerRegistry := map[string]service.IssuerConnector{
		"iss-local":        service.NewIssuerConnectorAdapter(localCA),
		"iss-acme-staging": service.NewIssuerConnectorAdapter(acmeConnector),
		"iss-acme-prod":    service.NewIssuerConnectorAdapter(acmeConnector),
		"iss-stepca":       service.NewIssuerConnectorAdapter(stepcaConnector),
		"iss-openssl":      service.NewIssuerConnectorAdapter(opensslConnector),
	}

	// Conditionally register Vault PKI (only if CERTCTL_VAULT_ADDR is set)
	if os.Getenv("CERTCTL_VAULT_ADDR") != "" {
		issuerRegistry["iss-vault"] = service.NewIssuerConnectorAdapter(vaultConnector)
		logger.Info("Vault PKI issuer registered", "id", "iss-vault")
	}

	// Conditionally register DigiCert (only if CERTCTL_DIGICERT_API_KEY is set)
	if os.Getenv("CERTCTL_DIGICERT_API_KEY") != "" {
		issuerRegistry["iss-digicert"] = service.NewIssuerConnectorAdapter(digicertConnector)
		logger.Info("DigiCert CertCentral issuer registered", "id", "iss-digicert")
	}

	// Conditionally register Sectigo SCM (only if all 3 auth credentials are set)
	if cfg.Sectigo.CustomerURI != "" && cfg.Sectigo.Login != "" && cfg.Sectigo.Password != "" {
		issuerRegistry["iss-sectigo"] = service.NewIssuerConnectorAdapter(sectigoConnector)
		logger.Info("Sectigo SCM issuer registered", "id", "iss-sectigo")
	}

	// Conditionally register Google CAS (only if project and credentials are set)
	if cfg.GoogleCAS.Project != "" && cfg.GoogleCAS.Credentials != "" {
		issuerRegistry["iss-googlecas"] = service.NewIssuerConnectorAdapter(googlecasConnector)
		logger.Info("Google CAS issuer registered", "id", "iss-googlecas")
	}

	logger.Info("issuer registry configured", "issuers", len(issuerRegistry))

	// Initialize revocation repository
	revocationRepo := postgres.NewRevocationRepository(db)

	// Initialize services (following the dependency graph)
	auditService := service.NewAuditService(auditRepo)
	policyService := service.NewPolicyService(policyRepo, auditService)
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
	jobService := service.NewJobService(jobRepo, renewalService, deploymentService, logger)
	agentService := service.NewAgentService(agentRepo, certificateRepo, jobRepo, targetRepo, auditService, issuerRegistry, renewalService)
	agentService.SetProfileRepo(profileRepo)
	issuerService := service.NewIssuerService(issuerRepo, auditService)
	targetService := service.NewTargetService(targetRepo, auditService)
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
		if err := agentRepo.Create(context.Background(), sentinelAgent); err != nil {
			// Ignore duplicate key errors (agent already exists)
			logger.Debug("sentinel agent creation", "status", "exists or created", "id", service.SentinelAgentID)
		}
	}

	logger.Info("initialized all services")

	// Initialize stats and metrics services
	statsService := service.NewStatsService(certificateRepo, jobRepo, agentRepo)
	logger.Info("initialized stats service")

	// Initialize API handlers
	certificateHandler := handler.NewCertificateHandler(certificateService)
	issuerHandler := handler.NewIssuerHandler(issuerService)
	targetHandler := handler.NewTargetHandler(targetService)
	agentHandler := handler.NewAgentHandler(agentService)
	jobHandler := handler.NewJobHandler(jobService)
	policyHandler := handler.NewPolicyHandler(policyService)
	profileHandler := handler.NewProfileHandler(profileService)
	teamHandler := handler.NewTeamHandler(teamService)
	ownerHandler := handler.NewOwnerHandler(ownerService)
	agentGroupHandler := handler.NewAgentGroupHandler(agentGroupService)
	auditHandler := handler.NewAuditHandler(auditService)
	notificationHandler := handler.NewNotificationHandler(notificationService)
	statsHandler := handler.NewStatsHandler(statsService)
	metricsHandler := handler.NewMetricsHandler(statsService, time.Now())
	healthHandler := handler.NewHealthHandler(cfg.Auth.Type)
	discoveryHandler := handler.NewDiscoveryHandler(discoveryService)
	networkScanHandler := handler.NewNetworkScanHandler(networkScanService)
	verificationService := service.NewVerificationService(jobRepo, auditService, logger)
	verificationHandler := handler.NewVerificationHandler(verificationService)
	exportService := service.NewExportService(certificateRepo, auditService)
	exportHandler := handler.NewExportHandler(exportService)

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
	sched.SetAgentHealthCheckInterval(cfg.Scheduler.AgentHealthCheckInterval)
	sched.SetNotificationProcessInterval(cfg.Scheduler.NotificationProcessInterval)
	if cfg.NetworkScan.Enabled {
		sched.SetNetworkScanInterval(cfg.NetworkScan.ScanInterval)
		logger.Info("network scanning enabled", "interval", cfg.NetworkScan.ScanInterval.String())
	}
	if digestService != nil {
		sched.SetDigestService(digestService)
		sched.SetDigestInterval(cfg.Digest.Interval)
		logger.Info("digest scheduler enabled", "interval", cfg.Digest.Interval.String())
	}

	// Start scheduler
	logger.Info("starting scheduler")
	startedChan := sched.Start(ctx)
	<-startedChan
	logger.Info("scheduler started")

	// Build the API router with all handlers
	apiRouter := router.New()
	apiRouter.RegisterHandlers(router.HandlerRegistry{
		Certificates:  certificateHandler,
		Issuers:       issuerHandler,
		Targets:       targetHandler,
		Agents:        agentHandler,
		Jobs:          jobHandler,
		Policies:      policyHandler,
		Profiles:      profileHandler,
		Teams:         teamHandler,
		Owners:        ownerHandler,
		AgentGroups:   agentGroupHandler,
		Audit:         auditHandler,
		Notifications: notificationHandler,
		Stats:         statsHandler,
		Metrics:       metricsHandler,
		Health:        healthHandler,
		Discovery:     discoveryHandler,
		NetworkScan:   networkScanHandler,
		Verification:  verificationHandler,
		Export:        exportHandler,
		Digest:        *digestHandler,
	})
	// Register EST (RFC 7030) handlers if enabled
	if cfg.EST.Enabled {
		issuerConn, ok := issuerRegistry[cfg.EST.IssuerID]
		if !ok {
			logger.Error("EST issuer not found in registry", "issuer_id", cfg.EST.IssuerID)
			os.Exit(1)
		}
		estService := service.NewESTService(cfg.EST.IssuerID, issuerConn, auditService, logger)
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

	logger.Info("registered all API handlers")

	// Build middleware stack
	authMiddleware := middleware.NewAuth(middleware.AuthConfig{
		Type:   cfg.Auth.Type,
		Secret: cfg.Auth.Secret,
	})
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
		ExcludePaths: []string{"/health", "/ready"},
		Logger:       logger,
	})
	logger.Info("API audit logging enabled (excluding /health, /ready)")

	middlewareStack := []func(http.Handler) http.Handler{
		middleware.RequestID,
		structuredLogger,
		middleware.Recovery,
		bodyLimitMiddleware,
		corsMiddleware,
		authMiddleware,
		auditMiddleware,
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
			auditMiddleware,
		}
		logger.Info("rate limiting enabled", "rps", cfg.RateLimit.RPS, "burst", cfg.RateLimit.BurstSize)
	}

	if cfg.Auth.Type == "none" {
		logger.Warn("authentication disabled (CERTCTL_AUTH_TYPE=none) — not suitable for production")
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

	if _, err := os.Stat(webDir + "/index.html"); err == nil {
		fileServer := http.FileServer(http.Dir(webDir))
		finalHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			// Health/ready and auth/info bypass auth middleware.
			// Health/ready: Docker/K8s health probes don't carry Bearer tokens.
			// auth/info: React app calls this before login to detect auth mode.
			if path == "/health" || path == "/ready" || path == "/api/v1/auth/info" {
				noAuthHandler.ServeHTTP(w, r)
				return
			}
			// All other API and EST routes go through the full middleware stack (with auth)
			if (len(path) >= 8 && path[:8] == "/api/v1/") ||
				(len(path) >= 16 && path[:16] == "/.well-known/est") {
				apiHandler.ServeHTTP(w, r)
				return
			}
			// Try to serve static files (JS, CSS, assets)
			if len(path) > 8 && path[:8] == "/assets/" {
				fileServer.ServeHTTP(w, r)
				return
			}
			// SPA fallback: serve index.html for all other routes
			http.ServeFile(w, r, webDir+"/index.html")
		})
		logger.Info("dashboard available at /", "web_dir", webDir)
	} else {
		// No dashboard: route health/auth-info without auth, everything else through full stack
		finalHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			if path == "/health" || path == "/ready" || path == "/api/v1/auth/info" {
				noAuthHandler.ServeHTTP(w, r)
				return
			}
			apiHandler.ServeHTTP(w, r)
		})
		logger.Info("dashboard directory not found, serving API only")
	}

	// Server configuration
	addr := net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port))
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           finalHandler,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      120 * time.Second, // Must accommodate ACME issuance (order + challenge + finalize)
		IdleTimeout:       60 * time.Second,
	}

	// Start HTTP server in background
	logger.Info("starting HTTP server", "address", addr)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
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

	logger.Info("shutting down HTTP server")
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}

	// Close database connection
	if err := db.Close(); err != nil {
		logger.Error("error closing database connection", "error", err)
	}

	logger.Info("certctl server stopped")
}

// getEnvDefault reads an environment variable with a default fallback.
func getEnvDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// getEnvIntDefault parses an integer from a string with a default fallback.
func getEnvIntDefault(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return val
}
