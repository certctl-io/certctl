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
	opensslissuer "github.com/shankar0123/certctl/internal/connector/issuer/openssl"
	stepcaissuer "github.com/shankar0123/certctl/internal/connector/issuer/stepca"
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
		"version", "0.1.0",
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

	// Initialize ACME issuer connector (for Let's Encrypt, Sectigo, etc.)
	// Supports HTTP-01 (default) and DNS-01 (for wildcards) challenge types.
	acmeConnector := acmeissuer.New(&acmeissuer.Config{
		DirectoryURL:       os.Getenv("CERTCTL_ACME_DIRECTORY_URL"),
		Email:              os.Getenv("CERTCTL_ACME_EMAIL"),
		ChallengeType:      os.Getenv("CERTCTL_ACME_CHALLENGE_TYPE"),
		DNSPresentScript:   os.Getenv("CERTCTL_ACME_DNS_PRESENT_SCRIPT"),
		DNSCleanUpScript:   os.Getenv("CERTCTL_ACME_DNS_CLEANUP_SCRIPT"),
	}, logger)
	logger.Info("initialized ACME issuer connector")

	// Initialize step-ca issuer connector (for Smallstep private CA).
	// Uses the native /sign API with JWK provisioner authentication.
	stepcaConnector := stepcaissuer.New(&stepcaissuer.Config{
		CAURL:               os.Getenv("CERTCTL_STEPCA_URL"),
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

	notificationService := service.NewNotificationService(notificationRepo, notifierRegistry)
	notificationService.SetOwnerRepo(ownerRepo)

	// Wire revocation dependencies into CertificateService
	certificateService.SetRevocationRepo(revocationRepo)
	certificateService.SetNotificationService(notificationService)
	certificateService.SetIssuerRegistry(issuerRegistry)
	certificateService.SetProfileRepo(profileRepo)
	renewalService := service.NewRenewalService(certificateRepo, jobRepo, renewalPolicyRepo, profileRepo, auditService, notificationService, issuerRegistry, cfg.Keygen.Mode)
	deploymentService := service.NewDeploymentService(jobRepo, targetRepo, agentRepo, certificateRepo, auditService, notificationService)
	jobService := service.NewJobService(jobRepo, renewalService, deploymentService, logger)
	agentService := service.NewAgentService(agentRepo, certificateRepo, jobRepo, targetRepo, auditService, issuerRegistry, renewalService)
	issuerService := service.NewIssuerService(issuerRepo, auditService)
	targetService := service.NewTargetService(targetRepo, auditService)
	profileService := service.NewProfileService(profileRepo, auditService)
	teamService := service.NewTeamService(teamRepo, auditService)
	ownerService := service.NewOwnerService(ownerRepo, auditService)
	agentGroupRepo := postgres.NewAgentGroupRepository(db)
	agentGroupService := service.NewAgentGroupService(agentGroupRepo, auditService)
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
		logger,
	)

	// Configure scheduler intervals from config
	sched.SetRenewalCheckInterval(cfg.Scheduler.RenewalCheckInterval)
	sched.SetJobProcessorInterval(cfg.Scheduler.JobProcessorInterval)
	sched.SetAgentHealthCheckInterval(cfg.Scheduler.AgentHealthCheckInterval)
	sched.SetNotificationProcessInterval(cfg.Scheduler.NotificationProcessInterval)

	// Start scheduler
	logger.Info("starting scheduler")
	startedChan := sched.Start(ctx)
	<-startedChan
	logger.Info("scheduler started")

	// Build the API router with all handlers
	apiRouter := router.New()
	apiRouter.RegisterHandlers(
		certificateHandler,
		issuerHandler,
		targetHandler,
		agentHandler,
		jobHandler,
		policyHandler,
		profileHandler,
		teamHandler,
		ownerHandler,
		agentGroupHandler,
		auditHandler,
		notificationHandler,
		statsHandler,
		metricsHandler,
		healthHandler,
	)
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
	if _, err := os.Stat(webDir + "/index.html"); err == nil {
		fileServer := http.FileServer(http.Dir(webDir))
		finalHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			// API and health routes go to the API handler
			if path == "/health" || path == "/ready" ||
				(len(path) >= 8 && path[:8] == "/api/v1/") {
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
		finalHandler = apiHandler
		logger.Info("dashboard directory not found, serving API only")
	}

	// Server configuration
	addr := net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port))
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      finalHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
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
