package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shankar0123/certctl/internal/api/handler"
	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/api/router"
	"github.com/shankar0123/certctl/internal/config"
	acmeissuer "github.com/shankar0123/certctl/internal/connector/issuer/acme"
	"github.com/shankar0123/certctl/internal/connector/issuer/local"
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
	teamRepo := postgres.NewTeamRepository(db)
	ownerRepo := postgres.NewOwnerRepository(db)
	logger.Info("initialized all repositories")

	// Initialize Local CA issuer connector
	// This provides in-memory certificate signing for development, testing, and demo.
	// The CA is ephemeral (regenerated on restart) and NOT suitable for production.
	localCA := local.New(nil, logger)
	logger.Info("initialized Local CA issuer connector")

	// Initialize ACME issuer connector (for Let's Encrypt, Sectigo, etc.)
	// The ACME connector is registered but only activated when an issuer record
	// in the database references it. Configuration comes from the issuer's config JSON.
	acmeConnector := acmeissuer.New(&acmeissuer.Config{
		DirectoryURL: os.Getenv("CERTCTL_ACME_DIRECTORY_URL"),
		Email:        os.Getenv("CERTCTL_ACME_EMAIL"),
	}, logger)
	logger.Info("initialized ACME issuer connector")

	// Build issuer registry: maps issuer IDs (from database) to connector implementations.
	// "iss-local" matches the seed data issuer ID for the Local CA.
	// "iss-acme-staging" and "iss-acme-prod" are conventional IDs for ACME issuers.
	issuerRegistry := map[string]service.IssuerConnector{
		"iss-local":        service.NewIssuerConnectorAdapter(localCA),
		"iss-acme-staging": service.NewIssuerConnectorAdapter(acmeConnector),
		"iss-acme-prod":    service.NewIssuerConnectorAdapter(acmeConnector),
	}
	logger.Info("issuer registry configured", "issuers", len(issuerRegistry))

	// Initialize services (following the dependency graph)
	auditService := service.NewAuditService(auditRepo)
	policyService := service.NewPolicyService(policyRepo, auditService)
	certificateService := service.NewCertificateService(certificateRepo, policyService, auditService)
	notificationService := service.NewNotificationService(notificationRepo, make(map[string]service.Notifier))
	renewalService := service.NewRenewalService(certificateRepo, jobRepo, renewalPolicyRepo, auditService, notificationService, issuerRegistry)
	deploymentService := service.NewDeploymentService(jobRepo, targetRepo, agentRepo, certificateRepo, auditService, notificationService)
	jobService := service.NewJobService(jobRepo, renewalService, deploymentService, logger)
	agentService := service.NewAgentService(agentRepo, certificateRepo, jobRepo, targetRepo, auditService, issuerRegistry)
	issuerService := service.NewIssuerService(issuerRepo, auditService)
	targetService := service.NewTargetService(targetRepo, auditService)
	teamService := service.NewTeamService(teamRepo, auditService)
	ownerService := service.NewOwnerService(ownerRepo, auditService)
	logger.Info("initialized all services")

	// Initialize API handlers
	certificateHandler := handler.NewCertificateHandler(certificateService)
	issuerHandler := handler.NewIssuerHandler(issuerService)
	targetHandler := handler.NewTargetHandler(targetService)
	agentHandler := handler.NewAgentHandler(agentService)
	jobHandler := handler.NewJobHandler(jobService)
	policyHandler := handler.NewPolicyHandler(policyService)
	teamHandler := handler.NewTeamHandler(teamService)
	ownerHandler := handler.NewOwnerHandler(ownerService)
	auditHandler := handler.NewAuditHandler(auditService)
	notificationHandler := handler.NewNotificationHandler(notificationService)
	healthHandler := handler.NewHealthHandler()
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
		teamHandler,
		ownerHandler,
		auditHandler,
		notificationHandler,
		healthHandler,
	)
	logger.Info("registered all API handlers")

	// Apply middleware to API router
	apiHandler := middleware.Chain(
		apiRouter,
		middleware.RequestID,
		middleware.Logging,
		middleware.Recovery,
	)

	// Wrap with dashboard static file serving if web/ directory exists
	var finalHandler http.Handler
	webDir := "./web"
	if _, err := os.Stat(webDir); err == nil {
		finalHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			// API and health routes go to the API handler
			if path == "/health" || path == "/ready" ||
				(len(path) >= 8 && path[:8] == "/api/v1/") {
				apiHandler.ServeHTTP(w, r)
				return
			}
			// Serve the dashboard SPA index.html for everything else
			http.ServeFile(w, r, webDir+"/index.html")
		})
		logger.Info("dashboard available at /")
	} else {
		finalHandler = apiHandler
		logger.Info("dashboard directory not found, serving API only")
	}

	// Server configuration
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
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
