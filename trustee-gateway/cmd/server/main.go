package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/openanolis/trustee/gateway/internal/handlers"
	"github.com/openanolis/trustee/gateway/internal/middleware"
	"github.com/openanolis/trustee/gateway/internal/persistence/repository"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"github.com/openanolis/trustee/gateway/internal/proxy"
	"github.com/openanolis/trustee/gateway/internal/rvps"
	"github.com/openanolis/trustee/gateway/internal/services"
	"github.com/sirupsen/logrus"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.yaml", "Path to the configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup logging
	config.SetupLogging(cfg)

	// Initialize database
	db, err := storage.NewDatabase(cfg)
	if err != nil {
		logrus.Fatalf("Failed to initialize database: %v", err)
	}

	// Create repositories
	auditRepo := repository.NewAuditRepository(db)
	aaInstanceRepo := repository.NewAAInstanceRepository(db)

	// Initialize audit cleanup service
	auditCleanupService := services.NewAuditCleanupService(auditRepo, &cfg.Audit)

	// Initialize proxy
	p, err := proxy.NewProxy(cfg)
	if err != nil {
		logrus.Fatalf("Failed to initialize proxy: %v", err)
	}

	// Initialize RVPS gRPC client
	rvpsClient, err := rvps.NewClient(&cfg.RVPS)
	if err != nil {
		logrus.Warnf("Failed to initialize RVPS gRPC client: %v, using HTTP proxy only", err)
	} else if rvpsClient != nil {
		logrus.Infof("RVPS gRPC client initialized successfully")
		// Ensure the program exits when the gRPC connection is closed
		defer rvpsClient.Close()
	}

	// Create handlers
	kbsHandler := handlers.NewKBSHandler(p, auditRepo)
	rvpsHandler := handlers.NewRVPSHandler(p, rvpsClient)
	attestationServiceHandler := handlers.NewAttestationServiceHandler(p, auditRepo)
	auditHandler := handlers.NewAuditHandler(auditRepo)
	healthCheckHandler := handlers.NewHealthCheckHandler(p, rvpsClient)
	aaInstanceHandler := handlers.NewAAInstanceHandler(aaInstanceRepo, &cfg.AttestationAgentInstanceInfo)
	credentialHandler := handlers.NewCredentialHandler(&cfg.Credential)

	// Setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start audit cleanup service
	auditCleanupService.Start(ctx)

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.Logger())

	// API routes
	setupRoutes(router, kbsHandler, rvpsHandler, attestationServiceHandler, auditHandler, healthCheckHandler, p, aaInstanceHandler, credentialHandler)

	// Setup HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		var err error
		if !cfg.Server.InsecureHTTP && cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != "" {
			logrus.Infof("Starting HTTPS server on %s", addr)
			err = server.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		} else {
			logrus.Infof("Starting HTTP server on %s", addr)
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logrus.Errorf("Server failed to start: %v", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	select {
	case sig := <-sigChan:
		logrus.Infof("Received signal %v, shutting down gracefully...", sig)
	case <-ctx.Done():
		logrus.Info("Context cancelled, shutting down...")
	}

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	logrus.Info("Shutting down HTTP server...")
	if err := server.Shutdown(shutdownCtx); err != nil {
		logrus.Errorf("HTTP server shutdown failed: %v", err)
	}

	logrus.Info("Shutting down audit cleanup service...")
	auditCleanupService.Stop()

	logrus.Info("Shutting down database...")
	if err := db.Close(); err != nil {
		logrus.Errorf("Database shutdown failed: %v", err)
	}

	logrus.Info("Server shutdown complete")
}

func setupRoutes(router *gin.Engine, kbsHandler *handlers.KBSHandler, rvpsHandler *handlers.RVPSHandler, attestationServiceHandler *handlers.AttestationServiceHandler, auditHandler *handlers.AuditHandler, healthCheckHandler *handlers.HealthCheckHandler, p *proxy.Proxy, aaInstanceHandler *handlers.AAInstanceHandler, credentialHandler *handlers.CredentialHandler) {
	// KBS API routes
	kbs := router.Group("/api/kbs/v0")
	{
		// Attestation routes
		kbs.POST("/auth", kbsHandler.HandleAuth)
		kbs.POST("/attest", kbsHandler.HandleAttest)

		// Policy routes
		kbs.POST("/attestation-policy", kbsHandler.HandleSetAttestationPolicy)
		kbs.GET("/attestation-policy/:id", kbsHandler.GetAttestationPolicy)
		kbs.GET("/attestation-policies", kbsHandler.ListAttestationPolicies)
		kbs.DELETE("/attestation-policy/:id", kbsHandler.DeleteAttestationPolicy)

		kbs.POST("/resource-policy", kbsHandler.HandleSetResourcePolicy)
		kbs.GET("/resource-policy", kbsHandler.GetResourcePolicy)

		// Resource routes with explicit repository
		kbs.GET("/resource/:repository/:type/:tag", kbsHandler.HandleGetResource)
		kbs.POST("/resource/:repository/:type/:tag", kbsHandler.HandleSetResource)
		kbs.DELETE("/resource/:repository/:type/:tag", kbsHandler.HandleDeleteResource)

		kbs.GET("/resources", kbsHandler.ListResources)
	}

	// Attestation Service API routes
	attestationSvc := router.Group("/api/attestation-service")
	{
		attestationSvc.POST("/attestation", attestationServiceHandler.HandleAttestation)
		attestationSvc.POST("/challenge", attestationServiceHandler.HandleGeneralRequest)
		attestationSvc.GET("/certificate", attestationServiceHandler.HandleGeneralRequest)
		attestationSvc.GET("/jwks", attestationServiceHandler.HandleGeneralRequest)
		attestationSvc.GET("/.well-known/openid-configuration", attestationServiceHandler.HandleGeneralRequest)

		// Policy routes
		attestationSvc.POST("/policy", attestationServiceHandler.HandleSetAttestationPolicy)
		attestationSvc.GET("/policy/:id", attestationServiceHandler.GetAttestationPolicy)
		attestationSvc.GET("/policies", attestationServiceHandler.ListAttestationPolicies)
		attestationSvc.DELETE("/policy/:id", attestationServiceHandler.DeleteAttestationPolicy)
	}

	// AS API routes (alias for attestation-service)
	as := router.Group("/api/as")
	{
		as.POST("/attestation", attestationServiceHandler.HandleAttestation)
		as.POST("/challenge", attestationServiceHandler.HandleGeneralRequest)
		as.GET("/certificate", attestationServiceHandler.HandleGeneralRequest)
		as.GET("/jwks", attestationServiceHandler.HandleGeneralRequest)
		as.GET("/.well-known/openid-configuration", attestationServiceHandler.HandleGeneralRequest)

		// Policy routes
		as.POST("/policy", attestationServiceHandler.HandleSetAttestationPolicy)
		as.GET("/policy/:id", attestationServiceHandler.GetAttestationPolicy)
		as.GET("/policies", attestationServiceHandler.ListAttestationPolicies)
		as.DELETE("/policy/:id", attestationServiceHandler.DeleteAttestationPolicy)
	}

	// RVPS API routes
	rvps := router.Group("/api/rvps")
	{
		rvps.Any("/*path", rvpsHandler.HandleRVPSRequest)
	}

	// Audit routes
	audit := router.Group("/api/audit")
	{
		audit.GET("/attestation", auditHandler.ListAttestationRecords)
		audit.GET("/resources", auditHandler.ListResourceRequests)
	}

	// Health check routes
	router.GET("/api/health", healthCheckHandler.HandleHealthCheck)
	router.GET("/api/services-health", healthCheckHandler.HandleServicesHealthCheck)

	// Credential routes
	router.GET("/api/credential", credentialHandler.HandleGetCredential)

	// Attestation Agent routes
	aa := router.Group("/api/aa-instance")
	{
		aa.POST("/heartbeat", aaInstanceHandler.HandleHeartbeat)
		aa.GET("/list", aaInstanceHandler.HandleGetActiveAAInstances)
	}
}
