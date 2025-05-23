package main

import (
	"flag"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/openanolis/trustee/gateway/internal/handlers"
	"github.com/openanolis/trustee/gateway/internal/middleware"
	"github.com/openanolis/trustee/gateway/internal/persistence/repository"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"github.com/openanolis/trustee/gateway/internal/proxy"
	"github.com/openanolis/trustee/gateway/internal/rvps"
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
	resourceRepo := repository.NewResourceRepository(db)
	policyRepo := repository.NewPolicyRepository(db)
	auditRepo := repository.NewAuditRepository(db)

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
	kbsHandler := handlers.NewKBSHandler(p, resourceRepo, policyRepo, auditRepo)
	rvpsHandler := handlers.NewRVPSHandler(p, rvpsClient)
	attestationServiceHandler := handlers.NewAttestationServiceHandler(p, auditRepo)
	auditHandler := handlers.NewAuditHandler(auditRepo)
	healthCheckHandler := handlers.NewHealthCheckHandler(p)

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.Logger())

	// API routes
	setupRoutes(router, kbsHandler, rvpsHandler, attestationServiceHandler, auditHandler, healthCheckHandler, p)

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logrus.Infof("Starting server on %s", addr)
	if err := router.Run(addr); err != nil {
		logrus.Fatalf("Failed to start server: %v", err)
	}
}

func setupRoutes(router *gin.Engine, kbsHandler *handlers.KBSHandler, rvpsHandler *handlers.RVPSHandler, attestationServiceHandler *handlers.AttestationServiceHandler, auditHandler *handlers.AuditHandler, healthCheckHandler *handlers.HealthCheckHandler, p *proxy.Proxy) {
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

		kbs.POST("/resource-policy", kbsHandler.HandleSetResourcePolicy)
		kbs.GET("/resource-policy", kbsHandler.GetResourcePolicy)

		// Resource routes with explicit repository
		kbs.GET("/resource/:repository/:type/:tag", kbsHandler.HandleGetResource)
		kbs.POST("/resource/:repository/:type/:tag", kbsHandler.HandleSetResource)

		kbs.GET("/resources", kbsHandler.ListResources)
	}

	// Attestation Service API routes
	attestationSvc := router.Group("/api/attestation-service")
	{
		attestationSvc.POST("/attestation", attestationServiceHandler.HandleAttestation)
		attestationSvc.POST("/challenge", attestationServiceHandler.HandleGeneralRequest)
		attestationSvc.POST("/certificate", attestationServiceHandler.HandleGeneralRequest)
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
}
