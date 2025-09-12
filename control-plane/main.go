package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"

	"github.com/keyvault/control-plane/internal/analytics"
	"github.com/keyvault/control-plane/internal/dashboard"
	"github.com/keyvault/control-plane/internal/monitoring"
	"github.com/keyvault/control-plane/internal/policy"
	"github.com/keyvault/control-plane/internal/registry"
	"github.com/keyvault/control-plane/internal/users"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Connect to database
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://user:password@localhost/keyvault_control_plane?sslmode=disable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Initialize services
	registryService := registry.NewService(db)
	userService := users.NewService(db)
	policyService := policy.NewService(db, registryService)
	analyticsService := analytics.NewService(db, registryService)
	monitoringService := monitoring.NewService(registryService)
	dashboardService := dashboard.NewService(registryService, monitoringService, analyticsService)

	// Initialize database schemas
	if err := initSchemas(ctx, registryService, userService, policyService, analyticsService); err != nil {
		log.Fatal("Failed to initialize database schemas:", err)
	}

	// Start monitoring service
	if err := monitoringService.Start(ctx); err != nil {
		log.Fatal("Failed to start monitoring service:", err)
	}
	defer monitoringService.Stop()

	// Setup HTTP router
	router := setupRouter(registryService, userService, policyService, analyticsService, dashboardService)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8090"
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Starting Control Plane server on port %s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Server failed:", err)
		}
	}()

	// Wait for shutdown signal
	<-sigCh
	log.Println("Shutting down...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Shutdown complete")
}

func setupRouter(
	registryService *registry.Service,
	userService *users.Service,
	policyService *policy.Service,
	analyticsService *analytics.Service,
	dashboardService *dashboard.Service,
) *gin.Engine {
	router := gin.Default()

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// API routes
	api := router.Group("/api/v1")
	{
		// Agent registration and heartbeat
		agents := api.Group("/agents")
		{
			agents.POST("/register", handleAgentRegistration(registryService))
			agents.POST("/heartbeat", handleAgentHeartbeat(registryService, analyticsService))
			agents.POST("/sync", handleAgentSync(analyticsService))
			agents.GET("", handleListAgents(registryService))
			agents.GET("/:id", handleGetAgent(registryService))
		}

		// Policy management
		policies := api.Group("/policies")
		{
			policies.POST("", handleCreatePolicy(policyService))
			policies.GET("", handleListPolicies(policyService))
			policies.GET("/:id", handleGetPolicy(policyService))
			policies.POST("/:id/assign", handleAssignPolicy(policyService))
			policies.POST("/bulk-assign", handleBulkAssignPolicy(policyService))
		}

		// Analytics and reporting
		analytics := api.Group("/analytics")
		{
			analytics.GET("/usage/:orgId", handleUsageReport(analyticsService))
			analytics.GET("/capacity/:orgId", handleCapacityMetrics(analyticsService))
			analytics.GET("/metrics/:orgId", handleMetricsHistory(analyticsService))
		}

		// Dashboard
		dashboard := api.Group("/dashboard")
		{
			dashboard.GET("/:orgId", handleDashboardData(dashboardService))
			dashboard.GET("/agents/:id", handleAgentDetails(dashboardService))
		}

		// User management
		users := api.Group("/users")
		{
			users.POST("/organizations", handleCreateOrganization(userService))
			users.POST("", handleCreateUser(userService))
			users.POST("/auth", handleAuthenticateUser(userService))
			users.GET("/:orgId", handleListUsers(userService))
		}
	}

	return router
}

func initSchemas(ctx context.Context, registryService *registry.Service, userService *users.Service, policyService *policy.Service, analyticsService *analytics.Service) error {
	if err := registryService.InitSchema(ctx); err != nil {
		return err
	}
	if err := userService.InitSchema(ctx); err != nil {
		return err
	}
	if err := policyService.InitSchema(ctx); err != nil {
		return err
	}
	if err := analyticsService.InitSchema(ctx); err != nil {
		return err
	}
	return nil
}

// Handler functions (minimal implementations)

func handleAgentRegistration(service *registry.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			AgentID      string            `json:"agent_id"`
			Hostname     string            `json:"hostname"`
			Version      string            `json:"version"`
			Capabilities []string          `json:"capabilities"`
			Metadata     map[string]string `json:"metadata"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		agent := &registry.Agent{
			ID:           req.AgentID,
			Hostname:     req.Hostname,
			Version:      req.Version,
			Capabilities: req.Capabilities,
			Metadata:     req.Metadata,
			OrganizationID: "default", // In real implementation, extract from auth
		}

		if err := service.RegisterAgent(c.Request.Context(), agent); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "registered"})
	}
}

func handleAgentHeartbeat(registryService *registry.Service, analyticsService *analytics.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			AgentID   string                 `json:"agent_id"`
			Status    string                 `json:"status"`
			Timestamp time.Time              `json:"timestamp"`
			Metrics   map[string]interface{} `json:"metrics"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Update heartbeat
		if err := registryService.UpdateHeartbeat(c.Request.Context(), req.AgentID, req.Metrics); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Heartbeat failed"})
			return
		}

		// Record metrics
		analyticsService.RecordMetrics(c.Request.Context(), req.AgentID, "default", req.Metrics)

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func handleAgentSync(service *analytics.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			AgentID string `json:"agent_id"`
			Secrets []struct {
				SecretID  string            `json:"secret_id"`
				Name      string            `json:"name"`
				CreatedAt time.Time         `json:"created_at"`
				UpdatedAt time.Time         `json:"updated_at"`
				Metadata  map[string]string `json:"metadata"`
			} `json:"secrets"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Record sync metrics
		metrics := map[string]interface{}{
			"total_secrets": len(req.Secrets),
			"sync_time":     time.Now(),
		}

		service.RecordMetrics(c.Request.Context(), req.AgentID, "default", metrics)
		c.JSON(http.StatusOK, gin.H{"status": "synced"})
	}
}

func handleListAgents(service *registry.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		agents, err := service.ListAgents(c.Request.Context(), "default")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list agents"})
			return
		}
		c.JSON(http.StatusOK, agents)
	}
}

func handleGetAgent(service *registry.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		agentID := c.Param("id")
		agent, err := service.GetAgent(c.Request.Context(), agentID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
			return
		}
		c.JSON(http.StatusOK, agent)
	}
}

func handleCreatePolicy(service *policy.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var policy policy.Policy
		if err := c.ShouldBindJSON(&policy); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		policy.OrganizationID = "default"
		if err := service.CreatePolicy(c.Request.Context(), &policy); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create policy"})
			return
		}

		c.JSON(http.StatusCreated, policy)
	}
}

func handleListPolicies(service *policy.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		policies, err := service.ListPolicies(c.Request.Context(), "default")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list policies"})
			return
		}
		c.JSON(http.StatusOK, policies)
	}
}

func handleGetPolicy(service *policy.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		policyID := c.Param("id")
		policy, err := service.GetPolicy(c.Request.Context(), policyID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
			return
		}
		c.JSON(http.StatusOK, policy)
	}
}

func handleAssignPolicy(service *policy.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			AgentID string `json:"agent_id"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		policyID := c.Param("id")
		assignment := &policy.PolicyAssignment{
			ID:             policyID + "_" + req.AgentID,
			PolicyID:       policyID,
			AgentID:        req.AgentID,
			OrganizationID: "default",
		}

		if err := service.AssignPolicy(c.Request.Context(), assignment); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign policy"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "assigned"})
	}
}

func handleBulkAssignPolicy(service *policy.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			PolicyID string   `json:"policy_id"`
			AgentIDs []string `json:"agent_ids"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := service.BulkAssignPolicy(c.Request.Context(), req.PolicyID, "default", req.AgentIDs); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to bulk assign policy"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "assigned", "count": len(req.AgentIDs)})
	}
}

func handleUsageReport(service *analytics.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("orgId")
		period := c.DefaultQuery("period", "daily")

		report, err := service.GenerateUsageReport(c.Request.Context(), orgID, period)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate report"})
			return
		}

		c.JSON(http.StatusOK, report)
	}
}

func handleCapacityMetrics(service *analytics.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("orgId")

		metrics, err := service.GenerateCapacityMetrics(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate metrics"})
			return
		}

		c.JSON(http.StatusOK, metrics)
	}
}

func handleMetricsHistory(service *analytics.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("orgId")
		hours := 24 // Default to 24 hours

		metrics, err := service.GetMetricsHistory(c.Request.Context(), orgID, hours)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get metrics"})
			return
		}

		c.JSON(http.StatusOK, metrics)
	}
}

func handleDashboardData(service *dashboard.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("orgId")

		data, err := service.GetDashboardData(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get dashboard data"})
			return
		}

		c.JSON(http.StatusOK, data)
	}
}

func handleAgentDetails(service *dashboard.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		agentID := c.Param("id")

		details, err := service.GetAgentDetails(c.Request.Context(), agentID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get agent details"})
			return
		}

		c.JSON(http.StatusOK, details)
	}
}

func handleCreateOrganization(service *users.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var org users.Organization
		if err := c.ShouldBindJSON(&org); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := service.CreateOrganization(c.Request.Context(), &org); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create organization"})
			return
		}

		c.JSON(http.StatusCreated, org)
	}
}

func handleCreateUser(service *users.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			User     users.User `json:"user"`
			Password string     `json:"password"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := service.CreateUser(c.Request.Context(), &req.User, req.Password); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		c.JSON(http.StatusCreated, req.User)
	}
}

func handleAuthenticateUser(service *users.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user, err := service.AuthenticateUser(c.Request.Context(), req.Email, req.Password)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		c.JSON(http.StatusOK, user)
	}
}

func handleListUsers(service *users.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("orgId")

		users, err := service.ListUsers(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
			return
		}

		c.JSON(http.StatusOK, users)
	}
}
