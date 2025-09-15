package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/keyvault/agent/internal/handlers"
	"github.com/keyvault/agent/internal/storage"
)

// RouterConfig contains configuration for the API router
type RouterConfig struct {
	Storage         storage.StorageBackend
	Version         string
	EnableSwagger   bool
	EnableCORS      bool
	TrustedProxies  []string
}

// NewRouter creates a new Gin router with all API endpoints configured
func NewRouter(config *RouterConfig) *gin.Engine {
	// Set Gin mode based on environment
	gin.SetMode(gin.ReleaseMode)
	
	router := gin.New()

	// Configure trusted proxies
	if len(config.TrustedProxies) > 0 {
		router.SetTrustedProxies(config.TrustedProxies)
	}

	// Global middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(RequestIDMiddleware())
	router.Use(ResponseTimeMiddleware())
	router.Use(SecurityHeadersMiddleware())
	router.Use(APIVersionMiddleware())
	router.Use(ErrorHandlingMiddleware())

	// CORS middleware (optional)
	if config.EnableCORS {
		router.Use(CORSMiddleware())
	}

	// Create handlers
	secretHandler := NewSecretHandler(config.Storage)
	healthHandler := NewHealthHandler(config.Storage, config.Version)
	webHandler := handlers.NewWebHandler()
	systemHandler := NewSystemHandler()
	analyticsHandler := NewAnalyticsHandler()
	policiesHandler := NewPoliciesHandler()
	usersHandler := NewUsersHandler()

	// Health check endpoint (no authentication required)
	router.GET("/health", healthHandler.GetHealth)

	// Authentication endpoints (no auth required)
	auth := router.Group("/api/v1/auth")
	{
		auth.POST("/login", LoginHandler)
	}

	// Swagger documentation (optional)
	if config.EnableSwagger {
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		router.GET("/docs", func(c *gin.Context) {
			c.Redirect(http.StatusMovedPermanently, "/swagger/index.html")
		})
	}

	// API version 1 routes (with authentication)
	v1 := router.Group("/api/v1")
	v1.Use(AuthMiddleware()) // Apply authentication to all API routes
	{
		// Secrets endpoints
		secrets := v1.Group("/secrets")
		{
			secrets.POST("", secretHandler.CreateSecret)
			secrets.GET("", secretHandler.ListSecrets)
			secrets.GET("/:id", secretHandler.GetSecret)
			secrets.GET("/:id/value", secretHandler.GetSecretValue)
			secrets.PUT("/:id", secretHandler.UpdateSecret)
			secrets.DELETE("/:id", secretHandler.DeleteSecret)
			secrets.POST("/:id/rotate", secretHandler.RotateSecret)
			secrets.GET("/tags", secretHandler.GetSecretTags)
		}

		// Backup endpoints
		backupHandler := NewBackupHandler(nil) // Will be properly initialized
		backup := v1.Group("/backup")
		{
			backup.POST("", backupHandler.CreateBackup)
			backup.GET("", backupHandler.ListBackups)
			backup.POST("/:id/restore", backupHandler.RestoreBackup)
		}

		// System endpoints
		system := v1.Group("/system")
		{
			system.GET("/stats", systemHandler.GetSystemStats)
			system.GET("/health", systemHandler.GetSystemHealth)
			system.GET("/activity", systemHandler.GetRecentActivity)
			system.GET("/control-plane", systemHandler.GetControlPlaneStatus)
			system.GET("/security", systemHandler.GetSecurityStatus)
		}

		// Analytics endpoints
		analytics := v1.Group("/analytics")
		{
			analytics.GET("/access-patterns", analyticsHandler.GetAccessPatterns)
			analytics.GET("/request-volume", analyticsHandler.GetRequestVolume)
			analytics.GET("/response-times", analyticsHandler.GetResponseTimes)
			analytics.GET("/error-rates", analyticsHandler.GetErrorRates)
		}

		// Metrics endpoints (for performance charts)
		metrics := v1.Group("/metrics")
		{
			metrics.GET("/performance", analyticsHandler.GetResponseTimes)
		}

		// Policies endpoints
		v1.GET("/policies", policiesHandler.ListPolicies)

		// Users endpoints  
		users := v1.Group("/users")
		{
			users.GET("", usersHandler.ListUsers)
			users.POST("", usersHandler.CreateUser)
			users.PUT("/:id", usersHandler.UpdateUser)
			users.DELETE("/:id", usersHandler.DeleteUser)
			users.PUT("/:id/password", usersHandler.ResetUserPassword)
		}

		// Metrics endpoint
		v1.GET("/metrics", func(c *gin.Context) {
			// Basic metrics response - will be enhanced with Prometheus metrics
			metrics := &MetricsResponse{
				TotalSecrets:    0, // Would be populated from storage
				ActiveSecrets:   0,
				ExpiredSecrets:  0,
				RequestsPerSec:  0.0,
				AvgResponseTime: 0.0,
				Uptime:          "0s",
				LastUpdated:     GetCurrentTime(),
			}

			response := APIResponse{
				Success:   true,
				Data:      metrics,
				RequestID: GetRequestID(c),
				Timestamp: GetCurrentTime(),
			}

			c.JSON(http.StatusOK, response)
		})
	}

	// Setup web interface routes
	webHandler.SetupWebRoutes(router)

	return router
}

// SetupRoutes is a convenience function to set up routes with default configuration
func SetupRoutes(storage storage.StorageBackend, version string) *gin.Engine {
	config := &RouterConfig{
		Storage:       storage,
		Version:       version,
		EnableSwagger: true,
		EnableCORS:    true,
	}
	return NewRouter(config)
}