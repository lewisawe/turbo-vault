package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
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

	// Health check endpoint (no authentication required)
	router.GET("/health", healthHandler.GetHealth)

	// Swagger documentation (optional)
	if config.EnableSwagger {
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		router.GET("/docs", func(c *gin.Context) {
			c.Redirect(http.StatusMovedPermanently, "/swagger/index.html")
		})
	}

	// API version 1 routes
	v1 := router.Group("/api/v1")
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

	// Static file serving for web interface (if needed)
	router.Static("/static", "./web/static")
	router.StaticFile("/", "./web/index.html")

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