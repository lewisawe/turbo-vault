package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/keyvault/agent/internal/config"
	"github.com/keyvault/agent/internal/handlers"
	"github.com/keyvault/agent/internal/storage"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// Initialize storage
	store, err := storage.New(cfg.Database)
	if err != nil {
		log.Fatal("Failed to initialize storage:", err)
	}
	defer store.Close()

	// Setup router
	r := gin.Default()
	
	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// API routes
	api := r.Group("/api/v1")
	{
		secrets := api.Group("/secrets")
		{
			secrets.POST("", handlers.CreateSecret(store))
			secrets.GET("/:id", handlers.GetSecret(store))
			secrets.PUT("/:id", handlers.UpdateSecret(store))
			secrets.DELETE("/:id", handlers.DeleteSecret(store))
			secrets.GET("", handlers.ListSecrets(store))
			secrets.POST("/:id/rotate", handlers.RotateSecret(store))
		}
		
		api.GET("/metrics", handlers.GetMetrics(store))
	}

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("Starting KeyVault Agent on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}