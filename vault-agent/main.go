package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/keyvault/agent/internal/api"
	"github.com/keyvault/agent/internal/config"
	"github.com/keyvault/agent/internal/controlplane"
	"github.com/keyvault/agent/internal/crypto"
	"github.com/keyvault/agent/internal/storage"
)

const Version = "1.0.0"

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// Generate or load agent ID
	agentID := getOrCreateAgentID()
	log.Printf("Agent ID: %s", agentID)

	// Initialize crypto service
	cryptoService, err := crypto.NewCryptoService(&cfg.KeyManager)
	if err != nil {
		log.Fatal("Failed to initialize crypto service:", err)
	}

	// Initialize storage with crypto service
	store, err := storage.NewStorage(&cfg.Database, cryptoService)
	if err != nil {
		log.Fatal("Failed to initialize storage:", err)
	}
	defer store.Close()

	// Start performance monitoring if enabled
	if cfg.Performance.Metrics.Enabled {
		if err := store.StartPerformanceMonitoring(ctx); err != nil {
			log.Printf("Warning: Failed to start performance monitoring: %v", err)
		}
	}

	// Initialize control plane service
	cpService, err := controlplane.NewService(&cfg.ControlPlane, store, agentID)
	if err != nil {
		log.Fatal("Failed to initialize control plane service:", err)
	}

	// Start control plane service
	if err := cpService.Start(ctx); err != nil {
		log.Printf("Warning: Failed to start control plane service: %v", err)
	}
	defer cpService.Stop()

	// Setup API router with enhanced configuration
	routerConfig := &api.RouterConfig{
		Storage:        store,
		Version:        Version,
		EnableSwagger:  true,
		EnableCORS:     true,
		TrustedProxies: []string{},
	}
	
	router := api.NewRouter(routerConfig)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = strconv.Itoa(cfg.Server.Port)
	}
	
	log.Printf("Starting Vault Agent v%s on %s:%s", Version, cfg.Server.Host, port)
	log.Printf("API documentation available at: http://localhost:%s/swagger/index.html", port)
	
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in goroutine
	go func() {
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

// getOrCreateAgentID generates or loads persistent agent ID
func getOrCreateAgentID() string {
	idFile := "./data/agent.id"
	
	// Try to load existing ID
	if data, err := os.ReadFile(idFile); err == nil {
		return string(data)
	}

	// Generate new ID
	agentID := uuid.New().String()
	
	// Save ID
	os.MkdirAll("./data", 0755)
	if err := os.WriteFile(idFile, []byte(agentID), 0644); err != nil {
		log.Printf("Warning: Failed to save agent ID: %v", err)
	}

	return agentID
}