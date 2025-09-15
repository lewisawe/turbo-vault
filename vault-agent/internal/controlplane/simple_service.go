package controlplane

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/keyvault/agent/internal/config"
	"github.com/keyvault/agent/internal/storage"
)

// SimpleService provides basic control plane functionality without external dependencies
type SimpleService struct {
	config    *config.ControlPlaneConfig
	storage   storage.StorageBackend
	agentID   string
	active    bool
	mu        sync.RWMutex
	stopCh    chan struct{}
	lastSync  time.Time
	metrics   *ControlPlaneMetrics
}

// ControlPlaneMetrics tracks control plane metrics
type ControlPlaneMetrics struct {
	SyncCount     int64     `json:"sync_count"`
	LastSync      time.Time `json:"last_sync"`
	ErrorCount    int64     `json:"error_count"`
	Status        string    `json:"status"`
	AgentID       string    `json:"agent_id"`
	ConnectedTime time.Time `json:"connected_time"`
}

// NewSimpleService creates a new simple control plane service
func NewSimpleService(cfg *config.ControlPlaneConfig, storage storage.StorageBackend, agentID string) *SimpleService {
	return &SimpleService{
		config:  cfg,
		storage: storage,
		agentID: agentID,
		stopCh:  make(chan struct{}),
		metrics: &ControlPlaneMetrics{
			AgentID:       agentID,
			Status:        "initializing",
			ConnectedTime: time.Now(),
		},
	}
}

// Start starts the control plane service
func (s *SimpleService) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.config.Enabled {
		log.Println("Control plane disabled, running in standalone mode")
		s.metrics.Status = "standalone"
		return nil
	}

	log.Printf("Starting Simple Control Plane Service for agent %s", s.agentID)
	
	s.active = true
	s.metrics.Status = "connected"
	s.lastSync = time.Now()
	s.metrics.LastSync = s.lastSync

	// Start background sync routine
	go s.syncRoutine(ctx)
	
	log.Println("Simple Control Plane Service started successfully")
	return nil
}

// Stop stops the control plane service
func (s *SimpleService) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return
	}

	log.Println("Stopping Simple Control Plane Service...")
	close(s.stopCh)
	s.active = false
	s.metrics.Status = "stopped"
	log.Println("Simple Control Plane Service stopped")
}

// GetMetrics returns control plane metrics
func (s *SimpleService) GetMetrics() *ControlPlaneMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	metrics := *s.metrics
	return &metrics
}

// GetStatus returns the current status
func (s *SimpleService) GetStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"active":         s.active,
		"agent_id":       s.agentID,
		"last_sync":      s.lastSync.Format(time.RFC3339),
		"sync_count":     s.metrics.SyncCount,
		"error_count":    s.metrics.ErrorCount,
		"status":         s.metrics.Status,
		"connected_time": s.metrics.ConnectedTime.Format(time.RFC3339),
		"uptime_seconds": int64(time.Since(s.metrics.ConnectedTime).Seconds()),
	}
}

// syncRoutine runs the background sync process
func (s *SimpleService) syncRoutine(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute) // Sync every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.performSync()
		}
	}
}

// performSync performs a sync with the control plane
func (s *SimpleService) performSync() {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Println("Performing control plane sync...")
	
	// Simulate sync operation
	s.metrics.SyncCount++
	s.lastSync = time.Now()
	s.metrics.LastSync = s.lastSync
	
	// In a real implementation, this would:
	// 1. Send agent status to control plane
	// 2. Receive policy updates
	// 3. Report metrics and health
	// 4. Handle configuration changes
	
	log.Printf("Control plane sync completed (count: %d)", s.metrics.SyncCount)
}

// RegisterAgent registers this agent with the control plane
func (s *SimpleService) RegisterAgent() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("Registering agent %s with control plane", s.agentID)
	
	// In a real implementation, this would send registration to control plane
	registration := map[string]interface{}{
		"agent_id":    s.agentID,
		"timestamp":   time.Now(),
		"version":     "1.0.0",
		"capabilities": []string{"secrets", "encryption", "monitoring"},
	}
	
	registrationJSON, _ := json.Marshal(registration)
	log.Printf("Agent registration: %s", string(registrationJSON))
	
	return nil
}

// SendHeartbeat sends a heartbeat to the control plane
func (s *SimpleService) SendHeartbeat() error {
	if !s.active {
		return nil
	}

	log.Printf("Sending heartbeat for agent %s", s.agentID)
	
	// In a real implementation, this would send heartbeat to control plane
	heartbeat := map[string]interface{}{
		"agent_id":  s.agentID,
		"timestamp": time.Now(),
		"status":    "healthy",
	}
	
	heartbeatJSON, _ := json.Marshal(heartbeat)
	log.Printf("Heartbeat: %s", string(heartbeatJSON))
	
	return nil
}
