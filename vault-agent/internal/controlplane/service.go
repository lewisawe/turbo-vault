package controlplane

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"sync"
	"time"

	"github.com/keyvault/agent/internal/config"
	"github.com/keyvault/agent/internal/offline"
	"github.com/keyvault/agent/internal/storage"
)

// Service manages control plane communication with offline support
type Service struct {
	client          *Client
	config          *config.ControlPlaneConfig
	storage         *storage.Storage
	offlineDetector *offline.Detector
	
	// State management
	isOnline        bool
	lastSync        time.Time
	retryCount      int
	maxRetries      int
	
	// Circuit breaker
	circuitOpen     bool
	circuitOpenTime time.Time
	failureCount    int
	
	// Synchronization
	mu       sync.RWMutex
	stopCh   chan struct{}
	syncCh   chan struct{}
}

// NewService creates a new control plane service
func NewService(cfg *config.ControlPlaneConfig, storage *storage.Storage, agentID string) (*Service, error) {
	if !cfg.Enabled {
		return &Service{
			config:  cfg,
			storage: storage,
			stopCh:  make(chan struct{}),
		}, nil
	}

	client, err := NewClient(cfg, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to create control plane client: %w", err)
	}

	offlineDetector := offline.NewDetector(cfg)

	service := &Service{
		client:          client,
		config:          cfg,
		storage:         storage,
		offlineDetector: offlineDetector,
		maxRetries:      cfg.MaxRetries,
		stopCh:          make(chan struct{}),
		syncCh:          make(chan struct{}, 1),
	}

	return service, nil
}

// Start starts the control plane service
func (s *Service) Start(ctx context.Context) error {
	if !s.config.Enabled {
		log.Println("Control plane communication disabled, running in offline mode")
		return nil
	}

	// Start offline detector
	if err := s.offlineDetector.Start(ctx); err != nil {
		return fmt.Errorf("failed to start offline detector: %w", err)
	}

	// Subscribe to offline status changes
	statusCh := s.offlineDetector.Subscribe()
	go s.handleStatusChanges(statusCh)

	// Start background tasks
	go s.heartbeatLoop(ctx)
	go s.syncLoop(ctx)

	// Initial registration
	if err := s.register(ctx); err != nil {
		log.Printf("Initial registration failed: %v", err)
	}

	return nil
}

// Stop stops the control plane service
func (s *Service) Stop() error {
	close(s.stopCh)
	
	if s.offlineDetector != nil {
		s.offlineDetector.Stop()
	}
	
	if s.client != nil {
		return s.client.Close()
	}
	
	return nil
}

// TriggerSync triggers immediate metadata synchronization
func (s *Service) TriggerSync() {
	select {
	case s.syncCh <- struct{}{}:
	default:
		// Channel full, sync already pending
	}
}

// IsOnline returns current online status
func (s *Service) IsOnline() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isOnline
}

// register registers the agent with control plane
func (s *Service) register(ctx context.Context) error {
	if s.circuitOpen {
		return fmt.Errorf("circuit breaker is open")
	}

	req := &RegistrationRequest{
		Version:      "1.0.0",
		Hostname:     getHostname(),
		Capabilities: []string{"secrets", "rotation", "audit"},
		Metadata: map[string]string{
			"storage_type": s.storage.GetType(),
			"version":      "1.0.0",
		},
	}

	return s.executeWithRetry(ctx, func() error {
		return s.client.Register(ctx, req)
	})
}

// heartbeatLoop sends periodic heartbeats
func (s *Service) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			if s.IsOnline() && !s.circuitOpen {
				s.sendHeartbeat(ctx)
			}
		}
	}
}

// syncLoop handles metadata synchronization
func (s *Service) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute) // Sync every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			if s.IsOnline() && !s.circuitOpen {
				s.syncMetadata(ctx)
			}
		case <-s.syncCh:
			if s.IsOnline() && !s.circuitOpen {
				s.syncMetadata(ctx)
			}
		}
	}
}

// sendHeartbeat sends heartbeat to control plane
func (s *Service) sendHeartbeat(ctx context.Context) {
	metrics, err := s.storage.GetMetrics()
	if err != nil {
		log.Printf("Failed to get metrics for heartbeat: %v", err)
		metrics = make(map[string]interface{})
	}

	req := &HeartbeatRequest{
		Status:  "healthy",
		Metrics: metrics,
	}

	err = s.executeWithRetry(ctx, func() error {
		return s.client.Heartbeat(ctx, req)
	})

	if err != nil {
		log.Printf("Heartbeat failed: %v", err)
	}
}

// syncMetadata synchronizes secret metadata
func (s *Service) syncMetadata(ctx context.Context) {
	secrets, err := s.storage.ListAllSecrets()
	if err != nil {
		log.Printf("Failed to list secrets for sync: %v", err)
		return
	}

	metadata := make([]MetadataSync, len(secrets))
	for i, secret := range secrets {
		metadata[i] = MetadataSync{
			SecretID:    secret.ID,
			Name:        secret.Name,
			CreatedAt:   secret.CreatedAt,
			UpdatedAt:   secret.UpdatedAt,
			ExpiresAt:   secret.ExpiresAt,
			RotationDue: secret.RotationDue,
			Metadata:    secret.Metadata,
			Tags:        secret.Tags,
		}
	}

	err = s.executeWithRetry(ctx, func() error {
		return s.client.SyncMetadata(ctx, metadata)
	})

	if err != nil {
		log.Printf("Metadata sync failed: %v", err)
	} else {
		s.mu.Lock()
		s.lastSync = time.Now()
		s.mu.Unlock()
	}
}

// executeWithRetry executes operation with exponential backoff retry
func (s *Service) executeWithRetry(ctx context.Context, operation func() error) error {
	var lastErr error
	
	for attempt := 0; attempt <= s.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * s.config.RetryInterval
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		lastErr = operation()
		if lastErr == nil {
			s.onSuccess()
			return nil
		}

		log.Printf("Operation failed (attempt %d/%d): %v", attempt+1, s.maxRetries+1, lastErr)
	}

	s.onFailure()
	return fmt.Errorf("operation failed after %d attempts: %w", s.maxRetries+1, lastErr)
}

// handleStatusChanges handles offline detector status changes
func (s *Service) handleStatusChanges(statusCh <-chan offline.Status) {
	for status := range statusCh {
		s.mu.Lock()
		wasOnline := s.isOnline
		s.isOnline = status.Mode == offline.ModeOnline
		s.mu.Unlock()

		if !wasOnline && s.isOnline {
			log.Println("Control plane connection restored")
			// Trigger immediate sync when coming back online
			s.TriggerSync()
		} else if wasOnline && !s.isOnline {
			log.Println("Control plane connection lost, entering offline mode")
		}
	}
}

// onSuccess handles successful operation
func (s *Service) onSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.retryCount = 0
	s.failureCount = 0
	s.circuitOpen = false
}

// onFailure handles failed operation
func (s *Service) onFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.failureCount++
	if s.failureCount >= 5 {
		s.circuitOpen = true
		s.circuitOpenTime = time.Now()
		log.Println("Circuit breaker opened due to consecutive failures")
	}
}

// getHostname returns the system hostname
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
