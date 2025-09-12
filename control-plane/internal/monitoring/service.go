package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/keyvault/control-plane/internal/registry"
)

// Service implements the MonitoringService interface
type Service struct {
	registry         registry.VaultRegistry
	eventStorage     EventStorage
	ruleStorage      AlertRuleStorage
	notification     NotificationService
	config           MonitoringConfig
	ticker           *time.Ticker
	stopChan         chan struct{}
	mu               sync.RWMutex
	running          bool
}

// NewService creates a new monitoring service
func NewService(
	registry registry.VaultRegistry,
	eventStorage EventStorage,
	ruleStorage AlertRuleStorage,
	notification NotificationService,
	config MonitoringConfig,
) *Service {
	return &Service{
		registry:     registry,
		eventStorage: eventStorage,
		ruleStorage:  ruleStorage,
		notification: notification,
		config:       config,
		stopChan:     make(chan struct{}),
	}
}

// StartMonitoring starts the monitoring service
func (s *Service) StartMonitoring(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("monitoring service is already running")
	}

	s.ticker = time.NewTicker(time.Duration(s.config.CheckIntervalSeconds) * time.Second)
	s.running = true

	go s.monitoringLoop(ctx)
	return nil
}

// StopMonitoring stops the monitoring service
func (s *Service) StopMonitoring() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return fmt.Errorf("monitoring service is not running")
	}

	close(s.stopChan)
	s.ticker.Stop()
	s.running = false
	return nil
}

// CheckVaultHealth checks the health of a specific vault
func (s *Service) CheckVaultHealth(ctx context.Context, vaultID string) (*VaultHealthStatus, error) {
	vault, err := s.registry.GetVault(ctx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault: %w", err)
	}

	return s.calculateHealthStatus(vault), nil
}

// CheckAllVaults checks the health of all registered vaults
func (s *Service) CheckAllVaults(ctx context.Context) ([]VaultHealthStatus, error) {
	vaults, err := s.registry.ListVaults(ctx, &registry.VaultFilter{})
	if err != nil {
		return nil, fmt.Errorf("failed to list vaults: %w", err)
	}

	healthStatuses := make([]VaultHealthStatus, len(vaults.Vaults))
	for i, vault := range vaults.Vaults {
		healthStatuses[i] = *s.calculateHealthStatus(&vault)
	}

	return healthStatuses, nil
}

// GetMonitoringStats returns aggregated monitoring statistics
func (s *Service) GetMonitoringStats(ctx context.Context) (*MonitoringStats, error) {
	// Get vault counts by status
	vaults, err := s.registry.ListVaults(ctx, &registry.VaultFilter{})
	if err != nil {
		return nil, fmt.Errorf("failed to list vaults: %w", err)
	}

	stats := &MonitoringStats{
		TotalVaults:      len(vaults.Vaults),
		EventsByType:     make(map[MonitoringEventType]int),
		EventsBySeverity: make(map[Severity]int),
		GeneratedAt:      time.Now(),
	}

	// Count vaults by status
	for _, vault := range vaults.Vaults {
		switch vault.Status {
		case registry.VaultStatusOnline:
			stats.OnlineVaults++
		case registry.VaultStatusOffline:
			stats.OfflineVaults++
		case registry.VaultStatusDegraded:
			stats.DegradedVaults++
		}
	}

	// Get active events
	activeEvents, err := s.eventStorage.GetActiveEvents(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active events: %w", err)
	}

	stats.ActiveAlerts = len(activeEvents)

	// Count events by type and severity
	for _, event := range activeEvents {
		stats.EventsByType[event.EventType]++
		stats.EventsBySeverity[event.Severity]++
	}

	return stats, nil
}

// GetEvents retrieves monitoring events with filtering
func (s *Service) GetEvents(ctx context.Context, filter *EventFilter) ([]MonitoringEvent, error) {
	return s.eventStorage.GetEvents(ctx, filter)
}

// CreateAlertRule creates a new alert rule
func (s *Service) CreateAlertRule(ctx context.Context, rule *AlertRule) error {
	rule.ID = uuid.New().String()
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	
	return s.ruleStorage.CreateRule(ctx, rule)
}

// UpdateAlertRule updates an existing alert rule
func (s *Service) UpdateAlertRule(ctx context.Context, ruleID string, rule *AlertRule) error {
	rule.UpdatedAt = time.Now()
	return s.ruleStorage.UpdateRule(ctx, ruleID, rule)
}

// DeleteAlertRule deletes an alert rule
func (s *Service) DeleteAlertRule(ctx context.Context, ruleID string) error {
	return s.ruleStorage.DeleteRule(ctx, ruleID)
}

// GetAlertRules retrieves all alert rules
func (s *Service) GetAlertRules(ctx context.Context) ([]AlertRule, error) {
	return s.ruleStorage.ListRules(ctx)
}

// monitoringLoop runs the main monitoring loop
func (s *Service) monitoringLoop(ctx context.Context) {
	for {
		select {
		case <-s.ticker.C:
			s.performHealthChecks(ctx)
		case <-s.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// performHealthChecks performs health checks on all vaults
func (s *Service) performHealthChecks(ctx context.Context) {
	// Check for offline vaults
	offlineVaults, err := s.registry.GetOfflineVaults(ctx, s.config.HeartbeatTimeoutMinutes)
	if err != nil {
		fmt.Printf("Error checking offline vaults: %v\n", err)
		return
	}

	// Process offline vaults
	for _, vault := range offlineVaults {
		if vault.Status != registry.VaultStatusOffline {
			// Update vault status to offline
			s.registry.UpdateVaultStatus(ctx, vault.ID, registry.VaultStatusOffline)
			
			// Create offline event
			event := &MonitoringEvent{
				ID:        uuid.New().String(),
				VaultID:   vault.ID,
				EventType: EventTypeVaultOffline,
				Severity:  SeverityError,
				Message:   fmt.Sprintf("Vault %s has gone offline", vault.Name),
				Details: map[string]interface{}{
					"last_heartbeat": vault.LastHeartbeat,
					"vault_name":     vault.Name,
				},
				Timestamp: time.Now(),
				Resolved:  false,
			}

			if err := s.eventStorage.CreateEvent(ctx, event); err != nil {
				fmt.Printf("Error creating offline event: %v\n", err)
				continue
			}

			// Send notification
			if err := s.notification.SendAlert(ctx, event, s.config.NotificationChannels); err != nil {
				fmt.Printf("Error sending offline notification: %v\n", err)
			}
		}
	}

	// Check for performance issues
	s.checkPerformanceIssues(ctx)
}

// checkPerformanceIssues checks for performance-related issues
func (s *Service) checkPerformanceIssues(ctx context.Context) {
	vaults, err := s.registry.ListVaults(ctx, &registry.VaultFilter{
		Status: registry.VaultStatusOnline,
	})
	if err != nil {
		return
	}

	for _, vault := range vaults.Vaults {
		// Check error rate
		if vault.Metrics.ErrorRate > 0.05 { // 5% error rate threshold
			event := &MonitoringEvent{
				ID:        uuid.New().String(),
				VaultID:   vault.ID,
				EventType: EventTypeHighErrorRate,
				Severity:  SeverityWarning,
				Message:   fmt.Sprintf("High error rate detected for vault %s: %.2f%%", vault.Name, vault.Metrics.ErrorRate*100),
				Details: map[string]interface{}{
					"error_rate":  vault.Metrics.ErrorRate,
					"vault_name":  vault.Name,
				},
				Timestamp: time.Now(),
				Resolved:  false,
			}

			s.eventStorage.CreateEvent(ctx, event)
			s.notification.SendAlert(ctx, event, s.config.NotificationChannels)
		}

		// Check response time
		if vault.Metrics.AverageLatency > 1000 { // 1 second threshold
			event := &MonitoringEvent{
				ID:        uuid.New().String(),
				VaultID:   vault.ID,
				EventType: EventTypePerformanceDegraded,
				Severity:  SeverityWarning,
				Message:   fmt.Sprintf("High latency detected for vault %s: %.2fms", vault.Name, vault.Metrics.AverageLatency),
				Details: map[string]interface{}{
					"average_latency": vault.Metrics.AverageLatency,
					"vault_name":      vault.Name,
				},
				Timestamp: time.Now(),
				Resolved:  false,
			}

			s.eventStorage.CreateEvent(ctx, event)
			s.notification.SendAlert(ctx, event, s.config.NotificationChannels)
		}
	}
}

// calculateHealthStatus calculates the health status for a vault
func (s *Service) calculateHealthStatus(vault *registry.VaultAgent) *VaultHealthStatus {
	status := &VaultHealthStatus{
		VaultID:           vault.ID,
		Status:            string(vault.Status),
		LastHeartbeat:     vault.LastHeartbeat,
		ResponseTime:      vault.Metrics.AverageLatency,
		ErrorRate:         vault.Metrics.ErrorRate,
		RequestsPerSecond: vault.Metrics.RequestsPerSecond,
		Issues:            []string{},
		CheckedAt:         time.Now(),
	}

	// Calculate health score (0-100)
	healthScore := 100.0

	// Deduct points for high error rate
	if vault.Metrics.ErrorRate > 0.01 {
		healthScore -= vault.Metrics.ErrorRate * 1000 // 1% error = 10 points
	}

	// Deduct points for high latency
	if vault.Metrics.AverageLatency > 100 {
		healthScore -= (vault.Metrics.AverageLatency - 100) / 10 // Every 10ms over 100ms = 1 point
	}

	// Deduct points for being offline
	if vault.Status == registry.VaultStatusOffline {
		healthScore = 0
		status.Issues = append(status.Issues, "Vault is offline")
	}

	// Check for stale heartbeat
	if time.Since(vault.LastHeartbeat) > time.Duration(s.config.HeartbeatTimeoutMinutes)*time.Minute {
		healthScore -= 50
		status.Issues = append(status.Issues, "Stale heartbeat")
	}

	if healthScore < 0 {
		healthScore = 0
	}

	status.HealthScore = healthScore
	return status
}
