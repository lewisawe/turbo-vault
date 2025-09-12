package monitoring

import (
	"context"
	"time"
)

// MonitoringService defines the interface for monitoring vault agents
type MonitoringService interface {
	// StartMonitoring starts the monitoring service
	StartMonitoring(ctx context.Context) error
	
	// StopMonitoring stops the monitoring service
	StopMonitoring() error
	
	// CheckVaultHealth checks the health of a specific vault
	CheckVaultHealth(ctx context.Context, vaultID string) (*VaultHealthStatus, error)
	
	// CheckAllVaults checks the health of all registered vaults
	CheckAllVaults(ctx context.Context) ([]VaultHealthStatus, error)
	
	// GetMonitoringStats returns aggregated monitoring statistics
	GetMonitoringStats(ctx context.Context) (*MonitoringStats, error)
	
	// GetEvents retrieves monitoring events with filtering
	GetEvents(ctx context.Context, filter *EventFilter) ([]MonitoringEvent, error)
	
	// CreateAlertRule creates a new alert rule
	CreateAlertRule(ctx context.Context, rule *AlertRule) error
	
	// UpdateAlertRule updates an existing alert rule
	UpdateAlertRule(ctx context.Context, ruleID string, rule *AlertRule) error
	
	// DeleteAlertRule deletes an alert rule
	DeleteAlertRule(ctx context.Context, ruleID string) error
	
	// GetAlertRules retrieves all alert rules
	GetAlertRules(ctx context.Context) ([]AlertRule, error)
}

// EventStorage defines the interface for storing monitoring events
type EventStorage interface {
	// CreateEvent creates a new monitoring event
	CreateEvent(ctx context.Context, event *MonitoringEvent) error
	
	// GetEvents retrieves events with filtering and pagination
	GetEvents(ctx context.Context, filter *EventFilter) ([]MonitoringEvent, error)
	
	// UpdateEvent updates an existing event
	UpdateEvent(ctx context.Context, eventID string, event *MonitoringEvent) error
	
	// ResolveEvent marks an event as resolved
	ResolveEvent(ctx context.Context, eventID string) error
	
	// GetActiveEvents retrieves all unresolved events
	GetActiveEvents(ctx context.Context) ([]MonitoringEvent, error)
	
	// GetEventsByVault retrieves events for a specific vault
	GetEventsByVault(ctx context.Context, vaultID string, since time.Time) ([]MonitoringEvent, error)
	
	// DeleteOldEvents deletes events older than the specified duration
	DeleteOldEvents(ctx context.Context, olderThan time.Duration) error
}

// AlertRuleStorage defines the interface for storing alert rules
type AlertRuleStorage interface {
	// CreateRule creates a new alert rule
	CreateRule(ctx context.Context, rule *AlertRule) error
	
	// GetRule retrieves an alert rule by ID
	GetRule(ctx context.Context, ruleID string) (*AlertRule, error)
	
	// UpdateRule updates an existing alert rule
	UpdateRule(ctx context.Context, ruleID string, rule *AlertRule) error
	
	// DeleteRule deletes an alert rule
	DeleteRule(ctx context.Context, ruleID string) error
	
	// ListRules retrieves all alert rules
	ListRules(ctx context.Context) ([]AlertRule, error)
	
	// GetEnabledRules retrieves all enabled alert rules
	GetEnabledRules(ctx context.Context) ([]AlertRule, error)
}

// EventFilter represents filtering options for monitoring events
type EventFilter struct {
	VaultID     string              `json:"vault_id"`
	EventType   MonitoringEventType `json:"event_type"`
	Severity    Severity            `json:"severity"`
	Resolved    *bool               `json:"resolved"`
	Since       *time.Time          `json:"since"`
	Until       *time.Time          `json:"until"`
	Limit       int                 `json:"limit"`
	Offset      int                 `json:"offset"`
}

// NotificationService defines the interface for sending notifications
type NotificationService interface {
	// SendAlert sends an alert notification
	SendAlert(ctx context.Context, event *MonitoringEvent, channels []string) error
	
	// SendBulkAlert sends alerts to multiple channels
	SendBulkAlert(ctx context.Context, events []MonitoringEvent, channels []string) error
}