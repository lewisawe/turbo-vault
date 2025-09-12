package monitoring

import (
	"time"
)

// MonitoringEvent represents a monitoring event
type MonitoringEvent struct {
	ID          string                 `json:"id"`
	VaultID     string                 `json:"vault_id"`
	EventType   MonitoringEventType    `json:"event_type"`
	Severity    Severity               `json:"severity"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
	Timestamp   time.Time              `json:"timestamp"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
}

// MonitoringEventType represents the type of monitoring event
type MonitoringEventType string

const (
	EventTypeHeartbeatMissed   MonitoringEventType = "heartbeat_missed"
	EventTypeVaultOffline      MonitoringEventType = "vault_offline"
	EventTypeVaultOnline       MonitoringEventType = "vault_online"
	EventTypePerformanceDegraded MonitoringEventType = "performance_degraded"
	EventTypeHighErrorRate     MonitoringEventType = "high_error_rate"
	EventTypeStorageFull       MonitoringEventType = "storage_full"
	EventTypeCertificateExpiring MonitoringEventType = "certificate_expiring"
)

// Severity represents the severity level of an event
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// AlertRule defines conditions for triggering alerts
type AlertRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	EventType   MonitoringEventType    `json:"event_type"`
	Conditions  map[string]interface{} `json:"conditions"`
	Severity    Severity               `json:"severity"`
	Enabled     bool                   `json:"enabled"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// MonitoringConfig represents monitoring configuration
type MonitoringConfig struct {
	HeartbeatTimeoutMinutes int           `json:"heartbeat_timeout_minutes"`
	CheckIntervalSeconds    int           `json:"check_interval_seconds"`
	AlertRules              []AlertRule   `json:"alert_rules"`
	NotificationChannels    []string      `json:"notification_channels"`
}

// VaultHealthStatus represents the health status of a vault
type VaultHealthStatus struct {
	VaultID           string    `json:"vault_id"`
	Status            string    `json:"status"`
	LastHeartbeat     time.Time `json:"last_heartbeat"`
	ResponseTime      float64   `json:"response_time"`
	ErrorRate         float64   `json:"error_rate"`
	RequestsPerSecond float64   `json:"requests_per_second"`
	HealthScore       float64   `json:"health_score"`
	Issues            []string  `json:"issues"`
	CheckedAt         time.Time `json:"checked_at"`
}

// MonitoringStats represents aggregated monitoring statistics
type MonitoringStats struct {
	TotalVaults     int                          `json:"total_vaults"`
	OnlineVaults    int                          `json:"online_vaults"`
	OfflineVaults   int                          `json:"offline_vaults"`
	DegradedVaults  int                          `json:"degraded_vaults"`
	ActiveAlerts    int                          `json:"active_alerts"`
	EventsByType    map[MonitoringEventType]int  `json:"events_by_type"`
	EventsBySeverity map[Severity]int            `json:"events_by_severity"`
	GeneratedAt     time.Time                    `json:"generated_at"`
}