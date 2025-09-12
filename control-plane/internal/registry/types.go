package registry

import (
	"time"
)

// VaultStatus represents the current status of a vault agent
type VaultStatus string

const (
	VaultStatusOnline    VaultStatus = "online"
	VaultStatusOffline   VaultStatus = "offline"
	VaultStatusUnknown   VaultStatus = "unknown"
	VaultStatusDegraded  VaultStatus = "degraded"
)

// VaultAgent represents a registered vault instance
type VaultAgent struct {
	ID              string            `json:"id" db:"id"`
	Name            string            `json:"name" db:"name"`
	OrganizationID  string            `json:"organization_id" db:"organization_id"`
	Version         string            `json:"version" db:"version"`
	Status          VaultStatus       `json:"status" db:"status"`
	LastHeartbeat   time.Time         `json:"last_heartbeat" db:"last_heartbeat"`
	Configuration   VaultConfig       `json:"configuration" db:"configuration"`
	Metrics         VaultMetrics      `json:"metrics" db:"metrics"`
	Policies        []string          `json:"policies" db:"policies"`
	Tags            map[string]string `json:"tags" db:"tags"`
	RegisteredAt    time.Time         `json:"registered_at" db:"registered_at"`
	UpdatedAt       time.Time         `json:"updated_at" db:"updated_at"`
	IPAddress       string            `json:"ip_address" db:"ip_address"`
	Certificate     string            `json:"certificate" db:"certificate"`
	Capabilities    []string          `json:"capabilities" db:"capabilities"`
}

// VaultConfig represents vault agent configuration
type VaultConfig struct {
	StorageBackend   string            `json:"storage_backend"`
	EncryptionMethod string            `json:"encryption_method"`
	BackupEnabled    bool              `json:"backup_enabled"`
	AuditEnabled     bool              `json:"audit_enabled"`
	Settings         map[string]string `json:"settings"`
}

// VaultMetrics represents performance and usage metrics
type VaultMetrics struct {
	RequestsPerSecond float64   `json:"requests_per_second"`
	AverageLatency    float64   `json:"average_latency"`
	ErrorRate         float64   `json:"error_rate"`
	SecretCount       int64     `json:"secret_count"`
	StorageUsage      int64     `json:"storage_usage"`
	CPUUsage          float64   `json:"cpu_usage"`
	MemoryUsage       float64   `json:"memory_usage"`
	LastUpdated       time.Time `json:"last_updated"`
}

// RegistrationRequest represents a vault agent registration request
type RegistrationRequest struct {
	Name           string            `json:"name" validate:"required"`
	OrganizationID string            `json:"organization_id" validate:"required"`
	Version        string            `json:"version" validate:"required"`
	Configuration  VaultConfig       `json:"configuration"`
	Tags           map[string]string `json:"tags"`
	Certificate    string            `json:"certificate" validate:"required"`
	Capabilities   []string          `json:"capabilities"`
}

// HeartbeatRequest represents a heartbeat from a vault agent
type HeartbeatRequest struct {
	VaultID string       `json:"vault_id" validate:"required"`
	Status  VaultStatus  `json:"status" validate:"required"`
	Metrics VaultMetrics `json:"metrics"`
}

// VaultFilter represents filtering options for vault queries
type VaultFilter struct {
	OrganizationID string      `json:"organization_id"`
	Status         VaultStatus `json:"status"`
	Tags           map[string]string `json:"tags"`
	Limit          int         `json:"limit"`
	Offset         int         `json:"offset"`
}

// VaultListResponse represents a paginated list of vault agents
type VaultListResponse struct {
	Vaults     []VaultAgent `json:"vaults"`
	Total      int          `json:"total"`
	Limit      int          `json:"limit"`
	Offset     int          `json:"offset"`
	HasMore    bool         `json:"has_more"`
}