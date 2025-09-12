package vaultagent

import (
	"time"
)

// SecretStatus represents the status of a secret
type SecretStatus string

const (
	SecretStatusActive  SecretStatus = "active"
	SecretStatusExpired SecretStatus = "expired"
	SecretStatusRotated SecretStatus = "rotated"
	SecretStatusDeleted SecretStatus = "deleted"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	AuditEventSecretCreate AuditEventType = "secret_create"
	AuditEventSecretRead   AuditEventType = "secret_read"
	AuditEventSecretUpdate AuditEventType = "secret_update"
	AuditEventSecretDelete AuditEventType = "secret_delete"
	AuditEventSecretRotate AuditEventType = "secret_rotate"
	AuditEventPolicyCreate AuditEventType = "policy_create"
	AuditEventPolicyUpdate AuditEventType = "policy_update"
	AuditEventPolicyDelete AuditEventType = "policy_delete"
	AuditEventAuthLogin    AuditEventType = "auth_login"
	AuditEventAuthLogout   AuditEventType = "auth_logout"
	AuditEventAuthFailure  AuditEventType = "auth_failure"
)

// SecretMetadata represents secret metadata without the sensitive value
type SecretMetadata struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Metadata     map[string]interface{} `json:"metadata"`
	Tags         []string               `json:"tags"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	ExpiresAt    *time.Time             `json:"expires_at,omitempty"`
	RotationDue  *time.Time             `json:"rotation_due,omitempty"`
	Version      int                    `json:"version"`
	CreatedBy    string                 `json:"created_by"`
	AccessCount  int64                  `json:"access_count"`
	LastAccessed *time.Time             `json:"last_accessed,omitempty"`
	Status       SecretStatus           `json:"status"`
}

// Secret represents a complete secret with sensitive value
type Secret struct {
	SecretMetadata
	Value string `json:"value"`
}

// CreateSecretRequest represents a request to create a new secret
type CreateSecretRequest struct {
	Name     string                 `json:"name"`
	Value    string                 `json:"value"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Tags     []string               `json:"tags,omitempty"`
}

// UpdateSecretRequest represents a request to update an existing secret
type UpdateSecretRequest struct {
	Value    *string                `json:"value,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Tags     []string               `json:"tags,omitempty"`
}

// RotationPolicy represents secret rotation configuration
type RotationPolicy struct {
	ID                   string                 `json:"id"`
	Enabled              bool                   `json:"enabled"`
	IntervalDays         int                    `json:"interval_days"`
	MaxUsageCount        *int64                 `json:"max_usage_count,omitempty"`
	RotatorType          string                 `json:"rotator_type"`
	RotatorConfig        map[string]interface{} `json:"rotator_config"`
	NotificationChannels []string               `json:"notification_channels"`
}

// PolicyRule represents a single policy rule
type PolicyRule struct {
	ID         string                 `json:"id"`
	Resource   string                 `json:"resource"`
	Actions    []string               `json:"actions"`
	Effect     string                 `json:"effect"`
	Conditions map[string]interface{} `json:"conditions"`
}

// Policy represents an access control policy
type Policy struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description *string      `json:"description,omitempty"`
	Rules       []PolicyRule `json:"rules"`
	Priority    int          `json:"priority"`
	Enabled     bool         `json:"enabled"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// Actor represents an audit event actor
type Actor struct {
	Type string  `json:"type"`
	ID   string  `json:"id"`
	Name *string `json:"name,omitempty"`
}

// Resource represents an audit event resource
type Resource struct {
	Type string  `json:"type"`
	ID   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// AuditEvent represents an audit event record
type AuditEvent struct {
	ID         string                 `json:"id"`
	VaultID    string                 `json:"vault_id"`
	EventType  AuditEventType         `json:"event_type"`
	Actor      Actor                  `json:"actor"`
	Resource   Resource               `json:"resource"`
	Action     string                 `json:"action"`
	Result     string                 `json:"result"`
	Context    map[string]interface{} `json:"context"`
	Timestamp  time.Time              `json:"timestamp"`
	IPAddress  *string                `json:"ip_address,omitempty"`
	UserAgent  *string                `json:"user_agent,omitempty"`
}

// BackupInfo represents backup information
type BackupInfo struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	BackupType  string                 `json:"backup_type"`
	Status      string                 `json:"status"`
	FilePath    *string                `json:"file_path,omitempty"`
	FileSize    *int64                 `json:"file_size,omitempty"`
	Checksum    *string                `json:"checksum,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// VaultStatus represents vault agent status information
type VaultStatus struct {
	Status             string                 `json:"status"`
	Version            string                 `json:"version"`
	Uptime             int64                  `json:"uptime"`
	SecretsCount       int                    `json:"secrets_count"`
	PoliciesCount      int                    `json:"policies_count"`
	LastBackup         *time.Time             `json:"last_backup,omitempty"`
	StorageUsage       map[string]interface{} `json:"storage_usage"`
	PerformanceMetrics map[string]interface{} `json:"performance_metrics"`
}

// CloudProviderConfig represents cloud provider configuration
type CloudProviderConfig struct {
	Provider      string                 `json:"provider"`
	Region        *string                `json:"region,omitempty"`
	Credentials   map[string]interface{} `json:"credentials"`
	ServiceConfig map[string]interface{} `json:"service_config"`
}

// HybridConfig represents hybrid deployment configuration
type HybridConfig struct {
	Enabled             bool                            `json:"enabled"`
	PrimaryProvider     string                          `json:"primary_provider"`
	FallbackProviders   []string                        `json:"fallback_providers"`
	SyncInterval        int                             `json:"sync_interval"`
	ConflictResolution  string                          `json:"conflict_resolution"`
	CloudProviders      map[string]CloudProviderConfig `json:"cloud_providers"`
}

// ListSecretsOptions represents options for listing secrets
type ListSecretsOptions struct {
	Tags   []string `json:"tags,omitempty"`
	Limit  *int     `json:"limit,omitempty"`
	Offset *int     `json:"offset,omitempty"`
}

// AuditQueryOptions represents options for querying audit events
type AuditQueryOptions struct {
	StartTime *string `json:"start_time,omitempty"`
	EndTime   *string `json:"end_time,omitempty"`
	EventType *string `json:"event_type,omitempty"`
	Limit     *int    `json:"limit,omitempty"`
}

// Response wrappers for API responses
type SecretsResponse struct {
	Secrets []SecretMetadata `json:"secrets"`
}

type PoliciesResponse struct {
	Policies []Policy `json:"policies"`
}

type AuditEventsResponse struct {
	Events []AuditEvent `json:"events"`
}

type BackupsResponse struct {
	Backups []BackupInfo `json:"backups"`
}

type SecretVersionsResponse struct {
	Versions []SecretMetadata `json:"versions"`
}