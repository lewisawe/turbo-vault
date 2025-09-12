package rotation

import (
	"time"
)

// RotationStatusType represents the status of a rotation operation
type RotationStatusType string

const (
	RotationStatusPending    RotationStatusType = "pending"
	RotationStatusRunning    RotationStatusType = "running"
	RotationStatusCompleted  RotationStatusType = "completed"
	RotationStatusFailed     RotationStatusType = "failed"
	RotationStatusCancelled  RotationStatusType = "cancelled"
	RotationStatusScheduled  RotationStatusType = "scheduled"
)

// RotationTriggerType represents what triggered a rotation
type RotationTriggerType string

const (
	RotationTriggerScheduled RotationTriggerType = "scheduled"
	RotationTriggerManual    RotationTriggerType = "manual"
	RotationTriggerExpiry    RotationTriggerType = "expiry"
	RotationTriggerUsage     RotationTriggerType = "usage"
	RotationTriggerExternal  RotationTriggerType = "external"
)

// RotationPolicy defines how and when a secret should be rotated
type RotationPolicy struct {
	ID                string                 `json:"id" db:"id"`
	SecretID          string                 `json:"secret_id" db:"secret_id"`
	Enabled           bool                   `json:"enabled" db:"enabled"`
	RotatorType       string                 `json:"rotator_type" db:"rotator_type"`
	RotatorConfig     map[string]interface{} `json:"rotator_config" db:"rotator_config"`
	Schedule          *ScheduleConfig        `json:"schedule,omitempty" db:"schedule"`
	MaxUsageCount     *int64                 `json:"max_usage_count,omitempty" db:"max_usage_count"`
	MaxAge            *time.Duration         `json:"max_age,omitempty" db:"max_age"`
	NotifyChannels    []string               `json:"notify_channels" db:"notify_channels"`
	RetryPolicy       *RetryPolicy           `json:"retry_policy" db:"retry_policy"`
	RollbackOnFailure bool                   `json:"rollback_on_failure" db:"rollback_on_failure"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy         string                 `json:"created_by" db:"created_by"`
}

// ScheduleConfig defines rotation scheduling configuration
type ScheduleConfig struct {
	Type     string        `json:"type"` // cron, interval, fixed
	Cron     string        `json:"cron,omitempty"`
	Interval time.Duration `json:"interval,omitempty"`
	FixedTime time.Time    `json:"fixed_time,omitempty"`
	Timezone  string       `json:"timezone,omitempty"`
}

// RetryPolicy defines retry behavior for failed rotations
type RetryPolicy struct {
	MaxAttempts   int           `json:"max_attempts"`
	InitialDelay  time.Duration `json:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
	RetryOn       []string      `json:"retry_on"` // Error types to retry on
}

// RotationStatus represents the current rotation status of a secret
type RotationStatus struct {
	SecretID        string             `json:"secret_id"`
	Status          RotationStatusType `json:"status"`
	LastRotation    *time.Time         `json:"last_rotation,omitempty"`
	NextRotation    *time.Time         `json:"next_rotation,omitempty"`
	CurrentVersion  int                `json:"current_version"`
	RotationCount   int                `json:"rotation_count"`
	LastError       string             `json:"last_error,omitempty"`
	LastErrorAt     *time.Time         `json:"last_error_at,omitempty"`
	RetryCount      int                `json:"retry_count"`
	NextRetryAt     *time.Time         `json:"next_retry_at,omitempty"`
	Policy          *RotationPolicy    `json:"policy,omitempty"`
}

// RotationEvent represents a rotation event (success or failure)
type RotationEvent struct {
	ID              string              `json:"id" db:"id"`
	SecretID        string              `json:"secret_id" db:"secret_id"`
	Status          RotationStatusType  `json:"status" db:"status"`
	TriggerType     RotationTriggerType `json:"trigger_type" db:"trigger_type"`
	TriggeredBy     string              `json:"triggered_by" db:"triggered_by"`
	StartedAt       time.Time           `json:"started_at" db:"started_at"`
	CompletedAt     *time.Time          `json:"completed_at,omitempty" db:"completed_at"`
	Duration        *time.Duration      `json:"duration,omitempty" db:"duration"`
	OldVersion      int                 `json:"old_version" db:"old_version"`
	NewVersion      int                 `json:"new_version" db:"new_version"`
	RotatorType     string              `json:"rotator_type" db:"rotator_type"`
	Error           string              `json:"error,omitempty" db:"error"`
	ErrorCode       string              `json:"error_code,omitempty" db:"error_code"`
	Attempt         int                 `json:"attempt" db:"attempt"`
	MaxAttempts     int                 `json:"max_attempts" db:"max_attempts"`
	Metadata        map[string]string   `json:"metadata" db:"metadata"`
	NotificationsSent []string          `json:"notifications_sent" db:"notifications_sent"`
}

// RotationResult represents the result of a rotation operation
type RotationResult struct {
	Success      bool                   `json:"success"`
	NewValue     string                 `json:"new_value,omitempty"`
	NewVersion   int                    `json:"new_version"`
	Metadata     map[string]string      `json:"metadata,omitempty"`
	Error        error                  `json:"error,omitempty"`
	ErrorCode    string                 `json:"error_code,omitempty"`
	Duration     time.Duration          `json:"duration"`
	ExternalData map[string]interface{} `json:"external_data,omitempty"`
}

// PendingRotation represents a secret that is pending rotation
type PendingRotation struct {
	SecretID     string    `json:"secret_id"`
	SecretName   string    `json:"secret_name"`
	ScheduledAt  time.Time `json:"scheduled_at"`
	Reason       string    `json:"reason"`
	Priority     int       `json:"priority"`
	Policy       *RotationPolicy `json:"policy"`
	LastAttempt  *time.Time `json:"last_attempt,omitempty"`
	RetryCount   int       `json:"retry_count"`
}

// RotationTask represents a scheduled rotation task
type RotationTask struct {
	ID           string              `json:"id"`
	SecretID     string              `json:"secret_id"`
	ScheduledAt  time.Time           `json:"scheduled_at"`
	TriggerType  RotationTriggerType `json:"trigger_type"`
	Priority     int                 `json:"priority"`
	Policy       *RotationPolicy     `json:"policy"`
	CreatedAt    time.Time           `json:"created_at"`
	CreatedBy    string              `json:"created_by"`
}

// Secret represents a secret (simplified version for rotation)
type Secret struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Value          string            `json:"value,omitempty"`
	Version        int               `json:"version"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty"`
	LastAccessed   *time.Time        `json:"last_accessed,omitempty"`
	AccessCount    int64             `json:"access_count"`
	Metadata       map[string]string `json:"metadata"`
	Tags           []string          `json:"tags"`
	RotationPolicy *RotationPolicy   `json:"rotation_policy,omitempty"`
}

// SecretVersion represents a version of a secret
type SecretVersion struct {
	ID        string            `json:"id" db:"id"`
	SecretID  string            `json:"secret_id" db:"secret_id"`
	Version   int               `json:"version" db:"version"`
	Value     string            `json:"value,omitempty" db:"-"`
	EncryptedValue []byte        `json:"-" db:"encrypted_value"`
	Metadata  map[string]string `json:"metadata" db:"metadata"`
	CreatedAt time.Time         `json:"created_at" db:"created_at"`
	CreatedBy string            `json:"created_by" db:"created_by"`
	IsActive  bool              `json:"is_active" db:"is_active"`
}

// ExpirationPolicy defines how secret expiration should be handled
type ExpirationPolicy struct {
	ID                string        `json:"id" db:"id"`
	SecretID          string        `json:"secret_id" db:"secret_id"`
	ExpirationTime    time.Duration `json:"expiration_time" db:"expiration_time"`
	WarningThreshold  time.Duration `json:"warning_threshold" db:"warning_threshold"`
	AutoRotate        bool          `json:"auto_rotate" db:"auto_rotate"`
	CleanupAfterExpiry time.Duration `json:"cleanup_after_expiry" db:"cleanup_after_expiry"`
	NotifyChannels    []string      `json:"notify_channels" db:"notify_channels"`
	CreatedAt         time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at" db:"updated_at"`
}

// ExpiringSecret represents a secret that is nearing expiration
type ExpiringSecret struct {
	SecretID      string    `json:"secret_id"`
	SecretName    string    `json:"secret_name"`
	ExpiresAt     time.Time `json:"expires_at"`
	TimeRemaining time.Duration `json:"time_remaining"`
	Policy        *ExpirationPolicy `json:"policy,omitempty"`
	LastNotified  *time.Time `json:"last_notified,omitempty"`
}

// ExpiredSecret represents a secret that has expired
type ExpiredSecret struct {
	SecretID     string    `json:"secret_id"`
	SecretName   string    `json:"secret_name"`
	ExpiredAt    time.Time `json:"expired_at"`
	TimeSinceExpiry time.Duration `json:"time_since_expiry"`
	Policy       *ExpirationPolicy `json:"policy,omitempty"`
	LastAccessed *time.Time `json:"last_accessed,omitempty"`
	AccessCount  int64     `json:"access_count"`
}

// RotationConfig represents the configuration for the rotation system
type RotationConfig struct {
	Enabled              bool                    `yaml:"enabled" json:"enabled"`
	CheckInterval        time.Duration           `yaml:"check_interval" json:"check_interval"`
	MaxConcurrentRotations int                   `yaml:"max_concurrent_rotations" json:"max_concurrent_rotations"`
	DefaultRetryPolicy   *RetryPolicy            `yaml:"default_retry_policy" json:"default_retry_policy"`
	NotificationChannels []string                `yaml:"notification_channels" json:"notification_channels"`
	Rotators             map[string]interface{}  `yaml:"rotators" json:"rotators"`
	ExpirationCheck      *ExpirationCheckConfig  `yaml:"expiration_check" json:"expiration_check"`
	VersionRetention     *VersionRetentionConfig `yaml:"version_retention" json:"version_retention"`
}

// ExpirationCheckConfig defines configuration for expiration checking
type ExpirationCheckConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	CheckInterval   time.Duration `yaml:"check_interval" json:"check_interval"`
	WarningThreshold time.Duration `yaml:"warning_threshold" json:"warning_threshold"`
	CleanupEnabled  bool          `yaml:"cleanup_enabled" json:"cleanup_enabled"`
	CleanupDelay    time.Duration `yaml:"cleanup_delay" json:"cleanup_delay"`
}

// VersionRetentionConfig defines configuration for version retention
type VersionRetentionConfig struct {
	MaxVersions     int           `yaml:"max_versions" json:"max_versions"`
	RetentionPeriod time.Duration `yaml:"retention_period" json:"retention_period"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
}

// DefaultRotationConfig returns a default rotation configuration
func DefaultRotationConfig() *RotationConfig {
	return &RotationConfig{
		Enabled:                true,
		CheckInterval:          time.Minute,
		MaxConcurrentRotations: 5,
		DefaultRetryPolicy: &RetryPolicy{
			MaxAttempts:   3,
			InitialDelay:  time.Minute,
			MaxDelay:      time.Hour,
			BackoffFactor: 2.0,
			RetryOn:       []string{"timeout", "connection_error", "temporary_failure"},
		},
		NotificationChannels: []string{},
		Rotators:             make(map[string]interface{}),
		ExpirationCheck: &ExpirationCheckConfig{
			Enabled:          true,
			CheckInterval:    time.Hour,
			WarningThreshold: 24 * time.Hour,
			CleanupEnabled:   false,
			CleanupDelay:     7 * 24 * time.Hour,
		},
		VersionRetention: &VersionRetentionConfig{
			MaxVersions:     10,
			RetentionPeriod: 30 * 24 * time.Hour,
			CleanupInterval: 24 * time.Hour,
		},
	}
}