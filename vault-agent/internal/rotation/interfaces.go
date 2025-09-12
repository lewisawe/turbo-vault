package rotation

import (
	"context"
	"time"
)

// RotationManager defines the interface for managing secret rotation
type RotationManager interface {
	// ScheduleRotation schedules a secret for rotation
	ScheduleRotation(ctx context.Context, secretID string, policy *RotationPolicy) error
	
	// ExecuteRotation executes rotation for a specific secret
	ExecuteRotation(ctx context.Context, secretID string) error
	
	// CancelRotation cancels a scheduled rotation
	CancelRotation(ctx context.Context, secretID string) error
	
	// GetRotationStatus returns the rotation status for a secret
	GetRotationStatus(ctx context.Context, secretID string) (*RotationStatus, error)
	
	// GetRotationHistory returns the rotation history for a secret
	GetRotationHistory(ctx context.Context, secretID string, limit int) ([]*RotationEvent, error)
	
	// ListPendingRotations returns all secrets pending rotation
	ListPendingRotations(ctx context.Context) ([]*PendingRotation, error)
	
	// RegisterRotator registers a custom rotation strategy
	RegisterRotator(name string, rotator SecretRotator) error
	
	// GetRotator retrieves a registered rotator by name
	GetRotator(name string) (SecretRotator, error)
	
	// ListRotators returns all registered rotators
	ListRotators() []string
	
	// Start starts the rotation manager background processes
	Start(ctx context.Context) error
	
	// Stop stops the rotation manager
	Stop() error
}

// SecretRotator defines the interface for secret rotation strategies
type SecretRotator interface {
	// Rotate performs the actual secret rotation
	Rotate(ctx context.Context, secret *Secret, config map[string]interface{}) (*RotationResult, error)
	
	// Validate validates the rotation configuration
	Validate(config map[string]interface{}) error
	
	// GetType returns the rotator type identifier
	GetType() string
	
	// GetConfigSchema returns the configuration schema for this rotator
	GetConfigSchema() map[string]interface{}
	
	// SupportsRollback indicates if this rotator supports rollback operations
	SupportsRollback() bool
	
	// Rollback rolls back a rotation to the previous version
	Rollback(ctx context.Context, secret *Secret, targetVersion int) error
}

// LifecycleManager defines the interface for managing secret lifecycle
type LifecycleManager interface {
	// ProcessExpirations processes expired secrets
	ProcessExpirations(ctx context.Context) error
	
	// CleanupExpiredSecrets removes expired secrets based on cleanup policy
	CleanupExpiredSecrets(ctx context.Context) error
	
	// NotifyExpiringSecrets sends notifications for secrets nearing expiration
	NotifyExpiringSecrets(ctx context.Context) error
	
	// SetExpirationPolicy sets the expiration policy for a secret
	SetExpirationPolicy(ctx context.Context, secretID string, policy *ExpirationPolicy) error
	
	// GetExpirationPolicy retrieves the expiration policy for a secret
	GetExpirationPolicy(ctx context.Context, secretID string) (*ExpirationPolicy, error)
	
	// GetExpiringSecrets returns secrets that will expire within the specified duration
	GetExpiringSecrets(ctx context.Context, within time.Duration) ([]*ExpiringSecret, error)
	
	// GetExpiredSecrets returns secrets that have already expired
	GetExpiredSecrets(ctx context.Context) ([]*ExpiredSecret, error)
}

// SecretVersionManager defines the interface for managing secret versions
type SecretVersionManager interface {
	// CreateVersion creates a new version of a secret
	CreateVersion(ctx context.Context, secretID string, value string, metadata map[string]string) (*SecretVersion, error)
	
	// GetVersion retrieves a specific version of a secret
	GetVersion(ctx context.Context, secretID string, version int) (*SecretVersion, error)
	
	// GetVersions retrieves all versions of a secret
	GetVersions(ctx context.Context, secretID string) ([]*SecretVersion, error)
	
	// GetLatestVersion retrieves the latest version of a secret
	GetLatestVersion(ctx context.Context, secretID string) (*SecretVersion, error)
	
	// RollbackToVersion rolls back a secret to a specific version
	RollbackToVersion(ctx context.Context, secretID string, version int) error
	
	// DeleteVersion deletes a specific version of a secret
	DeleteVersion(ctx context.Context, secretID string, version int) error
	
	// CleanupOldVersions removes old versions based on retention policy
	CleanupOldVersions(ctx context.Context, secretID string, retainCount int) error
}

// SchedulerService defines the interface for scheduling rotation tasks
type SchedulerService interface {
	// Schedule schedules a rotation task
	Schedule(ctx context.Context, task *RotationTask) error
	
	// Unschedule removes a scheduled rotation task
	Unschedule(ctx context.Context, taskID string) error
	
	// GetScheduledTasks returns all scheduled rotation tasks
	GetScheduledTasks(ctx context.Context) ([]*RotationTask, error)
	
	// GetNextExecution returns the next execution time for a task
	GetNextExecution(ctx context.Context, taskID string) (*time.Time, error)
	
	// Start starts the scheduler
	Start(ctx context.Context) error
	
	// Stop stops the scheduler
	Stop() error
}

// NotificationService defines the interface for rotation notifications
type NotificationService interface {
	// NotifyRotationSuccess sends a notification for successful rotation
	NotifyRotationSuccess(ctx context.Context, event *RotationEvent) error
	
	// NotifyRotationFailure sends a notification for failed rotation
	NotifyRotationFailure(ctx context.Context, event *RotationEvent) error
	
	// NotifyExpirationWarning sends a notification for expiring secrets
	NotifyExpirationWarning(ctx context.Context, secret *ExpiringSecret) error
	
	// NotifySecretExpired sends a notification for expired secrets
	NotifySecretExpired(ctx context.Context, secret *ExpiredSecret) error
}

// StorageService defines the interface for rotation data persistence
type StorageService interface {
	// SaveRotationEvent saves a rotation event
	SaveRotationEvent(ctx context.Context, event *RotationEvent) error
	
	// GetRotationEvents retrieves rotation events for a secret
	GetRotationEvents(ctx context.Context, secretID string, limit int) ([]*RotationEvent, error)
	
	// SaveRotationPolicy saves a rotation policy
	SaveRotationPolicy(ctx context.Context, policy *RotationPolicy) error
	
	// GetRotationPolicy retrieves a rotation policy
	GetRotationPolicy(ctx context.Context, secretID string) (*RotationPolicy, error)
	
	// DeleteRotationPolicy deletes a rotation policy
	DeleteRotationPolicy(ctx context.Context, secretID string) error
	
	// SaveSecretVersion saves a secret version
	SaveSecretVersion(ctx context.Context, version *SecretVersion) error
	
	// GetSecretVersions retrieves all versions of a secret
	GetSecretVersions(ctx context.Context, secretID string) ([]*SecretVersion, error)
	
	// DeleteSecretVersion deletes a secret version
	DeleteSecretVersion(ctx context.Context, secretID string, version int) error
	
	// GetPendingRotations retrieves secrets pending rotation
	GetPendingRotations(ctx context.Context) ([]*PendingRotation, error)
	
	// UpdateRotationStatus updates the rotation status for a secret
	UpdateRotationStatus(ctx context.Context, secretID string, status RotationStatusType) error
}