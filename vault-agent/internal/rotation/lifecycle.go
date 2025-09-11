package rotation

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// LifecycleManagerImpl implements the LifecycleManager interface
type LifecycleManagerImpl struct {
	config          *RotationConfig
	storage         StorageService
	rotationManager RotationManager
	notificationSvc NotificationService
	logger          *logrus.Logger
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager(
	config *RotationConfig,
	storage StorageService,
	rotationManager RotationManager,
	notificationSvc NotificationService,
	logger *logrus.Logger,
) *LifecycleManagerImpl {
	return &LifecycleManagerImpl{
		config:          config,
		storage:         storage,
		rotationManager: rotationManager,
		notificationSvc: notificationSvc,
		logger:          logger,
	}
}

// ProcessExpirations processes expired secrets
func (lm *LifecycleManagerImpl) ProcessExpirations(ctx context.Context) error {
	// Check for expiring secrets and send warnings
	if err := lm.NotifyExpiringSecrets(ctx); err != nil {
		lm.logger.Errorf("Failed to notify expiring secrets: %v", err)
	}

	// Process expired secrets
	expiredSecrets, err := lm.GetExpiredSecrets(ctx)
	if err != nil {
		return fmt.Errorf("failed to get expired secrets: %w", err)
	}

	for _, expired := range expiredSecrets {
		lm.logger.Infof("Processing expired secret: %s", expired.SecretID)

		// Get expiration policy
		policy, err := lm.GetExpirationPolicy(ctx, expired.SecretID)
		if err != nil {
			lm.logger.Errorf("Failed to get expiration policy for secret %s: %v", expired.SecretID, err)
			continue
		}

		// Auto-rotate if configured
		if policy != nil && policy.AutoRotate {
			if err := lm.rotationManager.ExecuteRotation(ctx, expired.SecretID); err != nil {
				lm.logger.Errorf("Failed to auto-rotate expired secret %s: %v", expired.SecretID, err)
				
				// Send expiration notification if rotation failed
				if lm.notificationSvc != nil {
					if err := lm.notificationSvc.NotifySecretExpired(ctx, expired); err != nil {
						lm.logger.Errorf("Failed to send expiration notification: %v", err)
					}
				}
			} else {
				lm.logger.Infof("Successfully auto-rotated expired secret: %s", expired.SecretID)
			}
		} else {
			// Send expiration notification
			if lm.notificationSvc != nil {
				if err := lm.notificationSvc.NotifySecretExpired(ctx, expired); err != nil {
					lm.logger.Errorf("Failed to send expiration notification: %v", err)
				}
			}
		}
	}

	// Clean up expired secrets if configured
	if lm.config.ExpirationCheck.CleanupEnabled {
		if err := lm.CleanupExpiredSecrets(ctx); err != nil {
			lm.logger.Errorf("Failed to cleanup expired secrets: %v", err)
		}
	}

	return nil
}

// CleanupExpiredSecrets removes expired secrets based on cleanup policy
func (lm *LifecycleManagerImpl) CleanupExpiredSecrets(ctx context.Context) error {
	expiredSecrets, err := lm.GetExpiredSecrets(ctx)
	if err != nil {
		return fmt.Errorf("failed to get expired secrets: %w", err)
	}

	cleanupDelay := lm.config.ExpirationCheck.CleanupDelay

	for _, expired := range expiredSecrets {
		// Only cleanup secrets that have been expired for longer than the cleanup delay
		if expired.TimeSinceExpiry >= cleanupDelay {
			policy, err := lm.GetExpirationPolicy(ctx, expired.SecretID)
			if err != nil {
				lm.logger.Errorf("Failed to get expiration policy for secret %s: %v", expired.SecretID, err)
				continue
			}

			// Check if cleanup is allowed for this secret
			if policy != nil && policy.CleanupAfterExpiry > 0 {
				if expired.TimeSinceExpiry >= policy.CleanupAfterExpiry {
					lm.logger.Infof("Cleaning up expired secret: %s (expired %v ago)", 
						expired.SecretID, expired.TimeSinceExpiry)
					
					// TODO: Implement actual secret deletion
					// This would depend on the secret storage implementation
				}
			}
		}
	}

	return nil
}

// NotifyExpiringSecrets sends notifications for secrets nearing expiration
func (lm *LifecycleManagerImpl) NotifyExpiringSecrets(ctx context.Context) error {
	warningThreshold := lm.config.ExpirationCheck.WarningThreshold
	expiringSecrets, err := lm.GetExpiringSecrets(ctx, warningThreshold)
	if err != nil {
		return fmt.Errorf("failed to get expiring secrets: %w", err)
	}

	for _, expiring := range expiringSecrets {
		// Check if we've already notified recently
		if expiring.LastNotified != nil {
			timeSinceLastNotification := time.Since(*expiring.LastNotified)
			if timeSinceLastNotification < 24*time.Hour {
				continue // Don't spam notifications
			}
		}

		lm.logger.Infof("Notifying about expiring secret: %s (expires in %v)", 
			expiring.SecretID, expiring.TimeRemaining)

		if lm.notificationSvc != nil {
			if err := lm.notificationSvc.NotifyExpirationWarning(ctx, expiring); err != nil {
				lm.logger.Errorf("Failed to send expiration warning: %v", err)
			}
		}
	}

	return nil
}

// SetExpirationPolicy sets the expiration policy for a secret
func (lm *LifecycleManagerImpl) SetExpirationPolicy(ctx context.Context, secretID string, policy *ExpirationPolicy) error {
	policy.SecretID = secretID
	policy.UpdatedAt = time.Now()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = time.Now()
	}

	// Validate policy
	if err := lm.validateExpirationPolicy(policy); err != nil {
		return fmt.Errorf("invalid expiration policy: %w", err)
	}

	// TODO: Save policy to storage
	// This would depend on the storage implementation

	lm.logger.Infof("Set expiration policy for secret %s", secretID)
	return nil
}

// GetExpirationPolicy retrieves the expiration policy for a secret
func (lm *LifecycleManagerImpl) GetExpirationPolicy(ctx context.Context, secretID string) (*ExpirationPolicy, error) {
	// TODO: Retrieve policy from storage
	// This would depend on the storage implementation
	
	// Return default policy for now
	return &ExpirationPolicy{
		SecretID:           secretID,
		ExpirationTime:     30 * 24 * time.Hour, // 30 days
		WarningThreshold:   24 * time.Hour,      // 1 day
		AutoRotate:         false,
		CleanupAfterExpiry: 7 * 24 * time.Hour,  // 7 days
		NotifyChannels:     lm.config.NotificationChannels,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}, nil
}

// GetExpiringSecrets returns secrets that will expire within the specified duration
func (lm *LifecycleManagerImpl) GetExpiringSecrets(ctx context.Context, within time.Duration) ([]*ExpiringSecret, error) {
	// TODO: Query storage for expiring secrets
	// This would depend on the storage implementation
	
	// Return empty list for now
	return []*ExpiringSecret{}, nil
}

// GetExpiredSecrets returns secrets that have already expired
func (lm *LifecycleManagerImpl) GetExpiredSecrets(ctx context.Context) ([]*ExpiredSecret, error) {
	// TODO: Query storage for expired secrets
	// This would depend on the storage implementation
	
	// Return empty list for now
	return []*ExpiredSecret{}, nil
}

// validateExpirationPolicy validates an expiration policy
func (lm *LifecycleManagerImpl) validateExpirationPolicy(policy *ExpirationPolicy) error {
	if policy.SecretID == "" {
		return fmt.Errorf("secret ID is required")
	}

	if policy.ExpirationTime <= 0 {
		return fmt.Errorf("expiration time must be positive")
	}

	if policy.WarningThreshold <= 0 {
		return fmt.Errorf("warning threshold must be positive")
	}

	if policy.WarningThreshold >= policy.ExpirationTime {
		return fmt.Errorf("warning threshold must be less than expiration time")
	}

	return nil
}

// SecretVersionManagerImpl implements the SecretVersionManager interface
type SecretVersionManagerImpl struct {
	storage StorageService
	logger  *logrus.Logger
}

// NewSecretVersionManager creates a new secret version manager
func NewSecretVersionManager(storage StorageService, logger *logrus.Logger) *SecretVersionManagerImpl {
	return &SecretVersionManagerImpl{
		storage: storage,
		logger:  logger,
	}
}

// CreateVersion creates a new version of a secret
func (svm *SecretVersionManagerImpl) CreateVersion(ctx context.Context, secretID string, value string, metadata map[string]string) (*SecretVersion, error) {
	// Get existing versions to determine next version number
	versions, err := svm.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing versions: %w", err)
	}

	nextVersion := 1
	if len(versions) > 0 {
		// Find the highest version number
		for _, v := range versions {
			if v.Version >= nextVersion {
				nextVersion = v.Version + 1
			}
		}
	}

	version := &SecretVersion{
		ID:        fmt.Sprintf("%s-v%d", secretID, nextVersion),
		SecretID:  secretID,
		Version:   nextVersion,
		Value:     value,
		Metadata:  metadata,
		CreatedAt: time.Now(),
		IsActive:  true,
	}

	// Deactivate previous versions
	for _, v := range versions {
		if v.IsActive {
			v.IsActive = false
			if err := svm.storage.SaveSecretVersion(ctx, v); err != nil {
				svm.logger.Errorf("Failed to deactivate version %d: %v", v.Version, err)
			}
		}
	}

	// Save new version
	if err := svm.storage.SaveSecretVersion(ctx, version); err != nil {
		return nil, fmt.Errorf("failed to save secret version: %w", err)
	}

	svm.logger.Infof("Created version %d for secret %s", nextVersion, secretID)
	return version, nil
}

// GetVersion retrieves a specific version of a secret
func (svm *SecretVersionManagerImpl) GetVersion(ctx context.Context, secretID string, version int) (*SecretVersion, error) {
	versions, err := svm.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret versions: %w", err)
	}

	for _, v := range versions {
		if v.Version == version {
			return v, nil
		}
	}

	return nil, fmt.Errorf("version %d not found for secret %s", version, secretID)
}

// GetVersions retrieves all versions of a secret
func (svm *SecretVersionManagerImpl) GetVersions(ctx context.Context, secretID string) ([]*SecretVersion, error) {
	return svm.storage.GetSecretVersions(ctx, secretID)
}

// GetLatestVersion retrieves the latest version of a secret
func (svm *SecretVersionManagerImpl) GetLatestVersion(ctx context.Context, secretID string) (*SecretVersion, error) {
	versions, err := svm.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret versions: %w", err)
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no versions found for secret %s", secretID)
	}

	// Find the active version or the highest version number
	var latest *SecretVersion
	for _, v := range versions {
		if v.IsActive {
			return v, nil
		}
		if latest == nil || v.Version > latest.Version {
			latest = v
		}
	}

	return latest, nil
}

// RollbackToVersion rolls back a secret to a specific version
func (svm *SecretVersionManagerImpl) RollbackToVersion(ctx context.Context, secretID string, version int) error {
	targetVersion, err := svm.GetVersion(ctx, secretID, version)
	if err != nil {
		return fmt.Errorf("failed to get target version: %w", err)
	}

	// Deactivate all versions
	versions, err := svm.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return fmt.Errorf("failed to get secret versions: %w", err)
	}

	for _, v := range versions {
		v.IsActive = false
		if err := svm.storage.SaveSecretVersion(ctx, v); err != nil {
			svm.logger.Errorf("Failed to deactivate version %d: %v", v.Version, err)
		}
	}

	// Activate target version
	targetVersion.IsActive = true
	if err := svm.storage.SaveSecretVersion(ctx, targetVersion); err != nil {
		return fmt.Errorf("failed to activate target version: %w", err)
	}

	svm.logger.Infof("Rolled back secret %s to version %d", secretID, version)
	return nil
}

// DeleteVersion deletes a specific version of a secret
func (svm *SecretVersionManagerImpl) DeleteVersion(ctx context.Context, secretID string, version int) error {
	// Don't allow deletion of active version
	targetVersion, err := svm.GetVersion(ctx, secretID, version)
	if err != nil {
		return fmt.Errorf("failed to get target version: %w", err)
	}

	if targetVersion.IsActive {
		return fmt.Errorf("cannot delete active version %d", version)
	}

	if err := svm.storage.DeleteSecretVersion(ctx, secretID, version); err != nil {
		return fmt.Errorf("failed to delete secret version: %w", err)
	}

	svm.logger.Infof("Deleted version %d for secret %s", version, secretID)
	return nil
}

// CleanupOldVersions removes old versions based on retention policy
func (svm *SecretVersionManagerImpl) CleanupOldVersions(ctx context.Context, secretID string, retainCount int) error {
	versions, err := svm.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return fmt.Errorf("failed to get secret versions: %w", err)
	}

	if len(versions) <= retainCount {
		return nil // Nothing to cleanup
	}

	// Sort versions by version number (descending)
	// Keep the latest versions and delete older ones
	toDelete := len(versions) - retainCount
	deletedCount := 0

	for _, v := range versions {
		if deletedCount >= toDelete {
			break
		}

		// Don't delete active version
		if v.IsActive {
			continue
		}

		if err := svm.storage.DeleteSecretVersion(ctx, secretID, v.Version); err != nil {
			svm.logger.Errorf("Failed to delete version %d: %v", v.Version, err)
			continue
		}

		deletedCount++
	}

	svm.logger.Infof("Cleaned up %d old versions for secret %s", deletedCount, secretID)
	return nil
}