package rotation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockNotificationService for testing
type MockNotificationService struct {
	successNotifications []string
	failureNotifications []string
	expirationWarnings   []string
	expiredNotifications []string
}

func (m *MockNotificationService) NotifyRotationSuccess(ctx context.Context, event *RotationEvent) error {
	m.successNotifications = append(m.successNotifications, event.SecretID)
	return nil
}

func (m *MockNotificationService) NotifyRotationFailure(ctx context.Context, event *RotationEvent) error {
	m.failureNotifications = append(m.failureNotifications, event.SecretID)
	return nil
}

func (m *MockNotificationService) NotifyExpirationWarning(ctx context.Context, secret *ExpiringSecret) error {
	m.expirationWarnings = append(m.expirationWarnings, secret.SecretID)
	return nil
}

func (m *MockNotificationService) NotifySecretExpired(ctx context.Context, secret *ExpiredSecret) error {
	m.expiredNotifications = append(m.expiredNotifications, secret.SecretID)
	return nil
}

func TestRandomRotator(t *testing.T) {
	rotator := NewRandomRotator()

	t.Run("BasicRotation", func(t *testing.T) {
		secret := &Secret{
			ID:      "test-secret",
			Value:   "old-value",
			Version: 1,
		}

		config := map[string]interface{}{
			"length":   16,
			"encoding": "base64",
		}

		result, err := rotator.Rotate(context.Background(), secret, config)
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.NotEmpty(t, result.NewValue)
		assert.NotEqual(t, secret.Value, result.NewValue)
		assert.Equal(t, "random", result.Metadata["rotator_type"])
	})

	t.Run("HexEncoding", func(t *testing.T) {
		secret := &Secret{
			ID:      "test-secret",
			Value:   "old-value",
			Version: 1,
		}

		config := map[string]interface{}{
			"length":   32,
			"encoding": "hex",
		}

		result, err := rotator.Rotate(context.Background(), secret, config)
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.NotEmpty(t, result.NewValue)
		assert.Equal(t, "hex", result.Metadata["encoding"])
	})

	t.Run("CharsetEncoding", func(t *testing.T) {
		secret := &Secret{
			ID:      "test-secret",
			Value:   "old-value",
			Version: 1,
		}

		config := map[string]interface{}{
			"length":   10,
			"encoding": "charset",
			"charset":  "ABCDEF123456",
		}

		result, err := rotator.Rotate(context.Background(), secret, config)
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.NotEmpty(t, result.NewValue)
		assert.Len(t, result.NewValue, 10)
		
		// Check that all characters are from the specified charset
		for _, char := range result.NewValue {
			assert.Contains(t, "ABCDEF123456", string(char))
		}
	})

	t.Run("Validation", func(t *testing.T) {
		// Valid config
		validConfig := map[string]interface{}{
			"length":   16,
			"encoding": "base64",
		}
		err := rotator.Validate(validConfig)
		assert.NoError(t, err)

		// Invalid length
		invalidConfig := map[string]interface{}{
			"length": -1,
		}
		err = rotator.Validate(invalidConfig)
		assert.Error(t, err)

		// Invalid encoding
		invalidConfig = map[string]interface{}{
			"encoding": "invalid",
		}
		err = rotator.Validate(invalidConfig)
		assert.Error(t, err)
	})

	t.Run("GetType", func(t *testing.T) {
		assert.Equal(t, "random", rotator.GetType())
	})

	t.Run("SupportsRollback", func(t *testing.T) {
		assert.False(t, rotator.SupportsRollback())
	})
}

func TestScriptRotator(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	rotator := NewScriptRotator(logger)

	t.Run("Validation", func(t *testing.T) {
		// Missing script path
		invalidConfig := map[string]interface{}{}
		err := rotator.Validate(invalidConfig)
		assert.Error(t, err)

		// Valid config with echo command (should exist on most systems)
		validConfig := map[string]interface{}{
			"script_path": "echo",
		}
		err = rotator.Validate(validConfig)
		assert.NoError(t, err)
	})

	t.Run("GetType", func(t *testing.T) {
		assert.Equal(t, "script", rotator.GetType())
	})

	t.Run("SupportsRollback", func(t *testing.T) {
		assert.True(t, rotator.SupportsRollback())
	})
}

func TestAPIRotator(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	rotator := NewAPIRotator(logger)

	t.Run("Validation", func(t *testing.T) {
		// Missing URL
		invalidConfig := map[string]interface{}{}
		err := rotator.Validate(invalidConfig)
		assert.Error(t, err)

		// Valid config
		validConfig := map[string]interface{}{
			"url": "https://api.example.com/rotate",
		}
		err = rotator.Validate(validConfig)
		assert.NoError(t, err)

		// Invalid method
		invalidConfig = map[string]interface{}{
			"url":    "https://api.example.com/rotate",
			"method": "INVALID",
		}
		err = rotator.Validate(invalidConfig)
		assert.Error(t, err)
	})

	t.Run("GetType", func(t *testing.T) {
		assert.Equal(t, "api", rotator.GetType())
	})

	t.Run("SupportsRollback", func(t *testing.T) {
		assert.True(t, rotator.SupportsRollback())
	})
}

func TestRotationManager(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	config := DefaultRotationConfig()
	storage := NewMemoryStorageService()
	versionManager := NewSecretVersionManager(storage, logger)
	notificationSvc := &MockNotificationService{}
	
	// Create a simple scheduler callback
	var rotationManager *Manager
	executeCallback := func(ctx context.Context, task *RotationTask) error {
		return rotationManager.ExecuteRotation(ctx, task.SecretID)
	}
	
	scheduler := NewScheduler(logger, executeCallback)
	lifecycleManager := NewLifecycleManager(config, storage, nil, notificationSvc, logger)
	
	rotationManager = NewManager(config, storage, versionManager, lifecycleManager, scheduler, notificationSvc, logger)

	t.Run("StartStop", func(t *testing.T) {
		ctx := context.Background()
		
		err := rotationManager.Start(ctx)
		require.NoError(t, err)
		
		err = rotationManager.Stop()
		require.NoError(t, err)
	})

	t.Run("RegisterRotator", func(t *testing.T) {
		randomRotator := NewRandomRotator()
		err := rotationManager.RegisterRotator("test-random", randomRotator)
		require.NoError(t, err)

		retrievedRotator, err := rotationManager.GetRotator("test-random")
		require.NoError(t, err)
		assert.Equal(t, randomRotator, retrievedRotator)

		rotators := rotationManager.ListRotators()
		assert.Contains(t, rotators, "test-random")
	})

	t.Run("ScheduleRotation", func(t *testing.T) {
		ctx := context.Background()
		err := rotationManager.Start(ctx)
		require.NoError(t, err)
		defer rotationManager.Stop()

		secretID := "test-secret-1"
		policy := &RotationPolicy{
			SecretID:      secretID,
			Enabled:       true,
			RotatorType:   "random",
			RotatorConfig: map[string]interface{}{
				"length":   16,
				"encoding": "base64",
			},
			RetryPolicy: &RetryPolicy{
				MaxAttempts:   3,
				InitialDelay:  time.Second,
				MaxDelay:      time.Minute,
				BackoffFactor: 2.0,
			},
		}

		err = rotationManager.ScheduleRotation(ctx, secretID, policy)
		require.NoError(t, err)

		// Verify policy was saved
		savedPolicy, err := storage.GetRotationPolicy(ctx, secretID)
		require.NoError(t, err)
		assert.Equal(t, secretID, savedPolicy.SecretID)
		assert.Equal(t, "random", savedPolicy.RotatorType)
	})

	t.Run("ExecuteRotation", func(t *testing.T) {
		ctx := context.Background()
		err := rotationManager.Start(ctx)
		require.NoError(t, err)
		defer rotationManager.Stop()

		secretID := "test-secret-2"
		
		// Create initial version
		initialVersion, err := versionManager.CreateVersion(ctx, secretID, "initial-value", map[string]string{})
		require.NoError(t, err)
		assert.Equal(t, 1, initialVersion.Version)

		// Schedule rotation
		policy := &RotationPolicy{
			SecretID:      secretID,
			Enabled:       true,
			RotatorType:   "random",
			RotatorConfig: map[string]interface{}{
				"length":   16,
				"encoding": "base64",
			},
			RetryPolicy: &RetryPolicy{
				MaxAttempts:   3,
				InitialDelay:  time.Second,
				MaxDelay:      time.Minute,
				BackoffFactor: 2.0,
			},
		}

		err = rotationManager.ScheduleRotation(ctx, secretID, policy)
		require.NoError(t, err)

		// Execute rotation
		err = rotationManager.ExecuteRotation(ctx, secretID)
		require.NoError(t, err)

		// Verify new version was created
		latestVersion, err := versionManager.GetLatestVersion(ctx, secretID)
		require.NoError(t, err)
		assert.Equal(t, 2, latestVersion.Version)
		assert.NotEqual(t, "initial-value", latestVersion.Value)

		// Verify rotation event was recorded
		events, err := storage.GetRotationEvents(ctx, secretID, 10)
		require.NoError(t, err)
		assert.Len(t, events, 1)
		assert.Equal(t, RotationStatusCompleted, events[0].Status)

		// Verify success notification was sent
		assert.Contains(t, notificationSvc.successNotifications, secretID)
	})

	t.Run("GetRotationStatus", func(t *testing.T) {
		ctx := context.Background()
		err := rotationManager.Start(ctx)
		require.NoError(t, err)
		defer rotationManager.Stop()

		secretID := "test-secret-3"
		
		// Create initial version and policy
		versionManager.CreateVersion(ctx, secretID, "initial-value", map[string]string{})
		policy := &RotationPolicy{
			SecretID:      secretID,
			Enabled:       true,
			RotatorType:   "random",
			RotatorConfig: map[string]interface{}{},
		}
		rotationManager.ScheduleRotation(ctx, secretID, policy)

		status, err := rotationManager.GetRotationStatus(ctx, secretID)
		require.NoError(t, err)
		assert.Equal(t, secretID, status.SecretID)
		assert.NotNil(t, status.Policy)
	})
}

func TestSecretVersionManager(t *testing.T) {
	logger := logrus.New()
	storage := NewMemoryStorageService()
	versionManager := NewSecretVersionManager(storage, logger)

	t.Run("CreateVersion", func(t *testing.T) {
		ctx := context.Background()
		secretID := "test-secret"

		// Create first version
		version1, err := versionManager.CreateVersion(ctx, secretID, "value1", map[string]string{"key": "value"})
		require.NoError(t, err)
		assert.Equal(t, 1, version1.Version)
		assert.True(t, version1.IsActive)

		// Create second version
		version2, err := versionManager.CreateVersion(ctx, secretID, "value2", map[string]string{})
		require.NoError(t, err)
		assert.Equal(t, 2, version2.Version)
		assert.True(t, version2.IsActive)

		// Verify first version is no longer active
		version1Retrieved, err := versionManager.GetVersion(ctx, secretID, 1)
		require.NoError(t, err)
		assert.False(t, version1Retrieved.IsActive)
	})

	t.Run("GetLatestVersion", func(t *testing.T) {
		ctx := context.Background()
		secretID := "test-secret-latest"

		// Create versions
		versionManager.CreateVersion(ctx, secretID, "value1", map[string]string{})
		versionManager.CreateVersion(ctx, secretID, "value2", map[string]string{})

		latest, err := versionManager.GetLatestVersion(ctx, secretID)
		require.NoError(t, err)
		assert.Equal(t, 2, latest.Version)
		assert.Equal(t, "value2", latest.Value)
		assert.True(t, latest.IsActive)
	})

	t.Run("RollbackToVersion", func(t *testing.T) {
		ctx := context.Background()
		secretID := "test-secret-rollback"

		// Create versions
		versionManager.CreateVersion(ctx, secretID, "value1", map[string]string{})
		versionManager.CreateVersion(ctx, secretID, "value2", map[string]string{})
		versionManager.CreateVersion(ctx, secretID, "value3", map[string]string{})

		// Rollback to version 2
		err := versionManager.RollbackToVersion(ctx, secretID, 2)
		require.NoError(t, err)

		// Verify version 2 is now active
		latest, err := versionManager.GetLatestVersion(ctx, secretID)
		require.NoError(t, err)
		assert.Equal(t, 2, latest.Version)
		assert.Equal(t, "value2", latest.Value)
		assert.True(t, latest.IsActive)
	})

	t.Run("DeleteVersion", func(t *testing.T) {
		ctx := context.Background()
		secretID := "test-secret-delete"

		// Create versions
		versionManager.CreateVersion(ctx, secretID, "value1", map[string]string{})
		versionManager.CreateVersion(ctx, secretID, "value2", map[string]string{})

		// Try to delete active version (should fail)
		err := versionManager.DeleteVersion(ctx, secretID, 2)
		assert.Error(t, err)

		// Delete inactive version (should succeed)
		err = versionManager.DeleteVersion(ctx, secretID, 1)
		require.NoError(t, err)

		// Verify version 1 is gone
		_, err = versionManager.GetVersion(ctx, secretID, 1)
		assert.Error(t, err)
	})

	t.Run("CleanupOldVersions", func(t *testing.T) {
		ctx := context.Background()
		secretID := "test-secret-cleanup"

		// Create multiple versions
		for i := 1; i <= 5; i++ {
			versionManager.CreateVersion(ctx, secretID, fmt.Sprintf("value%d", i), map[string]string{})
		}

		// Cleanup, keeping only 3 versions
		err := versionManager.CleanupOldVersions(ctx, secretID, 3)
		require.NoError(t, err)

		// Verify we still have versions
		versions, err := versionManager.GetVersions(ctx, secretID)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(versions), 3)

		// Verify latest version is still active
		latest, err := versionManager.GetLatestVersion(ctx, secretID)
		require.NoError(t, err)
		assert.Equal(t, 5, latest.Version)
		assert.True(t, latest.IsActive)
	})
}

func TestScheduler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	executedTasks := make([]string, 0)
	executeCallback := func(ctx context.Context, task *RotationTask) error {
		executedTasks = append(executedTasks, task.ID)
		return nil
	}

	scheduler := NewScheduler(logger, executeCallback)

	t.Run("StartStop", func(t *testing.T) {
		ctx := context.Background()
		
		err := scheduler.Start(ctx)
		require.NoError(t, err)
		
		err = scheduler.Stop()
		require.NoError(t, err)
	})

	t.Run("ScheduleTask", func(t *testing.T) {
		ctx := context.Background()
		err := scheduler.Start(ctx)
		require.NoError(t, err)
		defer scheduler.Stop()

		task := &RotationTask{
			ID:          "test-task-1",
			SecretID:    "test-secret",
			ScheduledAt: time.Now().Add(100 * time.Millisecond),
			TriggerType: RotationTriggerScheduled,
			Priority:    1,
			CreatedAt:   time.Now(),
		}

		err = scheduler.Schedule(ctx, task)
		require.NoError(t, err)

		// Wait for task execution
		time.Sleep(200 * time.Millisecond)

		// Verify task was executed
		assert.Contains(t, executedTasks, "test-task-1")
	})

	t.Run("UnscheduleTask", func(t *testing.T) {
		ctx := context.Background()
		err := scheduler.Start(ctx)
		require.NoError(t, err)
		defer scheduler.Stop()

		task := &RotationTask{
			ID:          "test-task-2",
			SecretID:    "test-secret",
			ScheduledAt: time.Now().Add(time.Hour), // Far in the future
			TriggerType: RotationTriggerScheduled,
			Priority:    1,
			CreatedAt:   time.Now(),
		}

		err = scheduler.Schedule(ctx, task)
		require.NoError(t, err)

		// Unschedule the task
		err = scheduler.Unschedule(ctx, "test-task-2")
		require.NoError(t, err)

		// Verify task is not in scheduled tasks
		tasks, err := scheduler.GetScheduledTasks(ctx)
		require.NoError(t, err)
		
		found := false
		for _, t := range tasks {
			if t.ID == "test-task-2" {
				found = true
				break
			}
		}
		assert.False(t, found)
	})
}

func TestLifecycleManager(t *testing.T) {
	logger := logrus.New()
	config := DefaultRotationConfig()
	storage := NewMemoryStorageService()
	notificationSvc := &MockNotificationService{}
	
	lifecycleManager := NewLifecycleManager(config, storage, nil, notificationSvc, logger)

	t.Run("SetExpirationPolicy", func(t *testing.T) {
		ctx := context.Background()
		secretID := "test-secret"

		policy := &ExpirationPolicy{
			ExpirationTime:     30 * 24 * time.Hour,
			WarningThreshold:   24 * time.Hour,
			AutoRotate:         true,
			CleanupAfterExpiry: 7 * 24 * time.Hour,
		}

		err := lifecycleManager.SetExpirationPolicy(ctx, secretID, policy)
		require.NoError(t, err)
		assert.Equal(t, secretID, policy.SecretID)
	})

	t.Run("GetExpirationPolicy", func(t *testing.T) {
		ctx := context.Background()
		secretID := "test-secret"

		policy, err := lifecycleManager.GetExpirationPolicy(ctx, secretID)
		require.NoError(t, err)
		assert.Equal(t, secretID, policy.SecretID)
		assert.Greater(t, policy.ExpirationTime, time.Duration(0))
	})
}