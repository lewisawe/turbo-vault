package rotation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Manager implements the RotationManager interface
type Manager struct {
	config           *RotationConfig
	storage          StorageService
	versionManager   SecretVersionManager
	lifecycleManager LifecycleManager
	scheduler        SchedulerService
	notificationSvc  NotificationService
	rotators         map[string]SecretRotator
	logger           *logrus.Logger
	
	// Runtime state
	running          bool
	stopChan         chan struct{}
	rotationSemaphore chan struct{} // Limits concurrent rotations
	mu               sync.RWMutex
}

// NewManager creates a new rotation manager
func NewManager(
	config *RotationConfig,
	storage StorageService,
	versionManager SecretVersionManager,
	lifecycleManager LifecycleManager,
	scheduler SchedulerService,
	notificationSvc NotificationService,
	logger *logrus.Logger,
) *Manager {
	if config == nil {
		config = DefaultRotationConfig()
	}

	return &Manager{
		config:            config,
		storage:           storage,
		versionManager:    versionManager,
		lifecycleManager:  lifecycleManager,
		scheduler:         scheduler,
		notificationSvc:   notificationSvc,
		rotators:          make(map[string]SecretRotator),
		logger:            logger,
		stopChan:          make(chan struct{}),
		rotationSemaphore: make(chan struct{}, config.MaxConcurrentRotations),
	}
}

// Start starts the rotation manager background processes
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("rotation manager is already running")
	}
	m.running = true
	m.mu.Unlock()

	// Register default rotators (this calls RegisterRotator which needs the lock)
	m.registerDefaultRotators()

	// Start scheduler
	if err := m.scheduler.Start(ctx); err != nil {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
		return fmt.Errorf("failed to start scheduler: %w", err)
	}
	
	// Start background processes
	go m.rotationCheckLoop(ctx)
	go m.expirationCheckLoop(ctx)
	go m.versionCleanupLoop(ctx)

	m.logger.Info("Rotation manager started")
	return nil
}

// Stop stops the rotation manager
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	close(m.stopChan)
	
	// Stop scheduler
	if err := m.scheduler.Stop(); err != nil {
		m.logger.Errorf("Error stopping scheduler: %v", err)
	}

	m.running = false
	
	// Create new stop channel for next start
	m.stopChan = make(chan struct{})
	
	m.logger.Info("Rotation manager stopped")
	return nil
}

// ScheduleRotation schedules a secret for rotation
func (m *Manager) ScheduleRotation(ctx context.Context, secretID string, policy *RotationPolicy) error {
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	policy.SecretID = secretID
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	// Validate policy
	if err := m.validateRotationPolicy(policy); err != nil {
		return fmt.Errorf("invalid rotation policy: %w", err)
	}

	// Save policy
	if err := m.storage.SaveRotationPolicy(ctx, policy); err != nil {
		return fmt.Errorf("failed to save rotation policy: %w", err)
	}

	// Schedule rotation task if needed
	if policy.Schedule != nil {
		nextExecution := m.calculateNextExecution(policy.Schedule)
		if nextExecution != nil {
			task := &RotationTask{
				ID:          uuid.New().String(),
				SecretID:    secretID,
				ScheduledAt: *nextExecution,
				TriggerType: RotationTriggerScheduled,
				Priority:    1,
				Policy:      policy,
				CreatedAt:   time.Now(),
			}

			if err := m.scheduler.Schedule(ctx, task); err != nil {
				return fmt.Errorf("failed to schedule rotation task: %w", err)
			}
		}
	}

	m.logger.Infof("Scheduled rotation for secret %s", secretID)
	return nil
}

// ExecuteRotation executes rotation for a specific secret
func (m *Manager) ExecuteRotation(ctx context.Context, secretID string) error {
	// Acquire semaphore to limit concurrent rotations
	select {
	case m.rotationSemaphore <- struct{}{}:
		defer func() { <-m.rotationSemaphore }()
	case <-ctx.Done():
		return ctx.Err()
	}

	// Get rotation policy
	policy, err := m.storage.GetRotationPolicy(ctx, secretID)
	if err != nil {
		return fmt.Errorf("failed to get rotation policy: %w", err)
	}

	if !policy.Enabled {
		return fmt.Errorf("rotation is disabled for secret %s", secretID)
	}

	// Get current secret version
	currentVersion, err := m.versionManager.GetLatestVersion(ctx, secretID)
	if err != nil {
		return fmt.Errorf("failed to get current secret version: %w", err)
	}

	// Create rotation event
	event := &RotationEvent{
		ID:          uuid.New().String(),
		SecretID:    secretID,
		Status:      RotationStatusRunning,
		TriggerType: RotationTriggerManual,
		StartedAt:   time.Now(),
		OldVersion:  currentVersion.Version,
		RotatorType: policy.RotatorType,
		Attempt:     1,
		MaxAttempts: policy.RetryPolicy.MaxAttempts,
		Metadata:    make(map[string]string),
	}

	// Save initial event
	if err := m.storage.SaveRotationEvent(ctx, event); err != nil {
		m.logger.Errorf("Failed to save rotation event: %v", err)
	}

	// Update rotation status
	if err := m.storage.UpdateRotationStatus(ctx, secretID, RotationStatusRunning); err != nil {
		m.logger.Errorf("Failed to update rotation status: %v", err)
	}

	// Execute rotation with retry logic
	result := m.executeRotationWithRetry(ctx, secretID, policy, event)

	// Update event with result
	now := time.Now()
	event.CompletedAt = &now
	duration := now.Sub(event.StartedAt)
	event.Duration = &duration

	if result.Success {
		event.Status = RotationStatusCompleted
		event.NewVersion = result.NewVersion
		
		// Update rotation status
		m.storage.UpdateRotationStatus(ctx, secretID, RotationStatusCompleted)
		
		// Send success notification
		if m.notificationSvc != nil {
			if err := m.notificationSvc.NotifyRotationSuccess(ctx, event); err != nil {
				m.logger.Errorf("Failed to send rotation success notification: %v", err)
			}
		}
		
		m.logger.Infof("Successfully rotated secret %s to version %d", secretID, result.NewVersion)
	} else {
		event.Status = RotationStatusFailed
		event.Error = result.Error.Error()
		event.ErrorCode = result.ErrorCode
		
		// Update rotation status
		m.storage.UpdateRotationStatus(ctx, secretID, RotationStatusFailed)
		
		// Handle rollback if configured
		if policy.RollbackOnFailure && result.NewVersion > 0 {
			if err := m.rollbackRotation(ctx, secretID, currentVersion.Version, policy); err != nil {
				m.logger.Errorf("Failed to rollback rotation for secret %s: %v", secretID, err)
			}
		}
		
		// Send failure notification
		if m.notificationSvc != nil {
			if err := m.notificationSvc.NotifyRotationFailure(ctx, event); err != nil {
				m.logger.Errorf("Failed to send rotation failure notification: %v", err)
			}
		}
		
		m.logger.Errorf("Failed to rotate secret %s: %v", secretID, result.Error)
	}

	// Save final event
	if err := m.storage.SaveRotationEvent(ctx, event); err != nil {
		m.logger.Errorf("Failed to save final rotation event: %v", err)
	}

	if result.Success {
		return nil
	}
	return result.Error
}

// executeRotationWithRetry executes rotation with retry logic
func (m *Manager) executeRotationWithRetry(ctx context.Context, secretID string, policy *RotationPolicy, event *RotationEvent) *RotationResult {
	retryPolicy := policy.RetryPolicy
	if retryPolicy == nil {
		retryPolicy = m.config.DefaultRetryPolicy
	}

	var lastResult *RotationResult
	
	for attempt := 1; attempt <= retryPolicy.MaxAttempts; attempt++ {
		event.Attempt = attempt
		
		// Execute rotation
		result := m.executeRotationAttempt(ctx, secretID, policy)
		lastResult = result
		
		if result.Success {
			return result
		}
		
		// Check if we should retry
		if attempt < retryPolicy.MaxAttempts && m.shouldRetry(result.ErrorCode, retryPolicy.RetryOn) {
			delay := m.calculateRetryDelay(attempt, retryPolicy)
			m.logger.Warnf("Rotation attempt %d failed for secret %s, retrying in %v: %v", 
				attempt, secretID, delay, result.Error)
			
			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				result.Error = ctx.Err()
				return result
			}
		} else {
			break
		}
	}
	
	return lastResult
}

// executeRotationAttempt executes a single rotation attempt
func (m *Manager) executeRotationAttempt(ctx context.Context, secretID string, policy *RotationPolicy) *RotationResult {
	startTime := time.Now()
	
	// Get rotator
	rotator, err := m.GetRotator(policy.RotatorType)
	if err != nil {
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("rotator not found: %w", err),
			ErrorCode: "rotator_not_found",
			Duration:  time.Since(startTime),
		}
	}
	
	// Get current secret
	currentVersion, err := m.versionManager.GetLatestVersion(ctx, secretID)
	if err != nil {
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("failed to get current secret: %w", err),
			ErrorCode: "secret_not_found",
			Duration:  time.Since(startTime),
		}
	}
	
	secret := &Secret{
		ID:       secretID,
		Value:    currentVersion.Value,
		Version:  currentVersion.Version,
		Metadata: currentVersion.Metadata,
	}
	
	// Execute rotation
	result, err := rotator.Rotate(ctx, secret, policy.RotatorConfig)
	if err != nil {
		return &RotationResult{
			Success:   false,
			Error:     err,
			ErrorCode: "rotation_failed",
			Duration:  time.Since(startTime),
		}
	}
	
	// Create new version if rotation succeeded
	if result.Success && result.NewValue != "" {
		newVersion, err := m.versionManager.CreateVersion(ctx, secretID, result.NewValue, result.Metadata)
		if err != nil {
			return &RotationResult{
				Success:   false,
				Error:     fmt.Errorf("failed to create new version: %w", err),
				ErrorCode: "version_creation_failed",
				Duration:  time.Since(startTime),
			}
		}
		result.NewVersion = newVersion.Version
	}
	
	result.Duration = time.Since(startTime)
	return result
}

// CancelRotation cancels a scheduled rotation
func (m *Manager) CancelRotation(ctx context.Context, secretID string) error {
	// Update rotation status
	if err := m.storage.UpdateRotationStatus(ctx, secretID, RotationStatusCancelled); err != nil {
		return fmt.Errorf("failed to update rotation status: %w", err)
	}

	m.logger.Infof("Cancelled rotation for secret %s", secretID)
	return nil
}

// GetRotationStatus returns the rotation status for a secret
func (m *Manager) GetRotationStatus(ctx context.Context, secretID string) (*RotationStatus, error) {
	policy, err := m.storage.GetRotationPolicy(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to get rotation policy: %w", err)
	}

	events, err := m.storage.GetRotationEvents(ctx, secretID, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to get rotation events: %w", err)
	}

	status := &RotationStatus{
		SecretID: secretID,
		Status:   RotationStatusPending,
		Policy:   policy,
	}

	if len(events) > 0 {
		lastEvent := events[0]
		status.Status = lastEvent.Status
		if lastEvent.CompletedAt != nil {
			status.LastRotation = lastEvent.CompletedAt
		}
		status.CurrentVersion = lastEvent.NewVersion
		if lastEvent.Error != "" {
			status.LastError = lastEvent.Error
			status.LastErrorAt = lastEvent.CompletedAt
		}
		status.RetryCount = lastEvent.Attempt - 1
	}

	// Calculate next rotation time
	if policy.Schedule != nil {
		nextExecution := m.calculateNextExecution(policy.Schedule)
		status.NextRotation = nextExecution
	}

	return status, nil
}

// GetRotationHistory returns the rotation history for a secret
func (m *Manager) GetRotationHistory(ctx context.Context, secretID string, limit int) ([]*RotationEvent, error) {
	return m.storage.GetRotationEvents(ctx, secretID, limit)
}

// ListPendingRotations returns all secrets pending rotation
func (m *Manager) ListPendingRotations(ctx context.Context) ([]*PendingRotation, error) {
	return m.storage.GetPendingRotations(ctx)
}

// RegisterRotator registers a custom rotation strategy
func (m *Manager) RegisterRotator(name string, rotator SecretRotator) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rotators[name] = rotator
	m.logger.Infof("Registered rotator: %s", name)
	return nil
}

// GetRotator retrieves a registered rotator by name
func (m *Manager) GetRotator(name string) (SecretRotator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rotator, exists := m.rotators[name]
	if !exists {
		return nil, fmt.Errorf("rotator %s not found", name)
	}

	return rotator, nil
}

// ListRotators returns all registered rotators
func (m *Manager) ListRotators() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rotators := make([]string, 0, len(m.rotators))
	for name := range m.rotators {
		rotators = append(rotators, name)
	}

	return rotators
}

// Background processes

// rotationCheckLoop periodically checks for rotations that need to be executed
func (m *Manager) rotationCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkPendingRotations(ctx)
		case <-m.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// expirationCheckLoop periodically checks for expired secrets
func (m *Manager) expirationCheckLoop(ctx context.Context) {
	if !m.config.ExpirationCheck.Enabled {
		return
	}

	ticker := time.NewTicker(m.config.ExpirationCheck.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.lifecycleManager.ProcessExpirations(ctx); err != nil {
				m.logger.Errorf("Error processing expirations: %v", err)
			}
		case <-m.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// versionCleanupLoop periodically cleans up old versions
func (m *Manager) versionCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.VersionRetention.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanupOldVersions(ctx)
		case <-m.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// Helper methods

// validateRotationPolicy validates a rotation policy
func (m *Manager) validateRotationPolicy(policy *RotationPolicy) error {
	if policy.SecretID == "" {
		return fmt.Errorf("secret ID is required")
	}

	if policy.RotatorType == "" {
		return fmt.Errorf("rotator type is required")
	}

	// Check if rotator exists
	if _, err := m.GetRotator(policy.RotatorType); err != nil {
		return fmt.Errorf("invalid rotator type: %w", err)
	}

	// Validate rotator configuration
	rotator, _ := m.GetRotator(policy.RotatorType)
	if err := rotator.Validate(policy.RotatorConfig); err != nil {
		return fmt.Errorf("invalid rotator configuration: %w", err)
	}

	return nil
}

// calculateNextExecution calculates the next execution time for a schedule
func (m *Manager) calculateNextExecution(schedule *ScheduleConfig) *time.Time {
	now := time.Now()
	
	switch schedule.Type {
	case "interval":
		next := now.Add(schedule.Interval)
		return &next
	case "fixed":
		if schedule.FixedTime.After(now) {
			return &schedule.FixedTime
		}
		return nil
	case "cron":
		// TODO: Implement cron parsing
		return nil
	default:
		return nil
	}
}

// shouldRetry determines if a rotation should be retried based on error code
func (m *Manager) shouldRetry(errorCode string, retryOn []string) bool {
	for _, retryableError := range retryOn {
		if errorCode == retryableError {
			return true
		}
	}
	return false
}

// calculateRetryDelay calculates the delay for retry attempts
func (m *Manager) calculateRetryDelay(attempt int, policy *RetryPolicy) time.Duration {
	delay := policy.InitialDelay
	for i := 1; i < attempt; i++ {
		delay = time.Duration(float64(delay) * policy.BackoffFactor)
		if delay > policy.MaxDelay {
			delay = policy.MaxDelay
			break
		}
	}
	return delay
}

// rollbackRotation rolls back a failed rotation
func (m *Manager) rollbackRotation(ctx context.Context, secretID string, targetVersion int, policy *RotationPolicy) error {
	rotator, err := m.GetRotator(policy.RotatorType)
	if err != nil {
		return fmt.Errorf("rotator not found: %w", err)
	}

	if !rotator.SupportsRollback() {
		return fmt.Errorf("rotator %s does not support rollback", policy.RotatorType)
	}

	// Get target version
	targetVersionData, err := m.versionManager.GetVersion(ctx, secretID, targetVersion)
	if err != nil {
		return fmt.Errorf("failed to get target version: %w", err)
	}

	secret := &Secret{
		ID:       secretID,
		Value:    targetVersionData.Value,
		Version:  targetVersionData.Version,
		Metadata: targetVersionData.Metadata,
	}

	return rotator.Rollback(ctx, secret, targetVersion)
}

// checkPendingRotations checks for rotations that need to be executed
func (m *Manager) checkPendingRotations(ctx context.Context) {
	pendingRotations, err := m.storage.GetPendingRotations(ctx)
	if err != nil {
		m.logger.Errorf("Failed to get pending rotations: %v", err)
		return
	}

	for _, pending := range pendingRotations {
		if time.Now().After(pending.ScheduledAt) {
			go func(secretID string) {
				if err := m.ExecuteRotation(ctx, secretID); err != nil {
					m.logger.Errorf("Failed to execute scheduled rotation for secret %s: %v", secretID, err)
				}
			}(pending.SecretID)
		}
	}
}

// cleanupOldVersions cleans up old secret versions
func (m *Manager) cleanupOldVersions(ctx context.Context) {
	// This would iterate through all secrets and clean up old versions
	// Implementation depends on how secrets are stored
	m.logger.Debug("Cleaning up old secret versions")
}

// registerDefaultRotators registers the default rotation strategies
func (m *Manager) registerDefaultRotators() {
	// Register built-in rotators
	m.RegisterRotator("random", NewRandomRotator())
	m.RegisterRotator("script", NewScriptRotator(m.logger))
	m.RegisterRotator("api", NewAPIRotator(m.logger))
}