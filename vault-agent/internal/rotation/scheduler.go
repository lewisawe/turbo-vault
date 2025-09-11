package rotation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// SchedulerImpl implements the SchedulerService interface
type SchedulerImpl struct {
	tasks    map[string]*RotationTask
	timers   map[string]*time.Timer
	logger   *logrus.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
	
	// Callback function to execute when a task is due
	executeCallback func(ctx context.Context, task *RotationTask) error
}

// NewScheduler creates a new scheduler
func NewScheduler(logger *logrus.Logger, executeCallback func(ctx context.Context, task *RotationTask) error) *SchedulerImpl {
	return &SchedulerImpl{
		tasks:           make(map[string]*RotationTask),
		timers:          make(map[string]*time.Timer),
		logger:          logger,
		stopChan:        make(chan struct{}),
		executeCallback: executeCallback,
	}
}

// Start starts the scheduler
func (s *SchedulerImpl) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("scheduler is already running")
	}

	s.running = true
	s.logger.Info("Scheduler started")
	return nil
}

// Stop stops the scheduler
func (s *SchedulerImpl) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	close(s.stopChan)

	// Cancel all timers
	for taskID, timer := range s.timers {
		timer.Stop()
		delete(s.timers, taskID)
	}

	s.running = false
	
	// Create new stop channel for next start
	s.stopChan = make(chan struct{})
	
	s.logger.Info("Scheduler stopped")
	return nil
}

// Schedule schedules a rotation task
func (s *SchedulerImpl) Schedule(ctx context.Context, task *RotationTask) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return fmt.Errorf("scheduler is not running")
	}

	// Cancel existing timer if task already exists
	if existingTimer, exists := s.timers[task.ID]; exists {
		existingTimer.Stop()
		delete(s.timers, task.ID)
	}

	// Store task
	s.tasks[task.ID] = task

	// Calculate delay until execution
	delay := time.Until(task.ScheduledAt)
	if delay <= 0 {
		// Task is overdue, execute immediately
		go s.executeTask(ctx, task)
		return nil
	}

	// Create timer for future execution
	timer := time.AfterFunc(delay, func() {
		s.executeTask(ctx, task)
	})

	s.timers[task.ID] = timer
	s.logger.Infof("Scheduled task %s for execution at %v", task.ID, task.ScheduledAt)
	return nil
}

// Unschedule removes a scheduled rotation task
func (s *SchedulerImpl) Unschedule(ctx context.Context, taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Cancel timer
	if timer, exists := s.timers[taskID]; exists {
		timer.Stop()
		delete(s.timers, taskID)
	}

	// Remove task
	delete(s.tasks, taskID)

	s.logger.Infof("Unscheduled task %s", taskID)
	return nil
}

// GetScheduledTasks returns all scheduled rotation tasks
func (s *SchedulerImpl) GetScheduledTasks(ctx context.Context) ([]*RotationTask, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tasks := make([]*RotationTask, 0, len(s.tasks))
	for _, task := range s.tasks {
		taskCopy := *task
		tasks = append(tasks, &taskCopy)
	}

	return tasks, nil
}

// GetNextExecution returns the next execution time for a task
func (s *SchedulerImpl) GetNextExecution(ctx context.Context, taskID string) (*time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	task, exists := s.tasks[taskID]
	if !exists {
		return nil, fmt.Errorf("task %s not found", taskID)
	}

	return &task.ScheduledAt, nil
}

// executeTask executes a scheduled task
func (s *SchedulerImpl) executeTask(ctx context.Context, task *RotationTask) {
	s.logger.Infof("Executing scheduled task %s for secret %s", task.ID, task.SecretID)

	// Remove task from scheduler after execution
	defer func() {
		s.mu.Lock()
		delete(s.tasks, task.ID)
		delete(s.timers, task.ID)
		s.mu.Unlock()
	}()

	// Execute the callback
	if s.executeCallback != nil {
		if err := s.executeCallback(ctx, task); err != nil {
			s.logger.Errorf("Failed to execute scheduled task %s: %v", task.ID, err)
		}
	}

	// Reschedule if this is a recurring task
	if task.Policy != nil && task.Policy.Schedule != nil {
		s.rescheduleRecurringTask(ctx, task)
	}
}

// rescheduleRecurringTask reschedules a recurring task
func (s *SchedulerImpl) rescheduleRecurringTask(ctx context.Context, task *RotationTask) {
	schedule := task.Policy.Schedule
	if schedule == nil {
		return
	}

	var nextExecution *time.Time

	switch schedule.Type {
	case "interval":
		next := time.Now().Add(schedule.Interval)
		nextExecution = &next
	case "cron":
		// TODO: Implement cron scheduling
		s.logger.Warn("Cron scheduling not yet implemented")
		return
	default:
		s.logger.Warnf("Unknown schedule type: %s", schedule.Type)
		return
	}

	if nextExecution != nil {
		newTask := &RotationTask{
			ID:          fmt.Sprintf("%s-next", task.ID),
			SecretID:    task.SecretID,
			ScheduledAt: *nextExecution,
			TriggerType: task.TriggerType,
			Priority:    task.Priority,
			Policy:      task.Policy,
			CreatedAt:   time.Now(),
			CreatedBy:   "scheduler",
		}

		if err := s.Schedule(ctx, newTask); err != nil {
			s.logger.Errorf("Failed to reschedule recurring task: %v", err)
		}
	}
}

// MemoryStorageService provides an in-memory implementation of StorageService for testing
type MemoryStorageService struct {
	rotationEvents   map[string][]*RotationEvent
	rotationPolicies map[string]*RotationPolicy
	secretVersions   map[string][]*SecretVersion
	mu               sync.RWMutex
}

// NewMemoryStorageService creates a new in-memory storage service
func NewMemoryStorageService() *MemoryStorageService {
	return &MemoryStorageService{
		rotationEvents:   make(map[string][]*RotationEvent),
		rotationPolicies: make(map[string]*RotationPolicy),
		secretVersions:   make(map[string][]*SecretVersion),
	}
}

// SaveRotationEvent saves a rotation event
func (mss *MemoryStorageService) SaveRotationEvent(ctx context.Context, event *RotationEvent) error {
	mss.mu.Lock()
	defer mss.mu.Unlock()

	events := mss.rotationEvents[event.SecretID]
	
	// Update existing event or add new one
	found := false
	for i, e := range events {
		if e.ID == event.ID {
			events[i] = event
			found = true
			break
		}
	}
	
	if !found {
		events = append(events, event)
	}
	
	mss.rotationEvents[event.SecretID] = events
	return nil
}

// GetRotationEvents retrieves rotation events for a secret
func (mss *MemoryStorageService) GetRotationEvents(ctx context.Context, secretID string, limit int) ([]*RotationEvent, error) {
	mss.mu.RLock()
	defer mss.mu.RUnlock()

	events := mss.rotationEvents[secretID]
	if len(events) == 0 {
		return []*RotationEvent{}, nil
	}

	// Return most recent events first
	result := make([]*RotationEvent, 0, len(events))
	for i := len(events) - 1; i >= 0 && len(result) < limit; i-- {
		eventCopy := *events[i]
		result = append(result, &eventCopy)
	}

	return result, nil
}

// SaveRotationPolicy saves a rotation policy
func (mss *MemoryStorageService) SaveRotationPolicy(ctx context.Context, policy *RotationPolicy) error {
	mss.mu.Lock()
	defer mss.mu.Unlock()

	mss.rotationPolicies[policy.SecretID] = policy
	return nil
}

// GetRotationPolicy retrieves a rotation policy
func (mss *MemoryStorageService) GetRotationPolicy(ctx context.Context, secretID string) (*RotationPolicy, error) {
	mss.mu.RLock()
	defer mss.mu.RUnlock()

	policy, exists := mss.rotationPolicies[secretID]
	if !exists {
		return nil, fmt.Errorf("rotation policy not found for secret %s", secretID)
	}

	policyCopy := *policy
	return &policyCopy, nil
}

// DeleteRotationPolicy deletes a rotation policy
func (mss *MemoryStorageService) DeleteRotationPolicy(ctx context.Context, secretID string) error {
	mss.mu.Lock()
	defer mss.mu.Unlock()

	delete(mss.rotationPolicies, secretID)
	return nil
}

// SaveSecretVersion saves a secret version
func (mss *MemoryStorageService) SaveSecretVersion(ctx context.Context, version *SecretVersion) error {
	mss.mu.Lock()
	defer mss.mu.Unlock()

	versions := mss.secretVersions[version.SecretID]
	
	// Update existing version or add new one
	found := false
	for i, v := range versions {
		if v.Version == version.Version {
			versions[i] = version
			found = true
			break
		}
	}
	
	if !found {
		versions = append(versions, version)
	}
	
	mss.secretVersions[version.SecretID] = versions
	return nil
}

// GetSecretVersions retrieves all versions of a secret
func (mss *MemoryStorageService) GetSecretVersions(ctx context.Context, secretID string) ([]*SecretVersion, error) {
	mss.mu.RLock()
	defer mss.mu.RUnlock()

	versions := mss.secretVersions[secretID]
	result := make([]*SecretVersion, len(versions))
	for i, v := range versions {
		versionCopy := *v
		result[i] = &versionCopy
	}

	return result, nil
}

// DeleteSecretVersion deletes a secret version
func (mss *MemoryStorageService) DeleteSecretVersion(ctx context.Context, secretID string, version int) error {
	mss.mu.Lock()
	defer mss.mu.Unlock()

	versions := mss.secretVersions[secretID]
	for i, v := range versions {
		if v.Version == version {
			// Remove version from slice
			versions = append(versions[:i], versions[i+1:]...)
			mss.secretVersions[secretID] = versions
			return nil
		}
	}

	return fmt.Errorf("version %d not found for secret %s", version, secretID)
}

// GetPendingRotations retrieves secrets pending rotation
func (mss *MemoryStorageService) GetPendingRotations(ctx context.Context) ([]*PendingRotation, error) {
	mss.mu.RLock()
	defer mss.mu.RUnlock()

	// For now, return empty list
	// In a real implementation, this would query for secrets that need rotation
	return []*PendingRotation{}, nil
}

// UpdateRotationStatus updates the rotation status for a secret
func (mss *MemoryStorageService) UpdateRotationStatus(ctx context.Context, secretID string, status RotationStatusType) error {
	// For in-memory implementation, we don't need to track status separately
	// as it's part of the rotation events
	return nil
}