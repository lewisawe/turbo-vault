package backup

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

// BackupScheduler manages scheduled backup operations
type BackupScheduler struct {
	manager    *Manager
	cron       *cron.Cron
	schedules  map[string]*BackupSchedule
	mu         sync.RWMutex
	logger     *log.Logger
	ctx        context.Context
	cancel     context.CancelFunc
}

// BackupSchedule defines a scheduled backup configuration
type BackupSchedule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	CronExpr    string        `json:"cron_expression"`
	Config      *BackupConfig `json:"config"`
	Enabled     bool          `json:"enabled"`
	NextRun     time.Time     `json:"next_run"`
	LastRun     *time.Time    `json:"last_run,omitempty"`
	LastStatus  string        `json:"last_status,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	cronEntryID cron.EntryID  `json:"-"`
}

// NewBackupScheduler creates a new backup scheduler
func NewBackupScheduler(manager *Manager, logger *log.Logger) *BackupScheduler {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &BackupScheduler{
		manager:   manager,
		cron:      cron.New(cron.WithSeconds()),
		schedules: make(map[string]*BackupSchedule),
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start starts the backup scheduler
func (bs *BackupScheduler) Start() error {
	bs.cron.Start()
	bs.logger.Println("Backup scheduler started")
	return nil
}

// Stop stops the backup scheduler
func (bs *BackupScheduler) Stop() error {
	bs.cancel()
	ctx := bs.cron.Stop()
	<-ctx.Done()
	bs.logger.Println("Backup scheduler stopped")
	return nil
}

// AddSchedule adds a new backup schedule
func (bs *BackupScheduler) AddSchedule(schedule *BackupSchedule) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Validate cron expression (with seconds support)
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	_, err := parser.Parse(schedule.CronExpr)
	if err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	// Set timestamps
	now := time.Now().UTC()
	if schedule.CreatedAt.IsZero() {
		schedule.CreatedAt = now
	}
	schedule.UpdatedAt = now

	// Add to cron if enabled
	if schedule.Enabled {
		entryID, err := bs.cron.AddFunc(schedule.CronExpr, func() {
			bs.executeScheduledBackup(schedule.ID)
		})
		if err != nil {
			return fmt.Errorf("failed to add cron job: %w", err)
		}
		schedule.cronEntryID = entryID

		// Calculate next run time
		entries := bs.cron.Entries()
		for _, entry := range entries {
			if entry.ID == entryID {
				schedule.NextRun = entry.Next
				break
			}
		}
	}

	bs.schedules[schedule.ID] = schedule
	bs.logger.Printf("Added backup schedule: %s", schedule.Name)
	return nil
}

// RemoveSchedule removes a backup schedule
func (bs *BackupScheduler) RemoveSchedule(scheduleID string) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	schedule, exists := bs.schedules[scheduleID]
	if !exists {
		return fmt.Errorf("schedule not found: %s", scheduleID)
	}

	// Remove from cron
	if schedule.Enabled && schedule.cronEntryID != 0 {
		bs.cron.Remove(schedule.cronEntryID)
	}

	delete(bs.schedules, scheduleID)
	bs.logger.Printf("Removed backup schedule: %s", schedule.Name)
	return nil
}

// UpdateSchedule updates an existing backup schedule
func (bs *BackupScheduler) UpdateSchedule(schedule *BackupSchedule) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	existing, exists := bs.schedules[schedule.ID]
	if !exists {
		return fmt.Errorf("schedule not found: %s", schedule.ID)
	}

	// Remove existing cron job
	if existing.Enabled && existing.cronEntryID != 0 {
		bs.cron.Remove(existing.cronEntryID)
	}

	// Validate new cron expression (with seconds support)
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	_, err := parser.Parse(schedule.CronExpr)
	if err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	// Update timestamps
	schedule.CreatedAt = existing.CreatedAt
	schedule.UpdatedAt = time.Now().UTC()

	// Add new cron job if enabled
	if schedule.Enabled {
		entryID, err := bs.cron.AddFunc(schedule.CronExpr, func() {
			bs.executeScheduledBackup(schedule.ID)
		})
		if err != nil {
			return fmt.Errorf("failed to add cron job: %w", err)
		}
		schedule.cronEntryID = entryID

		// Calculate next run time
		entries := bs.cron.Entries()
		for _, entry := range entries {
			if entry.ID == entryID {
				schedule.NextRun = entry.Next
				break
			}
		}
	}

	bs.schedules[schedule.ID] = schedule
	bs.logger.Printf("Updated backup schedule: %s", schedule.Name)
	return nil
}

// GetSchedule retrieves a backup schedule
func (bs *BackupScheduler) GetSchedule(scheduleID string) (*BackupSchedule, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	schedule, exists := bs.schedules[scheduleID]
	if !exists {
		return nil, fmt.Errorf("schedule not found: %s", scheduleID)
	}

	// Create a copy to avoid race conditions
	scheduleCopy := *schedule
	return &scheduleCopy, nil
}

// ListSchedules returns all backup schedules
func (bs *BackupScheduler) ListSchedules() []*BackupSchedule {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	schedules := make([]*BackupSchedule, 0, len(bs.schedules))
	for _, schedule := range bs.schedules {
		scheduleCopy := *schedule
		schedules = append(schedules, &scheduleCopy)
	}

	return schedules
}

// EnableSchedule enables a backup schedule
func (bs *BackupScheduler) EnableSchedule(scheduleID string) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	schedule, exists := bs.schedules[scheduleID]
	if !exists {
		return fmt.Errorf("schedule not found: %s", scheduleID)
	}

	if schedule.Enabled {
		return nil // Already enabled
	}

	// Add to cron
	entryID, err := bs.cron.AddFunc(schedule.CronExpr, func() {
		bs.executeScheduledBackup(schedule.ID)
	})
	if err != nil {
		return fmt.Errorf("failed to add cron job: %w", err)
	}

	schedule.cronEntryID = entryID
	schedule.Enabled = true
	schedule.UpdatedAt = time.Now().UTC()

	// Calculate next run time
	entries := bs.cron.Entries()
	for _, entry := range entries {
		if entry.ID == entryID {
			schedule.NextRun = entry.Next
			break
		}
	}

	bs.logger.Printf("Enabled backup schedule: %s", schedule.Name)
	return nil
}

// DisableSchedule disables a backup schedule
func (bs *BackupScheduler) DisableSchedule(scheduleID string) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	schedule, exists := bs.schedules[scheduleID]
	if !exists {
		return fmt.Errorf("schedule not found: %s", scheduleID)
	}

	if !schedule.Enabled {
		return nil // Already disabled
	}

	// Remove from cron
	if schedule.cronEntryID != 0 {
		bs.cron.Remove(schedule.cronEntryID)
	}

	schedule.Enabled = false
	schedule.cronEntryID = 0
	schedule.UpdatedAt = time.Now().UTC()

	bs.logger.Printf("Disabled backup schedule: %s", schedule.Name)
	return nil
}

// ExecuteNow executes a backup schedule immediately
func (bs *BackupScheduler) ExecuteNow(scheduleID string) (*BackupInfo, error) {
	bs.mu.RLock()
	schedule, exists := bs.schedules[scheduleID]
	bs.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("schedule not found: %s", scheduleID)
	}

	return bs.manager.CreateBackup(bs.ctx, schedule.Config)
}

// executeScheduledBackup executes a scheduled backup
func (bs *BackupScheduler) executeScheduledBackup(scheduleID string) {
	bs.mu.Lock()
	schedule, exists := bs.schedules[scheduleID]
	if !exists {
		bs.mu.Unlock()
		return
	}

	// Update last run time
	now := time.Now().UTC()
	schedule.LastRun = &now
	schedule.LastStatus = "running"

	// Calculate next run time
	entries := bs.cron.Entries()
	for _, entry := range entries {
		if entry.ID == schedule.cronEntryID {
			schedule.NextRun = entry.Next
			break
		}
	}
	bs.mu.Unlock()

	// Execute backup
	backupInfo, err := bs.manager.CreateBackup(bs.ctx, schedule.Config)
	
	// Update status
	bs.mu.Lock()
	if err != nil {
		schedule.LastStatus = fmt.Sprintf("failed: %v", err)
		bs.logger.Printf("Scheduled backup failed for %s: %v", schedule.Name, err)
	} else {
		schedule.LastStatus = "completed"
		bs.logger.Printf("Scheduled backup completed for %s: %s", schedule.Name, backupInfo.ID)
	}
	bs.mu.Unlock()
}

// GetNextRunTimes returns the next run times for all enabled schedules
func (bs *BackupScheduler) GetNextRunTimes() map[string]time.Time {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	nextRuns := make(map[string]time.Time)
	for id, schedule := range bs.schedules {
		if schedule.Enabled {
			nextRuns[id] = schedule.NextRun
		}
	}

	return nextRuns
}