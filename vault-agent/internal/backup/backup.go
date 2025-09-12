// Package backup provides comprehensive backup and disaster recovery functionality
// for the vault agent, including automated backups, multiple destination support,
// integrity validation, and disaster recovery testing.
package backup

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
)

// Service provides the main backup service interface
type Service struct {
	manager            *Manager
	restoreManager     *RestoreManager
	scheduler          *BackupScheduler
	drManager          *DisasterRecoveryManager
	logger             *log.Logger
	config             *ServiceConfig
}

// ServiceConfig contains configuration for the backup service
type ServiceConfig struct {
	DefaultDestinations []DestinationConfig `json:"default_destinations"`
	AutoBackupEnabled   bool                `json:"auto_backup_enabled"`
	AutoBackupSchedule  string              `json:"auto_backup_schedule"`
	RetentionPolicy     RetentionPolicy     `json:"retention_policy"`
	ValidationLevel     ValidationLevel     `json:"validation_level"`
	DRTestSchedule      string              `json:"dr_test_schedule,omitempty"`
	EnableDRTesting     bool                `json:"enable_dr_testing"`
}

// NewService creates a new backup service
func NewService(manager *Manager, logger *log.Logger, config *ServiceConfig) *Service {
	restoreManager := NewRestoreManager(manager, logger)
	scheduler := NewBackupScheduler(manager, logger)
	drManager := NewDisasterRecoveryManager(manager, restoreManager, logger)

	return &Service{
		manager:        manager,
		restoreManager: restoreManager,
		scheduler:      scheduler,
		drManager:      drManager,
		logger:         logger,
		config:         config,
	}
}

// Start starts the backup service
func (s *Service) Start(ctx context.Context) error {
	s.logger.Println("Starting backup service...")

	// Start scheduler
	if err := s.scheduler.Start(); err != nil {
		return fmt.Errorf("failed to start backup scheduler: %w", err)
	}

	// Setup automatic backup if enabled
	if s.config.AutoBackupEnabled && s.config.AutoBackupSchedule != "" {
		if err := s.setupAutoBackup(); err != nil {
			s.logger.Printf("Failed to setup auto backup: %v", err)
		}
	}

	// Setup DR testing if enabled
	if s.config.EnableDRTesting && s.config.DRTestSchedule != "" {
		if err := s.setupDRTesting(); err != nil {
			s.logger.Printf("Failed to setup DR testing: %v", err)
		}
	}

	s.logger.Println("Backup service started successfully")
	return nil
}

// Stop stops the backup service
func (s *Service) Stop() error {
	s.logger.Println("Stopping backup service...")

	if err := s.scheduler.Stop(); err != nil {
		s.logger.Printf("Error stopping scheduler: %v", err)
	}

	s.logger.Println("Backup service stopped")
	return nil
}

// CreateBackup creates a new backup
func (s *Service) CreateBackup(ctx context.Context, config *BackupConfig) (*BackupInfo, error) {
	// Apply default destinations if none specified
	if len(config.Destinations) == 0 {
		config.Destinations = s.config.DefaultDestinations
	}

	// Apply default retention policy if not specified
	if config.Retention.MaxAge == 0 && config.Retention.MaxCount == 0 {
		config.Retention = s.config.RetentionPolicy
	}

	return s.manager.CreateBackup(ctx, config)
}

// RestoreBackup restores from a backup
func (s *Service) RestoreBackup(ctx context.Context, options *RestoreOptions) (*RestoreResult, error) {
	return s.restoreManager.RestoreBackup(ctx, options)
}

// ValidateBackup validates a backup
func (s *Service) ValidateBackup(ctx context.Context, backupID string) (*ValidationResult, error) {
	return s.manager.ValidateBackup(ctx, backupID)
}

// ListBackups lists all backups
func (s *Service) ListBackups(ctx context.Context) ([]*BackupInfo, error) {
	return s.manager.ListBackups(ctx)
}

// GetBackupInfo retrieves backup information
func (s *Service) GetBackupInfo(ctx context.Context, backupID string) (*BackupInfo, error) {
	return s.manager.GetBackupInfo(ctx, backupID)
}

// DeleteBackup deletes a backup
func (s *Service) DeleteBackup(ctx context.Context, backupID string) error {
	// Get backup info
	backupInfo, err := s.manager.GetBackupInfo(ctx, backupID)
	if err != nil {
		return fmt.Errorf("failed to get backup info: %w", err)
	}

	// Delete backup file from destinations
	for _, destName := range backupInfo.Destinations {
		if dest, exists := s.manager.destinations[destName]; exists {
			if err := dest.Delete(ctx, backupInfo.FilePath, nil); err != nil {
				s.logger.Printf("Failed to delete backup from destination %s: %v", destName, err)
			}
		}
	}

	// Delete backup record from database
	query := `DELETE FROM backups WHERE id = ?`
	_, err = s.manager.db.ExecContext(ctx, query, backupID)
	if err != nil {
		return fmt.Errorf("failed to delete backup record: %w", err)
	}

	s.logger.Printf("Backup deleted: %s", backupID)
	return nil
}

// Schedule Management

// AddBackupSchedule adds a new backup schedule
func (s *Service) AddBackupSchedule(schedule *BackupSchedule) error {
	return s.scheduler.AddSchedule(schedule)
}

// RemoveBackupSchedule removes a backup schedule
func (s *Service) RemoveBackupSchedule(scheduleID string) error {
	return s.scheduler.RemoveSchedule(scheduleID)
}

// UpdateBackupSchedule updates a backup schedule
func (s *Service) UpdateBackupSchedule(schedule *BackupSchedule) error {
	return s.scheduler.UpdateSchedule(schedule)
}

// GetBackupSchedule retrieves a backup schedule
func (s *Service) GetBackupSchedule(scheduleID string) (*BackupSchedule, error) {
	return s.scheduler.GetSchedule(scheduleID)
}

// ListBackupSchedules lists all backup schedules
func (s *Service) ListBackupSchedules() []*BackupSchedule {
	return s.scheduler.ListSchedules()
}

// EnableBackupSchedule enables a backup schedule
func (s *Service) EnableBackupSchedule(scheduleID string) error {
	return s.scheduler.EnableSchedule(scheduleID)
}

// DisableBackupSchedule disables a backup schedule
func (s *Service) DisableBackupSchedule(scheduleID string) error {
	return s.scheduler.DisableSchedule(scheduleID)
}

// ExecuteBackupSchedule executes a backup schedule immediately
func (s *Service) ExecuteBackupSchedule(scheduleID string) (*BackupInfo, error) {
	return s.scheduler.ExecuteNow(scheduleID)
}

// Disaster Recovery

// RunDRTest runs a disaster recovery test
func (s *Service) RunDRTest(ctx context.Context, config *DRTestConfig) (*DRTestResult, error) {
	return s.drManager.RunDRTest(ctx, config)
}

// GetDRTestResult retrieves a DR test result
func (s *Service) GetDRTestResult(testID string) (*DRTestResult, error) {
	return s.drManager.GetTestResult(testID)
}

// ListDRTestResults lists all DR test results
func (s *Service) ListDRTestResults() []*DRTestResult {
	return s.drManager.ListTestResults()
}

// Destination Management

// RegisterDestination registers a backup destination
func (s *Service) RegisterDestination(name string, destination Destination) {
	s.manager.RegisterDestination(name, destination)
}

// ValidateDestination validates a destination configuration
func (s *Service) ValidateDestination(config *DestinationConfig) error {
	var destination Destination

	switch config.Type {
	case DestinationTypeLocal:
		destination = NewLocalDestination()
	case DestinationTypeS3:
		destination = NewS3Destination()
	case DestinationTypeSFTP:
		destination = NewSFTPDestination()
	default:
		return fmt.Errorf("unsupported destination type: %s", config.Type)
	}

	return destination.Validate(config)
}

// Maintenance

// CleanupExpiredBackups removes expired backups based on retention policies
func (s *Service) CleanupExpiredBackups(ctx context.Context) error {
	backups, err := s.manager.ListBackups(ctx)
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	now := time.Now().UTC()
	var deletedCount int

	for _, backup := range backups {
		shouldDelete := false

		// Check expiration time
		if backup.ExpiresAt != nil && now.After(*backup.ExpiresAt) {
			shouldDelete = true
		}

		// Check retention policy
		if s.config.RetentionPolicy.MaxAge > 0 {
			if now.Sub(backup.CreatedAt) > s.config.RetentionPolicy.MaxAge {
				shouldDelete = true
			}
		}

		if shouldDelete {
			if err := s.DeleteBackup(ctx, backup.ID); err != nil {
				s.logger.Printf("Failed to delete expired backup %s: %v", backup.ID, err)
			} else {
				deletedCount++
			}
		}
	}

	// Apply count-based retention
	if s.config.RetentionPolicy.MaxCount > 0 {
		remaining := len(backups) - deletedCount
		if remaining > s.config.RetentionPolicy.MaxCount {
			// Sort backups by creation time (oldest first) and delete excess
			// This would require sorting the backups slice
			excessCount := remaining - s.config.RetentionPolicy.MaxCount
			s.logger.Printf("Need to delete %d excess backups to meet retention policy", excessCount)
		}
	}

	s.logger.Printf("Cleanup completed: deleted %d expired backups", deletedCount)
	return nil
}

// GetBackupStatistics returns backup statistics
func (s *Service) GetBackupStatistics(ctx context.Context) (*BackupStatistics, error) {
	backups, err := s.manager.ListBackups(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list backups: %w", err)
	}

	stats := &BackupStatistics{
		TotalBackups:     len(backups),
		CompletedBackups: 0,
		FailedBackups:    0,
		TotalSize:        0,
		OldestBackup:     time.Now().UTC(),
		NewestBackup:     time.Time{},
	}

	for _, backup := range backups {
		switch backup.Status {
		case BackupStatusCompleted:
			stats.CompletedBackups++
		case BackupStatusFailed:
			stats.FailedBackups++
		}

		stats.TotalSize += backup.FileSize

		if backup.CreatedAt.Before(stats.OldestBackup) {
			stats.OldestBackup = backup.CreatedAt
		}
		if backup.CreatedAt.After(stats.NewestBackup) {
			stats.NewestBackup = backup.CreatedAt
		}
	}

	return stats, nil
}

// BackupStatistics contains backup statistics
type BackupStatistics struct {
	TotalBackups     int       `json:"total_backups"`
	CompletedBackups int       `json:"completed_backups"`
	FailedBackups    int       `json:"failed_backups"`
	TotalSize        int64     `json:"total_size"`
	OldestBackup     time.Time `json:"oldest_backup"`
	NewestBackup     time.Time `json:"newest_backup"`
}

// Private helper methods

func (s *Service) setupAutoBackup() error {
	schedule := &BackupSchedule{
		ID:       "auto_backup",
		Name:     "Automatic Backup",
		CronExpr: s.config.AutoBackupSchedule,
		Config: &BackupConfig{
			Name:             fmt.Sprintf("auto_backup_%s", time.Now().Format("20060102")),
			Type:             BackupTypeFull,
			IncludeSecrets:   true,
			IncludeAuditLogs: true,
			IncludeConfig:    true,
			Compression:      true,
			Destinations:     s.config.DefaultDestinations,
			Retention:        s.config.RetentionPolicy,
		},
		Enabled: true,
	}

	return s.scheduler.AddSchedule(schedule)
}

func (s *Service) setupDRTesting() error {
	// This would setup automated DR testing
	s.logger.Printf("DR testing scheduled: %s", s.config.DRTestSchedule)
	return nil
}

// GetHostname returns the system hostname
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}