package storage

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keyvault/agent/internal/backup"
	"github.com/keyvault/agent/internal/crypto"
)

// BackupManager provides integration with the enhanced backup system
type BackupManager struct {
	service *backup.Service
	logger  *log.Logger
}

// Legacy type aliases for backward compatibility
type BackupConfig = backup.BackupConfig
type BackupType = backup.BackupType
type BackupStatus = backup.BackupStatus
type RetentionPolicy = backup.RetentionPolicy
type BackupInfo = backup.BackupInfo
type RestoreOptions = backup.RestoreOptions
type ValidationResult = backup.ValidationResult

// Legacy constants for backward compatibility
const (
	BackupTypeFull        = backup.BackupTypeFull
	BackupTypeIncremental = backup.BackupTypeIncremental
	BackupTypeDifferential = backup.BackupTypeDifferential
	
	BackupStatusPending    = backup.BackupStatusPending
	BackupStatusInProgress = backup.BackupStatusInProgress
	BackupStatusCompleted  = backup.BackupStatusCompleted
	BackupStatusFailed     = backup.BackupStatusFailed
)

// NewBackupManager creates a new backup manager with enhanced backup service
func NewBackupManager(storage *Storage, encryptor crypto.Encryptor, keyID string, logger *log.Logger) *BackupManager {
	// Create adapter to bridge storage.Secret and backup.Secret
	adapter := &storageAdapter{storage: storage}
	
	// Create enhanced backup manager
	backupManager := backup.NewManager(adapter, storage.db, encryptor, keyID, logger)
	
	// Register default destinations
	localDest := backup.NewLocalDestination()
	backupManager.RegisterDestination("local", localDest)
	
	s3Dest := backup.NewS3Destination()
	backupManager.RegisterDestination("s3", s3Dest)
	
	sftpDest := backup.NewSFTPDestination()
	backupManager.RegisterDestination("sftp", sftpDest)
	
	// Create service with default configuration
	serviceConfig := &backup.ServiceConfig{
		AutoBackupEnabled:  false,
		AutoBackupSchedule: "0 2 * * *", // Daily at 2 AM
		RetentionPolicy: backup.RetentionPolicy{
			MaxAge:   30 * 24 * time.Hour, // 30 days
			MaxCount: 10,
		},
		ValidationLevel: backup.ValidationLevelStandard,
		EnableDRTesting: false,
	}
	
	service := backup.NewService(backupManager, logger, serviceConfig)
	
	return &BackupManager{
		service: service,
		logger:  logger,
	}
}

// CreateBackup creates a new backup using the enhanced backup service
func (bm *BackupManager) CreateBackup(ctx context.Context, config *BackupConfig) (*BackupInfo, error) {
	return bm.service.CreateBackup(ctx, config)
}

// RestoreBackup restores from a backup using the enhanced restore service
func (bm *BackupManager) RestoreBackup(ctx context.Context, options *RestoreOptions) error {
	result, err := bm.service.RestoreBackup(ctx, options)
	if err != nil {
		return err
	}
	
	if result.Status == backup.RestoreStatusFailed {
		return fmt.Errorf("restore failed: %v", result.Errors)
	}
	
	bm.logger.Printf("Restore completed: %s, Status: %s", options.BackupID, result.Status)
	return nil
}

// ValidateBackup validates a backup using the enhanced validation service
func (bm *BackupManager) ValidateBackup(ctx context.Context, backupID string) (*ValidationResult, error) {
	return bm.service.ValidateBackup(ctx, backupID)
}

// GetBackupInfo retrieves backup information using the enhanced service
func (bm *BackupManager) GetBackupInfo(ctx context.Context, backupID string) (*BackupInfo, error) {
	return bm.service.GetBackupInfo(ctx, backupID)
}

// ListBackups lists all backups using the enhanced service
func (bm *BackupManager) ListBackups(ctx context.Context) ([]*BackupInfo, error) {
	return bm.service.ListBackups(ctx)
}

// Start starts the backup service
func (bm *BackupManager) Start(ctx context.Context) error {
	return bm.service.Start(ctx)
}

// Stop stops the backup service
func (bm *BackupManager) Stop() error {
	return bm.service.Stop()
}

// ScheduleBackup schedules a backup operation
func (bm *BackupManager) ScheduleBackup(schedule *backup.BackupSchedule) error {
	return bm.service.AddBackupSchedule(schedule)
}

// RunDRTest runs a disaster recovery test
func (bm *BackupManager) RunDRTest(ctx context.Context, config *backup.DRTestConfig) (*backup.DRTestResult, error) {
	return bm.service.RunDRTest(ctx, config)
}

// GetBackupStatistics returns backup statistics
func (bm *BackupManager) GetBackupStatistics(ctx context.Context) (*backup.BackupStatistics, error) {
	return bm.service.GetBackupStatistics(ctx)
}

// CleanupExpiredBackups removes expired backups
func (bm *BackupManager) CleanupExpiredBackups(ctx context.Context) error {
	return bm.service.CleanupExpiredBackups(ctx)
}

// storageAdapter adapts storage.Storage to backup.StorageInterface
type storageAdapter struct {
	storage *Storage
}

func (a *storageAdapter) GetSecret(ctx context.Context, id string) (*backup.Secret, error) {
	secret, err := a.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	return a.convertToBackupSecret(secret), nil
}

func (a *storageAdapter) CreateSecret(ctx context.Context, secret *backup.Secret) error {
	storageSecret := a.convertFromBackupSecret(secret)
	return a.storage.CreateSecret(ctx, storageSecret)
}

func (a *storageAdapter) UpdateSecret(ctx context.Context, id string, secret *backup.Secret) error {
	storageSecret := a.convertFromBackupSecret(secret)
	return a.storage.UpdateSecret(ctx, id, storageSecret)
}

func (a *storageAdapter) convertToBackupSecret(s *Secret) *backup.Secret {
	return &backup.Secret{
		ID:             s.ID,
		Name:           s.Name,
		EncryptedValue: s.EncryptedValue,
		KeyID:          s.KeyID,
		Metadata:       s.Metadata,
		Tags:           s.Tags,
		CreatedAt:      s.CreatedAt,
		UpdatedAt:      s.UpdatedAt,
		ExpiresAt:      s.ExpiresAt,
		Version:        1, // Default version
	}
}

func (a *storageAdapter) convertFromBackupSecret(s *backup.Secret) *Secret {
	return &Secret{
		ID:             s.ID,
		Name:           s.Name,
		EncryptedValue: s.EncryptedValue,
		KeyID:          s.KeyID,
		Metadata:       s.Metadata,
		Tags:           s.Tags,
		CreatedAt:      s.CreatedAt,
		UpdatedAt:      s.UpdatedAt,
		ExpiresAt:      s.ExpiresAt,
	}
}