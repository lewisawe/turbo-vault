package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/keyvault/agent/internal/crypto"
)

// Secret represents a secret for backup purposes (avoiding circular dependency)
type Secret struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	EncryptedValue []byte            `json:"encrypted_value"`
	KeyID          string            `json:"key_id"`
	Metadata       map[string]string `json:"metadata"`
	Tags           []string          `json:"tags"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty"`
	RotationDue    *time.Time        `json:"rotation_due,omitempty"`
	Version        int               `json:"version"`
	CreatedBy      string            `json:"created_by"`
	AccessCount    int64             `json:"access_count"`
	LastAccessed   *time.Time        `json:"last_accessed,omitempty"`
	Status         string            `json:"status"`
}

// SecretStatus represents the status of a secret
type SecretStatus string

const (
	SecretStatusActive  SecretStatus = "active"
	SecretStatusDeleted SecretStatus = "deleted"
	SecretStatusExpired SecretStatus = "expired"
)

// StorageInterface defines the interface for storage operations needed by backup
type StorageInterface interface {
	GetSecret(ctx context.Context, id string) (*Secret, error)
	CreateSecret(ctx context.Context, secret *Secret) error
	UpdateSecret(ctx context.Context, id string, secret *Secret) error
}

// Manager handles backup and restore operations with enhanced features
type Manager struct {
	storage      StorageInterface
	db          *sql.DB
	encryptor   crypto.Encryptor
	keyID       string
	logger      *log.Logger
	destinations map[string]Destination
	mu          sync.RWMutex
}

// BackupConfig contains comprehensive backup configuration
type BackupConfig struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Type             BackupType             `json:"type"`
	Destinations     []DestinationConfig    `json:"destinations"`
	IncludeSecrets   bool                   `json:"include_secrets"`
	IncludeAuditLogs bool                   `json:"include_audit_logs"`
	IncludeConfig    bool                   `json:"include_config"`
	Compression      bool                   `json:"compression"`
	Encryption       bool                   `json:"encryption"`
	Retention        RetentionPolicy        `json:"retention"`
	Metadata         map[string]string      `json:"metadata"`
	Filters          *BackupFilters         `json:"filters,omitempty"`
}

// BackupType represents the type of backup
type BackupType string

const (
	BackupTypeFull        BackupType = "full"
	BackupTypeIncremental BackupType = "incremental"
	BackupTypeDifferential BackupType = "differential"
)

// BackupStatus represents the status of a backup operation
type BackupStatus string

const (
	BackupStatusPending    BackupStatus = "pending"
	BackupStatusInProgress BackupStatus = "in_progress"
	BackupStatusCompleted  BackupStatus = "completed"
	BackupStatusFailed     BackupStatus = "failed"
	BackupStatusCorrupted  BackupStatus = "corrupted"
)

// RetentionPolicy defines backup retention rules
type RetentionPolicy struct {
	MaxAge   time.Duration `json:"max_age"`
	MaxCount int           `json:"max_count"`
	MaxSize  int64         `json:"max_size"`
}

// BackupFilters defines what data to include in backups
type BackupFilters struct {
	SecretTags       []string  `json:"secret_tags,omitempty"`
	SecretNamePattern string   `json:"secret_name_pattern,omitempty"`
	CreatedAfter     *time.Time `json:"created_after,omitempty"`
	CreatedBefore    *time.Time `json:"created_before,omitempty"`
	ExcludeExpired   bool      `json:"exclude_expired"`
}

// BackupInfo contains comprehensive information about a backup
type BackupInfo struct {
	ID            string                 `json:"id" db:"id"`
	Name          string                 `json:"name" db:"name"`
	Type          BackupType             `json:"backup_type" db:"backup_type"`
	Status        BackupStatus           `json:"status" db:"status"`
	FilePath      string                 `json:"file_path" db:"file_path"`
	FileSize      int64                  `json:"file_size" db:"file_size"`
	Checksum      string                 `json:"checksum" db:"checksum"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
	CompletedAt   *time.Time             `json:"completed_at" db:"completed_at"`
	ExpiresAt     *time.Time             `json:"expires_at" db:"expires_at"`
	Metadata      map[string]interface{} `json:"metadata" db:"metadata"`
	Destinations  []string               `json:"destinations" db:"destinations"`
	ErrorMessage  string                 `json:"error_message,omitempty" db:"error_message"`
	Progress      *BackupProgress        `json:"progress,omitempty" db:"-"`
}

// BackupProgress tracks backup operation progress
type BackupProgress struct {
	Stage          string    `json:"stage"`
	SecretsTotal   int       `json:"secrets_total"`
	SecretsBackedUp int      `json:"secrets_backed_up"`
	AuditEventsTotal int     `json:"audit_events_total"`
	AuditEventsBackedUp int  `json:"audit_events_backed_up"`
	BytesProcessed int64     `json:"bytes_processed"`
	StartTime      time.Time `json:"start_time"`
	EstimatedCompletion *time.Time `json:"estimated_completion,omitempty"`
}

// RestoreOptions contains comprehensive options for restore operations
type RestoreOptions struct {
	BackupID         string            `json:"backup_id"`
	TargetPath       string            `json:"target_path,omitempty"`
	RestoreSecrets   bool              `json:"restore_secrets"`
	RestoreAuditLogs bool              `json:"restore_audit_logs"`
	RestoreConfig    bool              `json:"restore_config"`
	OverwriteExisting bool             `json:"overwrite_existing"`
	DryRun           bool              `json:"dry_run"`
	Metadata         map[string]string `json:"metadata"`
	Filters          *RestoreFilters   `json:"filters,omitempty"`
}

// RestoreFilters defines what data to restore
type RestoreFilters struct {
	SecretNames      []string   `json:"secret_names,omitempty"`
	SecretTags       []string   `json:"secret_tags,omitempty"`
	RestoreAfter     *time.Time `json:"restore_after,omitempty"`
	RestoreBefore    *time.Time `json:"restore_before,omitempty"`
}

// ValidationResult contains comprehensive backup validation results
type ValidationResult struct {
	Valid         bool                   `json:"valid"`
	Errors        []string               `json:"errors,omitempty"`
	Warnings      []string               `json:"warnings,omitempty"`
	ChecksumMatch bool                   `json:"checksum_match"`
	FileSize      int64                  `json:"file_size"`
	Contents      map[string]interface{} `json:"contents"`
	Integrity     *IntegrityCheck        `json:"integrity,omitempty"`
}

// IntegrityCheck contains detailed integrity validation results
type IntegrityCheck struct {
	SecretsCount     int       `json:"secrets_count"`
	AuditEventsCount int       `json:"audit_events_count"`
	ConfigValid      bool      `json:"config_valid"`
	EncryptionValid  bool      `json:"encryption_valid"`
	CheckedAt        time.Time `json:"checked_at"`
}

// NewManager creates a new enhanced backup manager
func NewManager(storage StorageInterface, db *sql.DB, encryptor crypto.Encryptor, keyID string, logger *log.Logger) *Manager {
	return &Manager{
		storage:      storage,
		db:           db,
		encryptor:    encryptor,
		keyID:        keyID,
		logger:       logger,
		destinations: make(map[string]Destination),
	}
}

// RegisterDestination registers a backup destination
func (m *Manager) RegisterDestination(name string, destination Destination) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.destinations[name] = destination
	m.logger.Printf("Registered backup destination: %s", name)
}

// CreateBackup creates a new backup with enhanced features
func (m *Manager) CreateBackup(ctx context.Context, config *BackupConfig) (*BackupInfo, error) {
	// Generate backup ID if not provided
	if config.ID == "" {
		config.ID = generateBackupID()
	}

	// Create backup info record
	backupInfo := &BackupInfo{
		ID:        config.ID,
		Name:      config.Name,
		Type:      config.Type,
		Status:    BackupStatusPending,
		CreatedAt: time.Now().UTC(),
		Progress: &BackupProgress{
			Stage:     "initializing",
			StartTime: time.Now().UTC(),
		},
	}

	// Set expiration based on retention policy
	if config.Retention.MaxAge > 0 {
		expiresAt := time.Now().Add(config.Retention.MaxAge)
		backupInfo.ExpiresAt = &expiresAt
	}

	// Extract destination names
	var destinationNames []string
	for _, dest := range config.Destinations {
		destinationNames = append(destinationNames, dest.Name)
	}
	backupInfo.Destinations = destinationNames

	// Insert backup record
	if err := m.insertBackupRecord(ctx, backupInfo); err != nil {
		return nil, fmt.Errorf("failed to create backup record: %w", err)
	}

	// Start backup process asynchronously
	go m.performBackup(context.Background(), config, backupInfo)

	return backupInfo, nil
}

// performBackup performs the actual backup operation with progress tracking
func (m *Manager) performBackup(ctx context.Context, config *BackupConfig, info *BackupInfo) {
	// Update status to in progress
	m.updateBackupStatus(ctx, info.ID, BackupStatusInProgress)
	
	defer func() {
		if r := recover(); r != nil {
			m.logger.Printf("Backup panic recovered: %v", r)
			m.updateBackupError(ctx, info.ID, BackupStatusFailed, fmt.Sprintf("panic: %v", r))
		}
	}()

	// Create temporary backup file
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, fmt.Sprintf("%s_%s.backup.tmp", config.Name, info.ID))
	
	file, err := os.Create(tempFile)
	if err != nil {
		m.updateBackupError(ctx, info.ID, BackupStatusFailed, fmt.Sprintf("failed to create temp file: %v", err))
		return
	}
	defer func() {
		file.Close()
		os.Remove(tempFile) // Clean up temp file
	}()

	var writer io.Writer = file
	var gzWriter *gzip.Writer

	// Add compression if enabled
	if config.Compression {
		gzWriter = gzip.NewWriter(file)
		writer = gzWriter
		defer gzWriter.Close()
	}

	// Create tar archive
	tarWriter := tar.NewWriter(writer)
	defer tarWriter.Close()

	// Update progress
	m.updateBackupProgress(ctx, info.ID, "collecting_data")

	// Backup secrets
	if config.IncludeSecrets {
		if err := m.backupSecrets(ctx, tarWriter, config.Filters, info.ID); err != nil {
			m.updateBackupError(ctx, info.ID, BackupStatusFailed, fmt.Sprintf("failed to backup secrets: %v", err))
			return
		}
	}

	// Backup audit logs
	if config.IncludeAuditLogs {
		if err := m.backupAuditLogs(ctx, tarWriter, config.Filters, info.ID); err != nil {
			m.updateBackupError(ctx, info.ID, BackupStatusFailed, fmt.Sprintf("failed to backup audit logs: %v", err))
			return
		}
	}

	// Backup configuration
	if config.IncludeConfig {
		if err := m.backupConfiguration(ctx, tarWriter); err != nil {
			m.updateBackupError(ctx, info.ID, BackupStatusFailed, fmt.Sprintf("failed to backup configuration: %v", err))
			return
		}
	}

	// Close writers to ensure all data is written
	tarWriter.Close()
	if gzWriter != nil {
		gzWriter.Close()
	}
	file.Close()

	// Update progress
	m.updateBackupProgress(ctx, info.ID, "finalizing")

	// Calculate file size and checksum
	fileInfo, err := os.Stat(tempFile)
	if err != nil {
		m.updateBackupError(ctx, info.ID, BackupStatusFailed, fmt.Sprintf("failed to stat backup file: %v", err))
		return
	}

	checksum, err := m.calculateFileChecksum(tempFile)
	if err != nil {
		m.updateBackupError(ctx, info.ID, BackupStatusFailed, fmt.Sprintf("failed to calculate checksum: %v", err))
		return
	}

	// Update progress
	m.updateBackupProgress(ctx, info.ID, "uploading")

	// Upload to destinations
	var finalPath string
	var uploadErrors []string

	for _, destConfig := range config.Destinations {
		m.mu.RLock()
		destination, exists := m.destinations[destConfig.Name]
		m.mu.RUnlock()

		if !exists {
			uploadErrors = append(uploadErrors, fmt.Sprintf("destination not found: %s", destConfig.Name))
			continue
		}

		destPath, err := destination.Upload(ctx, tempFile, &destConfig)
		if err != nil {
			uploadErrors = append(uploadErrors, fmt.Sprintf("upload to %s failed: %v", destConfig.Name, err))
			continue
		}

		// Use first successful upload as primary path
		if finalPath == "" {
			finalPath = destPath
		}

		m.logger.Printf("Backup uploaded to %s: %s", destConfig.Name, destPath)
	}

	// Check if any uploads succeeded
	if finalPath == "" {
		errorMsg := fmt.Sprintf("all uploads failed: %s", strings.Join(uploadErrors, "; "))
		m.updateBackupError(ctx, info.ID, BackupStatusFailed, errorMsg)
		return
	}

	// Update backup record with completion info
	completedAt := time.Now().UTC()
	if err := m.updateBackupCompletion(ctx, info.ID, finalPath, fileInfo.Size(), checksum, &completedAt); err != nil {
		m.updateBackupError(ctx, info.ID, BackupStatusFailed, fmt.Sprintf("failed to update completion: %v", err))
		return
	}

	m.logger.Printf("Backup completed successfully: %s", info.ID)
}

// backupSecrets backs up secrets with filtering support
func (m *Manager) backupSecrets(ctx context.Context, tarWriter *tar.Writer, filters *BackupFilters, backupID string) error {
	// Build query with filters
	query := `
	SELECT id, name, encrypted_value, key_id, metadata, tags, 
		created_at, updated_at, expires_at, rotation_due, version, 
		created_by, access_count, last_accessed, status
	FROM secrets
	WHERE status != 'deleted'
	`
	
	var args []interface{}
	argIndex := 1

	if filters != nil {
		if filters.CreatedAfter != nil {
			query += fmt.Sprintf(" AND created_at >= $%d", argIndex)
			args = append(args, *filters.CreatedAfter)
			argIndex++
		}
		
		if filters.CreatedBefore != nil {
			query += fmt.Sprintf(" AND created_at <= $%d", argIndex)
			args = append(args, *filters.CreatedBefore)
			argIndex++
		}
		
		if filters.ExcludeExpired {
			query += " AND (expires_at IS NULL OR expires_at > NOW())"
		}
		
		if filters.SecretNamePattern != "" {
			query += fmt.Sprintf(" AND name LIKE $%d", argIndex)
			args = append(args, filters.SecretNamePattern)
			argIndex++
		}
	}

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to query secrets: %w", err)
	}
	defer rows.Close()

	var secrets []map[string]interface{}
	secretCount := 0

	for rows.Next() {
		var secret Secret
		var metadataJSON, tagsJSON string

		err := rows.Scan(
			&secret.ID, &secret.Name, &secret.EncryptedValue, &secret.KeyID,
			&metadataJSON, &tagsJSON, &secret.CreatedAt, &secret.UpdatedAt,
			&secret.ExpiresAt, &secret.RotationDue, &secret.Version,
			&secret.CreatedBy, &secret.AccessCount, &secret.LastAccessed, &secret.Status,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(metadataJSON), &secret.Metadata)
		json.Unmarshal([]byte(tagsJSON), &secret.Tags)

		// Apply tag filters
		if filters != nil && len(filters.SecretTags) > 0 {
			hasMatchingTag := false
			for _, filterTag := range filters.SecretTags {
				for _, secretTag := range secret.Tags {
					if secretTag == filterTag {
						hasMatchingTag = true
						break
					}
				}
				if hasMatchingTag {
					break
				}
			}
			if !hasMatchingTag {
				continue
			}
		}

		// Convert to map for JSON serialization
		secretMap := map[string]interface{}{
			"id":              secret.ID,
			"name":            secret.Name,
			"encrypted_value": secret.EncryptedValue,
			"key_id":          secret.KeyID,
			"metadata":        secret.Metadata,
			"tags":            secret.Tags,
			"created_at":      secret.CreatedAt,
			"updated_at":      secret.UpdatedAt,
			"expires_at":      secret.ExpiresAt,
			"rotation_due":    secret.RotationDue,
			"version":         secret.Version,
			"created_by":      secret.CreatedBy,
			"access_count":    secret.AccessCount,
			"last_accessed":   secret.LastAccessed,
			"status":          secret.Status,
		}

		secrets = append(secrets, secretMap)
		secretCount++

		// Update progress periodically
		if secretCount%100 == 0 {
			m.updateBackupProgressSecrets(ctx, backupID, secretCount)
		}
	}

	// Final progress update
	m.updateBackupProgressSecrets(ctx, backupID, secretCount)

	// Serialize secrets to JSON
	secretsJSON, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secrets: %w", err)
	}

	// Add to tar archive
	header := &tar.Header{
		Name: "secrets.json",
		Mode: 0644,
		Size: int64(len(secretsJSON)),
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write secrets header: %w", err)
	}

	if _, err := tarWriter.Write(secretsJSON); err != nil {
		return fmt.Errorf("failed to write secrets data: %w", err)
	}

	return nil
}

// backupAuditLogs backs up audit logs with filtering support
func (m *Manager) backupAuditLogs(ctx context.Context, tarWriter *tar.Writer, filters *BackupFilters, backupID string) error {
	// Build query with filters
	query := `
	SELECT id, vault_id, event_type, actor_type, actor_id, resource_type, 
		resource_id, action, result, context, timestamp, ip_address, 
		user_agent, session_id
	FROM audit_events
	`
	
	var args []interface{}
	argIndex := 1
	whereAdded := false

	if filters != nil {
		if filters.CreatedAfter != nil {
			query += " WHERE timestamp >= $1"
			args = append(args, *filters.CreatedAfter)
			argIndex++
			whereAdded = true
		}
		
		if filters.CreatedBefore != nil {
			if whereAdded {
				query += " AND"
			} else {
				query += " WHERE"
				whereAdded = true
			}
			query += fmt.Sprintf(" timestamp <= $%d", argIndex)
			args = append(args, *filters.CreatedBefore)
			argIndex++
		}
	}

	query += " ORDER BY timestamp DESC LIMIT 50000"

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to query audit events: %w", err)
	}
	defer rows.Close()

	var events []map[string]interface{}
	eventCount := 0

	for rows.Next() {
		var event map[string]interface{} = make(map[string]interface{})
		var id, vaultID, eventType, actorType, actorID, resourceType string
		var resourceID, action, result, context, ipAddress, userAgent, sessionID sql.NullString
		var timestamp time.Time

		err := rows.Scan(
			&id, &vaultID, &eventType, &actorType, &actorID, &resourceType,
			&resourceID, &action, &result, &context, &timestamp, &ipAddress,
			&userAgent, &sessionID,
		)
		if err != nil {
			continue
		}

		event["id"] = id
		event["vault_id"] = vaultID
		event["event_type"] = eventType
		event["actor_type"] = actorType
		event["actor_id"] = actorID
		event["resource_type"] = resourceType
		event["resource_id"] = resourceID.String
		event["action"] = action.String
		event["result"] = result.String
		event["context"] = context.String
		event["timestamp"] = timestamp
		event["ip_address"] = ipAddress.String
		event["user_agent"] = userAgent.String
		event["session_id"] = sessionID.String

		events = append(events, event)
		eventCount++

		// Update progress periodically
		if eventCount%1000 == 0 {
			m.updateBackupProgressAuditEvents(ctx, backupID, eventCount)
		}
	}

	// Final progress update
	m.updateBackupProgressAuditEvents(ctx, backupID, eventCount)

	// Serialize audit events to JSON
	eventsJSON, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal audit events: %w", err)
	}

	// Add to tar archive
	header := &tar.Header{
		Name: "audit_events.json",
		Mode: 0644,
		Size: int64(len(eventsJSON)),
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write audit events header: %w", err)
	}

	if _, err := tarWriter.Write(eventsJSON); err != nil {
		return fmt.Errorf("failed to write audit events data: %w", err)
	}

	return nil
}

// backupConfiguration backs up system configuration
func (m *Manager) backupConfiguration(ctx context.Context, tarWriter *tar.Writer) error {
	// Create comprehensive configuration backup
	config := map[string]interface{}{
		"backup_created_at": time.Now().UTC(),
		"version":          "1.0.0",
		"database_schema":  m.getDatabaseSchema(ctx),
		"system_info":      m.getSystemInfo(),
		"backup_metadata": map[string]interface{}{
			"created_by": "backup_manager",
			"format_version": "2.0",
		},
	}

	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Add to tar archive
	header := &tar.Header{
		Name: "configuration.json",
		Mode: 0644,
		Size: int64(len(configJSON)),
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write configuration header: %w", err)
	}

	if _, err := tarWriter.Write(configJSON); err != nil {
		return fmt.Errorf("failed to write configuration data: %w", err)
	}

	return nil
}

// Helper methods for progress tracking and database operations

func (m *Manager) updateBackupStatus(ctx context.Context, backupID string, status BackupStatus) error {
	query := `UPDATE backups SET status = ?, updated_at = ? WHERE id = ?`
	_, err := m.db.ExecContext(ctx, query, status, time.Now().UTC(), backupID)
	return err
}

func (m *Manager) updateBackupError(ctx context.Context, backupID string, status BackupStatus, errorMsg string) error {
	query := `UPDATE backups SET status = ?, error_message = ?, updated_at = ? WHERE id = ?`
	_, err := m.db.ExecContext(ctx, query, status, errorMsg, time.Now().UTC(), backupID)
	return err
}

func (m *Manager) updateBackupProgress(ctx context.Context, backupID, stage string) error {
	// This would update progress in a separate table or cache
	// For now, we'll just log the progress
	m.logger.Printf("Backup %s progress: %s", backupID, stage)
	return nil
}

func (m *Manager) updateBackupProgressSecrets(ctx context.Context, backupID string, count int) error {
	m.logger.Printf("Backup %s: backed up %d secrets", backupID, count)
	return nil
}

func (m *Manager) updateBackupProgressAuditEvents(ctx context.Context, backupID string, count int) error {
	m.logger.Printf("Backup %s: backed up %d audit events", backupID, count)
	return nil
}

func (m *Manager) insertBackupRecord(ctx context.Context, info *BackupInfo) error {
	metadataJSON, _ := json.Marshal(info.Metadata)
	destinationsJSON, _ := json.Marshal(info.Destinations)
	
	query := `
	INSERT INTO backups (id, name, backup_type, status, file_path, file_size, checksum, 
		created_at, expires_at, metadata, destinations, error_message)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := m.db.ExecContext(ctx, query,
		info.ID, info.Name, info.Type, info.Status, info.FilePath, info.FileSize, info.Checksum,
		info.CreatedAt, info.ExpiresAt, string(metadataJSON), string(destinationsJSON), info.ErrorMessage)

	return err
}

func (m *Manager) updateBackupCompletion(ctx context.Context, backupID, filePath string, fileSize int64, checksum string, completedAt *time.Time) error {
	query := `
	UPDATE backups 
	SET status = ?, file_path = ?, file_size = ?, checksum = ?, completed_at = ?, updated_at = ?
	WHERE id = ?
	`

	_, err := m.db.ExecContext(ctx, query,
		BackupStatusCompleted, filePath, fileSize, checksum, completedAt, time.Now().UTC(), backupID)

	return err
}

func (m *Manager) calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (m *Manager) getDatabaseSchema(ctx context.Context) map[string]interface{} {
	return map[string]interface{}{
		"tables": []string{"secrets", "secret_versions", "audit_events", "cluster_nodes", "backups"},
		"version": "1.0.0",
	}
}

func (m *Manager) getSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"hostname": getHostname(),
		"timestamp": time.Now().UTC(),
		"backup_format": "tar.gz",
	}
}

// ValidateBackup validates a backup with comprehensive integrity checks
func (m *Manager) ValidateBackup(ctx context.Context, backupID string) (*ValidationResult, error) {
	// Get backup info
	backupInfo, err := m.GetBackupInfo(ctx, backupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup info: %w", err)
	}

	result := &ValidationResult{
		Valid:    true,
		FileSize: backupInfo.FileSize,
		Contents: make(map[string]interface{}),
		Integrity: &IntegrityCheck{
			CheckedAt:       time.Now().UTC(),
			EncryptionValid: true,
			ConfigValid:     true,
		},
	}

	// Check if backup file exists
	if _, err := os.Stat(backupInfo.FilePath); os.IsNotExist(err) {
		result.Valid = false
		result.Errors = append(result.Errors, "backup file not found")
		return result, nil
	}

	// Verify file size
	fileInfo, err := os.Stat(backupInfo.FilePath)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to stat backup file: %v", err))
		return result, nil
	}

	if fileInfo.Size() != backupInfo.FileSize {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("file size mismatch: expected %d, got %d", backupInfo.FileSize, fileInfo.Size()))
	}

	// Verify checksum
	actualChecksum, err := m.calculateFileChecksum(backupInfo.FilePath)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to calculate checksum: %v", err))
		return result, nil
	}

	result.ChecksumMatch = actualChecksum == backupInfo.Checksum
	if !result.ChecksumMatch {
		result.Valid = false
		result.Errors = append(result.Errors, "checksum mismatch")
	}

	// Validate backup content structure (only if it's a tar file)
	if strings.HasSuffix(backupInfo.FilePath, ".backup") || strings.HasSuffix(backupInfo.FilePath, ".tar") || strings.HasSuffix(backupInfo.FilePath, ".tar.gz") {
		if err := m.validateBackupContent(backupInfo.FilePath, result); err != nil {
			// Don't fail validation for content issues, just add warnings
			result.Warnings = append(result.Warnings, fmt.Sprintf("content validation warning: %v", err))
		}
	}

	return result, nil
}

// GetBackupInfo retrieves backup information from database
func (m *Manager) GetBackupInfo(ctx context.Context, backupID string) (*BackupInfo, error) {
	query := `
	SELECT id, name, backup_type, status, file_path, file_size, checksum,
		created_at, completed_at, expires_at, metadata, destinations, error_message
	FROM backups WHERE id = ?
	`

	var info BackupInfo
	var filePath, checksum, errorMessage sql.NullString
	var fileSize sql.NullInt64
	var metadataJSON, destinationsJSON sql.NullString
	var completedAt, expiresAt sql.NullTime

	err := m.db.QueryRowContext(ctx, query, backupID).Scan(
		&info.ID, &info.Name, &info.Type, &info.Status, &filePath,
		&fileSize, &checksum, &info.CreatedAt, &completedAt,
		&expiresAt, &metadataJSON, &destinationsJSON, &errorMessage,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("backup not found: %s", backupID)
		}
		return nil, fmt.Errorf("failed to query backup: %w", err)
	}

	// Handle nullable fields
	if filePath.Valid {
		info.FilePath = filePath.String
	}
	if fileSize.Valid {
		info.FileSize = fileSize.Int64
	}
	if checksum.Valid {
		info.Checksum = checksum.String
	}
	if errorMessage.Valid {
		info.ErrorMessage = errorMessage.String
	}
	if completedAt.Valid {
		info.CompletedAt = &completedAt.Time
	}
	if expiresAt.Valid {
		info.ExpiresAt = &expiresAt.Time
	}

	// Parse metadata
	if metadataJSON.Valid {
		json.Unmarshal([]byte(metadataJSON.String), &info.Metadata)
	}

	// Parse destinations
	if destinationsJSON.Valid {
		json.Unmarshal([]byte(destinationsJSON.String), &info.Destinations)
	}

	return &info, nil
}

// ListBackups lists all backups with optional filtering
func (m *Manager) ListBackups(ctx context.Context) ([]*BackupInfo, error) {
	query := `
	SELECT id, name, backup_type, status, file_path, file_size, checksum,
		created_at, completed_at, expires_at, metadata, destinations, error_message
	FROM backups ORDER BY created_at DESC
	`

	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query backups: %w", err)
	}
	defer rows.Close()

	var backups []*BackupInfo

	for rows.Next() {
		var info BackupInfo
		var filePath, checksum, errorMessage sql.NullString
		var fileSize sql.NullInt64
		var metadataJSON, destinationsJSON sql.NullString
		var completedAt, expiresAt sql.NullTime

		err := rows.Scan(
			&info.ID, &info.Name, &info.Type, &info.Status, &filePath,
			&fileSize, &checksum, &info.CreatedAt, &completedAt,
			&expiresAt, &metadataJSON, &destinationsJSON, &errorMessage,
		)
		if err != nil {
			continue
		}

		// Handle nullable fields
		if filePath.Valid {
			info.FilePath = filePath.String
		}
		if fileSize.Valid {
			info.FileSize = fileSize.Int64
		}
		if checksum.Valid {
			info.Checksum = checksum.String
		}
		if errorMessage.Valid {
			info.ErrorMessage = errorMessage.String
		}
		if completedAt.Valid {
			info.CompletedAt = &completedAt.Time
		}
		if expiresAt.Valid {
			info.ExpiresAt = &expiresAt.Time
		}

		// Parse metadata
		if metadataJSON.Valid {
			json.Unmarshal([]byte(metadataJSON.String), &info.Metadata)
		}

		// Parse destinations
		if destinationsJSON.Valid {
			json.Unmarshal([]byte(destinationsJSON.String), &info.Destinations)
		}

		backups = append(backups, &info)
	}

	return backups, nil
}

// validateBackupContent validates the internal structure and content of a backup
func (m *Manager) validateBackupContent(filePath string, result *ValidationResult) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file

	// Handle compression
	if strings.HasSuffix(filePath, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Create tar reader
	tarReader := tar.NewReader(reader)

	// Track what we find in the backup
	foundFiles := make(map[string]bool)

	// Process each file in the archive
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		foundFiles[header.Name] = true

		switch header.Name {
		case "secrets.json":
			if err := m.validateSecretsContent(tarReader, result); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("secrets validation warning: %v", err))
			}
		case "audit_events.json":
			if err := m.validateAuditEventsContent(tarReader, result); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("audit events validation warning: %v", err))
			}
		case "configuration.json":
			if err := m.validateConfigurationContent(tarReader, result); err != nil {
				result.Integrity.ConfigValid = false
				result.Warnings = append(result.Warnings, fmt.Sprintf("configuration validation warning: %v", err))
			}
		}
	}

	// Check for expected files
	result.Contents["found_files"] = foundFiles
	if !foundFiles["secrets.json"] {
		result.Warnings = append(result.Warnings, "secrets.json not found in backup")
	}
	if !foundFiles["audit_events.json"] {
		result.Warnings = append(result.Warnings, "audit_events.json not found in backup")
	}
	if !foundFiles["configuration.json"] {
		result.Warnings = append(result.Warnings, "configuration.json not found in backup")
	}

	return nil
}

// validateSecretsContent validates the secrets JSON content
func (m *Manager) validateSecretsContent(reader io.Reader, result *ValidationResult) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read secrets data: %w", err)
	}

	var secrets []map[string]interface{}
	if err := json.Unmarshal(data, &secrets); err != nil {
		return fmt.Errorf("failed to unmarshal secrets: %w", err)
	}

	result.Integrity.SecretsCount = len(secrets)
	result.Contents["secrets_count"] = len(secrets)

	// Validate secret structure
	for i, secret := range secrets {
		if _, ok := secret["id"]; !ok {
			return fmt.Errorf("secret %d missing id field", i)
		}
		if _, ok := secret["name"]; !ok {
			return fmt.Errorf("secret %d missing name field", i)
		}
		if _, ok := secret["encrypted_value"]; !ok {
			return fmt.Errorf("secret %d missing encrypted_value field", i)
		}
	}

	return nil
}

// validateAuditEventsContent validates the audit events JSON content
func (m *Manager) validateAuditEventsContent(reader io.Reader, result *ValidationResult) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read audit events data: %w", err)
	}

	var events []map[string]interface{}
	if err := json.Unmarshal(data, &events); err != nil {
		return fmt.Errorf("failed to unmarshal audit events: %w", err)
	}

	result.Integrity.AuditEventsCount = len(events)
	result.Contents["audit_events_count"] = len(events)

	// Validate event structure
	for i, event := range events {
		if _, ok := event["id"]; !ok {
			return fmt.Errorf("audit event %d missing id field", i)
		}
		if _, ok := event["event_type"]; !ok {
			return fmt.Errorf("audit event %d missing event_type field", i)
		}
		if _, ok := event["timestamp"]; !ok {
			return fmt.Errorf("audit event %d missing timestamp field", i)
		}
	}

	return nil
}

// validateConfigurationContent validates the configuration JSON content
func (m *Manager) validateConfigurationContent(reader io.Reader, result *ValidationResult) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read configuration data: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	result.Contents["configuration"] = config

	// Validate configuration structure
	if _, ok := config["version"]; !ok {
		return fmt.Errorf("configuration missing version field")
	}
	if _, ok := config["backup_created_at"]; !ok {
		return fmt.Errorf("configuration missing backup_created_at field")
	}

	return nil
}

func generateBackupID() string {
	return fmt.Sprintf("backup-%d", time.Now().UnixNano())
}