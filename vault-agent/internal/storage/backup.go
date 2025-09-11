package storage

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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyvault/agent/internal/crypto"
)

// BackupManager handles backup and restore operations
type BackupManager struct {
	storage   *Storage
	db        *sql.DB
	encryptor crypto.Encryptor
	keyID     string
}

// BackupConfig contains backup configuration
type BackupConfig struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Type             BackupType        `json:"type"`
	Destination      string            `json:"destination"`
	IncludeSecrets   bool              `json:"include_secrets"`
	IncludeAuditLogs bool              `json:"include_audit_logs"`
	IncludeConfig    bool              `json:"include_config"`
	Compression      bool              `json:"compression"`
	Encryption       bool              `json:"encryption"`
	Retention        RetentionPolicy   `json:"retention"`
	Metadata         map[string]string `json:"metadata"`
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
)

// RetentionPolicy defines backup retention rules
type RetentionPolicy struct {
	MaxAge   time.Duration `json:"max_age"`
	MaxCount int           `json:"max_count"`
	MaxSize  int64         `json:"max_size"`
}

// BackupInfo contains information about a backup
type BackupInfo struct {
	ID          string                 `json:"id" db:"id"`
	Name        string                 `json:"name" db:"name"`
	Type        BackupType             `json:"backup_type" db:"backup_type"`
	Status      BackupStatus           `json:"status" db:"status"`
	FilePath    string                 `json:"file_path" db:"file_path"`
	FileSize    int64                  `json:"file_size" db:"file_size"`
	Checksum    string                 `json:"checksum" db:"checksum"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	CompletedAt *time.Time             `json:"completed_at" db:"completed_at"`
	ExpiresAt   *time.Time             `json:"expires_at" db:"expires_at"`
	Metadata    map[string]interface{} `json:"metadata" db:"metadata"`
}

// RestoreOptions contains options for restore operations
type RestoreOptions struct {
	BackupID         string            `json:"backup_id"`
	TargetPath       string            `json:"target_path,omitempty"`
	RestoreSecrets   bool              `json:"restore_secrets"`
	RestoreAuditLogs bool              `json:"restore_audit_logs"`
	RestoreConfig    bool              `json:"restore_config"`
	OverwriteExisting bool             `json:"overwrite_existing"`
	DryRun           bool              `json:"dry_run"`
	Metadata         map[string]string `json:"metadata"`
}

// ValidationResult contains backup validation results
type ValidationResult struct {
	Valid        bool                   `json:"valid"`
	Errors       []string               `json:"errors,omitempty"`
	Warnings     []string               `json:"warnings,omitempty"`
	ChecksumMatch bool                  `json:"checksum_match"`
	FileSize     int64                  `json:"file_size"`
	Contents     map[string]interface{} `json:"contents"`
}

// NewBackupManager creates a new backup manager
func NewBackupManager(storage *Storage, db *sql.DB, encryptor crypto.Encryptor, keyID string) *BackupManager {
	return &BackupManager{
		storage:   storage,
		db:        db,
		encryptor: encryptor,
		keyID:     keyID,
	}
}

// CreateBackup creates a new backup
func (bm *BackupManager) CreateBackup(ctx context.Context, config *BackupConfig) (*BackupInfo, error) {
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
		CreatedAt: time.Now(),
	}

	// Set expiration based on retention policy
	if config.Retention.MaxAge > 0 {
		expiresAt := time.Now().Add(config.Retention.MaxAge)
		backupInfo.ExpiresAt = &expiresAt
	}

	// Insert backup record
	if err := bm.insertBackupRecord(ctx, backupInfo); err != nil {
		return nil, fmt.Errorf("failed to create backup record: %w", err)
	}

	// Start backup process
	go bm.performBackup(context.Background(), config, backupInfo)

	return backupInfo, nil
}

// performBackup performs the actual backup operation
func (bm *BackupManager) performBackup(ctx context.Context, config *BackupConfig, info *BackupInfo) {
	// Update status to in progress
	bm.updateBackupStatus(ctx, info.ID, BackupStatusInProgress)

	// Create backup file
	backupPath := filepath.Join(config.Destination, fmt.Sprintf("%s_%s.backup", config.Name, info.ID))
	if config.Compression {
		backupPath += ".gz"
	}

	file, err := os.Create(backupPath)
	if err != nil {
		bm.updateBackupStatus(ctx, info.ID, BackupStatusFailed)
		return
	}
	defer file.Close()

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

	// Backup secrets
	if config.IncludeSecrets {
		if err := bm.backupSecrets(ctx, tarWriter); err != nil {
			bm.updateBackupStatus(ctx, info.ID, BackupStatusFailed)
			return
		}
	}

	// Backup audit logs
	if config.IncludeAuditLogs {
		if err := bm.backupAuditLogs(ctx, tarWriter); err != nil {
			bm.updateBackupStatus(ctx, info.ID, BackupStatusFailed)
			return
		}
	}

	// Backup configuration
	if config.IncludeConfig {
		if err := bm.backupConfiguration(ctx, tarWriter); err != nil {
			bm.updateBackupStatus(ctx, info.ID, BackupStatusFailed)
			return
		}
	}

	// Close writers to ensure all data is written
	tarWriter.Close()
	if gzWriter != nil {
		gzWriter.Close()
	}
	file.Close()

	// Calculate file size and checksum
	fileInfo, err := os.Stat(backupPath)
	if err != nil {
		bm.updateBackupStatus(ctx, info.ID, BackupStatusFailed)
		return
	}

	checksum, err := bm.calculateFileChecksum(backupPath)
	if err != nil {
		bm.updateBackupStatus(ctx, info.ID, BackupStatusFailed)
		return
	}

	// Update backup record with completion info
	completedAt := time.Now()
	bm.updateBackupCompletion(ctx, info.ID, backupPath, fileInfo.Size(), checksum, &completedAt)
}

// backupSecrets backs up all secrets to the tar archive
func (bm *BackupManager) backupSecrets(ctx context.Context, tarWriter *tar.Writer) error {
	// Query all secrets
	query := `
	SELECT id, name, encrypted_value, key_id, metadata, tags, 
		created_at, updated_at, expires_at, rotation_due, version, 
		created_by, access_count, last_accessed, status
	FROM secrets
	WHERE status != 'deleted'
	`

	rows, err := bm.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query secrets: %w", err)
	}
	defer rows.Close()

	var secrets []map[string]interface{}
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
	}

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

// backupAuditLogs backs up audit logs to the tar archive
func (bm *BackupManager) backupAuditLogs(ctx context.Context, tarWriter *tar.Writer) error {
	// Query audit events
	query := `
	SELECT id, vault_id, event_type, actor_type, actor_id, resource_type, 
		resource_id, action, result, context, timestamp, ip_address, 
		user_agent, session_id
	FROM audit_events
	ORDER BY timestamp DESC
	LIMIT 10000
	`

	rows, err := bm.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query audit events: %w", err)
	}
	defer rows.Close()

	var events []map[string]interface{}
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
		event["action"] = action
		event["result"] = result
		event["context"] = context.String
		event["timestamp"] = timestamp
		event["ip_address"] = ipAddress.String
		event["user_agent"] = userAgent.String
		event["session_id"] = sessionID.String

		events = append(events, event)
	}

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

// backupConfiguration backs up configuration to the tar archive
func (bm *BackupManager) backupConfiguration(ctx context.Context, tarWriter *tar.Writer) error {
	// Create configuration backup data
	config := map[string]interface{}{
		"backup_created_at": time.Now(),
		"version":          "1.0.0",
		"database_schema":  bm.getDatabaseSchema(ctx),
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

// RestoreBackup restores from a backup
func (bm *BackupManager) RestoreBackup(ctx context.Context, options *RestoreOptions) error {
	// Get backup info
	backupInfo, err := bm.GetBackupInfo(ctx, options.BackupID)
	if err != nil {
		return fmt.Errorf("failed to get backup info: %w", err)
	}

	if backupInfo.Status != BackupStatusCompleted {
		return fmt.Errorf("backup is not in completed state: %s", backupInfo.Status)
	}

	// Validate backup before restore
	validation, err := bm.ValidateBackup(ctx, options.BackupID)
	if err != nil {
		return fmt.Errorf("failed to validate backup: %w", err)
	}

	if !validation.Valid {
		return fmt.Errorf("backup validation failed: %v", validation.Errors)
	}

	// Perform restore
	if options.DryRun {
		return bm.performDryRunRestore(ctx, backupInfo, options)
	}

	return bm.performRestore(ctx, backupInfo, options)
}

// performRestore performs the actual restore operation
func (bm *BackupManager) performRestore(ctx context.Context, backupInfo *BackupInfo, options *RestoreOptions) error {
	// Open backup file
	file, err := os.Open(backupInfo.FilePath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file

	// Handle compression
	if strings.HasSuffix(backupInfo.FilePath, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Create tar reader
	tarReader := tar.NewReader(reader)

	// Process each file in the archive
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		switch header.Name {
		case "secrets.json":
			if options.RestoreSecrets {
				if err := bm.restoreSecrets(ctx, tarReader, options.OverwriteExisting); err != nil {
					return fmt.Errorf("failed to restore secrets: %w", err)
				}
			}
		case "audit_events.json":
			if options.RestoreAuditLogs {
				if err := bm.restoreAuditLogs(ctx, tarReader, options.OverwriteExisting); err != nil {
					return fmt.Errorf("failed to restore audit logs: %w", err)
				}
			}
		case "configuration.json":
			if options.RestoreConfig {
				if err := bm.restoreConfiguration(ctx, tarReader); err != nil {
					return fmt.Errorf("failed to restore configuration: %w", err)
				}
			}
		}
	}

	return nil
}

// restoreSecrets restores secrets from backup data
func (bm *BackupManager) restoreSecrets(ctx context.Context, reader io.Reader, overwrite bool) error {
	// Read and parse secrets data
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read secrets data: %w", err)
	}

	var secrets []map[string]interface{}
	if err := json.Unmarshal(data, &secrets); err != nil {
		return fmt.Errorf("failed to unmarshal secrets: %w", err)
	}

	// Restore each secret
	for _, secretData := range secrets {
		if err := bm.restoreSecret(ctx, secretData, overwrite); err != nil {
			// Log error but continue with other secrets
			continue
		}
	}

	return nil
}

// restoreSecret restores a single secret
func (bm *BackupManager) restoreSecret(ctx context.Context, secretData map[string]interface{}, overwrite bool) error {
	// Check if secret already exists
	id := secretData["id"].(string)
	_, err := bm.storage.GetSecret(ctx, id)
	
	if err == nil && !overwrite {
		// Secret exists and overwrite is disabled
		return nil
	}

	// Convert map back to Secret struct
	secret := &Secret{
		ID:     id,
		Name:   secretData["name"].(string),
		KeyID:  secretData["key_id"].(string),
		Status: SecretStatus(secretData["status"].(string)),
	}

	// Handle encrypted value
	if encryptedValue, ok := secretData["encrypted_value"].([]byte); ok {
		secret.EncryptedValue = encryptedValue
	}

	// Handle metadata and tags
	if metadata, ok := secretData["metadata"].(map[string]interface{}); ok {
		secret.Metadata = make(map[string]string)
		for k, v := range metadata {
			if str, ok := v.(string); ok {
				secret.Metadata[k] = str
			}
		}
	}

	if tags, ok := secretData["tags"].([]interface{}); ok {
		for _, tag := range tags {
			if str, ok := tag.(string); ok {
				secret.Tags = append(secret.Tags, str)
			}
		}
	}

	// Insert or update secret
	if overwrite {
		return bm.storage.UpdateSecret(ctx, id, secret)
	} else {
		return bm.storage.CreateSecret(ctx, secret)
	}
}

// restoreAuditLogs restores audit logs from backup data
func (bm *BackupManager) restoreAuditLogs(ctx context.Context, reader io.Reader, overwrite bool) error {
	// Read and parse audit events data
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read audit events data: %w", err)
	}

	var events []map[string]interface{}
	if err := json.Unmarshal(data, &events); err != nil {
		return fmt.Errorf("failed to unmarshal audit events: %w", err)
	}

	// Restore each event
	for _, eventData := range events {
		if err := bm.restoreAuditEvent(ctx, eventData, overwrite); err != nil {
			// Log error but continue with other events
			continue
		}
	}

	return nil
}

// restoreAuditEvent restores a single audit event
func (bm *BackupManager) restoreAuditEvent(ctx context.Context, eventData map[string]interface{}, overwrite bool) error {
	// Check if event already exists
	id := eventData["id"].(string)
	var exists bool
	err := bm.db.QueryRowContext(ctx, "SELECT 1 FROM audit_events WHERE id = ?", id).Scan(&exists)
	
	if err == nil && !overwrite {
		// Event exists and overwrite is disabled
		return nil
	}

	// Insert audit event
	query := `
	INSERT OR REPLACE INTO audit_events 
	(id, vault_id, event_type, actor_type, actor_id, resource_type, 
	 resource_id, action, result, context, timestamp, ip_address, 
	 user_agent, session_id)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = bm.db.ExecContext(ctx, query,
		eventData["id"], eventData["vault_id"], eventData["event_type"],
		eventData["actor_type"], eventData["actor_id"], eventData["resource_type"],
		eventData["resource_id"], eventData["action"], eventData["result"],
		eventData["context"], eventData["timestamp"], eventData["ip_address"],
		eventData["user_agent"], eventData["session_id"])

	return err
}

// restoreConfiguration restores configuration from backup data
func (bm *BackupManager) restoreConfiguration(ctx context.Context, reader io.Reader) error {
	// Read configuration data
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read configuration data: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	// Process configuration restoration
	// This would typically involve updating system configuration
	// For now, we'll just validate the schema version
	if version, ok := config["version"].(string); ok {
		if version != "1.0.0" {
			return fmt.Errorf("unsupported backup version: %s", version)
		}
	}

	return nil
}

// ValidateBackup validates a backup file
func (bm *BackupManager) ValidateBackup(ctx context.Context, backupID string) (*ValidationResult, error) {
	backupInfo, err := bm.GetBackupInfo(ctx, backupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup info: %w", err)
	}

	result := &ValidationResult{
		Valid:    true,
		Contents: make(map[string]interface{}),
	}

	// Check file existence
	if _, err := os.Stat(backupInfo.FilePath); os.IsNotExist(err) {
		result.Valid = false
		result.Errors = append(result.Errors, "backup file does not exist")
		return result, nil
	}

	// Verify checksum
	actualChecksum, err := bm.calculateFileChecksum(backupInfo.FilePath)
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

	// Get file size
	fileInfo, err := os.Stat(backupInfo.FilePath)
	if err == nil {
		result.FileSize = fileInfo.Size()
		if result.FileSize != backupInfo.FileSize {
			result.Warnings = append(result.Warnings, "file size mismatch")
		}
	}

	return result, nil
}

// GetBackupInfo retrieves backup information
func (bm *BackupManager) GetBackupInfo(ctx context.Context, backupID string) (*BackupInfo, error) {
	query := `
	SELECT id, name, backup_type, status, file_path, file_size, checksum,
		created_at, completed_at, expires_at, metadata
	FROM backups WHERE id = ?
	`

	var info BackupInfo
	var metadataJSON string
	
	err := bm.db.QueryRowContext(ctx, query, backupID).Scan(
		&info.ID, &info.Name, &info.Type, &info.Status, &info.FilePath,
		&info.FileSize, &info.Checksum, &info.CreatedAt, &info.CompletedAt,
		&info.ExpiresAt, &metadataJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup info: %w", err)
	}

	json.Unmarshal([]byte(metadataJSON), &info.Metadata)

	return &info, nil
}

// ListBackups lists all backups
func (bm *BackupManager) ListBackups(ctx context.Context) ([]*BackupInfo, error) {
	query := `
	SELECT id, name, backup_type, status, file_path, file_size, checksum,
		created_at, completed_at, expires_at, metadata
	FROM backups ORDER BY created_at DESC
	`

	rows, err := bm.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query backups: %w", err)
	}
	defer rows.Close()

	var backups []*BackupInfo
	for rows.Next() {
		var info BackupInfo
		var metadataJSON string

		err := rows.Scan(
			&info.ID, &info.Name, &info.Type, &info.Status, &info.FilePath,
			&info.FileSize, &info.Checksum, &info.CreatedAt, &info.CompletedAt,
			&info.ExpiresAt, &metadataJSON,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(metadataJSON), &info.Metadata)
		backups = append(backups, &info)
	}

	return backups, nil
}

// Helper methods

func (bm *BackupManager) insertBackupRecord(ctx context.Context, info *BackupInfo) error {
	metadataJSON, _ := json.Marshal(info.Metadata)
	
	query := `
	INSERT INTO backups (id, name, backup_type, status, created_at, expires_at, metadata)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := bm.db.ExecContext(ctx, query,
		info.ID, info.Name, info.Type, info.Status,
		info.CreatedAt, info.ExpiresAt, string(metadataJSON))

	return err
}

func (bm *BackupManager) updateBackupStatus(ctx context.Context, backupID string, status BackupStatus) error {
	query := `UPDATE backups SET status = ? WHERE id = ?`
	_, err := bm.db.ExecContext(ctx, query, status, backupID)
	return err
}

func (bm *BackupManager) updateBackupCompletion(ctx context.Context, backupID, filePath string, fileSize int64, checksum string, completedAt *time.Time) error {
	query := `
	UPDATE backups 
	SET status = ?, file_path = ?, file_size = ?, checksum = ?, completed_at = ?
	WHERE id = ?
	`

	_, err := bm.db.ExecContext(ctx, query,
		BackupStatusCompleted, filePath, fileSize, checksum, completedAt, backupID)

	return err
}

func (bm *BackupManager) calculateFileChecksum(filePath string) (string, error) {
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

func (bm *BackupManager) getDatabaseSchema(ctx context.Context) map[string]interface{} {
	// Return basic schema information
	return map[string]interface{}{
		"tables": []string{"secrets", "secret_versions", "audit_events", "cluster_nodes", "backups"},
		"version": "1.0.0",
	}
}

func (bm *BackupManager) performDryRunRestore(ctx context.Context, backupInfo *BackupInfo, options *RestoreOptions) error {
	// Simulate restore without making changes
	// This would analyze the backup and report what would be restored
	return nil
}

func generateBackupID() string {
	return fmt.Sprintf("backup-%d", time.Now().UnixNano())
}