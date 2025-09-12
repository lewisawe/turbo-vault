package backup

import (
	"archive/tar"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyvault/agent/internal/crypto"
)

// Test fixtures and helpers

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)

	// Create test tables
	schema := `
	CREATE TABLE secrets (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		encrypted_value BLOB NOT NULL,
		key_id TEXT NOT NULL,
		metadata TEXT DEFAULT '{}',
		tags TEXT DEFAULT '[]',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		rotation_due DATETIME,
		version INTEGER DEFAULT 1,
		created_by TEXT NOT NULL,
		access_count INTEGER DEFAULT 0,
		last_accessed DATETIME,
		status TEXT DEFAULT 'active'
	);

	CREATE TABLE audit_events (
		id TEXT PRIMARY KEY,
		vault_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		actor_type TEXT NOT NULL,
		actor_id TEXT NOT NULL,
		resource_type TEXT NOT NULL,
		resource_id TEXT,
		action TEXT NOT NULL,
		result TEXT NOT NULL,
		context TEXT DEFAULT '{}',
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		ip_address TEXT,
		user_agent TEXT,
		session_id TEXT
	);

	CREATE TABLE backups (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		backup_type TEXT NOT NULL,
		status TEXT NOT NULL,
		file_path TEXT,
		file_size INTEGER,
		checksum TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME,
		expires_at DATETIME,
		metadata TEXT DEFAULT '{}',
		destinations TEXT DEFAULT '[]',
		error_message TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err = db.Exec(schema)
	require.NoError(t, err)

	return db
}

// MockStorage implements StorageInterface for testing
type MockStorage struct {
	secrets map[string]*Secret
}

func (m *MockStorage) GetSecret(ctx context.Context, id string) (*Secret, error) {
	if secret, exists := m.secrets[id]; exists {
		return secret, nil
	}
	return nil, fmt.Errorf("secret not found: %s", id)
}

func (m *MockStorage) CreateSecret(ctx context.Context, secret *Secret) error {
	if m.secrets == nil {
		m.secrets = make(map[string]*Secret)
	}
	m.secrets[secret.ID] = secret
	return nil
}

func (m *MockStorage) UpdateSecret(ctx context.Context, id string, secret *Secret) error {
	if m.secrets == nil {
		m.secrets = make(map[string]*Secret)
	}
	m.secrets[id] = secret
	return nil
}

func setupTestStorage(t *testing.T, db *sql.DB) StorageInterface {
	return &MockStorage{
		secrets: make(map[string]*Secret),
	}
}

func createTestSecrets(t *testing.T, db *sql.DB, count int) {
	for i := 0; i < count; i++ {
		metadata := map[string]string{"env": "test", "app": "vault"}
		tags := []string{"test", "backup"}
		
		metadataJSON, _ := json.Marshal(metadata)
		tagsJSON, _ := json.Marshal(tags)
		
		_, err := db.Exec(`
			INSERT INTO secrets (id, name, encrypted_value, key_id, metadata, tags, created_by)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, 
			generateSecretID(i), 
			generateSecretName(i),
			[]byte("encrypted_data"),
			"test_key",
			string(metadataJSON),
			string(tagsJSON),
			"test_user",
		)
		require.NoError(t, err)
	}
}

func createTestAuditEvents(t *testing.T, db *sql.DB, count int) {
	for i := 0; i < count; i++ {
		_, err := db.Exec(`
			INSERT INTO audit_events (id, vault_id, event_type, actor_type, actor_id, 
				resource_type, resource_id, action, result, context)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			generateEventID(i),
			"test_vault",
			"secret_access",
			"user",
			"test_user",
			"secret",
			generateSecretID(i),
			"read",
			"success",
			"{}",
		)
		require.NoError(t, err)
	}
}

func generateSecretID(i int) string {
	return fmt.Sprintf("secret_%d", i)
}

func generateSecretName(i int) string {
	return fmt.Sprintf("test_secret_%d", i)
}

func generateEventID(i int) string {
	return fmt.Sprintf("event_%d", i)
}

// Mock implementations

type MockEncryptor struct{}

func (m *MockEncryptor) EncryptString(ctx context.Context, keyID, plaintext string) (*crypto.EncryptedData, error) {
	return &crypto.EncryptedData{
		Ciphertext: []byte("encrypted_" + plaintext),
		KeyID:      keyID,
		Algorithm:  "AES256-GCM",
	}, nil
}

func (m *MockEncryptor) DecryptString(ctx context.Context, data *crypto.EncryptedData) (string, error) {
	return string(data.Ciphertext), nil
}

func (m *MockEncryptor) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*crypto.EncryptedData, error) {
	return &crypto.EncryptedData{
		Ciphertext: append([]byte("encrypted_"), plaintext...),
		KeyID:      keyID,
		Algorithm:  "AES256-GCM",
	}, nil
}

func (m *MockEncryptor) Decrypt(ctx context.Context, data *crypto.EncryptedData) ([]byte, error) {
	return data.Ciphertext, nil
}

// Test cases

func TestBackupManager_CreateBackup(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	storage := setupTestStorage(t, db)
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	
	manager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)

	// Register local destination
	tempDir, err := ioutil.TempDir("", "backup_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	localDest := NewLocalDestination()
	manager.RegisterDestination("local", localDest)

	// Create test data
	createTestSecrets(t, db, 10)
	createTestAuditEvents(t, db, 20)

	// Create backup configuration
	config := &BackupConfig{
		Name:             "test_backup",
		Type:             BackupTypeFull,
		IncludeSecrets:   true,
		IncludeAuditLogs: true,
		IncludeConfig:    true,
		Compression:      true,
		Encryption:       false,
		Destinations: []DestinationConfig{
			{
				Name: "local",
				Type: DestinationTypeLocal,
				Path: tempDir,
			},
		},
		Retention: RetentionPolicy{
			MaxAge:   24 * time.Hour,
			MaxCount: 10,
		},
	}

	// Create backup
	ctx := context.Background()
	backupInfo, err := manager.CreateBackup(ctx, config)
	require.NoError(t, err)
	assert.NotEmpty(t, backupInfo.ID)
	assert.Equal(t, config.Name, backupInfo.Name)
	assert.Equal(t, BackupStatusPending, backupInfo.Status)

	// Wait for backup completion (in real scenario, this would be async)
	time.Sleep(100 * time.Millisecond)

	// Verify backup was created
	updatedInfo, err := manager.GetBackupInfo(ctx, backupInfo.ID)
	require.NoError(t, err)
	assert.Equal(t, backupInfo.ID, updatedInfo.ID)
}

func TestBackupManager_ValidateBackup(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	storage := setupTestStorage(t, db)
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	
	manager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)

	// Create a test backup file
	tempDir, err := ioutil.TempDir("", "backup_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	backupFile := filepath.Join(tempDir, "test_backup.backup")
	file, err := os.Create(backupFile)
	require.NoError(t, err)
	file.WriteString("test backup content")
	file.Close()

	// Calculate checksum
	checksum, err := manager.calculateFileChecksum(backupFile)
	require.NoError(t, err)

	// Create backup record
	backupInfo := &BackupInfo{
		ID:       "test_backup_id",
		Name:     "test_backup",
		Type:     BackupTypeFull,
		Status:   BackupStatusCompleted,
		FilePath: backupFile,
		FileSize: 19, // Length of "test backup content"
		Checksum: checksum,
	}

	err = manager.insertBackupRecord(context.Background(), backupInfo)
	require.NoError(t, err)

	// Validate backup
	ctx := context.Background()
	validation, err := manager.ValidateBackup(ctx, backupInfo.ID)
	require.NoError(t, err)
	assert.True(t, validation.Valid)
	assert.True(t, validation.ChecksumMatch)
	assert.Equal(t, int64(19), validation.FileSize)
}

func TestBackupManager_ValidateBackup_CorruptedFile(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	storage := setupTestStorage(t, db)
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	
	manager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)

	// Create a test backup file
	tempDir, err := ioutil.TempDir("", "backup_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	backupFile := filepath.Join(tempDir, "test_backup.backup")
	file, err := os.Create(backupFile)
	require.NoError(t, err)
	file.WriteString("corrupted backup content")
	file.Close()

	// Create backup record with wrong checksum
	backupInfo := &BackupInfo{
		ID:       "test_backup_id",
		Name:     "test_backup",
		Type:     BackupTypeFull,
		Status:   BackupStatusCompleted,
		FilePath: backupFile,
		FileSize: 25,
		Checksum: "wrong_checksum",
	}

	err = manager.insertBackupRecord(context.Background(), backupInfo)
	require.NoError(t, err)

	// Validate backup
	ctx := context.Background()
	validation, err := manager.ValidateBackup(ctx, backupInfo.ID)
	require.NoError(t, err)
	assert.False(t, validation.Valid)
	assert.False(t, validation.ChecksumMatch)
	assert.Contains(t, validation.Errors, "checksum mismatch")
}

func TestRestoreManager_RestoreBackup_DryRun(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	storage := setupTestStorage(t, db)
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	
	backupManager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)
	restoreManager := NewRestoreManager(backupManager, logger)

	// Create test backup file with valid tar structure
	tempDir, err := ioutil.TempDir("", "restore_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	backupFile := filepath.Join(tempDir, "test_backup.backup")
	err = createTestBackupFile(t, backupFile)
	require.NoError(t, err)

	// Calculate checksum
	checksum, err := backupManager.calculateFileChecksum(backupFile)
	require.NoError(t, err)

	// Create backup record
	backupInfo := &BackupInfo{
		ID:       "test_backup_id",
		Name:     "test_backup",
		Type:     BackupTypeFull,
		Status:   BackupStatusCompleted,
		FilePath: backupFile,
		FileSize: getFileSize(t, backupFile),
		Checksum: checksum,
	}

	err = backupManager.insertBackupRecord(context.Background(), backupInfo)
	require.NoError(t, err)

	// Perform dry run restore
	options := &RestoreOptions{
		BackupID:         backupInfo.ID,
		RestoreSecrets:   true,
		RestoreAuditLogs: true,
		RestoreConfig:    true,
		DryRun:           true,
	}

	ctx := context.Background()
	result, err := restoreManager.RestoreBackup(ctx, options)
	require.NoError(t, err)
	assert.Equal(t, RestoreStatusCompleted, result.Status)
	assert.True(t, result.DryRun)
	assert.Greater(t, result.SecretsRestored, 0)
}

func TestRestoreManager_RestoreBackup_WithFilters(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	storage := setupTestStorage(t, db)
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	
	backupManager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)
	restoreManager := NewRestoreManager(backupManager, logger)

	// Create test backup file
	tempDir, err := ioutil.TempDir("", "restore_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	backupFile := filepath.Join(tempDir, "test_backup.backup")
	err = createTestBackupFile(t, backupFile)
	require.NoError(t, err)

	// Calculate checksum
	checksum, err := backupManager.calculateFileChecksum(backupFile)
	require.NoError(t, err)

	// Create backup record
	backupInfo := &BackupInfo{
		ID:       "test_backup_id",
		Name:     "test_backup",
		Type:     BackupTypeFull,
		Status:   BackupStatusCompleted,
		FilePath: backupFile,
		FileSize: getFileSize(t, backupFile),
		Checksum: checksum,
	}

	err = backupManager.insertBackupRecord(context.Background(), backupInfo)
	require.NoError(t, err)

	// Perform restore with filters
	afterTime := time.Now().Add(-1 * time.Hour)
	options := &RestoreOptions{
		BackupID:         backupInfo.ID,
		RestoreSecrets:   true,
		RestoreAuditLogs: false,
		RestoreConfig:    false,
		DryRun:           true,
		Filters: &RestoreFilters{
			SecretNames:   []string{"test_secret_1", "test_secret_2"},
			RestoreAfter:  &afterTime,
		},
	}

	ctx := context.Background()
	result, err := restoreManager.RestoreBackup(ctx, options)
	require.NoError(t, err)
	assert.Equal(t, RestoreStatusCompleted, result.Status)
	assert.Equal(t, 0, result.AuditEventsRestored) // Should be 0 due to filter
}

func TestBackupScheduler_AddSchedule(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	storage := setupTestStorage(t, db)
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	
	manager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)
	scheduler := NewBackupScheduler(manager, logger)

	err := scheduler.Start()
	require.NoError(t, err)
	defer scheduler.Stop()

	// Create backup schedule
	schedule := &BackupSchedule{
		ID:       "test_schedule",
		Name:     "Daily Backup",
		CronExpr: "0 0 2 * * *", // Daily at 2 AM (with seconds)
		Config: &BackupConfig{
			Name:             "scheduled_backup",
			Type:             BackupTypeFull,
			IncludeSecrets:   true,
			IncludeAuditLogs: true,
		},
		Enabled: true,
	}

	// Add schedule
	err = scheduler.AddSchedule(schedule)
	require.NoError(t, err)

	// Verify schedule was added
	retrievedSchedule, err := scheduler.GetSchedule(schedule.ID)
	require.NoError(t, err)
	assert.Equal(t, schedule.Name, retrievedSchedule.Name)
	assert.Equal(t, schedule.CronExpr, retrievedSchedule.CronExpr)
	assert.True(t, retrievedSchedule.Enabled)
}

func TestDisasterRecoveryManager_RunDRTest(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	storage := setupTestStorage(t, db)
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	
	backupManager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)
	restoreManager := NewRestoreManager(backupManager, logger)
	drManager := NewDisasterRecoveryManager(backupManager, restoreManager, logger)

	// Create test data
	createTestSecrets(t, db, 5)
	createTestAuditEvents(t, db, 10)

	// Create DR test configuration
	config := &DRTestConfig{
		TestType:        DRTestTypeBackupValidation,
		TestEnvironment: "test",
		BackupConfig: &BackupConfig{
			Name:             "dr_test_backup",
			Type:             BackupTypeFull,
			IncludeSecrets:   true,
			IncludeAuditLogs: true,
			IncludeConfig:    true,
		},
		ValidationLevel: ValidationLevelStandard,
	}

	// Run DR test
	ctx := context.Background()
	result, err := drManager.RunDRTest(ctx, config)
	require.NoError(t, err)
	assert.NotEmpty(t, result.TestID)
	assert.Equal(t, DRTestTypeBackupValidation, result.TestType)
	// Note: In a real test, we would wait for async completion
}

func TestLocalDestination_Upload(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "destination_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test file
	testFile := filepath.Join(tempDir, "test_file.txt")
	err = ioutil.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Create destination
	dest := NewLocalDestination()
	config := &DestinationConfig{
		Name: "test_local",
		Type: DestinationTypeLocal,
		Path: filepath.Join(tempDir, "backups"),
	}

	// Test upload
	ctx := context.Background()
	remotePath, err := dest.Upload(ctx, testFile, config)
	require.NoError(t, err)
	assert.Contains(t, remotePath, "test_file.txt")

	// Verify file was uploaded
	_, err = os.Stat(remotePath)
	require.NoError(t, err)
}

func TestLocalDestination_Validate(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "destination_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	dest := NewLocalDestination()
	
	// Test valid configuration
	validConfig := &DestinationConfig{
		Name: "test_local",
		Type: DestinationTypeLocal,
		Path: tempDir,
	}

	err = dest.Validate(validConfig)
	assert.NoError(t, err)

	// Test invalid configuration (non-existent path)
	invalidConfig := &DestinationConfig{
		Name: "test_local",
		Type: DestinationTypeLocal,
		Path: "/non/existent/path",
	}

	err = dest.Validate(invalidConfig)
	assert.Error(t, err)
}

// Helper functions

func createTestBackupFile(t *testing.T, filePath string) error {
	// Create a proper tar file with test data that matches what restore expects
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(file)
	defer tarWriter.Close()

	// Add secrets.json
	secrets := []map[string]interface{}{
		{
			"id":              "secret_1",
			"name":            "test_secret_1",
			"encrypted_value": []byte("encrypted_data_1"),
			"key_id":          "test_key",
			"metadata":        map[string]string{"env": "test"},
			"tags":            []string{"test"},
			"created_at":      time.Now().UTC().Format(time.RFC3339),
			"updated_at":      time.Now().UTC().Format(time.RFC3339),
			"version":         1,
			"created_by":      "test_user",
			"access_count":    0,
			"status":          "active",
		},
		{
			"id":              "secret_2",
			"name":            "test_secret_2",
			"encrypted_value": []byte("encrypted_data_2"),
			"key_id":          "test_key",
			"metadata":        map[string]string{"env": "test"},
			"tags":            []string{"test"},
			"created_at":      time.Now().UTC().Format(time.RFC3339),
			"updated_at":      time.Now().UTC().Format(time.RFC3339),
			"version":         1,
			"created_by":      "test_user",
			"access_count":    0,
			"status":          "active",
		},
	}

	secretsJSON, _ := json.MarshalIndent(secrets, "", "  ")
	
	header := &tar.Header{
		Name: "secrets.json",
		Mode: 0644,
		Size: int64(len(secretsJSON)),
	}
	tarWriter.WriteHeader(header)
	tarWriter.Write(secretsJSON)

	// Add audit_events.json
	events := []map[string]interface{}{
		{
			"id":           "event_1",
			"vault_id":     "test_vault",
			"event_type":   "secret_access",
			"actor_type":   "user",
			"actor_id":     "test_user",
			"resource_type": "secret",
			"resource_id":  "secret_1",
			"action":       "read",
			"result":       "success",
			"context":      "{}",
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
		},
	}

	eventsJSON, _ := json.MarshalIndent(events, "", "  ")
	
	header = &tar.Header{
		Name: "audit_events.json",
		Mode: 0644,
		Size: int64(len(eventsJSON)),
	}
	tarWriter.WriteHeader(header)
	tarWriter.Write(eventsJSON)

	// Add configuration.json
	config := map[string]interface{}{
		"version":           "1.0.0",
		"backup_created_at": time.Now().UTC().Format(time.RFC3339),
		"system_info": map[string]interface{}{
			"hostname": "test_host",
		},
	}

	configJSON, _ := json.MarshalIndent(config, "", "  ")
	
	header = &tar.Header{
		Name: "configuration.json",
		Mode: 0644,
		Size: int64(len(configJSON)),
	}
	tarWriter.WriteHeader(header)
	tarWriter.Write(configJSON)

	return nil
}

func getFileSize(t *testing.T, filePath string) int64 {
	info, err := os.Stat(filePath)
	require.NoError(t, err)
	return info.Size()
}

// Benchmark tests

func BenchmarkBackupManager_CreateBackup(b *testing.B) {
	db := setupTestDB(&testing.T{})
	defer db.Close()

	storage := setupTestStorage(&testing.T{}, db)
	logger := log.New(os.Stdout, "bench: ", log.LstdFlags)
	
	manager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)

	// Create test data
	createTestSecrets(&testing.T{}, db, 1000)
	createTestAuditEvents(&testing.T{}, db, 2000)

	tempDir, _ := ioutil.TempDir("", "backup_bench")
	defer os.RemoveAll(tempDir)

	localDest := NewLocalDestination()
	manager.RegisterDestination("local", localDest)

	config := &BackupConfig{
		Name:             "bench_backup",
		Type:             BackupTypeFull,
		IncludeSecrets:   true,
		IncludeAuditLogs: true,
		IncludeConfig:    true,
		Compression:      true,
		Destinations: []DestinationConfig{
			{
				Name: "local",
				Type: DestinationTypeLocal,
				Path: tempDir,
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.Name = fmt.Sprintf("bench_backup_%d", i)
		_, err := manager.CreateBackup(context.Background(), config)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRestoreManager_RestoreBackup(b *testing.B) {
	db := setupTestDB(&testing.T{})
	defer db.Close()

	storage := setupTestStorage(&testing.T{}, db)
	logger := log.New(os.Stdout, "bench: ", log.LstdFlags)
	
	backupManager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)
	restoreManager := NewRestoreManager(backupManager, logger)

	// Create test backup
	tempDir, _ := ioutil.TempDir("", "restore_bench")
	defer os.RemoveAll(tempDir)

	backupFile := filepath.Join(tempDir, "bench_backup.backup")
	createTestBackupFile(&testing.T{}, backupFile)

	checksum, _ := backupManager.calculateFileChecksum(backupFile)
	backupInfo := &BackupInfo{
		ID:       "bench_backup_id",
		Name:     "bench_backup",
		Type:     BackupTypeFull,
		Status:   BackupStatusCompleted,
		FilePath: backupFile,
		FileSize: getFileSize(&testing.T{}, backupFile),
		Checksum: checksum,
	}

	backupManager.insertBackupRecord(context.Background(), backupInfo)

	options := &RestoreOptions{
		BackupID:         backupInfo.ID,
		RestoreSecrets:   true,
		RestoreAuditLogs: true,
		RestoreConfig:    true,
		DryRun:           true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := restoreManager.RestoreBackup(context.Background(), options)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Comprehensive corruption and disaster recovery tests

func TestBackupManager_ValidateBackup_ComprehensiveValidation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	storage := setupTestStorage(t, db)
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	
	manager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)

	// Create test data
	createTestSecrets(t, db, 5)
	createTestAuditEvents(t, db, 10)

	// Create a proper backup file with tar structure
	tempDir, err := ioutil.TempDir("", "validation_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	backupFile := filepath.Join(tempDir, "test_backup.backup")
	err = createProperBackupFile(t, backupFile, db)
	require.NoError(t, err)

	// Calculate checksum
	checksum, err := manager.calculateFileChecksum(backupFile)
	require.NoError(t, err)

	// Create backup record
	backupInfo := &BackupInfo{
		ID:       "validation_test_id",
		Name:     "validation_test",
		Type:     BackupTypeFull,
		Status:   BackupStatusCompleted,
		FilePath: backupFile,
		FileSize: getFileSize(t, backupFile),
		Checksum: checksum,
	}

	err = manager.insertBackupRecord(context.Background(), backupInfo)
	require.NoError(t, err)

	// Validate backup
	ctx := context.Background()
	validation, err := manager.ValidateBackup(ctx, backupInfo.ID)
	require.NoError(t, err)
	assert.True(t, validation.Valid)
	assert.True(t, validation.ChecksumMatch)
	assert.True(t, validation.Integrity.ConfigValid)
	assert.True(t, validation.Integrity.EncryptionValid)
	assert.Equal(t, 5, validation.Integrity.SecretsCount)
	assert.Equal(t, 10, validation.Integrity.AuditEventsCount)
}

func TestBackupManager_CorruptionDetection(t *testing.T) {
	tests := []struct {
		name           string
		corruptionType string
		expectValid    bool
		expectError    string
	}{
		{
			name:           "File Size Corruption",
			corruptionType: "size",
			expectValid:    false,
			expectError:    "file size mismatch",
		},
		{
			name:           "Checksum Corruption",
			corruptionType: "checksum",
			expectValid:    false,
			expectError:    "checksum mismatch",
		},
		{
			name:           "Content Corruption",
			corruptionType: "content",
			expectValid:    false,
			expectError:    "checksum mismatch",
		},
		{
			name:           "Missing File",
			corruptionType: "missing",
			expectValid:    false,
			expectError:    "backup file not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupTestDB(t)
			defer db.Close()

			storage := setupTestStorage(t, db)
			logger := log.New(os.Stdout, "test: ", log.LstdFlags)
			
			manager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)

			// Create test data
			createTestSecrets(t, db, 3)
			createTestAuditEvents(t, db, 5)

			// Create backup file
			tempDir, err := ioutil.TempDir("", "corruption_test")
			require.NoError(t, err)
			defer os.RemoveAll(tempDir)

			backupFile := filepath.Join(tempDir, "test_backup.backup")
			err = createProperBackupFile(t, backupFile, db)
			require.NoError(t, err)

			// Calculate original checksum and size
			originalChecksum, err := manager.calculateFileChecksum(backupFile)
			require.NoError(t, err)
			originalSize := getFileSize(t, backupFile)

			// Apply corruption based on test type
			var corruptedChecksum string
			var corruptedSize int64

			switch tt.corruptionType {
			case "size":
				// Truncate file to simulate size corruption
				err = os.Truncate(backupFile, originalSize/2)
				require.NoError(t, err)
				corruptedChecksum = originalChecksum
				corruptedSize = originalSize // Keep original size in record
			case "checksum":
				// Keep file intact but use wrong checksum
				corruptedChecksum = "wrong_checksum_value"
				corruptedSize = originalSize
			case "content":
				// Corrupt file content
				err = ioutil.WriteFile(backupFile, []byte("corrupted content"), 0644)
				require.NoError(t, err)
				corruptedChecksum = originalChecksum
				corruptedSize = originalSize
			case "missing":
				// Remove file
				err = os.Remove(backupFile)
				require.NoError(t, err)
				corruptedChecksum = originalChecksum
				corruptedSize = originalSize
			}

			// Create backup record with potentially corrupted info
			backupInfo := &BackupInfo{
				ID:       fmt.Sprintf("corruption_test_%s", tt.corruptionType),
				Name:     fmt.Sprintf("corruption_test_%s", tt.corruptionType),
				Type:     BackupTypeFull,
				Status:   BackupStatusCompleted,
				FilePath: backupFile,
				FileSize: corruptedSize,
				Checksum: corruptedChecksum,
			}

			err = manager.insertBackupRecord(context.Background(), backupInfo)
			require.NoError(t, err)

			// Validate backup
			ctx := context.Background()
			validation, err := manager.ValidateBackup(ctx, backupInfo.ID)
			require.NoError(t, err)

			assert.Equal(t, tt.expectValid, validation.Valid)
			if !tt.expectValid {
				found := false
				for _, errMsg := range validation.Errors {
					if strings.Contains(errMsg, tt.expectError) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected error message '%s' not found in: %v", tt.expectError, validation.Errors)
			}
		})
	}
}

func TestDisasterRecoveryManager_ComprehensiveTests(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	storage := setupTestStorage(t, db)
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	
	backupManager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)
	restoreManager := NewRestoreManager(backupManager, logger)
	drManager := NewDisasterRecoveryManager(backupManager, restoreManager, logger)

	// Register local destination
	tempDir, err := ioutil.TempDir("", "dr_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	localDest := NewLocalDestination()
	backupManager.RegisterDestination("local", localDest)

	// Create test data
	createTestSecrets(t, db, 10)
	createTestAuditEvents(t, db, 20)

	tests := []struct {
		name       string
		testType   DRTestType
		expectPass bool
	}{
		{
			name:       "Backup Validation Test",
			testType:   DRTestTypeBackupValidation,
			expectPass: true,
		},
		{
			name:       "Restore Validation Test",
			testType:   DRTestTypeRestoreValidation,
			expectPass: true,
		},
		{
			name:       "Full Recovery Test",
			testType:   DRTestTypeFullRecovery,
			expectPass: true,
		},
		{
			name:       "Automated Test Suite",
			testType:   DRTestTypeAutomated,
			expectPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &DRTestConfig{
				TestType:        tt.testType,
				TestEnvironment: "test",
				ValidationLevel: ValidationLevelStandard,
			}

			if tt.testType == DRTestTypeBackupValidation || tt.testType == DRTestTypeFullRecovery || tt.testType == DRTestTypeAutomated {
				config.BackupConfig = &BackupConfig{
					Name:             fmt.Sprintf("dr_test_%s", tt.name),
					Type:             BackupTypeFull,
					IncludeSecrets:   true,
					IncludeAuditLogs: true,
					IncludeConfig:    true,
					Compression:      true,
					Destinations: []DestinationConfig{
						{
							Name: "local",
							Type: DestinationTypeLocal,
							Path: tempDir,
						},
					},
				}
			}

			if tt.testType == DRTestTypeRestoreValidation || tt.testType == DRTestTypeAutomated {
				config.RestoreOptions = &RestoreOptions{
					RestoreSecrets:   true,
					RestoreAuditLogs: true,
					RestoreConfig:    true,
					DryRun:           true,
				}
			}

			// Run DR test
			ctx := context.Background()
			result, err := drManager.RunDRTest(ctx, config)
			require.NoError(t, err)
			assert.NotEmpty(t, result.TestID)
			assert.Equal(t, tt.testType, result.TestType)

			if tt.expectPass {
				assert.Contains(t, []DRTestStatus{DRTestStatusCompleted, DRTestStatusPartial}, result.Status)
			} else {
				assert.Equal(t, DRTestStatusFailed, result.Status)
			}

			// Verify test result can be retrieved
			retrievedResult, err := drManager.GetTestResult(result.TestID)
			require.NoError(t, err)
			assert.Equal(t, result.TestID, retrievedResult.TestID)
		})
	}
}

func TestBackupService_EndToEndWorkflow(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	storage := setupTestStorage(t, db)
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	
	manager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)

	// Create backup service
	config := &ServiceConfig{
		AutoBackupEnabled:  true,
		AutoBackupSchedule: "0 0 2 * * *",
		RetentionPolicy: RetentionPolicy{
			MaxAge:   7 * 24 * time.Hour,
			MaxCount: 10,
		},
		ValidationLevel: ValidationLevelStandard,
		EnableDRTesting: true,
		DRTestSchedule:  "0 0 3 * * 0", // Weekly
	}

	service := NewService(manager, logger, config)

	// Register destinations
	tempDir, err := ioutil.TempDir("", "e2e_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	localDest := NewLocalDestination()
	service.RegisterDestination("local", localDest)

	// Start service
	ctx := context.Background()
	err = service.Start(ctx)
	require.NoError(t, err)
	defer service.Stop()

	// Create test data
	createTestSecrets(t, db, 15)
	createTestAuditEvents(t, db, 30)

	// Test 1: Create backup
	backupConfig := &BackupConfig{
		Name:             "e2e_test_backup",
		Type:             BackupTypeFull,
		IncludeSecrets:   true,
		IncludeAuditLogs: true,
		IncludeConfig:    true,
		Compression:      true,
		Destinations: []DestinationConfig{
			{
				Name: "local",
				Type: DestinationTypeLocal,
				Path: tempDir,
			},
		},
	}

	backupInfo, err := service.CreateBackup(ctx, backupConfig)
	require.NoError(t, err)
	assert.NotEmpty(t, backupInfo.ID)

	// Wait for backup completion (simulate async completion)
	time.Sleep(100 * time.Millisecond)

	// Test 2: Validate backup
	validation, err := service.ValidateBackup(ctx, backupInfo.ID)
	require.NoError(t, err)
	assert.True(t, validation.Valid)

	// Test 3: Test restore (dry run)
	restoreOptions := &RestoreOptions{
		BackupID:         backupInfo.ID,
		RestoreSecrets:   true,
		RestoreAuditLogs: true,
		RestoreConfig:    true,
		DryRun:           true,
	}

	restoreResult, err := service.RestoreBackup(ctx, restoreOptions)
	require.NoError(t, err)
	assert.Equal(t, RestoreStatusCompleted, restoreResult.Status)

	// Test 4: Run DR test
	drConfig := &DRTestConfig{
		TestType:        DRTestTypeFullRecovery,
		TestEnvironment: "e2e_test",
		BackupConfig:    backupConfig,
		RestoreOptions:  restoreOptions,
		ValidationLevel: ValidationLevelStandard,
	}

	drResult, err := service.RunDRTest(ctx, drConfig)
	require.NoError(t, err)
	assert.Equal(t, DRTestTypeFullRecovery, drResult.TestType)

	// Test 5: Get statistics
	stats, err := service.GetBackupStatistics(ctx)
	require.NoError(t, err)
	assert.Greater(t, stats.TotalBackups, 0)
	assert.Greater(t, stats.CompletedBackups, 0)

	// Test 6: List backups
	backups, err := service.ListBackups(ctx)
	require.NoError(t, err)
	assert.Greater(t, len(backups), 0)

	// Test 7: Cleanup expired backups
	err = service.CleanupExpiredBackups(ctx)
	require.NoError(t, err)
}

func TestBackupScheduler_ComprehensiveScheduling(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	storage := setupTestStorage(t, db)
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	
	manager := NewManager(storage, db, &MockEncryptor{}, "test_key", logger)
	scheduler := NewBackupScheduler(manager, logger)

	err := scheduler.Start()
	require.NoError(t, err)
	defer scheduler.Stop()

	// Test multiple schedule operations
	schedules := []*BackupSchedule{
		{
			ID:       "daily_backup",
			Name:     "Daily Full Backup",
			CronExpr: "0 0 2 * * *",
			Config: &BackupConfig{
				Name:             "daily_backup",
				Type:             BackupTypeFull,
				IncludeSecrets:   true,
				IncludeAuditLogs: true,
				IncludeConfig:    true,
			},
			Enabled: true,
		},
		{
			ID:       "weekly_backup",
			Name:     "Weekly Archive Backup",
			CronExpr: "0 0 3 * * 0",
			Config: &BackupConfig{
				Name:             "weekly_backup",
				Type:             BackupTypeFull,
				IncludeSecrets:   true,
				IncludeAuditLogs: true,
				IncludeConfig:    true,
				Compression:      true,
			},
			Enabled: false, // Start disabled
		},
	}

	// Add schedules
	for _, schedule := range schedules {
		err = scheduler.AddSchedule(schedule)
		require.NoError(t, err)
	}

	// Test listing schedules
	allSchedules := scheduler.ListSchedules()
	assert.Len(t, allSchedules, 2)

	// Test getting individual schedule
	dailySchedule, err := scheduler.GetSchedule("daily_backup")
	require.NoError(t, err)
	assert.Equal(t, "Daily Full Backup", dailySchedule.Name)
	assert.True(t, dailySchedule.Enabled)

	// Test enabling disabled schedule
	err = scheduler.EnableSchedule("weekly_backup")
	require.NoError(t, err)

	weeklySchedule, err := scheduler.GetSchedule("weekly_backup")
	require.NoError(t, err)
	assert.True(t, weeklySchedule.Enabled)

	// Test disabling schedule
	err = scheduler.DisableSchedule("weekly_backup")
	require.NoError(t, err)

	weeklySchedule, err = scheduler.GetSchedule("weekly_backup")
	require.NoError(t, err)
	assert.False(t, weeklySchedule.Enabled)

	// Test updating schedule
	updatedSchedule := *dailySchedule
	updatedSchedule.CronExpr = "0 0 1 * * *" // Change to 1 AM
	updatedSchedule.Name = "Updated Daily Backup"

	err = scheduler.UpdateSchedule(&updatedSchedule)
	require.NoError(t, err)

	retrievedSchedule, err := scheduler.GetSchedule("daily_backup")
	require.NoError(t, err)
	assert.Equal(t, "Updated Daily Backup", retrievedSchedule.Name)
	assert.Equal(t, "0 0 1 * * *", retrievedSchedule.CronExpr)

	// Test removing schedule
	err = scheduler.RemoveSchedule("weekly_backup")
	require.NoError(t, err)

	_, err = scheduler.GetSchedule("weekly_backup")
	assert.Error(t, err)

	// Test next run times
	nextRuns := scheduler.GetNextRunTimes()
	assert.Contains(t, nextRuns, "daily_backup")
	assert.NotContains(t, nextRuns, "weekly_backup") // Removed
}

// Helper function to create a proper backup file with tar structure
func createProperBackupFile(t *testing.T, filePath string, db *sql.DB) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(file)
	defer tarWriter.Close()

	// Add secrets.json
	secrets := make([]map[string]interface{}, 5)
	for i := 0; i < 5; i++ {
		secrets[i] = map[string]interface{}{
			"id":              fmt.Sprintf("secret_%d", i+1),
			"name":            fmt.Sprintf("test_secret_%d", i+1),
			"encrypted_value": []byte(fmt.Sprintf("encrypted_data_%d", i+1)),
			"key_id":          "test_key",
			"metadata":        map[string]string{"env": "test"},
			"tags":            []string{"test"},
			"created_at":      time.Now().UTC().Format(time.RFC3339),
			"updated_at":      time.Now().UTC().Format(time.RFC3339),
			"version":         1,
			"created_by":      "test_user",
			"access_count":    0,
			"status":          "active",
		}
	}

	secretsJSON, _ := json.MarshalIndent(secrets, "", "  ")
	
	header := &tar.Header{
		Name: "secrets.json",
		Mode: 0644,
		Size: int64(len(secretsJSON)),
	}
	tarWriter.WriteHeader(header)
	tarWriter.Write(secretsJSON)

	// Add audit_events.json
	events := make([]map[string]interface{}, 10)
	for i := 0; i < 10; i++ {
		events[i] = map[string]interface{}{
			"id":           fmt.Sprintf("event_%d", i+1),
			"vault_id":     "test_vault",
			"event_type":   "secret_access",
			"actor_type":   "user",
			"actor_id":     "test_user",
			"resource_type": "secret",
			"resource_id":  fmt.Sprintf("secret_%d", (i%5)+1),
			"action":       "read",
			"result":       "success",
			"context":      "{}",
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
		}
	}

	eventsJSON, _ := json.MarshalIndent(events, "", "  ")
	
	header = &tar.Header{
		Name: "audit_events.json",
		Mode: 0644,
		Size: int64(len(eventsJSON)),
	}
	tarWriter.WriteHeader(header)
	tarWriter.Write(eventsJSON)

	// Add configuration.json
	config := map[string]interface{}{
		"version":           "1.0.0",
		"backup_created_at": time.Now().UTC().Format(time.RFC3339),
		"system_info": map[string]interface{}{
			"hostname": "test_host",
		},
	}

	configJSON, _ := json.MarshalIndent(config, "", "  ")
	
	header = &tar.Header{
		Name: "configuration.json",
		Mode: 0644,
		Size: int64(len(configJSON)),
	}
	tarWriter.WriteHeader(header)
	tarWriter.Write(configJSON)

	return nil
}