package backup

import (
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
	"github.com/stretchr/testify/suite"
)

// BackupIntegrationTestSuite provides comprehensive integration tests for backup and disaster recovery
type BackupIntegrationTestSuite struct {
	suite.Suite
	db          *sql.DB
	storage     StorageInterface
	manager     *Manager
	service     *Service
	tempDir     string
	logger      *log.Logger
}

func (suite *BackupIntegrationTestSuite) SetupSuite() {
	// Setup database
	db, err := sql.Open("sqlite3", ":memory:")
	suite.Require().NoError(err)

	// Create comprehensive schema
	schema := `
	CREATE TABLE secrets (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
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

	CREATE TABLE secret_versions (
		id TEXT PRIMARY KEY,
		secret_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		encrypted_value BLOB NOT NULL,
		key_id TEXT NOT NULL,
		metadata TEXT DEFAULT '{}',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		created_by TEXT NOT NULL,
		FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
		UNIQUE(secret_id, version)
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

	CREATE TABLE cluster_nodes (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		address TEXT NOT NULL,
		status TEXT DEFAULT 'active',
		last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
		metadata TEXT DEFAULT '{}'
	);

	-- Indexes for performance
	CREATE INDEX idx_secrets_name ON secrets(name);
	CREATE INDEX idx_secrets_status ON secrets(status);
	CREATE INDEX idx_secrets_created_at ON secrets(created_at);
	CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp);
	CREATE INDEX idx_audit_events_vault_id ON audit_events(vault_id);
	CREATE INDEX idx_backups_status ON backups(status);
	CREATE INDEX idx_backups_created_at ON backups(created_at);
	`

	_, err = db.Exec(schema)
	suite.Require().NoError(err)

	suite.db = db

	// Setup storage and crypto
	mockEncryptor := &MockEncryptor{}
	suite.storage = &MockStorage{secrets: make(map[string]*Secret)} // Mock storage

	// Setup logger
	suite.logger = log.New(os.Stdout, "integration_test: ", log.LstdFlags)

	// Create temp directory
	tempDir, err := ioutil.TempDir("", "backup_integration_test")
	suite.Require().NoError(err)
	suite.tempDir = tempDir

	// Setup backup manager
	suite.manager = NewManager(suite.storage, suite.db, mockEncryptor, "test_key", suite.logger)

	// Register destinations
	localDest := NewLocalDestination()
	suite.manager.RegisterDestination("local", localDest)

	// Setup backup service
	config := &ServiceConfig{
		DefaultDestinations: []DestinationConfig{
			{
				Name: "local",
				Type: DestinationTypeLocal,
				Path: suite.tempDir,
			},
		},
		AutoBackupEnabled:  false, // Disable for testing
		RetentionPolicy: RetentionPolicy{
			MaxAge:   24 * time.Hour,
			MaxCount: 5,
		},
		ValidationLevel: ValidationLevelComprehensive,
		EnableDRTesting: true,
	}

	suite.service = NewService(suite.manager, suite.logger, config)
}

func (suite *BackupIntegrationTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}
	if suite.tempDir != "" {
		os.RemoveAll(suite.tempDir)
	}
}

func (suite *BackupIntegrationTestSuite) SetupTest() {
	// Clean up any existing data
	suite.db.Exec("DELETE FROM secrets")
	suite.db.Exec("DELETE FROM secret_versions")
	suite.db.Exec("DELETE FROM audit_events")
	suite.db.Exec("DELETE FROM backups")
	suite.db.Exec("DELETE FROM cluster_nodes")
}

func (suite *BackupIntegrationTestSuite) TestCompleteBackupRestoreWorkflow() {
	ctx := context.Background()

	// Step 1: Create comprehensive test data
	suite.createComprehensiveTestData()

	// Step 2: Start backup service
	err := suite.service.Start(ctx)
	suite.Require().NoError(err)
	defer suite.service.Stop()

	// Step 3: Create full backup
	backupConfig := &BackupConfig{
		Name:             "integration_test_full_backup",
		Type:             BackupTypeFull,
		IncludeSecrets:   true,
		IncludeAuditLogs: true,
		IncludeConfig:    true,
		Compression:      true,
		Encryption:       false, // Disable for testing
		Destinations: []DestinationConfig{
			{
				Name: "local",
				Type: DestinationTypeLocal,
				Path: suite.tempDir,
			},
		},
		Retention: RetentionPolicy{
			MaxAge:   7 * 24 * time.Hour,
			MaxCount: 10,
		},
		Metadata: map[string]string{
			"test_type": "integration",
			"created_by": "test_suite",
		},
	}

	backupInfo, err := suite.service.CreateBackup(ctx, backupConfig)
	suite.Require().NoError(err)
	suite.Assert().NotEmpty(backupInfo.ID)
	suite.Assert().Equal(backupConfig.Name, backupInfo.Name)

	// Wait for backup completion (simulate async processing)
	suite.waitForBackupCompletion(ctx, backupInfo.ID, 30*time.Second)

	// Step 4: Validate backup integrity
	validation, err := suite.service.ValidateBackup(ctx, backupInfo.ID)
	suite.Require().NoError(err)
	suite.Assert().True(validation.Valid, "Backup validation failed: %v", validation.Errors)
	suite.Assert().True(validation.ChecksumMatch)
	suite.Assert().True(validation.Integrity.ConfigValid)
	suite.Assert().Equal(50, validation.Integrity.SecretsCount)
	suite.Assert().Equal(100, validation.Integrity.AuditEventsCount)

	// Step 5: Test dry run restore
	restoreOptions := &RestoreOptions{
		BackupID:         backupInfo.ID,
		RestoreSecrets:   true,
		RestoreAuditLogs: true,
		RestoreConfig:    true,
		DryRun:           true,
		OverwriteExisting: false,
		Metadata: map[string]string{
			"restore_type": "dry_run",
			"test_id":      "integration_test",
		},
	}

	restoreResult, err := suite.service.RestoreBackup(ctx, restoreOptions)
	suite.Require().NoError(err)
	suite.Assert().Equal(RestoreStatusCompleted, restoreResult.Status)
	suite.Assert().True(restoreResult.DryRun)
	suite.Assert().Equal(50, restoreResult.SecretsRestored)
	suite.Assert().Equal(100, restoreResult.AuditEventsRestored)
	suite.Assert().True(restoreResult.ConfigRestored)

	// Step 6: Test filtered restore
	filteredRestoreOptions := &RestoreOptions{
		BackupID:         backupInfo.ID,
		RestoreSecrets:   true,
		RestoreAuditLogs: false,
		RestoreConfig:    false,
		DryRun:           true,
		Filters: &RestoreFilters{
			SecretNames: []string{"test_secret_1", "test_secret_5", "test_secret_10"},
			SecretTags:  []string{"production"},
		},
	}

	filteredResult, err := suite.service.RestoreBackup(ctx, filteredRestoreOptions)
	suite.Require().NoError(err)
	suite.Assert().Equal(RestoreStatusCompleted, filteredResult.Status)
	suite.Assert().Greater(filteredResult.SecretsRestored, 0)
	suite.Assert().Less(filteredResult.SecretsRestored, 50) // Should be filtered
	suite.Assert().Equal(0, filteredResult.AuditEventsRestored)
	suite.Assert().False(filteredResult.ConfigRestored)

	// Step 7: Test backup statistics
	stats, err := suite.service.GetBackupStatistics(ctx)
	suite.Require().NoError(err)
	suite.Assert().Equal(1, stats.TotalBackups)
	suite.Assert().Equal(1, stats.CompletedBackups)
	suite.Assert().Equal(0, stats.FailedBackups)
	suite.Assert().Greater(stats.TotalSize, int64(0))
}

func (suite *BackupIntegrationTestSuite) TestDisasterRecoveryScenarios() {
	ctx := context.Background()

	// Create test data
	suite.createComprehensiveTestData()

	// Start service
	err := suite.service.Start(ctx)
	suite.Require().NoError(err)
	defer suite.service.Stop()

	// Test scenarios
	scenarios := []struct {
		name        string
		testType    DRTestType
		description string
	}{
		{
			name:        "Backup Validation",
			testType:    DRTestTypeBackupValidation,
			description: "Validates backup creation and integrity",
		},
		{
			name:        "Restore Validation",
			testType:    DRTestTypeRestoreValidation,
			description: "Validates restore functionality",
		},
		{
			name:        "Full Recovery",
			testType:    DRTestTypeFullRecovery,
			description: "Complete backup and restore cycle",
		},
		{
			name:        "Performance Test",
			testType:    DRTestTypePerformance,
			description: "Tests backup/restore performance",
		},
		{
			name:        "Automated Suite",
			testType:    DRTestTypeAutomated,
			description: "Comprehensive automated test suite",
		},
	}

	for _, scenario := range scenarios {
		suite.Run(scenario.name, func() {
			config := &DRTestConfig{
				TestType:        scenario.testType,
				TestEnvironment: "integration_test",
				ValidationLevel: ValidationLevelComprehensive,
			}

			// Configure based on test type
			if scenario.testType == DRTestTypeBackupValidation || 
			   scenario.testType == DRTestTypeFullRecovery || 
			   scenario.testType == DRTestTypeAutomated {
				config.BackupConfig = &BackupConfig{
					Name:             fmt.Sprintf("dr_test_%s", scenario.name),
					Type:             BackupTypeFull,
					IncludeSecrets:   true,
					IncludeAuditLogs: true,
					IncludeConfig:    true,
					Compression:      true,
					Destinations: []DestinationConfig{
						{
							Name: "local",
							Type: DestinationTypeLocal,
							Path: suite.tempDir,
						},
					},
				}
			}

			if scenario.testType == DRTestTypeRestoreValidation || 
			   scenario.testType == DRTestTypeAutomated {
				config.RestoreOptions = &RestoreOptions{
					RestoreSecrets:   true,
					RestoreAuditLogs: true,
					RestoreConfig:    true,
					DryRun:           true,
				}
			}

			if scenario.testType == DRTestTypePerformance {
				config.PerformanceTests = []PerformanceTest{
					{
						Name: "Backup Speed Test",
						Type: PerformanceTestTypeBackupSpeed,
						Parameters: map[string]interface{}{
							"data_size": 1024 * 1024, // 1MB
						},
						ExpectedMetrics: map[string]float64{
							"throughput_mbps": 10.0,
						},
					},
				}
			}

			// Run DR test
			result, err := suite.service.RunDRTest(ctx, config)
			suite.Require().NoError(err)
			suite.Assert().NotEmpty(result.TestID)
			suite.Assert().Equal(scenario.testType, result.TestType)
			suite.Assert().Contains([]DRTestStatus{DRTestStatusCompleted, DRTestStatusPartial}, result.Status)

			// Verify test metrics
			suite.Assert().NotNil(result.Metrics)
			suite.Assert().Greater(result.Metrics.TotalTime, time.Duration(0))

			// Verify test can be retrieved
			retrievedResult, err := suite.service.GetDRTestResult(result.TestID)
			suite.Require().NoError(err)
			suite.Assert().Equal(result.TestID, retrievedResult.TestID)
		})
	}
}

func (suite *BackupIntegrationTestSuite) TestBackupSchedulingAndRetention() {
	ctx := context.Background()

	// Create test data
	suite.createComprehensiveTestData()

	// Start service
	err := suite.service.Start(ctx)
	suite.Require().NoError(err)
	defer suite.service.Stop()

	// Test 1: Add backup schedules
	schedules := []*BackupSchedule{
		{
			ID:       "hourly_incremental",
			Name:     "Hourly Incremental Backup",
			CronExpr: "0 0 * * * *", // Every hour
			Config: &BackupConfig{
				Name:             "hourly_backup",
				Type:             BackupTypeIncremental,
				IncludeSecrets:   true,
				IncludeAuditLogs: false,
				IncludeConfig:    false,
				Compression:      true,
			},
			Enabled: true,
		},
		{
			ID:       "daily_full",
			Name:     "Daily Full Backup",
			CronExpr: "0 0 2 * * *", // Daily at 2 AM
			Config: &BackupConfig{
				Name:             "daily_backup",
				Type:             BackupTypeFull,
				IncludeSecrets:   true,
				IncludeAuditLogs: true,
				IncludeConfig:    true,
				Compression:      true,
			},
			Enabled: true,
		},
	}

	for _, schedule := range schedules {
		err = suite.service.AddBackupSchedule(schedule)
		suite.Require().NoError(err)
	}

	// Test 2: List and verify schedules
	allSchedules := suite.service.ListBackupSchedules()
	suite.Assert().Len(allSchedules, 2)

	// Test 3: Execute schedule immediately
	backupInfo, err := suite.service.ExecuteBackupSchedule("daily_full")
	suite.Require().NoError(err)
	suite.Assert().NotEmpty(backupInfo.ID)

	// Wait for completion
	suite.waitForBackupCompletion(ctx, backupInfo.ID, 30*time.Second)

	// Test 4: Create multiple backups for retention testing
	for i := 0; i < 7; i++ {
		config := &BackupConfig{
			Name:             fmt.Sprintf("retention_test_%d", i),
			Type:             BackupTypeFull,
			IncludeSecrets:   true,
			IncludeAuditLogs: true,
			IncludeConfig:    true,
			Destinations: []DestinationConfig{
				{
					Name: "local",
					Type: DestinationTypeLocal,
					Path: suite.tempDir,
				},
			},
			Retention: RetentionPolicy{
				MaxAge:   1 * time.Hour, // Short retention for testing
				MaxCount: 3,
			},
		}

		info, err := suite.service.CreateBackup(ctx, config)
		suite.Require().NoError(err)
		suite.waitForBackupCompletion(ctx, info.ID, 30*time.Second)

		// Add small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
	}

	// Test 5: Verify retention policy enforcement
	backupsBeforeCleanup, err := suite.service.ListBackups(ctx)
	suite.Require().NoError(err)
	suite.Assert().Greater(len(backupsBeforeCleanup), 3)

	// Run cleanup
	err = suite.service.CleanupExpiredBackups(ctx)
	suite.Require().NoError(err)

	// Verify cleanup results
	backupsAfterCleanup, err := suite.service.ListBackups(ctx)
	suite.Require().NoError(err)
	suite.Assert().LessOrEqual(len(backupsAfterCleanup), len(backupsBeforeCleanup))

	// Test 6: Disable and remove schedules
	err = suite.service.DisableBackupSchedule("hourly_incremental")
	suite.Require().NoError(err)

	err = suite.service.RemoveBackupSchedule("hourly_incremental")
	suite.Require().NoError(err)

	remainingSchedules := suite.service.ListBackupSchedules()
	suite.Assert().Len(remainingSchedules, 1)
}

func (suite *BackupIntegrationTestSuite) TestCorruptionDetectionAndRecovery() {
	ctx := context.Background()

	// Create test data
	suite.createComprehensiveTestData()

	// Start service
	err := suite.service.Start(ctx)
	suite.Require().NoError(err)
	defer suite.service.Stop()

	// Create a backup
	backupConfig := &BackupConfig{
		Name:             "corruption_test_backup",
		Type:             BackupTypeFull,
		IncludeSecrets:   true,
		IncludeAuditLogs: true,
		IncludeConfig:    true,
		Compression:      true,
		Destinations: []DestinationConfig{
			{
				Name: "local",
				Type: DestinationTypeLocal,
				Path: suite.tempDir,
			},
		},
	}

	backupInfo, err := suite.service.CreateBackup(ctx, backupConfig)
	suite.Require().NoError(err)
	suite.waitForBackupCompletion(ctx, backupInfo.ID, 30*time.Second)

	// Verify backup is valid initially
	validation, err := suite.service.ValidateBackup(ctx, backupInfo.ID)
	suite.Require().NoError(err)
	suite.Assert().True(validation.Valid)

	// Test corruption scenarios
	corruptionTests := []struct {
		name           string
		corruptionFunc func(string) error
		expectValid    bool
		expectError    string
	}{
		{
			name: "File Truncation",
			corruptionFunc: func(filePath string) error {
				info, err := os.Stat(filePath)
				if err != nil {
					return err
				}
				return os.Truncate(filePath, info.Size()/2)
			},
			expectValid: false,
			expectError: "file size mismatch",
		},
		{
			name: "Content Corruption",
			corruptionFunc: func(filePath string) error {
				return ioutil.WriteFile(filePath, []byte("corrupted content"), 0644)
			},
			expectValid: false,
			expectError: "checksum mismatch",
		},
		{
			name: "File Deletion",
			corruptionFunc: func(filePath string) error {
				return os.Remove(filePath)
			},
			expectValid: false,
			expectError: "backup file not found",
		},
	}

	for _, test := range corruptionTests {
		suite.Run(test.name, func() {
			// Get fresh backup info
			currentInfo, err := suite.service.GetBackupInfo(ctx, backupInfo.ID)
			suite.Require().NoError(err)

			// Apply corruption
			err = test.corruptionFunc(currentInfo.FilePath)
			suite.Require().NoError(err)

			// Validate corrupted backup
			validation, err := suite.service.ValidateBackup(ctx, backupInfo.ID)
			suite.Require().NoError(err)

			suite.Assert().Equal(test.expectValid, validation.Valid)
			if !test.expectValid {
				found := false
				for _, errMsg := range validation.Errors {
					if strings.Contains(errMsg, test.expectError) {
						found = true
						break
					}
				}
				suite.Assert().True(found, "Expected error '%s' not found in: %v", test.expectError, validation.Errors)
			}

			// Test DR corruption detection
			drConfig := &DRTestConfig{
				TestType:        DRTestTypeCorruptionDetection,
				TestEnvironment: "corruption_test",
				ValidationLevel: ValidationLevelComprehensive,
				CorruptionTests: []CorruptionTest{
					{
						Name:   test.name,
						Type:   CorruptionTypeFileCorruption,
						Target: currentInfo.FilePath,
					},
				},
			}

			drResult, err := suite.service.RunDRTest(ctx, drConfig)
			suite.Require().NoError(err)
			suite.Assert().Equal(DRTestTypeCorruptionDetection, drResult.TestType)
		})

		// Recreate backup for next test
		backupInfo, err = suite.service.CreateBackup(ctx, backupConfig)
		suite.Require().NoError(err)
		suite.waitForBackupCompletion(ctx, backupInfo.ID, 30*time.Second)
	}
}

func (suite *BackupIntegrationTestSuite) TestMultipleDestinations() {
	ctx := context.Background()

	// Create test data
	suite.createComprehensiveTestData()

	// Start service
	err := suite.service.Start(ctx)
	suite.Require().NoError(err)
	defer suite.service.Stop()

	// Create additional destination directories
	localDir1 := filepath.Join(suite.tempDir, "dest1")
	localDir2 := filepath.Join(suite.tempDir, "dest2")
	
	err = os.MkdirAll(localDir1, 0755)
	suite.Require().NoError(err)
	err = os.MkdirAll(localDir2, 0755)
	suite.Require().NoError(err)

	// Register additional destinations
	localDest1 := NewLocalDestination()
	localDest2 := NewLocalDestination()
	suite.service.RegisterDestination("local1", localDest1)
	suite.service.RegisterDestination("local2", localDest2)

	// Create backup with multiple destinations
	backupConfig := &BackupConfig{
		Name:             "multi_destination_backup",
		Type:             BackupTypeFull,
		IncludeSecrets:   true,
		IncludeAuditLogs: true,
		IncludeConfig:    true,
		Compression:      true,
		Destinations: []DestinationConfig{
			{
				Name: "local1",
				Type: DestinationTypeLocal,
				Path: localDir1,
			},
			{
				Name: "local2",
				Type: DestinationTypeLocal,
				Path: localDir2,
			},
		},
	}

	backupInfo, err := suite.service.CreateBackup(ctx, backupConfig)
	suite.Require().NoError(err)
	suite.waitForBackupCompletion(ctx, backupInfo.ID, 30*time.Second)

	// Verify backup was uploaded to both destinations
	files1, err := ioutil.ReadDir(localDir1)
	suite.Require().NoError(err)
	suite.Assert().Greater(len(files1), 0)

	files2, err := ioutil.ReadDir(localDir2)
	suite.Require().NoError(err)
	suite.Assert().Greater(len(files2), 0)

	// Validate backup
	validation, err := suite.service.ValidateBackup(ctx, backupInfo.ID)
	suite.Require().NoError(err)
	suite.Assert().True(validation.Valid)

	// Test restore from backup
	restoreOptions := &RestoreOptions{
		BackupID:         backupInfo.ID,
		RestoreSecrets:   true,
		RestoreAuditLogs: true,
		RestoreConfig:    true,
		DryRun:           true,
	}

	restoreResult, err := suite.service.RestoreBackup(ctx, restoreOptions)
	suite.Require().NoError(err)
	suite.Assert().Equal(RestoreStatusCompleted, restoreResult.Status)
}

// Helper methods

func (suite *BackupIntegrationTestSuite) createComprehensiveTestData() {
	// Create secrets with various attributes
	for i := 0; i < 50; i++ {
		metadata := map[string]string{
			"environment": []string{"development", "staging", "production"}[i%3],
			"application": fmt.Sprintf("app_%d", i%5),
			"owner":       fmt.Sprintf("team_%d", i%3),
		}
		
		tags := []string{"test", "backup"}
		if i%3 == 0 {
			tags = append(tags, "production")
		}
		if i%5 == 0 {
			tags = append(tags, "critical")
		}
		
		metadataJSON, _ := json.Marshal(metadata)
		tagsJSON, _ := json.Marshal(tags)
		
		expiresAt := sql.NullTime{}
		if i%10 == 0 {
			// Some secrets expire in the future
			expiresAt.Valid = true
			expiresAt.Time = time.Now().Add(30 * 24 * time.Hour)
		}
		
		_, err := suite.db.Exec(`
			INSERT INTO secrets (id, name, encrypted_value, key_id, metadata, tags, 
				created_by, expires_at, version, access_count, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, 
			fmt.Sprintf("secret_%d", i),
			fmt.Sprintf("test_secret_%d", i),
			[]byte(fmt.Sprintf("encrypted_data_%d", i)),
			"test_key",
			string(metadataJSON),
			string(tagsJSON),
			fmt.Sprintf("user_%d", i%5),
			expiresAt,
			1,
			int64(i*10),
			"active",
		)
		suite.Require().NoError(err)
	}

	// Create audit events
	eventTypes := []string{"secret_access", "secret_create", "secret_update", "secret_delete", "policy_change"}
	actions := []string{"read", "write", "delete", "rotate"}
	results := []string{"success", "failure", "denied"}

	for i := 0; i < 100; i++ {
		context := map[string]interface{}{
			"request_id": fmt.Sprintf("req_%d", i),
			"session_id": fmt.Sprintf("sess_%d", i%10),
			"user_agent": "vault-agent/1.0",
		}
		contextJSON, _ := json.Marshal(context)

		_, err := suite.db.Exec(`
			INSERT INTO audit_events (id, vault_id, event_type, actor_type, actor_id, 
				resource_type, resource_id, action, result, context, timestamp, ip_address)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			fmt.Sprintf("event_%d", i),
			"test_vault",
			eventTypes[i%len(eventTypes)],
			"user",
			fmt.Sprintf("user_%d", i%5),
			"secret",
			fmt.Sprintf("secret_%d", i%50),
			actions[i%len(actions)],
			results[i%len(results)],
			string(contextJSON),
			time.Now().Add(-time.Duration(i)*time.Minute),
			fmt.Sprintf("192.168.1.%d", (i%254)+1),
		)
		suite.Require().NoError(err)
	}

	// Create cluster nodes
	for i := 0; i < 3; i++ {
		metadata := map[string]interface{}{
			"region": fmt.Sprintf("region-%d", i),
			"zone":   fmt.Sprintf("zone-%d", i),
		}
		metadataJSON, _ := json.Marshal(metadata)

		_, err := suite.db.Exec(`
			INSERT INTO cluster_nodes (id, name, address, status, metadata)
			VALUES (?, ?, ?, ?, ?)
		`,
			fmt.Sprintf("node_%d", i),
			fmt.Sprintf("vault-node-%d", i),
			fmt.Sprintf("10.0.0.%d:8200", i+1),
			"active",
			string(metadataJSON),
		)
		suite.Require().NoError(err)
	}
}

func (suite *BackupIntegrationTestSuite) waitForBackupCompletion(ctx context.Context, backupID string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			suite.Fail("Timeout waiting for backup completion")
			return
		case <-ticker.C:
			info, err := suite.service.GetBackupInfo(ctx, backupID)
			suite.Require().NoError(err)
			
			if info.Status == BackupStatusCompleted {
				return
			} else if info.Status == BackupStatusFailed {
				suite.Fail("Backup failed: %s", info.ErrorMessage)
				return
			}
		}
	}
}

// Mock implementations for integration tests are in backup_test.go

// Test suite runner
func TestBackupIntegrationSuite(t *testing.T) {
	suite.Run(t, new(BackupIntegrationTestSuite))
}