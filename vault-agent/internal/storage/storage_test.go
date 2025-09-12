package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/keyvault/agent/internal/config"
	"github.com/keyvault/agent/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLiteBackend(t *testing.T) {
	testStorageBackend(t, "sqlite", ":memory:")
}

func TestPostgreSQLBackend(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping PostgreSQL integration test in short mode")
	}
	
	// Check if PostgreSQL is available
	connStr := os.Getenv("POSTGRES_TEST_URL")
	if connStr == "" {
		connStr = "postgres://postgres:password@localhost/vault_test?sslmode=disable"
	}
	
	// Test connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	defer db.Close()
	
	if err := db.Ping(); err != nil {
		t.Skipf("PostgreSQL not reachable: %v", err)
	}
	
	testStorageBackend(t, "postgres", connStr)
}

func TestMySQLBackend(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping MySQL integration test in short mode")
	}
	
	// Check if MySQL is available
	connStr := os.Getenv("MYSQL_TEST_URL")
	if connStr == "" {
		connStr = "root:password@tcp(localhost:3306)/vault_test"
	}
	
	// Test connection
	db, err := sql.Open("mysql", connStr)
	if err != nil {
		t.Skipf("MySQL not available: %v", err)
	}
	defer db.Close()
	
	if err := db.Ping(); err != nil {
		t.Skipf("MySQL not reachable: %v", err)
	}
	
	testStorageBackend(t, "mysql", connStr)
}

func testStorageBackend(t *testing.T, dbType, connStr string) {
	ctx := context.Background()
	
	// Create test configuration
	cfg := &config.DatabaseConfig{
		Type:             dbType,
		ConnectionString: connStr,
		MaxOpenConns:     5,
		MaxIdleConns:     2,
		ConnMaxLifetime:  5 * time.Minute,
	}
	
	// Create crypto service for testing
	cryptoService, err := createTestCryptoService()
	require.NoError(t, err)
	
	// Create storage instance
	storage, err := NewStorage(cfg, cryptoService)
	require.NoError(t, err)
	defer storage.Close()
	
	// Test basic operations
	t.Run("CreateSecret", func(t *testing.T) {
		secret := &Secret{
			ID:       "test-secret-1",
			Name:     "test-secret",
			Value:    "secret-value",
			Metadata: map[string]string{"env": "test"},
			Tags:     []string{"test", "demo"},
			CreatedBy: "test-user",
		}
		
		err := storage.CreateSecret(ctx, secret)
		assert.NoError(t, err)
	})
	
	t.Run("GetSecret", func(t *testing.T) {
		secret, err := storage.GetSecret(ctx, "test-secret-1")
		require.NoError(t, err)
		
		assert.Equal(t, "test-secret-1", secret.ID)
		assert.Equal(t, "test-secret", secret.Name)
		assert.Equal(t, "secret-value", secret.Value)
		assert.Equal(t, "test", secret.Metadata["env"])
		assert.Contains(t, secret.Tags, "test")
		assert.Equal(t, "test-user", secret.CreatedBy)
	})
	
	t.Run("UpdateSecret", func(t *testing.T) {
		secret := &Secret{
			Name:     "updated-secret",
			Value:    "updated-value",
			Metadata: map[string]string{"env": "production"},
			Tags:     []string{"updated"},
		}
		
		err := storage.UpdateSecret(ctx, "test-secret-1", secret)
		assert.NoError(t, err)
		
		// Verify update
		updated, err := storage.GetSecret(ctx, "test-secret-1")
		require.NoError(t, err)
		assert.Equal(t, "updated-secret", updated.Name)
		assert.Equal(t, "updated-value", updated.Value)
		assert.Equal(t, "production", updated.Metadata["env"])
	})
	
	t.Run("ListSecrets", func(t *testing.T) {
		// Create additional secrets
		for i := 2; i <= 5; i++ {
			secret := &Secret{
				ID:       fmt.Sprintf("test-secret-%d", i),
				Name:     fmt.Sprintf("secret-%d", i),
				Value:    fmt.Sprintf("value-%d", i),
				CreatedBy: "test-user",
			}
			err := storage.CreateSecret(ctx, secret)
			require.NoError(t, err)
		}
		
		// List all secrets
		secrets, err := storage.ListSecrets(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(secrets), 4)
		
		// Test filtering
		filter := &SecretFilter{
			NamePattern: "secret-2",
			Limit:       10,
		}
		filtered, err := storage.ListSecrets(ctx, filter)
		require.NoError(t, err)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "secret-2", filtered[0].Name)
	})
	
	t.Run("DeleteSecret", func(t *testing.T) {
		err := storage.DeleteSecret(ctx, "test-secret-2")
		assert.NoError(t, err)
		
		// Verify deletion
		_, err = storage.GetSecret(ctx, "test-secret-2")
		assert.Error(t, err)
	})
	
	t.Run("HealthCheck", func(t *testing.T) {
		err := storage.HealthCheck(ctx)
		assert.NoError(t, err)
	})
}

func TestMigrationManager(t *testing.T) {
	ctx := context.Background()
	
	// Create in-memory SQLite database for testing
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()
	
	// Create migration manager
	mm := NewMigrationManager(db, "sqlite")
	
	// Initialize migration tracking
	err = mm.Initialize(ctx)
	require.NoError(t, err)
	
	// Register test migrations
	mm.RegisterMigration(1, "Create test table", `
		CREATE TABLE test_table (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL
		);
	`, `
		DROP TABLE test_table;
	`)
	
	mm.RegisterMigration(2, "Add column to test table", `
		ALTER TABLE test_table ADD COLUMN description TEXT;
	`, `
		-- SQLite doesn't support DROP COLUMN easily
	`)
	
	t.Run("GetCurrentVersion", func(t *testing.T) {
		version, err := mm.GetCurrentVersion(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, version)
	})
	
	t.Run("MigrateToLatest", func(t *testing.T) {
		err := mm.MigrateToLatest(ctx)
		require.NoError(t, err)
		
		// Check current version
		version, err := mm.GetCurrentVersion(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, version)
		
		// Verify table exists
		var count int
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test_table'").Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})
	
	t.Run("GetMigrationStatus", func(t *testing.T) {
		status, err := mm.GetMigrationStatus(ctx)
		require.NoError(t, err)
		assert.Len(t, status, 2)
		
		for _, migration := range status {
			assert.True(t, migration.Applied)
			assert.NotNil(t, migration.AppliedAt)
		}
	})
	
	t.Run("Rollback", func(t *testing.T) {
		err := mm.Rollback(ctx, 1)
		require.NoError(t, err)
		
		// Check current version
		version, err := mm.GetCurrentVersion(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, version)
	})
}

func TestClusterManager(t *testing.T) {
	ctx := context.Background()
	
	// Create in-memory SQLite database for testing
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()
	
	// Create test storage
	cfg := &config.DatabaseConfig{
		Type:             "sqlite",
		ConnectionString: ":memory:",
		MaxOpenConns:     5,
		MaxIdleConns:     2,
	}
	
	cryptoService, err := createTestCryptoService()
	require.NoError(t, err)
	
	storage, err := NewStorage(cfg, cryptoService)
	require.NoError(t, err)
	defer storage.Close()
	
	// Create cluster configuration
	clusterConfig := &ClusterConfig{
		NodeID:              "test-node-1",
		LeaderElectionTTL:   30 * time.Second,
		HeartbeatInterval:   5 * time.Second,
		HealthCheckInterval: 10 * time.Second,
		FailoverTimeout:     60 * time.Second,
		SessionAffinity:     true,
		LoadBalancing: LoadBalancingConfig{
			Strategy:    "round_robin",
			HealthCheck: true,
		},
	}
	
	// Create cluster manager
	cm, err := NewClusterManager(storage, clusterConfig, db)
	require.NoError(t, err)
	
	t.Run("Start", func(t *testing.T) {
		err := cm.Start(ctx)
		assert.NoError(t, err)
		
		// Give it a moment to initialize
		time.Sleep(100 * time.Millisecond)
		
		// Check if node is registered
		nodes, err := cm.GetActiveNodes(ctx)
		require.NoError(t, err)
		assert.Len(t, nodes, 1)
		assert.Equal(t, "test-node-1", nodes[0].ID)
	})
	
	t.Run("LeaderElection", func(t *testing.T) {
		// Initially should become leader (only node)
		// Wait for leader election to complete
		for i := 0; i < 10; i++ {
			time.Sleep(100 * time.Millisecond)
			if cm.IsLeader() {
				break
			}
		}
		assert.True(t, cm.IsLeader())
		assert.Equal(t, "test-node-1", cm.GetLeaderID())
	})
	
	t.Run("SelectHealthyNode", func(t *testing.T) {
		node, err := cm.SelectHealthyNode(ctx, "test-session")
		require.NoError(t, err)
		assert.Equal(t, "test-node-1", node.ID)
	})
	
	t.Run("Stop", func(t *testing.T) {
		err := cm.Stop(ctx)
		assert.NoError(t, err)
	})
}

func TestBackupManager(t *testing.T) {
	ctx := context.Background()
	
	// Create temporary directory for backups
	tmpDir, err := os.MkdirTemp("", "vault-backup-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Create test storage
	cfg := &config.DatabaseConfig{
		Type:             "sqlite",
		ConnectionString: ":memory:",
		MaxOpenConns:     5,
		MaxIdleConns:     2,
	}
	
	cryptoService, err := createTestCryptoService()
	require.NoError(t, err)
	
	storage, err := NewStorage(cfg, cryptoService)
	require.NoError(t, err)
	defer storage.Close()
	
	// Create some test data
	secret := &Secret{
		ID:       "backup-test-secret",
		Name:     "backup-secret",
		Value:    "backup-value",
		CreatedBy: "test-user",
	}
	err = storage.CreateSecret(ctx, secret)
	require.NoError(t, err)
	
	// Create backup manager
	bm := NewBackupManager(storage, storage.backend.(*SQLiteBackend).db, storage.encryptor, storage.keyID)
	
	t.Run("CreateBackup", func(t *testing.T) {
		config := &BackupConfig{
			Name:           "test-backup",
			Type:           BackupTypeFull,
			Destination:    tmpDir,
			IncludeSecrets: true,
			Compression:    true,
			Retention: RetentionPolicy{
				MaxAge: 24 * time.Hour,
			},
		}
		
		backupInfo, err := bm.CreateBackup(ctx, config)
		require.NoError(t, err)
		assert.NotEmpty(t, backupInfo.ID)
		assert.Equal(t, "test-backup", backupInfo.Name)
		
		// Wait for backup to complete
		time.Sleep(1 * time.Second)
		
		// Check backup status
		info, err := bm.GetBackupInfo(ctx, backupInfo.ID)
		require.NoError(t, err)
		assert.Equal(t, BackupStatusCompleted, info.Status)
	})
	
	t.Run("ListBackups", func(t *testing.T) {
		backups, err := bm.ListBackups(ctx)
		require.NoError(t, err)
		assert.Len(t, backups, 1)
	})
	
	t.Run("ValidateBackup", func(t *testing.T) {
		backups, err := bm.ListBackups(ctx)
		require.NoError(t, err)
		require.Len(t, backups, 1)
		
		validation, err := bm.ValidateBackup(ctx, backups[0].ID)
		require.NoError(t, err)
		assert.True(t, validation.Valid)
		assert.True(t, validation.ChecksumMatch)
	})
}

func TestPerformanceMonitor(t *testing.T) {
	ctx := context.Background()
	
	// Create test database
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()
	
	// Create performance monitor
	pm := NewPerformanceMonitor(db, "sqlite")
	
	t.Run("Start", func(t *testing.T) {
		err := pm.Start(ctx)
		assert.NoError(t, err)
	})
	
	t.Run("TrackOperation", func(t *testing.T) {
		pm.TrackOperation("create_secret", 100*time.Millisecond, nil)
		pm.TrackOperation("get_secret", 50*time.Millisecond, nil)
		pm.TrackOperation("update_secret", 200*time.Millisecond, fmt.Errorf("test error"))
	})
	
	t.Run("TrackQuery", func(t *testing.T) {
		pm.TrackQuery("SELECT * FROM secrets WHERE id = ?", "secrets", 25*time.Millisecond, nil)
		pm.TrackQuery("INSERT INTO secrets VALUES (?)", "secrets", 75*time.Millisecond, nil)
	})
	
	t.Run("GetPerformanceReport", func(t *testing.T) {
		report, err := pm.GetPerformanceReport(ctx)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.NotZero(t, report.GeneratedAt)
	})
	
	t.Run("OptimizeConnectionPool", func(t *testing.T) {
		err := pm.OptimizeConnectionPool()
		assert.NoError(t, err)
	})
	
	t.Run("Stop", func(t *testing.T) {
		err := pm.Stop()
		assert.NoError(t, err)
	})
}

// Helper function to create a test crypto service
func createTestCryptoService() (*crypto.CryptoService, error) {
	config := &crypto.KeyManagerConfig{
		Type:     crypto.KeyTypeFile,
		FilePath: ":memory:",
	}
	
	return crypto.NewCryptoService(config)
}

// Benchmark tests
func BenchmarkSQLiteOperations(b *testing.B) {
	benchmarkStorageOperations(b, "sqlite", ":memory:")
}

func benchmarkStorageOperations(b *testing.B, dbType, connStr string) {
	ctx := context.Background()
	
	cfg := &config.DatabaseConfig{
		Type:             dbType,
		ConnectionString: connStr,
		MaxOpenConns:     25,
		MaxIdleConns:     5,
	}
	
	cryptoService, err := createTestCryptoService()
	require.NoError(b, err)
	
	storage, err := NewStorage(cfg, cryptoService)
	require.NoError(b, err)
	defer storage.Close()
	
	b.Run("CreateSecret", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			secret := &Secret{
				ID:       fmt.Sprintf("bench-secret-%d", i),
				Name:     fmt.Sprintf("secret-%d", i),
				Value:    "benchmark-value",
				CreatedBy: "benchmark",
			}
			storage.CreateSecret(ctx, secret)
		}
	})
	
	b.Run("GetSecret", func(b *testing.B) {
		// Create a secret first
		secret := &Secret{
			ID:       "bench-get-secret",
			Name:     "get-secret",
			Value:    "get-value",
			CreatedBy: "benchmark",
		}
		storage.CreateSecret(ctx, secret)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			storage.GetSecret(ctx, "bench-get-secret")
		}
	})
	
	b.Run("ListSecrets", func(b *testing.B) {
		// Create some secrets first
		for i := 0; i < 100; i++ {
			secret := &Secret{
				ID:       fmt.Sprintf("list-secret-%d", i),
				Name:     fmt.Sprintf("list-%d", i),
				Value:    "list-value",
				CreatedBy: "benchmark",
			}
			storage.CreateSecret(ctx, secret)
		}
		
		filter := &SecretFilter{Limit: 50}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			storage.ListSecrets(ctx, filter)
		}
	})
}