package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	_ "github.com/lib/pq"
	"github.com/lib/pq"
	_ "github.com/go-sql-driver/mysql"
	
	"github.com/keyvault/agent/internal/config"
	"github.com/keyvault/agent/internal/crypto"
)

// StorageBackend defines the interface for storage backends
type StorageBackend interface {
	// Secret operations
	CreateSecret(ctx context.Context, secret *Secret) error
	GetSecret(ctx context.Context, id string) (*Secret, error)
	GetSecretByName(ctx context.Context, name string) (*Secret, error)
	UpdateSecret(ctx context.Context, id string, secret *Secret) error
	DeleteSecret(ctx context.Context, id string) error
	ListSecrets(ctx context.Context, filter *SecretFilter) ([]*Secret, error)
	
	// Health and maintenance
	HealthCheck(ctx context.Context) error
	Close() error
	
	// Backup operations
	Backup(ctx context.Context, destination string) error
	Restore(ctx context.Context, source string) error
}

// Secret represents a stored secret with metadata
type Secret struct {
	ID          string            `json:"id" db:"id"`
	Name        string            `json:"name" db:"name"`
	Value       string            `json:"value,omitempty" db:"-"` // Never stored directly
	EncryptedValue []byte         `json:"-" db:"encrypted_value"`
	KeyID       string            `json:"key_id" db:"key_id"`
	Metadata    map[string]string `json:"metadata" db:"metadata"`
	Tags        []string          `json:"tags" db:"tags"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty" db:"expires_at"`
	RotationDue *time.Time        `json:"rotation_due,omitempty" db:"rotation_due"`
	Version     int               `json:"version" db:"version"`
	CreatedBy   string            `json:"created_by" db:"created_by"`
	AccessCount int64             `json:"access_count" db:"access_count"`
	LastAccessed *time.Time       `json:"last_accessed,omitempty" db:"last_accessed"`
	Status      SecretStatus      `json:"status" db:"status"`
}

// SecretStatus represents the lifecycle status of a secret
type SecretStatus string

const (
	SecretStatusActive     SecretStatus = "active"
	SecretStatusDeprecated SecretStatus = "deprecated"
	SecretStatusDeleted    SecretStatus = "deleted"
	SecretStatusExpired    SecretStatus = "expired"
)

// SecretFilter contains filtering options for listing secrets
type SecretFilter struct {
	NamePattern  string            `json:"name_pattern,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Status       SecretStatus      `json:"status,omitempty"`
	CreatedAfter *time.Time        `json:"created_after,omitempty"`
	CreatedBy    string            `json:"created_by,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Limit        int               `json:"limit,omitempty"`
	Offset       int               `json:"offset,omitempty"`
}

// Storage provides encrypted storage with pluggable backends
type Storage struct {
	backend           StorageBackend
	encryptor         crypto.Encryptor
	keyID             string
	migrationManager  *MigrationManager
	clusterManager    *ClusterManager
	backupManager     *BackupManager
	performanceMonitor *PerformanceMonitor
	db                *sql.DB
}

// NewStorage creates a new storage instance with the specified backend
func NewStorage(cfg *config.DatabaseConfig, cryptoService *crypto.CryptoService) (*Storage, error) {
	// Create backend based on configuration
	backend, err := createBackend(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}

	// Get database connection for additional components
	var db *sql.DB
	switch b := backend.(type) {
	case *SQLiteBackend:
		db = b.db
	case *PostgreSQLBackend:
		db = b.db
	case *MySQLBackend:
		db = b.db
	default:
		return nil, fmt.Errorf("unsupported backend type")
	}

	// Use default key for encryption
	keyID := "default"
	
	// Ensure default key exists
	_, err = cryptoService.KeyManager().GetKey(context.Background(), keyID)
	if err != nil {
		// Generate default key if it doesn't exist
		_, err = cryptoService.KeyManager().GenerateKey(context.Background(), keyID, crypto.AlgorithmAES256GCM)
		if err != nil {
			return nil, fmt.Errorf("failed to generate default encryption key: %w", err)
		}
	}

	storage := &Storage{
		backend:   backend,
		encryptor: cryptoService.Encryptor(),
		keyID:     keyID,
		db:        db,
	}

	// Initialize migration manager
	storage.migrationManager = NewMigrationManager(db, cfg.Type)
	storage.migrationManager.RegisterCoreMigrations()

	// Initialize migration tracking
	if err := storage.migrationManager.Initialize(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize migrations: %w", err)
	}

	// Run migrations
	if err := storage.migrationManager.MigrateToLatest(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// Initialize backup manager with logger
	logger := log.New(os.Stdout, "backup: ", log.LstdFlags)
	storage.backupManager = NewBackupManager(storage, cryptoService.Encryptor(), keyID, logger)

	// Initialize performance monitor
	storage.performanceMonitor = NewPerformanceMonitor(db, cfg.Type)

	return storage, nil
}

// createBackend creates the appropriate storage backend
func createBackend(cfg *config.DatabaseConfig) (StorageBackend, error) {
	switch cfg.Type {
	case "sqlite":
		return NewSQLiteBackend(cfg)
	case "postgres":
		return NewPostgreSQLBackend(cfg)
	case "mysql":
		return NewMySQLBackend(cfg)
	default:
		return nil, fmt.Errorf("unsupported storage backend: %s", cfg.Type)
	}
}

// CreateSecret creates a new secret
func (s *Storage) CreateSecret(ctx context.Context, secret *Secret) error {
	// Encrypt the secret value
	encryptedData, err := s.encryptor.EncryptString(ctx, s.keyID, secret.Value)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Serialize encrypted data
	encryptedBytes, err := json.Marshal(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to serialize encrypted data: %w", err)
	}

	// Set encryption metadata
	secret.EncryptedValue = encryptedBytes
	secret.KeyID = s.keyID
	secret.Value = "" // Clear plaintext value

	// Set timestamps
	now := time.Now().UTC()
	secret.CreatedAt = now
	secret.UpdatedAt = now
	secret.Version = 1
	secret.Status = SecretStatusActive

	return s.backend.CreateSecret(ctx, secret)
}

// GetSecret retrieves and decrypts a secret
func (s *Storage) GetSecret(ctx context.Context, id string) (*Secret, error) {
	secret, err := s.backend.GetSecret(ctx, id)
	if err != nil {
		return nil, err
	}

	// Decrypt the secret value
	var encryptedData crypto.EncryptedData
	if err := json.Unmarshal(secret.EncryptedValue, &encryptedData); err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted data: %w", err)
	}

	plaintext, err := s.encryptor.DecryptString(ctx, &encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	secret.Value = plaintext
	secret.EncryptedValue = nil // Don't return encrypted data

	// Update access tracking
	go s.updateAccessTracking(ctx, id)

	return secret, nil
}

// GetSecretByName retrieves and decrypts a secret by name
func (s *Storage) GetSecretByName(ctx context.Context, name string) (*Secret, error) {
	secret, err := s.backend.GetSecretByName(ctx, name)
	if err != nil {
		return nil, err
	}

	// Decrypt the secret value
	var encryptedData crypto.EncryptedData
	if err := json.Unmarshal(secret.EncryptedValue, &encryptedData); err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted data: %w", err)
	}

	plaintext, err := s.encryptor.DecryptString(ctx, &encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	secret.Value = plaintext
	secret.EncryptedValue = nil // Don't return encrypted data

	// Update access tracking
	go s.updateAccessTracking(ctx, secret.ID)

	return secret, nil
}

// UpdateSecret updates an existing secret
func (s *Storage) UpdateSecret(ctx context.Context, id string, secret *Secret) error {
	// Encrypt the new value if provided
	if secret.Value != "" {
		encryptedData, err := s.encryptor.EncryptString(ctx, s.keyID, secret.Value)
		if err != nil {
			return fmt.Errorf("failed to encrypt secret: %w", err)
		}

		encryptedBytes, err := json.Marshal(encryptedData)
		if err != nil {
			return fmt.Errorf("failed to serialize encrypted data: %w", err)
		}

		secret.EncryptedValue = encryptedBytes
		secret.KeyID = s.keyID
	}

	// Update timestamp and version
	secret.UpdatedAt = time.Now().UTC()
	secret.Value = "" // Clear plaintext value

	return s.backend.UpdateSecret(ctx, id, secret)
}

// DeleteSecret deletes a secret
func (s *Storage) DeleteSecret(ctx context.Context, id string) error {
	return s.backend.DeleteSecret(ctx, id)
}

// ListSecrets lists secrets with optional filtering
func (s *Storage) ListSecrets(ctx context.Context, filter *SecretFilter) ([]*Secret, error) {
	secrets, err := s.backend.ListSecrets(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Don't decrypt values for list operations (metadata only)
	for _, secret := range secrets {
		secret.EncryptedValue = nil
		secret.Value = ""
	}

	return secrets, nil
}

// ListAllSecrets lists all secrets (simplified version for control plane)
func (s *Storage) ListAllSecrets() ([]*Secret, error) {
	ctx := context.Background()
	return s.ListSecrets(ctx, nil)
}

// GetType returns the storage backend type
func (s *Storage) GetType() string {
	// Determine type based on backend
	switch s.backend.(type) {
	case *SQLiteBackend:
		return "sqlite"
	case *PostgreSQLBackend:
		return "postgresql"
	case *MySQLBackend:
		return "mysql"
	default:
		return "unknown"
	}
}

// GetMetrics returns storage metrics for monitoring
func (s *Storage) GetMetrics() (map[string]interface{}, error) {
	ctx := context.Background()
	
	// Get basic metrics
	secrets, err := s.backend.ListSecrets(ctx, nil)
	if err != nil {
		return nil, err
	}

	metrics := map[string]interface{}{
		"total_secrets": len(secrets),
		"storage_type":  s.GetType(),
		"timestamp":     time.Now(),
	}

	// Add expiration metrics
	var expiring, expired int
	now := time.Now()
	for _, secret := range secrets {
		if secret.ExpiresAt != nil {
			if secret.ExpiresAt.Before(now) {
				expired++
			} else if secret.ExpiresAt.Before(now.AddDate(0, 0, 30)) {
				expiring++
			}
		}
	}

	metrics["expired_secrets"] = expired
	metrics["expiring_secrets"] = expiring

	return metrics, nil
}

// updateAccessTracking updates access count and last accessed time
func (s *Storage) updateAccessTracking(ctx context.Context, id string) {
	// This would typically be done asynchronously to avoid impacting read performance
	// Implementation would update access_count and last_accessed fields
}

// HealthCheck checks the health of the storage backend
func (s *Storage) HealthCheck(ctx context.Context) error {
	return s.backend.HealthCheck(ctx)
}

// Close closes the storage backend
func (s *Storage) Close() error {
	if s.performanceMonitor != nil {
		s.performanceMonitor.Stop()
	}
	if s.clusterManager != nil {
		s.clusterManager.Stop(context.Background())
	}
	return s.backend.Close()
}

// InitializeCluster initializes clustering support
func (s *Storage) InitializeCluster(config *ClusterConfig) error {
	if s.clusterManager != nil {
		return fmt.Errorf("cluster manager already initialized")
	}

	cm, err := NewClusterManager(s, config, s.db)
	if err != nil {
		return fmt.Errorf("failed to create cluster manager: %w", err)
	}

	s.clusterManager = cm
	return nil
}

// StartCluster starts the cluster manager
func (s *Storage) StartCluster(ctx context.Context) error {
	if s.clusterManager == nil {
		return fmt.Errorf("cluster manager not initialized")
	}
	return s.clusterManager.Start(ctx)
}

// StartPerformanceMonitoring starts performance monitoring
func (s *Storage) StartPerformanceMonitoring(ctx context.Context) error {
	if s.performanceMonitor == nil {
		return fmt.Errorf("performance monitor not initialized")
	}
	return s.performanceMonitor.Start(ctx)
}

// GetMigrationManager returns the migration manager
func (s *Storage) GetMigrationManager() *MigrationManager {
	return s.migrationManager
}

// GetClusterManager returns the cluster manager
func (s *Storage) GetClusterManager() *ClusterManager {
	return s.clusterManager
}

// GetBackupManager returns the backup manager
func (s *Storage) GetBackupManager() *BackupManager {
	return s.backupManager
}

// GetPerformanceMonitor returns the performance monitor
func (s *Storage) GetPerformanceMonitor() *PerformanceMonitor {
	return s.performanceMonitor
}

// Backup creates a backup of the storage
func (s *Storage) Backup(ctx context.Context, destination string) error {
	return s.backend.Backup(ctx, destination)
}

// Restore restores from a backup
func (s *Storage) Restore(ctx context.Context, source string) error {
	return s.backend.Restore(ctx, source)
}

// SQLiteBackend implements StorageBackend for SQLite
type SQLiteBackend struct {
	db *sql.DB
}

// NewSQLiteBackend creates a new SQLite storage backend
func NewSQLiteBackend(cfg *config.DatabaseConfig) (*SQLiteBackend, error) {
	db, err := sql.Open("sqlite3", cfg.ConnectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	backend := &SQLiteBackend{db: db}

	// Run migrations
	if err := backend.migrate(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return backend, nil
}

// migrate runs database migrations for SQLite
func (b *SQLiteBackend) migrate() error {
	// Migration is now handled by MigrationManager
	return nil
}

// CreateSecret implements StorageBackend.CreateSecret for SQLite
func (b *SQLiteBackend) CreateSecret(ctx context.Context, secret *Secret) error {
	metadataJSON, _ := json.Marshal(secret.Metadata)
	tagsJSON, _ := json.Marshal(secret.Tags)
	
	query := `
	INSERT INTO secrets (id, name, encrypted_value, key_id, metadata, tags, 
		created_at, updated_at, expires_at, rotation_due, version, created_by, status)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	_, err := b.db.ExecContext(ctx, query, 
		secret.ID, secret.Name, secret.EncryptedValue, secret.KeyID,
		string(metadataJSON), string(tagsJSON),
		secret.CreatedAt, secret.UpdatedAt, secret.ExpiresAt, secret.RotationDue,
		secret.Version, secret.CreatedBy, secret.Status)
	
	return err
}

// GetSecret implements StorageBackend.GetSecret for SQLite
func (b *SQLiteBackend) GetSecret(ctx context.Context, id string) (*Secret, error) {
	query := `
	SELECT id, name, encrypted_value, key_id, metadata, tags,
		created_at, updated_at, expires_at, rotation_due, version,
		created_by, access_count, last_accessed, status
	FROM secrets WHERE id = ?
	`
	
	var secret Secret
	var metadataJSON, tagsJSON string
	
	err := b.db.QueryRowContext(ctx, query, id).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedValue, &secret.KeyID,
		&metadataJSON, &tagsJSON, &secret.CreatedAt, &secret.UpdatedAt,
		&secret.ExpiresAt, &secret.RotationDue, &secret.Version,
		&secret.CreatedBy, &secret.AccessCount, &secret.LastAccessed, &secret.Status,
	)
	if err != nil {
		return nil, err
	}
	
	json.Unmarshal([]byte(metadataJSON), &secret.Metadata)
	json.Unmarshal([]byte(tagsJSON), &secret.Tags)
	
	return &secret, nil
}

// GetSecretByName implements StorageBackend.GetSecretByName for SQLite
func (b *SQLiteBackend) GetSecretByName(ctx context.Context, name string) (*Secret, error) {
	query := `
	SELECT id, name, encrypted_value, key_id, metadata, tags,
		created_at, updated_at, expires_at, rotation_due, version,
		created_by, access_count, last_accessed, status
	FROM secrets WHERE name = ?
	`
	
	var secret Secret
	var metadataJSON, tagsJSON string
	
	err := b.db.QueryRowContext(ctx, query, name).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedValue, &secret.KeyID,
		&metadataJSON, &tagsJSON, &secret.CreatedAt, &secret.UpdatedAt,
		&secret.ExpiresAt, &secret.RotationDue, &secret.Version,
		&secret.CreatedBy, &secret.AccessCount, &secret.LastAccessed, &secret.Status,
	)
	if err != nil {
		return nil, err
	}
	
	json.Unmarshal([]byte(metadataJSON), &secret.Metadata)
	json.Unmarshal([]byte(tagsJSON), &secret.Tags)
	
	return &secret, nil
}

// UpdateSecret implements StorageBackend.UpdateSecret for SQLite
func (b *SQLiteBackend) UpdateSecret(ctx context.Context, id string, secret *Secret) error {
	metadataJSON, _ := json.Marshal(secret.Metadata)
	tagsJSON, _ := json.Marshal(secret.Tags)
	
	query := `
	UPDATE secrets 
	SET name = ?, encrypted_value = ?, key_id = ?, metadata = ?, tags = ?,
		updated_at = ?, expires_at = ?, rotation_due = ?, version = version + 1,
		status = ?
	WHERE id = ?
	`
	
	_, err := b.db.ExecContext(ctx, query,
		secret.Name, secret.EncryptedValue, secret.KeyID,
		string(metadataJSON), string(tagsJSON), secret.UpdatedAt,
		secret.ExpiresAt, secret.RotationDue, secret.Status, id)
	
	return err
}

// DeleteSecret implements StorageBackend.DeleteSecret for SQLite
func (b *SQLiteBackend) DeleteSecret(ctx context.Context, id string) error {
	query := `DELETE FROM secrets WHERE id = ?`
	_, err := b.db.ExecContext(ctx, query, id)
	return err
}

// ListSecrets implements StorageBackend.ListSecrets for SQLite
func (b *SQLiteBackend) ListSecrets(ctx context.Context, filter *SecretFilter) ([]*Secret, error) {
	query := `
	SELECT id, name, key_id, metadata, tags, created_at, updated_at,
		expires_at, rotation_due, version, created_by, access_count,
		last_accessed, status
	FROM secrets
	WHERE 1=1
	`
	args := []interface{}{}
	
	// Apply filters
	if filter != nil {
		if filter.Status != "" {
			query += " AND status = ?"
			args = append(args, filter.Status)
		}
		if filter.NamePattern != "" {
			query += " AND name LIKE ?"
			args = append(args, "%"+filter.NamePattern+"%")
		}
		if filter.CreatedBy != "" {
			query += " AND created_by = ?"
			args = append(args, filter.CreatedBy)
		}
		if filter.CreatedAfter != nil {
			query += " AND created_at > ?"
			args = append(args, filter.CreatedAfter)
		}
	}
	
	query += " ORDER BY created_at DESC"
	
	// Apply limit and offset
	if filter != nil {
		if filter.Limit > 0 {
			query += " LIMIT ?"
			args = append(args, filter.Limit)
		}
		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}
	
	rows, err := b.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var secrets []*Secret
	for rows.Next() {
		var secret Secret
		var metadataJSON, tagsJSON string
		
		err := rows.Scan(
			&secret.ID, &secret.Name, &secret.KeyID, &metadataJSON, &tagsJSON,
			&secret.CreatedAt, &secret.UpdatedAt, &secret.ExpiresAt,
			&secret.RotationDue, &secret.Version, &secret.CreatedBy,
			&secret.AccessCount, &secret.LastAccessed, &secret.Status,
		)
		if err != nil {
			continue
		}
		
		json.Unmarshal([]byte(metadataJSON), &secret.Metadata)
		json.Unmarshal([]byte(tagsJSON), &secret.Tags)
		
		secrets = append(secrets, &secret)
	}
	
	return secrets, nil
}

// HealthCheck implements StorageBackend.HealthCheck for SQLite
func (b *SQLiteBackend) HealthCheck(ctx context.Context) error {
	_, err := b.db.ExecContext(ctx, "SELECT 1")
	return err
}

// Close implements StorageBackend.Close for SQLite
func (b *SQLiteBackend) Close() error {
	return b.db.Close()
}

// Backup implements StorageBackend.Backup for SQLite
func (b *SQLiteBackend) Backup(ctx context.Context, destination string) error {
	// SQLite backup implementation would use VACUUM INTO or file copy
	return fmt.Errorf("backup not implemented for SQLite backend")
}

// Restore implements StorageBackend.Restore for SQLite
func (b *SQLiteBackend) Restore(ctx context.Context, source string) error {
	// SQLite restore implementation would replace the database file
	return fmt.Errorf("restore not implemented for SQLite backend")
}

// PostgreSQLBackend implements StorageBackend for PostgreSQL
type PostgreSQLBackend struct {
	db *sql.DB
}

// NewPostgreSQLBackend creates a new PostgreSQL storage backend
func NewPostgreSQLBackend(cfg *config.DatabaseConfig) (*PostgreSQLBackend, error) {
	connectionString := cfg.ConnectionString
	if connectionString == "" {
		connectionString = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Database, cfg.SSLMode)
	}
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open PostgreSQL database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	backend := &PostgreSQLBackend{db: db}

	// Run migrations
	if err := backend.migrate(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return backend, nil
}

// migrate runs database migrations for PostgreSQL
func (b *PostgreSQLBackend) migrate() error {
	// Migration is now handled by MigrationManager
	return nil
}

// CreateSecret implements StorageBackend.CreateSecret for PostgreSQL
func (b *PostgreSQLBackend) CreateSecret(ctx context.Context, secret *Secret) error {
	metadataJSON, _ := json.Marshal(secret.Metadata)
	
	query := `
	INSERT INTO secrets (id, name, encrypted_value, key_id, metadata, tags, 
		created_at, updated_at, expires_at, rotation_due, version, created_by, status)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	
	_, err := b.db.ExecContext(ctx, query, 
		secret.ID, secret.Name, secret.EncryptedValue, secret.KeyID,
		string(metadataJSON), pq.Array(secret.Tags),
		secret.CreatedAt, secret.UpdatedAt, secret.ExpiresAt, secret.RotationDue,
		secret.Version, secret.CreatedBy, secret.Status)
	
	return err
}

// GetSecret implements StorageBackend.GetSecret for PostgreSQL
func (b *PostgreSQLBackend) GetSecret(ctx context.Context, id string) (*Secret, error) {
	query := `
	SELECT id, name, encrypted_value, key_id, metadata, tags,
		created_at, updated_at, expires_at, rotation_due, version,
		created_by, access_count, last_accessed, status
	FROM secrets WHERE id = $1
	`
	
	var secret Secret
	var metadataJSON string
	
	err := b.db.QueryRowContext(ctx, query, id).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedValue, &secret.KeyID,
		&metadataJSON, pq.Array(&secret.Tags), &secret.CreatedAt, &secret.UpdatedAt,
		&secret.ExpiresAt, &secret.RotationDue, &secret.Version,
		&secret.CreatedBy, &secret.AccessCount, &secret.LastAccessed, &secret.Status,
	)
	if err != nil {
		return nil, err
	}
	
	json.Unmarshal([]byte(metadataJSON), &secret.Metadata)
	
	return &secret, nil
}

// GetSecretByName implements StorageBackend.GetSecretByName for PostgreSQL
func (b *PostgreSQLBackend) GetSecretByName(ctx context.Context, name string) (*Secret, error) {
	query := `
	SELECT id, name, encrypted_value, key_id, metadata, tags,
		created_at, updated_at, expires_at, rotation_due, version,
		created_by, access_count, last_accessed, status
	FROM secrets WHERE name = $1
	`
	
	var secret Secret
	var metadataJSON string
	
	err := b.db.QueryRowContext(ctx, query, name).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedValue, &secret.KeyID,
		&metadataJSON, pq.Array(&secret.Tags), &secret.CreatedAt, &secret.UpdatedAt,
		&secret.ExpiresAt, &secret.RotationDue, &secret.Version,
		&secret.CreatedBy, &secret.AccessCount, &secret.LastAccessed, &secret.Status,
	)
	if err != nil {
		return nil, err
	}
	
	json.Unmarshal([]byte(metadataJSON), &secret.Metadata)
	
	return &secret, nil
}

// UpdateSecret implements StorageBackend.UpdateSecret for PostgreSQL
func (b *PostgreSQLBackend) UpdateSecret(ctx context.Context, id string, secret *Secret) error {
	metadataJSON, _ := json.Marshal(secret.Metadata)
	
	query := `
	UPDATE secrets 
	SET name = $1, encrypted_value = $2, key_id = $3, metadata = $4, tags = $5,
		updated_at = $6, expires_at = $7, rotation_due = $8, version = version + 1,
		status = $9
	WHERE id = $10
	`
	
	_, err := b.db.ExecContext(ctx, query,
		secret.Name, secret.EncryptedValue, secret.KeyID,
		string(metadataJSON), pq.Array(secret.Tags), secret.UpdatedAt,
		secret.ExpiresAt, secret.RotationDue, secret.Status, id)
	
	return err
}

// DeleteSecret implements StorageBackend.DeleteSecret for PostgreSQL
func (b *PostgreSQLBackend) DeleteSecret(ctx context.Context, id string) error {
	query := `DELETE FROM secrets WHERE id = $1`
	_, err := b.db.ExecContext(ctx, query, id)
	return err
}

// ListSecrets implements StorageBackend.ListSecrets for PostgreSQL
func (b *PostgreSQLBackend) ListSecrets(ctx context.Context, filter *SecretFilter) ([]*Secret, error) {
	query := `
	SELECT id, name, key_id, metadata, tags, created_at, updated_at,
		expires_at, rotation_due, version, created_by, access_count,
		last_accessed, status
	FROM secrets
	WHERE 1=1
	`
	args := []interface{}{}
	argIndex := 1
	
	// Apply filters
	if filter != nil {
		if filter.Status != "" {
			query += fmt.Sprintf(" AND status = $%d", argIndex)
			args = append(args, filter.Status)
			argIndex++
		}
		if filter.NamePattern != "" {
			query += fmt.Sprintf(" AND name ILIKE $%d", argIndex)
			args = append(args, "%"+filter.NamePattern+"%")
			argIndex++
		}
		if filter.CreatedBy != "" {
			query += fmt.Sprintf(" AND created_by = $%d", argIndex)
			args = append(args, filter.CreatedBy)
			argIndex++
		}
		if filter.CreatedAfter != nil {
			query += fmt.Sprintf(" AND created_at > $%d", argIndex)
			args = append(args, filter.CreatedAfter)
			argIndex++
		}
	}
	
	query += " ORDER BY created_at DESC"
	
	// Apply limit and offset
	if filter != nil {
		if filter.Limit > 0 {
			query += fmt.Sprintf(" LIMIT $%d", argIndex)
			args = append(args, filter.Limit)
			argIndex++
		}
		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", argIndex)
			args = append(args, filter.Offset)
			argIndex++
		}
	}
	
	rows, err := b.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var secrets []*Secret
	for rows.Next() {
		var secret Secret
		var metadataJSON string
		
		err := rows.Scan(
			&secret.ID, &secret.Name, &secret.KeyID, &metadataJSON, pq.Array(&secret.Tags),
			&secret.CreatedAt, &secret.UpdatedAt, &secret.ExpiresAt,
			&secret.RotationDue, &secret.Version, &secret.CreatedBy,
			&secret.AccessCount, &secret.LastAccessed, &secret.Status,
		)
		if err != nil {
			continue
		}
		
		json.Unmarshal([]byte(metadataJSON), &secret.Metadata)
		
		secrets = append(secrets, &secret)
	}
	
	return secrets, nil
}

func (b *PostgreSQLBackend) HealthCheck(ctx context.Context) error {
	_, err := b.db.ExecContext(ctx, "SELECT 1")
	return err
}

func (b *PostgreSQLBackend) Close() error {
	return b.db.Close()
}

func (b *PostgreSQLBackend) Backup(ctx context.Context, destination string) error {
	// PostgreSQL backup using pg_dump
	return fmt.Errorf("PostgreSQL backup requires pg_dump - use BackupManager instead")
}

func (b *PostgreSQLBackend) Restore(ctx context.Context, source string) error {
	// PostgreSQL restore using pg_restore
	return fmt.Errorf("PostgreSQL restore requires pg_restore - use BackupManager instead")
}

// MySQLBackend implements StorageBackend for MySQL
type MySQLBackend struct {
	db *sql.DB
}

// NewMySQLBackend creates a new MySQL storage backend
func NewMySQLBackend(cfg *config.DatabaseConfig) (*MySQLBackend, error) {
	connectionString := cfg.ConnectionString
	if connectionString == "" {
		connectionString = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			cfg.Username, cfg.Password, cfg.Host, cfg.Port, cfg.Database)
	}
	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open MySQL database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	backend := &MySQLBackend{db: db}

	// Run migrations
	if err := backend.migrate(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return backend, nil
}

// migrate runs database migrations for MySQL
func (b *MySQLBackend) migrate() error {
	// Migration is now handled by MigrationManager
	return nil
}

// CreateSecret implements StorageBackend.CreateSecret for MySQL
func (b *MySQLBackend) CreateSecret(ctx context.Context, secret *Secret) error {
	metadataJSON, _ := json.Marshal(secret.Metadata)
	tagsJSON, _ := json.Marshal(secret.Tags)
	
	query := `
	INSERT INTO secrets (id, name, encrypted_value, key_id, metadata, tags, 
		created_at, updated_at, expires_at, rotation_due, version, created_by, status)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	_, err := b.db.ExecContext(ctx, query, 
		secret.ID, secret.Name, secret.EncryptedValue, secret.KeyID,
		string(metadataJSON), string(tagsJSON),
		secret.CreatedAt, secret.UpdatedAt, secret.ExpiresAt, secret.RotationDue,
		secret.Version, secret.CreatedBy, secret.Status)
	
	return err
}

// GetSecret implements StorageBackend.GetSecret for MySQL
func (b *MySQLBackend) GetSecret(ctx context.Context, id string) (*Secret, error) {
	query := `
	SELECT id, name, encrypted_value, key_id, metadata, tags,
		created_at, updated_at, expires_at, rotation_due, version,
		created_by, access_count, last_accessed, status
	FROM secrets WHERE id = ?
	`
	
	var secret Secret
	var metadataJSON, tagsJSON string
	
	err := b.db.QueryRowContext(ctx, query, id).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedValue, &secret.KeyID,
		&metadataJSON, &tagsJSON, &secret.CreatedAt, &secret.UpdatedAt,
		&secret.ExpiresAt, &secret.RotationDue, &secret.Version,
		&secret.CreatedBy, &secret.AccessCount, &secret.LastAccessed, &secret.Status,
	)
	if err != nil {
		return nil, err
	}
	
	json.Unmarshal([]byte(metadataJSON), &secret.Metadata)
	json.Unmarshal([]byte(tagsJSON), &secret.Tags)
	
	return &secret, nil
}

// GetSecretByName implements StorageBackend.GetSecretByName for MySQL
func (b *MySQLBackend) GetSecretByName(ctx context.Context, name string) (*Secret, error) {
	query := `
	SELECT id, name, encrypted_value, key_id, metadata, tags,
		created_at, updated_at, expires_at, rotation_due, version,
		created_by, access_count, last_accessed, status
	FROM secrets WHERE name = ?
	`
	
	var secret Secret
	var metadataJSON, tagsJSON string
	
	err := b.db.QueryRowContext(ctx, query, name).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedValue, &secret.KeyID,
		&metadataJSON, &tagsJSON, &secret.CreatedAt, &secret.UpdatedAt,
		&secret.ExpiresAt, &secret.RotationDue, &secret.Version,
		&secret.CreatedBy, &secret.AccessCount, &secret.LastAccessed, &secret.Status,
	)
	if err != nil {
		return nil, err
	}
	
	json.Unmarshal([]byte(metadataJSON), &secret.Metadata)
	json.Unmarshal([]byte(tagsJSON), &secret.Tags)
	
	return &secret, nil
}

// UpdateSecret implements StorageBackend.UpdateSecret for MySQL
func (b *MySQLBackend) UpdateSecret(ctx context.Context, id string, secret *Secret) error {
	metadataJSON, _ := json.Marshal(secret.Metadata)
	tagsJSON, _ := json.Marshal(secret.Tags)
	
	query := `
	UPDATE secrets 
	SET name = ?, encrypted_value = ?, key_id = ?, metadata = ?, tags = ?,
		updated_at = ?, expires_at = ?, rotation_due = ?, version = version + 1,
		status = ?
	WHERE id = ?
	`
	
	_, err := b.db.ExecContext(ctx, query,
		secret.Name, secret.EncryptedValue, secret.KeyID,
		string(metadataJSON), string(tagsJSON), secret.UpdatedAt,
		secret.ExpiresAt, secret.RotationDue, secret.Status, id)
	
	return err
}

// DeleteSecret implements StorageBackend.DeleteSecret for MySQL
func (b *MySQLBackend) DeleteSecret(ctx context.Context, id string) error {
	query := `DELETE FROM secrets WHERE id = ?`
	_, err := b.db.ExecContext(ctx, query, id)
	return err
}

// ListSecrets implements StorageBackend.ListSecrets for MySQL
func (b *MySQLBackend) ListSecrets(ctx context.Context, filter *SecretFilter) ([]*Secret, error) {
	query := `
	SELECT id, name, key_id, metadata, tags, created_at, updated_at,
		expires_at, rotation_due, version, created_by, access_count,
		last_accessed, status
	FROM secrets
	WHERE 1=1
	`
	args := []interface{}{}
	
	// Apply filters
	if filter != nil {
		if filter.Status != "" {
			query += " AND status = ?"
			args = append(args, filter.Status)
		}
		if filter.NamePattern != "" {
			query += " AND name LIKE ?"
			args = append(args, "%"+filter.NamePattern+"%")
		}
		if filter.CreatedBy != "" {
			query += " AND created_by = ?"
			args = append(args, filter.CreatedBy)
		}
		if filter.CreatedAfter != nil {
			query += " AND created_at > ?"
			args = append(args, filter.CreatedAfter)
		}
	}
	
	query += " ORDER BY created_at DESC"
	
	// Apply limit and offset
	if filter != nil {
		if filter.Limit > 0 {
			query += " LIMIT ?"
			args = append(args, filter.Limit)
		}
		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}
	
	rows, err := b.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var secrets []*Secret
	for rows.Next() {
		var secret Secret
		var metadataJSON, tagsJSON string
		
		err := rows.Scan(
			&secret.ID, &secret.Name, &secret.KeyID, &metadataJSON, &tagsJSON,
			&secret.CreatedAt, &secret.UpdatedAt, &secret.ExpiresAt,
			&secret.RotationDue, &secret.Version, &secret.CreatedBy,
			&secret.AccessCount, &secret.LastAccessed, &secret.Status,
		)
		if err != nil {
			continue
		}
		
		json.Unmarshal([]byte(metadataJSON), &secret.Metadata)
		json.Unmarshal([]byte(tagsJSON), &secret.Tags)
		
		secrets = append(secrets, &secret)
	}
	
	return secrets, nil
}

func (b *MySQLBackend) HealthCheck(ctx context.Context) error {
	_, err := b.db.ExecContext(ctx, "SELECT 1")
	return err
}

func (b *MySQLBackend) Close() error {
	return b.db.Close()
}

func (b *MySQLBackend) Backup(ctx context.Context, destination string) error {
	// MySQL backup using mysqldump
	return fmt.Errorf("MySQL backup requires mysqldump - use BackupManager instead")
}

func (b *MySQLBackend) Restore(ctx context.Context, source string) error {
	// MySQL restore using mysql client
	return fmt.Errorf("MySQL restore requires mysql client - use BackupManager instead")
}