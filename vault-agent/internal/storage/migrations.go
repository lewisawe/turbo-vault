package storage

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Migration represents a database migration
type Migration struct {
	Version     int
	Description string
	Up          string
	Down        string
	Applied     bool
	AppliedAt   *time.Time
}

// MigrationManager handles database migrations with version control
type MigrationManager struct {
	db          *sql.DB
	dbType      string
	migrations  []*Migration
	tableName   string
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db *sql.DB, dbType string) *MigrationManager {
	return &MigrationManager{
		db:         db,
		dbType:     dbType,
		migrations: []*Migration{},
		tableName:  "schema_migrations",
	}
}

// RegisterMigration registers a new migration
func (mm *MigrationManager) RegisterMigration(version int, description, up, down string) {
	migration := &Migration{
		Version:     version,
		Description: description,
		Up:          up,
		Down:        down,
	}
	mm.migrations = append(mm.migrations, migration)
}

// Initialize creates the migration tracking table
func (mm *MigrationManager) Initialize(ctx context.Context) error {
	var query string
	
	switch mm.dbType {
	case "sqlite":
		query = `
		CREATE TABLE IF NOT EXISTS ` + mm.tableName + ` (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			checksum TEXT NOT NULL
		)`
	case "postgres":
		query = `
		CREATE TABLE IF NOT EXISTS ` + mm.tableName + ` (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			checksum TEXT NOT NULL
		)`
	case "mysql":
		query = `
		CREATE TABLE IF NOT EXISTS ` + mm.tableName + ` (
			version INT PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			checksum TEXT NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
	default:
		return fmt.Errorf("unsupported database type: %s", mm.dbType)
	}

	_, err := mm.db.ExecContext(ctx, query)
	return err
}

// GetAppliedMigrations returns all applied migrations
func (mm *MigrationManager) GetAppliedMigrations(ctx context.Context) (map[int]*Migration, error) {
	query := `SELECT version, description, applied_at FROM ` + mm.tableName + ` ORDER BY version`
	
	rows, err := mm.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]*Migration)
	for rows.Next() {
		var version int
		var description string
		var appliedAt time.Time

		if err := rows.Scan(&version, &description, &appliedAt); err != nil {
			continue
		}

		applied[version] = &Migration{
			Version:     version,
			Description: description,
			Applied:     true,
			AppliedAt:   &appliedAt,
		}
	}

	return applied, nil
}

// GetCurrentVersion returns the current schema version
func (mm *MigrationManager) GetCurrentVersion(ctx context.Context) (int, error) {
	query := `SELECT COALESCE(MAX(version), 0) FROM ` + mm.tableName
	
	var version int
	err := mm.db.QueryRowContext(ctx, query).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to get current version: %w", err)
	}

	return version, nil
}

// Migrate runs all pending migrations up to the target version
func (mm *MigrationManager) Migrate(ctx context.Context, targetVersion int) error {
	// Sort migrations by version
	sort.Slice(mm.migrations, func(i, j int) bool {
		return mm.migrations[i].Version < mm.migrations[j].Version
	})

	// Get applied migrations
	applied, err := mm.GetAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Get current version
	currentVersion, err := mm.GetCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Determine migrations to run
	var toRun []*Migration
	for _, migration := range mm.migrations {
		if migration.Version > currentVersion && migration.Version <= targetVersion {
			if _, isApplied := applied[migration.Version]; !isApplied {
				toRun = append(toRun, migration)
			}
		}
	}

	// Run migrations in transaction
	for _, migration := range toRun {
		if err := mm.runMigration(ctx, migration, true); err != nil {
			return fmt.Errorf("failed to run migration %d: %w", migration.Version, err)
		}
	}

	return nil
}

// MigrateToLatest runs all pending migrations
func (mm *MigrationManager) MigrateToLatest(ctx context.Context) error {
	if len(mm.migrations) == 0 {
		return nil
	}

	// Find highest version
	maxVersion := 0
	for _, migration := range mm.migrations {
		if migration.Version > maxVersion {
			maxVersion = migration.Version
		}
	}

	return mm.Migrate(ctx, maxVersion)
}

// Rollback rolls back migrations to the target version
func (mm *MigrationManager) Rollback(ctx context.Context, targetVersion int) error {
	// Sort migrations by version (descending for rollback)
	sort.Slice(mm.migrations, func(i, j int) bool {
		return mm.migrations[i].Version > mm.migrations[j].Version
	})

	// Get applied migrations
	applied, err := mm.GetAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Get current version
	currentVersion, err := mm.GetCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Determine migrations to rollback
	var toRollback []*Migration
	for _, migration := range mm.migrations {
		if migration.Version > targetVersion && migration.Version <= currentVersion {
			if _, isApplied := applied[migration.Version]; isApplied {
				toRollback = append(toRollback, migration)
			}
		}
	}

	// Rollback migrations in transaction
	for _, migration := range toRollback {
		if err := mm.runMigration(ctx, migration, false); err != nil {
			return fmt.Errorf("failed to rollback migration %d: %w", migration.Version, err)
		}
	}

	return nil
}

// runMigration runs a single migration (up or down)
func (mm *MigrationManager) runMigration(ctx context.Context, migration *Migration, up bool) error {
	tx, err := mm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var sql string
	if up {
		sql = migration.Up
	} else {
		sql = migration.Down
	}

	// Execute migration SQL
	statements := mm.splitSQL(sql)
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}

		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to execute migration statement: %w", err)
		}
	}

	// Update migration tracking
	if up {
		checksum := mm.calculateChecksum(migration.Up)
		_, err = tx.ExecContext(ctx,
			`INSERT INTO `+mm.tableName+` (version, description, checksum) VALUES (?, ?, ?)`,
			migration.Version, migration.Description, checksum)
	} else {
		_, err = tx.ExecContext(ctx,
			`DELETE FROM `+mm.tableName+` WHERE version = ?`,
			migration.Version)
	}

	if err != nil {
		return fmt.Errorf("failed to update migration tracking: %w", err)
	}

	return tx.Commit()
}

// splitSQL splits SQL into individual statements
func (mm *MigrationManager) splitSQL(sql string) []string {
	// Simple SQL statement splitter
	// In production, you'd want a more sophisticated parser
	statements := strings.Split(sql, ";")
	var result []string
	
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt != "" {
			result = append(result, stmt)
		}
	}
	
	return result
}

// calculateChecksum calculates a checksum for migration content
func (mm *MigrationManager) calculateChecksum(content string) string {
	// Simple checksum - in production use proper hashing
	return fmt.Sprintf("%x", len(content))
}

// ValidateMigrations validates all registered migrations
func (mm *MigrationManager) ValidateMigrations(ctx context.Context) error {
	applied, err := mm.GetAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Check for version conflicts
	versions := make(map[int]bool)
	for _, migration := range mm.migrations {
		if versions[migration.Version] {
			return fmt.Errorf("duplicate migration version: %d", migration.Version)
		}
		versions[migration.Version] = true

		// Validate applied migrations haven't changed
		if appliedMigration, exists := applied[migration.Version]; exists {
			expectedChecksum := mm.calculateChecksum(migration.Up)
			
			// Get stored checksum
			var storedChecksum string
			err := mm.db.QueryRowContext(ctx,
				`SELECT checksum FROM `+mm.tableName+` WHERE version = ?`,
				migration.Version).Scan(&storedChecksum)
			
			if err == nil && storedChecksum != expectedChecksum {
				return fmt.Errorf("migration %d has been modified after being applied", migration.Version)
			}
			
			appliedMigration.Applied = true
		}
	}

	return nil
}

// GetMigrationStatus returns the status of all migrations
func (mm *MigrationManager) GetMigrationStatus(ctx context.Context) ([]*Migration, error) {
	applied, err := mm.GetAppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	// Sort migrations by version
	sort.Slice(mm.migrations, func(i, j int) bool {
		return mm.migrations[i].Version < mm.migrations[j].Version
	})

	var status []*Migration
	for _, migration := range mm.migrations {
		migrationCopy := *migration
		if appliedMigration, exists := applied[migration.Version]; exists {
			migrationCopy.Applied = true
			migrationCopy.AppliedAt = appliedMigration.AppliedAt
		}
		status = append(status, &migrationCopy)
	}

	return status, nil
}

// RegisterCoreMigrations registers the core vault agent migrations
func (mm *MigrationManager) RegisterCoreMigrations() {
	// Migration 1: Initial schema
	mm.RegisterMigration(1, "Create initial secrets table", `
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
			created_by TEXT DEFAULT '',
			access_count INTEGER DEFAULT 0,
			last_accessed DATETIME,
			status TEXT DEFAULT 'active'
		);
		
		CREATE INDEX idx_secrets_name ON secrets(name);
		CREATE INDEX idx_secrets_status ON secrets(status);
		CREATE INDEX idx_secrets_created_at ON secrets(created_at);
		CREATE INDEX idx_secrets_rotation_due ON secrets(rotation_due);
		CREATE INDEX idx_secrets_expires_at ON secrets(expires_at);
	`, `
		DROP INDEX IF EXISTS idx_secrets_expires_at;
		DROP INDEX IF EXISTS idx_secrets_rotation_due;
		DROP INDEX IF EXISTS idx_secrets_created_at;
		DROP INDEX IF EXISTS idx_secrets_status;
		DROP INDEX IF EXISTS idx_secrets_name;
		DROP TABLE secrets;
	`)

	// Migration 2: Add secret versions table
	mm.RegisterMigration(2, "Create secret versions table", `
		CREATE TABLE secret_versions (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			version INTEGER NOT NULL,
			encrypted_value BLOB NOT NULL,
			key_id TEXT NOT NULL,
			metadata TEXT DEFAULT '{}',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			created_by TEXT NOT NULL,
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE
		);
		
		CREATE UNIQUE INDEX idx_secret_versions_unique ON secret_versions(secret_id, version);
		CREATE INDEX idx_secret_versions_secret_id ON secret_versions(secret_id);
	`, `
		DROP INDEX IF EXISTS idx_secret_versions_secret_id;
		DROP INDEX IF EXISTS idx_secret_versions_unique;
		DROP TABLE secret_versions;
	`)

	// Migration 3: Add audit events table
	mm.RegisterMigration(3, "Create audit events table", `
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
		
		CREATE INDEX idx_audit_events_vault_timestamp ON audit_events(vault_id, timestamp);
		CREATE INDEX idx_audit_events_actor ON audit_events(actor_type, actor_id);
		CREATE INDEX idx_audit_events_resource ON audit_events(resource_type, resource_id);
		CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp);
	`, `
		DROP INDEX IF EXISTS idx_audit_events_timestamp;
		DROP INDEX IF EXISTS idx_audit_events_resource;
		DROP INDEX IF EXISTS idx_audit_events_actor;
		DROP INDEX IF EXISTS idx_audit_events_vault_timestamp;
		DROP TABLE audit_events;
	`)

	// Migration 4: Add cluster support tables
	mm.RegisterMigration(4, "Create cluster support tables", `
		CREATE TABLE cluster_nodes (
			id TEXT PRIMARY KEY,
			address TEXT NOT NULL,
			port INTEGER NOT NULL,
			status TEXT DEFAULT 'active',
			is_leader INTEGER DEFAULT 0,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			version TEXT DEFAULT '',
			metadata TEXT DEFAULT '{}',
			load_metrics TEXT DEFAULT '{}',
			registered_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		
		CREATE INDEX idx_cluster_nodes_status ON cluster_nodes(status);
		CREATE INDEX idx_cluster_nodes_last_seen ON cluster_nodes(last_seen);
		CREATE INDEX idx_cluster_nodes_leader ON cluster_nodes(is_leader);
		
		CREATE TABLE leader_election (
			id INTEGER PRIMARY KEY,
			leader_id TEXT NOT NULL,
			elected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			term INTEGER DEFAULT 1
		);
		
		CREATE TABLE cluster_sessions (
			session_id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_accessed DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		);
		
		CREATE INDEX idx_cluster_sessions_node ON cluster_sessions(node_id);
		CREATE INDEX idx_cluster_sessions_expires ON cluster_sessions(expires_at);
	`, `
		DROP INDEX IF EXISTS idx_cluster_sessions_expires;
		DROP INDEX IF EXISTS idx_cluster_sessions_node;
		DROP TABLE cluster_sessions;
		DROP TABLE leader_election;
		DROP INDEX IF EXISTS idx_cluster_nodes_leader;
		DROP INDEX IF EXISTS idx_cluster_nodes_last_seen;
		DROP INDEX IF EXISTS idx_cluster_nodes_status;
		DROP TABLE cluster_nodes;
	`)

	// Migration 5: Add backup tracking table
	mm.RegisterMigration(5, "Create backup tracking table", `
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
			metadata TEXT DEFAULT '{}'
		);
		
		CREATE INDEX idx_backups_status ON backups(status);
		CREATE INDEX idx_backups_created_at ON backups(created_at);
		CREATE INDEX idx_backups_expires_at ON backups(expires_at);
	`, `
		DROP INDEX IF EXISTS idx_backups_expires_at;
		DROP INDEX IF EXISTS idx_backups_created_at;
		DROP INDEX IF EXISTS idx_backups_status;
		DROP TABLE backups;
	`)
}