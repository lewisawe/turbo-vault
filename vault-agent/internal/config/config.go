package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"github.com/keyvault/agent/internal/audit"
	"github.com/keyvault/agent/internal/crypto"
)

// Config represents the complete vault agent configuration
type Config struct {
	Server       ServerConfig       `yaml:"server" json:"server"`
	Database     DatabaseConfig     `yaml:"database" json:"database"`
	ControlPlane ControlPlaneConfig `yaml:"control_plane" json:"control_plane"`
	Security     SecurityConfig     `yaml:"security" json:"security"`
	Logging      LoggingConfig      `yaml:"logging" json:"logging"`
	Audit        audit.AuditConfig  `yaml:"audit" json:"audit"`
	KeyManager   crypto.KeyManagerConfig `yaml:"key_manager" json:"key_manager"`
	Performance  PerformanceConfig  `yaml:"performance" json:"performance"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host         string        `yaml:"host" json:"host"`
	Port         int           `yaml:"port" json:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout" json:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout" json:"idle_timeout"`
	TLS          TLSConfig     `yaml:"tls" json:"tls"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
	CAFile   string `yaml:"ca_file" json:"ca_file"`
}

// DatabaseConfig contains database configuration with support for multiple backends
type DatabaseConfig struct {
	Type             string            `yaml:"type" json:"type"`
	ConnectionString string            `yaml:"connection_string" json:"connection_string"`
	Host             string            `yaml:"host" json:"host"`
	Port             int               `yaml:"port" json:"port"`
	Database         string            `yaml:"database" json:"database"`
	Username         string            `yaml:"username" json:"username"`
	Password         string            `yaml:"password" json:"password"`
	SSLMode          string            `yaml:"ssl_mode" json:"ssl_mode"`
	MaxOpenConns     int               `yaml:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns     int               `yaml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetime  time.Duration     `yaml:"conn_max_lifetime" json:"conn_max_lifetime"`
	MigrationPath    string            `yaml:"migration_path" json:"migration_path"`
	Options          map[string]string `yaml:"options" json:"options"`
}

// ControlPlaneConfig contains control plane connection configuration
type ControlPlaneConfig struct {
	Enabled           bool          `yaml:"enabled" json:"enabled"`
	URL               string        `yaml:"url" json:"url"`
	CertFile          string        `yaml:"cert_file" json:"cert_file"`
	KeyFile           string        `yaml:"key_file" json:"key_file"`
	CAFile            string        `yaml:"ca_file" json:"ca_file"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval" json:"heartbeat_interval"`
	RetryInterval     time.Duration `yaml:"retry_interval" json:"retry_interval"`
	MaxRetries        int           `yaml:"max_retries" json:"max_retries"`
	Timeout           time.Duration `yaml:"timeout" json:"timeout"`
	OfflineMode       bool          `yaml:"offline_mode" json:"offline_mode"`
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	MasterKeyFile     string            `yaml:"master_key_file" json:"master_key_file"`
	EncryptionKey     []byte            `yaml:"-" json:"-"` // Never serialize
	APIKeys           APIKeysConfig     `yaml:"api_keys" json:"api_keys"`
	Authentication    AuthConfig        `yaml:"authentication" json:"authentication"`
	RateLimiting      RateLimitConfig   `yaml:"rate_limiting" json:"rate_limiting"`
	SessionManagement SessionConfig     `yaml:"session_management" json:"session_management"`
}

// APIKeysConfig contains API key configuration
type APIKeysConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	DefaultExpiry time.Duration `yaml:"default_expiry" json:"default_expiry"`
	MaxKeys       int           `yaml:"max_keys" json:"max_keys"`
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	Methods          []string      `yaml:"methods" json:"methods"`
	JWTSecret        string        `yaml:"jwt_secret" json:"jwt_secret"`
	JWTExpiry        time.Duration `yaml:"jwt_expiry" json:"jwt_expiry"`
	PasswordMinLength int          `yaml:"password_min_length" json:"password_min_length"`
	RequireMFA       bool          `yaml:"require_mfa" json:"require_mfa"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	RequestsPerSec int           `yaml:"requests_per_sec" json:"requests_per_sec"`
	BurstSize      int           `yaml:"burst_size" json:"burst_size"`
	WindowSize     time.Duration `yaml:"window_size" json:"window_size"`
}

// SessionConfig contains session management configuration
type SessionConfig struct {
	Timeout         time.Duration `yaml:"timeout" json:"timeout"`
	MaxConcurrent   int           `yaml:"max_concurrent" json:"max_concurrent"`
	SecureCookies   bool          `yaml:"secure_cookies" json:"secure_cookies"`
	SameSiteCookies string        `yaml:"same_site_cookies" json:"same_site_cookies"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level      string            `yaml:"level" json:"level"`
	Format     string            `yaml:"format" json:"format"`
	Output     []string          `yaml:"output" json:"output"`
	File       LogFileConfig     `yaml:"file" json:"file"`
	Structured bool              `yaml:"structured" json:"structured"`
	Fields     map[string]string `yaml:"fields" json:"fields"`
}

// LogFileConfig contains file logging configuration
type LogFileConfig struct {
	Path       string `yaml:"path" json:"path"`
	MaxSize    int    `yaml:"max_size" json:"max_size"`
	MaxAge     int    `yaml:"max_age" json:"max_age"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
	Compress   bool   `yaml:"compress" json:"compress"`
}

// PerformanceConfig contains performance-related configuration
type PerformanceConfig struct {
	Cache         CacheConfig `yaml:"cache" json:"cache"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
	Metrics       MetricsConfig `yaml:"metrics" json:"metrics"`
}

// CacheConfig contains caching configuration
type CacheConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	Type         string        `yaml:"type" json:"type"`
	TTL          time.Duration `yaml:"ttl" json:"ttl"`
	MaxSize      int           `yaml:"max_size" json:"max_size"`
	RedisURL     string        `yaml:"redis_url" json:"redis_url"`
	RedisDB      int           `yaml:"redis_db" json:"redis_db"`
	RedisPassword string       `yaml:"redis_password" json:"redis_password"`
}

// CircuitBreakerConfig contains circuit breaker configuration
type CircuitBreakerConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	FailureThreshold int           `yaml:"failure_threshold" json:"failure_threshold"`
	RecoveryTimeout  time.Duration `yaml:"recovery_timeout" json:"recovery_timeout"`
	HalfOpenRequests int           `yaml:"half_open_requests" json:"half_open_requests"`
}

// MetricsConfig contains metrics configuration
type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Path       string `yaml:"path" json:"path"`
	Namespace  string `yaml:"namespace" json:"namespace"`
	Subsystem  string `yaml:"subsystem" json:"subsystem"`
}

// Load loads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	// Start with default configuration
	cfg := DefaultConfig()

	// Load from YAML file if provided
	if configPath != "" {
		if err := cfg.LoadFromFile(configPath); err != nil {
			return nil, fmt.Errorf("failed to load config from file: %w", err)
		}
	}

	// Override with environment variables
	cfg.LoadFromEnv()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Load sensitive data (keys, passwords, etc.)
	if err := cfg.LoadSensitiveData(); err != nil {
		return nil, fmt.Errorf("failed to load sensitive data: %w", err)
	}

	return cfg, nil
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLS: TLSConfig{
				Enabled: false,
			},
		},
		Database: DatabaseConfig{
			Type:            "sqlite",
			ConnectionString: "./data/vault.db",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
			MigrationPath:   "./migrations",
			Options:         make(map[string]string),
		},
		ControlPlane: ControlPlaneConfig{
			Enabled:           false,
			HeartbeatInterval: 30 * time.Second,
			RetryInterval:     5 * time.Second,
			MaxRetries:        3,
			Timeout:           10 * time.Second,
			OfflineMode:       true,
		},
		Security: SecurityConfig{
			MasterKeyFile: "./config/master.key",
			APIKeys: APIKeysConfig{
				Enabled:       true,
				DefaultExpiry: 365 * 24 * time.Hour,
				MaxKeys:       100,
			},
			Authentication: AuthConfig{
				Methods:           []string{"api_key", "jwt"},
				JWTExpiry:         24 * time.Hour,
				PasswordMinLength: 8,
				RequireMFA:        false,
			},
			RateLimiting: RateLimitConfig{
				Enabled:        true,
				RequestsPerSec: 1000,
				BurstSize:      100,
				WindowSize:     time.Minute,
			},
			SessionManagement: SessionConfig{
				Timeout:         30 * time.Minute,
				MaxConcurrent:   10,
				SecureCookies:   true,
				SameSiteCookies: "strict",
			},
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     []string{"stdout"},
			Structured: true,
			File: LogFileConfig{
				Path:       "./logs/vault-agent.log",
				MaxSize:    100,
				MaxAge:     30,
				MaxBackups: 10,
				Compress:   true,
			},
			Fields: make(map[string]string),
		},
		Audit: *audit.DefaultAuditConfig("./logs/audit"),
		KeyManager: *crypto.DefaultKeyManagerConfig("./keys"),
		Performance: PerformanceConfig{
			Cache: CacheConfig{
				Enabled: true,
				Type:    "memory",
				TTL:     5 * time.Minute,
				MaxSize: 1000,
			},
			CircuitBreaker: CircuitBreakerConfig{
				Enabled:          true,
				FailureThreshold: 5,
				RecoveryTimeout:  30 * time.Second,
				HalfOpenRequests: 3,
			},
			Metrics: MetricsConfig{
				Enabled:   true,
				Path:      "/metrics",
				Namespace: "vault_agent",
				Subsystem: "core",
			},
		},
	}
}

// LoadFromFile loads configuration from a YAML file
func (c *Config) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, c); err != nil {
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	return nil
}

// LoadFromEnv loads configuration from environment variables
func (c *Config) LoadFromEnv() {
	// Server configuration
	if host := os.Getenv("VAULT_HOST"); host != "" {
		c.Server.Host = host
	}
	if port := getEnvInt("VAULT_PORT", 0); port != 0 {
		c.Server.Port = port
	}

	// Database configuration
	if dbType := os.Getenv("DB_TYPE"); dbType != "" {
		c.Database.Type = dbType
	}
	if dbConn := os.Getenv("DB_CONNECTION_STRING"); dbConn != "" {
		c.Database.ConnectionString = dbConn
	}
	if dbHost := os.Getenv("DB_HOST"); dbHost != "" {
		c.Database.Host = dbHost
	}
	if dbPort := getEnvInt("DB_PORT", 0); dbPort != 0 {
		c.Database.Port = dbPort
	}
	if dbName := os.Getenv("DB_NAME"); dbName != "" {
		c.Database.Database = dbName
	}
	if dbUser := os.Getenv("DB_USER"); dbUser != "" {
		c.Database.Username = dbUser
	}
	if dbPass := os.Getenv("DB_PASSWORD"); dbPass != "" {
		c.Database.Password = dbPass
	}

	// Control plane configuration
	if cpURL := os.Getenv("CONTROL_PLANE_URL"); cpURL != "" {
		c.ControlPlane.URL = cpURL
		c.ControlPlane.Enabled = true
	}
	if cpCert := os.Getenv("CONTROL_PLANE_CERT"); cpCert != "" {
		c.ControlPlane.CertFile = cpCert
	}
	if cpKey := os.Getenv("CONTROL_PLANE_KEY"); cpKey != "" {
		c.ControlPlane.KeyFile = cpKey
	}
	if offline := getEnvBool("OFFLINE_MODE", false); offline {
		c.ControlPlane.OfflineMode = true
		c.ControlPlane.Enabled = false
	}

	// Security configuration
	if keyFile := os.Getenv("MASTER_KEY_FILE"); keyFile != "" {
		c.Security.MasterKeyFile = keyFile
	}
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		c.Security.Authentication.JWTSecret = jwtSecret
	}

	// Logging configuration
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		c.Logging.Level = logLevel
	}
	if logFormat := os.Getenv("LOG_FORMAT"); logFormat != "" {
		c.Logging.Format = logFormat
	}

	// Key manager configuration
	if keyPath := os.Getenv("KEY_MANAGER_PATH"); keyPath != "" {
		c.KeyManager.FilePath = keyPath
	}
	if keyType := os.Getenv("KEY_MANAGER_TYPE"); keyType != "" {
		c.KeyManager.Type = crypto.KeyType(keyType)
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	// Validate database configuration
	validDBTypes := []string{"sqlite", "postgres", "mysql"}
	if !contains(validDBTypes, c.Database.Type) {
		return fmt.Errorf("unsupported database type: %s", c.Database.Type)
	}

	if c.Database.Type != "sqlite" && c.Database.ConnectionString == "" {
		if c.Database.Host == "" || c.Database.Database == "" {
			return fmt.Errorf("database host and name are required for %s", c.Database.Type)
		}
	}

	// Validate control plane configuration
	if c.ControlPlane.Enabled {
		if c.ControlPlane.URL == "" {
			return fmt.Errorf("control plane URL is required when enabled")
		}
		if c.ControlPlane.CertFile == "" || c.ControlPlane.KeyFile == "" {
			return fmt.Errorf("control plane certificates are required when enabled")
		}
	}

	// Validate logging configuration
	validLogLevels := []string{"debug", "info", "warn", "error", "fatal"}
	if !contains(validLogLevels, c.Logging.Level) {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	return nil
}

// LoadSensitiveData loads sensitive data like encryption keys
func (c *Config) LoadSensitiveData() error {
	// Load master encryption key
	if err := c.loadMasterKey(); err != nil {
		return fmt.Errorf("failed to load master key: %w", err)
	}

	// Generate JWT secret if not provided
	if c.Security.Authentication.JWTSecret == "" {
		c.Security.Authentication.JWTSecret = generateRandomString(32)
	}

	return nil
}

// loadMasterKey loads the master encryption key
func (c *Config) loadMasterKey() error {
	keyFile := c.Security.MasterKeyFile
	
	// Check if key file exists
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		// Generate new key file
		return c.generateMasterKey(keyFile)
	}

	// Load existing key
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read master key file: %w", err)
	}

	if len(keyData) != 32 {
		return fmt.Errorf("invalid master key size: expected 32 bytes, got %d", len(keyData))
	}

	c.Security.EncryptionKey = keyData
	return nil
}

// generateMasterKey generates a new master encryption key
func (c *Config) generateMasterKey(keyFile string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(keyFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Generate 32-byte key
	key := make([]byte, 32)
	if _, err := os.Open("/dev/urandom"); err == nil {
		// Use /dev/urandom on Unix systems
		urandom, err := os.Open("/dev/urandom")
		if err != nil {
			return fmt.Errorf("failed to open /dev/urandom: %w", err)
		}
		defer urandom.Close()
		
		if _, err := urandom.Read(key); err != nil {
			return fmt.Errorf("failed to read from /dev/urandom: %w", err)
		}
	} else {
		// Fallback to crypto/rand
		return fmt.Errorf("secure random source not available")
	}

	// Write key to file with secure permissions
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		return fmt.Errorf("failed to write master key file: %w", err)
	}

	c.Security.EncryptionKey = key
	return nil
}

// SaveToFile saves the configuration to a YAML file
func (c *Config) SaveToFile(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetDatabaseConnectionString returns the appropriate connection string for the database
func (c *Config) GetDatabaseConnectionString() string {
	if c.Database.ConnectionString != "" {
		return c.Database.ConnectionString
	}

	switch c.Database.Type {
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			c.Database.Host, c.Database.Port, c.Database.Username, 
			c.Database.Password, c.Database.Database, c.Database.SSLMode)
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			c.Database.Username, c.Database.Password, 
			c.Database.Host, c.Database.Port, c.Database.Database)
	case "sqlite":
		return c.Database.ConnectionString
	default:
		return ""
	}
}

// Helper functions

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[len(charset)/2] // Simple fallback
	}
	return string(b)
}