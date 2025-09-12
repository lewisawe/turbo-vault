package vaultagent

import (
	"time"
)

// RetryConfig represents retry configuration
type RetryConfig struct {
	MaxAttempts           int           `json:"max_attempts"`
	InitialDelay          time.Duration `json:"initial_delay"`
	MaxDelay              time.Duration `json:"max_delay"`
	BackoffFactor         float64       `json:"backoff_factor"`
	RetryableStatusCodes  []int         `json:"retryable_status_codes"`
}

// ClientConfig represents client configuration
type ClientConfig struct {
	Timeout        time.Duration     `json:"timeout"`
	MaxConnections int               `json:"max_connections"`
	VerifySSL      bool              `json:"verify_ssl"`
	Retry          RetryConfig       `json:"retry"`
	UserAgent      string            `json:"user_agent"`
	DefaultHeaders map[string]string `json:"default_headers"`
	LogLevel       string            `json:"log_level"`
	CacheEnabled   bool              `json:"cache_enabled"`
	CacheTTL       time.Duration     `json:"cache_ttl"`
	CacheMaxSize   int               `json:"cache_max_size"`
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:          3,
		InitialDelay:         1 * time.Second,
		MaxDelay:             30 * time.Second,
		BackoffFactor:        2.0,
		RetryableStatusCodes: []int{408, 429, 500, 502, 503, 504},
	}
}

// DefaultClientConfig returns default client configuration
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Timeout:        30 * time.Second,
		MaxConnections: 10,
		VerifySSL:      true,
		Retry:          DefaultRetryConfig(),
		UserAgent:      "vault-agent-go-sdk/1.0.0",
		DefaultHeaders: make(map[string]string),
		LogLevel:       "info",
		CacheEnabled:   true,
		CacheTTL:       5 * time.Minute,
		CacheMaxSize:   1000,
	}
}

// ClientOption represents a client configuration option
type ClientOption func(*ClientConfig)

// WithTimeout sets the client timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *ClientConfig) {
		c.Timeout = timeout
	}
}

// WithMaxConnections sets the maximum number of connections
func WithMaxConnections(maxConnections int) ClientOption {
	return func(c *ClientConfig) {
		c.MaxConnections = maxConnections
	}
}

// WithVerifySSL sets SSL verification
func WithVerifySSL(verifySSL bool) ClientOption {
	return func(c *ClientConfig) {
		c.VerifySSL = verifySSL
	}
}

// WithRetryConfig sets retry configuration
func WithRetryConfig(retry RetryConfig) ClientOption {
	return func(c *ClientConfig) {
		c.Retry = retry
	}
}

// WithUserAgent sets the user agent
func WithUserAgent(userAgent string) ClientOption {
	return func(c *ClientConfig) {
		c.UserAgent = userAgent
	}
}

// WithDefaultHeaders sets default headers
func WithDefaultHeaders(headers map[string]string) ClientOption {
	return func(c *ClientConfig) {
		c.DefaultHeaders = headers
	}
}

// WithLogLevel sets the log level
func WithLogLevel(logLevel string) ClientOption {
	return func(c *ClientConfig) {
		c.LogLevel = logLevel
	}
}

// WithCache enables/disables caching
func WithCache(enabled bool, ttl time.Duration, maxSize int) ClientOption {
	return func(c *ClientConfig) {
		c.CacheEnabled = enabled
		c.CacheTTL = ttl
		c.CacheMaxSize = maxSize
	}
}

// ValidateConfig validates the client configuration
func (c *ClientConfig) ValidateConfig() error {
	if c.Timeout <= 0 {
		return NewConfigurationError("timeout must be positive")
	}
	if c.MaxConnections <= 0 {
		return NewConfigurationError("max_connections must be positive")
	}
	if c.Retry.MaxAttempts <= 0 {
		return NewConfigurationError("retry max_attempts must be positive")
	}
	if c.Retry.InitialDelay <= 0 {
		return NewConfigurationError("retry initial_delay must be positive")
	}
	if c.Retry.MaxDelay <= 0 {
		return NewConfigurationError("retry max_delay must be positive")
	}
	if c.Retry.BackoffFactor <= 0 {
		return NewConfigurationError("retry backoff_factor must be positive")
	}
	if c.CacheEnabled && c.CacheTTL <= 0 {
		return NewConfigurationError("cache_ttl must be positive when cache is enabled")
	}
	if c.CacheEnabled && c.CacheMaxSize <= 0 {
		return NewConfigurationError("cache_max_size must be positive when cache is enabled")
	}
	return nil
}