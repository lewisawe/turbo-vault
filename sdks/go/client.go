package vaultagent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

// Client represents the Vault Agent client
type Client struct {
	client          *resty.Client
	config          ClientConfig
	auth            AuthMethod
	logger          *logrus.Logger
	cache           *cache.Cache
	cloudIntegration *CloudIntegration
}

// NewClient creates a new Vault Agent client
func NewClient(baseURL string, auth AuthMethod, options ...ClientOption) (*Client, error) {
	config := DefaultClientConfig()
	for _, option := range options {
		option(&config)
	}

	if err := config.ValidateConfig(); err != nil {
		return nil, err
	}

	// Initialize logger
	logger := logrus.New()
	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Initialize cache
	var clientCache *cache.Cache
	if config.CacheEnabled {
		clientCache = cache.New(config.CacheTTL, config.CacheTTL*2)
	}

	// Initialize HTTP client
	restyClient := resty.New()
	restyClient.SetBaseURL(strings.TrimSuffix(baseURL, "/"))
	restyClient.SetTimeout(config.Timeout)
	restyClient.SetHeader("User-Agent", config.UserAgent)

	// Set default headers
	for key, value := range config.DefaultHeaders {
		restyClient.SetHeader(key, value)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !config.VerifySSL,
	}

	// Get TLS config from auth method if available
	if authTLSConfig, err := auth.GetTLSConfig(); err == nil && authTLSConfig != nil {
		tlsConfig.Certificates = authTLSConfig.Certificates
	}

	restyClient.SetTLSClientConfig(tlsConfig)

	// Configure retry
	restyClient.SetRetryCount(config.Retry.MaxAttempts - 1) // resty counts retries, not attempts
	restyClient.SetRetryWaitTime(config.Retry.InitialDelay)
	restyClient.SetRetryMaxWaitTime(config.Retry.MaxDelay)
	restyClient.AddRetryCondition(func(r *resty.Response, err error) bool {
		if err != nil {
			return true
		}
		for _, code := range config.Retry.RetryableStatusCodes {
			if r.StatusCode() == code {
				return true
			}
		}
		return false
	})

	// Custom retry after function with exponential backoff and jitter
	restyClient.SetRetryAfter(func(client *resty.Client, resp *resty.Response) (time.Duration, error) {
		retryCount := resp.Request.Attempt - 1
		delay := time.Duration(float64(config.Retry.InitialDelay) * math.Pow(config.Retry.BackoffFactor, float64(retryCount)))
		if delay > config.Retry.MaxDelay {
			delay = config.Retry.MaxDelay
		}
		// Add jitter
		jitter := time.Duration(rand.Float64() * float64(delay) * 0.1)
		return delay + jitter, nil
	})

	client := &Client{
		client: restyClient,
		config: config,
		auth:   auth,
		logger: logger,
		cache:  clientCache,
	}

	// Set up request/response middleware
	client.setupMiddleware()

	return client, nil
}

// setupMiddleware configures request and response middleware
func (c *Client) setupMiddleware() {
	// Request middleware for authentication
	c.client.OnBeforeRequest(func(client *resty.Client, req *resty.Request) error {
		headers, err := c.auth.GetHeaders()
		if err != nil {
			return fmt.Errorf("failed to get auth headers: %w", err)
		}
		for key, value := range headers {
			req.SetHeader(key, value)
		}
		return nil
	})

	// Response middleware for error handling
	c.client.OnAfterResponse(func(client *resty.Client, resp *resty.Response) error {
		if resp.IsSuccess() {
			return nil
		}

		requestID := resp.Header().Get("X-Request-ID")
		
		var errorBody map[string]interface{}
		if err := json.Unmarshal(resp.Body(), &errorBody); err != nil {
			errorBody = map[string]interface{}{
				"message": string(resp.Body()),
			}
		}

		return parseErrorResponse(resp.StatusCode(), errorBody, requestID)
	})
}

// EnableCloudIntegration enables cloud provider integration
func (c *Client) EnableCloudIntegration(config HybridConfig) error {
	integration, err := NewCloudIntegration(config)
	if err != nil {
		return err
	}
	c.cloudIntegration = integration
	return nil
}

// withCache executes a function with caching support
func (c *Client) withCache(ctx context.Context, key string, fn func() (interface{}, error), ttl ...time.Duration) (interface{}, error) {
	if c.cache == nil {
		return fn()
	}

	if cached, found := c.cache.Get(key); found {
		c.logger.Debugf("Cache hit for key: %s", key)
		return cached, nil
	}

	result, err := fn()
	if err != nil {
		return nil, err
	}

	cacheTTL := c.config.CacheTTL
	if len(ttl) > 0 {
		cacheTTL = ttl[0]
	}

	c.cache.Set(key, result, cacheTTL)
	c.logger.Debugf("Cache set for key: %s", key)
	return result, nil
}

// invalidateCache removes cache entries matching the pattern
func (c *Client) invalidateCache(pattern string) {
	if c.cache == nil {
		return
	}

	items := c.cache.Items()
	for key := range items {
		if strings.Contains(key, pattern) {
			c.cache.Delete(key)
		}
	}
	c.logger.Debugf("Invalidated cache entries matching: %s", pattern)
}

// Secret Management Methods

// CreateSecret creates a new secret
func (c *Client) CreateSecret(ctx context.Context, req CreateSecretRequest) (*Secret, error) {
	c.logger.Infof("Creating secret: %s", req.Name)

	var secret Secret
	resp, err := c.client.R().
		SetContext(ctx).
		SetBody(req).
		SetResult(&secret).
		Post("/api/v1/secrets")

	if err != nil {
		return nil, NewConnectionError(fmt.Sprintf("failed to create secret: %v", err))
	}

	// Sync to cloud providers if enabled
	if c.cloudIntegration != nil && c.cloudIntegration.IsEnabled() {
		if err := c.cloudIntegration.SyncSecret(ctx, secret.Name, secret.Value); err != nil {
			c.logger.Warnf("Failed to sync secret to cloud providers: %v", err)
		}
	}

	c.invalidateCache("secrets")
	return &secret, nil
}

// GetSecret retrieves a secret by ID
func (c *Client) GetSecret(ctx context.Context, secretID string) (*Secret, error) {
	cacheKey := fmt.Sprintf("secret:%s", secretID)
	
	result, err := c.withCache(ctx, cacheKey, func() (interface{}, error) {
		c.logger.Infof("Getting secret: %s", secretID)
		
		var secret Secret
		_, err := c.client.R().
			SetContext(ctx).
			SetResult(&secret).
			Get(fmt.Sprintf("/api/v1/secrets/%s", secretID))
		
		if err != nil {
			return nil, err
		}
		
		return &secret, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*Secret), nil
}

// UpdateSecret updates an existing secret
func (c *Client) UpdateSecret(ctx context.Context, secretID string, req UpdateSecretRequest) (*Secret, error) {
	c.logger.Infof("Updating secret: %s", secretID)

	var secret Secret
	_, err := c.client.R().
		SetContext(ctx).
		SetBody(req).
		SetResult(&secret).
		Put(fmt.Sprintf("/api/v1/secrets/%s", secretID))

	if err != nil {
		return nil, err
	}

	// Sync to cloud providers if enabled
	if c.cloudIntegration != nil && c.cloudIntegration.IsEnabled() && req.Value != nil {
		if err := c.cloudIntegration.SyncSecret(ctx, secret.Name, *req.Value); err != nil {
			c.logger.Warnf("Failed to sync updated secret to cloud providers: %v", err)
		}
	}

	c.invalidateCache(fmt.Sprintf("secret:%s", secretID))
	c.invalidateCache("secrets")
	return &secret, nil
}

// DeleteSecret deletes a secret
func (c *Client) DeleteSecret(ctx context.Context, secretID string) error {
	c.logger.Infof("Deleting secret: %s", secretID)

	// Get secret name for cloud sync
	var secretName string
	if c.cloudIntegration != nil && c.cloudIntegration.IsEnabled() {
		if secret, err := c.GetSecret(ctx, secretID); err == nil {
			secretName = secret.Name
		}
	}

	_, err := c.client.R().
		SetContext(ctx).
		Delete(fmt.Sprintf("/api/v1/secrets/%s", secretID))

	if err != nil {
		return err
	}

	// Delete from cloud providers if enabled
	if c.cloudIntegration != nil && c.cloudIntegration.IsEnabled() && secretName != "" {
		if err := c.cloudIntegration.DeleteSecret(ctx, secretName); err != nil {
			c.logger.Warnf("Failed to delete secret from cloud providers: %v", err)
		}
	}

	c.invalidateCache(fmt.Sprintf("secret:%s", secretID))
	c.invalidateCache("secrets")
	return nil
}

// ListSecrets lists secrets with optional filtering
func (c *Client) ListSecrets(ctx context.Context, options ListSecretsOptions) ([]SecretMetadata, error) {
	cacheKey := fmt.Sprintf("secrets:%v", options)
	
	result, err := c.withCache(ctx, cacheKey, func() (interface{}, error) {
		c.logger.Info("Listing secrets")
		
		req := c.client.R().SetContext(ctx)
		
		if len(options.Tags) > 0 {
			req.SetQueryParam("tags", strings.Join(options.Tags, ","))
		}
		if options.Limit != nil {
			req.SetQueryParam("limit", strconv.Itoa(*options.Limit))
		}
		if options.Offset != nil {
			req.SetQueryParam("offset", strconv.Itoa(*options.Offset))
		}

		var response SecretsResponse
		_, err := req.SetResult(&response).Get("/api/v1/secrets")
		if err != nil {
			return nil, err
		}
		
		return response.Secrets, nil
	})

	if err != nil {
		return nil, err
	}

	return result.([]SecretMetadata), nil
}

// RotateSecret rotates a secret
func (c *Client) RotateSecret(ctx context.Context, secretID string) (*Secret, error) {
	c.logger.Infof("Rotating secret: %s", secretID)

	var secret Secret
	_, err := c.client.R().
		SetContext(ctx).
		SetResult(&secret).
		Post(fmt.Sprintf("/api/v1/secrets/%s/rotate", secretID))

	if err != nil {
		return nil, err
	}

	c.invalidateCache(fmt.Sprintf("secret:%s", secretID))
	c.invalidateCache("secrets")
	return &secret, nil
}

// GetSecretVersions gets all versions of a secret
func (c *Client) GetSecretVersions(ctx context.Context, secretID string) ([]SecretMetadata, error) {
	cacheKey := fmt.Sprintf("secret-versions:%s", secretID)
	
	result, err := c.withCache(ctx, cacheKey, func() (interface{}, error) {
		c.logger.Infof("Getting secret versions: %s", secretID)
		
		var response SecretVersionsResponse
		_, err := c.client.R().
			SetContext(ctx).
			SetResult(&response).
			Get(fmt.Sprintf("/api/v1/secrets/%s/versions", secretID))
		
		if err != nil {
			return nil, err
		}
		
		return response.Versions, nil
	})

	if err != nil {
		return nil, err
	}

	return result.([]SecretMetadata), nil
}

// RollbackSecret rolls back a secret to a specific version
func (c *Client) RollbackSecret(ctx context.Context, secretID string, version int) (*Secret, error) {
	c.logger.Infof("Rolling back secret %s to version %d", secretID, version)

	var secret Secret
	_, err := c.client.R().
		SetContext(ctx).
		SetBody(map[string]int{"version": version}).
		SetResult(&secret).
		Post(fmt.Sprintf("/api/v1/secrets/%s/rollback", secretID))

	if err != nil {
		return nil, err
	}

	c.invalidateCache(fmt.Sprintf("secret:%s", secretID))
	c.invalidateCache("secrets")
	return &secret, nil
}

// Policy Management Methods

// CreatePolicy creates a new policy
func (c *Client) CreatePolicy(ctx context.Context, policy Policy) (*Policy, error) {
	c.logger.Infof("Creating policy: %s", policy.Name)

	var result Policy
	_, err := c.client.R().
		SetContext(ctx).
		SetBody(policy).
		SetResult(&result).
		Post("/api/v1/policies")

	if err != nil {
		return nil, err
	}

	c.invalidateCache("policies")
	return &result, nil
}

// GetPolicy retrieves a policy by ID
func (c *Client) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	cacheKey := fmt.Sprintf("policy:%s", policyID)
	
	result, err := c.withCache(ctx, cacheKey, func() (interface{}, error) {
		c.logger.Infof("Getting policy: %s", policyID)
		
		var policy Policy
		_, err := c.client.R().
			SetContext(ctx).
			SetResult(&policy).
			Get(fmt.Sprintf("/api/v1/policies/%s", policyID))
		
		if err != nil {
			return nil, err
		}
		
		return &policy, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*Policy), nil
}

// UpdatePolicy updates an existing policy
func (c *Client) UpdatePolicy(ctx context.Context, policyID string, policy Policy) (*Policy, error) {
	c.logger.Infof("Updating policy: %s", policyID)

	var result Policy
	_, err := c.client.R().
		SetContext(ctx).
		SetBody(policy).
		SetResult(&result).
		Put(fmt.Sprintf("/api/v1/policies/%s", policyID))

	if err != nil {
		return nil, err
	}

	c.invalidateCache(fmt.Sprintf("policy:%s", policyID))
	c.invalidateCache("policies")
	return &result, nil
}

// DeletePolicy deletes a policy
func (c *Client) DeletePolicy(ctx context.Context, policyID string) error {
	c.logger.Infof("Deleting policy: %s", policyID)

	_, err := c.client.R().
		SetContext(ctx).
		Delete(fmt.Sprintf("/api/v1/policies/%s", policyID))

	if err != nil {
		return err
	}

	c.invalidateCache(fmt.Sprintf("policy:%s", policyID))
	c.invalidateCache("policies")
	return nil
}

// ListPolicies lists all policies
func (c *Client) ListPolicies(ctx context.Context) ([]Policy, error) {
	result, err := c.withCache(ctx, "policies", func() (interface{}, error) {
		c.logger.Info("Listing policies")
		
		var response PoliciesResponse
		_, err := c.client.R().
			SetContext(ctx).
			SetResult(&response).
			Get("/api/v1/policies")
		
		if err != nil {
			return nil, err
		}
		
		return response.Policies, nil
	})

	if err != nil {
		return nil, err
	}

	return result.([]Policy), nil
}

// Audit Methods

// GetAuditEvents retrieves audit events
func (c *Client) GetAuditEvents(ctx context.Context, options AuditQueryOptions) ([]AuditEvent, error) {
	cacheKey := fmt.Sprintf("audit:%v", options)
	
	result, err := c.withCache(ctx, cacheKey, func() (interface{}, error) {
		c.logger.Info("Getting audit events")
		
		req := c.client.R().SetContext(ctx)
		
		if options.StartTime != nil {
			req.SetQueryParam("start_time", *options.StartTime)
		}
		if options.EndTime != nil {
			req.SetQueryParam("end_time", *options.EndTime)
		}
		if options.EventType != nil {
			req.SetQueryParam("event_type", *options.EventType)
		}
		if options.Limit != nil {
			req.SetQueryParam("limit", strconv.Itoa(*options.Limit))
		}

		var response AuditEventsResponse
		_, err := req.SetResult(&response).Get("/api/v1/audit/events")
		if err != nil {
			return nil, err
		}
		
		return response.Events, nil
	}, 1*time.Minute) // Cache audit events for only 1 minute

	if err != nil {
		return nil, err
	}

	return result.([]AuditEvent), nil
}

// Backup Methods

// CreateBackup creates a new backup
func (c *Client) CreateBackup(ctx context.Context, name string, options map[string]interface{}) (*BackupInfo, error) {
	c.logger.Infof("Creating backup: %s", name)

	requestBody := map[string]interface{}{
		"name": name,
	}
	for k, v := range options {
		requestBody[k] = v
	}

	var backup BackupInfo
	_, err := c.client.R().
		SetContext(ctx).
		SetBody(requestBody).
		SetResult(&backup).
		Post("/api/v1/backups")

	if err != nil {
		return nil, err
	}

	return &backup, nil
}

// ListBackups lists all backups
func (c *Client) ListBackups(ctx context.Context) ([]BackupInfo, error) {
	result, err := c.withCache(ctx, "backups", func() (interface{}, error) {
		c.logger.Info("Listing backups")
		
		var response BackupsResponse
		_, err := c.client.R().
			SetContext(ctx).
			SetResult(&response).
			Get("/api/v1/backups")
		
		if err != nil {
			return nil, err
		}
		
		return response.Backups, nil
	})

	if err != nil {
		return nil, err
	}

	return result.([]BackupInfo), nil
}

// RestoreBackup restores from a backup
func (c *Client) RestoreBackup(ctx context.Context, backupID string, options map[string]interface{}) error {
	c.logger.Infof("Restoring backup: %s", backupID)

	_, err := c.client.R().
		SetContext(ctx).
		SetBody(options).
		Post(fmt.Sprintf("/api/v1/backups/%s/restore", backupID))

	if err != nil {
		return err
	}

	// Clear all caches after restore
	if c.cache != nil {
		c.cache.Flush()
	}

	return nil
}

// Health and Status Methods

// HealthCheck performs a health check
func (c *Client) HealthCheck(ctx context.Context) (*VaultStatus, error) {
	c.logger.Debug("Performing health check")

	var status VaultStatus
	_, err := c.client.R().
		SetContext(ctx).
		SetResult(&status).
		Get("/api/v1/health")

	if err != nil {
		return nil, err
	}

	return &status, nil
}

// GetMetrics retrieves Prometheus metrics
func (c *Client) GetMetrics(ctx context.Context) (string, error) {
	c.logger.Debug("Getting metrics")

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeader("Accept", "text/plain").
		Get("/metrics")

	if err != nil {
		return "", err
	}

	return string(resp.Body()), nil
}

// Utility Methods

// ClearCache clears all cached data
func (c *Client) ClearCache() {
	if c.cache != nil {
		c.cache.Flush()
		c.logger.Info("Cache cleared")
	}
}

// GetCacheStats returns cache statistics
func (c *Client) GetCacheStats() map[string]interface{} {
	if c.cache == nil {
		return nil
	}

	return map[string]interface{}{
		"item_count": c.cache.ItemCount(),
	}
}

// Close closes the client and cleans up resources
func (c *Client) Close() error {
	if c.cache != nil {
		c.cache.Flush()
	}
	c.logger.Info("Client closed")
	return nil
}