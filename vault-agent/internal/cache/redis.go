package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisCache implements a Redis-based cache
type RedisCache struct {
	client     *redis.Client
	defaultTTL time.Duration
	stats      CacheStats
	statsMu    sync.RWMutex
	keyPrefix  string
}

// NewRedisCache creates a new Redis cache
func NewRedisCache(config *CacheConfig) (*RedisCache, error) {
	opts, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	if config.RedisPassword != "" {
		opts.Password = config.RedisPassword
	}
	if config.RedisDB > 0 {
		opts.DB = config.RedisDB
	}
	if config.RedisPoolSize > 0 {
		opts.PoolSize = config.RedisPoolSize
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	cache := &RedisCache{
		client:     client,
		defaultTTL: config.TTL,
		stats: CacheStats{
			LastUpdated: time.Now(),
		},
		keyPrefix: "vault_cache:",
	}

	return cache, nil
}

// Get retrieves a value from the cache
func (c *RedisCache) Get(ctx context.Context, key string) (interface{}, bool) {
	fullKey := c.keyPrefix + key
	
	data, err := c.client.Get(ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			c.updateStats(false, false)
			return nil, false
		}
		c.updateStats(false, true)
		return nil, false
	}

	var entry CacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		c.updateStats(false, true)
		return nil, false
	}

	// Check if expired (Redis should handle this, but double-check)
	if entry.IsExpired() {
		c.client.Del(ctx, fullKey)
		c.updateStats(false, false)
		return nil, false
	}

	// Update access information
	entry.AccessedAt = time.Now()
	entry.AccessCount++
	
	// Store updated entry back to Redis
	updatedData, _ := json.Marshal(entry)
	c.client.Set(ctx, fullKey, updatedData, time.Until(entry.ExpiresAt))

	c.updateStats(true, false)
	return entry.Value, true
}

// Set stores a value in the cache with TTL
func (c *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	now := time.Now()
	entry := &CacheEntry{
		Key:         key,
		Value:       value,
		TTL:         ttl,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		AccessedAt:  now,
		AccessCount: 0,
		Size:        c.calculateSize(value),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		c.updateStats(false, true)
		return fmt.Errorf("failed to marshal cache entry: %w", err)
	}

	fullKey := c.keyPrefix + key
	if err := c.client.Set(ctx, fullKey, data, ttl).Err(); err != nil {
		c.updateStats(false, true)
		return fmt.Errorf("failed to set cache entry: %w", err)
	}

	return nil
}

// Delete removes a value from the cache
func (c *RedisCache) Delete(ctx context.Context, key string) error {
	fullKey := c.keyPrefix + key
	if err := c.client.Del(ctx, fullKey).Err(); err != nil {
		c.updateStats(false, true)
		return fmt.Errorf("failed to delete cache entry: %w", err)
	}
	return nil
}

// Invalidate removes all keys matching the pattern
func (c *RedisCache) Invalidate(ctx context.Context, pattern string) error {
	// Validate regex pattern
	_, err := regexp.Compile(pattern)
	if err != nil {
		c.updateStats(false, true)
		return fmt.Errorf("invalid pattern: %w", err)
	}

	// Convert regex pattern to Redis pattern (simplified)
	redisPattern := c.keyPrefix + pattern
	if pattern == ".*" {
		redisPattern = c.keyPrefix + "*"
	}

	// Get all matching keys
	keys, err := c.client.Keys(ctx, redisPattern).Result()
	if err != nil {
		c.updateStats(false, true)
		return fmt.Errorf("failed to get keys: %w", err)
	}

	if len(keys) == 0 {
		return nil
	}

	// Delete all matching keys
	if err := c.client.Del(ctx, keys...).Err(); err != nil {
		c.updateStats(false, true)
		return fmt.Errorf("failed to delete keys: %w", err)
	}

	return nil
}

// Clear removes all entries from the cache
func (c *RedisCache) Clear(ctx context.Context) error {
	pattern := c.keyPrefix + "*"
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		c.updateStats(false, true)
		return fmt.Errorf("failed to get keys: %w", err)
	}

	if len(keys) == 0 {
		return nil
	}

	if err := c.client.Del(ctx, keys...).Err(); err != nil {
		c.updateStats(false, true)
		return fmt.Errorf("failed to clear cache: %w", err)
	}

	return nil
}

// Stats returns cache statistics
func (c *RedisCache) Stats() CacheStats {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()
	
	// Get Redis info for additional stats
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	info, err := c.client.Info(ctx, "memory").Result()
	if err == nil {
		// Parse memory usage from Redis info (simplified)
		// In a real implementation, you'd parse the info string properly
		_ = info
	}

	return c.stats
}

// Close closes the Redis connection
func (c *RedisCache) Close() error {
	return c.client.Close()
}

// calculateSize estimates the size of a value in bytes
func (c *RedisCache) calculateSize(value interface{}) int64 {
	data, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	return int64(len(data))
}

// updateStats updates cache statistics
func (c *RedisCache) updateStats(hit bool, error bool) {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()

	if hit {
		c.stats.Hits++
	} else {
		c.stats.Misses++
	}

	if error {
		c.stats.Errors++
	}

	c.stats.LastUpdated = time.Now()
	if c.stats.Hits+c.stats.Misses > 0 {
		c.stats.HitRatio = float64(c.stats.Hits) / float64(c.stats.Hits+c.stats.Misses)
	}
}