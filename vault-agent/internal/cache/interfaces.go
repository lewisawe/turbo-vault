package cache

import (
	"context"
	"time"
)

// Cache defines the interface for caching implementations
type Cache interface {
	// Get retrieves a value from the cache
	Get(ctx context.Context, key string) (interface{}, bool)
	
	// Set stores a value in the cache with TTL
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	
	// Delete removes a value from the cache
	Delete(ctx context.Context, key string) error
	
	// Invalidate removes all keys matching the pattern
	Invalidate(ctx context.Context, pattern string) error
	
	// Clear removes all entries from the cache
	Clear(ctx context.Context) error
	
	// Stats returns cache statistics
	Stats() CacheStats
	
	// Close closes the cache connection
	Close() error
}

// CacheStats represents cache performance statistics
type CacheStats struct {
	Hits        int64   `json:"hits"`
	Misses      int64   `json:"misses"`
	HitRatio    float64 `json:"hit_ratio"`
	Size        int64   `json:"size"`
	MaxSize     int64   `json:"max_size"`
	Evictions   int64   `json:"evictions"`
	Errors      int64   `json:"errors"`
	LastUpdated time.Time `json:"last_updated"`
}

// CacheConfig represents cache configuration
type CacheConfig struct {
	Type         string        `yaml:"type" json:"type"`                   // memory, redis, multi
	TTL          time.Duration `yaml:"ttl" json:"ttl"`                     // Default TTL
	MaxSize      int           `yaml:"max_size" json:"max_size"`           // Max entries for memory cache
	EvictionPolicy string      `yaml:"eviction_policy" json:"eviction_policy"` // LRU, LFU, TTL
	
	// Redis configuration
	RedisURL      string `yaml:"redis_url" json:"redis_url"`
	RedisDB       int    `yaml:"redis_db" json:"redis_db"`
	RedisPassword string `yaml:"redis_password" json:"redis_password"`
	RedisPoolSize int    `yaml:"redis_pool_size" json:"redis_pool_size"`
	
	// Multi-level cache configuration
	L1Config *CacheConfig `yaml:"l1_config" json:"l1_config"` // Memory cache
	L2Config *CacheConfig `yaml:"l2_config" json:"l2_config"` // Redis cache
	
	// Performance settings
	WarmupEnabled      bool          `yaml:"warmup_enabled" json:"warmup_enabled"`
	InvalidationEvents []string      `yaml:"invalidation_events" json:"invalidation_events"`
	Compression        bool          `yaml:"compression" json:"compression"`
	Serialization      string        `yaml:"serialization" json:"serialization"` // json, gob, msgpack
}

// EvictionPolicy represents cache eviction policies
type EvictionPolicy string

const (
	EvictionPolicyLRU EvictionPolicy = "lru"
	EvictionPolicyLFU EvictionPolicy = "lfu"
	EvictionPolicyTTL EvictionPolicy = "ttl"
)

// CacheEntry represents a cached item with metadata
type CacheEntry struct {
	Key        string      `json:"key"`
	Value      interface{} `json:"value"`
	TTL        time.Duration `json:"ttl"`
	CreatedAt  time.Time   `json:"created_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	AccessedAt time.Time   `json:"accessed_at"`
	AccessCount int64      `json:"access_count"`
	Size       int64       `json:"size"`
}

// IsExpired checks if the cache entry has expired
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// CacheManager manages multiple cache instances and provides unified access
type CacheManager interface {
	// GetCache returns a cache instance by name
	GetCache(name string) Cache
	
	// RegisterCache registers a new cache instance
	RegisterCache(name string, cache Cache) error
	
	// InvalidateAll invalidates all caches
	InvalidateAll(ctx context.Context, pattern string) error
	
	// GetStats returns aggregated statistics for all caches
	GetStats() map[string]CacheStats
	
	// Close closes all cache connections
	Close() error
}