package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// MemoryCache implements an in-memory cache with LRU eviction
type MemoryCache struct {
	mu             sync.RWMutex
	entries        map[string]*CacheEntry
	accessOrder    []string // For LRU tracking
	maxSize        int
	defaultTTL     time.Duration
	evictionPolicy EvictionPolicy
	stats          CacheStats
	stopCleanup    chan struct{}
	cleanupTicker  *time.Ticker
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache(config *CacheConfig) *MemoryCache {
	cache := &MemoryCache{
		entries:        make(map[string]*CacheEntry),
		accessOrder:    make([]string, 0),
		maxSize:        config.MaxSize,
		defaultTTL:     config.TTL,
		evictionPolicy: EvictionPolicy(config.EvictionPolicy),
		stats: CacheStats{
			MaxSize:     int64(config.MaxSize),
			LastUpdated: time.Now(),
		},
		stopCleanup: make(chan struct{}),
	}

	// Set default eviction policy
	if cache.evictionPolicy == "" {
		cache.evictionPolicy = EvictionPolicyLRU
	}

	// Start cleanup goroutine for expired entries
	cache.cleanupTicker = time.NewTicker(time.Minute)
	go cache.cleanupExpired()

	return cache
}

// Get retrieves a value from the cache
func (c *MemoryCache) Get(ctx context.Context, key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		c.stats.Misses++
		c.updateStats()
		return nil, false
	}

	// Check if expired
	if entry.IsExpired() {
		delete(c.entries, key)
		c.removeFromAccessOrder(key)
		c.stats.Misses++
		c.updateStats()
		return nil, false
	}

	// Update access information
	entry.AccessedAt = time.Now()
	entry.AccessCount++
	c.updateAccessOrder(key)

	c.stats.Hits++
	c.updateStats()
	return entry.Value, true
}

// Set stores a value in the cache with TTL
func (c *MemoryCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

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

	// Check if we need to evict entries
	if len(c.entries) >= c.maxSize && c.entries[key] == nil {
		c.evict()
	}

	c.entries[key] = entry
	c.updateAccessOrder(key)
	c.stats.Size = int64(len(c.entries))
	c.updateStats()

	return nil
}

// Delete removes a value from the cache
func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[key]; exists {
		delete(c.entries, key)
		c.removeFromAccessOrder(key)
		c.stats.Size = int64(len(c.entries))
		c.updateStats()
	}

	return nil
}

// Invalidate removes all keys matching the pattern
func (c *MemoryCache) Invalidate(ctx context.Context, pattern string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	regex, err := regexp.Compile(pattern)
	if err != nil {
		c.stats.Errors++
		c.updateStats()
		return fmt.Errorf("invalid pattern: %w", err)
	}

	keysToDelete := make([]string, 0)
	for key := range c.entries {
		if regex.MatchString(key) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		delete(c.entries, key)
		c.removeFromAccessOrder(key)
	}

	c.stats.Size = int64(len(c.entries))
	c.updateStats()
	return nil
}

// Clear removes all entries from the cache
func (c *MemoryCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CacheEntry)
	c.accessOrder = make([]string, 0)
	c.stats.Size = 0
	c.updateStats()

	return nil
}

// Stats returns cache statistics
func (c *MemoryCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// Close closes the cache and stops cleanup goroutines
func (c *MemoryCache) Close() error {
	close(c.stopCleanup)
	if c.cleanupTicker != nil {
		c.cleanupTicker.Stop()
	}
	return nil
}

// evict removes entries based on the eviction policy
func (c *MemoryCache) evict() {
	switch c.evictionPolicy {
	case EvictionPolicyLRU:
		c.evictLRU()
	case EvictionPolicyLFU:
		c.evictLFU()
	case EvictionPolicyTTL:
		c.evictTTL()
	default:
		c.evictLRU()
	}
}

// evictLRU removes the least recently used entry
func (c *MemoryCache) evictLRU() {
	if len(c.accessOrder) > 0 {
		key := c.accessOrder[0]
		delete(c.entries, key)
		c.accessOrder = c.accessOrder[1:]
		c.stats.Evictions++
	}
}

// evictLFU removes the least frequently used entry
func (c *MemoryCache) evictLFU() {
	var minKey string
	var minCount int64 = -1

	for key, entry := range c.entries {
		if minCount == -1 || entry.AccessCount < minCount {
			minCount = entry.AccessCount
			minKey = key
		}
	}

	if minKey != "" {
		delete(c.entries, minKey)
		c.removeFromAccessOrder(minKey)
		c.stats.Evictions++
	}
}

// evictTTL removes the entry that expires soonest
func (c *MemoryCache) evictTTL() {
	var minKey string
	var minExpiry time.Time

	for key, entry := range c.entries {
		if minKey == "" || entry.ExpiresAt.Before(minExpiry) {
			minExpiry = entry.ExpiresAt
			minKey = key
		}
	}

	if minKey != "" {
		delete(c.entries, minKey)
		c.removeFromAccessOrder(minKey)
		c.stats.Evictions++
	}
}

// updateAccessOrder updates the access order for LRU tracking
func (c *MemoryCache) updateAccessOrder(key string) {
	// Remove key from current position
	c.removeFromAccessOrder(key)
	// Add to end (most recently used)
	c.accessOrder = append(c.accessOrder, key)
}

// removeFromAccessOrder removes a key from the access order list
func (c *MemoryCache) removeFromAccessOrder(key string) {
	for i, k := range c.accessOrder {
		if k == key {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			break
		}
	}
}

// calculateSize estimates the size of a value in bytes
func (c *MemoryCache) calculateSize(value interface{}) int64 {
	// Simple size estimation using JSON marshaling
	data, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	return int64(len(data))
}

// updateStats updates cache statistics
func (c *MemoryCache) updateStats() {
	c.stats.LastUpdated = time.Now()
	if c.stats.Hits+c.stats.Misses > 0 {
		c.stats.HitRatio = float64(c.stats.Hits) / float64(c.stats.Hits+c.stats.Misses)
	}
}

// cleanupExpired removes expired entries periodically
func (c *MemoryCache) cleanupExpired() {
	for {
		select {
		case <-c.cleanupTicker.C:
			c.mu.Lock()
			now := time.Now()
			keysToDelete := make([]string, 0)

			for key, entry := range c.entries {
				if now.After(entry.ExpiresAt) {
					keysToDelete = append(keysToDelete, key)
				}
			}

			for _, key := range keysToDelete {
				delete(c.entries, key)
				c.removeFromAccessOrder(key)
			}

			c.stats.Size = int64(len(c.entries))
			c.updateStats()
			c.mu.Unlock()

		case <-c.stopCleanup:
			return
		}
	}
}