package policy

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// MemoryPolicyCache implements PolicyCache using in-memory storage
type MemoryPolicyCache struct {
	cache   map[string]*cacheEntry
	mu      sync.RWMutex
	config  *CacheConfig
	logger  *logrus.Logger
	stats   *CacheStats
	janitor *janitor
}

// CacheConfig contains cache configuration
type CacheConfig struct {
	MaxSize      int           `json:"max_size"`
	DefaultTTL   time.Duration `json:"default_ttl"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
	EvictionPolicy string       `json:"eviction_policy"` // LRU, LFU, TTL
}

// cacheEntry represents a cached policy with metadata
type cacheEntry struct {
	policy    *Policy
	expiry    time.Time
	accessCount int64
	lastAccess time.Time
	size      int64
}

// janitor handles cache cleanup
type janitor struct {
	interval time.Duration
	stop     chan bool
}

// NewMemoryPolicyCache creates a new in-memory policy cache
func NewMemoryPolicyCache(config *CacheConfig, logger *logrus.Logger) *MemoryPolicyCache {
	if config == nil {
		config = DefaultCacheConfig()
	}

	cache := &MemoryPolicyCache{
		cache:  make(map[string]*cacheEntry),
		config: config,
		logger: logger,
		stats: &CacheStats{
			MaxSize: config.MaxSize,
		},
	}

	// Start cleanup janitor
	if config.CleanupInterval > 0 {
		cache.janitor = &janitor{
			interval: config.CleanupInterval,
			stop:     make(chan bool),
		}
		go cache.janitor.run(cache)
	}

	return cache
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		MaxSize:         1000,
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
		EvictionPolicy:  "LRU",
	}
}

// Get retrieves a policy from the cache
func (c *MemoryPolicyCache) Get(ctx context.Context, key string) (*Policy, bool) {
	c.mu.RLock()
	entry, exists := c.cache[key]
	c.mu.RUnlock()

	if !exists {
		c.stats.incrementMisses()
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.expiry) {
		c.mu.Lock()
		delete(c.cache, key)
		c.mu.Unlock()
		c.stats.incrementMisses()
		c.stats.incrementEvictions()
		return nil, false
	}

	// Update access statistics
	c.mu.Lock()
	entry.accessCount++
	entry.lastAccess = time.Now()
	c.mu.Unlock()

	c.stats.incrementHits()
	return entry.policy, true
}

// Set stores a policy in the cache
func (c *MemoryPolicyCache) Set(ctx context.Context, key string, policy *Policy, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = c.config.DefaultTTL
	}

	entry := &cacheEntry{
		policy:      policy,
		expiry:      time.Now().Add(ttl),
		accessCount: 0,
		lastAccess:  time.Now(),
		size:        c.calculatePolicySize(policy),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict entries
	if len(c.cache) >= c.config.MaxSize {
		c.evictEntries(1)
	}

	c.cache[key] = entry
	c.updateStats()

	c.logger.WithFields(logrus.Fields{
		"key":    key,
		"ttl":    ttl,
		"size":   entry.size,
		"expiry": entry.expiry,
	}).Debug("Policy cached")

	return nil
}

// Delete removes a policy from the cache
func (c *MemoryPolicyCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.cache[key]; exists {
		delete(c.cache, key)
		c.updateStats()
		c.logger.WithField("key", key).Debug("Policy removed from cache")
	}

	return nil
}

// Clear removes all policies from the cache
func (c *MemoryPolicyCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*cacheEntry)
	c.updateStats()
	c.logger.Info("Policy cache cleared")

	return nil
}

// Stats returns cache statistics
func (c *MemoryPolicyCache) Stats() *CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Calculate hit rate
	total := c.stats.Hits + c.stats.Misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(c.stats.Hits) / float64(total)
	}

	return &CacheStats{
		Hits:        c.stats.Hits,
		Misses:      c.stats.Misses,
		Evictions:   c.stats.Evictions,
		Size:        len(c.cache),
		MaxSize:     c.config.MaxSize,
		HitRate:     hitRate,
		MemoryUsage: c.calculateMemoryUsage(),
	}
}

// Close stops the cache janitor
func (c *MemoryPolicyCache) Close() error {
	if c.janitor != nil {
		c.janitor.stop <- true
	}
	return nil
}

// Helper methods

func (c *MemoryPolicyCache) evictEntries(count int) {
	if len(c.cache) == 0 {
		return
	}

	switch c.config.EvictionPolicy {
	case "LRU":
		c.evictLRU(count)
	case "LFU":
		c.evictLFU(count)
	case "TTL":
		c.evictTTL(count)
	default:
		c.evictLRU(count) // Default to LRU
	}
}

func (c *MemoryPolicyCache) evictLRU(count int) {
	type keyTime struct {
		key        string
		lastAccess time.Time
	}

	var entries []keyTime
	for key, entry := range c.cache {
		entries = append(entries, keyTime{key: key, lastAccess: entry.lastAccess})
	}

	// Sort by last access time (oldest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].lastAccess.After(entries[j].lastAccess) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Evict oldest entries
	evicted := 0
	for _, entry := range entries {
		if evicted >= count {
			break
		}
		delete(c.cache, entry.key)
		evicted++
		c.stats.incrementEvictions()
	}

	c.logger.WithField("evicted", evicted).Debug("LRU eviction completed")
}

func (c *MemoryPolicyCache) evictLFU(count int) {
	type keyCount struct {
		key         string
		accessCount int64
	}

	var entries []keyCount
	for key, entry := range c.cache {
		entries = append(entries, keyCount{key: key, accessCount: entry.accessCount})
	}

	// Sort by access count (least accessed first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].accessCount > entries[j].accessCount {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Evict least frequently used entries
	evicted := 0
	for _, entry := range entries {
		if evicted >= count {
			break
		}
		delete(c.cache, entry.key)
		evicted++
		c.stats.incrementEvictions()
	}

	c.logger.WithField("evicted", evicted).Debug("LFU eviction completed")
}

func (c *MemoryPolicyCache) evictTTL(count int) {
	type keyExpiry struct {
		key    string
		expiry time.Time
	}

	var entries []keyExpiry
	for key, entry := range c.cache {
		entries = append(entries, keyExpiry{key: key, expiry: entry.expiry})
	}

	// Sort by expiry time (earliest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].expiry.After(entries[j].expiry) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Evict entries with earliest expiry
	evicted := 0
	for _, entry := range entries {
		if evicted >= count {
			break
		}
		delete(c.cache, entry.key)
		evicted++
		c.stats.incrementEvictions()
	}

	c.logger.WithField("evicted", evicted).Debug("TTL eviction completed")
}

func (c *MemoryPolicyCache) cleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var expiredKeys []string

	for key, entry := range c.cache {
		if now.After(entry.expiry) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(c.cache, key)
		c.stats.incrementEvictions()
	}

	if len(expiredKeys) > 0 {
		c.updateStats()
		c.logger.WithField("expired", len(expiredKeys)).Debug("Expired entries cleaned up")
	}
}

func (c *MemoryPolicyCache) calculatePolicySize(policy *Policy) int64 {
	// Rough estimation of policy size in bytes
	size := int64(len(policy.ID) + len(policy.Name) + len(policy.Description) + len(policy.CreatedBy))
	
	// Add size of rules
	for _, rule := range policy.Rules {
		size += int64(len(rule.ID) + len(rule.Resource) + len(rule.Description))
		for _, action := range rule.Actions {
			size += int64(len(action))
		}
		for _, principal := range rule.Principals {
			size += int64(len(principal))
		}
		size += int64(len(rule.Conditions) * 100) // Rough estimate for conditions
	}

	// Add size of conditions and actions
	size += int64(len(policy.Conditions) * 100)
	size += int64(len(policy.Actions) * 50)

	// Add size of tags and metadata
	for _, tag := range policy.Tags {
		size += int64(len(tag))
	}
	for key, value := range policy.Metadata {
		size += int64(len(key) + len(value))
	}

	return size
}

func (c *MemoryPolicyCache) calculateMemoryUsage() int64 {
	var totalSize int64
	for _, entry := range c.cache {
		totalSize += entry.size
	}
	return totalSize
}

func (c *MemoryPolicyCache) updateStats() {
	// Update size in stats
	// Other stats are updated in real-time by increment methods
}

// Statistics methods

func (s *CacheStats) incrementHits() {
	// In a real implementation, you'd use atomic operations
	s.Hits++
}

func (s *CacheStats) incrementMisses() {
	s.Misses++
}

func (s *CacheStats) incrementEvictions() {
	s.Evictions++
}

// Janitor implementation

func (j *janitor) run(cache *MemoryPolicyCache) {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cache.cleanupExpired()
		case <-j.stop:
			return
		}
	}
}

// RedisPolicyCache implements PolicyCache using Redis (placeholder for future implementation)
type RedisPolicyCache struct {
	// Redis client would go here
	logger *logrus.Logger
}

// NewRedisPolicyCache creates a new Redis-based policy cache
func NewRedisPolicyCache(logger *logrus.Logger) *RedisPolicyCache {
	return &RedisPolicyCache{
		logger: logger,
	}
}

// Placeholder implementations for Redis cache
func (r *RedisPolicyCache) Get(ctx context.Context, key string) (*Policy, bool) {
	// TODO: Implement Redis get
	return nil, false
}

func (r *RedisPolicyCache) Set(ctx context.Context, key string, policy *Policy, ttl time.Duration) error {
	// TODO: Implement Redis set
	return nil
}

func (r *RedisPolicyCache) Delete(ctx context.Context, key string) error {
	// TODO: Implement Redis delete
	return nil
}

func (r *RedisPolicyCache) Clear(ctx context.Context) error {
	// TODO: Implement Redis clear
	return nil
}

func (r *RedisPolicyCache) Stats() *CacheStats {
	// TODO: Implement Redis stats
	return &CacheStats{}
}

// CacheFactory creates cache instances based on configuration
type CacheFactory struct {
	logger *logrus.Logger
}

// NewCacheFactory creates a new cache factory
func NewCacheFactory(logger *logrus.Logger) *CacheFactory {
	return &CacheFactory{
		logger: logger,
	}
}

// CreateCache creates a cache instance based on the specified type
func (f *CacheFactory) CreateCache(cacheType string, config *CacheConfig) PolicyCache {
	switch cacheType {
	case "memory":
		return NewMemoryPolicyCache(config, f.logger)
	case "redis":
		return NewRedisPolicyCache(f.logger)
	default:
		f.logger.WithField("type", cacheType).Warn("Unknown cache type, defaulting to memory")
		return NewMemoryPolicyCache(config, f.logger)
	}
}