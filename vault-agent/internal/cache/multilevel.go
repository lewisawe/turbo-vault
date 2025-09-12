package cache

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MultiLevelCache implements a multi-level cache with L1 (memory) and L2 (Redis) tiers
type MultiLevelCache struct {
	l1Cache Cache // Memory cache (fast, small)
	l2Cache Cache // Redis cache (slower, larger)
	stats   CacheStats
	statsMu sync.RWMutex
}

// NewMultiLevelCache creates a new multi-level cache
func NewMultiLevelCache(config *CacheConfig) (*MultiLevelCache, error) {
	if config.L1Config == nil || config.L2Config == nil {
		return nil, fmt.Errorf("both L1 and L2 configurations are required for multi-level cache")
	}

	// Create L1 cache (memory)
	l1Cache := NewMemoryCache(config.L1Config)

	// Create L2 cache (Redis)
	l2Cache, err := NewRedisCache(config.L2Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create L2 cache: %w", err)
	}

	return &MultiLevelCache{
		l1Cache: l1Cache,
		l2Cache: l2Cache,
		stats: CacheStats{
			LastUpdated: time.Now(),
		},
	}, nil
}

// Get retrieves a value from the cache, checking L1 first, then L2
func (c *MultiLevelCache) Get(ctx context.Context, key string) (interface{}, bool) {
	// Try L1 cache first
	if value, found := c.l1Cache.Get(ctx, key); found {
		c.updateStats(true, false, "l1")
		return value, true
	}

	// Try L2 cache
	if value, found := c.l2Cache.Get(ctx, key); found {
		// Promote to L1 cache for faster future access
		go func() {
			// Use a background context to avoid blocking
			bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c.l1Cache.Set(bgCtx, key, value, time.Hour) // Use shorter TTL for L1
		}()
		
		c.updateStats(true, false, "l2")
		return value, true
	}

	c.updateStats(false, false, "miss")
	return nil, false
}

// Set stores a value in both cache levels
func (c *MultiLevelCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	var errs []error

	// Set in L1 cache with shorter TTL (memory is more limited)
	l1TTL := ttl
	if ttl > time.Hour {
		l1TTL = time.Hour
	}
	if err := c.l1Cache.Set(ctx, key, value, l1TTL); err != nil {
		errs = append(errs, fmt.Errorf("L1 cache error: %w", err))
		c.updateStats(false, true, "l1")
	}

	// Set in L2 cache with full TTL
	if err := c.l2Cache.Set(ctx, key, value, ttl); err != nil {
		errs = append(errs, fmt.Errorf("L2 cache error: %w", err))
		c.updateStats(false, true, "l2")
	}

	if len(errs) > 0 {
		return fmt.Errorf("cache errors: %v", errs)
	}

	return nil
}

// Delete removes a value from both cache levels
func (c *MultiLevelCache) Delete(ctx context.Context, key string) error {
	var errs []error

	// Delete from L1 cache
	if err := c.l1Cache.Delete(ctx, key); err != nil {
		errs = append(errs, fmt.Errorf("L1 cache error: %w", err))
		c.updateStats(false, true, "l1")
	}

	// Delete from L2 cache
	if err := c.l2Cache.Delete(ctx, key); err != nil {
		errs = append(errs, fmt.Errorf("L2 cache error: %w", err))
		c.updateStats(false, true, "l2")
	}

	if len(errs) > 0 {
		return fmt.Errorf("cache errors: %v", errs)
	}

	return nil
}

// Invalidate removes all keys matching the pattern from both cache levels
func (c *MultiLevelCache) Invalidate(ctx context.Context, pattern string) error {
	var errs []error

	// Invalidate L1 cache
	if err := c.l1Cache.Invalidate(ctx, pattern); err != nil {
		errs = append(errs, fmt.Errorf("L1 cache error: %w", err))
		c.updateStats(false, true, "l1")
	}

	// Invalidate L2 cache
	if err := c.l2Cache.Invalidate(ctx, pattern); err != nil {
		errs = append(errs, fmt.Errorf("L2 cache error: %w", err))
		c.updateStats(false, true, "l2")
	}

	if len(errs) > 0 {
		return fmt.Errorf("cache errors: %v", errs)
	}

	return nil
}

// Clear removes all entries from both cache levels
func (c *MultiLevelCache) Clear(ctx context.Context) error {
	var errs []error

	// Clear L1 cache
	if err := c.l1Cache.Clear(ctx); err != nil {
		errs = append(errs, fmt.Errorf("L1 cache error: %w", err))
		c.updateStats(false, true, "l1")
	}

	// Clear L2 cache
	if err := c.l2Cache.Clear(ctx); err != nil {
		errs = append(errs, fmt.Errorf("L2 cache error: %w", err))
		c.updateStats(false, true, "l2")
	}

	if len(errs) > 0 {
		return fmt.Errorf("cache errors: %v", errs)
	}

	return nil
}

// Stats returns aggregated cache statistics
func (c *MultiLevelCache) Stats() CacheStats {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()

	// Get stats from both levels
	l1Stats := c.l1Cache.Stats()
	l2Stats := c.l2Cache.Stats()

	// Aggregate stats
	aggregated := c.stats
	aggregated.Hits = l1Stats.Hits + l2Stats.Hits
	aggregated.Misses = l1Stats.Misses + l2Stats.Misses
	aggregated.Errors = l1Stats.Errors + l2Stats.Errors
	aggregated.Evictions = l1Stats.Evictions + l2Stats.Evictions
	aggregated.Size = l1Stats.Size + l2Stats.Size

	if aggregated.Hits+aggregated.Misses > 0 {
		aggregated.HitRatio = float64(aggregated.Hits) / float64(aggregated.Hits+aggregated.Misses)
	}

	return aggregated
}

// GetL1Stats returns L1 cache statistics
func (c *MultiLevelCache) GetL1Stats() CacheStats {
	return c.l1Cache.Stats()
}

// GetL2Stats returns L2 cache statistics
func (c *MultiLevelCache) GetL2Stats() CacheStats {
	return c.l2Cache.Stats()
}

// Close closes both cache levels
func (c *MultiLevelCache) Close() error {
	var errs []error

	if err := c.l1Cache.Close(); err != nil {
		errs = append(errs, fmt.Errorf("L1 cache error: %w", err))
	}

	if err := c.l2Cache.Close(); err != nil {
		errs = append(errs, fmt.Errorf("L2 cache error: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("cache errors: %v", errs)
	}

	return nil
}

// WarmUp pre-loads frequently accessed data into the cache
func (c *MultiLevelCache) WarmUp(ctx context.Context, data map[string]interface{}) error {
	for key, value := range data {
		if err := c.Set(ctx, key, value, time.Hour); err != nil {
			return fmt.Errorf("failed to warm up key %s: %w", key, err)
		}
	}
	return nil
}

// updateStats updates internal statistics
func (c *MultiLevelCache) updateStats(hit bool, error bool, level string) {
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