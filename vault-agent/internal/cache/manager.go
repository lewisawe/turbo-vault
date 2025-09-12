package cache

import (
	"context"
	"fmt"
	"sync"
)

// DefaultCacheManager implements the CacheManager interface
type DefaultCacheManager struct {
	caches map[string]Cache
	mu     sync.RWMutex
}

// NewCacheManager creates a new cache manager
func NewCacheManager() *DefaultCacheManager {
	return &DefaultCacheManager{
		caches: make(map[string]Cache),
	}
}

// GetCache returns a cache instance by name
func (m *DefaultCacheManager) GetCache(name string) Cache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.caches[name]
}

// RegisterCache registers a new cache instance
func (m *DefaultCacheManager) RegisterCache(name string, cache Cache) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.caches[name]; exists {
		return fmt.Errorf("cache with name %s already exists", name)
	}

	m.caches[name] = cache
	return nil
}

// InvalidateAll invalidates all caches with the given pattern
func (m *DefaultCacheManager) InvalidateAll(ctx context.Context, pattern string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error
	for name, cache := range m.caches {
		if err := cache.Invalidate(ctx, pattern); err != nil {
			errs = append(errs, fmt.Errorf("cache %s: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalidation errors: %v", errs)
	}

	return nil
}

// GetStats returns aggregated statistics for all caches
func (m *DefaultCacheManager) GetStats() map[string]CacheStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]CacheStats)
	for name, cache := range m.caches {
		stats[name] = cache.Stats()
	}

	return stats
}

// Close closes all cache connections
func (m *DefaultCacheManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for name, cache := range m.caches {
		if err := cache.Close(); err != nil {
			errs = append(errs, fmt.Errorf("cache %s: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}

	return nil
}

// CreateCache creates a cache instance based on configuration
func CreateCache(config *CacheConfig) (Cache, error) {
	switch config.Type {
	case "memory":
		return NewMemoryCache(config), nil
	case "redis":
		return NewRedisCache(config)
	case "multi":
		return NewMultiLevelCache(config)
	default:
		return nil, fmt.Errorf("unsupported cache type: %s", config.Type)
	}
}