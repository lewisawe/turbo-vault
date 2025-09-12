package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryCache(t *testing.T) {
	config := &CacheConfig{
		Type:           "memory",
		TTL:            time.Minute,
		MaxSize:        100,
		EvictionPolicy: "lru",
	}

	cache := NewMemoryCache(config)
	defer cache.Close()

	ctx := context.Background()

	// Test Set and Get
	err := cache.Set(ctx, "key1", "value1", time.Minute)
	require.NoError(t, err)

	value, found := cache.Get(ctx, "key1")
	assert.True(t, found)
	assert.Equal(t, "value1", value)

	// Test cache miss
	_, found = cache.Get(ctx, "nonexistent")
	assert.False(t, found)

	// Test Delete
	err = cache.Delete(ctx, "key1")
	require.NoError(t, err)

	_, found = cache.Get(ctx, "key1")
	assert.False(t, found)

	// Test TTL expiration
	err = cache.Set(ctx, "key2", "value2", time.Millisecond*100)
	require.NoError(t, err)

	value, found = cache.Get(ctx, "key2")
	assert.True(t, found)
	assert.Equal(t, "value2", value)

	// Wait for expiration
	time.Sleep(time.Millisecond * 150)

	_, found = cache.Get(ctx, "key2")
	assert.False(t, found)

	// Test stats
	stats := cache.Stats()
	assert.Greater(t, stats.Hits, int64(0))
	assert.Greater(t, stats.Misses, int64(0))
}

func TestCacheManager(t *testing.T) {
	manager := NewCacheManager()
	defer manager.Close()

	config := &CacheConfig{
		Type:    "memory",
		TTL:     time.Minute,
		MaxSize: 100,
	}

	cache := NewMemoryCache(config)
	
	// Register cache
	err := manager.RegisterCache("test", cache)
	require.NoError(t, err)

	// Get cache
	retrievedCache := manager.GetCache("test")
	assert.NotNil(t, retrievedCache)

	// Test duplicate registration
	err = manager.RegisterCache("test", cache)
	assert.Error(t, err)

	// Test stats
	stats := manager.GetStats()
	assert.Contains(t, stats, "test")
}