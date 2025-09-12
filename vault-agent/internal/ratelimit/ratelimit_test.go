package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenBucket(t *testing.T) {
	// Create a token bucket with 10 capacity and 5 tokens per second refill rate
	bucket := NewTokenBucket(10, 5)

	// Should allow initial requests up to capacity
	assert.True(t, bucket.Allow(5))
	assert.True(t, bucket.Allow(5))
	assert.False(t, bucket.Allow(1)) // Should be empty now

	// Wait for refill
	time.Sleep(time.Second)
	assert.True(t, bucket.Allow(5)) // Should have refilled 5 tokens

	// Test capacity and refill rate getters
	assert.Equal(t, int64(10), bucket.Capacity())
	assert.Equal(t, int64(5), bucket.RefillRate())
}

func TestTokenBucketWait(t *testing.T) {
	bucket := NewTokenBucket(1, 10) // 1 capacity, 10 tokens per second

	// Consume the token
	assert.True(t, bucket.Allow(1))

	// Wait for refill with timeout (need longer timeout for 10 tokens/sec = 100ms per token)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
	defer cancel()

	err := bucket.Wait(ctx, 1)
	assert.NoError(t, err)
}

func TestSlidingWindowRateLimiter(t *testing.T) {
	// Create a sliding window limiter: 5 requests per second
	limiter := NewSlidingWindowRateLimiter(5, time.Second)

	// Should allow initial requests
	assert.True(t, limiter.Allow(3))
	assert.True(t, limiter.Allow(2))
	assert.False(t, limiter.Allow(1)) // Should exceed limit

	// Wait for window to slide
	time.Sleep(time.Second + time.Millisecond*100)
	assert.True(t, limiter.Allow(5)) // Should allow again
}

func TestMultiKeyRateLimiter(t *testing.T) {
	config := &RateLimiterConfig{
		RequestsPerSecond: 10,
		BurstSize:         5,
		Algorithm:         "token_bucket",
	}

	limiter := NewMultiKeyRateLimiter(config)
	defer limiter.Close()

	// Test different keys
	assert.True(t, limiter.Allow("user1", 3))
	assert.True(t, limiter.Allow("user2", 3))
	assert.True(t, limiter.Allow("user1", 2))
	assert.False(t, limiter.Allow("user1", 1)) // user1 should be limited

	// user2 should still have capacity
	assert.True(t, limiter.Allow("user2", 2))

	// Test stats
	stats := limiter.Stats()
	assert.Contains(t, stats, "active_limiters")
	assert.Equal(t, 2, stats["active_limiters"])
}

func TestCircuitBreaker(t *testing.T) {
	config := &CircuitBreakerConfig{
		MaxFailures:      3,
		ResetTimeout:     time.Millisecond * 100,
		HalfOpenRequests: 2,
	}

	cb := NewCircuitBreaker(config)

	// Initially closed
	assert.Equal(t, CircuitBreakerClosed, cb.State())

	// Simulate failures
	for i := 0; i < 3; i++ {
		err := cb.Call(func() error {
			return assert.AnError
		})
		assert.Error(t, err)
	}

	// Should be open now
	assert.Equal(t, CircuitBreakerOpen, cb.State())

	// Should reject calls
	err := cb.Call(func() error {
		return nil
	})
	assert.Equal(t, ErrCircuitBreakerOpen, err)

	// Wait for reset timeout
	time.Sleep(time.Millisecond * 150)

	// Should allow limited requests (half-open)
	err = cb.Call(func() error {
		return nil
	})
	assert.NoError(t, err)

	// After successful requests, should be closed again
	err = cb.Call(func() error {
		return nil
	})
	assert.NoError(t, err)

	assert.Equal(t, CircuitBreakerClosed, cb.State())
}