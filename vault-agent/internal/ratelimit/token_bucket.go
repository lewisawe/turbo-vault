package ratelimit

import (
	"context"
	"sync"
	"time"
)

// TokenBucket implements the token bucket rate limiting algorithm
type TokenBucket struct {
	capacity     int64         // Maximum number of tokens
	tokens       int64         // Current number of tokens
	refillRate   int64         // Tokens added per second
	lastRefill   time.Time     // Last time tokens were added
	mu           sync.Mutex    // Mutex for thread safety
}

// NewTokenBucket creates a new token bucket rate limiter
func NewTokenBucket(capacity, refillRate int64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity, // Start with full bucket
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed and consumes tokens if so
func (tb *TokenBucket) Allow(tokens int64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= tokens {
		tb.tokens -= tokens
		return true
	}

	return false
}

// AllowN checks if N requests are allowed and consumes tokens if so
func (tb *TokenBucket) AllowN(n int64) bool {
	return tb.Allow(n)
}

// Wait waits until tokens are available or context is cancelled
func (tb *TokenBucket) Wait(ctx context.Context, tokens int64) error {
	for {
		if tb.Allow(tokens) {
			return nil
		}

		// Calculate wait time based on refill rate (time per token)
		waitTime := time.Duration(float64(time.Second) / float64(tb.refillRate))
		
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
			// Continue to next iteration
		}
	}
}

// Tokens returns the current number of available tokens
func (tb *TokenBucket) Tokens() int64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	tb.refill()
	return tb.tokens
}

// Capacity returns the bucket capacity
func (tb *TokenBucket) Capacity() int64 {
	return tb.capacity
}

// RefillRate returns the refill rate (tokens per second)
func (tb *TokenBucket) RefillRate() int64 {
	return tb.refillRate
}

// refill adds tokens based on elapsed time (must be called with lock held)
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	
	if elapsed <= 0 {
		return
	}

	// Calculate tokens to add based on elapsed time (more precise calculation)
	tokensToAdd := int64(elapsed.Seconds() * float64(tb.refillRate))
	
	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}
}

// RateLimiter defines the interface for rate limiting implementations
type RateLimiter interface {
	Allow(tokens int64) bool
	AllowN(n int64) bool
	Wait(ctx context.Context, tokens int64) error
	Tokens() int64
}

// RateLimiterConfig contains rate limiter configuration
type RateLimiterConfig struct {
	RequestsPerSecond int64         `yaml:"requests_per_second" json:"requests_per_second"`
	BurstSize         int64         `yaml:"burst_size" json:"burst_size"`
	WindowSize        time.Duration `yaml:"window_size" json:"window_size"`
	Algorithm         string        `yaml:"algorithm" json:"algorithm"` // token_bucket, sliding_window
}

// MultiKeyRateLimiter manages rate limiters for multiple keys (e.g., per-user, per-IP)
type MultiKeyRateLimiter struct {
	limiters map[string]RateLimiter
	config   *RateLimiterConfig
	mu       sync.RWMutex
	cleanup  *time.Ticker
	stop     chan struct{}
}

// NewMultiKeyRateLimiter creates a new multi-key rate limiter
func NewMultiKeyRateLimiter(config *RateLimiterConfig) *MultiKeyRateLimiter {
	limiter := &MultiKeyRateLimiter{
		limiters: make(map[string]RateLimiter),
		config:   config,
		cleanup:  time.NewTicker(time.Minute),
		stop:     make(chan struct{}),
	}

	// Start cleanup goroutine to remove unused limiters
	go limiter.cleanupLoop()

	return limiter
}

// Allow checks if a request is allowed for the given key
func (ml *MultiKeyRateLimiter) Allow(key string, tokens int64) bool {
	limiter := ml.getLimiter(key)
	return limiter.Allow(tokens)
}

// AllowN checks if N requests are allowed for the given key
func (ml *MultiKeyRateLimiter) AllowN(key string, n int64) bool {
	limiter := ml.getLimiter(key)
	return limiter.AllowN(n)
}

// Wait waits until tokens are available for the given key
func (ml *MultiKeyRateLimiter) Wait(ctx context.Context, key string, tokens int64) error {
	limiter := ml.getLimiter(key)
	return limiter.Wait(ctx, tokens)
}

// Tokens returns available tokens for the given key
func (ml *MultiKeyRateLimiter) Tokens(key string) int64 {
	limiter := ml.getLimiter(key)
	return limiter.Tokens()
}

// getLimiter gets or creates a rate limiter for the given key
func (ml *MultiKeyRateLimiter) getLimiter(key string) RateLimiter {
	ml.mu.RLock()
	limiter, exists := ml.limiters[key]
	ml.mu.RUnlock()

	if exists {
		return limiter
	}

	ml.mu.Lock()
	defer ml.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := ml.limiters[key]; exists {
		return limiter
	}

	// Create new limiter based on algorithm
	switch ml.config.Algorithm {
	case "sliding_window":
		limiter = NewSlidingWindowRateLimiter(ml.config.RequestsPerSecond, ml.config.WindowSize)
	default: // token_bucket
		limiter = NewTokenBucket(ml.config.BurstSize, ml.config.RequestsPerSecond)
	}

	ml.limiters[key] = limiter
	return limiter
}

// cleanupLoop removes unused rate limiters periodically
func (ml *MultiKeyRateLimiter) cleanupLoop() {
	for {
		select {
		case <-ml.cleanup.C:
			ml.cleanupUnusedLimiters()
		case <-ml.stop:
			return
		}
	}
}

// cleanupUnusedLimiters removes limiters that haven't been used recently
func (ml *MultiKeyRateLimiter) cleanupUnusedLimiters() {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	// Simple cleanup: remove limiters with full token buckets
	// In a production system, you'd track last access time
	for key, limiter := range ml.limiters {
		if tb, ok := limiter.(*TokenBucket); ok {
			if tb.Tokens() == tb.Capacity() {
				delete(ml.limiters, key)
			}
		}
	}
}

// Close stops the cleanup goroutine
func (ml *MultiKeyRateLimiter) Close() {
	close(ml.stop)
	ml.cleanup.Stop()
}

// Stats returns rate limiter statistics
func (ml *MultiKeyRateLimiter) Stats() map[string]interface{} {
	ml.mu.RLock()
	defer ml.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["active_limiters"] = len(ml.limiters)
	stats["config"] = ml.config

	return stats
}