package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SlidingWindowRateLimiter implements a sliding window rate limiter
type SlidingWindowRateLimiter struct {
	limit      int64         // Maximum requests per window
	window     time.Duration // Window duration
	requests   []time.Time   // Timestamps of requests
	mu         sync.Mutex    // Mutex for thread safety
}

// NewSlidingWindowRateLimiter creates a new sliding window rate limiter
func NewSlidingWindowRateLimiter(limit int64, window time.Duration) *SlidingWindowRateLimiter {
	return &SlidingWindowRateLimiter{
		limit:    limit,
		window:   window,
		requests: make([]time.Time, 0),
	}
}

// Allow checks if a request is allowed
func (sw *SlidingWindowRateLimiter) Allow(tokens int64) bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	sw.cleanup(now)

	if int64(len(sw.requests))+tokens <= sw.limit {
		// Add tokens number of requests
		for i := int64(0); i < tokens; i++ {
			sw.requests = append(sw.requests, now)
		}
		return true
	}

	return false
}

// AllowN checks if N requests are allowed
func (sw *SlidingWindowRateLimiter) AllowN(n int64) bool {
	return sw.Allow(n)
}

// Wait waits until tokens are available or context is cancelled
func (sw *SlidingWindowRateLimiter) Wait(ctx context.Context, tokens int64) error {
	for {
		if sw.Allow(tokens) {
			return nil
		}

		// Wait a small amount before retrying
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond * 100):
			// Continue to next iteration
		}
	}
}

// Tokens returns the number of available tokens (requests that can be made)
func (sw *SlidingWindowRateLimiter) Tokens() int64 {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	sw.cleanup(now)

	return sw.limit - int64(len(sw.requests))
}

// cleanup removes expired requests from the window
func (sw *SlidingWindowRateLimiter) cleanup(now time.Time) {
	cutoff := now.Add(-sw.window)
	
	// Find the first request that's still within the window
	i := 0
	for i < len(sw.requests) && sw.requests[i].Before(cutoff) {
		i++
	}
	
	// Remove expired requests
	if i > 0 {
		sw.requests = sw.requests[i:]
	}
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	CircuitBreakerClosed CircuitBreakerState = iota
	CircuitBreakerOpen
	CircuitBreakerHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern for stability
type CircuitBreaker struct {
	maxFailures      int64
	resetTimeout     time.Duration
	halfOpenRequests int64
	
	failures         int64
	requests         int64
	lastFailureTime  time.Time
	state           CircuitBreakerState
	halfOpenCount   int64
	
	mu sync.RWMutex
}

// CircuitBreakerConfig contains circuit breaker configuration
type CircuitBreakerConfig struct {
	MaxFailures      int64         `yaml:"max_failures" json:"max_failures"`
	ResetTimeout     time.Duration `yaml:"reset_timeout" json:"reset_timeout"`
	HalfOpenRequests int64         `yaml:"half_open_requests" json:"half_open_requests"`
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:      config.MaxFailures,
		resetTimeout:     config.ResetTimeout,
		halfOpenRequests: config.HalfOpenRequests,
		state:           CircuitBreakerClosed,
	}
}

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	if !cb.allowRequest() {
		return ErrCircuitBreakerOpen
	}

	err := fn()
	cb.recordResult(err == nil)
	return err
}

// allowRequest checks if a request should be allowed
func (cb *CircuitBreaker) allowRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitBreakerClosed:
		return true
	case CircuitBreakerOpen:
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.state = CircuitBreakerHalfOpen
			cb.halfOpenCount = 0
			return true
		}
		return false
	case CircuitBreakerHalfOpen:
		return cb.halfOpenCount < cb.halfOpenRequests
	default:
		return false
	}
}

// recordResult records the result of a request
func (cb *CircuitBreaker) recordResult(success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.requests++

	if success {
		if cb.state == CircuitBreakerHalfOpen {
			cb.halfOpenCount++
			if cb.halfOpenCount >= cb.halfOpenRequests {
				cb.state = CircuitBreakerClosed
				cb.failures = 0
			}
		} else if cb.state == CircuitBreakerClosed {
			cb.failures = 0
		}
	} else {
		cb.failures++
		cb.lastFailureTime = time.Now()
		
		if cb.state == CircuitBreakerClosed && cb.failures >= cb.maxFailures {
			cb.state = CircuitBreakerOpen
		} else if cb.state == CircuitBreakerHalfOpen {
			cb.state = CircuitBreakerOpen
		}
	}
}

// State returns the current circuit breaker state
func (cb *CircuitBreaker) State() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Stats returns circuit breaker statistics
func (cb *CircuitBreaker) Stats() map[string]interface{} {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return map[string]interface{}{
		"state":            cb.state,
		"failures":         cb.failures,
		"requests":         cb.requests,
		"last_failure":     cb.lastFailureTime,
		"half_open_count":  cb.halfOpenCount,
	}
}

// Custom errors
var (
	ErrCircuitBreakerOpen = fmt.Errorf("circuit breaker is open")
)