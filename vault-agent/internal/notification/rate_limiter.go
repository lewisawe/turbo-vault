package notification

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryRateLimiter implements in-memory rate limiting
type MemoryRateLimiter struct {
	config   *GlobalRateLimitConfig
	buckets  map[string]*tokenBucket
	mu       sync.RWMutex
	stopChan chan struct{}
}

// tokenBucket represents a token bucket for rate limiting
type tokenBucket struct {
	maxTokens     int
	tokens        int
	refillRate    time.Duration
	lastRefill    time.Time
	windowStart   time.Time
	notifications int
	mu            sync.Mutex
}

// NewMemoryRateLimiter creates a new in-memory rate limiter
func NewMemoryRateLimiter(config *GlobalRateLimitConfig) *MemoryRateLimiter {
	if config == nil {
		config = &GlobalRateLimitConfig{
			Enabled:            true,
			DefaultMaxPerHour:  100,
			DefaultBurstSize:   10,
			CleanupInterval:    time.Hour,
		}
	}

	limiter := &MemoryRateLimiter{
		config:   config,
		buckets:  make(map[string]*tokenBucket),
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	go limiter.cleanupLoop()

	return limiter
}

// Allow checks if a notification is allowed based on rate limiting rules
func (r *MemoryRateLimiter) Allow(ctx context.Context, channelID string, notificationType NotificationType) (bool, error) {
	if !r.config.Enabled {
		return true, nil
	}

	r.mu.Lock()
	bucket, exists := r.buckets[channelID]
	if !exists {
		bucket = r.createBucket()
		r.buckets[channelID] = bucket
	}
	r.mu.Unlock()

	return bucket.allow(), nil
}

// Reset resets the rate limit for a channel
func (r *MemoryRateLimiter) Reset(ctx context.Context, channelID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if bucket, exists := r.buckets[channelID]; exists {
		bucket.reset()
	}

	return nil
}

// GetLimitStatus returns the current rate limit status for a channel
func (r *MemoryRateLimiter) GetLimitStatus(ctx context.Context, channelID string) (*RateLimitStatus, error) {
	r.mu.RLock()
	bucket, exists := r.buckets[channelID]
	r.mu.RUnlock()

	if !exists {
		// Return default status for non-existent bucket
		return &RateLimitStatus{
			ChannelID:        channelID,
			CurrentCount:     0,
			MaxNotifications: r.config.DefaultMaxPerHour,
			WindowStart:      time.Now().Truncate(time.Hour),
			WindowEnd:        time.Now().Truncate(time.Hour).Add(time.Hour),
			IsLimited:        false,
			ResetAt:          time.Now().Truncate(time.Hour).Add(time.Hour),
		}, nil
	}

	return bucket.getStatus(channelID), nil
}

// createBucket creates a new token bucket with default configuration
func (r *MemoryRateLimiter) createBucket() *tokenBucket {
	now := time.Now()
	return &tokenBucket{
		maxTokens:     r.config.DefaultBurstSize,
		tokens:        r.config.DefaultBurstSize,
		refillRate:    time.Hour / time.Duration(r.config.DefaultMaxPerHour),
		lastRefill:    now,
		windowStart:   now.Truncate(time.Hour),
		notifications: 0,
	}
}

// allow checks if a token is available and consumes it if so
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	// Check if we need to start a new window
	if now.Sub(b.windowStart) >= time.Hour {
		b.windowStart = now.Truncate(time.Hour)
		b.notifications = 0
		b.tokens = b.maxTokens
		b.lastRefill = now
	}

	// Refill tokens based on time elapsed
	b.refill(now)

	// Check if we have tokens available
	if b.tokens > 0 {
		b.tokens--
		b.notifications++
		return true
	}

	return false
}

// refill adds tokens to the bucket based on elapsed time
func (b *tokenBucket) refill(now time.Time) {
	elapsed := now.Sub(b.lastRefill)
	tokensToAdd := int(elapsed / b.refillRate)

	if tokensToAdd > 0 {
		b.tokens += tokensToAdd
		if b.tokens > b.maxTokens {
			b.tokens = b.maxTokens
		}
		b.lastRefill = now
	}
}

// reset resets the token bucket
func (b *tokenBucket) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.tokens = b.maxTokens
	b.lastRefill = now
	b.windowStart = now.Truncate(time.Hour)
	b.notifications = 0
}

// getStatus returns the current status of the token bucket
func (b *tokenBucket) getStatus(channelID string) *RateLimitStatus {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.refill(now)

	windowEnd := b.windowStart.Add(time.Hour)
	maxNotifications := int(time.Hour / b.refillRate)

	return &RateLimitStatus{
		ChannelID:        channelID,
		CurrentCount:     b.notifications,
		MaxNotifications: maxNotifications,
		WindowStart:      b.windowStart,
		WindowEnd:        windowEnd,
		IsLimited:        b.tokens == 0,
		ResetAt:          windowEnd,
	}
}

// cleanupLoop periodically cleans up old buckets
func (r *MemoryRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(r.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.cleanup()
		case <-r.stopChan:
			return
		}
	}
}

// cleanup removes old unused buckets
func (r *MemoryRateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-2 * time.Hour) // Remove buckets older than 2 hours

	for channelID, bucket := range r.buckets {
		bucket.mu.Lock()
		if bucket.windowStart.Before(cutoff) {
			delete(r.buckets, channelID)
		}
		bucket.mu.Unlock()
	}
}

// Stop stops the rate limiter cleanup goroutine
func (r *MemoryRateLimiter) Stop() {
	close(r.stopChan)
}

// MemoryDeduplicator implements in-memory notification deduplication
type MemoryDeduplicator struct {
	config      *DeduplicationConfig
	sentHashes  map[string]time.Time
	mu          sync.RWMutex
	stopChan    chan struct{}
}

// NewMemoryDeduplicator creates a new in-memory deduplicator
func NewMemoryDeduplicator(config *DeduplicationConfig) *MemoryDeduplicator {
	if config == nil {
		config = &DeduplicationConfig{
			Enabled:         true,
			WindowDuration:  5 * time.Minute,
			KeyFields:       []string{"type", "subject", "source"},
			CleanupInterval: time.Hour,
		}
	}

	dedup := &MemoryDeduplicator{
		config:     config,
		sentHashes: make(map[string]time.Time),
		stopChan:   make(chan struct{}),
	}

	// Start cleanup goroutine
	go dedup.cleanupLoop()

	return dedup
}

// IsDuplicate checks if a notification is a duplicate
func (d *MemoryDeduplicator) IsDuplicate(ctx context.Context, notification *Notification) (bool, error) {
	if !d.config.Enabled {
		return false, nil
	}

	hash := d.generateHash(notification)
	
	d.mu.RLock()
	lastSent, exists := d.sentHashes[hash]
	d.mu.RUnlock()

	if !exists {
		return false, nil
	}

	// Check if within deduplication window
	if time.Since(lastSent) <= d.config.WindowDuration {
		return true, nil
	}

	return false, nil
}

// MarkSent marks a notification as sent for deduplication
func (d *MemoryDeduplicator) MarkSent(ctx context.Context, notification *Notification) error {
	if !d.config.Enabled {
		return nil
	}

	hash := d.generateHash(notification)
	
	d.mu.Lock()
	d.sentHashes[hash] = time.Now()
	d.mu.Unlock()

	return nil
}

// Cleanup removes old deduplication records
func (d *MemoryDeduplicator) Cleanup(ctx context.Context, olderThan time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for hash, sentTime := range d.sentHashes {
		if sentTime.Before(olderThan) {
			delete(d.sentHashes, hash)
		}
	}

	return nil
}

// generateHash generates a hash for deduplication based on configured key fields
func (d *MemoryDeduplicator) generateHash(notification *Notification) string {
	var parts []string

	for _, field := range d.config.KeyFields {
		switch field {
		case "type":
			parts = append(parts, string(notification.Type))
		case "subject":
			parts = append(parts, notification.Subject)
		case "message":
			parts = append(parts, notification.Message)
		case "source":
			if source, ok := notification.Data["source"].(string); ok {
				parts = append(parts, source)
			}
		case "priority":
			parts = append(parts, fmt.Sprintf("%d", notification.Priority))
		}
	}

	// Simple hash function - in production, consider using a proper hash function
	hash := ""
	for _, part := range parts {
		hash += part + "|"
	}

	return hash
}

// cleanupLoop periodically cleans up old deduplication records
func (d *MemoryDeduplicator) cleanupLoop() {
	ticker := time.NewTicker(d.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-d.config.WindowDuration * 2)
			d.Cleanup(context.Background(), cutoff)
		case <-d.stopChan:
			return
		}
	}
}

// Stop stops the deduplicator cleanup goroutine
func (d *MemoryDeduplicator) Stop() {
	close(d.stopChan)
}