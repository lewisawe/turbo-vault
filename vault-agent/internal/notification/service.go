package notification

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Service implements the NotificationService interface
type Service struct {
	config       *NotificationConfig
	providers    map[NotificationType]NotificationProvider
	channels     map[string]*Channel
	templates    map[string]*Template
	rateLimiter  RateLimiter
	deduplicator Deduplicator
	logger       *logrus.Logger
	mu           sync.RWMutex
}

// NewService creates a new notification service
func NewService(config *NotificationConfig, logger *logrus.Logger) *Service {
	if config == nil {
		config = DefaultNotificationConfig()
	}

	service := &Service{
		config:       config,
		providers:    make(map[NotificationType]NotificationProvider),
		channels:     make(map[string]*Channel),
		templates:    make(map[string]*Template),
		rateLimiter:  NewMemoryRateLimiter(config.RateLimit),
		deduplicator: NewMemoryDeduplicator(config.Deduplication),
		logger:       logger,
	}

	// Register default providers
	service.registerProviders()

	// Load configured channels and templates
	service.loadChannels()
	service.loadTemplates()

	return service
}

// registerProviders registers the default notification providers
func (s *Service) registerProviders() {
	s.providers[NotificationTypeEmail] = NewEmailProvider(s.logger)
	s.providers[NotificationTypeWebhook] = NewWebhookProvider(s.logger)
	s.providers[NotificationTypeSlack] = NewSlackProvider(s.logger)
}

// loadChannels loads configured channels
func (s *Service) loadChannels() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, channel := range s.config.Channels {
		s.channels[id] = channel
	}
}

// loadTemplates loads configured templates
func (s *Service) loadTemplates() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, template := range s.config.Templates {
		s.templates[id] = template
	}
}

// Send sends a notification using the specified channel
func (s *Service) Send(ctx context.Context, channelID string, notification *Notification) error {
	if !s.config.Enabled {
		s.logger.Debug("Notification service is disabled, skipping notification")
		return nil
	}

	// Get channel configuration
	channel, err := s.GetChannel(ctx, channelID)
	if err != nil {
		return fmt.Errorf("failed to get channel %s: %w", channelID, err)
	}

	if !channel.Enabled {
		s.logger.Debugf("Channel %s is disabled, skipping notification", channelID)
		return nil
	}

	// Check rate limiting
	allowed, err := s.rateLimiter.Allow(ctx, channelID, notification.Type)
	if err != nil {
		s.logger.Errorf("Rate limiter error for channel %s: %v", channelID, err)
	} else if !allowed {
		s.logger.Warnf("Rate limit exceeded for channel %s, dropping notification", channelID)
		return fmt.Errorf("rate limit exceeded for channel %s", channelID)
	}

	// Check for duplicates
	if s.config.Deduplication.Enabled {
		isDuplicate, err := s.deduplicator.IsDuplicate(ctx, notification)
		if err != nil {
			s.logger.Errorf("Deduplication check error: %v", err)
		} else if isDuplicate {
			s.logger.Debugf("Duplicate notification detected, skipping")
			return nil
		}
	}

	// Get provider for channel type
	provider, exists := s.providers[channel.Type]
	if !exists {
		return fmt.Errorf("no provider found for notification type %s", channel.Type)
	}

	// Set notification metadata
	if notification.ID == "" {
		notification.ID = uuid.New().String()
	}
	if notification.CreatedAt.IsZero() {
		notification.CreatedAt = time.Now()
	}

	// Send notification with retry logic
	err = s.sendWithRetry(ctx, provider, channel, notification)
	if err != nil {
		s.updateChannelFailureCount(channelID, true)
		return fmt.Errorf("failed to send notification: %w", err)
	}

	// Mark as sent for deduplication
	if s.config.Deduplication.Enabled {
		if err := s.deduplicator.MarkSent(ctx, notification); err != nil {
			s.logger.Errorf("Failed to mark notification as sent: %v", err)
		}
	}

	// Update channel usage
	s.updateChannelUsage(channelID)
	s.updateChannelFailureCount(channelID, false)

	s.logger.Infof("Notification sent successfully via channel %s", channelID)
	return nil
}

// SendBulk sends notifications to multiple channels
func (s *Service) SendBulk(ctx context.Context, channelIDs []string, notification *Notification) error {
	var errors []error

	for _, channelID := range channelIDs {
		if err := s.Send(ctx, channelID, notification); err != nil {
			errors = append(errors, fmt.Errorf("channel %s: %w", channelID, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("bulk send failed for %d channels: %v", len(errors), errors)
	}

	return nil
}

// sendWithRetry sends a notification with retry logic
func (s *Service) sendWithRetry(ctx context.Context, provider NotificationProvider, channel *Channel, notification *Notification) error {
	maxRetries := s.config.RetryPolicy.MaxRetries
	if notification.MaxRetries > 0 {
		maxRetries = notification.MaxRetries
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := s.calculateRetryDelay(attempt)
			s.logger.Debugf("Retrying notification send in %v (attempt %d/%d)", delay, attempt, maxRetries)
			
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		err := provider.Send(ctx, channel.Config, notification)
		if err == nil {
			notification.SentAt = &[]time.Time{time.Now()}[0]
			notification.Status = "sent"
			return nil
		}

		lastErr = err
		notification.Retries = attempt + 1
		notification.Error = err.Error()

		// Check if error is retryable
		if !s.isRetryableError(err) {
			break
		}

		s.logger.Warnf("Notification send failed (attempt %d/%d): %v", attempt+1, maxRetries+1, err)
	}

	notification.Status = "failed"
	return fmt.Errorf("notification send failed after %d attempts: %w", notification.Retries, lastErr)
}

// calculateRetryDelay calculates the delay for retry attempts
func (s *Service) calculateRetryDelay(attempt int) time.Duration {
	delay := s.config.RetryPolicy.InitialDelay
	for i := 1; i < attempt; i++ {
		delay = time.Duration(float64(delay) * s.config.RetryPolicy.BackoffFactor)
		if delay > s.config.RetryPolicy.MaxDelay {
			delay = s.config.RetryPolicy.MaxDelay
			break
		}
	}
	return delay
}

// isRetryableError checks if an error is retryable
func (s *Service) isRetryableError(err error) bool {
	errStr := err.Error()
	for _, retryableErr := range s.config.RetryPolicy.RetryableErrors {
		if contains(errStr, retryableErr) {
			return true
		}
	}
	return false
}

// RegisterChannel registers a new notification channel
func (s *Service) RegisterChannel(ctx context.Context, channel *Channel) error {
	if channel.ID == "" {
		channel.ID = uuid.New().String()
	}

	// Validate channel configuration
	provider, exists := s.providers[channel.Type]
	if !exists {
		return fmt.Errorf("unsupported notification type: %s", channel.Type)
	}

	if err := provider.Validate(channel.Config); err != nil {
		return fmt.Errorf("invalid channel configuration: %w", err)
	}

	// Set timestamps
	now := time.Now()
	if channel.CreatedAt.IsZero() {
		channel.CreatedAt = now
	}
	channel.UpdatedAt = now

	s.mu.Lock()
	s.channels[channel.ID] = channel
	s.mu.Unlock()

	s.logger.Infof("Registered notification channel %s (%s)", channel.ID, channel.Type)
	return nil
}

// UpdateChannel updates an existing notification channel
func (s *Service) UpdateChannel(ctx context.Context, channel *Channel) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.channels[channel.ID]
	if !exists {
		return fmt.Errorf("channel %s not found", channel.ID)
	}

	// Validate configuration if type changed
	if channel.Type != existing.Type {
		provider, exists := s.providers[channel.Type]
		if !exists {
			return fmt.Errorf("unsupported notification type: %s", channel.Type)
		}
		if err := provider.Validate(channel.Config); err != nil {
			return fmt.Errorf("invalid channel configuration: %w", err)
		}
	}

	// Preserve creation time and update timestamp
	channel.CreatedAt = existing.CreatedAt
	channel.UpdatedAt = time.Now()

	s.channels[channel.ID] = channel
	s.logger.Infof("Updated notification channel %s", channel.ID)
	return nil
}

// DeleteChannel removes a notification channel
func (s *Service) DeleteChannel(ctx context.Context, channelID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.channels[channelID]; !exists {
		return fmt.Errorf("channel %s not found", channelID)
	}

	delete(s.channels, channelID)
	s.logger.Infof("Deleted notification channel %s", channelID)
	return nil
}

// GetChannel retrieves a notification channel by ID
func (s *Service) GetChannel(ctx context.Context, channelID string) (*Channel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	channel, exists := s.channels[channelID]
	if !exists {
		return nil, fmt.Errorf("channel %s not found", channelID)
	}

	// Return a copy to prevent external modifications
	channelCopy := *channel
	return &channelCopy, nil
}

// ListChannels lists all notification channels
func (s *Service) ListChannels(ctx context.Context) ([]*Channel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	channels := make([]*Channel, 0, len(s.channels))
	for _, channel := range s.channels {
		channelCopy := *channel
		channels = append(channels, &channelCopy)
	}

	return channels, nil
}

// TestChannel tests a notification channel configuration
func (s *Service) TestChannel(ctx context.Context, channelID string) error {
	channel, err := s.GetChannel(ctx, channelID)
	if err != nil {
		return err
	}

	provider, exists := s.providers[channel.Type]
	if !exists {
		return fmt.Errorf("no provider found for notification type %s", channel.Type)
	}

	// Create test notification
	testNotification := &Notification{
		ID:      uuid.New().String(),
		Type:    channel.Type,
		Subject: "Test Notification",
		Message: "This is a test notification from the vault agent notification system.",
		Data: map[string]interface{}{
			"test": true,
			"timestamp": time.Now().Format(time.RFC3339),
		},
		Priority:  1,
		CreatedAt: time.Now(),
	}

	return provider.Send(ctx, channel.Config, testNotification)
}

// updateChannelUsage updates the last used timestamp for a channel
func (s *Service) updateChannelUsage(channelID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if channel, exists := s.channels[channelID]; exists {
		now := time.Now()
		channel.LastUsed = &now
	}
}

// updateChannelFailureCount updates the failure count for a channel
func (s *Service) updateChannelFailureCount(channelID string, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if channel, exists := s.channels[channelID]; exists {
		if failed {
			channel.FailureCount++
		} else {
			channel.FailureCount = 0
		}
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		 len(s) > len(substr)*2 && s[len(s)/2-len(substr)/2:len(s)/2+len(substr)/2+len(substr)%2] == substr)))
}