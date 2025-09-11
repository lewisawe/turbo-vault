package notification

import (
	"context"
	"time"
)

// NotificationService defines the interface for sending notifications
type NotificationService interface {
	// Send sends a notification using the specified channel
	Send(ctx context.Context, channelID string, notification *Notification) error
	
	// SendBulk sends notifications to multiple channels
	SendBulk(ctx context.Context, channelIDs []string, notification *Notification) error
	
	// RegisterChannel registers a new notification channel
	RegisterChannel(ctx context.Context, channel *Channel) error
	
	// UpdateChannel updates an existing notification channel
	UpdateChannel(ctx context.Context, channel *Channel) error
	
	// DeleteChannel removes a notification channel
	DeleteChannel(ctx context.Context, channelID string) error
	
	// GetChannel retrieves a notification channel by ID
	GetChannel(ctx context.Context, channelID string) (*Channel, error)
	
	// ListChannels lists all notification channels
	ListChannels(ctx context.Context) ([]*Channel, error)
	
	// TestChannel tests a notification channel configuration
	TestChannel(ctx context.Context, channelID string) error
}

// AlertManager defines the interface for managing alerts and rules
type AlertManager interface {
	// CreateRule creates a new alert rule
	CreateRule(ctx context.Context, rule *AlertRule) error
	
	// UpdateRule updates an existing alert rule
	UpdateRule(ctx context.Context, rule *AlertRule) error
	
	// DeleteRule deletes an alert rule
	DeleteRule(ctx context.Context, ruleID string) error
	
	// GetRule retrieves an alert rule by ID
	GetRule(ctx context.Context, ruleID string) (*AlertRule, error)
	
	// ListRules lists all alert rules
	ListRules(ctx context.Context) ([]*AlertRule, error)
	
	// EvaluateRules evaluates all active alert rules against an event
	EvaluateRules(ctx context.Context, event *AlertEvent) ([]*Alert, error)
	
	// ProcessAlert processes an alert and sends notifications
	ProcessAlert(ctx context.Context, alert *Alert) error
	
	// GetAlertHistory retrieves alert history
	GetAlertHistory(ctx context.Context, filter *AlertFilter) ([]*Alert, error)
}

// TemplateManager defines the interface for managing notification templates
type TemplateManager interface {
	// RegisterTemplate registers a new notification template
	RegisterTemplate(ctx context.Context, template *Template) error
	
	// UpdateTemplate updates an existing template
	UpdateTemplate(ctx context.Context, template *Template) error
	
	// DeleteTemplate deletes a template
	DeleteTemplate(ctx context.Context, templateID string) error
	
	// GetTemplate retrieves a template by ID
	GetTemplate(ctx context.Context, templateID string) (*Template, error)
	
	// ListTemplates lists all templates
	ListTemplates(ctx context.Context) ([]*Template, error)
	
	// RenderTemplate renders a template with the provided data
	RenderTemplate(ctx context.Context, templateID string, data interface{}) (string, error)
}

// RateLimiter defines the interface for rate limiting notifications
type RateLimiter interface {
	// Allow checks if a notification is allowed based on rate limiting rules
	Allow(ctx context.Context, channelID string, notificationType NotificationType) (bool, error)
	
	// Reset resets the rate limit for a channel
	Reset(ctx context.Context, channelID string) error
	
	// GetLimitStatus returns the current rate limit status for a channel
	GetLimitStatus(ctx context.Context, channelID string) (*RateLimitStatus, error)
}

// Deduplicator defines the interface for deduplicating notifications
type Deduplicator interface {
	// IsDuplicate checks if a notification is a duplicate
	IsDuplicate(ctx context.Context, notification *Notification) (bool, error)
	
	// MarkSent marks a notification as sent for deduplication
	MarkSent(ctx context.Context, notification *Notification) error
	
	// Cleanup removes old deduplication records
	Cleanup(ctx context.Context, olderThan time.Time) error
}

// NotificationProvider defines the interface for specific notification providers
type NotificationProvider interface {
	// Send sends a notification using the provider
	Send(ctx context.Context, config map[string]interface{}, notification *Notification) error
	
	// Validate validates the provider configuration
	Validate(config map[string]interface{}) error
	
	// GetType returns the provider type
	GetType() NotificationType
	
	// GetConfigSchema returns the configuration schema for the provider
	GetConfigSchema() map[string]interface{}
}