package notification

import (
	"time"
)

// NotificationType represents the type of notification provider
type NotificationType string

const (
	NotificationTypeEmail   NotificationType = "email"
	NotificationTypeWebhook NotificationType = "webhook"
	NotificationTypeSlack   NotificationType = "slack"
)

// EventType represents the type of event that can trigger notifications
type EventType string

const (
	EventTypeSecretCreated     EventType = "secret_created"
	EventTypeSecretUpdated     EventType = "secret_updated"
	EventTypeSecretDeleted     EventType = "secret_deleted"
	EventTypeSecretAccessed    EventType = "secret_accessed"
	EventTypeSecretRotated     EventType = "secret_rotation"
	EventTypeSecretExpired     EventType = "secret_expired"
	EventTypeAuthFailure       EventType = "auth_failure"
	EventTypePolicyViolation   EventType = "policy_violation"
	EventTypeSystemHealth      EventType = "system_health"
	EventTypeBackupCompleted   EventType = "backup_completed"
	EventTypeBackupFailed      EventType = "backup_failed"
	EventTypeRotationFailed    EventType = "rotation_failed"
	EventTypeVaultOffline      EventType = "vault_offline"
	EventTypeVaultOnline       EventType = "vault_online"
)

// Severity represents the severity level of an alert
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// AlertStatus represents the status of an alert
type AlertStatus string

const (
	AlertStatusPending   AlertStatus = "pending"
	AlertStatusFiring    AlertStatus = "firing"
	AlertStatusResolved  AlertStatus = "resolved"
	AlertStatusSuppressed AlertStatus = "suppressed"
)

// Notification represents a notification to be sent
type Notification struct {
	ID          string                 `json:"id"`
	Type        NotificationType       `json:"type"`
	Subject     string                 `json:"subject"`
	Message     string                 `json:"message"`
	Data        map[string]interface{} `json:"data"`
	Priority    int                    `json:"priority"`
	CreatedAt   time.Time              `json:"created_at"`
	ScheduledAt *time.Time             `json:"scheduled_at,omitempty"`
	SentAt      *time.Time             `json:"sent_at,omitempty"`
	Status      string                 `json:"status"`
	Retries     int                    `json:"retries"`
	MaxRetries  int                    `json:"max_retries"`
	Error       string                 `json:"error,omitempty"`
}

// Channel represents a notification channel configuration
type Channel struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        NotificationType       `json:"type"`
	Config      map[string]interface{} `json:"config"`
	Enabled     bool                   `json:"enabled"`
	Events      []EventType            `json:"events"`
	RateLimit   *RateLimitConfig       `json:"rate_limit,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	LastUsed    *time.Time             `json:"last_used,omitempty"`
	FailureCount int                   `json:"failure_count"`
}

// RateLimitConfig represents rate limiting configuration for a channel
type RateLimitConfig struct {
	MaxNotifications int           `json:"max_notifications"`
	WindowDuration   time.Duration `json:"window_duration"`
	BurstSize        int           `json:"burst_size"`
}

// RateLimitStatus represents the current rate limit status
type RateLimitStatus struct {
	ChannelID        string    `json:"channel_id"`
	CurrentCount     int       `json:"current_count"`
	MaxNotifications int       `json:"max_notifications"`
	WindowStart      time.Time `json:"window_start"`
	WindowEnd        time.Time `json:"window_end"`
	IsLimited        bool      `json:"is_limited"`
	ResetAt          time.Time `json:"reset_at"`
}

// AlertRule represents a rule for generating alerts
type AlertRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	EventType   EventType              `json:"event_type"`
	Conditions  []AlertCondition       `json:"conditions"`
	Severity    Severity               `json:"severity"`
	Channels    []string               `json:"channels"`
	Template    string                 `json:"template"`
	Enabled     bool                   `json:"enabled"`
	Cooldown    time.Duration          `json:"cooldown"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	LastFired   *time.Time             `json:"last_fired,omitempty"`
	FireCount   int                    `json:"fire_count"`
}

// AlertCondition represents a condition for alert rules
type AlertCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, ne, gt, lt, gte, lte, contains, regex
	Value    interface{} `json:"value"`
}

// AlertEvent represents an event that can trigger alerts
type AlertEvent struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]string      `json:"metadata"`
}

// Alert represents a fired alert
type Alert struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	EventID     string                 `json:"event_id"`
	Severity    Severity               `json:"severity"`
	Status      AlertStatus            `json:"status"`
	Message     string                 `json:"message"`
	Data        map[string]interface{} `json:"data"`
	FiredAt     time.Time              `json:"fired_at"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Channels    []string               `json:"channels"`
	Notifications []string             `json:"notifications"`
}

// AlertFilter represents filters for querying alerts
type AlertFilter struct {
	RuleID     string       `json:"rule_id,omitempty"`
	Severity   Severity     `json:"severity,omitempty"`
	Status     AlertStatus  `json:"status,omitempty"`
	StartTime  *time.Time   `json:"start_time,omitempty"`
	EndTime    *time.Time   `json:"end_time,omitempty"`
	Limit      int          `json:"limit,omitempty"`
	Offset     int          `json:"offset,omitempty"`
}

// Template represents a notification template
type Template struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        NotificationType       `json:"type"`
	Subject     string                 `json:"subject"`
	Body        string                 `json:"body"`
	Variables   []string               `json:"variables"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// EmailConfig represents email notification configuration
type EmailConfig struct {
	SMTPHost     string   `json:"smtp_host"`
	SMTPPort     int      `json:"smtp_port"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	From         string   `json:"from"`
	To           []string `json:"to"`
	CC           []string `json:"cc,omitempty"`
	BCC          []string `json:"bcc,omitempty"`
	UseTLS       bool     `json:"use_tls"`
	UseStartTLS  bool     `json:"use_starttls"`
	SkipVerify   bool     `json:"skip_verify"`
}

// WebhookConfig represents webhook notification configuration
type WebhookConfig struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"`
	Timeout     time.Duration     `json:"timeout"`
	RetryCount  int               `json:"retry_count"`
	SkipVerify  bool              `json:"skip_verify"`
	Secret      string            `json:"secret,omitempty"`
}

// SlackConfig represents Slack notification configuration
type SlackConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username,omitempty"`
	IconEmoji  string `json:"icon_emoji,omitempty"`
	IconURL    string `json:"icon_url,omitempty"`
}

// NotificationConfig represents the notification system configuration
type NotificationConfig struct {
	Enabled           bool                    `yaml:"enabled" json:"enabled"`
	DefaultChannels   []string                `yaml:"default_channels" json:"default_channels"`
	RateLimit         *GlobalRateLimitConfig  `yaml:"rate_limit" json:"rate_limit"`
	Deduplication     *DeduplicationConfig    `yaml:"deduplication" json:"deduplication"`
	RetryPolicy       *RetryPolicyConfig      `yaml:"retry_policy" json:"retry_policy"`
	Templates         map[string]*Template    `yaml:"templates" json:"templates"`
	Channels          map[string]*Channel     `yaml:"channels" json:"channels"`
	AlertRules        map[string]*AlertRule   `yaml:"alert_rules" json:"alert_rules"`
}

// GlobalRateLimitConfig represents global rate limiting configuration
type GlobalRateLimitConfig struct {
	Enabled            bool          `yaml:"enabled" json:"enabled"`
	DefaultMaxPerHour  int           `yaml:"default_max_per_hour" json:"default_max_per_hour"`
	DefaultBurstSize   int           `yaml:"default_burst_size" json:"default_burst_size"`
	CleanupInterval    time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
}

// DeduplicationConfig represents deduplication configuration
type DeduplicationConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	WindowDuration  time.Duration `yaml:"window_duration" json:"window_duration"`
	KeyFields       []string      `yaml:"key_fields" json:"key_fields"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
}

// RetryPolicyConfig represents retry policy configuration
type RetryPolicyConfig struct {
	MaxRetries      int           `yaml:"max_retries" json:"max_retries"`
	InitialDelay    time.Duration `yaml:"initial_delay" json:"initial_delay"`
	MaxDelay        time.Duration `yaml:"max_delay" json:"max_delay"`
	BackoffFactor   float64       `yaml:"backoff_factor" json:"backoff_factor"`
	RetryableErrors []string      `yaml:"retryable_errors" json:"retryable_errors"`
}

// DefaultNotificationConfig returns a default notification configuration
func DefaultNotificationConfig() *NotificationConfig {
	return &NotificationConfig{
		Enabled:         true,
		DefaultChannels: []string{},
		RateLimit: &GlobalRateLimitConfig{
			Enabled:            true,
			DefaultMaxPerHour:  100,
			DefaultBurstSize:   10,
			CleanupInterval:    time.Hour,
		},
		Deduplication: &DeduplicationConfig{
			Enabled:         true,
			WindowDuration:  5 * time.Minute,
			KeyFields:       []string{"type", "subject", "source"},
			CleanupInterval: time.Hour,
		},
		RetryPolicy: &RetryPolicyConfig{
			MaxRetries:      3,
			InitialDelay:    time.Second,
			MaxDelay:        30 * time.Second,
			BackoffFactor:   2.0,
			RetryableErrors: []string{"timeout", "connection_error", "server_error"},
		},
		Templates:  make(map[string]*Template),
		Channels:   make(map[string]*Channel),
		AlertRules: make(map[string]*AlertRule),
	}
}