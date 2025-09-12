package notification

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNotificationService(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	config := DefaultNotificationConfig()
	service := NewService(config, logger)

	t.Run("RegisterChannel", func(t *testing.T) {
		channel := &Channel{
			Name:    "test-email",
			Type:    NotificationTypeEmail,
			Enabled: true,
			Config: map[string]interface{}{
				"smtp_host": "smtp.example.com",
				"smtp_port": 587,
				"username":  "test@example.com",
				"password":  "password",
				"from":      "test@example.com",
				"to":        []string{"recipient@example.com"},
			},
			Events: []EventType{EventTypeSecretRotated, EventTypeAuthFailure},
		}

		err := service.RegisterChannel(context.Background(), channel)
		require.NoError(t, err)
		assert.NotEmpty(t, channel.ID)
		assert.False(t, channel.CreatedAt.IsZero())
	})

	t.Run("GetChannel", func(t *testing.T) {
		channels, err := service.ListChannels(context.Background())
		require.NoError(t, err)
		require.Len(t, channels, 1)

		channel, err := service.GetChannel(context.Background(), channels[0].ID)
		require.NoError(t, err)
		assert.Equal(t, "test-email", channel.Name)
	})

	t.Run("UpdateChannel", func(t *testing.T) {
		channels, err := service.ListChannels(context.Background())
		require.NoError(t, err)
		require.Len(t, channels, 1)

		channel := channels[0]
		channel.Name = "updated-email"
		channel.Enabled = false

		err = service.UpdateChannel(context.Background(), channel)
		require.NoError(t, err)

		updated, err := service.GetChannel(context.Background(), channel.ID)
		require.NoError(t, err)
		assert.Equal(t, "updated-email", updated.Name)
		assert.False(t, updated.Enabled)
	})

	t.Run("DeleteChannel", func(t *testing.T) {
		channels, err := service.ListChannels(context.Background())
		require.NoError(t, err)
		require.Len(t, channels, 1)

		err = service.DeleteChannel(context.Background(), channels[0].ID)
		require.NoError(t, err)

		channels, err = service.ListChannels(context.Background())
		require.NoError(t, err)
		assert.Len(t, channels, 0)
	})
}

func TestEmailProvider(t *testing.T) {
	logger := logrus.New()
	provider := NewEmailProvider(logger)

	t.Run("ValidateConfig", func(t *testing.T) {
		validConfig := map[string]interface{}{
			"smtp_host": "smtp.example.com",
			"smtp_port": 587,
			"username":  "test@example.com",
			"password":  "password",
			"from":      "test@example.com",
			"to":        []string{"recipient@example.com"},
		}

		err := provider.Validate(validConfig)
		assert.NoError(t, err)

		invalidConfig := map[string]interface{}{
			"smtp_host": "smtp.example.com",
			// Missing required fields
		}

		err = provider.Validate(invalidConfig)
		assert.Error(t, err)
	})

	t.Run("GetType", func(t *testing.T) {
		assert.Equal(t, NotificationTypeEmail, provider.GetType())
	})

	t.Run("GetConfigSchema", func(t *testing.T) {
		schema := provider.GetConfigSchema()
		assert.NotEmpty(t, schema)
		assert.Contains(t, schema, "smtp_host")
		assert.Contains(t, schema, "from")
		assert.Contains(t, schema, "to")
	})
}

func TestWebhookProvider(t *testing.T) {
	logger := logrus.New()
	provider := NewWebhookProvider(logger)

	t.Run("ValidateConfig", func(t *testing.T) {
		validConfig := map[string]interface{}{
			"url":    "https://example.com/webhook",
			"method": "POST",
		}

		err := provider.Validate(validConfig)
		assert.NoError(t, err)

		invalidConfig := map[string]interface{}{
			"method": "POST",
			// Missing URL
		}

		err = provider.Validate(invalidConfig)
		assert.Error(t, err)
	})

	t.Run("GetType", func(t *testing.T) {
		assert.Equal(t, NotificationTypeWebhook, provider.GetType())
	})
}

func TestSlackProvider(t *testing.T) {
	logger := logrus.New()
	provider := NewSlackProvider(logger)

	t.Run("ValidateConfig", func(t *testing.T) {
		validConfig := map[string]interface{}{
			"webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
			"channel":     "#alerts",
		}

		err := provider.Validate(validConfig)
		assert.NoError(t, err)

		invalidConfig := map[string]interface{}{
			"channel": "#alerts",
			// Missing webhook_url
		}

		err = provider.Validate(invalidConfig)
		assert.Error(t, err)
	})

	t.Run("GetType", func(t *testing.T) {
		assert.Equal(t, NotificationTypeSlack, provider.GetType())
	})
}

func TestRateLimiter(t *testing.T) {
	config := &GlobalRateLimitConfig{
		Enabled:            true,
		DefaultMaxPerHour:  10,
		DefaultBurstSize:   3,
		CleanupInterval:    time.Minute,
	}

	limiter := NewMemoryRateLimiter(config)
	defer limiter.Stop()

	t.Run("AllowWithinLimit", func(t *testing.T) {
		ctx := context.Background()
		channelID := "test-channel"

		// Should allow up to burst size
		for i := 0; i < 3; i++ {
			allowed, err := limiter.Allow(ctx, channelID, NotificationTypeEmail)
			require.NoError(t, err)
			assert.True(t, allowed, "Request %d should be allowed", i+1)
		}

		// Should deny after burst size
		allowed, err := limiter.Allow(ctx, channelID, NotificationTypeEmail)
		require.NoError(t, err)
		assert.False(t, allowed, "Request after burst should be denied")
	})

	t.Run("Reset", func(t *testing.T) {
		ctx := context.Background()
		channelID := "test-channel-2"

		// Exhaust limit
		for i := 0; i < 3; i++ {
			limiter.Allow(ctx, channelID, NotificationTypeEmail)
		}

		// Should be denied
		allowed, err := limiter.Allow(ctx, channelID, NotificationTypeEmail)
		require.NoError(t, err)
		assert.False(t, allowed)

		// Reset and try again
		err = limiter.Reset(ctx, channelID)
		require.NoError(t, err)

		allowed, err = limiter.Allow(ctx, channelID, NotificationTypeEmail)
		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("GetLimitStatus", func(t *testing.T) {
		ctx := context.Background()
		channelID := "test-channel-3"

		status, err := limiter.GetLimitStatus(ctx, channelID)
		require.NoError(t, err)
		assert.Equal(t, channelID, status.ChannelID)
		assert.Equal(t, 0, status.CurrentCount)
		assert.False(t, status.IsLimited)
	})
}

func TestDeduplicator(t *testing.T) {
	config := &DeduplicationConfig{
		Enabled:         true,
		WindowDuration:  time.Minute,
		KeyFields:       []string{"type", "subject"},
		CleanupInterval: time.Hour,
	}

	dedup := NewMemoryDeduplicator(config)
	defer dedup.Stop()

	t.Run("DetectDuplicate", func(t *testing.T) {
		ctx := context.Background()
		
		notification := &Notification{
			Type:    NotificationTypeEmail,
			Subject: "Test Notification",
			Message: "This is a test",
		}

		// First notification should not be duplicate
		isDupe, err := dedup.IsDuplicate(ctx, notification)
		require.NoError(t, err)
		assert.False(t, isDupe)

		// Mark as sent
		err = dedup.MarkSent(ctx, notification)
		require.NoError(t, err)

		// Same notification should be duplicate
		isDupe, err = dedup.IsDuplicate(ctx, notification)
		require.NoError(t, err)
		assert.True(t, isDupe)

		// Different notification should not be duplicate
		differentNotification := &Notification{
			Type:    NotificationTypeEmail,
			Subject: "Different Subject",
			Message: "This is a test",
		}

		isDupe, err = dedup.IsDuplicate(ctx, differentNotification)
		require.NoError(t, err)
		assert.False(t, isDupe)
	})

	t.Run("Cleanup", func(t *testing.T) {
		ctx := context.Background()
		
		notification := &Notification{
			Type:    NotificationTypeEmail,
			Subject: "Cleanup Test",
			Message: "This is a test",
		}

		err := dedup.MarkSent(ctx, notification)
		require.NoError(t, err)

		// Should be duplicate
		isDupe, err := dedup.IsDuplicate(ctx, notification)
		require.NoError(t, err)
		assert.True(t, isDupe)

		// Cleanup old records
		cutoff := time.Now().Add(-time.Hour)
		err = dedup.Cleanup(ctx, cutoff)
		require.NoError(t, err)

		// Should still be duplicate (not old enough)
		isDupe, err = dedup.IsDuplicate(ctx, notification)
		require.NoError(t, err)
		assert.True(t, isDupe)

		// Cleanup recent records
		cutoff = time.Now().Add(time.Hour)
		err = dedup.Cleanup(ctx, cutoff)
		require.NoError(t, err)

		// Should not be duplicate anymore
		isDupe, err = dedup.IsDuplicate(ctx, notification)
		require.NoError(t, err)
		assert.False(t, isDupe)
	})
}

func TestAlertManager(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	config := DefaultNotificationConfig()
	notificationSvc := NewService(config, logger)
	templateManager := NewTemplateManager(logger)
	alertManager := NewAlertManager(notificationSvc, templateManager, logger)

	t.Run("CreateRule", func(t *testing.T) {
		rule := &AlertRule{
			Name:        "Test Rule",
			Description: "Test alert rule",
			EventType:   EventTypeAuthFailure,
			Conditions: []AlertCondition{
				{
					Field:    "source",
					Operator: "eq",
					Value:    "auth_service",
				},
			},
			Severity: SeverityWarning,
			Channels: []string{"test-channel"},
			Enabled:  true,
			Cooldown: time.Minute,
		}

		err := alertManager.CreateRule(context.Background(), rule)
		require.NoError(t, err)
		assert.NotEmpty(t, rule.ID)
	})

	t.Run("EvaluateRules", func(t *testing.T) {
		event := &AlertEvent{
			ID:     "test-event",
			Type:   EventTypeAuthFailure,
			Source: "auth_service",
			Data: map[string]interface{}{
				"user":       "testuser",
				"ip_address": "192.168.1.1",
			},
			Timestamp: time.Now(),
		}

		alerts, err := alertManager.EvaluateRules(context.Background(), event)
		require.NoError(t, err)
		assert.Len(t, alerts, 1)

		alert := alerts[0]
		assert.Equal(t, SeverityWarning, alert.Severity)
		assert.Equal(t, AlertStatusFiring, alert.Status)
		assert.NotEmpty(t, alert.Message)
	})

	t.Run("GetRule", func(t *testing.T) {
		rules, err := alertManager.ListRules(context.Background())
		require.NoError(t, err)
		require.Len(t, rules, 1)

		rule, err := alertManager.GetRule(context.Background(), rules[0].ID)
		require.NoError(t, err)
		assert.Equal(t, "Test Rule", rule.Name)
	})

	t.Run("UpdateRule", func(t *testing.T) {
		rules, err := alertManager.ListRules(context.Background())
		require.NoError(t, err)
		require.Len(t, rules, 1)

		rule := rules[0]
		rule.Name = "Updated Test Rule"
		rule.Severity = SeverityError

		err = alertManager.UpdateRule(context.Background(), rule)
		require.NoError(t, err)

		updated, err := alertManager.GetRule(context.Background(), rule.ID)
		require.NoError(t, err)
		assert.Equal(t, "Updated Test Rule", updated.Name)
		assert.Equal(t, SeverityError, updated.Severity)
	})

	t.Run("DeleteRule", func(t *testing.T) {
		rules, err := alertManager.ListRules(context.Background())
		require.NoError(t, err)
		require.Len(t, rules, 1)

		err = alertManager.DeleteRule(context.Background(), rules[0].ID)
		require.NoError(t, err)

		rules, err = alertManager.ListRules(context.Background())
		require.NoError(t, err)
		assert.Len(t, rules, 0)
	})
}

func TestTemplateManager(t *testing.T) {
	logger := logrus.New()
	templateManager := NewTemplateManager(logger)

	t.Run("RegisterTemplate", func(t *testing.T) {
		template := &Template{
			Name:    "Test Template",
			Type:    NotificationTypeEmail,
			Subject: "Test Subject",
			Body:    "Hello {{.name}}, this is a test notification.",
		}

		err := templateManager.RegisterTemplate(context.Background(), template)
		require.NoError(t, err)
		assert.NotEmpty(t, template.ID)
		assert.Contains(t, template.Variables, "name")
	})

	t.Run("RenderTemplate", func(t *testing.T) {
		templates, err := templateManager.ListTemplates(context.Background())
		require.NoError(t, err)
		
		// Find our test template
		var testTemplate *Template
		for _, tmpl := range templates {
			if tmpl.Name == "Test Template" {
				testTemplate = tmpl
				break
			}
		}
		require.NotNil(t, testTemplate)

		data := map[string]interface{}{
			"name": "John Doe",
		}

		rendered, err := templateManager.RenderTemplate(context.Background(), testTemplate.ID, data)
		require.NoError(t, err)
		assert.Equal(t, "Hello John Doe, this is a test notification.", rendered)
	})

	t.Run("DefaultTemplates", func(t *testing.T) {
		templates, err := templateManager.ListTemplates(context.Background())
		require.NoError(t, err)
		
		// Should have default templates plus our test template
		assert.Greater(t, len(templates), 5)

		// Check for specific default templates
		templateNames := make(map[string]bool)
		for _, tmpl := range templates {
			templateNames[tmpl.ID] = true
		}

		assert.True(t, templateNames["secret_rotation_success"])
		assert.True(t, templateNames["secret_rotation_failed"])
		assert.True(t, templateNames["auth_failure"])
	})
}