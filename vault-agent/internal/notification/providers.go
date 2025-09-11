package notification

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// EmailProvider implements email notifications
type EmailProvider struct {
	logger *logrus.Logger
}

// NewEmailProvider creates a new email provider
func NewEmailProvider(logger *logrus.Logger) *EmailProvider {
	return &EmailProvider{
		logger: logger,
	}
}

// Send sends an email notification
func (p *EmailProvider) Send(ctx context.Context, config map[string]interface{}, notification *Notification) error {
	emailConfig, err := p.parseConfig(config)
	if err != nil {
		return fmt.Errorf("invalid email configuration: %w", err)
	}

	// Create message
	message := p.buildMessage(emailConfig, notification)

	// Setup authentication
	auth := smtp.PlainAuth("", emailConfig.Username, emailConfig.Password, emailConfig.SMTPHost)

	// Setup TLS config
	tlsConfig := &tls.Config{
		ServerName:         emailConfig.SMTPHost,
		InsecureSkipVerify: emailConfig.SkipVerify,
	}

	// Connect to server
	addr := fmt.Sprintf("%s:%d", emailConfig.SMTPHost, emailConfig.SMTPPort)
	
	if emailConfig.UseTLS {
		// Direct TLS connection
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server with TLS: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, emailConfig.SMTPHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Quit()

		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}

		return p.sendMessage(client, emailConfig, message)
	} else {
		// Plain connection with optional STARTTLS
		client, err := smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer client.Quit()

		if emailConfig.UseStartTLS {
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("STARTTLS failed: %w", err)
			}
		}

		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}

		return p.sendMessage(client, emailConfig, message)
	}
}

// sendMessage sends the email message using the SMTP client
func (p *EmailProvider) sendMessage(client *smtp.Client, config *EmailConfig, message []byte) error {
	// Set sender
	if err := client.Mail(config.From); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipients
	allRecipients := append(config.To, config.CC...)
	allRecipients = append(allRecipients, config.BCC...)
	
	for _, recipient := range allRecipients {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}

	// Send message
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}
	defer writer.Close()

	if _, err := writer.Write(message); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

// buildMessage builds the email message
func (p *EmailProvider) buildMessage(config *EmailConfig, notification *Notification) []byte {
	var buffer bytes.Buffer

	// Headers
	buffer.WriteString(fmt.Sprintf("From: %s\r\n", config.From))
	buffer.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(config.To, ", ")))
	
	if len(config.CC) > 0 {
		buffer.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(config.CC, ", ")))
	}
	
	buffer.WriteString(fmt.Sprintf("Subject: %s\r\n", notification.Subject))
	buffer.WriteString("MIME-Version: 1.0\r\n")
	buffer.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	buffer.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	buffer.WriteString("\r\n")

	// Body
	buffer.WriteString(notification.Message)
	
	// Add data if present
	if len(notification.Data) > 0 {
		buffer.WriteString("\r\n\r\n--- Additional Data ---\r\n")
		for key, value := range notification.Data {
			buffer.WriteString(fmt.Sprintf("%s: %v\r\n", key, value))
		}
	}

	return buffer.Bytes()
}

// parseConfig parses email configuration
func (p *EmailProvider) parseConfig(config map[string]interface{}) (*EmailConfig, error) {
	emailConfig := &EmailConfig{}

	if host, ok := config["smtp_host"].(string); ok {
		emailConfig.SMTPHost = host
	} else {
		return nil, fmt.Errorf("smtp_host is required")
	}

	if port, ok := config["smtp_port"].(int); ok {
		emailConfig.SMTPPort = port
	} else if portStr, ok := config["smtp_port"].(string); ok {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid smtp_port: %w", err)
		}
		emailConfig.SMTPPort = port
	} else {
		emailConfig.SMTPPort = 587 // Default SMTP port
	}

	if username, ok := config["username"].(string); ok {
		emailConfig.Username = username
	}

	if password, ok := config["password"].(string); ok {
		emailConfig.Password = password
	}

	if from, ok := config["from"].(string); ok {
		emailConfig.From = from
	} else {
		return nil, fmt.Errorf("from address is required")
	}

	if to, ok := config["to"].([]interface{}); ok {
		for _, recipient := range to {
			if recipientStr, ok := recipient.(string); ok {
				emailConfig.To = append(emailConfig.To, recipientStr)
			}
		}
	} else if toStr, ok := config["to"].(string); ok {
		emailConfig.To = []string{toStr}
	} else if toSlice, ok := config["to"].([]string); ok {
		emailConfig.To = toSlice
	}

	if len(emailConfig.To) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	// Optional fields
	if cc, ok := config["cc"].([]interface{}); ok {
		for _, recipient := range cc {
			if recipientStr, ok := recipient.(string); ok {
				emailConfig.CC = append(emailConfig.CC, recipientStr)
			}
		}
	}

	if bcc, ok := config["bcc"].([]interface{}); ok {
		for _, recipient := range bcc {
			if recipientStr, ok := recipient.(string); ok {
				emailConfig.BCC = append(emailConfig.BCC, recipientStr)
			}
		}
	}

	if useTLS, ok := config["use_tls"].(bool); ok {
		emailConfig.UseTLS = useTLS
	}

	if useStartTLS, ok := config["use_starttls"].(bool); ok {
		emailConfig.UseStartTLS = useStartTLS
	}

	if skipVerify, ok := config["skip_verify"].(bool); ok {
		emailConfig.SkipVerify = skipVerify
	}

	return emailConfig, nil
}

// Validate validates email configuration
func (p *EmailProvider) Validate(config map[string]interface{}) error {
	_, err := p.parseConfig(config)
	return err
}

// GetType returns the provider type
func (p *EmailProvider) GetType() NotificationType {
	return NotificationTypeEmail
}

// GetConfigSchema returns the configuration schema
func (p *EmailProvider) GetConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"smtp_host":     "string (required)",
		"smtp_port":     "int (default: 587)",
		"username":      "string",
		"password":      "string",
		"from":          "string (required)",
		"to":            "[]string (required)",
		"cc":            "[]string (optional)",
		"bcc":           "[]string (optional)",
		"use_tls":       "bool (default: false)",
		"use_starttls":  "bool (default: false)",
		"skip_verify":   "bool (default: false)",
	}
}

// WebhookProvider implements webhook notifications
type WebhookProvider struct {
	logger *logrus.Logger
	client *http.Client
}

// NewWebhookProvider creates a new webhook provider
func NewWebhookProvider(logger *logrus.Logger) *WebhookProvider {
	return &WebhookProvider{
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Send sends a webhook notification
func (p *WebhookProvider) Send(ctx context.Context, config map[string]interface{}, notification *Notification) error {
	webhookConfig, err := p.parseConfig(config)
	if err != nil {
		return fmt.Errorf("invalid webhook configuration: %w", err)
	}

	// Create payload
	payload := map[string]interface{}{
		"id":         notification.ID,
		"type":       string(notification.Type),
		"subject":    notification.Subject,
		"message":    notification.Message,
		"data":       notification.Data,
		"priority":   notification.Priority,
		"created_at": notification.CreatedAt.Format(time.RFC3339),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, webhookConfig.Method, webhookConfig.URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vault-agent-notification/1.0")
	
	for key, value := range webhookConfig.Headers {
		req.Header.Set(key, value)
	}

	// Set timeout
	client := p.client
	if webhookConfig.Timeout > 0 {
		client = &http.Client{
			Timeout: webhookConfig.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: webhookConfig.SkipVerify,
				},
			},
		}
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// parseConfig parses webhook configuration
func (p *WebhookProvider) parseConfig(config map[string]interface{}) (*WebhookConfig, error) {
	webhookConfig := &WebhookConfig{}

	if url, ok := config["url"].(string); ok {
		webhookConfig.URL = url
	} else {
		return nil, fmt.Errorf("url is required")
	}

	if method, ok := config["method"].(string); ok {
		webhookConfig.Method = strings.ToUpper(method)
	} else {
		webhookConfig.Method = "POST"
	}

	if headers, ok := config["headers"].(map[string]interface{}); ok {
		webhookConfig.Headers = make(map[string]string)
		for key, value := range headers {
			if valueStr, ok := value.(string); ok {
				webhookConfig.Headers[key] = valueStr
			}
		}
	}

	if timeout, ok := config["timeout"].(string); ok {
		duration, err := time.ParseDuration(timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout duration: %w", err)
		}
		webhookConfig.Timeout = duration
	}

	if retryCount, ok := config["retry_count"].(int); ok {
		webhookConfig.RetryCount = retryCount
	}

	if skipVerify, ok := config["skip_verify"].(bool); ok {
		webhookConfig.SkipVerify = skipVerify
	}

	if secret, ok := config["secret"].(string); ok {
		webhookConfig.Secret = secret
	}

	return webhookConfig, nil
}

// Validate validates webhook configuration
func (p *WebhookProvider) Validate(config map[string]interface{}) error {
	_, err := p.parseConfig(config)
	return err
}

// GetType returns the provider type
func (p *WebhookProvider) GetType() NotificationType {
	return NotificationTypeWebhook
}

// GetConfigSchema returns the configuration schema
func (p *WebhookProvider) GetConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"url":         "string (required)",
		"method":      "string (default: POST)",
		"headers":     "map[string]string (optional)",
		"timeout":     "duration (default: 30s)",
		"retry_count": "int (default: 0)",
		"skip_verify": "bool (default: false)",
		"secret":      "string (optional)",
	}
}

// SlackProvider implements Slack notifications
type SlackProvider struct {
	logger *logrus.Logger
	client *http.Client
}

// NewSlackProvider creates a new Slack provider
func NewSlackProvider(logger *logrus.Logger) *SlackProvider {
	return &SlackProvider{
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Send sends a Slack notification
func (p *SlackProvider) Send(ctx context.Context, config map[string]interface{}, notification *Notification) error {
	slackConfig, err := p.parseConfig(config)
	if err != nil {
		return fmt.Errorf("invalid Slack configuration: %w", err)
	}

	// Create Slack message
	message := p.buildSlackMessage(slackConfig, notification)

	payloadBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	// Send to Slack
	req, err := http.NewRequestWithContext(ctx, "POST", slackConfig.WebhookURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create Slack request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("Slack request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Slack returned status %d", resp.StatusCode)
	}

	return nil
}

// buildSlackMessage builds a Slack message
func (p *SlackProvider) buildSlackMessage(config *SlackConfig, notification *Notification) map[string]interface{} {
	message := map[string]interface{}{
		"text": notification.Subject,
	}

	if config.Channel != "" {
		message["channel"] = config.Channel
	}

	if config.Username != "" {
		message["username"] = config.Username
	}

	if config.IconEmoji != "" {
		message["icon_emoji"] = config.IconEmoji
	}

	if config.IconURL != "" {
		message["icon_url"] = config.IconURL
	}

	// Create attachment with notification details
	attachment := map[string]interface{}{
		"color":     p.getColorForPriority(notification.Priority),
		"text":      notification.Message,
		"timestamp": notification.CreatedAt.Unix(),
		"fields":    []map[string]interface{}{},
	}

	// Add data fields
	if len(notification.Data) > 0 {
		fields := attachment["fields"].([]map[string]interface{})
		for key, value := range notification.Data {
			fields = append(fields, map[string]interface{}{
				"title": key,
				"value": fmt.Sprintf("%v", value),
				"short": true,
			})
		}
		attachment["fields"] = fields
	}

	message["attachments"] = []map[string]interface{}{attachment}

	return message
}

// getColorForPriority returns a color based on notification priority
func (p *SlackProvider) getColorForPriority(priority int) string {
	switch {
	case priority >= 4:
		return "danger"  // Red for critical
	case priority >= 3:
		return "warning" // Yellow for warning
	case priority >= 2:
		return "good"    // Green for info
	default:
		return "#36a64f" // Default green
	}
}

// parseConfig parses Slack configuration
func (p *SlackProvider) parseConfig(config map[string]interface{}) (*SlackConfig, error) {
	slackConfig := &SlackConfig{}

	if webhookURL, ok := config["webhook_url"].(string); ok {
		slackConfig.WebhookURL = webhookURL
	} else {
		return nil, fmt.Errorf("webhook_url is required")
	}

	if channel, ok := config["channel"].(string); ok {
		slackConfig.Channel = channel
	}

	if username, ok := config["username"].(string); ok {
		slackConfig.Username = username
	}

	if iconEmoji, ok := config["icon_emoji"].(string); ok {
		slackConfig.IconEmoji = iconEmoji
	}

	if iconURL, ok := config["icon_url"].(string); ok {
		slackConfig.IconURL = iconURL
	}

	return slackConfig, nil
}

// Validate validates Slack configuration
func (p *SlackProvider) Validate(config map[string]interface{}) error {
	_, err := p.parseConfig(config)
	return err
}

// GetType returns the provider type
func (p *SlackProvider) GetType() NotificationType {
	return NotificationTypeSlack
}

// GetConfigSchema returns the configuration schema
func (p *SlackProvider) GetConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"webhook_url": "string (required)",
		"channel":     "string (optional)",
		"username":    "string (optional)",
		"icon_emoji":  "string (optional)",
		"icon_url":    "string (optional)",
	}
}