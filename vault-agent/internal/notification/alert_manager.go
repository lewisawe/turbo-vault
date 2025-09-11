package notification

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// AlertManagerImpl implements the AlertManager interface
type AlertManagerImpl struct {
	rules            map[string]*AlertRule
	alerts           map[string]*Alert
	notificationSvc  NotificationService
	templateManager  TemplateManager
	logger           *logrus.Logger
	mu               sync.RWMutex
	cooldownTracker  map[string]time.Time
}

// NewAlertManager creates a new alert manager
func NewAlertManager(notificationSvc NotificationService, templateManager TemplateManager, logger *logrus.Logger) *AlertManagerImpl {
	return &AlertManagerImpl{
		rules:           make(map[string]*AlertRule),
		alerts:          make(map[string]*Alert),
		notificationSvc: notificationSvc,
		templateManager: templateManager,
		logger:          logger,
		cooldownTracker: make(map[string]time.Time),
	}
}

// CreateRule creates a new alert rule
func (am *AlertManagerImpl) CreateRule(ctx context.Context, rule *AlertRule) error {
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}

	// Validate rule
	if err := am.validateRule(rule); err != nil {
		return fmt.Errorf("invalid alert rule: %w", err)
	}

	// Set timestamps
	now := time.Now()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now

	am.mu.Lock()
	am.rules[rule.ID] = rule
	am.mu.Unlock()

	am.logger.Infof("Created alert rule %s (%s)", rule.ID, rule.Name)
	return nil
}

// UpdateRule updates an existing alert rule
func (am *AlertManagerImpl) UpdateRule(ctx context.Context, rule *AlertRule) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	existing, exists := am.rules[rule.ID]
	if !exists {
		return fmt.Errorf("alert rule %s not found", rule.ID)
	}

	// Validate rule
	if err := am.validateRule(rule); err != nil {
		return fmt.Errorf("invalid alert rule: %w", err)
	}

	// Preserve creation time and fire count
	rule.CreatedAt = existing.CreatedAt
	rule.FireCount = existing.FireCount
	rule.LastFired = existing.LastFired
	rule.UpdatedAt = time.Now()

	am.rules[rule.ID] = rule
	am.logger.Infof("Updated alert rule %s", rule.ID)
	return nil
}

// DeleteRule deletes an alert rule
func (am *AlertManagerImpl) DeleteRule(ctx context.Context, ruleID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.rules[ruleID]; !exists {
		return fmt.Errorf("alert rule %s not found", ruleID)
	}

	delete(am.rules, ruleID)
	delete(am.cooldownTracker, ruleID)
	am.logger.Infof("Deleted alert rule %s", ruleID)
	return nil
}

// GetRule retrieves an alert rule by ID
func (am *AlertManagerImpl) GetRule(ctx context.Context, ruleID string) (*AlertRule, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	rule, exists := am.rules[ruleID]
	if !exists {
		return nil, fmt.Errorf("alert rule %s not found", ruleID)
	}

	// Return a copy
	ruleCopy := *rule
	return &ruleCopy, nil
}

// ListRules lists all alert rules
func (am *AlertManagerImpl) ListRules(ctx context.Context) ([]*AlertRule, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	rules := make([]*AlertRule, 0, len(am.rules))
	for _, rule := range am.rules {
		ruleCopy := *rule
		rules = append(rules, &ruleCopy)
	}

	return rules, nil
}

// EvaluateRules evaluates all active alert rules against an event
func (am *AlertManagerImpl) EvaluateRules(ctx context.Context, event *AlertEvent) ([]*Alert, error) {
	am.mu.RLock()
	rules := make([]*AlertRule, 0, len(am.rules))
	for _, rule := range am.rules {
		if rule.Enabled && rule.EventType == event.Type {
			rules = append(rules, rule)
		}
	}
	am.mu.RUnlock()

	var alerts []*Alert
	for _, rule := range rules {
		// Check cooldown
		if am.isInCooldown(rule.ID, rule.Cooldown) {
			continue
		}

		// Evaluate conditions
		if am.evaluateConditions(rule.Conditions, event) {
			alert, err := am.createAlert(rule, event)
			if err != nil {
				am.logger.Errorf("Failed to create alert for rule %s: %v", rule.ID, err)
				continue
			}

			alerts = append(alerts, alert)
			
			// Update rule statistics
			am.updateRuleStats(rule.ID)
		}
	}

	return alerts, nil
}

// ProcessAlert processes an alert and sends notifications
func (am *AlertManagerImpl) ProcessAlert(ctx context.Context, alert *Alert) error {
	// Store alert
	am.mu.Lock()
	am.alerts[alert.ID] = alert
	am.mu.Unlock()

	// Get rule for template
	rule, err := am.GetRule(ctx, alert.RuleID)
	if err != nil {
		return fmt.Errorf("failed to get rule for alert: %w", err)
	}

	// Create notification
	notification, err := am.createNotificationFromAlert(ctx, alert, rule)
	if err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	// Send notifications to all configured channels
	var notificationIDs []string
	for _, channelID := range alert.Channels {
		notificationCopy := *notification
		notificationCopy.ID = uuid.New().String()
		
		if err := am.notificationSvc.Send(ctx, channelID, &notificationCopy); err != nil {
			am.logger.Errorf("Failed to send alert notification to channel %s: %v", channelID, err)
		} else {
			notificationIDs = append(notificationIDs, notificationCopy.ID)
		}
	}

	// Update alert with notification IDs
	am.mu.Lock()
	alert.Notifications = notificationIDs
	am.mu.Unlock()

	am.logger.Infof("Processed alert %s, sent %d notifications", alert.ID, len(notificationIDs))
	return nil
}

// GetAlertHistory retrieves alert history
func (am *AlertManagerImpl) GetAlertHistory(ctx context.Context, filter *AlertFilter) ([]*Alert, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var alerts []*Alert
	for _, alert := range am.alerts {
		if am.matchesFilter(alert, filter) {
			alertCopy := *alert
			alerts = append(alerts, &alertCopy)
		}
	}

	// Apply limit and offset
	if filter != nil {
		if filter.Offset > 0 && filter.Offset < len(alerts) {
			alerts = alerts[filter.Offset:]
		}
		if filter.Limit > 0 && filter.Limit < len(alerts) {
			alerts = alerts[:filter.Limit]
		}
	}

	return alerts, nil
}

// validateRule validates an alert rule
func (am *AlertManagerImpl) validateRule(rule *AlertRule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}

	if rule.EventType == "" {
		return fmt.Errorf("event type is required")
	}

	if len(rule.Channels) == 0 {
		return fmt.Errorf("at least one notification channel is required")
	}

	// Validate conditions
	for i, condition := range rule.Conditions {
		if err := am.validateCondition(&condition); err != nil {
			return fmt.Errorf("invalid condition %d: %w", i, err)
		}
	}

	return nil
}

// validateCondition validates an alert condition
func (am *AlertManagerImpl) validateCondition(condition *AlertCondition) error {
	if condition.Field == "" {
		return fmt.Errorf("condition field is required")
	}

	validOperators := []string{"eq", "ne", "gt", "lt", "gte", "lte", "contains", "regex"}
	validOperator := false
	for _, op := range validOperators {
		if condition.Operator == op {
			validOperator = true
			break
		}
	}

	if !validOperator {
		return fmt.Errorf("invalid operator %s", condition.Operator)
	}

	if condition.Value == nil {
		return fmt.Errorf("condition value is required")
	}

	return nil
}

// evaluateConditions evaluates alert conditions against an event
func (am *AlertManagerImpl) evaluateConditions(conditions []AlertCondition, event *AlertEvent) bool {
	if len(conditions) == 0 {
		return true // No conditions means always match
	}

	for _, condition := range conditions {
		if !am.evaluateCondition(&condition, event) {
			return false // All conditions must match (AND logic)
		}
	}

	return true
}

// evaluateCondition evaluates a single condition
func (am *AlertManagerImpl) evaluateCondition(condition *AlertCondition, event *AlertEvent) bool {
	// Get field value from event
	var fieldValue interface{}
	
	switch condition.Field {
	case "type":
		fieldValue = string(event.Type)
	case "source":
		fieldValue = event.Source
	case "timestamp":
		fieldValue = event.Timestamp
	default:
		// Look in event data
		if value, exists := event.Data[condition.Field]; exists {
			fieldValue = value
		} else if value, exists := event.Metadata[condition.Field]; exists {
			fieldValue = value
		} else {
			return false // Field not found
		}
	}

	return am.compareValues(fieldValue, condition.Operator, condition.Value)
}

// compareValues compares two values using the specified operator
func (am *AlertManagerImpl) compareValues(fieldValue interface{}, operator string, conditionValue interface{}) bool {
	switch operator {
	case "eq":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", conditionValue)
	case "ne":
		return fmt.Sprintf("%v", fieldValue) != fmt.Sprintf("%v", conditionValue)
	case "contains":
		fieldStr := fmt.Sprintf("%v", fieldValue)
		conditionStr := fmt.Sprintf("%v", conditionValue)
		return strings.Contains(fieldStr, conditionStr)
	case "regex":
		fieldStr := fmt.Sprintf("%v", fieldValue)
		conditionStr := fmt.Sprintf("%v", conditionValue)
		matched, err := regexp.MatchString(conditionStr, fieldStr)
		return err == nil && matched
	case "gt", "lt", "gte", "lte":
		return am.compareNumeric(fieldValue, operator, conditionValue)
	default:
		return false
	}
}

// compareNumeric compares numeric values
func (am *AlertManagerImpl) compareNumeric(fieldValue interface{}, operator string, conditionValue interface{}) bool {
	fieldNum, err1 := am.toFloat64(fieldValue)
	conditionNum, err2 := am.toFloat64(conditionValue)
	
	if err1 != nil || err2 != nil {
		return false
	}

	switch operator {
	case "gt":
		return fieldNum > conditionNum
	case "lt":
		return fieldNum < conditionNum
	case "gte":
		return fieldNum >= conditionNum
	case "lte":
		return fieldNum <= conditionNum
	default:
		return false
	}
}

// toFloat64 converts a value to float64
func (am *AlertManagerImpl) toFloat64(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", value)
	}
}

// isInCooldown checks if a rule is in cooldown period
func (am *AlertManagerImpl) isInCooldown(ruleID string, cooldown time.Duration) bool {
	if cooldown == 0 {
		return false
	}

	am.mu.RLock()
	lastFired, exists := am.cooldownTracker[ruleID]
	am.mu.RUnlock()

	if !exists {
		return false
	}

	return time.Since(lastFired) < cooldown
}

// createAlert creates an alert from a rule and event
func (am *AlertManagerImpl) createAlert(rule *AlertRule, event *AlertEvent) (*Alert, error) {
	alert := &Alert{
		ID:       uuid.New().String(),
		RuleID:   rule.ID,
		RuleName: rule.Name,
		EventID:  event.ID,
		Severity: rule.Severity,
		Status:   AlertStatusFiring,
		Data:     event.Data,
		FiredAt:  time.Now(),
		Channels: rule.Channels,
	}

	// Generate alert message
	if rule.Template != "" {
		message, err := am.templateManager.RenderTemplate(context.Background(), rule.Template, map[string]interface{}{
			"alert": alert,
			"event": event,
			"rule":  rule,
		})
		if err != nil {
			am.logger.Warnf("Failed to render template %s: %v", rule.Template, err)
			alert.Message = fmt.Sprintf("Alert: %s - %s", rule.Name, rule.Description)
		} else {
			alert.Message = message
		}
	} else {
		alert.Message = fmt.Sprintf("Alert: %s - %s", rule.Name, rule.Description)
	}

	return alert, nil
}

// createNotificationFromAlert creates a notification from an alert
func (am *AlertManagerImpl) createNotificationFromAlert(ctx context.Context, alert *Alert, rule *AlertRule) (*Notification, error) {
	var priority int
	switch alert.Severity {
	case SeverityCritical:
		priority = 4
	case SeverityError:
		priority = 3
	case SeverityWarning:
		priority = 2
	case SeverityInfo:
		priority = 1
	default:
		priority = 1
	}

	notification := &Notification{
		Type:     NotificationTypeEmail, // Default, will be overridden by channel type
		Subject:  fmt.Sprintf("[%s] %s", strings.ToUpper(string(alert.Severity)), rule.Name),
		Message:  alert.Message,
		Priority: priority,
		Data: map[string]interface{}{
			"alert_id":   alert.ID,
			"rule_id":    alert.RuleID,
			"rule_name":  alert.RuleName,
			"severity":   string(alert.Severity),
			"fired_at":   alert.FiredAt.Format(time.RFC3339),
			"event_id":   alert.EventID,
		},
		CreatedAt:  time.Now(),
		MaxRetries: 3,
	}

	// Merge alert data
	for key, value := range alert.Data {
		notification.Data[key] = value
	}

	return notification, nil
}

// updateRuleStats updates rule statistics after firing
func (am *AlertManagerImpl) updateRuleStats(ruleID string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if rule, exists := am.rules[ruleID]; exists {
		now := time.Now()
		rule.FireCount++
		rule.LastFired = &now
		am.cooldownTracker[ruleID] = now
	}
}

// matchesFilter checks if an alert matches the given filter
func (am *AlertManagerImpl) matchesFilter(alert *Alert, filter *AlertFilter) bool {
	if filter == nil {
		return true
	}

	if filter.RuleID != "" && alert.RuleID != filter.RuleID {
		return false
	}

	if filter.Severity != "" && alert.Severity != filter.Severity {
		return false
	}

	if filter.Status != "" && alert.Status != filter.Status {
		return false
	}

	if filter.StartTime != nil && alert.FiredAt.Before(*filter.StartTime) {
		return false
	}

	if filter.EndTime != nil && alert.FiredAt.After(*filter.EndTime) {
		return false
	}

	return true
}