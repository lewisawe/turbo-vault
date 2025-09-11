package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DefaultConditionEvaluator implements the ConditionEvaluator interface
type DefaultConditionEvaluator struct {
	logger    *logrus.Logger
	functions map[string]ConditionFunction
}

// ConditionFunction represents a custom function that can be used in conditions
type ConditionFunction func(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error)

// NewDefaultConditionEvaluator creates a new condition evaluator with built-in functions
func NewDefaultConditionEvaluator(logger *logrus.Logger) *DefaultConditionEvaluator {
	evaluator := &DefaultConditionEvaluator{
		logger:    logger,
		functions: make(map[string]ConditionFunction),
	}

	// Register built-in functions
	evaluator.registerBuiltinFunctions()

	return evaluator
}

// Evaluate evaluates a single policy condition
func (e *DefaultConditionEvaluator) Evaluate(ctx context.Context, condition *PolicyCondition, context *RequestContext) (bool, error) {
	switch condition.Type {
	case ConditionTypeTime:
		return e.evaluateTimeCondition(condition, context)
	case ConditionTypeIP:
		return e.evaluateIPCondition(condition, context)
	case ConditionTypeAttribute:
		return e.evaluateAttributeCondition(condition, context)
	case ConditionTypeFunction:
		return e.evaluateFunctionCondition(ctx, condition, context)
	case ConditionTypeRegex:
		return e.evaluateRegexCondition(condition, context)
	case ConditionTypeJSON:
		return e.evaluateJSONCondition(condition, context)
	default:
		return false, fmt.Errorf("unsupported condition type: %s", condition.Type)
	}
}

// SupportedOperators returns the list of supported operators
func (e *DefaultConditionEvaluator) SupportedOperators() []string {
	return []string{
		string(OperatorEquals), string(OperatorNotEquals),
		string(OperatorGreaterThan), string(OperatorLessThan),
		string(OperatorGreaterOrEqual), string(OperatorLessOrEqual),
		string(OperatorIn), string(OperatorNotIn),
		string(OperatorContains), string(OperatorNotContains),
		string(OperatorStartsWith), string(OperatorEndsWith),
		string(OperatorMatches), string(OperatorNotMatches),
		string(OperatorExists), string(OperatorNotExists),
	}
}

// SupportedFunctions returns the list of supported functions
func (e *DefaultConditionEvaluator) SupportedFunctions() []string {
	functions := make([]string, 0, len(e.functions))
	for name := range e.functions {
		functions = append(functions, name)
	}
	return functions
}

// RegisterFunction registers a custom condition function
func (e *DefaultConditionEvaluator) RegisterFunction(name string, fn ConditionFunction) {
	e.functions[name] = fn
}

// Time Condition Evaluation

func (e *DefaultConditionEvaluator) evaluateTimeCondition(condition *PolicyCondition, context *RequestContext) (bool, error) {
	var currentTime time.Time
	if context != nil && !context.Timestamp.IsZero() {
		currentTime = context.Timestamp
	} else {
		currentTime = time.Now()
	}

	switch condition.Field {
	case "hour":
		return e.compareValues(currentTime.Hour(), condition.Operator, condition.Value)
	case "minute":
		return e.compareValues(currentTime.Minute(), condition.Operator, condition.Value)
	case "day_of_week":
		return e.compareValues(int(currentTime.Weekday()), condition.Operator, condition.Value)
	case "day_of_month":
		return e.compareValues(currentTime.Day(), condition.Operator, condition.Value)
	case "month":
		return e.compareValues(int(currentTime.Month()), condition.Operator, condition.Value)
	case "year":
		return e.compareValues(currentTime.Year(), condition.Operator, condition.Value)
	case "time_of_day":
		timeStr := fmt.Sprintf("%02d:%02d", currentTime.Hour(), currentTime.Minute())
		return e.compareValues(timeStr, condition.Operator, condition.Value)
	case "timestamp":
		return e.compareValues(currentTime.Unix(), condition.Operator, condition.Value)
	case "timezone":
		zone, _ := currentTime.Zone()
		return e.compareValues(zone, condition.Operator, condition.Value)
	default:
		return false, fmt.Errorf("unsupported time field: %s", condition.Field)
	}
}

// IP Condition Evaluation

func (e *DefaultConditionEvaluator) evaluateIPCondition(condition *PolicyCondition, context *RequestContext) (bool, error) {
	if context == nil || context.IPAddress == "" {
		return false, fmt.Errorf("IP address not available in context")
	}

	clientIP := net.ParseIP(context.IPAddress)
	if clientIP == nil {
		return false, fmt.Errorf("invalid IP address: %s", context.IPAddress)
	}

	switch condition.Field {
	case "address":
		return e.compareIPAddress(clientIP, condition.Operator, condition.Value)
	case "network":
		return e.compareIPNetwork(clientIP, condition.Operator, condition.Value)
	case "country":
		if context.Location != nil {
			return e.compareValues(context.Location.Country, condition.Operator, condition.Value)
		}
		return false, fmt.Errorf("location information not available")
	case "region":
		if context.Location != nil {
			return e.compareValues(context.Location.Region, condition.Operator, condition.Value)
		}
		return false, fmt.Errorf("location information not available")
	case "city":
		if context.Location != nil {
			return e.compareValues(context.Location.City, condition.Operator, condition.Value)
		}
		return false, fmt.Errorf("location information not available")
	case "is_private":
		isPrivate := e.isPrivateIP(clientIP)
		return e.compareValues(isPrivate, condition.Operator, condition.Value)
	case "is_loopback":
		isLoopback := clientIP.IsLoopback()
		return e.compareValues(isLoopback, condition.Operator, condition.Value)
	default:
		return false, fmt.Errorf("unsupported IP field: %s", condition.Field)
	}
}

// Attribute Condition Evaluation

func (e *DefaultConditionEvaluator) evaluateAttributeCondition(condition *PolicyCondition, context *RequestContext) (bool, error) {
	if context == nil {
		return false, fmt.Errorf("request context not available")
	}

	var value interface{}
	var exists bool

	// Get value from context based on field
	switch condition.Field {
	case "user_id":
		value, exists = context.UserID, context.UserID != ""
	case "username":
		value, exists = context.Username, context.Username != ""
	case "roles":
		value, exists = context.Roles, len(context.Roles) > 0
	case "groups":
		value, exists = context.Groups, len(context.Groups) > 0
	case "session_id":
		value, exists = context.SessionID, context.SessionID != ""
	case "user_agent":
		value, exists = context.UserAgent, context.UserAgent != ""
	case "device_type":
		if context.Device != nil {
			value, exists = context.Device.Type, context.Device.Type != ""
		}
	case "os":
		if context.Device != nil {
			value, exists = context.Device.OS, context.Device.OS != ""
		}
	case "browser":
		if context.Device != nil {
			value, exists = context.Device.Browser, context.Device.Browser != ""
		}
	case "trusted_device":
		if context.Device != nil {
			value, exists = context.Device.TrustedDevice, true
		}
	case "network_type":
		if context.Network != nil {
			value, exists = context.Network.NetworkType, context.Network.NetworkType != ""
		}
	case "trusted_network":
		if context.Network != nil {
			value, exists = context.Network.TrustedNetwork, true
		}
	case "vpn":
		if context.Network != nil {
			value, exists = context.Network.VPN, true
		}
	case "auth_method":
		if context.Authentication != nil {
			value, exists = context.Authentication.Method, context.Authentication.Method != ""
		}
	case "mfa_verified":
		if context.Authentication != nil {
			value, exists = context.Authentication.MFAVerified, true
		}
	case "auth_strength":
		if context.Authentication != nil {
			value, exists = context.Authentication.Strength, true
		}
	default:
		// Check custom attributes
		if context.Attributes != nil {
			value, exists = context.Attributes[condition.Field]
		}
	}

	// Handle existence checks
	if condition.Operator == OperatorExists {
		return exists, nil
	}
	if condition.Operator == OperatorNotExists {
		return !exists, nil
	}

	if !exists {
		return false, nil
	}

	return e.compareValues(value, condition.Operator, condition.Value)
}

// Function Condition Evaluation

func (e *DefaultConditionEvaluator) evaluateFunctionCondition(ctx context.Context, condition *PolicyCondition, context *RequestContext) (bool, error) {
	fn, exists := e.functions[condition.Function]
	if !exists {
		return false, fmt.Errorf("unknown function: %s", condition.Function)
	}

	result, err := fn(ctx, condition.Args, context)
	if err != nil {
		return false, fmt.Errorf("function %s failed: %w", condition.Function, err)
	}

	return e.compareValues(result, condition.Operator, condition.Value)
}

// Regex Condition Evaluation

func (e *DefaultConditionEvaluator) evaluateRegexCondition(condition *PolicyCondition, context *RequestContext) (bool, error) {
	if context == nil {
		return false, fmt.Errorf("request context not available")
	}

	var fieldValue string
	switch condition.Field {
	case "user_agent":
		fieldValue = context.UserAgent
	case "username":
		fieldValue = context.Username
	case "session_id":
		fieldValue = context.SessionID
	default:
		if context.Attributes != nil {
			if val, ok := context.Attributes[condition.Field]; ok {
				fieldValue = fmt.Sprintf("%v", val)
			}
		}
	}

	pattern, ok := condition.Value.(string)
	if !ok {
		return false, fmt.Errorf("regex pattern must be a string")
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}

	switch condition.Operator {
	case OperatorMatches:
		return regex.MatchString(fieldValue), nil
	case OperatorNotMatches:
		return !regex.MatchString(fieldValue), nil
	default:
		return false, fmt.Errorf("unsupported operator for regex condition: %s", condition.Operator)
	}
}

// JSON Condition Evaluation

func (e *DefaultConditionEvaluator) evaluateJSONCondition(condition *PolicyCondition, context *RequestContext) (bool, error) {
	if context == nil || context.Attributes == nil {
		return false, fmt.Errorf("request context or attributes not available")
	}

	jsonData, exists := context.Attributes[condition.Field]
	if !exists {
		return condition.Operator == OperatorNotExists, nil
	}

	if condition.Operator == OperatorExists {
		return true, nil
	}

	// Parse JSON path and extract value
	// This is a simplified implementation - in production, use a proper JSON path library
	jsonStr, ok := jsonData.(string)
	if !ok {
		// Try to marshal if it's not a string
		jsonBytes, err := json.Marshal(jsonData)
		if err != nil {
			return false, fmt.Errorf("failed to marshal JSON data: %w", err)
		}
		jsonStr = string(jsonBytes)
	}

	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return false, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Extract value using simple dot notation (e.g., "user.profile.name")
	value, err := e.extractJSONValue(data, condition.Field)
	if err != nil {
		return false, err
	}

	return e.compareValues(value, condition.Operator, condition.Value)
}

// Helper Methods

func (e *DefaultConditionEvaluator) compareValues(actual interface{}, operator ConditionOperator, expected interface{}) (bool, error) {
	switch operator {
	case OperatorEquals:
		return e.equals(actual, expected), nil
	case OperatorNotEquals:
		return !e.equals(actual, expected), nil
	case OperatorGreaterThan:
		return e.greaterThan(actual, expected)
	case OperatorLessThan:
		return e.lessThan(actual, expected)
	case OperatorGreaterOrEqual:
		gt, err := e.greaterThan(actual, expected)
		if err != nil {
			return false, err
		}
		return gt || e.equals(actual, expected), nil
	case OperatorLessOrEqual:
		lt, err := e.lessThan(actual, expected)
		if err != nil {
			return false, err
		}
		return lt || e.equals(actual, expected), nil
	case OperatorIn:
		return e.in(actual, expected)
	case OperatorNotIn:
		result, err := e.in(actual, expected)
		return !result, err
	case OperatorContains:
		return e.contains(actual, expected)
	case OperatorNotContains:
		result, err := e.contains(actual, expected)
		return !result, err
	case OperatorStartsWith:
		return e.startsWith(actual, expected)
	case OperatorEndsWith:
		return e.endsWith(actual, expected)
	default:
		return false, fmt.Errorf("unsupported operator: %s", operator)
	}
}

func (e *DefaultConditionEvaluator) equals(actual, expected interface{}) bool {
	return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected)
}

func (e *DefaultConditionEvaluator) greaterThan(actual, expected interface{}) (bool, error) {
	actualNum, err := e.toNumber(actual)
	if err != nil {
		return false, err
	}
	expectedNum, err := e.toNumber(expected)
	if err != nil {
		return false, err
	}
	return actualNum > expectedNum, nil
}

func (e *DefaultConditionEvaluator) lessThan(actual, expected interface{}) (bool, error) {
	actualNum, err := e.toNumber(actual)
	if err != nil {
		return false, err
	}
	expectedNum, err := e.toNumber(expected)
	if err != nil {
		return false, err
	}
	return actualNum < expectedNum, nil
}

func (e *DefaultConditionEvaluator) in(actual, expected interface{}) (bool, error) {
	switch exp := expected.(type) {
	case []interface{}:
		for _, item := range exp {
			if e.equals(actual, item) {
				return true, nil
			}
		}
		return false, nil
	case []string:
		actualStr := fmt.Sprintf("%v", actual)
		for _, item := range exp {
			if actualStr == item {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("expected value must be an array for IN operator")
	}
}

func (e *DefaultConditionEvaluator) contains(actual, expected interface{}) (bool, error) {
	// Handle array contains
	if actualSlice, ok := actual.([]string); ok {
		expectedStr := fmt.Sprintf("%v", expected)
		for _, item := range actualSlice {
			if item == expectedStr {
				return true, nil
			}
		}
		return false, nil
	}
	
	// Handle string contains
	actualStr := fmt.Sprintf("%v", actual)
	expectedStr := fmt.Sprintf("%v", expected)
	return strings.Contains(actualStr, expectedStr), nil
}

func (e *DefaultConditionEvaluator) startsWith(actual, expected interface{}) (bool, error) {
	actualStr := fmt.Sprintf("%v", actual)
	expectedStr := fmt.Sprintf("%v", expected)
	return strings.HasPrefix(actualStr, expectedStr), nil
}

func (e *DefaultConditionEvaluator) endsWith(actual, expected interface{}) (bool, error) {
	actualStr := fmt.Sprintf("%v", actual)
	expectedStr := fmt.Sprintf("%v", expected)
	return strings.HasSuffix(actualStr, expectedStr), nil
}

func (e *DefaultConditionEvaluator) toNumber(value interface{}) (float64, error) {
	switch v := value.(type) {
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case float64:
		return v, nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to number", value)
	}
}

func (e *DefaultConditionEvaluator) compareIPAddress(clientIP net.IP, operator ConditionOperator, expected interface{}) (bool, error) {
	expectedStr, ok := expected.(string)
	if !ok {
		return false, fmt.Errorf("IP address must be a string")
	}

	expectedIP := net.ParseIP(expectedStr)
	if expectedIP == nil {
		return false, fmt.Errorf("invalid expected IP address: %s", expectedStr)
	}

	switch operator {
	case OperatorEquals:
		return clientIP.Equal(expectedIP), nil
	case OperatorNotEquals:
		return !clientIP.Equal(expectedIP), nil
	default:
		return false, fmt.Errorf("unsupported operator for IP address: %s", operator)
	}
}

func (e *DefaultConditionEvaluator) compareIPNetwork(clientIP net.IP, operator ConditionOperator, expected interface{}) (bool, error) {
	expectedStr, ok := expected.(string)
	if !ok {
		return false, fmt.Errorf("network must be a string")
	}

	_, network, err := net.ParseCIDR(expectedStr)
	if err != nil {
		return false, fmt.Errorf("invalid network CIDR: %w", err)
	}

	switch operator {
	case OperatorIn:
		return network.Contains(clientIP), nil
	case OperatorNotIn:
		return !network.Contains(clientIP), nil
	default:
		return false, fmt.Errorf("unsupported operator for IP network: %s", operator)
	}
}

func (e *DefaultConditionEvaluator) isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, rangeStr := range privateRanges {
		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func (e *DefaultConditionEvaluator) extractJSONValue(data interface{}, path string) (interface{}, error) {
	// Simple dot notation parser
	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var exists bool
			current, exists = v[part]
			if !exists {
				return nil, fmt.Errorf("path not found: %s", path)
			}
		case []interface{}:
			// Handle array index
			index, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid array index: %s", part)
			}
			if index < 0 || index >= len(v) {
				return nil, fmt.Errorf("array index out of bounds: %d", index)
			}
			current = v[index]
		default:
			return nil, fmt.Errorf("cannot navigate path %s at %s", path, part)
		}
	}

	return current, nil
}

// Built-in Functions

func (e *DefaultConditionEvaluator) registerBuiltinFunctions() {
	// Time-based functions
	e.functions["is_business_hours"] = e.isBusinessHours
	e.functions["is_weekend"] = e.isWeekend
	e.functions["days_since"] = e.daysSince
	e.functions["hours_since"] = e.hoursSince

	// Security functions
	e.functions["is_high_risk_country"] = e.isHighRiskCountry
	e.functions["is_tor_exit"] = e.isTorExit
	e.functions["is_vpn"] = e.isVPN
	e.functions["risk_score"] = e.calculateRiskScore

	// User functions
	e.functions["has_role"] = e.hasRole
	e.functions["has_permission"] = e.hasPermission
	e.functions["session_age"] = e.sessionAge
	e.functions["login_frequency"] = e.loginFrequency
}

func (e *DefaultConditionEvaluator) isBusinessHours(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	if context == nil {
		return false, fmt.Errorf("context required")
	}

	now := context.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	// Default business hours: 9 AM to 5 PM, Monday to Friday
	startHour := 9
	endHour := 17

	if start, ok := args["start_hour"]; ok {
		if h, ok := start.(int); ok {
			startHour = h
		}
	}

	if end, ok := args["end_hour"]; ok {
		if h, ok := end.(int); ok {
			endHour = h
		}
	}

	// Check if it's a weekday
	weekday := now.Weekday()
	if weekday == time.Saturday || weekday == time.Sunday {
		return false, nil
	}

	// Check if it's within business hours
	hour := now.Hour()
	return hour >= startHour && hour < endHour, nil
}

func (e *DefaultConditionEvaluator) isWeekend(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	if context == nil {
		return false, fmt.Errorf("context required")
	}

	now := context.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	weekday := now.Weekday()
	return weekday == time.Saturday || weekday == time.Sunday, nil
}

func (e *DefaultConditionEvaluator) daysSince(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	timestampArg, ok := args["timestamp"]
	if !ok {
		return nil, fmt.Errorf("timestamp argument required")
	}

	var timestamp time.Time
	switch t := timestampArg.(type) {
	case string:
		var err error
		timestamp, err = time.Parse(time.RFC3339, t)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp format: %w", err)
		}
	case int64:
		timestamp = time.Unix(t, 0)
	default:
		return nil, fmt.Errorf("invalid timestamp type")
	}

	now := time.Now()
	if context != nil && !context.Timestamp.IsZero() {
		now = context.Timestamp
	}

	duration := now.Sub(timestamp)
	return int(duration.Hours() / 24), nil
}

func (e *DefaultConditionEvaluator) hoursSince(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	timestampArg, ok := args["timestamp"]
	if !ok {
		return nil, fmt.Errorf("timestamp argument required")
	}

	var timestamp time.Time
	switch t := timestampArg.(type) {
	case string:
		var err error
		timestamp, err = time.Parse(time.RFC3339, t)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp format: %w", err)
		}
	case int64:
		timestamp = time.Unix(t, 0)
	default:
		return nil, fmt.Errorf("invalid timestamp type")
	}

	now := time.Now()
	if context != nil && !context.Timestamp.IsZero() {
		now = context.Timestamp
	}

	duration := now.Sub(timestamp)
	return int(duration.Hours()), nil
}

func (e *DefaultConditionEvaluator) isHighRiskCountry(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	if context == nil || context.Location == nil {
		return false, nil
	}

	// Default high-risk countries list (this would be configurable in production)
	highRiskCountries := []string{"XX", "YY", "ZZ"} // Placeholder country codes

	if countries, ok := args["countries"]; ok {
		if countryList, ok := countries.([]string); ok {
			highRiskCountries = countryList
		}
	}

	for _, country := range highRiskCountries {
		if context.Location.Country == country {
			return true, nil
		}
	}

	return false, nil
}

func (e *DefaultConditionEvaluator) isTorExit(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	if context == nil || context.Network == nil {
		return false, nil
	}

	return context.Network.TorExit, nil
}

func (e *DefaultConditionEvaluator) isVPN(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	if context == nil || context.Network == nil {
		return false, nil
	}

	return context.Network.VPN, nil
}

func (e *DefaultConditionEvaluator) calculateRiskScore(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	if context == nil {
		return 0, nil
	}

	score := 0

	// Base score factors
	if context.Network != nil {
		if context.Network.VPN {
			score += 10
		}
		if context.Network.TorExit {
			score += 50
		}
		if !context.Network.TrustedNetwork {
			score += 20
		}
	}

	if context.Device != nil && !context.Device.TrustedDevice {
		score += 15
	}

	if context.Authentication != nil {
		if !context.Authentication.MFAVerified {
			score += 25
		}
		if context.Authentication.Strength < 3 {
			score += 30
		}
	}

	// Time-based risk
	now := context.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	hour := now.Hour()
	if hour < 6 || hour > 22 {
		score += 10 // Higher risk during off-hours
	}

	return score, nil
}

func (e *DefaultConditionEvaluator) hasRole(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	if context == nil {
		return false, nil
	}

	roleArg, ok := args["role"]
	if !ok {
		return false, fmt.Errorf("role argument required")
	}

	role, ok := roleArg.(string)
	if !ok {
		return false, fmt.Errorf("role must be a string")
	}

	for _, userRole := range context.Roles {
		if userRole == role {
			return true, nil
		}
	}

	return false, nil
}

func (e *DefaultConditionEvaluator) hasPermission(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	// This would integrate with the permission system
	// For now, return false as a placeholder
	return false, nil
}

func (e *DefaultConditionEvaluator) sessionAge(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	if context == nil || context.Authentication == nil {
		return 0, nil
	}

	now := context.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	duration := now.Sub(context.Authentication.LoginTime)
	return int(duration.Minutes()), nil
}

func (e *DefaultConditionEvaluator) loginFrequency(ctx context.Context, args map[string]interface{}, context *RequestContext) (interface{}, error) {
	// This would integrate with user analytics
	// For now, return a placeholder value
	return 1, nil
}