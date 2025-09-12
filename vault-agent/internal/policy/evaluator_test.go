package policy

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestDefaultConditionEvaluator_TimeConditions(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	evaluator := NewDefaultConditionEvaluator(logger)

	ctx := context.Background()
	testTime := time.Date(2023, 6, 15, 14, 30, 0, 0, time.UTC) // Thursday, 2:30 PM

	requestContext := &RequestContext{
		Timestamp: testTime,
	}

	tests := []struct {
		name      string
		condition *PolicyCondition
		expected  bool
	}{
		{
			name: "hour equals",
			condition: &PolicyCondition{
				Type:     ConditionTypeTime,
				Field:    "hour",
				Operator: OperatorEquals,
				Value:    14,
			},
			expected: true,
		},
		{
			name: "hour greater than",
			condition: &PolicyCondition{
				Type:     ConditionTypeTime,
				Field:    "hour",
				Operator: OperatorGreaterThan,
				Value:    10,
			},
			expected: true,
		},
		{
			name: "day of week",
			condition: &PolicyCondition{
				Type:     ConditionTypeTime,
				Field:    "day_of_week",
				Operator: OperatorEquals,
				Value:    4, // Thursday
			},
			expected: true,
		},
		{
			name: "time of day",
			condition: &PolicyCondition{
				Type:     ConditionTypeTime,
				Field:    "time_of_day",
				Operator: OperatorEquals,
				Value:    "14:30",
			},
			expected: true,
		},
		{
			name: "business hours",
			condition: &PolicyCondition{
				Type:     ConditionTypeTime,
				Field:    "hour",
				Operator: OperatorGreaterOrEqual,
				Value:    9,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.Evaluate(ctx, tt.condition, requestContext)
			if err != nil {
				t.Fatalf("Evaluation failed: %v", err)
			}

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDefaultConditionEvaluator_IPConditions(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	evaluator := NewDefaultConditionEvaluator(logger)

	ctx := context.Background()
	requestContext := &RequestContext{
		IPAddress: "192.168.1.100",
		Location: &GeoLocation{
			Country: "US",
			Region:  "CA",
			City:    "San Francisco",
		},
	}

	tests := []struct {
		name      string
		condition *PolicyCondition
		expected  bool
	}{
		{
			name: "IP address equals",
			condition: &PolicyCondition{
				Type:     ConditionTypeIP,
				Field:    "address",
				Operator: OperatorEquals,
				Value:    "192.168.1.100",
			},
			expected: true,
		},
		{
			name: "IP in network",
			condition: &PolicyCondition{
				Type:     ConditionTypeIP,
				Field:    "network",
				Operator: OperatorIn,
				Value:    "192.168.1.0/24",
			},
			expected: true,
		},
		{
			name: "IP not in network",
			condition: &PolicyCondition{
				Type:     ConditionTypeIP,
				Field:    "network",
				Operator: OperatorNotIn,
				Value:    "10.0.0.0/8",
			},
			expected: true,
		},
		{
			name: "country equals",
			condition: &PolicyCondition{
				Type:     ConditionTypeIP,
				Field:    "country",
				Operator: OperatorEquals,
				Value:    "US",
			},
			expected: true,
		},
		{
			name: "is private IP",
			condition: &PolicyCondition{
				Type:     ConditionTypeIP,
				Field:    "is_private",
				Operator: OperatorEquals,
				Value:    true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.Evaluate(ctx, tt.condition, requestContext)
			if err != nil {
				t.Fatalf("Evaluation failed: %v", err)
			}

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDefaultConditionEvaluator_AttributeConditions(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	evaluator := NewDefaultConditionEvaluator(logger)

	ctx := context.Background()
	requestContext := &RequestContext{
		UserID:   "user-123",
		Username: "testuser",
		Roles:    []string{"admin", "user"},
		Groups:   []string{"developers", "engineers"},
		Device: &DeviceInfo{
			Type:          "desktop",
			OS:            "Linux",
			TrustedDevice: true,
		},
		Network: &NetworkInfo{
			NetworkType:    "corporate",
			TrustedNetwork: true,
			VPN:            false,
		},
		Authentication: &AuthenticationInfo{
			Method:      "password",
			MFAVerified: true,
			Strength:    5,
		},
		Attributes: map[string]interface{}{
			"department": "engineering",
			"clearance":  "secret",
		},
	}

	tests := []struct {
		name      string
		condition *PolicyCondition
		expected  bool
	}{
		{
			name: "user ID equals",
			condition: &PolicyCondition{
				Type:     ConditionTypeAttribute,
				Field:    "user_id",
				Operator: OperatorEquals,
				Value:    "user-123",
			},
			expected: true,
		},
		{
			name: "roles contains admin",
			condition: &PolicyCondition{
				Type:     ConditionTypeAttribute,
				Field:    "roles",
				Operator: OperatorContains,
				Value:    "admin",
			},
			expected: true,
		},
		{
			name: "trusted device",
			condition: &PolicyCondition{
				Type:     ConditionTypeAttribute,
				Field:    "trusted_device",
				Operator: OperatorEquals,
				Value:    true,
			},
			expected: true,
		},
		{
			name: "MFA verified",
			condition: &PolicyCondition{
				Type:     ConditionTypeAttribute,
				Field:    "mfa_verified",
				Operator: OperatorEquals,
				Value:    true,
			},
			expected: true,
		},
		{
			name: "auth strength greater than",
			condition: &PolicyCondition{
				Type:     ConditionTypeAttribute,
				Field:    "auth_strength",
				Operator: OperatorGreaterThan,
				Value:    3,
			},
			expected: true,
		},
		{
			name: "custom attribute",
			condition: &PolicyCondition{
				Type:     ConditionTypeAttribute,
				Field:    "department",
				Operator: OperatorEquals,
				Value:    "engineering",
			},
			expected: true,
		},
		{
			name: "attribute exists",
			condition: &PolicyCondition{
				Type:     ConditionTypeAttribute,
				Field:    "clearance",
				Operator: OperatorExists,
			},
			expected: true,
		},
		{
			name: "attribute not exists",
			condition: &PolicyCondition{
				Type:     ConditionTypeAttribute,
				Field:    "nonexistent",
				Operator: OperatorNotExists,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.Evaluate(ctx, tt.condition, requestContext)
			if err != nil {
				t.Fatalf("Evaluation failed: %v", err)
			}

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDefaultConditionEvaluator_RegexConditions(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	evaluator := NewDefaultConditionEvaluator(logger)

	ctx := context.Background()
	requestContext := &RequestContext{
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		Username:  "john.doe@example.com",
	}

	tests := []struct {
		name      string
		condition *PolicyCondition
		expected  bool
	}{
		{
			name: "user agent matches browser",
			condition: &PolicyCondition{
				Type:     ConditionTypeRegex,
				Field:    "user_agent",
				Operator: OperatorMatches,
				Value:    "Mozilla.*",
			},
			expected: true,
		},
		{
			name: "username matches email pattern",
			condition: &PolicyCondition{
				Type:     ConditionTypeRegex,
				Field:    "username",
				Operator: OperatorMatches,
				Value:    `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
			},
			expected: true,
		},
		{
			name: "user agent does not match IE",
			condition: &PolicyCondition{
				Type:     ConditionTypeRegex,
				Field:    "user_agent",
				Operator: OperatorNotMatches,
				Value:    ".*MSIE.*",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.Evaluate(ctx, tt.condition, requestContext)
			if err != nil {
				t.Fatalf("Evaluation failed: %v", err)
			}

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDefaultConditionEvaluator_FunctionConditions(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	evaluator := NewDefaultConditionEvaluator(logger)

	ctx := context.Background()
	
	// Business hours test (10 AM on a weekday)
	businessHoursTime := time.Date(2023, 6, 15, 10, 0, 0, 0, time.UTC) // Thursday
	requestContext := &RequestContext{
		Timestamp: businessHoursTime,
		Roles:     []string{"admin", "user"},
		Network: &NetworkInfo{
			VPN:            false,
			TorExit:        false,
			TrustedNetwork: true,
		},
		Device: &DeviceInfo{
			TrustedDevice: true,
		},
		Authentication: &AuthenticationInfo{
			MFAVerified: true,
			Strength:    5,
		},
	}

	tests := []struct {
		name      string
		condition *PolicyCondition
		expected  bool
	}{
		{
			name: "is business hours",
			condition: &PolicyCondition{
				Type:     ConditionTypeFunction,
				Function: "is_business_hours",
				Operator: OperatorEquals,
				Value:    true,
				Args: map[string]interface{}{
					"start_hour": 9,
					"end_hour":   17,
				},
			},
			expected: true,
		},
		{
			name: "is not weekend",
			condition: &PolicyCondition{
				Type:     ConditionTypeFunction,
				Function: "is_weekend",
				Operator: OperatorEquals,
				Value:    false,
			},
			expected: true,
		},
		{
			name: "has admin role",
			condition: &PolicyCondition{
				Type:     ConditionTypeFunction,
				Function: "has_role",
				Operator: OperatorEquals,
				Value:    true,
				Args: map[string]interface{}{
					"role": "admin",
				},
			},
			expected: true,
		},
		{
			name: "does not have manager role",
			condition: &PolicyCondition{
				Type:     ConditionTypeFunction,
				Function: "has_role",
				Operator: OperatorEquals,
				Value:    false,
				Args: map[string]interface{}{
					"role": "manager",
				},
			},
			expected: true,
		},
		{
			name: "is not VPN",
			condition: &PolicyCondition{
				Type:     ConditionTypeFunction,
				Function: "is_vpn",
				Operator: OperatorEquals,
				Value:    false,
			},
			expected: true,
		},
		{
			name: "low risk score",
			condition: &PolicyCondition{
				Type:     ConditionTypeFunction,
				Function: "risk_score",
				Operator: OperatorLessThan,
				Value:    50,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.Evaluate(ctx, tt.condition, requestContext)
			if err != nil {
				t.Fatalf("Evaluation failed: %v", err)
			}

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDefaultConditionEvaluator_ComparisonOperators(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	evaluator := NewDefaultConditionEvaluator(logger)

	tests := []struct {
		name     string
		actual   interface{}
		operator ConditionOperator
		expected interface{}
		result   bool
	}{
		{"equals string", "hello", OperatorEquals, "hello", true},
		{"not equals string", "hello", OperatorNotEquals, "world", true},
		{"greater than int", 10, OperatorGreaterThan, 5, true},
		{"less than int", 5, OperatorLessThan, 10, true},
		{"greater or equal", 10, OperatorGreaterOrEqual, 10, true},
		{"less or equal", 5, OperatorLessOrEqual, 10, true},
		{"in array", "apple", OperatorIn, []interface{}{"apple", "banana", "orange"}, true},
		{"not in array", "grape", OperatorNotIn, []interface{}{"apple", "banana", "orange"}, true},
		{"contains", "hello world", OperatorContains, "world", true},
		{"not contains", "hello world", OperatorNotContains, "foo", true},
		{"starts with", "hello world", OperatorStartsWith, "hello", true},
		{"ends with", "hello world", OperatorEndsWith, "world", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.compareValues(tt.actual, tt.operator, tt.expected)
			if err != nil {
				t.Fatalf("Comparison failed: %v", err)
			}

			if result != tt.result {
				t.Errorf("Expected %v, got %v", tt.result, result)
			}
		})
	}
}

func TestDefaultConditionEvaluator_EdgeCases(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	evaluator := NewDefaultConditionEvaluator(logger)

	ctx := context.Background()

	tests := []struct {
		name        string
		condition   *PolicyCondition
		context     *RequestContext
		expectError bool
	}{
		{
			name: "nil context",
			condition: &PolicyCondition{
				Type:     ConditionTypeAttribute,
				Field:    "user_id",
				Operator: OperatorEquals,
				Value:    "user-123",
			},
			context:     nil,
			expectError: true,
		},
		{
			name: "unsupported condition type",
			condition: &PolicyCondition{
				Type:     ConditionType("INVALID"),
				Field:    "test",
				Operator: OperatorEquals,
				Value:    "test",
			},
			context: &RequestContext{},
			expectError: true,
		},
		{
			name: "invalid regex pattern",
			condition: &PolicyCondition{
				Type:     ConditionTypeRegex,
				Field:    "user_agent",
				Operator: OperatorMatches,
				Value:    "[invalid",
			},
			context: &RequestContext{
				UserAgent: "test",
			},
			expectError: true,
		},
		{
			name: "unknown function",
			condition: &PolicyCondition{
				Type:     ConditionTypeFunction,
				Function: "unknown_function",
				Operator: OperatorEquals,
				Value:    true,
			},
			context:     &RequestContext{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := evaluator.Evaluate(ctx, tt.condition, tt.context)
			
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestDefaultConditionEvaluator_NegatedConditions(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()
	
	requestContext := &RequestContext{
		UserID: "user-123",
	}

	// Test normal condition
	condition := PolicyCondition{
		Type:     ConditionTypeAttribute,
		Field:    "user_id",
		Operator: OperatorEquals,
		Value:    "user-123",
		Negate:   false,
	}

	result, err := engine.EvaluateConditions(ctx, []PolicyCondition{condition}, requestContext)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	if !result {
		t.Error("Expected true for matching condition")
	}

	// Test negated condition
	condition.Negate = true

	result, err = engine.EvaluateConditions(ctx, []PolicyCondition{condition}, requestContext)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	if result {
		t.Error("Expected false for negated matching condition")
	}
}

func TestDefaultConditionEvaluator_ComplexScenarios(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	evaluator := NewDefaultConditionEvaluator(logger)

	ctx := context.Background()

	// Scenario: High-risk access attempt
	highRiskContext := &RequestContext{
		UserID:    "user-123",
		IPAddress: "1.2.3.4", // Public IP
		Timestamp: time.Date(2023, 6, 15, 23, 0, 0, 0, time.UTC), // 11 PM
		Network: &NetworkInfo{
			VPN:            true,
			TrustedNetwork: false,
			TorExit:        false,
		},
		Device: &DeviceInfo{
			TrustedDevice: false,
		},
		Authentication: &AuthenticationInfo{
			MFAVerified: false,
			Strength:    2,
		},
	}

	// Test multiple conditions that should indicate high risk
	conditions := []struct {
		name      string
		condition *PolicyCondition
		expected  bool
	}{
		{
			name: "outside business hours",
			condition: &PolicyCondition{
				Type:     ConditionTypeFunction,
				Function: "is_business_hours",
				Operator: OperatorEquals,
				Value:    false,
			},
			expected: true,
		},
		{
			name: "using VPN",
			condition: &PolicyCondition{
				Type:     ConditionTypeFunction,
				Function: "is_vpn",
				Operator: OperatorEquals,
				Value:    true,
			},
			expected: true,
		},
		{
			name: "untrusted device",
			condition: &PolicyCondition{
				Type:     ConditionTypeAttribute,
				Field:    "trusted_device",
				Operator: OperatorEquals,
				Value:    false,
			},
			expected: true,
		},
		{
			name: "no MFA",
			condition: &PolicyCondition{
				Type:     ConditionTypeAttribute,
				Field:    "mfa_verified",
				Operator: OperatorEquals,
				Value:    false,
			},
			expected: true,
		},
		{
			name: "high risk score",
			condition: &PolicyCondition{
				Type:     ConditionTypeFunction,
				Function: "risk_score",
				Operator: OperatorGreaterThan,
				Value:    50,
			},
			expected: true,
		},
	}

	for _, tt := range conditions {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.Evaluate(ctx, tt.condition, highRiskContext)
			if err != nil {
				t.Fatalf("Evaluation failed: %v", err)
			}

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Benchmark tests

func BenchmarkConditionEvaluator_TimeCondition(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	evaluator := NewDefaultConditionEvaluator(logger)

	ctx := context.Background()
	condition := &PolicyCondition{
		Type:     ConditionTypeTime,
		Field:    "hour",
		Operator: OperatorGreaterThan,
		Value:    9,
	}
	requestContext := &RequestContext{
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := evaluator.Evaluate(ctx, condition, requestContext)
		if err != nil {
			b.Fatalf("Evaluation failed: %v", err)
		}
	}
}

func BenchmarkConditionEvaluator_AttributeCondition(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	evaluator := NewDefaultConditionEvaluator(logger)

	ctx := context.Background()
	condition := &PolicyCondition{
		Type:     ConditionTypeAttribute,
		Field:    "user_id",
		Operator: OperatorEquals,
		Value:    "user-123",
	}
	requestContext := &RequestContext{
		UserID: "user-123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := evaluator.Evaluate(ctx, condition, requestContext)
		if err != nil {
			b.Fatalf("Evaluation failed: %v", err)
		}
	}
}

func BenchmarkConditionEvaluator_FunctionCondition(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	evaluator := NewDefaultConditionEvaluator(logger)

	ctx := context.Background()
	condition := &PolicyCondition{
		Type:     ConditionTypeFunction,
		Function: "is_business_hours",
		Operator: OperatorEquals,
		Value:    true,
	}
	requestContext := &RequestContext{
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := evaluator.Evaluate(ctx, condition, requestContext)
		if err != nil {
			b.Fatalf("Evaluation failed: %v", err)
		}
	}
}