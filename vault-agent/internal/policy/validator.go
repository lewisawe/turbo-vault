package policy

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DefaultPolicyValidator implements the PolicyValidator interface
type DefaultPolicyValidator struct {
	logger           *logrus.Logger
	config          *ValidatorConfig
	evaluator       ConditionEvaluator
	reservedNames   map[string]bool
	maxComplexity   int
}

// ValidatorConfig contains configuration for the policy validator
type ValidatorConfig struct {
	MaxRulesPerPolicy      int      `json:"max_rules_per_policy"`
	MaxConditionsPerRule   int      `json:"max_conditions_per_rule"`
	MaxActionsPerPolicy    int      `json:"max_actions_per_policy"`
	AllowedResourcePatterns []string `json:"allowed_resource_patterns"`
	AllowedActions         []string `json:"allowed_actions"`
	RequiredFields         []string `json:"required_fields"`
	MaxPolicyNameLength    int      `json:"max_policy_name_length"`
	MaxDescriptionLength   int      `json:"max_description_length"`
	ValidateConditions     bool     `json:"validate_conditions"`
	StrictMode            bool     `json:"strict_mode"`
}

// ValidationError represents a policy validation error
type ValidationError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

// ValidationResult contains the result of policy validation
type ValidationResult struct {
	Valid   bool               `json:"valid"`
	Errors  []*ValidationError `json:"errors"`
	Warnings []*ValidationError `json:"warnings"`
}

// NewDefaultPolicyValidator creates a new policy validator
func NewDefaultPolicyValidator(logger *logrus.Logger, config *ValidatorConfig, evaluator ConditionEvaluator) *DefaultPolicyValidator {
	if config == nil {
		config = DefaultValidatorConfig()
	}

	validator := &DefaultPolicyValidator{
		logger:        logger,
		config:        config,
		evaluator:     evaluator,
		reservedNames: make(map[string]bool),
		maxComplexity: 100,
	}

	// Initialize reserved names
	validator.initializeReservedNames()

	return validator
}

// DefaultValidatorConfig returns default validator configuration
func DefaultValidatorConfig() *ValidatorConfig {
	return &ValidatorConfig{
		MaxRulesPerPolicy:      50,
		MaxConditionsPerRule:   20,
		MaxActionsPerPolicy:    10,
		AllowedResourcePatterns: []string{"*", "secrets/*", "users/*", "policies/*"},
		AllowedActions:         []string{"read", "write", "delete", "create", "list", "update"},
		RequiredFields:         []string{"name", "rules"},
		MaxPolicyNameLength:    100,
		MaxDescriptionLength:   500,
		ValidateConditions:     true,
		StrictMode:            false,
	}
}

// ValidatePolicy validates a complete policy
func (v *DefaultPolicyValidator) ValidatePolicy(ctx context.Context, policy *Policy) error {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []*ValidationError{},
		Warnings: []*ValidationError{},
	}

	// Basic field validation
	v.validateBasicFields(policy, result)

	// Validate rules
	v.validateRules(ctx, policy, result)

	// Validate conditions
	if v.config.ValidateConditions {
		v.validateConditions(ctx, policy, result)
	}

	// Validate actions
	v.validateActions(ctx, policy, result)

	// Check complexity
	v.validateComplexity(policy, result)

	// Check for logical consistency
	v.validateLogicalConsistency(policy, result)

	if len(result.Errors) > 0 {
		return fmt.Errorf("policy validation failed: %s", v.formatErrors(result.Errors))
	}

	if len(result.Warnings) > 0 {
		v.logger.WithField("warnings", result.Warnings).Warn("Policy validation completed with warnings")
	}

	return nil
}

// ValidateRule validates a single policy rule
func (v *DefaultPolicyValidator) ValidateRule(ctx context.Context, rule *PolicyRule) error {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []*ValidationError{},
		Warnings: []*ValidationError{},
	}

	v.validateSingleRule(ctx, rule, result)

	if len(result.Errors) > 0 {
		return fmt.Errorf("rule validation failed: %s", v.formatErrors(result.Errors))
	}

	return nil
}

// ValidateCondition validates a single policy condition
func (v *DefaultPolicyValidator) ValidateCondition(ctx context.Context, condition *PolicyCondition) error {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []*ValidationError{},
		Warnings: []*ValidationError{},
	}

	v.validateSingleCondition(ctx, condition, result)

	if len(result.Errors) > 0 {
		return fmt.Errorf("condition validation failed: %s", v.formatErrors(result.Errors))
	}

	return nil
}

// ValidateAction validates a single policy action
func (v *DefaultPolicyValidator) ValidateAction(ctx context.Context, action *PolicyAction) error {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []*ValidationError{},
		Warnings: []*ValidationError{},
	}

	v.validateSingleAction(ctx, action, result)

	if len(result.Errors) > 0 {
		return fmt.Errorf("action validation failed: %s", v.formatErrors(result.Errors))
	}

	return nil
}

// Basic field validation

func (v *DefaultPolicyValidator) validateBasicFields(policy *Policy, result *ValidationResult) {
	// Validate name
	if policy.Name == "" {
		v.addError(result, "name", "REQUIRED", "Policy name is required", nil)
	} else {
		if len(policy.Name) > v.config.MaxPolicyNameLength {
			v.addError(result, "name", "TOO_LONG", 
				fmt.Sprintf("Policy name exceeds maximum length of %d", v.config.MaxPolicyNameLength), 
				policy.Name)
		}

		if v.reservedNames[strings.ToLower(policy.Name)] {
			v.addError(result, "name", "RESERVED", "Policy name is reserved", policy.Name)
		}

		if !v.isValidName(policy.Name) {
			v.addError(result, "name", "INVALID_FORMAT", 
				"Policy name contains invalid characters", policy.Name)
		}
	}

	// Validate description
	if len(policy.Description) > v.config.MaxDescriptionLength {
		v.addError(result, "description", "TOO_LONG", 
			fmt.Sprintf("Description exceeds maximum length of %d", v.config.MaxDescriptionLength), 
			policy.Description)
	}

	// Validate priority
	if policy.Priority < 0 || policy.Priority > 1000 {
		v.addError(result, "priority", "OUT_OF_RANGE", 
			"Priority must be between 0 and 1000", policy.Priority)
	}

	// Validate rules count
	if len(policy.Rules) == 0 {
		v.addError(result, "rules", "REQUIRED", "At least one rule is required", nil)
	} else if len(policy.Rules) > v.config.MaxRulesPerPolicy {
		v.addError(result, "rules", "TOO_MANY", 
			fmt.Sprintf("Too many rules (max: %d)", v.config.MaxRulesPerPolicy), 
			len(policy.Rules))
	}

	// Validate actions count
	if len(policy.Actions) > v.config.MaxActionsPerPolicy {
		v.addError(result, "actions", "TOO_MANY", 
			fmt.Sprintf("Too many actions (max: %d)", v.config.MaxActionsPerPolicy), 
			len(policy.Actions))
	}

	// Validate timestamps
	if !policy.CreatedAt.IsZero() && !policy.UpdatedAt.IsZero() {
		if policy.UpdatedAt.Before(policy.CreatedAt) {
			v.addError(result, "updated_at", "INVALID", 
				"Updated timestamp cannot be before created timestamp", nil)
		}
	}
}

// Rules validation

func (v *DefaultPolicyValidator) validateRules(ctx context.Context, policy *Policy, result *ValidationResult) {
	ruleIDs := make(map[string]bool)

	for i, rule := range policy.Rules {
		fieldPrefix := fmt.Sprintf("rules[%d]", i)

		// Check for duplicate rule IDs
		if rule.ID != "" {
			if ruleIDs[rule.ID] {
				v.addError(result, fieldPrefix+".id", "DUPLICATE", 
					"Duplicate rule ID", rule.ID)
			}
			ruleIDs[rule.ID] = true
		}

		v.validateSingleRule(ctx, &rule, result, fieldPrefix)
	}
}

func (v *DefaultPolicyValidator) validateSingleRule(ctx context.Context, rule *PolicyRule, result *ValidationResult, fieldPrefix ...string) {
	prefix := ""
	if len(fieldPrefix) > 0 {
		prefix = fieldPrefix[0] + "."
	}

	// Validate effect
	if !rule.Effect.IsValid() {
		v.addError(result, prefix+"effect", "INVALID", 
			"Invalid rule effect", rule.Effect)
	}

	// Validate resource
	if rule.Resource == "" {
		v.addError(result, prefix+"resource", "REQUIRED", 
			"Resource pattern is required", nil)
	} else {
		if !v.isValidResourcePattern(rule.Resource) {
			v.addError(result, prefix+"resource", "INVALID_PATTERN", 
				"Invalid resource pattern", rule.Resource)
		}
	}

	// Validate actions
	if len(rule.Actions) == 0 {
		v.addError(result, prefix+"actions", "REQUIRED", 
			"At least one action is required", nil)
	} else {
		for j, action := range rule.Actions {
			if !v.isValidAction(action) {
				v.addError(result, fmt.Sprintf("%sactions[%d]", prefix, j), "INVALID", 
					"Invalid action", action)
			}
		}
	}

	// Validate principals
	if len(rule.Principals) == 0 {
		v.addWarning(result, prefix+"principals", "EMPTY", 
			"No principals specified - rule will not match any requests", nil)
	} else {
		for j, principal := range rule.Principals {
			if !v.isValidPrincipal(principal) {
				v.addError(result, fmt.Sprintf("%sprincipals[%d]", prefix, j), "INVALID", 
					"Invalid principal format", principal)
			}
		}
	}

	// Validate conditions
	if len(rule.Conditions) > v.config.MaxConditionsPerRule {
		v.addError(result, prefix+"conditions", "TOO_MANY", 
			fmt.Sprintf("Too many conditions (max: %d)", v.config.MaxConditionsPerRule), 
			len(rule.Conditions))
	}

	// Validate priority
	if rule.Priority < 0 || rule.Priority > 1000 {
		v.addError(result, prefix+"priority", "OUT_OF_RANGE", 
			"Rule priority must be between 0 and 1000", rule.Priority)
	}
}

// Conditions validation

func (v *DefaultPolicyValidator) validateConditions(ctx context.Context, policy *Policy, result *ValidationResult) {
	// Validate policy-level conditions
	for i, condition := range policy.Conditions {
		fieldPrefix := fmt.Sprintf("conditions[%d]", i)
		v.validateSingleCondition(ctx, &condition, result, fieldPrefix)
	}

	// Validate rule-level conditions
	for i, rule := range policy.Rules {
		for j, condition := range rule.Conditions {
			fieldPrefix := fmt.Sprintf("rules[%d].conditions[%d]", i, j)
			v.validateSingleCondition(ctx, &condition, result, fieldPrefix)
		}
	}
}

func (v *DefaultPolicyValidator) validateSingleCondition(ctx context.Context, condition *PolicyCondition, result *ValidationResult, fieldPrefix ...string) {
	prefix := ""
	if len(fieldPrefix) > 0 {
		prefix = fieldPrefix[0] + "."
	}

	// Validate type
	if !condition.Type.IsValid() {
		v.addError(result, prefix+"type", "INVALID", 
			"Invalid condition type", condition.Type)
		return
	}

	// Validate operator
	if !condition.Operator.IsValid() {
		v.addError(result, prefix+"operator", "INVALID", 
			"Invalid condition operator", condition.Operator)
		return
	}

	// Validate field
	if condition.Field == "" && condition.Type != ConditionTypeFunction {
		v.addError(result, prefix+"field", "REQUIRED", 
			"Field is required for non-function conditions", nil)
	}

	// Type-specific validation
	switch condition.Type {
	case ConditionTypeTime:
		v.validateTimeCondition(condition, result, prefix)
	case ConditionTypeIP:
		v.validateIPCondition(condition, result, prefix)
	case ConditionTypeAttribute:
		v.validateAttributeCondition(condition, result, prefix)
	case ConditionTypeFunction:
		v.validateFunctionCondition(condition, result, prefix)
	case ConditionTypeRegex:
		v.validateRegexCondition(condition, result, prefix)
	case ConditionTypeJSON:
		v.validateJSONCondition(condition, result, prefix)
	}

	// Validate operator compatibility
	v.validateOperatorCompatibility(condition, result, prefix)
}

func (v *DefaultPolicyValidator) validateTimeCondition(condition *PolicyCondition, result *ValidationResult, prefix string) {
	validTimeFields := []string{"hour", "minute", "day_of_week", "day_of_month", "month", "year", "time_of_day", "timestamp", "timezone"}
	
	if !v.contains(validTimeFields, condition.Field) {
		v.addError(result, prefix+"field", "INVALID", 
			"Invalid time field", condition.Field)
	}

	// Validate value ranges
	switch condition.Field {
	case "hour":
		if !v.isIntInRange(condition.Value, 0, 23) {
			v.addError(result, prefix+"value", "OUT_OF_RANGE", 
				"Hour must be between 0 and 23", condition.Value)
		}
	case "minute":
		if !v.isIntInRange(condition.Value, 0, 59) {
			v.addError(result, prefix+"value", "OUT_OF_RANGE", 
				"Minute must be between 0 and 59", condition.Value)
		}
	case "day_of_week":
		if !v.isIntInRange(condition.Value, 0, 6) {
			v.addError(result, prefix+"value", "OUT_OF_RANGE", 
				"Day of week must be between 0 and 6", condition.Value)
		}
	case "day_of_month":
		if !v.isIntInRange(condition.Value, 1, 31) {
			v.addError(result, prefix+"value", "OUT_OF_RANGE", 
				"Day of month must be between 1 and 31", condition.Value)
		}
	case "month":
		if !v.isIntInRange(condition.Value, 1, 12) {
			v.addError(result, prefix+"value", "OUT_OF_RANGE", 
				"Month must be between 1 and 12", condition.Value)
		}
	case "time_of_day":
		if !v.isValidTimeFormat(condition.Value) {
			v.addError(result, prefix+"value", "INVALID_FORMAT", 
				"Time must be in HH:MM format", condition.Value)
		}
	}
}

func (v *DefaultPolicyValidator) validateIPCondition(condition *PolicyCondition, result *ValidationResult, prefix string) {
	validIPFields := []string{"address", "network", "country", "region", "city", "is_private", "is_loopback"}
	
	if !v.contains(validIPFields, condition.Field) {
		v.addError(result, prefix+"field", "INVALID", 
			"Invalid IP field", condition.Field)
	}

	// Validate IP address format
	if condition.Field == "address" {
		if !v.isValidIPAddress(condition.Value) {
			v.addError(result, prefix+"value", "INVALID_FORMAT", 
				"Invalid IP address format", condition.Value)
		}
	}

	// Validate network CIDR format
	if condition.Field == "network" {
		if !v.isValidCIDR(condition.Value) {
			v.addError(result, prefix+"value", "INVALID_FORMAT", 
				"Invalid CIDR format", condition.Value)
		}
	}
}

func (v *DefaultPolicyValidator) validateAttributeCondition(condition *PolicyCondition, result *ValidationResult, prefix string) {
	validAttributeFields := []string{
		"user_id", "username", "roles", "groups", "session_id", "user_agent",
		"device_type", "os", "browser", "trusted_device", "network_type", 
		"trusted_network", "vpn", "auth_method", "mfa_verified", "auth_strength",
	}
	
	// Allow custom attributes (not in the predefined list)
	if v.config.StrictMode && !v.contains(validAttributeFields, condition.Field) {
		v.addWarning(result, prefix+"field", "UNKNOWN", 
			"Unknown attribute field", condition.Field)
	}
}

func (v *DefaultPolicyValidator) validateFunctionCondition(condition *PolicyCondition, result *ValidationResult, prefix string) {
	if condition.Function == "" {
		v.addError(result, prefix+"function", "REQUIRED", 
			"Function name is required", nil)
		return
	}

	// Check if function is supported
	if v.evaluator != nil {
		supportedFunctions := v.evaluator.SupportedFunctions()
		if !v.contains(supportedFunctions, condition.Function) {
			v.addError(result, prefix+"function", "UNSUPPORTED", 
				"Unsupported function", condition.Function)
		}
	}

	// Validate function arguments
	if condition.Args == nil {
		condition.Args = make(map[string]interface{})
	}

	// Function-specific argument validation
	switch condition.Function {
	case "is_business_hours":
		v.validateBusinessHoursArgs(condition.Args, result, prefix)
	case "days_since", "hours_since":
		v.validateTimestampArgs(condition.Args, result, prefix)
	case "has_role":
		v.validateRoleArgs(condition.Args, result, prefix)
	}
}

func (v *DefaultPolicyValidator) validateRegexCondition(condition *PolicyCondition, result *ValidationResult, prefix string) {
	// Validate that value is a string
	pattern, ok := condition.Value.(string)
	if !ok {
		v.addError(result, prefix+"value", "INVALID_TYPE", 
			"Regex pattern must be a string", condition.Value)
		return
	}

	// Validate regex pattern
	if _, err := regexp.Compile(pattern); err != nil {
		v.addError(result, prefix+"value", "INVALID_REGEX", 
			fmt.Sprintf("Invalid regex pattern: %v", err), pattern)
	}

	// Check for potentially dangerous patterns
	if v.isDangerousRegex(pattern) {
		v.addWarning(result, prefix+"value", "DANGEROUS_PATTERN", 
			"Regex pattern may cause performance issues", pattern)
	}
}

func (v *DefaultPolicyValidator) validateJSONCondition(condition *PolicyCondition, result *ValidationResult, prefix string) {
	// Validate JSON path format
	if !v.isValidJSONPath(condition.Field) {
		v.addError(result, prefix+"field", "INVALID_FORMAT", 
			"Invalid JSON path format", condition.Field)
	}
}

// Actions validation

func (v *DefaultPolicyValidator) validateActions(ctx context.Context, policy *Policy, result *ValidationResult) {
	for i, action := range policy.Actions {
		fieldPrefix := fmt.Sprintf("actions[%d]", i)
		v.validateSingleAction(ctx, &action, result, fieldPrefix)
	}
}

func (v *DefaultPolicyValidator) validateSingleAction(ctx context.Context, action *PolicyAction, result *ValidationResult, fieldPrefix ...string) {
	prefix := ""
	if len(fieldPrefix) > 0 {
		prefix = fieldPrefix[0] + "."
	}

	// Validate type
	if !action.Type.IsValid() {
		v.addError(result, prefix+"type", "INVALID", 
			"Invalid action type", action.Type)
		return
	}

	// Type-specific validation
	switch action.Type {
	case ActionTypeLog:
		v.validateLogAction(action, result, prefix)
	case ActionTypeAlert:
		v.validateAlertAction(action, result, prefix)
	case ActionTypeNotify:
		v.validateNotifyAction(action, result, prefix)
	case ActionTypeThrottle:
		v.validateThrottleAction(action, result, prefix)
	case ActionTypeRequireApproval:
		v.validateApprovalAction(action, result, prefix)
	}
}

// Complexity validation

func (v *DefaultPolicyValidator) validateComplexity(policy *Policy, result *ValidationResult) {
	complexity := v.calculateComplexity(policy)
	
	if complexity > v.maxComplexity {
		v.addError(result, "complexity", "TOO_COMPLEX", 
			fmt.Sprintf("Policy complexity (%d) exceeds maximum (%d)", complexity, v.maxComplexity), 
			complexity)
	}

	if complexity > v.maxComplexity/2 {
		v.addWarning(result, "complexity", "HIGH", 
			"Policy has high complexity, consider simplifying", complexity)
	}
}

func (v *DefaultPolicyValidator) calculateComplexity(policy *Policy) int {
	complexity := 0
	
	// Base complexity
	complexity += len(policy.Rules) * 5
	complexity += len(policy.Conditions) * 3
	complexity += len(policy.Actions) * 2

	// Rule complexity
	for _, rule := range policy.Rules {
		complexity += len(rule.Actions) * 2
		complexity += len(rule.Principals) * 1
		complexity += len(rule.Conditions) * 4
		
		// Wildcard patterns add complexity
		if strings.Contains(rule.Resource, "*") {
			complexity += 3
		}
	}

	// Condition complexity
	for _, condition := range policy.Conditions {
		switch condition.Type {
		case ConditionTypeFunction:
			complexity += 10
		case ConditionTypeRegex:
			complexity += 8
		case ConditionTypeJSON:
			complexity += 6
		default:
			complexity += 3
		}
	}

	return complexity
}

// Logical consistency validation

func (v *DefaultPolicyValidator) validateLogicalConsistency(policy *Policy, result *ValidationResult) {
	// Check for contradictory rules
	v.checkContradictoryRules(policy, result)
	
	// Check for unreachable rules
	v.checkUnreachableRules(policy, result)
	
	// Check for redundant conditions
	v.checkRedundantConditions(policy, result)
}

func (v *DefaultPolicyValidator) checkContradictoryRules(policy *Policy, result *ValidationResult) {
	for i, rule1 := range policy.Rules {
		for j, rule2 := range policy.Rules {
			if i >= j {
				continue
			}

			if v.rulesContradict(&rule1, &rule2) {
				v.addWarning(result, fmt.Sprintf("rules[%d]", i), "CONTRADICTORY", 
					fmt.Sprintf("Rule contradicts with rule %d", j), nil)
			}
		}
	}
}

func (v *DefaultPolicyValidator) checkUnreachableRules(policy *Policy, result *ValidationResult) {
	// Sort rules by priority
	rules := make([]PolicyRule, len(policy.Rules))
	copy(rules, policy.Rules)

	for i, rule := range rules {
		if v.isRuleUnreachable(&rule, rules[:i]) {
			v.addWarning(result, fmt.Sprintf("rules[%d]", i), "UNREACHABLE", 
				"Rule may be unreachable due to higher priority rules", nil)
		}
	}
}

func (v *DefaultPolicyValidator) checkRedundantConditions(policy *Policy, result *ValidationResult) {
	// Check for duplicate conditions within rules
	for i, rule := range policy.Rules {
		conditionMap := make(map[string]bool)
		
		for j, condition := range rule.Conditions {
			key := v.conditionKey(&condition)
			if conditionMap[key] {
				v.addWarning(result, fmt.Sprintf("rules[%d].conditions[%d]", i, j), "REDUNDANT", 
					"Duplicate condition", nil)
			}
			conditionMap[key] = true
		}
	}
}

// Helper methods

func (v *DefaultPolicyValidator) addError(result *ValidationResult, field, code, message string, value interface{}) {
	result.Valid = false
	result.Errors = append(result.Errors, &ValidationError{
		Field:   field,
		Code:    code,
		Message: message,
		Value:   value,
	})
}

func (v *DefaultPolicyValidator) addWarning(result *ValidationResult, field, code, message string, value interface{}) {
	result.Warnings = append(result.Warnings, &ValidationError{
		Field:   field,
		Code:    code,
		Message: message,
		Value:   value,
	})
}

func (v *DefaultPolicyValidator) formatErrors(errors []*ValidationError) string {
	var messages []string
	for _, err := range errors {
		messages = append(messages, fmt.Sprintf("%s: %s", err.Field, err.Message))
	}
	return strings.Join(messages, "; ")
}

func (v *DefaultPolicyValidator) initializeReservedNames() {
	reserved := []string{
		"admin", "root", "system", "default", "public", "private",
		"internal", "external", "guest", "anonymous", "service",
	}
	
	for _, name := range reserved {
		v.reservedNames[name] = true
	}
}

func (v *DefaultPolicyValidator) isValidName(name string) bool {
	// Allow alphanumeric, hyphens, underscores
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, name)
	return matched
}

func (v *DefaultPolicyValidator) isValidResourcePattern(pattern string) bool {
	if v.config.StrictMode {
		return v.contains(v.config.AllowedResourcePatterns, pattern)
	}
	
	// Basic validation - no empty patterns, valid characters
	if pattern == "" {
		return false
	}
	
	// Allow alphanumeric, slashes, wildcards, hyphens, underscores
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9/_*-]+$`, pattern)
	return matched
}

func (v *DefaultPolicyValidator) isValidAction(action string) bool {
	if v.config.StrictMode {
		return v.contains(v.config.AllowedActions, action)
	}
	
	// Allow wildcard
	if action == "*" {
		return true
	}
	
	// Basic validation
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, action)
	return matched
}

func (v *DefaultPolicyValidator) isValidPrincipal(principal string) bool {
	// Allow wildcards
	if principal == "*" {
		return true
	}
	
	// Allow role: and group: prefixes
	if strings.HasPrefix(principal, "role:") || strings.HasPrefix(principal, "group:") {
		return len(principal) > 5
	}
	
	// Basic validation for user IDs
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9@._-]+$`, principal)
	return matched
}

func (v *DefaultPolicyValidator) isIntInRange(value interface{}, min, max int) bool {
	switch v := value.(type) {
	case int:
		return v >= min && v <= max
	case float64:
		return int(v) >= min && int(v) <= max
	default:
		return false
	}
}

func (v *DefaultPolicyValidator) isValidTimeFormat(value interface{}) bool {
	str, ok := value.(string)
	if !ok {
		return false
	}
	
	matched, _ := regexp.MatchString(`^([01]?[0-9]|2[0-3]):[0-5][0-9]$`, str)
	return matched
}

func (v *DefaultPolicyValidator) isValidIPAddress(value interface{}) bool {
	str, ok := value.(string)
	if !ok {
		return false
	}
	
	// Simple IP validation
	matched, _ := regexp.MatchString(`^(\d{1,3}\.){3}\d{1,3}$`, str)
	return matched
}

func (v *DefaultPolicyValidator) isValidCIDR(value interface{}) bool {
	str, ok := value.(string)
	if !ok {
		return false
	}
	
	// Simple CIDR validation
	matched, _ := regexp.MatchString(`^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$`, str)
	return matched
}

func (v *DefaultPolicyValidator) isDangerousRegex(pattern string) bool {
	// Check for patterns that might cause ReDoS
	dangerous := []string{
		`.*.*`, `(.+)+`, `(.*)*`, `(.*).*`, 
		`(a+)+`, `(a*)*`, `(a|a)*`,
	}
	
	for _, d := range dangerous {
		if strings.Contains(pattern, d) {
			return true
		}
	}
	
	return false
}

func (v *DefaultPolicyValidator) isValidJSONPath(path string) bool {
	// Simple JSON path validation (dot notation)
	if path == "" {
		return false
	}
	
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_.[\]]+$`, path)
	return matched
}

func (v *DefaultPolicyValidator) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (v *DefaultPolicyValidator) rulesContradict(rule1, rule2 *PolicyRule) bool {
	// Check if rules have overlapping resources and actions but different effects
	if rule1.Effect == rule2.Effect {
		return false
	}
	
	// Simple overlap check
	return v.resourcesOverlap(rule1.Resource, rule2.Resource) && 
		   v.actionsOverlap(rule1.Actions, rule2.Actions)
}

func (v *DefaultPolicyValidator) resourcesOverlap(resource1, resource2 string) bool {
	// Simple overlap detection
	if resource1 == "*" || resource2 == "*" {
		return true
	}
	
	if resource1 == resource2 {
		return true
	}
	
	// Check prefix matching with wildcards
	if strings.HasSuffix(resource1, "*") {
		prefix := strings.TrimSuffix(resource1, "*")
		return strings.HasPrefix(resource2, prefix)
	}
	
	if strings.HasSuffix(resource2, "*") {
		prefix := strings.TrimSuffix(resource2, "*")
		return strings.HasPrefix(resource1, prefix)
	}
	
	return false
}

func (v *DefaultPolicyValidator) actionsOverlap(actions1, actions2 []string) bool {
	for _, a1 := range actions1 {
		for _, a2 := range actions2 {
			if a1 == "*" || a2 == "*" || a1 == a2 {
				return true
			}
		}
	}
	return false
}

func (v *DefaultPolicyValidator) isRuleUnreachable(rule *PolicyRule, higherPriorityRules []PolicyRule) bool {
	// Check if any higher priority rule completely shadows this rule
	for _, higherRule := range higherPriorityRules {
		if higherRule.Priority <= rule.Priority {
			continue
		}
		
		if v.ruleShadows(&higherRule, rule) {
			return true
		}
	}
	
	return false
}

func (v *DefaultPolicyValidator) ruleShadows(shadowingRule, shadowedRule *PolicyRule) bool {
	// Check if shadowingRule completely covers shadowedRule
	return v.resourcesOverlap(shadowingRule.Resource, shadowedRule.Resource) &&
		   v.actionsOverlap(shadowingRule.Actions, shadowedRule.Actions) &&
		   v.principalsOverlap(shadowingRule.Principals, shadowedRule.Principals)
}

func (v *DefaultPolicyValidator) principalsOverlap(principals1, principals2 []string) bool {
	for _, p1 := range principals1 {
		for _, p2 := range principals2 {
			if p1 == "*" || p2 == "*" || p1 == p2 {
				return true
			}
		}
	}
	return false
}

func (v *DefaultPolicyValidator) conditionKey(condition *PolicyCondition) string {
	return fmt.Sprintf("%s:%s:%s:%v", condition.Type, condition.Field, condition.Operator, condition.Value)
}

func (v *DefaultPolicyValidator) validateOperatorCompatibility(condition *PolicyCondition, result *ValidationResult, prefix string) {
	// Check if operator is compatible with condition type
	switch condition.Type {
	case ConditionTypeRegex:
		if condition.Operator != OperatorMatches && condition.Operator != OperatorNotMatches {
			v.addError(result, prefix+"operator", "INCOMPATIBLE", 
				"Regex conditions only support MATCHES and NOT_MATCHES operators", condition.Operator)
		}
	case ConditionTypeIP:
		if condition.Field == "network" {
			if condition.Operator != OperatorIn && condition.Operator != OperatorNotIn {
				v.addError(result, prefix+"operator", "INCOMPATIBLE", 
					"Network conditions only support IN and NOT_IN operators", condition.Operator)
			}
		}
	}
}

// Action-specific validation methods

func (v *DefaultPolicyValidator) validateLogAction(action *PolicyAction, result *ValidationResult, prefix string) {
	// Validate log level
	if level, ok := action.Config["level"]; ok {
		validLevels := []string{"debug", "info", "warn", "error"}
		if levelStr, ok := level.(string); ok {
			if !v.contains(validLevels, levelStr) {
				v.addError(result, prefix+"config.level", "INVALID", 
					"Invalid log level", level)
			}
		}
	}
}

func (v *DefaultPolicyValidator) validateAlertAction(action *PolicyAction, result *ValidationResult, prefix string) {
	// Validate severity
	if severity, ok := action.Config["severity"]; ok {
		validSeverities := []string{"low", "medium", "high", "critical"}
		if severityStr, ok := severity.(string); ok {
			if !v.contains(validSeverities, severityStr) {
				v.addError(result, prefix+"config.severity", "INVALID", 
					"Invalid alert severity", severity)
			}
		}
	}
}

func (v *DefaultPolicyValidator) validateNotifyAction(action *PolicyAction, result *ValidationResult, prefix string) {
	// Validate channels
	if channels, ok := action.Config["channels"]; ok {
		if channelList, ok := channels.([]interface{}); ok {
			for i, channel := range channelList {
				if channelStr, ok := channel.(string); ok {
					if channelStr == "" {
						v.addError(result, fmt.Sprintf("%sconfig.channels[%d]", prefix, i), "EMPTY", 
							"Channel name cannot be empty", nil)
					}
				}
			}
		}
	}
}

func (v *DefaultPolicyValidator) validateThrottleAction(action *PolicyAction, result *ValidationResult, prefix string) {
	// Validate rate limit
	if rate, ok := action.Config["rate"]; ok {
		if rateNum, ok := rate.(float64); ok {
			if rateNum <= 0 {
				v.addError(result, prefix+"config.rate", "INVALID", 
					"Rate must be positive", rate)
			}
		}
	}
}

func (v *DefaultPolicyValidator) validateApprovalAction(action *PolicyAction, result *ValidationResult, prefix string) {
	// Validate approvers
	if approvers, ok := action.Config["approvers"]; ok {
		if approverList, ok := approvers.([]interface{}); ok {
			if len(approverList) == 0 {
				v.addError(result, prefix+"config.approvers", "EMPTY", 
					"At least one approver is required", nil)
			}
		}
	}
}

// Function argument validation methods

func (v *DefaultPolicyValidator) validateBusinessHoursArgs(args map[string]interface{}, result *ValidationResult, prefix string) {
	if startHour, ok := args["start_hour"]; ok {
		if !v.isIntInRange(startHour, 0, 23) {
			v.addError(result, prefix+"args.start_hour", "OUT_OF_RANGE", 
				"Start hour must be between 0 and 23", startHour)
		}
	}
	
	if endHour, ok := args["end_hour"]; ok {
		if !v.isIntInRange(endHour, 0, 23) {
			v.addError(result, prefix+"args.end_hour", "OUT_OF_RANGE", 
				"End hour must be between 0 and 23", endHour)
		}
	}
}

func (v *DefaultPolicyValidator) validateTimestampArgs(args map[string]interface{}, result *ValidationResult, prefix string) {
	if timestamp, ok := args["timestamp"]; ok {
		switch t := timestamp.(type) {
		case string:
			if _, err := time.Parse(time.RFC3339, t); err != nil {
				v.addError(result, prefix+"args.timestamp", "INVALID_FORMAT", 
					"Invalid timestamp format, expected RFC3339", timestamp)
			}
		case int64:
			// Unix timestamp is valid
		default:
			v.addError(result, prefix+"args.timestamp", "INVALID_TYPE", 
				"Timestamp must be string (RFC3339) or int64 (Unix)", timestamp)
		}
	}
}

func (v *DefaultPolicyValidator) validateRoleArgs(args map[string]interface{}, result *ValidationResult, prefix string) {
	if role, ok := args["role"]; ok {
		if roleStr, ok := role.(string); ok {
			if roleStr == "" {
				v.addError(result, prefix+"args.role", "EMPTY", 
					"Role name cannot be empty", nil)
			}
		} else {
			v.addError(result, prefix+"args.role", "INVALID_TYPE", 
				"Role must be a string", role)
		}
	} else {
		v.addError(result, prefix+"args.role", "REQUIRED", 
			"Role argument is required", nil)
	}
}