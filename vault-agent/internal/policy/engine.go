package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Engine implements the PolicyEngine interface
type Engine struct {
	storage    PolicyStorage
	cache      PolicyCache
	validator  PolicyValidator
	evaluator  ConditionEvaluator
	logger     *logrus.Logger
	config     *EngineConfig
	mu         sync.RWMutex
	stats      *EngineStats
}

// EngineConfig contains configuration for the policy engine
type EngineConfig struct {
	CacheEnabled     bool          `json:"cache_enabled"`
	CacheTTL         time.Duration `json:"cache_ttl"`
	MaxPolicies      int           `json:"max_policies"`
	MaxRulesPerPolicy int          `json:"max_rules_per_policy"`
	EvaluationTimeout time.Duration `json:"evaluation_timeout"`
	ConflictDetection bool          `json:"conflict_detection"`
	MetricsEnabled   bool          `json:"metrics_enabled"`
}

// EngineStats contains engine statistics
type EngineStats struct {
	EvaluationsTotal    int64         `json:"evaluations_total"`
	EvaluationsAllowed  int64         `json:"evaluations_allowed"`
	EvaluationsDenied   int64         `json:"evaluations_denied"`
	EvaluationErrors    int64         `json:"evaluation_errors"`
	AverageEvalTime     time.Duration `json:"average_eval_time"`
	CacheHits          int64         `json:"cache_hits"`
	CacheMisses        int64         `json:"cache_misses"`
	PoliciesLoaded     int64         `json:"policies_loaded"`
	ConflictsDetected  int64         `json:"conflicts_detected"`
	mu                 sync.RWMutex
}

// NewEngine creates a new policy engine
func NewEngine(storage PolicyStorage, cache PolicyCache, validator PolicyValidator, evaluator ConditionEvaluator, logger *logrus.Logger, config *EngineConfig) *Engine {
	if config == nil {
		config = DefaultEngineConfig()
	}

	return &Engine{
		storage:   storage,
		cache:     cache,
		validator: validator,
		evaluator: evaluator,
		logger:    logger,
		config:    config,
		stats:     &EngineStats{},
	}
}

// DefaultEngineConfig returns default engine configuration
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		CacheEnabled:      true,
		CacheTTL:          5 * time.Minute,
		MaxPolicies:       1000,
		MaxRulesPerPolicy: 100,
		EvaluationTimeout: 5 * time.Second,
		ConflictDetection: true,
		MetricsEnabled:    true,
	}
}

// Policy Management Methods

func (e *Engine) CreatePolicy(ctx context.Context, policy *Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Generate ID if not provided
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now
	policy.Version = 1

	// Validate policy
	if err := e.validator.ValidatePolicy(ctx, policy); err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}

	// Check for conflicts if enabled
	if e.config.ConflictDetection {
		conflicts, err := e.DetectConflicts(ctx, policy)
		if err != nil {
			e.logger.WithError(err).Warn("Failed to detect policy conflicts")
		} else if len(conflicts) > 0 {
			e.stats.incrementConflictsDetected(int64(len(conflicts)))
			e.logger.WithField("conflicts", len(conflicts)).Warn("Policy conflicts detected")
		}
	}

	// Store policy
	if err := e.storage.CreatePolicy(ctx, policy); err != nil {
		return fmt.Errorf("failed to store policy: %w", err)
	}

	// Invalidate cache
	if e.config.CacheEnabled {
		e.cache.Clear(ctx)
	}

	e.stats.incrementPoliciesLoaded(1)
	e.logger.WithFields(logrus.Fields{
		"policy_id":   policy.ID,
		"policy_name": policy.Name,
	}).Info("Policy created successfully")

	return nil
}

func (e *Engine) UpdatePolicy(ctx context.Context, id string, policy *Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Get existing policy
	existing, err := e.storage.GetPolicy(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get existing policy: %w", err)
	}

	// Update fields
	policy.ID = id
	policy.CreatedAt = existing.CreatedAt
	policy.UpdatedAt = time.Now()
	policy.Version = existing.Version + 1

	// Validate policy
	if err := e.validator.ValidatePolicy(ctx, policy); err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}

	// Check for conflicts if enabled
	if e.config.ConflictDetection {
		conflicts, err := e.DetectConflicts(ctx, policy)
		if err != nil {
			e.logger.WithError(err).Warn("Failed to detect policy conflicts")
		} else if len(conflicts) > 0 {
			e.stats.incrementConflictsDetected(int64(len(conflicts)))
			e.logger.WithField("conflicts", len(conflicts)).Warn("Policy conflicts detected")
		}
	}

	// Update policy
	if err := e.storage.UpdatePolicy(ctx, id, policy); err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	// Invalidate cache
	if e.config.CacheEnabled {
		e.cache.Clear(ctx)
	}

	e.logger.WithFields(logrus.Fields{
		"policy_id":   policy.ID,
		"policy_name": policy.Name,
		"version":     policy.Version,
	}).Info("Policy updated successfully")

	return nil
}

func (e *Engine) DeletePolicy(ctx context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.storage.DeletePolicy(ctx, id); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	// Invalidate cache
	if e.config.CacheEnabled {
		e.cache.Clear(ctx)
	}

	e.logger.WithField("policy_id", id).Info("Policy deleted successfully")
	return nil
}

func (e *Engine) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Try cache first
	if e.config.CacheEnabled {
		if policy, found := e.cache.Get(ctx, "policy:"+id); found {
			e.stats.incrementCacheHits(1)
			return policy, nil
		}
		e.stats.incrementCacheMisses(1)
	}

	// Get from storage
	policy, err := e.storage.GetPolicy(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	// Cache the result
	if e.config.CacheEnabled && policy != nil {
		e.cache.Set(ctx, "policy:"+id, policy, e.config.CacheTTL)
	}

	return policy, nil
}

func (e *Engine) ListPolicies(ctx context.Context, filter *PolicyFilter) ([]*Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policies, err := e.storage.ListPolicies(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	return policies, nil
}

// Policy Evaluation Methods

func (e *Engine) EvaluateAccess(ctx context.Context, request *AccessRequest) (*AccessDecision, error) {
	startTime := time.Now()
	defer func() {
		evalTime := time.Since(startTime)
		e.stats.updateAverageEvalTime(evalTime)
	}()

	e.stats.incrementEvaluationsTotal(1)

	// Set evaluation timeout
	evalCtx, cancel := context.WithTimeout(ctx, e.config.EvaluationTimeout)
	defer cancel()

	// Get effective policies for the resource
	policies, err := e.GetEffectivePolicies(evalCtx, request.Resource)
	if err != nil {
		e.stats.incrementEvaluationErrors(1)
		return nil, fmt.Errorf("failed to get effective policies: %w", err)
	}

	// Evaluate policies
	decision := &AccessDecision{
		Decision:        PolicyEffectDeny, // Default deny
		Reason:          "No matching policies found",
		MatchedPolicies: []*PolicyMatch{},
		RequiredActions: []PolicyAction{},
		Conditions:      []string{},
		TTL:             e.config.CacheTTL,
		Metadata:        make(map[string]interface{}),
		EvaluationTime:  0, // Will be set at the end
		RequestID:       request.RequestID,
		Timestamp:       time.Now(),
	}

	var matches []*PolicyMatch

	// Evaluate each policy
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		match, err := e.evaluatePolicy(evalCtx, policy, request)
		if err != nil {
			e.logger.WithError(err).WithField("policy_id", policy.ID).Warn("Failed to evaluate policy")
			continue
		}

		if match != nil {
			matches = append(matches, match)
		}
	}

	// Sort matches by priority and score
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Policy.Priority != matches[j].Policy.Priority {
			return matches[i].Policy.Priority > matches[j].Policy.Priority
		}
		return matches[i].Score > matches[j].Score
	})

	// Apply policy precedence rules
	finalDecision := e.applyPrecedenceRules(matches)
	decision.Decision = finalDecision
	decision.MatchedPolicies = matches

	// Collect required actions
	for _, match := range matches {
		if match.Policy.Actions != nil {
			decision.RequiredActions = append(decision.RequiredActions, match.Policy.Actions...)
		}
	}

	// Set reason based on decision
	if decision.Decision == PolicyEffectAllow {
		decision.Reason = "Access granted by policy"
		e.stats.incrementEvaluationsAllowed(1)
	} else {
		decision.Reason = "Access denied by policy"
		e.stats.incrementEvaluationsDenied(1)
	}

	decision.EvaluationTime = time.Since(startTime)

	e.logger.WithFields(logrus.Fields{
		"request_id":      request.RequestID,
		"principal":       request.Principal,
		"resource":        request.Resource,
		"action":          request.Action,
		"decision":        decision.Decision,
		"matched_policies": len(matches),
		"evaluation_time": decision.EvaluationTime,
	}).Info("Access evaluation completed")

	return decision, nil
}

func (e *Engine) evaluatePolicy(ctx context.Context, policy *Policy, request *AccessRequest) (*PolicyMatch, error) {
	for _, rule := range policy.Rules {
		match, err := e.evaluateRule(ctx, &rule, request)
		if err != nil {
			return nil, err
		}

		if match {
			// Calculate match score
			score := e.calculateMatchScore(policy, &rule, request)

			return &PolicyMatch{
				Policy:      policy,
				Rule:        &rule,
				Conditions:  []bool{true}, // Simplified for now
				Score:       score,
				Explanation: fmt.Sprintf("Rule %s matched for resource %s", rule.ID, request.Resource),
			}, nil
		}
	}

	return nil, nil
}

func (e *Engine) evaluateRule(ctx context.Context, rule *PolicyRule, request *AccessRequest) (bool, error) {
	// Check if resource matches
	if !e.matchesPattern(rule.Resource, request.Resource) {
		return false, nil
	}

	// Check if action matches
	if !e.containsAction(rule.Actions, request.Action) {
		return false, nil
	}

	// Check if principal matches
	if !e.containsPrincipal(rule.Principals, request.Principal, request.Context) {
		return false, nil
	}

	// Evaluate conditions
	if len(rule.Conditions) > 0 {
		conditionsMatch, err := e.EvaluateConditions(ctx, rule.Conditions, request.Context)
		if err != nil {
			return false, err
		}
		if !conditionsMatch {
			return false, nil
		}
	}

	return true, nil
}

func (e *Engine) EvaluateConditions(ctx context.Context, conditions []PolicyCondition, context *RequestContext) (bool, error) {
	for _, condition := range conditions {
		match, err := e.evaluator.Evaluate(ctx, &condition, context)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate condition %s: %w", condition.ID, err)
		}

		if condition.Negate {
			match = !match
		}

		if !match {
			return false, nil
		}
	}

	return true, nil
}

func (e *Engine) GetEffectivePolicies(ctx context.Context, resource string) ([]*Policy, error) {
	// For now, get all policies and filter by resource pattern
	// In a production system, this would be optimized with indexing
	filter := &PolicyFilter{
		Enabled: &[]bool{true}[0],
		Limit:   e.config.MaxPolicies,
	}

	allPolicies, err := e.storage.ListPolicies(ctx, filter)
	if err != nil {
		return nil, err
	}

	var effectivePolicies []*Policy
	for _, policy := range allPolicies {
		if e.policyAppliesToResource(policy, resource) {
			effectivePolicies = append(effectivePolicies, policy)
		}
	}

	return effectivePolicies, nil
}

// Policy Validation Methods

func (e *Engine) ValidatePolicy(ctx context.Context, policy *Policy) error {
	return e.validator.ValidatePolicy(ctx, policy)
}

func (e *Engine) DetectConflicts(ctx context.Context, policy *Policy) ([]*PolicyConflict, error) {
	// Get all existing policies
	filter := &PolicyFilter{
		Enabled: &[]bool{true}[0],
		Limit:   e.config.MaxPolicies,
	}

	existingPolicies, err := e.storage.ListPolicies(ctx, filter)
	if err != nil {
		return nil, err
	}

	var conflicts []*PolicyConflict

	for _, existing := range existingPolicies {
		if existing.ID == policy.ID {
			continue // Skip self
		}

		policyConflicts := e.detectPolicyConflicts(policy, existing)
		conflicts = append(conflicts, policyConflicts...)
	}

	return conflicts, nil
}

// Cache Management Methods

func (e *Engine) InvalidateCache(ctx context.Context, pattern string) error {
	if !e.config.CacheEnabled {
		return nil
	}

	if pattern == "" {
		return e.cache.Clear(ctx)
	}

	// For now, clear entire cache for any pattern
	// In production, implement pattern-based invalidation
	return e.cache.Clear(ctx)
}

func (e *Engine) GetCacheStats() *CacheStats {
	if !e.config.CacheEnabled {
		return &CacheStats{}
	}

	return e.cache.Stats()
}

// Helper Methods

func (e *Engine) matchesPattern(pattern, resource string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(resource, prefix)
	}

	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(resource, suffix)
	}

	return pattern == resource
}

func (e *Engine) containsAction(actions []string, action string) bool {
	for _, a := range actions {
		if a == "*" || a == action {
			return true
		}
	}
	return false
}

func (e *Engine) containsPrincipal(principals []string, principal string, context *RequestContext) bool {
	for _, p := range principals {
		if p == "*" || p == principal {
			return true
		}

		// Check if principal matches any role
		if context != nil {
			for _, role := range context.Roles {
				if p == "role:"+role {
					return true
				}
			}

			// Check if principal matches any group
			for _, group := range context.Groups {
				if p == "group:"+group {
					return true
				}
			}
		}
	}
	return false
}

func (e *Engine) policyAppliesToResource(policy *Policy, resource string) bool {
	for _, rule := range policy.Rules {
		if e.matchesPattern(rule.Resource, resource) {
			return true
		}
	}
	return false
}

func (e *Engine) calculateMatchScore(policy *Policy, rule *PolicyRule, request *AccessRequest) float64 {
	score := 0.0

	// Base score from policy priority
	score += float64(policy.Priority) * 10

	// Bonus for exact resource match
	if rule.Resource == request.Resource {
		score += 100
	} else if !strings.Contains(rule.Resource, "*") {
		score += 50
	}

	// Bonus for exact action match
	for _, action := range rule.Actions {
		if action == request.Action {
			score += 50
			break
		}
	}

	// Bonus for specific principal match
	for _, principal := range rule.Principals {
		if principal == request.Principal {
			score += 30
			break
		}
	}

	return score
}

func (e *Engine) applyPrecedenceRules(matches []*PolicyMatch) PolicyEffect {
	// Default deny
	if len(matches) == 0 {
		return PolicyEffectDeny
	}

	// Check for explicit deny first (deny takes precedence)
	for _, match := range matches {
		if match.Rule.Effect == PolicyEffectDeny {
			return PolicyEffectDeny
		}
	}

	// Check for allow
	for _, match := range matches {
		if match.Rule.Effect == PolicyEffectAllow {
			return PolicyEffectAllow
		}
	}

	return PolicyEffectDeny
}

func (e *Engine) detectPolicyConflicts(policy1, policy2 *Policy) []*PolicyConflict {
	var conflicts []*PolicyConflict

	// Check for overlapping rules with different effects
	for _, rule1 := range policy1.Rules {
		for _, rule2 := range policy2.Rules {
			if e.rulesOverlap(&rule1, &rule2) && rule1.Effect != rule2.Effect {
				conflicts = append(conflicts, &PolicyConflict{
					Type:        ConflictTypeContradictory,
					Policy1:     policy1,
					Policy2:     policy2,
					Rule1:       &rule1,
					Rule2:       &rule2,
					Description: fmt.Sprintf("Rules have contradictory effects for overlapping resources"),
					Severity:    "HIGH",
					Resolution:  "Review policy priorities and rule specificity",
				})
			}
		}
	}

	return conflicts
}

func (e *Engine) rulesOverlap(rule1, rule2 *PolicyRule) bool {
	// Check if resources overlap
	if !e.resourcesOverlap(rule1.Resource, rule2.Resource) {
		return false
	}

	// Check if actions overlap
	if !e.actionsOverlap(rule1.Actions, rule2.Actions) {
		return false
	}

	// Check if principals overlap
	if !e.principalsOverlap(rule1.Principals, rule2.Principals) {
		return false
	}

	return true
}

func (e *Engine) resourcesOverlap(resource1, resource2 string) bool {
	// Simple overlap detection
	return e.matchesPattern(resource1, resource2) || e.matchesPattern(resource2, resource1)
}

func (e *Engine) actionsOverlap(actions1, actions2 []string) bool {
	for _, a1 := range actions1 {
		for _, a2 := range actions2 {
			if a1 == "*" || a2 == "*" || a1 == a2 {
				return true
			}
		}
	}
	return false
}

func (e *Engine) principalsOverlap(principals1, principals2 []string) bool {
	for _, p1 := range principals1 {
		for _, p2 := range principals2 {
			if p1 == "*" || p2 == "*" || p1 == p2 {
				return true
			}
		}
	}
	return false
}

// Statistics Methods

func (s *EngineStats) incrementEvaluationsTotal(count int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EvaluationsTotal += count
}

func (s *EngineStats) incrementEvaluationsAllowed(count int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EvaluationsAllowed += count
}

func (s *EngineStats) incrementEvaluationsDenied(count int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EvaluationsDenied += count
}

func (s *EngineStats) incrementEvaluationErrors(count int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EvaluationErrors += count
}

func (s *EngineStats) incrementCacheHits(count int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CacheHits += count
}

func (s *EngineStats) incrementCacheMisses(count int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CacheMisses += count
}

func (s *EngineStats) incrementPoliciesLoaded(count int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PoliciesLoaded += count
}

func (s *EngineStats) incrementConflictsDetected(count int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ConflictsDetected += count
}

func (s *EngineStats) updateAverageEvalTime(duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Simple moving average
	if s.AverageEvalTime == 0 {
		s.AverageEvalTime = duration
	} else {
		s.AverageEvalTime = (s.AverageEvalTime + duration) / 2
	}
}

// GetStats returns a copy of the current statistics
func (e *Engine) GetStats() *EngineStats {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()

	return &EngineStats{
		EvaluationsTotal:   e.stats.EvaluationsTotal,
		EvaluationsAllowed: e.stats.EvaluationsAllowed,
		EvaluationsDenied:  e.stats.EvaluationsDenied,
		EvaluationErrors:   e.stats.EvaluationErrors,
		AverageEvalTime:    e.stats.AverageEvalTime,
		CacheHits:         e.stats.CacheHits,
		CacheMisses:       e.stats.CacheMisses,
		PoliciesLoaded:    e.stats.PoliciesLoaded,
		ConflictsDetected: e.stats.ConflictsDetected,
	}
}