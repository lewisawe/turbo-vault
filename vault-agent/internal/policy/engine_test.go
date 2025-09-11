package policy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// Mock implementations for testing

type mockPolicyStorage struct {
	policies map[string]*Policy
}

func newMockPolicyStorage() *mockPolicyStorage {
	return &mockPolicyStorage{
		policies: make(map[string]*Policy),
	}
}

func (m *mockPolicyStorage) CreatePolicy(ctx context.Context, policy *Policy) error {
	m.policies[policy.ID] = policy
	return nil
}

func (m *mockPolicyStorage) UpdatePolicy(ctx context.Context, id string, policy *Policy) error {
	m.policies[id] = policy
	return nil
}

func (m *mockPolicyStorage) DeletePolicy(ctx context.Context, id string) error {
	delete(m.policies, id)
	return nil
}

func (m *mockPolicyStorage) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	if policy, exists := m.policies[id]; exists {
		return policy, nil
	}
	return nil, nil
}

func (m *mockPolicyStorage) ListPolicies(ctx context.Context, filter *PolicyFilter) ([]*Policy, error) {
	var result []*Policy
	for _, policy := range m.policies {
		if filter == nil || filter.Enabled == nil || *filter.Enabled == policy.Enabled {
			result = append(result, policy)
		}
	}
	
	// Apply limit if specified
	if filter != nil && filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}
	
	return result, nil
}

func (m *mockPolicyStorage) GetPoliciesByResource(ctx context.Context, resource string) ([]*Policy, error) {
	return m.ListPolicies(ctx, nil)
}

func (m *mockPolicyStorage) GetPoliciesByRole(ctx context.Context, role string) ([]*Policy, error) {
	return m.ListPolicies(ctx, nil)
}

type mockPolicyCache struct {
	cache map[string]*Policy
	hits  int64
	misses int64
}

func newMockPolicyCache() *mockPolicyCache {
	return &mockPolicyCache{
		cache: make(map[string]*Policy),
	}
}

func (m *mockPolicyCache) Get(ctx context.Context, key string) (*Policy, bool) {
	policy, exists := m.cache[key]
	if exists {
		m.hits++
	} else {
		m.misses++
	}
	return policy, exists
}

func (m *mockPolicyCache) Set(ctx context.Context, key string, policy *Policy, ttl time.Duration) error {
	m.cache[key] = policy
	return nil
}

func (m *mockPolicyCache) Delete(ctx context.Context, key string) error {
	delete(m.cache, key)
	return nil
}

func (m *mockPolicyCache) Clear(ctx context.Context) error {
	m.cache = make(map[string]*Policy)
	return nil
}

func (m *mockPolicyCache) Stats() *CacheStats {
	return &CacheStats{
		Size:    len(m.cache),
		MaxSize: 1000,
		Hits:    m.hits,
		Misses:  m.misses,
	}
}

type mockPolicyValidator struct{}

func (m *mockPolicyValidator) ValidatePolicy(ctx context.Context, policy *Policy) error {
	return nil
}

func (m *mockPolicyValidator) ValidateRule(ctx context.Context, rule *PolicyRule) error {
	return nil
}

func (m *mockPolicyValidator) ValidateCondition(ctx context.Context, condition *PolicyCondition) error {
	return nil
}

func (m *mockPolicyValidator) ValidateAction(ctx context.Context, action *PolicyAction) error {
	return nil
}

// Test helper functions

func createTestEngine() *Engine {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests

	storage := newMockPolicyStorage()
	cache := newMockPolicyCache()
	validator := &mockPolicyValidator{}
	evaluator := NewDefaultConditionEvaluator(logger)

	config := DefaultEngineConfig()
	config.CacheEnabled = true

	return NewEngine(storage, cache, validator, evaluator, logger, config)
}

func createTestPolicy(id, name string, effect PolicyEffect, resource string, actions []string, principals []string) *Policy {
	return &Policy{
		ID:          id,
		Name:        name,
		Description: "Test policy",
		Rules: []PolicyRule{
			{
				ID:          "rule-1",
				Effect:      effect,
				Resource:    resource,
				Actions:     actions,
				Principals:  principals,
				Conditions:  []PolicyCondition{},
				Priority:    100,
				Description: "Test rule",
			},
		},
		Conditions: []PolicyCondition{},
		Actions:    []PolicyAction{},
		Priority:   100,
		Enabled:    true,
		Version:    1,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		CreatedBy:  "test-user",
		Tags:       []string{"test"},
		Metadata:   map[string]string{"env": "test"},
	}
}

func createTestAccessRequest(principal, resource, action string) *AccessRequest {
	return &AccessRequest{
		Principal: principal,
		Resource:  resource,
		Action:    action,
		Context: &RequestContext{
			UserID:    "user-123",
			Username:  "testuser",
			Roles:     []string{"user"},
			Groups:    []string{"developers"},
			IPAddress: "192.168.1.100",
			UserAgent: "test-agent",
			SessionID: "session-123",
			Timestamp: time.Now(),
		},
		Attributes: map[string]interface{}{
			"department": "engineering",
		},
		RequestID: "req-123",
		Timestamp: time.Now(),
	}
}

// Test cases

func TestEngine_CreatePolicy(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	policy := createTestPolicy("policy-1", "test-policy", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"user-123"})

	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Verify policy was stored
	stored, err := engine.GetPolicy(ctx, "policy-1")
	if err != nil {
		t.Fatalf("Failed to get policy: %v", err)
	}

	if stored.Name != "test-policy" {
		t.Errorf("Expected policy name 'test-policy', got '%s'", stored.Name)
	}
}

func TestEngine_EvaluateAccess_Allow(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create an allow policy
	policy := createTestPolicy("policy-1", "allow-policy", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"user-123"})
	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Create access request
	request := createTestAccessRequest("user-123", "secrets/test", "read")

	// Evaluate access
	decision, err := engine.EvaluateAccess(ctx, request)
	if err != nil {
		t.Fatalf("Failed to evaluate access: %v", err)
	}

	if decision.Decision != PolicyEffectAllow {
		t.Errorf("Expected ALLOW decision, got %s", decision.Decision)
	}

	if len(decision.MatchedPolicies) != 1 {
		t.Errorf("Expected 1 matched policy, got %d", len(decision.MatchedPolicies))
	}
}

func TestEngine_EvaluateAccess_Deny(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create a deny policy
	policy := createTestPolicy("policy-1", "deny-policy", PolicyEffectDeny, "secrets/*", []string{"delete"}, []string{"user-123"})
	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Create access request
	request := createTestAccessRequest("user-123", "secrets/test", "delete")

	// Evaluate access
	decision, err := engine.EvaluateAccess(ctx, request)
	if err != nil {
		t.Fatalf("Failed to evaluate access: %v", err)
	}

	if decision.Decision != PolicyEffectDeny {
		t.Errorf("Expected DENY decision, got %s", decision.Decision)
	}
}

func TestEngine_EvaluateAccess_NoMatch(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create a policy that doesn't match
	policy := createTestPolicy("policy-1", "no-match-policy", PolicyEffectAllow, "users/*", []string{"read"}, []string{"user-456"})
	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Create access request that doesn't match
	request := createTestAccessRequest("user-123", "secrets/test", "read")

	// Evaluate access
	decision, err := engine.EvaluateAccess(ctx, request)
	if err != nil {
		t.Fatalf("Failed to evaluate access: %v", err)
	}

	if decision.Decision != PolicyEffectDeny {
		t.Errorf("Expected DENY decision (default), got %s", decision.Decision)
	}

	if len(decision.MatchedPolicies) != 0 {
		t.Errorf("Expected 0 matched policies, got %d", len(decision.MatchedPolicies))
	}
}

func TestEngine_EvaluateAccess_WithConditions(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create a policy with time condition
	policy := createTestPolicy("policy-1", "time-policy", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"user-123"})
	policy.Rules[0].Conditions = []PolicyCondition{
		{
			ID:       "cond-1",
			Type:     ConditionTypeTime,
			Field:    "hour",
			Operator: OperatorGreaterOrEqual,
			Value:    9,
		},
		{
			ID:       "cond-2",
			Type:     ConditionTypeTime,
			Field:    "hour",
			Operator: OperatorLessOrEqual,
			Value:    17,
		},
	}

	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Create access request during business hours
	request := createTestAccessRequest("user-123", "secrets/test", "read")
	request.Context.Timestamp = time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC) // 10 AM

	// Evaluate access
	decision, err := engine.EvaluateAccess(ctx, request)
	if err != nil {
		t.Fatalf("Failed to evaluate access: %v", err)
	}

	if decision.Decision != PolicyEffectAllow {
		t.Errorf("Expected ALLOW decision during business hours, got %s", decision.Decision)
	}

	// Test outside business hours
	request.Context.Timestamp = time.Date(2023, 1, 1, 20, 0, 0, 0, time.UTC) // 8 PM

	decision, err = engine.EvaluateAccess(ctx, request)
	if err != nil {
		t.Fatalf("Failed to evaluate access: %v", err)
	}

	if decision.Decision != PolicyEffectDeny {
		t.Errorf("Expected DENY decision outside business hours, got %s", decision.Decision)
	}
}

func TestEngine_EvaluateAccess_RoleBased(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create a role-based policy
	policy := createTestPolicy("policy-1", "role-policy", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"role:admin"})
	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Create access request with admin role
	request := createTestAccessRequest("user-123", "secrets/test", "read")
	request.Context.Roles = []string{"admin", "user"}

	// Evaluate access
	decision, err := engine.EvaluateAccess(ctx, request)
	if err != nil {
		t.Fatalf("Failed to evaluate access: %v", err)
	}

	if decision.Decision != PolicyEffectAllow {
		t.Errorf("Expected ALLOW decision for admin role, got %s", decision.Decision)
	}

	// Test without admin role
	request.Context.Roles = []string{"user"}

	decision, err = engine.EvaluateAccess(ctx, request)
	if err != nil {
		t.Fatalf("Failed to evaluate access: %v", err)
	}

	if decision.Decision != PolicyEffectDeny {
		t.Errorf("Expected DENY decision without admin role, got %s", decision.Decision)
	}
}

func TestEngine_EvaluateAccess_WildcardResource(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create a wildcard policy
	policy := createTestPolicy("policy-1", "wildcard-policy", PolicyEffectAllow, "*", []string{"*"}, []string{"*"})
	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Create access request
	request := createTestAccessRequest("user-123", "any/resource", "any-action")

	// Evaluate access
	decision, err := engine.EvaluateAccess(ctx, request)
	if err != nil {
		t.Fatalf("Failed to evaluate access: %v", err)
	}

	if decision.Decision != PolicyEffectAllow {
		t.Errorf("Expected ALLOW decision for wildcard policy, got %s", decision.Decision)
	}
}

func TestEngine_EvaluateAccess_PriorityOrdering(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create high priority deny policy
	denyPolicy := createTestPolicy("policy-1", "deny-policy", PolicyEffectDeny, "secrets/*", []string{"read"}, []string{"user-123"})
	denyPolicy.Priority = 200
	err := engine.CreatePolicy(ctx, denyPolicy)
	if err != nil {
		t.Fatalf("Failed to create deny policy: %v", err)
	}

	// Create low priority allow policy
	allowPolicy := createTestPolicy("policy-2", "allow-policy", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"user-123"})
	allowPolicy.Priority = 100
	err = engine.CreatePolicy(ctx, allowPolicy)
	if err != nil {
		t.Fatalf("Failed to create allow policy: %v", err)
	}

	// Create access request
	request := createTestAccessRequest("user-123", "secrets/test", "read")

	// Evaluate access - deny should take precedence
	decision, err := engine.EvaluateAccess(ctx, request)
	if err != nil {
		t.Fatalf("Failed to evaluate access: %v", err)
	}

	if decision.Decision != PolicyEffectDeny {
		t.Errorf("Expected DENY decision (higher priority), got %s", decision.Decision)
	}
}

func TestEngine_DetectConflicts(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create first policy
	policy1 := createTestPolicy("policy-1", "allow-policy", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"user-123"})
	err := engine.CreatePolicy(ctx, policy1)
	if err != nil {
		t.Fatalf("Failed to create first policy: %v", err)
	}

	// Create conflicting policy
	policy2 := createTestPolicy("policy-2", "deny-policy", PolicyEffectDeny, "secrets/*", []string{"read"}, []string{"user-123"})

	// Detect conflicts
	conflicts, err := engine.DetectConflicts(ctx, policy2)
	if err != nil {
		t.Fatalf("Failed to detect conflicts: %v", err)
	}

	if len(conflicts) == 0 {
		t.Error("Expected conflicts to be detected")
	}

	if len(conflicts) > 0 && conflicts[0].Type != ConflictTypeContradictory {
		t.Errorf("Expected contradictory conflict, got %s", conflicts[0].Type)
	}
}

func TestEngine_Cache(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	policy := createTestPolicy("policy-1", "cached-policy", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"user-123"})
	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// First get should miss cache
	retrieved1, err := engine.GetPolicy(ctx, "policy-1")
	if err != nil {
		t.Fatalf("Failed to get policy: %v", err)
	}

	// Second get should hit cache
	retrieved2, err := engine.GetPolicy(ctx, "policy-1")
	if err != nil {
		t.Fatalf("Failed to get policy from cache: %v", err)
	}

	if retrieved1.Name != retrieved2.Name {
		t.Error("Cached policy should be identical to original")
	}

	// Check cache stats
	stats := engine.GetCacheStats()
	if stats.Hits == 0 {
		t.Error("Expected cache hits")
	}
}

func TestEngine_UpdatePolicy(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create initial policy
	policy := createTestPolicy("policy-1", "original-policy", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"user-123"})
	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Update policy
	policy.Name = "updated-policy"
	policy.Description = "Updated description"
	err = engine.UpdatePolicy(ctx, "policy-1", policy)
	if err != nil {
		t.Fatalf("Failed to update policy: %v", err)
	}

	// Verify update
	updated, err := engine.GetPolicy(ctx, "policy-1")
	if err != nil {
		t.Fatalf("Failed to get updated policy: %v", err)
	}

	if updated.Name != "updated-policy" {
		t.Errorf("Expected updated name 'updated-policy', got '%s'", updated.Name)
	}

	if updated.Version != 2 {
		t.Errorf("Expected version 2, got %d", updated.Version)
	}
}

func TestEngine_DeletePolicy(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create policy
	policy := createTestPolicy("policy-1", "delete-me", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"user-123"})
	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Delete policy
	err = engine.DeletePolicy(ctx, "policy-1")
	if err != nil {
		t.Fatalf("Failed to delete policy: %v", err)
	}

	// Verify deletion
	deleted, err := engine.GetPolicy(ctx, "policy-1")
	if err != nil {
		t.Fatalf("Unexpected error getting deleted policy: %v", err)
	}

	if deleted != nil {
		t.Error("Policy should be deleted")
	}
}

func TestEngine_ListPolicies(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create multiple policies
	for i := 0; i < 5; i++ {
		policy := createTestPolicy(
			fmt.Sprintf("policy-%d", i),
			fmt.Sprintf("test-policy-%d", i),
			PolicyEffectAllow,
			"secrets/*",
			[]string{"read"},
			[]string{"user-123"},
		)
		err := engine.CreatePolicy(ctx, policy)
		if err != nil {
			t.Fatalf("Failed to create policy %d: %v", i, err)
		}
	}

	// List all policies
	policies, err := engine.ListPolicies(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to list policies: %v", err)
	}

	if len(policies) != 5 {
		t.Errorf("Expected 5 policies, got %d", len(policies))
	}

	// List with filter
	enabled := true
	filter := &PolicyFilter{
		Enabled: &enabled,
		Limit:   3,
	}

	filteredPolicies, err := engine.ListPolicies(ctx, filter)
	if err != nil {
		t.Fatalf("Failed to list filtered policies: %v", err)
	}

	if len(filteredPolicies) > 3 {
		t.Errorf("Expected at most 3 policies, got %d", len(filteredPolicies))
	}
}

func TestEngine_GetEffectivePolicies(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create policies for different resources
	secretsPolicy := createTestPolicy("policy-1", "secrets-policy", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"user-123"})
	err := engine.CreatePolicy(ctx, secretsPolicy)
	if err != nil {
		t.Fatalf("Failed to create secrets policy: %v", err)
	}

	usersPolicy := createTestPolicy("policy-2", "users-policy", PolicyEffectAllow, "users/*", []string{"read"}, []string{"user-123"})
	err = engine.CreatePolicy(ctx, usersPolicy)
	if err != nil {
		t.Fatalf("Failed to create users policy: %v", err)
	}

	// Get effective policies for secrets
	effectivePolicies, err := engine.GetEffectivePolicies(ctx, "secrets/test")
	if err != nil {
		t.Fatalf("Failed to get effective policies: %v", err)
	}

	// Should only return the secrets policy
	if len(effectivePolicies) != 1 {
		t.Errorf("Expected 1 effective policy for secrets, got %d", len(effectivePolicies))
	}

	if len(effectivePolicies) > 0 && effectivePolicies[0].Name != "secrets-policy" {
		t.Errorf("Expected secrets-policy, got %s", effectivePolicies[0].Name)
	}
}

func TestEngine_Statistics(t *testing.T) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create a policy
	policy := createTestPolicy("policy-1", "stats-policy", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"user-123"})
	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Perform some evaluations
	request := createTestAccessRequest("user-123", "secrets/test", "read")
	
	for i := 0; i < 10; i++ {
		_, err := engine.EvaluateAccess(ctx, request)
		if err != nil {
			t.Fatalf("Failed to evaluate access: %v", err)
		}
	}

	// Check statistics
	stats := engine.GetStats()
	if stats.EvaluationsTotal != 10 {
		t.Errorf("Expected 10 total evaluations, got %d", stats.EvaluationsTotal)
	}

	if stats.EvaluationsAllowed != 10 {
		t.Errorf("Expected 10 allowed evaluations, got %d", stats.EvaluationsAllowed)
	}

	if stats.PoliciesLoaded == 0 {
		t.Error("Expected policies to be loaded")
	}
}

// Benchmark tests

func BenchmarkEngine_EvaluateAccess(b *testing.B) {
	engine := createTestEngine()
	ctx := context.Background()

	// Create a policy
	policy := createTestPolicy("policy-1", "bench-policy", PolicyEffectAllow, "secrets/*", []string{"read"}, []string{"user-123"})
	err := engine.CreatePolicy(ctx, policy)
	if err != nil {
		b.Fatalf("Failed to create policy: %v", err)
	}

	request := createTestAccessRequest("user-123", "secrets/test", "read")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.EvaluateAccess(ctx, request)
		if err != nil {
			b.Fatalf("Failed to evaluate access: %v", err)
		}
	}
}

func BenchmarkEngine_CreatePolicy(b *testing.B) {
	engine := createTestEngine()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		policy := createTestPolicy(
			fmt.Sprintf("policy-%d", i),
			fmt.Sprintf("bench-policy-%d", i),
			PolicyEffectAllow,
			"secrets/*",
			[]string{"read"},
			[]string{"user-123"},
		)
		err := engine.CreatePolicy(ctx, policy)
		if err != nil {
			b.Fatalf("Failed to create policy: %v", err)
		}
	}
}

