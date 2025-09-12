package policy

import (
	"context"
	"time"
)

// PolicyEngine defines the interface for policy evaluation and management
type PolicyEngine interface {
	// Policy Management
	CreatePolicy(ctx context.Context, policy *Policy) error
	UpdatePolicy(ctx context.Context, id string, policy *Policy) error
	DeletePolicy(ctx context.Context, id string) error
	GetPolicy(ctx context.Context, id string) (*Policy, error)
	ListPolicies(ctx context.Context, filter *PolicyFilter) ([]*Policy, error)
	
	// Policy Evaluation
	EvaluateAccess(ctx context.Context, request *AccessRequest) (*AccessDecision, error)
	EvaluateConditions(ctx context.Context, conditions []PolicyCondition, context *RequestContext) (bool, error)
	GetEffectivePolicies(ctx context.Context, resource string) ([]*Policy, error)
	
	// Policy Validation
	ValidatePolicy(ctx context.Context, policy *Policy) error
	DetectConflicts(ctx context.Context, policy *Policy) ([]*PolicyConflict, error)
	
	// Cache Management
	InvalidateCache(ctx context.Context, pattern string) error
	GetCacheStats() *CacheStats
}

// PolicyStorage defines the interface for policy persistence
type PolicyStorage interface {
	CreatePolicy(ctx context.Context, policy *Policy) error
	UpdatePolicy(ctx context.Context, id string, policy *Policy) error
	DeletePolicy(ctx context.Context, id string) error
	GetPolicy(ctx context.Context, id string) (*Policy, error)
	ListPolicies(ctx context.Context, filter *PolicyFilter) ([]*Policy, error)
	GetPoliciesByResource(ctx context.Context, resource string) ([]*Policy, error)
	GetPoliciesByRole(ctx context.Context, role string) ([]*Policy, error)
}

// PolicyCache defines the interface for policy caching
type PolicyCache interface {
	Get(ctx context.Context, key string) (*Policy, bool)
	Set(ctx context.Context, key string, policy *Policy, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
	Stats() *CacheStats
}

// ConditionEvaluator defines the interface for evaluating policy conditions
type ConditionEvaluator interface {
	Evaluate(ctx context.Context, condition *PolicyCondition, context *RequestContext) (bool, error)
	SupportedOperators() []string
	SupportedFunctions() []string
}

// PolicyValidator defines the interface for policy validation
type PolicyValidator interface {
	ValidatePolicy(ctx context.Context, policy *Policy) error
	ValidateRule(ctx context.Context, rule *PolicyRule) error
	ValidateCondition(ctx context.Context, condition *PolicyCondition) error
	ValidateAction(ctx context.Context, action *PolicyAction) error
}