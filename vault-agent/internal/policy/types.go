package policy

import (
	"encoding/json"
	"time"
)

// Policy represents a security policy with rules and conditions
type Policy struct {
	ID          string            `json:"id" db:"id"`
	Name        string            `json:"name" db:"name"`
	Description string            `json:"description" db:"description"`
	Rules       []PolicyRule      `json:"rules" db:"rules"`
	Conditions  []PolicyCondition `json:"conditions" db:"conditions"`
	Actions     []PolicyAction    `json:"actions" db:"actions"`
	Priority    int               `json:"priority" db:"priority"`
	Enabled     bool              `json:"enabled" db:"enabled"`
	Version     int               `json:"version" db:"version"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	CreatedBy   string            `json:"created_by" db:"created_by"`
	Tags        []string          `json:"tags" db:"tags"`
	Metadata    map[string]string `json:"metadata" db:"metadata"`
}

// PolicyRule defines a specific access control rule
type PolicyRule struct {
	ID          string            `json:"id"`
	Effect      PolicyEffect      `json:"effect"`      // ALLOW, DENY
	Resource    string            `json:"resource"`    // Resource pattern (e.g., "secrets/*", "secrets/prod/*")
	Actions     []string          `json:"actions"`     // Actions allowed/denied (e.g., "read", "write", "delete")
	Principals  []string          `json:"principals"`  // Users, roles, or groups
	Conditions  []PolicyCondition `json:"conditions"`  // Additional conditions
	Priority    int               `json:"priority"`    // Rule priority within policy
	Description string            `json:"description"` // Human-readable description
}

// PolicyCondition defines a condition that must be met for a rule to apply
type PolicyCondition struct {
	ID       string                 `json:"id"`
	Type     ConditionType          `json:"type"`     // TIME, IP, ATTRIBUTE, FUNCTION
	Field    string                 `json:"field"`    // Field to evaluate
	Operator ConditionOperator      `json:"operator"` // Comparison operator
	Value    interface{}            `json:"value"`    // Expected value
	Values   []interface{}          `json:"values"`   // Multiple values for IN/NOT_IN operators
	Function string                 `json:"function"` // Function name for FUNCTION type
	Args     map[string]interface{} `json:"args"`     // Function arguments
	Negate   bool                   `json:"negate"`   // Negate the condition result
}

// PolicyAction defines an action to take when a policy matches
type PolicyAction struct {
	Type       ActionType             `json:"type"`       // LOG, ALERT, BLOCK, REQUIRE_APPROVAL
	Config     map[string]interface{} `json:"config"`     // Action-specific configuration
	Conditions []PolicyCondition      `json:"conditions"` // Conditions for action execution
}

// AccessRequest represents a request for access to a resource
type AccessRequest struct {
	Principal   string                 `json:"principal"`   // User, service, or role making the request
	Resource    string                 `json:"resource"`    // Resource being accessed
	Action      string                 `json:"action"`      // Action being performed
	Context     *RequestContext        `json:"context"`     // Request context
	Attributes  map[string]interface{} `json:"attributes"`  // Additional request attributes
	RequestID   string                 `json:"request_id"`  // Unique request identifier
	Timestamp   time.Time              `json:"timestamp"`   // Request timestamp
}

// RequestContext provides context information for policy evaluation
type RequestContext struct {
	UserID        string                 `json:"user_id"`
	Username      string                 `json:"username"`
	Roles         []string               `json:"roles"`
	Groups        []string               `json:"groups"`
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	SessionID     string                 `json:"session_id"`
	Timestamp     time.Time              `json:"timestamp"`
	TimeOfDay     string                 `json:"time_of_day"`     // HH:MM format
	DayOfWeek     string                 `json:"day_of_week"`     // Monday, Tuesday, etc.
	Location      *GeoLocation           `json:"location"`        // Geographic location
	Device        *DeviceInfo            `json:"device"`          // Device information
	Network       *NetworkInfo           `json:"network"`         // Network information
	Authentication *AuthenticationInfo   `json:"authentication"`  // Authentication details
	Attributes    map[string]interface{} `json:"attributes"`      // Custom attributes
}

// GeoLocation represents geographic location information
type GeoLocation struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timezone  string  `json:"timezone"`
}

// DeviceInfo represents device information
type DeviceInfo struct {
	Type         string `json:"type"`          // desktop, mobile, tablet
	OS           string `json:"os"`            // Operating system
	Browser      string `json:"browser"`       // Browser name
	Version      string `json:"version"`       // Browser version
	Fingerprint  string `json:"fingerprint"`   // Device fingerprint
	TrustedDevice bool   `json:"trusted_device"` // Whether device is trusted
}

// NetworkInfo represents network information
type NetworkInfo struct {
	IPAddress    string   `json:"ip_address"`
	NetworkType  string   `json:"network_type"`  // corporate, public, vpn
	ISP          string   `json:"isp"`           // Internet service provider
	ASN          string   `json:"asn"`           // Autonomous system number
	TrustedNetwork bool   `json:"trusted_network"` // Whether network is trusted
	VPN          bool     `json:"vpn"`           // Whether connection is through VPN
	Proxy        bool     `json:"proxy"`         // Whether connection is through proxy
	TorExit      bool     `json:"tor_exit"`      // Whether IP is a Tor exit node
}

// AuthenticationInfo represents authentication details
type AuthenticationInfo struct {
	Method       string    `json:"method"`        // password, mfa, certificate, etc.
	Strength     int       `json:"strength"`      // Authentication strength score
	MFAVerified  bool      `json:"mfa_verified"`  // Whether MFA was used
	CertificateInfo *CertInfo `json:"certificate"` // Certificate details if applicable
	LoginTime    time.Time `json:"login_time"`    // When user logged in
	LastActivity time.Time `json:"last_activity"` // Last activity timestamp
}

// CertInfo represents certificate information
type CertInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	SerialNumber string   `json:"serial_number"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
}

// AccessDecision represents the result of policy evaluation
type AccessDecision struct {
	Decision      PolicyEffect       `json:"decision"`       // ALLOW, DENY
	Reason        string             `json:"reason"`         // Human-readable reason
	MatchedPolicies []*PolicyMatch   `json:"matched_policies"` // Policies that matched
	RequiredActions []PolicyAction   `json:"required_actions"` // Actions that must be taken
	Conditions    []string           `json:"conditions"`     // Additional conditions
	TTL           time.Duration      `json:"ttl"`            // Decision cache TTL
	Metadata      map[string]interface{} `json:"metadata"`   // Additional metadata
	EvaluationTime time.Duration     `json:"evaluation_time"` // Time taken to evaluate
	RequestID     string             `json:"request_id"`     // Request identifier
	Timestamp     time.Time          `json:"timestamp"`      // Decision timestamp
}

// PolicyMatch represents a policy that matched during evaluation
type PolicyMatch struct {
	Policy      *Policy       `json:"policy"`
	Rule        *PolicyRule   `json:"rule"`
	Conditions  []bool        `json:"conditions"`  // Which conditions matched
	Score       float64       `json:"score"`       // Match score for prioritization
	Explanation string        `json:"explanation"` // Why this policy matched
}

// PolicyFilter defines filters for policy queries
type PolicyFilter struct {
	IDs         []string          `json:"ids"`
	Names       []string          `json:"names"`
	Enabled     *bool             `json:"enabled"`
	Resource    string            `json:"resource"`
	Principal   string            `json:"principal"`
	Action      string            `json:"action"`
	Tags        []string          `json:"tags"`
	CreatedBy   string            `json:"created_by"`
	CreatedAfter *time.Time       `json:"created_after"`
	CreatedBefore *time.Time      `json:"created_before"`
	Metadata    map[string]string `json:"metadata"`
	Limit       int               `json:"limit"`
	Offset      int               `json:"offset"`
	SortBy      string            `json:"sort_by"`
	SortOrder   string            `json:"sort_order"`
}

// PolicyConflict represents a conflict between policies
type PolicyConflict struct {
	Type        ConflictType `json:"type"`
	Policy1     *Policy      `json:"policy1"`
	Policy2     *Policy      `json:"policy2"`
	Rule1       *PolicyRule  `json:"rule1"`
	Rule2       *PolicyRule  `json:"rule2"`
	Description string       `json:"description"`
	Severity    string       `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Resolution  string       `json:"resolution"` // Suggested resolution
}

// CacheStats represents cache statistics
type CacheStats struct {
	Hits        int64   `json:"hits"`
	Misses      int64   `json:"misses"`
	Evictions   int64   `json:"evictions"`
	Size        int     `json:"size"`
	MaxSize     int     `json:"max_size"`
	HitRate     float64 `json:"hit_rate"`
	MemoryUsage int64   `json:"memory_usage"`
}

// Enums and constants

// PolicyEffect represents the effect of a policy rule
type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "ALLOW"
	PolicyEffectDeny  PolicyEffect = "DENY"
)

// ConditionType represents the type of condition
type ConditionType string

const (
	ConditionTypeTime      ConditionType = "TIME"
	ConditionTypeIP        ConditionType = "IP"
	ConditionTypeAttribute ConditionType = "ATTRIBUTE"
	ConditionTypeFunction  ConditionType = "FUNCTION"
	ConditionTypeRegex     ConditionType = "REGEX"
	ConditionTypeJSON      ConditionType = "JSON"
)

// ConditionOperator represents comparison operators
type ConditionOperator string

const (
	OperatorEquals         ConditionOperator = "EQUALS"
	OperatorNotEquals      ConditionOperator = "NOT_EQUALS"
	OperatorGreaterThan    ConditionOperator = "GREATER_THAN"
	OperatorLessThan       ConditionOperator = "LESS_THAN"
	OperatorGreaterOrEqual ConditionOperator = "GREATER_OR_EQUAL"
	OperatorLessOrEqual    ConditionOperator = "LESS_OR_EQUAL"
	OperatorIn             ConditionOperator = "IN"
	OperatorNotIn          ConditionOperator = "NOT_IN"
	OperatorContains       ConditionOperator = "CONTAINS"
	OperatorNotContains    ConditionOperator = "NOT_CONTAINS"
	OperatorStartsWith     ConditionOperator = "STARTS_WITH"
	OperatorEndsWith       ConditionOperator = "ENDS_WITH"
	OperatorMatches        ConditionOperator = "MATCHES"
	OperatorNotMatches     ConditionOperator = "NOT_MATCHES"
	OperatorExists         ConditionOperator = "EXISTS"
	OperatorNotExists      ConditionOperator = "NOT_EXISTS"
)

// ActionType represents the type of policy action
type ActionType string

const (
	ActionTypeLog             ActionType = "LOG"
	ActionTypeAlert           ActionType = "ALERT"
	ActionTypeBlock           ActionType = "BLOCK"
	ActionTypeRequireApproval ActionType = "REQUIRE_APPROVAL"
	ActionTypeNotify          ActionType = "NOTIFY"
	ActionTypeAudit           ActionType = "AUDIT"
	ActionTypeThrottle        ActionType = "THROTTLE"
)

// ConflictType represents the type of policy conflict
type ConflictType string

const (
	ConflictTypeOverlapping ConflictType = "OVERLAPPING"
	ConflictTypeContradictory ConflictType = "CONTRADICTORY"
	ConflictTypeDuplicate   ConflictType = "DUPLICATE"
	ConflictTypePriority    ConflictType = "PRIORITY"
)

// JSON marshaling helpers

func (p *Policy) MarshalJSON() ([]byte, error) {
	type Alias Policy
	return json.Marshal(&struct {
		*Alias
		Rules      json.RawMessage `json:"rules"`
		Conditions json.RawMessage `json:"conditions"`
		Actions    json.RawMessage `json:"actions"`
	}{
		Alias:      (*Alias)(p),
		Rules:      mustMarshal(p.Rules),
		Conditions: mustMarshal(p.Conditions),
		Actions:    mustMarshal(p.Actions),
	})
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	type Alias Policy
	aux := &struct {
		*Alias
		Rules      json.RawMessage `json:"rules"`
		Conditions json.RawMessage `json:"conditions"`
		Actions    json.RawMessage `json:"actions"`
	}{
		Alias: (*Alias)(p),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if len(aux.Rules) > 0 {
		if err := json.Unmarshal(aux.Rules, &p.Rules); err != nil {
			return err
		}
	}

	if len(aux.Conditions) > 0 {
		if err := json.Unmarshal(aux.Conditions, &p.Conditions); err != nil {
			return err
		}
	}

	if len(aux.Actions) > 0 {
		if err := json.Unmarshal(aux.Actions, &p.Actions); err != nil {
			return err
		}
	}

	return nil
}

func mustMarshal(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// Validation helpers

func (pe PolicyEffect) IsValid() bool {
	return pe == PolicyEffectAllow || pe == PolicyEffectDeny
}

func (ct ConditionType) IsValid() bool {
	validTypes := []ConditionType{
		ConditionTypeTime, ConditionTypeIP, ConditionTypeAttribute,
		ConditionTypeFunction, ConditionTypeRegex, ConditionTypeJSON,
	}
	for _, t := range validTypes {
		if ct == t {
			return true
		}
	}
	return false
}

func (co ConditionOperator) IsValid() bool {
	validOperators := []ConditionOperator{
		OperatorEquals, OperatorNotEquals, OperatorGreaterThan, OperatorLessThan,
		OperatorGreaterOrEqual, OperatorLessOrEqual, OperatorIn, OperatorNotIn,
		OperatorContains, OperatorNotContains, OperatorStartsWith, OperatorEndsWith,
		OperatorMatches, OperatorNotMatches, OperatorExists, OperatorNotExists,
	}
	for _, op := range validOperators {
		if co == op {
			return true
		}
	}
	return false
}

func (at ActionType) IsValid() bool {
	validActions := []ActionType{
		ActionTypeLog, ActionTypeAlert, ActionTypeBlock, ActionTypeRequireApproval,
		ActionTypeNotify, ActionTypeAudit, ActionTypeThrottle,
	}
	for _, a := range validActions {
		if at == a {
			return true
		}
	}
	return false
}