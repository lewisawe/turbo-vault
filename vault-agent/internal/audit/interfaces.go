package audit

import (
	"context"
	"time"
)

// AuditLogger defines the interface for audit logging operations
type AuditLogger interface {
	// LogAccess logs access events (authentication, authorization)
	LogAccess(ctx context.Context, event *AccessEvent) error
	
	// LogOperation logs operational events (CRUD operations on secrets)
	LogOperation(ctx context.Context, event *OperationEvent) error
	
	// LogSecurityEvent logs security-related events (policy violations, suspicious activity)
	LogSecurityEvent(ctx context.Context, event *SecurityEvent) error
	
	// QueryLogs retrieves audit logs based on query parameters
	QueryLogs(ctx context.Context, query *LogQuery) ([]*AuditEvent, error)
	
	// RotateLogs performs log rotation based on configured policies
	RotateLogs(ctx context.Context) error
	
	// ForwardLogs forwards logs to external systems
	ForwardLogs(ctx context.Context, destination string) error
	
	// Close releases any resources held by the audit logger
	Close() error
}

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	EventTypeAccess    AuditEventType = "access"
	EventTypeOperation AuditEventType = "operation"
	EventTypeSecurity  AuditEventType = "security"
	EventTypeSystem    AuditEventType = "system"
)

// AuditResult represents the result of an audited action
type AuditResult string

const (
	ResultSuccess AuditResult = "success"
	ResultFailure AuditResult = "failure"
	ResultDenied  AuditResult = "denied"
	ResultError   AuditResult = "error"
)

// Actor represents the entity performing an action
type Actor struct {
	Type      ActorType `json:"type"`
	ID        string    `json:"id"`
	Username  string    `json:"username,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
}

// ActorType represents the type of actor
type ActorType string

const (
	ActorTypeUser    ActorType = "user"
	ActorTypeService ActorType = "service"
	ActorTypeSystem  ActorType = "system"
	ActorTypeAPI     ActorType = "api"
)

// Resource represents the resource being accessed or modified
type Resource struct {
	Type       ResourceType `json:"type"`
	ID         string       `json:"id"`
	Name       string       `json:"name,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// ResourceType represents the type of resource
type ResourceType string

const (
	ResourceTypeSecret ResourceType = "secret"
	ResourceTypeKey    ResourceType = "key"
	ResourceTypePolicy ResourceType = "policy"
	ResourceTypeUser   ResourceType = "user"
	ResourceTypeSystem ResourceType = "system"
)

// AuditEvent is the base structure for all audit events
type AuditEvent struct {
	ID          string                 `json:"id"`
	VaultID     string                 `json:"vault_id"`
	EventType   AuditEventType         `json:"event_type"`
	Actor       Actor                  `json:"actor"`
	Resource    Resource               `json:"resource"`
	Action      string                 `json:"action"`
	Result      AuditResult            `json:"result"`
	Context     map[string]interface{} `json:"context"`
	Timestamp   time.Time              `json:"timestamp"`
	Duration    time.Duration          `json:"duration,omitempty"`
	ErrorMsg    string                 `json:"error_message,omitempty"`
	Severity    Severity               `json:"severity"`
}

// AccessEvent represents authentication and authorization events
type AccessEvent struct {
	AuditEvent
	AuthMethod     string `json:"auth_method"`
	Permissions    []string `json:"permissions,omitempty"`
	PolicyViolated string `json:"policy_violated,omitempty"`
}

// OperationEvent represents CRUD operations on resources
type OperationEvent struct {
	AuditEvent
	ResourceVersion string                 `json:"resource_version,omitempty"`
	Changes         map[string]interface{} `json:"changes,omitempty"`
	Metadata        map[string]string      `json:"metadata,omitempty"`
}

// SecurityEvent represents security-related events
type SecurityEvent struct {
	AuditEvent
	ThreatLevel   ThreatLevel `json:"threat_level"`
	Indicators    []string    `json:"indicators,omitempty"`
	Mitigation    string      `json:"mitigation,omitempty"`
	AlertTriggered bool       `json:"alert_triggered"`
}

// Severity represents the severity level of an audit event
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// ThreatLevel represents the threat level of a security event
type ThreatLevel string

const (
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
)

// LogQuery represents parameters for querying audit logs
type LogQuery struct {
	StartTime    *time.Time     `json:"start_time,omitempty"`
	EndTime      *time.Time     `json:"end_time,omitempty"`
	EventTypes   []AuditEventType `json:"event_types,omitempty"`
	ActorID      string         `json:"actor_id,omitempty"`
	ResourceType ResourceType   `json:"resource_type,omitempty"`
	ResourceID   string         `json:"resource_id,omitempty"`
	Action       string         `json:"action,omitempty"`
	Result       AuditResult    `json:"result,omitempty"`
	Severity     Severity       `json:"severity,omitempty"`
	Limit        int            `json:"limit,omitempty"`
	Offset       int            `json:"offset,omitempty"`
	OrderBy      string         `json:"order_by,omitempty"`
	OrderDesc    bool           `json:"order_desc,omitempty"`
}

// LogRotationPolicy defines log rotation settings
type LogRotationPolicy struct {
	MaxSize       int64         `json:"max_size"`        // Maximum size in bytes
	MaxAge        time.Duration `json:"max_age"`         // Maximum age of log files
	MaxFiles      int           `json:"max_files"`       // Maximum number of log files to retain
	CompressOld   bool          `json:"compress_old"`    // Whether to compress old log files
	RotateDaily   bool          `json:"rotate_daily"`    // Whether to rotate daily regardless of size
}

// LogForwardingConfig defines log forwarding settings
type LogForwardingConfig struct {
	Enabled      bool              `json:"enabled"`
	Destinations []LogDestination  `json:"destinations"`
	BufferSize   int               `json:"buffer_size"`
	FlushInterval time.Duration    `json:"flush_interval"`
	RetryPolicy  *RetryPolicy      `json:"retry_policy,omitempty"`
}

// LogDestination represents a log forwarding destination
type LogDestination struct {
	Name     string            `json:"name"`
	Type     DestinationType   `json:"type"`
	Config   map[string]interface{} `json:"config"`
	Filters  []LogFilter       `json:"filters,omitempty"`
	Enabled  bool              `json:"enabled"`
}

// DestinationType represents the type of log destination
type DestinationType string

const (
	DestinationTypeSyslog    DestinationType = "syslog"
	DestinationTypeWebhook   DestinationType = "webhook"
	DestinationTypeFile      DestinationType = "file"
	DestinationTypeElastic   DestinationType = "elasticsearch"
	DestinationTypeSplunk    DestinationType = "splunk"
	DestinationTypeKafka     DestinationType = "kafka"
)

// LogFilter represents filters for log forwarding
type LogFilter struct {
	Field    string      `json:"field"`
	Operator FilterOp    `json:"operator"`
	Value    interface{} `json:"value"`
}

// FilterOp represents filter operators
type FilterOp string

const (
	FilterOpEquals      FilterOp = "equals"
	FilterOpNotEquals   FilterOp = "not_equals"
	FilterOpContains    FilterOp = "contains"
	FilterOpNotContains FilterOp = "not_contains"
	FilterOpGreaterThan FilterOp = "greater_than"
	FilterOpLessThan    FilterOp = "less_than"
	FilterOpIn          FilterOp = "in"
	FilterOpNotIn       FilterOp = "not_in"
)

// RetryPolicy defines retry behavior for log forwarding
type RetryPolicy struct {
	MaxAttempts   int           `json:"max_attempts"`
	InitialDelay  time.Duration `json:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
}

// AuditConfig contains configuration for the audit logging system
type AuditConfig struct {
	Enabled           bool                 `json:"enabled"`
	LogLevel          Severity             `json:"log_level"`
	StoragePath       string               `json:"storage_path"`
	RotationPolicy    LogRotationPolicy    `json:"rotation_policy"`
	ForwardingConfig  LogForwardingConfig  `json:"forwarding_config"`
	EncryptLogs       bool                 `json:"encrypt_logs"`
	EncryptionKeyID   string               `json:"encryption_key_id,omitempty"`
	IntegrityChecking bool                 `json:"integrity_checking"`
}