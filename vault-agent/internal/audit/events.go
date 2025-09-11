package audit

import (
	"time"

	"github.com/google/uuid"
)

// EventBuilder provides a fluent interface for building audit events
type EventBuilder struct {
	event *AuditEvent
}

// NewEventBuilder creates a new event builder
func NewEventBuilder() *EventBuilder {
	return &EventBuilder{
		event: &AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now().UTC(),
			Context:   make(map[string]interface{}),
			Severity:  SeverityInfo,
		},
	}
}

// WithVaultID sets the vault ID
func (b *EventBuilder) WithVaultID(vaultID string) *EventBuilder {
	b.event.VaultID = vaultID
	return b
}

// WithActor sets the actor information
func (b *EventBuilder) WithActor(actorType ActorType, id, username string) *EventBuilder {
	b.event.Actor = Actor{
		Type:     actorType,
		ID:       id,
		Username: username,
	}
	return b
}

// WithActorDetails adds additional actor details
func (b *EventBuilder) WithActorDetails(ipAddress, userAgent, sessionID string) *EventBuilder {
	b.event.Actor.IPAddress = ipAddress
	b.event.Actor.UserAgent = userAgent
	b.event.Actor.SessionID = sessionID
	return b
}

// WithResource sets the resource information
func (b *EventBuilder) WithResource(resourceType ResourceType, id, name string) *EventBuilder {
	b.event.Resource = Resource{
		Type: resourceType,
		ID:   id,
		Name: name,
		Attributes: make(map[string]interface{}),
	}
	return b
}

// WithResourceAttribute adds a resource attribute
func (b *EventBuilder) WithResourceAttribute(key string, value interface{}) *EventBuilder {
	if b.event.Resource.Attributes == nil {
		b.event.Resource.Attributes = make(map[string]interface{})
	}
	b.event.Resource.Attributes[key] = value
	return b
}

// WithAction sets the action
func (b *EventBuilder) WithAction(action string) *EventBuilder {
	b.event.Action = action
	return b
}

// WithResult sets the result
func (b *EventBuilder) WithResult(result AuditResult) *EventBuilder {
	b.event.Result = result
	return b
}

// WithSeverity sets the severity
func (b *EventBuilder) WithSeverity(severity Severity) *EventBuilder {
	b.event.Severity = severity
	return b
}

// WithDuration sets the operation duration
func (b *EventBuilder) WithDuration(duration time.Duration) *EventBuilder {
	b.event.Duration = duration
	return b
}

// WithError sets the error message
func (b *EventBuilder) WithError(errorMsg string) *EventBuilder {
	b.event.ErrorMsg = errorMsg
	b.event.Result = ResultError
	if b.event.Severity == SeverityInfo {
		b.event.Severity = SeverityError
	}
	return b
}

// WithContext adds context information
func (b *EventBuilder) WithContext(key string, value interface{}) *EventBuilder {
	b.event.Context[key] = value
	return b
}

// WithContextMap adds multiple context values
func (b *EventBuilder) WithContextMap(context map[string]interface{}) *EventBuilder {
	for k, v := range context {
		b.event.Context[k] = v
	}
	return b
}

// BuildAccessEvent builds an access event
func (b *EventBuilder) BuildAccessEvent(authMethod string, permissions []string) *AccessEvent {
	b.event.EventType = EventTypeAccess
	return &AccessEvent{
		AuditEvent:  *b.event,
		AuthMethod:  authMethod,
		Permissions: permissions,
	}
}

// BuildOperationEvent builds an operation event
func (b *EventBuilder) BuildOperationEvent(resourceVersion string, changes map[string]interface{}) *OperationEvent {
	b.event.EventType = EventTypeOperation
	return &OperationEvent{
		AuditEvent:      *b.event,
		ResourceVersion: resourceVersion,
		Changes:         changes,
		Metadata:        make(map[string]string),
	}
}

// BuildSecurityEvent builds a security event
func (b *EventBuilder) BuildSecurityEvent(threatLevel ThreatLevel, indicators []string) *SecurityEvent {
	b.event.EventType = EventTypeSecurity
	if b.event.Severity == SeverityInfo {
		// Security events should have at least warning severity
		b.event.Severity = SeverityWarning
	}
	return &SecurityEvent{
		AuditEvent:     *b.event,
		ThreatLevel:    threatLevel,
		Indicators:     indicators,
		AlertTriggered: threatLevel == ThreatLevelHigh || threatLevel == ThreatLevelCritical,
	}
}

// Build builds a generic audit event
func (b *EventBuilder) Build() *AuditEvent {
	return b.event
}

// Predefined event creators for common operations

// CreateSecretAccessEvent creates an event for secret access
func CreateSecretAccessEvent(vaultID, actorID, secretID string, result AuditResult) *OperationEvent {
	return NewEventBuilder().
		WithVaultID(vaultID).
		WithActor(ActorTypeUser, actorID, "").
		WithResource(ResourceTypeSecret, secretID, "").
		WithAction("read").
		WithResult(result).
		BuildOperationEvent("", nil)
}

// CreateSecretCreateEvent creates an event for secret creation
func CreateSecretCreateEvent(vaultID, actorID, secretID, secretName string, result AuditResult) *OperationEvent {
	changes := map[string]interface{}{
		"operation": "create",
		"name":      secretName,
	}
	
	return NewEventBuilder().
		WithVaultID(vaultID).
		WithActor(ActorTypeUser, actorID, "").
		WithResource(ResourceTypeSecret, secretID, secretName).
		WithAction("create").
		WithResult(result).
		BuildOperationEvent("1", changes)
}

// CreateSecretUpdateEvent creates an event for secret updates
func CreateSecretUpdateEvent(vaultID, actorID, secretID string, changes map[string]interface{}, result AuditResult) *OperationEvent {
	return NewEventBuilder().
		WithVaultID(vaultID).
		WithActor(ActorTypeUser, actorID, "").
		WithResource(ResourceTypeSecret, secretID, "").
		WithAction("update").
		WithResult(result).
		BuildOperationEvent("", changes)
}

// CreateSecretDeleteEvent creates an event for secret deletion
func CreateSecretDeleteEvent(vaultID, actorID, secretID string, result AuditResult) *OperationEvent {
	changes := map[string]interface{}{
		"operation": "delete",
	}
	
	return NewEventBuilder().
		WithVaultID(vaultID).
		WithActor(ActorTypeUser, actorID, "").
		WithResource(ResourceTypeSecret, secretID, "").
		WithAction("delete").
		WithResult(result).
		WithSeverity(SeverityWarning).
		BuildOperationEvent("", changes)
}

// CreateSecretRotationEvent creates an event for secret rotation
func CreateSecretRotationEvent(vaultID, actorID, secretID string, oldVersion, newVersion string, result AuditResult) *OperationEvent {
	changes := map[string]interface{}{
		"operation":   "rotate",
		"old_version": oldVersion,
		"new_version": newVersion,
	}
	
	return NewEventBuilder().
		WithVaultID(vaultID).
		WithActor(ActorTypeSystem, actorID, "").
		WithResource(ResourceTypeSecret, secretID, "").
		WithAction("rotate").
		WithResult(result).
		BuildOperationEvent(newVersion, changes)
}

// CreateAuthenticationEvent creates an event for authentication attempts
func CreateAuthenticationEvent(vaultID, actorID, username, authMethod string, result AuditResult, ipAddress string) *AccessEvent {
	builder := NewEventBuilder().
		WithVaultID(vaultID).
		WithActor(ActorTypeUser, actorID, username).
		WithActorDetails(ipAddress, "", "").
		WithAction("authenticate").
		WithResult(result)

	if result == ResultFailure {
		builder.WithSeverity(SeverityWarning)
	}

	return builder.BuildAccessEvent(authMethod, nil)
}

// CreateAuthorizationEvent creates an event for authorization checks
func CreateAuthorizationEvent(vaultID, actorID, resourceID string, action string, result AuditResult, permissions []string) *AccessEvent {
	builder := NewEventBuilder().
		WithVaultID(vaultID).
		WithActor(ActorTypeUser, actorID, "").
		WithResource(ResourceTypeSecret, resourceID, "").
		WithAction(action).
		WithResult(result)

	if result == ResultDenied {
		builder.WithSeverity(SeverityWarning)
	}

	return builder.BuildAccessEvent("", permissions)
}

// CreatePolicyViolationEvent creates an event for policy violations
func CreatePolicyViolationEvent(vaultID, actorID, policyID, violation string, threatLevel ThreatLevel) *SecurityEvent {
	indicators := []string{
		"policy_violation",
		"policy_id:" + policyID,
		"violation:" + violation,
	}

	severity := SeverityWarning
	if threatLevel == ThreatLevelHigh || threatLevel == ThreatLevelCritical {
		severity = SeverityError
	}

	return NewEventBuilder().
		WithVaultID(vaultID).
		WithActor(ActorTypeUser, actorID, "").
		WithResource(ResourceTypePolicy, policyID, "").
		WithAction("violate").
		WithResult(ResultDenied).
		WithSeverity(severity).
		WithContext("violation_details", violation).
		BuildSecurityEvent(threatLevel, indicators)
}

// CreateSuspiciousActivityEvent creates an event for suspicious activity
func CreateSuspiciousActivityEvent(vaultID, actorID, activity string, indicators []string, threatLevel ThreatLevel) *SecurityEvent {
	severity := SeverityWarning
	if threatLevel == ThreatLevelHigh || threatLevel == ThreatLevelCritical {
		severity = SeverityCritical
	}

	return NewEventBuilder().
		WithVaultID(vaultID).
		WithActor(ActorTypeUser, actorID, "").
		WithAction("suspicious_activity").
		WithResult(ResultFailure).
		WithSeverity(severity).
		WithContext("activity_type", activity).
		BuildSecurityEvent(threatLevel, indicators)
}

// CreateSystemEvent creates an event for system-level operations
func CreateSystemEvent(vaultID, component, action string, result AuditResult, context map[string]interface{}) *AuditEvent {
	builder := NewEventBuilder().
		WithVaultID(vaultID).
		WithActor(ActorTypeSystem, "system", "").
		WithResource(ResourceTypeSystem, component, "").
		WithAction(action).
		WithResult(result).
		WithContextMap(context)

	if result == ResultError || result == ResultFailure {
		builder.WithSeverity(SeverityError)
	}

	return builder.Build()
}

// CreateKeyManagementEvent creates an event for key management operations
func CreateKeyManagementEvent(vaultID, keyID, operation string, result AuditResult) *OperationEvent {
	changes := map[string]interface{}{
		"operation": operation,
	}

	severity := SeverityInfo
	if operation == "delete" || operation == "rotate" {
		severity = SeverityWarning
	}

	return NewEventBuilder().
		WithVaultID(vaultID).
		WithActor(ActorTypeSystem, "key_manager", "").
		WithResource(ResourceTypeKey, keyID, "").
		WithAction(operation).
		WithResult(result).
		WithSeverity(severity).
		BuildOperationEvent("", changes)
}