package auth

import (
	"encoding/json"
	"time"
)

// User represents a system user
type User struct {
	ID                string            `json:"id" db:"id"`
	Username          string            `json:"username" db:"username"`
	Email             string            `json:"email" db:"email"`
	DisplayName       string            `json:"display_name" db:"display_name"`
	PasswordHash      string            `json:"-" db:"password_hash"`
	Status            UserStatus        `json:"status" db:"status"`
	Roles             []string          `json:"roles" db:"roles"`
	Groups            []string          `json:"groups" db:"groups"`
	Permissions       []string          `json:"permissions" db:"permissions"`
	ExternalID        string            `json:"external_id,omitempty" db:"external_id"`
	IdentityProvider  string            `json:"identity_provider,omitempty" db:"identity_provider"`
	MFAEnabled        bool              `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret         string            `json:"-" db:"mfa_secret"`
	LastLogin         *time.Time        `json:"last_login,omitempty" db:"last_login"`
	LastPasswordChange *time.Time       `json:"last_password_change,omitempty" db:"last_password_change"`
	FailedLoginAttempts int             `json:"failed_login_attempts" db:"failed_login_attempts"`
	LockedUntil       *time.Time        `json:"locked_until,omitempty" db:"locked_until"`
	CreatedAt         time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at" db:"updated_at"`
	CreatedBy         string            `json:"created_by" db:"created_by"`
	Metadata          map[string]string `json:"metadata" db:"metadata"`
	Tags              []string          `json:"tags" db:"tags"`
}

// Role represents a user role with permissions
type Role struct {
	ID          string            `json:"id" db:"id"`
	Name        string            `json:"name" db:"name"`
	DisplayName string            `json:"display_name" db:"display_name"`
	Description string            `json:"description" db:"description"`
	Permissions []string          `json:"permissions" db:"permissions"`
	ParentRoles []string          `json:"parent_roles" db:"parent_roles"`
	ChildRoles  []string          `json:"child_roles" db:"child_roles"`
	IsSystem    bool              `json:"is_system" db:"is_system"`
	IsDefault   bool              `json:"is_default" db:"is_default"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	CreatedBy   string            `json:"created_by" db:"created_by"`
	Metadata    map[string]string `json:"metadata" db:"metadata"`
	Tags        []string          `json:"tags" db:"tags"`
}

// Permission represents a specific permission
type Permission struct {
	ID          string            `json:"id" db:"id"`
	Name        string            `json:"name" db:"name"`
	DisplayName string            `json:"display_name" db:"display_name"`
	Description string            `json:"description" db:"description"`
	Resource    string            `json:"resource" db:"resource"`
	Action      string            `json:"action" db:"action"`
	Effect      PermissionEffect  `json:"effect" db:"effect"`
	Conditions  []string          `json:"conditions" db:"conditions"`
	IsSystem    bool              `json:"is_system" db:"is_system"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	CreatedBy   string            `json:"created_by" db:"created_by"`
	Metadata    map[string]string `json:"metadata" db:"metadata"`
	Tags        []string          `json:"tags" db:"tags"`
}

// Session represents a user session
type Session struct {
	ID           string            `json:"id" db:"id"`
	UserID       string            `json:"user_id" db:"user_id"`
	Username     string            `json:"username" db:"username"`
	Status       SessionStatus     `json:"status" db:"status"`
	IPAddress    string            `json:"ip_address" db:"ip_address"`
	UserAgent    string            `json:"user_agent" db:"user_agent"`
	CreatedAt    time.Time         `json:"created_at" db:"created_at"`
	LastActivity time.Time         `json:"last_activity" db:"last_activity"`
	ExpiresAt    time.Time         `json:"expires_at" db:"expires_at"`
	Metadata     map[string]string `json:"metadata" db:"metadata"`
	DeviceInfo   *DeviceInfo       `json:"device_info,omitempty" db:"device_info"`
	LocationInfo *LocationInfo     `json:"location_info,omitempty" db:"location_info"`
}

// APIKey represents an API key for authentication
type APIKey struct {
	ID          string            `json:"id" db:"id"`
	UserID      string            `json:"user_id" db:"user_id"`
	Name        string            `json:"name" db:"name"`
	Description string            `json:"description" db:"description"`
	KeyHash     string            `json:"-" db:"key_hash"`
	KeyPrefix   string            `json:"key_prefix" db:"key_prefix"`
	Permissions []string          `json:"permissions" db:"permissions"`
	Scopes      []string          `json:"scopes" db:"scopes"`
	Status      APIKeyStatus      `json:"status" db:"status"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	LastUsed    *time.Time        `json:"last_used,omitempty" db:"last_used"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty" db:"expires_at"`
	UsageCount  int64             `json:"usage_count" db:"usage_count"`
	RateLimit   *RateLimit        `json:"rate_limit,omitempty" db:"rate_limit"`
	Metadata    map[string]string `json:"metadata" db:"metadata"`
}

// JWTToken represents a JWT token pair
type JWTToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope,omitempty"`
}

// JWTClaims represents JWT token claims
type JWTClaims struct {
	UserID      string            `json:"user_id"`
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	Roles       []string          `json:"roles"`
	Permissions []string          `json:"permissions"`
	Scopes      []string          `json:"scopes"`
	SessionID   string            `json:"session_id,omitempty"`
	IssuedAt    time.Time         `json:"iat"`
	ExpiresAt   time.Time         `json:"exp"`
	NotBefore   time.Time         `json:"nbf"`
	Issuer      string            `json:"iss"`
	Subject     string            `json:"sub"`
	Audience    []string          `json:"aud"`
	JTI         string            `json:"jti"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// AccessRequest represents an authorization request
type AccessRequest struct {
	UserID      string                 `json:"user_id"`
	Username    string                 `json:"username"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Context     map[string]interface{} `json:"context"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// AccessDecision represents an authorization decision
type AccessDecision struct {
	Allowed        bool                   `json:"allowed"`
	Reason         string                 `json:"reason"`
	RequiredRoles  []string               `json:"required_roles,omitempty"`
	RequiredPerms  []string               `json:"required_permissions,omitempty"`
	MatchedRoles   []string               `json:"matched_roles,omitempty"`
	MatchedPerms   []string               `json:"matched_permissions,omitempty"`
	Conditions     []string               `json:"conditions,omitempty"`
	TTL            time.Duration          `json:"ttl,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	EvaluationTime time.Duration          `json:"evaluation_time"`
	RequestID      string                 `json:"request_id,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
}

// ExternalUser represents a user from an external identity provider
type ExternalUser struct {
	ID           string            `json:"id"`
	Username     string            `json:"username"`
	Email        string            `json:"email"`
	DisplayName  string            `json:"display_name"`
	FirstName    string            `json:"first_name,omitempty"`
	LastName     string            `json:"last_name,omitempty"`
	Groups       []string          `json:"groups,omitempty"`
	Roles        []string          `json:"roles,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	Provider     string            `json:"provider"`
	ProviderID   string            `json:"provider_id"`
	AccessToken  string            `json:"access_token,omitempty"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	ExpiresAt    *time.Time        `json:"expires_at,omitempty"`
}

// DeviceInfo represents device information
type DeviceInfo struct {
	Type        string `json:"type"`
	OS          string `json:"os"`
	Browser     string `json:"browser"`
	Version     string `json:"version"`
	Fingerprint string `json:"fingerprint"`
	IsTrusted   bool   `json:"is_trusted"`
}

// LocationInfo represents location information
type LocationInfo struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timezone  string  `json:"timezone"`
	ISP       string  `json:"isp"`
}

// RateLimit represents rate limiting configuration
type RateLimit struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	WindowSize        time.Duration `json:"window_size"`
}

// SessionMetadata represents session metadata
type SessionMetadata struct {
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	DeviceInfo   *DeviceInfo            `json:"device_info,omitempty"`
	LocationInfo *LocationInfo          `json:"location_info,omitempty"`
	Attributes   map[string]interface{} `json:"attributes,omitempty"`
}

// APIKeyInfo represents API key information for validation
type APIKeyInfo struct {
	KeyID       string    `json:"key_id"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	Permissions []string  `json:"permissions"`
	Scopes      []string  `json:"scopes"`
	ExpiresAt   time.Time `json:"expires_at"`
	IsActive    bool      `json:"is_active"`
}

// CertificateInfo represents certificate information
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Fingerprint  string    `json:"fingerprint"`
	UserID       string    `json:"user_id,omitempty"`
	Username     string    `json:"username,omitempty"`
	IsValid      bool      `json:"is_valid"`
}

// PasswordStrengthResult represents password strength validation result
type PasswordStrengthResult struct {
	Score       int      `json:"score"`       // 0-100
	IsStrong    bool     `json:"is_strong"`
	Issues      []string `json:"issues"`
	Suggestions []string `json:"suggestions"`
}

// Request/Response types

// CreateUserRequest represents a user creation request
type CreateUserRequest struct {
	Username         string            `json:"username"`
	Email            string            `json:"email"`
	DisplayName      string            `json:"display_name"`
	Password         string            `json:"password,omitempty"`
	Roles            []string          `json:"roles,omitempty"`
	Groups           []string          `json:"groups,omitempty"`
	ExternalID       string            `json:"external_id,omitempty"`
	IdentityProvider string            `json:"identity_provider,omitempty"`
	MFAEnabled       bool              `json:"mfa_enabled"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
}

// UpdateUserRequest represents a user update request
type UpdateUserRequest struct {
	Email       *string           `json:"email,omitempty"`
	DisplayName *string           `json:"display_name,omitempty"`
	Status      *UserStatus       `json:"status,omitempty"`
	Roles       []string          `json:"roles,omitempty"`
	Groups      []string          `json:"groups,omitempty"`
	MFAEnabled  *bool             `json:"mfa_enabled,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
}

// CreateRoleRequest represents a role creation request
type CreateRoleRequest struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Description string            `json:"description"`
	Permissions []string          `json:"permissions,omitempty"`
	ParentRoles []string          `json:"parent_roles,omitempty"`
	IsDefault   bool              `json:"is_default"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
}

// UpdateRoleRequest represents a role update request
type UpdateRoleRequest struct {
	DisplayName *string           `json:"display_name,omitempty"`
	Description *string           `json:"description,omitempty"`
	Permissions []string          `json:"permissions,omitempty"`
	ParentRoles []string          `json:"parent_roles,omitempty"`
	IsDefault   *bool             `json:"is_default,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
}

// CreatePermissionRequest represents a permission creation request
type CreatePermissionRequest struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Description string            `json:"description"`
	Resource    string            `json:"resource"`
	Action      string            `json:"action"`
	Effect      PermissionEffect  `json:"effect"`
	Conditions  []string          `json:"conditions,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
}

// UpdatePermissionRequest represents a permission update request
type UpdatePermissionRequest struct {
	DisplayName *string           `json:"display_name,omitempty"`
	Description *string           `json:"description,omitempty"`
	Resource    *string           `json:"resource,omitempty"`
	Action      *string           `json:"action,omitempty"`
	Effect      *PermissionEffect `json:"effect,omitempty"`
	Conditions  []string          `json:"conditions,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
}

// CreateAPIKeyRequest represents an API key creation request
type CreateAPIKeyRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Permissions []string          `json:"permissions,omitempty"`
	Scopes      []string          `json:"scopes,omitempty"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	RateLimit   *RateLimit        `json:"rate_limit,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Filter types

// UserFilter represents user filtering options
type UserFilter struct {
	IDs              []string    `json:"ids,omitempty"`
	Usernames        []string    `json:"usernames,omitempty"`
	Emails           []string    `json:"emails,omitempty"`
	Status           *UserStatus `json:"status,omitempty"`
	Roles            []string    `json:"roles,omitempty"`
	Groups           []string    `json:"groups,omitempty"`
	IdentityProvider *string     `json:"identity_provider,omitempty"`
	CreatedAfter     *time.Time  `json:"created_after,omitempty"`
	CreatedBefore    *time.Time  `json:"created_before,omitempty"`
	LastLoginAfter   *time.Time  `json:"last_login_after,omitempty"`
	LastLoginBefore  *time.Time  `json:"last_login_before,omitempty"`
	Tags             []string    `json:"tags,omitempty"`
	Limit            int         `json:"limit,omitempty"`
	Offset           int         `json:"offset,omitempty"`
	SortBy           string      `json:"sort_by,omitempty"`
	SortOrder        string      `json:"sort_order,omitempty"`
}

// RoleFilter represents role filtering options
type RoleFilter struct {
	IDs         []string   `json:"ids,omitempty"`
	Names       []string   `json:"names,omitempty"`
	IsSystem    *bool      `json:"is_system,omitempty"`
	IsDefault   *bool      `json:"is_default,omitempty"`
	Permissions []string   `json:"permissions,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	CreatedAfter *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`
	Limit       int        `json:"limit,omitempty"`
	Offset      int        `json:"offset,omitempty"`
	SortBy      string     `json:"sort_by,omitempty"`
	SortOrder   string     `json:"sort_order,omitempty"`
}

// PermissionFilter represents permission filtering options
type PermissionFilter struct {
	IDs           []string          `json:"ids,omitempty"`
	Names         []string          `json:"names,omitempty"`
	Resources     []string          `json:"resources,omitempty"`
	Actions       []string          `json:"actions,omitempty"`
	Effects       []PermissionEffect `json:"effects,omitempty"`
	IsSystem      *bool             `json:"is_system,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	CreatedAfter  *time.Time        `json:"created_after,omitempty"`
	CreatedBefore *time.Time        `json:"created_before,omitempty"`
	Limit         int               `json:"limit,omitempty"`
	Offset        int               `json:"offset,omitempty"`
	SortBy        string            `json:"sort_by,omitempty"`
	SortOrder     string            `json:"sort_order,omitempty"`
}

// Event types for audit logging

// AuthenticationEvent represents an authentication event
type AuthenticationEvent struct {
	EventID      string                 `json:"event_id"`
	EventType    AuthEventType          `json:"event_type"`
	UserID       string                 `json:"user_id,omitempty"`
	Username     string                 `json:"username,omitempty"`
	Method       AuthMethod             `json:"method"`
	Success      bool                   `json:"success"`
	FailureReason string                `json:"failure_reason,omitempty"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	SessionID    string                 `json:"session_id,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// AuthorizationEvent represents an authorization event
type AuthorizationEvent struct {
	EventID      string                 `json:"event_id"`
	EventType    AuthzEventType         `json:"event_type"`
	UserID       string                 `json:"user_id"`
	Username     string                 `json:"username"`
	Resource     string                 `json:"resource"`
	Action       string                 `json:"action"`
	Decision     bool                   `json:"decision"`
	Reason       string                 `json:"reason,omitempty"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	SessionID    string                 `json:"session_id,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// SessionEvent represents a session event
type SessionEvent struct {
	EventID   string                 `json:"event_id"`
	EventType SessionEventType       `json:"event_type"`
	SessionID string                 `json:"session_id"`
	UserID    string                 `json:"user_id"`
	Username  string                 `json:"username"`
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// UserEvent represents a user management event
type UserEvent struct {
	EventID      string                 `json:"event_id"`
	EventType    UserEventType          `json:"event_type"`
	UserID       string                 `json:"user_id"`
	Username     string                 `json:"username"`
	PerformedBy  string                 `json:"performed_by"`
	Changes      map[string]interface{} `json:"changes,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// RoleEvent represents a role management event
type RoleEvent struct {
	EventID     string                 `json:"event_id"`
	EventType   RoleEventType          `json:"event_type"`
	RoleID      string                 `json:"role_id"`
	RoleName    string                 `json:"role_name"`
	UserID      string                 `json:"user_id,omitempty"`
	PerformedBy string                 `json:"performed_by"`
	Changes     map[string]interface{} `json:"changes,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Enums and constants

// UserStatus represents user account status
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusLocked   UserStatus = "locked"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusPending  UserStatus = "pending"
)

// SessionStatus represents session status
type SessionStatus string

const (
	SessionStatusActive  SessionStatus = "active"
	SessionStatusExpired SessionStatus = "expired"
	SessionStatusRevoked SessionStatus = "revoked"
)

// APIKeyStatus represents API key status
type APIKeyStatus string

const (
	APIKeyStatusActive   APIKeyStatus = "active"
	APIKeyStatusInactive APIKeyStatus = "inactive"
	APIKeyStatusRevoked  APIKeyStatus = "revoked"
	APIKeyStatusExpired  APIKeyStatus = "expired"
)

// PermissionEffect represents permission effect
type PermissionEffect string

const (
	PermissionEffectAllow PermissionEffect = "allow"
	PermissionEffectDeny  PermissionEffect = "deny"
)

// ProviderType represents identity provider type
type ProviderType string

const (
	ProviderTypeLDAP  ProviderType = "ldap"
	ProviderTypeSAML  ProviderType = "saml"
	ProviderTypeOIDC  ProviderType = "oidc"
	ProviderTypeLocal ProviderType = "local"
)

// AuthMethod represents authentication method
type AuthMethod string

const (
	AuthMethodPassword    AuthMethod = "password"
	AuthMethodAPIKey      AuthMethod = "api_key"
	AuthMethodJWT         AuthMethod = "jwt"
	AuthMethodCertificate AuthMethod = "certificate"
	AuthMethodExternal    AuthMethod = "external"
)

// Event types

// AuthEventType represents authentication event types
type AuthEventType string

const (
	AuthEventLogin          AuthEventType = "login"
	AuthEventLogout         AuthEventType = "logout"
	AuthEventLoginFailed    AuthEventType = "login_failed"
	AuthEventPasswordChange AuthEventType = "password_change"
	AuthEventMFAEnabled     AuthEventType = "mfa_enabled"
	AuthEventMFADisabled    AuthEventType = "mfa_disabled"
	AuthEventAccountLocked  AuthEventType = "account_locked"
	AuthEventAccountUnlocked AuthEventType = "account_unlocked"
)

// AuthzEventType represents authorization event types
type AuthzEventType string

const (
	AuthzEventAccessGranted AuthzEventType = "access_granted"
	AuthzEventAccessDenied  AuthzEventType = "access_denied"
	AuthzEventRoleAssigned  AuthzEventType = "role_assigned"
	AuthzEventRoleRevoked   AuthzEventType = "role_revoked"
	AuthzEventPermissionGranted AuthzEventType = "permission_granted"
	AuthzEventPermissionRevoked AuthzEventType = "permission_revoked"
)

// SessionEventType represents session event types
type SessionEventType string

const (
	SessionEventCreated   SessionEventType = "created"
	SessionEventRefreshed SessionEventType = "refreshed"
	SessionEventExpired   SessionEventType = "expired"
	SessionEventRevoked   SessionEventType = "revoked"
	SessionEventActivity  SessionEventType = "activity"
)

// UserEventType represents user event types
type UserEventType string

const (
	UserEventCreated  UserEventType = "created"
	UserEventUpdated  UserEventType = "updated"
	UserEventDeleted  UserEventType = "deleted"
	UserEventEnabled  UserEventType = "enabled"
	UserEventDisabled UserEventType = "disabled"
	UserEventLocked   UserEventType = "locked"
	UserEventUnlocked UserEventType = "unlocked"
)

// RoleEventType represents role event types
type RoleEventType string

const (
	RoleEventCreated  RoleEventType = "created"
	RoleEventUpdated  RoleEventType = "updated"
	RoleEventDeleted  RoleEventType = "deleted"
	RoleEventAssigned RoleEventType = "assigned"
	RoleEventRevoked  RoleEventType = "revoked"
)

// JSON marshaling helpers

func (u *User) MarshalJSON() ([]byte, error) {
	type Alias User
	return json.Marshal(&struct {
		*Alias
		Roles       json.RawMessage `json:"roles"`
		Groups      json.RawMessage `json:"groups"`
		Permissions json.RawMessage `json:"permissions"`
		Metadata    json.RawMessage `json:"metadata"`
		Tags        json.RawMessage `json:"tags"`
	}{
		Alias:       (*Alias)(u),
		Roles:       mustMarshal(u.Roles),
		Groups:      mustMarshal(u.Groups),
		Permissions: mustMarshal(u.Permissions),
		Metadata:    mustMarshal(u.Metadata),
		Tags:        mustMarshal(u.Tags),
	})
}

func (u *User) UnmarshalJSON(data []byte) error {
	type Alias User
	aux := &struct {
		*Alias
		Roles       json.RawMessage `json:"roles"`
		Groups      json.RawMessage `json:"groups"`
		Permissions json.RawMessage `json:"permissions"`
		Metadata    json.RawMessage `json:"metadata"`
		Tags        json.RawMessage `json:"tags"`
	}{
		Alias: (*Alias)(u),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if len(aux.Roles) > 0 {
		if err := json.Unmarshal(aux.Roles, &u.Roles); err != nil {
			return err
		}
	}

	if len(aux.Groups) > 0 {
		if err := json.Unmarshal(aux.Groups, &u.Groups); err != nil {
			return err
		}
	}

	if len(aux.Permissions) > 0 {
		if err := json.Unmarshal(aux.Permissions, &u.Permissions); err != nil {
			return err
		}
	}

	if len(aux.Metadata) > 0 {
		if err := json.Unmarshal(aux.Metadata, &u.Metadata); err != nil {
			return err
		}
	}

	if len(aux.Tags) > 0 {
		if err := json.Unmarshal(aux.Tags, &u.Tags); err != nil {
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

func (us UserStatus) IsValid() bool {
	validStatuses := []UserStatus{
		UserStatusActive, UserStatusInactive, UserStatusLocked,
		UserStatusSuspended, UserStatusPending,
	}
	for _, status := range validStatuses {
		if us == status {
			return true
		}
	}
	return false
}

func (ss SessionStatus) IsValid() bool {
	validStatuses := []SessionStatus{
		SessionStatusActive, SessionStatusExpired, SessionStatusRevoked,
	}
	for _, status := range validStatuses {
		if ss == status {
			return true
		}
	}
	return false
}

func (aks APIKeyStatus) IsValid() bool {
	validStatuses := []APIKeyStatus{
		APIKeyStatusActive, APIKeyStatusInactive, APIKeyStatusRevoked, APIKeyStatusExpired,
	}
	for _, status := range validStatuses {
		if aks == status {
			return true
		}
	}
	return false
}

func (pe PermissionEffect) IsValid() bool {
	return pe == PermissionEffectAllow || pe == PermissionEffectDeny
}

func (pt ProviderType) IsValid() bool {
	validTypes := []ProviderType{
		ProviderTypeLDAP, ProviderTypeSAML, ProviderTypeOIDC, ProviderTypeLocal,
	}
	for _, t := range validTypes {
		if pt == t {
			return true
		}
	}
	return false
}

func (am AuthMethod) IsValid() bool {
	validMethods := []AuthMethod{
		AuthMethodPassword, AuthMethodAPIKey, AuthMethodJWT,
		AuthMethodCertificate, AuthMethodExternal,
	}
	for _, method := range validMethods {
		if am == method {
			return true
		}
	}
	return false
}