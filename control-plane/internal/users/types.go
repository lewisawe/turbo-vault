package users

import (
	"time"
)

// User represents a system user
type User struct {
	ID               string            `json:"id" db:"id"`
	Username         string            `json:"username" db:"username"`
	Email            string            `json:"email" db:"email"`
	PasswordHash     string            `json:"-" db:"password_hash"`
	FirstName        string            `json:"first_name" db:"first_name"`
	LastName         string            `json:"last_name" db:"last_name"`
	OrganizationID   string            `json:"organization_id" db:"organization_id"`
	Roles            []string          `json:"roles" db:"roles"`
	Permissions      []Permission      `json:"permissions" db:"permissions"`
	ExternalID       string            `json:"external_id,omitempty" db:"external_id"`
	IdentityProvider string            `json:"identity_provider,omitempty" db:"identity_provider"`
	Metadata         map[string]string `json:"metadata" db:"metadata"`
	CreatedAt        time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at" db:"updated_at"`
	LastLogin        *time.Time        `json:"last_login,omitempty" db:"last_login"`
	Status           UserStatus        `json:"status" db:"status"`
	MFAEnabled       bool              `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret        string            `json:"-" db:"mfa_secret"`
}

// Organization represents a multi-tenant organization
type Organization struct {
	ID          string            `json:"id" db:"id"`
	Name        string            `json:"name" db:"name"`
	DisplayName string            `json:"display_name" db:"display_name"`
	Domain      string            `json:"domain" db:"domain"`
	Settings    OrganizationSettings `json:"settings" db:"settings"`
	Metadata    map[string]string `json:"metadata" db:"metadata"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	Status      OrganizationStatus `json:"status" db:"status"`
	OwnerID     string            `json:"owner_id" db:"owner_id"`
}

// OrganizationSettings represents organization-specific settings
type OrganizationSettings struct {
	MaxVaults           int               `json:"max_vaults"`
	MaxUsers            int               `json:"max_users"`
	RetentionDays       int               `json:"retention_days"`
	AllowedDomains      []string          `json:"allowed_domains"`
	RequireMFA          bool              `json:"require_mfa"`
	PasswordPolicy      PasswordPolicy    `json:"password_policy"`
	SessionTimeout      int               `json:"session_timeout_minutes"`
	AuditLogRetention   int               `json:"audit_log_retention_days"`
	NotificationSettings NotificationSettings `json:"notification_settings"`
}

// PasswordPolicy represents password requirements
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSymbols   bool `json:"require_symbols"`
	MaxAge           int  `json:"max_age_days"`
	PreventReuse     int  `json:"prevent_reuse_count"`
}

// NotificationSettings represents notification preferences
type NotificationSettings struct {
	EmailEnabled    bool     `json:"email_enabled"`
	SlackEnabled    bool     `json:"slack_enabled"`
	WebhookEnabled  bool     `json:"webhook_enabled"`
	AlertChannels   []string `json:"alert_channels"`
	ReportChannels  []string `json:"report_channels"`
}

// Permission represents a user permission
type Permission struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
}

// Role represents a user role with associated permissions
type Role struct {
	ID          string       `json:"id" db:"id"`
	Name        string       `json:"name" db:"name"`
	Description string       `json:"description" db:"description"`
	Permissions []Permission `json:"permissions" db:"permissions"`
	IsSystem    bool         `json:"is_system" db:"is_system"`
	CreatedAt   time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at" db:"updated_at"`
}

// UserStatus represents the status of a user account
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusInactive  UserStatus = "inactive"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusPending   UserStatus = "pending"
)

// OrganizationStatus represents the status of an organization
type OrganizationStatus string

const (
	OrganizationStatusActive    OrganizationStatus = "active"
	OrganizationStatusInactive  OrganizationStatus = "inactive"
	OrganizationStatusSuspended OrganizationStatus = "suspended"
	OrganizationStatusTrial     OrganizationStatus = "trial"
)

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Username         string            `json:"username" validate:"required"`
	Email            string            `json:"email" validate:"required,email"`
	Password         string            `json:"password" validate:"required"`
	FirstName        string            `json:"first_name"`
	LastName         string            `json:"last_name"`
	OrganizationID   string            `json:"organization_id" validate:"required"`
	Roles            []string          `json:"roles"`
	IdentityProvider string            `json:"identity_provider"`
	ExternalID       string            `json:"external_id"`
	Metadata         map[string]string `json:"metadata"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Email       string            `json:"email,omitempty"`
	FirstName   string            `json:"first_name,omitempty"`
	LastName    string            `json:"last_name,omitempty"`
	Roles       []string          `json:"roles,omitempty"`
	Status      UserStatus        `json:"status,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	MFAEnabled  *bool             `json:"mfa_enabled,omitempty"`
}

// CreateOrganizationRequest represents a request to create a new organization
type CreateOrganizationRequest struct {
	Name        string            `json:"name" validate:"required"`
	DisplayName string            `json:"display_name"`
	Domain      string            `json:"domain"`
	OwnerEmail  string            `json:"owner_email" validate:"required,email"`
	Settings    OrganizationSettings `json:"settings"`
	Metadata    map[string]string `json:"metadata"`
}

// UpdateOrganizationRequest represents a request to update an organization
type UpdateOrganizationRequest struct {
	DisplayName string               `json:"display_name,omitempty"`
	Domain      string               `json:"domain,omitempty"`
	Settings    *OrganizationSettings `json:"settings,omitempty"`
	Status      OrganizationStatus   `json:"status,omitempty"`
	Metadata    map[string]string    `json:"metadata,omitempty"`
}

// UserFilter represents filtering options for user queries
type UserFilter struct {
	OrganizationID   string     `json:"organization_id"`
	Status           UserStatus `json:"status"`
	Role             string     `json:"role"`
	IdentityProvider string     `json:"identity_provider"`
	Search           string     `json:"search"`
	Limit            int        `json:"limit"`
	Offset           int        `json:"offset"`
}

// OrganizationFilter represents filtering options for organization queries
type OrganizationFilter struct {
	Status OrganizationStatus `json:"status"`
	Domain string             `json:"domain"`
	Search string             `json:"search"`
	Limit  int                `json:"limit"`
	Offset int                `json:"offset"`
}

// UserListResponse represents a paginated list of users
type UserListResponse struct {
	Users   []User `json:"users"`
	Total   int    `json:"total"`
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
	HasMore bool   `json:"has_more"`
}

// OrganizationListResponse represents a paginated list of organizations
type OrganizationListResponse struct {
	Organizations []Organization `json:"organizations"`
	Total         int            `json:"total"`
	Limit         int            `json:"limit"`
	Offset        int            `json:"offset"`
	HasMore       bool           `json:"has_more"`
}

// Session represents a user session
type Session struct {
	ID             string    `json:"id" db:"id"`
	UserID         string    `json:"user_id" db:"user_id"`
	OrganizationID string    `json:"organization_id" db:"organization_id"`
	Token          string    `json:"-" db:"token"`
	ExpiresAt      time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	LastAccessedAt time.Time `json:"last_accessed_at" db:"last_accessed_at"`
	IPAddress      string    `json:"ip_address" db:"ip_address"`
	UserAgent      string    `json:"user_agent" db:"user_agent"`
	Active         bool      `json:"active" db:"active"`
}

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID             string            `json:"id" db:"id"`
	UserID         string            `json:"user_id" db:"user_id"`
	OrganizationID string            `json:"organization_id" db:"organization_id"`
	Name           string            `json:"name" db:"name"`
	KeyHash        string            `json:"-" db:"key_hash"`
	Permissions    []Permission      `json:"permissions" db:"permissions"`
	Metadata       map[string]string `json:"metadata" db:"metadata"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt      time.Time         `json:"created_at" db:"created_at"`
	LastUsedAt     *time.Time        `json:"last_used_at,omitempty" db:"last_used_at"`
	Status         string            `json:"status" db:"status"`
}

// CreateAPIKeyRequest represents a request to create an API key
type CreateAPIKeyRequest struct {
	Name        string            `json:"name" validate:"required"`
	Permissions []Permission      `json:"permissions"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	Metadata    map[string]string `json:"metadata"`
}

// OrganizationMember represents a user's membership in an organization
type OrganizationMember struct {
	UserID         string    `json:"user_id"`
	OrganizationID string    `json:"organization_id"`
	Role           string    `json:"role"`
	JoinedAt       time.Time `json:"joined_at"`
	InvitedBy      string    `json:"invited_by"`
	Status         string    `json:"status"`
}