package users

import (
	"context"
)

// UserService defines the interface for user management operations
type UserService interface {
	// CreateUser creates a new user
	CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error)
	
	// GetUser retrieves a user by ID
	GetUser(ctx context.Context, userID string) (*User, error)
	
	// GetUserByUsername retrieves a user by username
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	
	// GetUserByEmail retrieves a user by email
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	
	// UpdateUser updates an existing user
	UpdateUser(ctx context.Context, userID string, req *UpdateUserRequest) (*User, error)
	
	// DeleteUser deletes a user
	DeleteUser(ctx context.Context, userID string) error
	
	// ListUsers lists users with filtering and pagination
	ListUsers(ctx context.Context, filter *UserFilter) (*UserListResponse, error)
	
	// ChangePassword changes a user's password
	ChangePassword(ctx context.Context, userID string, oldPassword, newPassword string) error
	
	// ResetPassword resets a user's password
	ResetPassword(ctx context.Context, userID string, newPassword string) error
	
	// EnableMFA enables multi-factor authentication for a user
	EnableMFA(ctx context.Context, userID string) (string, error)
	
	// DisableMFA disables multi-factor authentication for a user
	DisableMFA(ctx context.Context, userID string) error
	
	// VerifyMFA verifies a multi-factor authentication token
	VerifyMFA(ctx context.Context, userID string, token string) (bool, error)
	
	// CreateAPIKey creates an API key for a user
	CreateAPIKey(ctx context.Context, userID string, req *CreateAPIKeyRequest) (*APIKey, string, error)
	
	// ListAPIKeys lists API keys for a user
	ListAPIKeys(ctx context.Context, userID string) ([]APIKey, error)
	
	// RevokeAPIKey revokes an API key
	RevokeAPIKey(ctx context.Context, keyID string) error
	
	// AuthenticateUser authenticates a user with username/password
	AuthenticateUser(ctx context.Context, username, password string) (*User, error)
	
	// AuthenticateAPIKey authenticates using an API key
	AuthenticateAPIKey(ctx context.Context, keyHash string) (*User, *APIKey, error)
}

// OrganizationService defines the interface for organization management operations
type OrganizationService interface {
	// CreateOrganization creates a new organization
	CreateOrganization(ctx context.Context, req *CreateOrganizationRequest) (*Organization, error)
	
	// GetOrganization retrieves an organization by ID
	GetOrganization(ctx context.Context, orgID string) (*Organization, error)
	
	// GetOrganizationByDomain retrieves an organization by domain
	GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error)
	
	// UpdateOrganization updates an existing organization
	UpdateOrganization(ctx context.Context, orgID string, req *UpdateOrganizationRequest) (*Organization, error)
	
	// DeleteOrganization deletes an organization
	DeleteOrganization(ctx context.Context, orgID string) error
	
	// ListOrganizations lists organizations with filtering and pagination
	ListOrganizations(ctx context.Context, filter *OrganizationFilter) (*OrganizationListResponse, error)
	
	// AddUserToOrganization adds a user to an organization
	AddUserToOrganization(ctx context.Context, orgID, userID, role string) error
	
	// RemoveUserFromOrganization removes a user from an organization
	RemoveUserFromOrganization(ctx context.Context, orgID, userID string) error
	
	// GetOrganizationMembers retrieves all members of an organization
	GetOrganizationMembers(ctx context.Context, orgID string) ([]OrganizationMember, error)
	
	// UpdateUserRole updates a user's role in an organization
	UpdateUserRole(ctx context.Context, orgID, userID, role string) error
	
	// GetUserOrganizations retrieves all organizations a user belongs to
	GetUserOrganizations(ctx context.Context, userID string) ([]Organization, error)
}

// SessionService defines the interface for session management operations
type SessionService interface {
	// CreateSession creates a new user session
	CreateSession(ctx context.Context, userID string, ipAddress, userAgent string) (*Session, string, error)
	
	// GetSession retrieves a session by token
	GetSession(ctx context.Context, token string) (*Session, error)
	
	// ValidateSession validates a session token
	ValidateSession(ctx context.Context, token string) (*User, error)
	
	// RefreshSession refreshes a session token
	RefreshSession(ctx context.Context, token string) (*Session, string, error)
	
	// RevokeSession revokes a session
	RevokeSession(ctx context.Context, token string) error
	
	// RevokeAllUserSessions revokes all sessions for a user
	RevokeAllUserSessions(ctx context.Context, userID string) error
	
	// ListUserSessions lists active sessions for a user
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
	
	// CleanupExpiredSessions removes expired sessions
	CleanupExpiredSessions(ctx context.Context) error
}

// RoleService defines the interface for role management operations
type RoleService interface {
	// CreateRole creates a new role
	CreateRole(ctx context.Context, role *Role) error
	
	// GetRole retrieves a role by ID
	GetRole(ctx context.Context, roleID string) (*Role, error)
	
	// UpdateRole updates an existing role
	UpdateRole(ctx context.Context, roleID string, role *Role) error
	
	// DeleteRole deletes a role
	DeleteRole(ctx context.Context, roleID string) error
	
	// ListRoles lists all roles
	ListRoles(ctx context.Context) ([]Role, error)
	
	// AssignRoleToUser assigns a role to a user
	AssignRoleToUser(ctx context.Context, userID, roleID string) error
	
	// RemoveRoleFromUser removes a role from a user
	RemoveRoleFromUser(ctx context.Context, userID, roleID string) error
	
	// GetUserRoles retrieves all roles for a user
	GetUserRoles(ctx context.Context, userID string) ([]Role, error)
}

// UserStorage defines the interface for user storage operations
type UserStorage interface {
	// CreateUser creates a new user record
	CreateUser(ctx context.Context, user *User) error
	
	// GetUser retrieves a user by ID
	GetUser(ctx context.Context, userID string) (*User, error)
	
	// GetUserByUsername retrieves a user by username
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	
	// GetUserByEmail retrieves a user by email
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	
	// UpdateUser updates an existing user record
	UpdateUser(ctx context.Context, userID string, user *User) error
	
	// DeleteUser deletes a user record
	DeleteUser(ctx context.Context, userID string) error
	
	// ListUsers lists users with filtering and pagination
	ListUsers(ctx context.Context, filter *UserFilter) ([]User, int, error)
	
	// UpdateLastLogin updates the last login timestamp for a user
	UpdateLastLogin(ctx context.Context, userID string) error
}

// OrganizationStorage defines the interface for organization storage operations
type OrganizationStorage interface {
	// CreateOrganization creates a new organization record
	CreateOrganization(ctx context.Context, org *Organization) error
	
	// GetOrganization retrieves an organization by ID
	GetOrganization(ctx context.Context, orgID string) (*Organization, error)
	
	// GetOrganizationByDomain retrieves an organization by domain
	GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error)
	
	// UpdateOrganization updates an existing organization record
	UpdateOrganization(ctx context.Context, orgID string, org *Organization) error
	
	// DeleteOrganization deletes an organization record
	DeleteOrganization(ctx context.Context, orgID string) error
	
	// ListOrganizations lists organizations with filtering and pagination
	ListOrganizations(ctx context.Context, filter *OrganizationFilter) ([]Organization, int, error)
	
	// AddUserToOrganization adds a user to an organization
	AddUserToOrganization(ctx context.Context, orgID, userID, role string) error
	
	// RemoveUserFromOrganization removes a user from an organization
	RemoveUserFromOrganization(ctx context.Context, orgID, userID string) error
	
	// GetOrganizationMembers retrieves organization members
	GetOrganizationMembers(ctx context.Context, orgID string) ([]OrganizationMember, error)
	
	// UpdateUserRole updates a user's role in an organization
	UpdateUserRole(ctx context.Context, orgID, userID, role string) error
	
	// GetUserOrganizations retrieves organizations for a user
	GetUserOrganizations(ctx context.Context, userID string) ([]Organization, error)
}

// SessionStorage defines the interface for session storage operations
type SessionStorage interface {
	// CreateSession creates a new session record
	CreateSession(ctx context.Context, session *Session) error
	
	// GetSession retrieves a session by token
	GetSession(ctx context.Context, token string) (*Session, error)
	
	// UpdateSession updates an existing session record
	UpdateSession(ctx context.Context, token string, session *Session) error
	
	// DeleteSession deletes a session record
	DeleteSession(ctx context.Context, token string) error
	
	// ListUserSessions lists sessions for a user
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
	
	// DeleteUserSessions deletes all sessions for a user
	DeleteUserSessions(ctx context.Context, userID string) error
	
	// DeleteExpiredSessions deletes expired sessions
	DeleteExpiredSessions(ctx context.Context) error
}

// APIKeyStorage defines the interface for API key storage operations
type APIKeyStorage interface {
	// CreateAPIKey creates a new API key record
	CreateAPIKey(ctx context.Context, apiKey *APIKey) error
	
	// GetAPIKey retrieves an API key by ID
	GetAPIKey(ctx context.Context, keyID string) (*APIKey, error)
	
	// GetAPIKeyByHash retrieves an API key by hash
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
	
	// UpdateAPIKey updates an existing API key record
	UpdateAPIKey(ctx context.Context, keyID string, apiKey *APIKey) error
	
	// DeleteAPIKey deletes an API key record
	DeleteAPIKey(ctx context.Context, keyID string) error
	
	// ListUserAPIKeys lists API keys for a user
	ListUserAPIKeys(ctx context.Context, userID string) ([]APIKey, error)
	
	// UpdateLastUsed updates the last used timestamp for an API key
	UpdateLastUsed(ctx context.Context, keyID string) error
}

// RoleStorage defines the interface for role storage operations
type RoleStorage interface {
	// CreateRole creates a new role record
	CreateRole(ctx context.Context, role *Role) error
	
	// GetRole retrieves a role by ID
	GetRole(ctx context.Context, roleID string) (*Role, error)
	
	// UpdateRole updates an existing role record
	UpdateRole(ctx context.Context, roleID string, role *Role) error
	
	// DeleteRole deletes a role record
	DeleteRole(ctx context.Context, roleID string) error
	
	// ListRoles lists all roles
	ListRoles(ctx context.Context) ([]Role, error)
	
	// GetUserRoles retrieves roles for a user
	GetUserRoles(ctx context.Context, userID string) ([]Role, error)
}