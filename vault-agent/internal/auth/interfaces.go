package auth

import (
	"context"
	"crypto/x509"
	"net/http"

	"google.golang.org/grpc"
)

// AuthenticationManager defines the interface for authentication operations
type AuthenticationManager interface {
	// Authentication methods
	AuthenticateAPIKey(ctx context.Context, apiKey string) (*User, error)
	AuthenticateJWT(ctx context.Context, token string) (*User, error)
	AuthenticateCertificate(ctx context.Context, cert *x509.Certificate) (*User, error)
	AuthenticateCredentials(ctx context.Context, username, password string) (*User, error)
	
	// Session management
	CreateSession(ctx context.Context, user *User) (*Session, error)
	ValidateSession(ctx context.Context, sessionID string) (*Session, error)
	RefreshSession(ctx context.Context, sessionID string) (*Session, error)
	RevokeSession(ctx context.Context, sessionID string) error
	RevokeAllUserSessions(ctx context.Context, userID string) error
	
	// API Key management
	CreateAPIKey(ctx context.Context, userID string, request *CreateAPIKeyRequest) (*APIKey, error)
	RevokeAPIKey(ctx context.Context, keyID string) error
	ListAPIKeys(ctx context.Context, userID string) ([]*APIKey, error)
	
	// JWT management
	GenerateJWT(ctx context.Context, user *User) (*JWTToken, error)
	ValidateJWT(ctx context.Context, token string) (*JWTClaims, error)
	RefreshJWT(ctx context.Context, refreshToken string) (*JWTToken, error)
}

// AuthorizationManager defines the interface for authorization operations
type AuthorizationManager interface {
	// Permission checks
	HasPermission(ctx context.Context, user *User, resource, action string) (bool, error)
	CheckAccess(ctx context.Context, user *User, request *AccessRequest) (*AccessDecision, error)
	
	// Role management
	AssignRole(ctx context.Context, userID, roleID string) error
	RevokeRole(ctx context.Context, userID, roleID string) error
	GetUserRoles(ctx context.Context, userID string) ([]*Role, error)
	
	// Permission management
	GrantPermission(ctx context.Context, roleID string, permission *Permission) error
	RevokePermission(ctx context.Context, roleID string, permissionID string) error
	GetRolePermissions(ctx context.Context, roleID string) ([]*Permission, error)
}

// UserManager defines the interface for user management operations
type UserManager interface {
	// User CRUD operations
	CreateUser(ctx context.Context, request *CreateUserRequest) (*User, error)
	GetUser(ctx context.Context, userID string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, userID string, request *UpdateUserRequest) (*User, error)
	DeleteUser(ctx context.Context, userID string) error
	ListUsers(ctx context.Context, filter *UserFilter) ([]*User, error)
	
	// Password management
	SetPassword(ctx context.Context, userID, password string) error
	ValidatePassword(ctx context.Context, userID, password string) (bool, error)
	ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error
	ResetPassword(ctx context.Context, userID string) (string, error)
	
	// User status management
	EnableUser(ctx context.Context, userID string) error
	DisableUser(ctx context.Context, userID string) error
	LockUser(ctx context.Context, userID string, reason string) error
	UnlockUser(ctx context.Context, userID string) error
}

// RoleManager defines the interface for role management operations
type RoleManager interface {
	// Role CRUD operations
	CreateRole(ctx context.Context, request *CreateRoleRequest) (*Role, error)
	GetRole(ctx context.Context, roleID string) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	UpdateRole(ctx context.Context, roleID string, request *UpdateRoleRequest) (*Role, error)
	DeleteRole(ctx context.Context, roleID string) error
	ListRoles(ctx context.Context, filter *RoleFilter) ([]*Role, error)
	
	// Role hierarchy
	AddChildRole(ctx context.Context, parentRoleID, childRoleID string) error
	RemoveChildRole(ctx context.Context, parentRoleID, childRoleID string) error
	GetRoleHierarchy(ctx context.Context, roleID string) ([]*Role, error)
}

// PermissionManager defines the interface for permission management operations
type PermissionManager interface {
	// Permission CRUD operations
	CreatePermission(ctx context.Context, request *CreatePermissionRequest) (*Permission, error)
	GetPermission(ctx context.Context, permissionID string) (*Permission, error)
	UpdatePermission(ctx context.Context, permissionID string, request *UpdatePermissionRequest) (*Permission, error)
	DeletePermission(ctx context.Context, permissionID string) error
	ListPermissions(ctx context.Context, filter *PermissionFilter) ([]*Permission, error)
	
	// Permission evaluation
	EvaluatePermission(ctx context.Context, permission *Permission, resource, action string) (bool, error)
}

// SessionManager defines the interface for session management operations
type SessionManager interface {
	// Session lifecycle
	CreateSession(ctx context.Context, user *User, metadata *SessionMetadata) (*Session, error)
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	UpdateSession(ctx context.Context, sessionID string, metadata *SessionMetadata) (*Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
	
	// Session validation
	ValidateSession(ctx context.Context, sessionID string) (*Session, error)
	RefreshSession(ctx context.Context, sessionID string) (*Session, error)
	
	// Session management
	GetUserSessions(ctx context.Context, userID string) ([]*Session, error)
	RevokeUserSessions(ctx context.Context, userID string) error
	CleanupExpiredSessions(ctx context.Context) error
	
	// Concurrent session limits
	CheckConcurrentSessions(ctx context.Context, userID string) (bool, error)
	GetActiveSessions(ctx context.Context, userID string) ([]*Session, error)
}

// IdentityProvider defines the interface for external identity providers
type IdentityProvider interface {
	// Provider information
	GetProviderType() ProviderType
	GetProviderName() string
	
	// Authentication
	Authenticate(ctx context.Context, credentials interface{}) (*ExternalUser, error)
	ValidateToken(ctx context.Context, token string) (*ExternalUser, error)
	
	// User information
	GetUserInfo(ctx context.Context, userID string) (*ExternalUser, error)
	GetUserGroups(ctx context.Context, userID string) ([]string, error)
	
	// Configuration
	Configure(ctx context.Context, config map[string]interface{}) error
	IsConfigured() bool
}

// Middleware defines the interface for authentication middleware
type Middleware interface {
	// HTTP middleware
	AuthenticateHTTP(next http.Handler) http.Handler
	RequireAuthentication(next http.Handler) http.Handler
	RequirePermission(resource, action string) func(http.Handler) http.Handler
	RequireRole(roleNames ...string) func(http.Handler) http.Handler
	
	// gRPC middleware
	AuthenticateGRPC(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)
	
	// Context helpers
	GetUserFromContext(ctx context.Context) (*User, bool)
	GetSessionFromContext(ctx context.Context) (*Session, bool)
	SetUserInContext(ctx context.Context, user *User) context.Context
	SetSessionInContext(ctx context.Context, session *Session) context.Context
}

// TokenValidator defines the interface for token validation
type TokenValidator interface {
	ValidateAPIKey(ctx context.Context, apiKey string) (*APIKeyInfo, error)
	ValidateJWT(ctx context.Context, token string) (*JWTClaims, error)
	ValidateCertificate(ctx context.Context, cert *x509.Certificate) (*CertificateInfo, error)
}

// PasswordManager defines the interface for password operations
type PasswordManager interface {
	HashPassword(password string) (string, error)
	ValidatePassword(hashedPassword, password string) (bool, error)
	GenerateRandomPassword(length int) (string, error)
	ValidatePasswordStrength(password string) (*PasswordStrengthResult, error)
}

// AuditLogger defines the interface for authentication audit logging
type AuditLogger interface {
	LogAuthentication(ctx context.Context, event *AuthenticationEvent) error
	LogAuthorization(ctx context.Context, event *AuthorizationEvent) error
	LogSessionEvent(ctx context.Context, event *SessionEvent) error
	LogUserEvent(ctx context.Context, event *UserEvent) error
	LogRoleEvent(ctx context.Context, event *RoleEvent) error
}

// Storage interfaces for persistence

// UserStorage defines the interface for user data persistence
type UserStorage interface {
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, userID string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, userID string) error
	ListUsers(ctx context.Context, filter *UserFilter) ([]*User, error)
}

// RoleStorage defines the interface for role data persistence
type RoleStorage interface {
	CreateRole(ctx context.Context, role *Role) error
	GetRole(ctx context.Context, roleID string) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, roleID string) error
	ListRoles(ctx context.Context, filter *RoleFilter) ([]*Role, error)
}

// PermissionStorage defines the interface for permission data persistence
type PermissionStorage interface {
	CreatePermission(ctx context.Context, permission *Permission) error
	GetPermission(ctx context.Context, permissionID string) (*Permission, error)
	UpdatePermission(ctx context.Context, permission *Permission) error
	DeletePermission(ctx context.Context, permissionID string) error
	ListPermissions(ctx context.Context, filter *PermissionFilter) ([]*Permission, error)
}

// SessionStorage defines the interface for session data persistence
type SessionStorage interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	UpdateSession(ctx context.Context, session *Session) error
	DeleteSession(ctx context.Context, sessionID string) error
	GetUserSessions(ctx context.Context, userID string) ([]*Session, error)
	DeleteUserSessions(ctx context.Context, userID string) error
	DeleteExpiredSessions(ctx context.Context) error
}

// APIKeyStorage defines the interface for API key data persistence
type APIKeyStorage interface {
	CreateAPIKey(ctx context.Context, apiKey *APIKey) error
	GetAPIKey(ctx context.Context, keyID string) (*APIKey, error)
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
	UpdateAPIKey(ctx context.Context, apiKey *APIKey) error
	DeleteAPIKey(ctx context.Context, keyID string) error
	ListAPIKeys(ctx context.Context, userID string) ([]*APIKey, error)
}