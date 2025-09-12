package users

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"github.com/pquerna/otp/totp"
)

// UserServiceImpl implements the UserService interface
type UserServiceImpl struct {
	userStorage    UserStorage
	sessionStorage SessionStorage
	apiKeyStorage  APIKeyStorage
	roleStorage    RoleStorage
}

// NewUserService creates a new user service
func NewUserService(
	userStorage UserStorage,
	sessionStorage SessionStorage,
	apiKeyStorage APIKeyStorage,
	roleStorage RoleStorage,
) *UserServiceImpl {
	return &UserServiceImpl{
		userStorage:    userStorage,
		sessionStorage: sessionStorage,
		apiKeyStorage:  apiKeyStorage,
		roleStorage:    roleStorage,
	}
}

// CreateUser creates a new user
func (s *UserServiceImpl) CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error) {
	// Check if user already exists
	if existingUser, _ := s.userStorage.GetUserByUsername(ctx, req.Username); existingUser != nil {
		return nil, fmt.Errorf("user with username %s already exists", req.Username)
	}
	
	if existingUser, _ := s.userStorage.GetUserByEmail(ctx, req.Email); existingUser != nil {
		return nil, fmt.Errorf("user with email %s already exists", req.Email)
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &User{
		ID:               uuid.New().String(),
		Username:         req.Username,
		Email:            req.Email,
		PasswordHash:     string(passwordHash),
		FirstName:        req.FirstName,
		LastName:         req.LastName,
		OrganizationID:   req.OrganizationID,
		Roles:            req.Roles,
		ExternalID:       req.ExternalID,
		IdentityProvider: req.IdentityProvider,
		Metadata:         req.Metadata,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		Status:           UserStatusActive,
		MFAEnabled:       false,
	}

	if err := s.userStorage.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Don't return password hash
	user.PasswordHash = ""
	return user, nil
}

// GetUser retrieves a user by ID
func (s *UserServiceImpl) GetUser(ctx context.Context, userID string) (*User, error) {
	user, err := s.userStorage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	
	// Don't return password hash
	user.PasswordHash = ""
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (s *UserServiceImpl) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user, err := s.userStorage.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	
	// Don't return password hash
	user.PasswordHash = ""
	return user, nil
}

// GetUserByEmail retrieves a user by email
func (s *UserServiceImpl) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user, err := s.userStorage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	
	// Don't return password hash
	user.PasswordHash = ""
	return user, nil
}

// UpdateUser updates an existing user
func (s *UserServiceImpl) UpdateUser(ctx context.Context, userID string, req *UpdateUserRequest) (*User, error) {
	user, err := s.userStorage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Update fields
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.Roles != nil {
		user.Roles = req.Roles
	}
	if req.Status != "" {
		user.Status = req.Status
	}
	if req.Metadata != nil {
		user.Metadata = req.Metadata
	}
	if req.MFAEnabled != nil {
		user.MFAEnabled = *req.MFAEnabled
	}
	
	user.UpdatedAt = time.Now()

	if err := s.userStorage.UpdateUser(ctx, userID, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Don't return password hash
	user.PasswordHash = ""
	return user, nil
}

// DeleteUser deletes a user
func (s *UserServiceImpl) DeleteUser(ctx context.Context, userID string) error {
	// Revoke all sessions
	if err := s.sessionStorage.DeleteUserSessions(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke user sessions: %w", err)
	}

	// Delete user
	if err := s.userStorage.DeleteUser(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// ListUsers lists users with filtering and pagination
func (s *UserServiceImpl) ListUsers(ctx context.Context, filter *UserFilter) (*UserListResponse, error) {
	if filter == nil {
		filter = &UserFilter{}
	}
	
	// Set default pagination
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}

	users, total, err := s.userStorage.ListUsers(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Remove password hashes
	for i := range users {
		users[i].PasswordHash = ""
	}

	return &UserListResponse{
		Users:   users,
		Total:   total,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
		HasMore: filter.Offset+len(users) < total,
	}, nil
}

// ChangePassword changes a user's password
func (s *UserServiceImpl) ChangePassword(ctx context.Context, userID string, oldPassword, newPassword string) error {
	user, err := s.userStorage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return fmt.Errorf("invalid old password")
	}

	// Hash new password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = string(passwordHash)
	user.UpdatedAt = time.Now()

	return s.userStorage.UpdateUser(ctx, userID, user)
}

// ResetPassword resets a user's password
func (s *UserServiceImpl) ResetPassword(ctx context.Context, userID string, newPassword string) error {
	user, err := s.userStorage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Hash new password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = string(passwordHash)
	user.UpdatedAt = time.Now()

	// Revoke all existing sessions
	s.sessionStorage.DeleteUserSessions(ctx, userID)

	return s.userStorage.UpdateUser(ctx, userID, user)
}

// EnableMFA enables multi-factor authentication for a user
func (s *UserServiceImpl) EnableMFA(ctx context.Context, userID string) (string, error) {
	user, err := s.userStorage.GetUser(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("user not found: %w", err)
	}

	// Generate MFA secret
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("failed to generate MFA secret: %w", err)
	}

	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	user.MFAEnabled = true
	user.MFASecret = secretBase32
	user.UpdatedAt = time.Now()

	if err := s.userStorage.UpdateUser(ctx, userID, user); err != nil {
		return "", fmt.Errorf("failed to update user: %w", err)
	}

	return secretBase32, nil
}

// DisableMFA disables multi-factor authentication for a user
func (s *UserServiceImpl) DisableMFA(ctx context.Context, userID string) error {
	user, err := s.userStorage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.MFAEnabled = false
	user.MFASecret = ""
	user.UpdatedAt = time.Now()

	return s.userStorage.UpdateUser(ctx, userID, user)
}

// VerifyMFA verifies a multi-factor authentication token
func (s *UserServiceImpl) VerifyMFA(ctx context.Context, userID string, token string) (bool, error) {
	user, err := s.userStorage.GetUser(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("user not found: %w", err)
	}

	if !user.MFAEnabled || user.MFASecret == "" {
		return false, fmt.Errorf("MFA not enabled for user")
	}

	return totp.Validate(token, user.MFASecret), nil
}

// CreateAPIKey creates an API key for a user
func (s *UserServiceImpl) CreateAPIKey(ctx context.Context, userID string, req *CreateAPIKeyRequest) (*APIKey, string, error) {
	user, err := s.userStorage.GetUser(ctx, userID)
	if err != nil {
		return nil, "", fmt.Errorf("user not found: %w", err)
	}

	// Generate API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate API key: %w", err)
	}

	keyString := base32.StdEncoding.EncodeToString(keyBytes)
	keyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(keyString)))

	apiKey := &APIKey{
		ID:             uuid.New().String(),
		UserID:         userID,
		OrganizationID: user.OrganizationID,
		Name:           req.Name,
		KeyHash:        keyHash,
		Permissions:    req.Permissions,
		Metadata:       req.Metadata,
		ExpiresAt:      req.ExpiresAt,
		CreatedAt:      time.Now(),
		Status:         "active",
	}

	if err := s.apiKeyStorage.CreateAPIKey(ctx, apiKey); err != nil {
		return nil, "", fmt.Errorf("failed to create API key: %w", err)
	}

	return apiKey, keyString, nil
}

// ListAPIKeys lists API keys for a user
func (s *UserServiceImpl) ListAPIKeys(ctx context.Context, userID string) ([]APIKey, error) {
	return s.apiKeyStorage.ListUserAPIKeys(ctx, userID)
}

// RevokeAPIKey revokes an API key
func (s *UserServiceImpl) RevokeAPIKey(ctx context.Context, keyID string) error {
	return s.apiKeyStorage.DeleteAPIKey(ctx, keyID)
}

// AuthenticateUser authenticates a user with username/password
func (s *UserServiceImpl) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	user, err := s.userStorage.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if user.Status != UserStatusActive {
		return nil, fmt.Errorf("user account is not active")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login
	s.userStorage.UpdateLastLogin(ctx, user.ID)

	// Don't return password hash
	user.PasswordHash = ""
	return user, nil
}

// AuthenticateAPIKey authenticates using an API key
func (s *UserServiceImpl) AuthenticateAPIKey(ctx context.Context, keyString string) (*User, *APIKey, error) {
	keyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(keyString)))
	
	apiKey, err := s.apiKeyStorage.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid API key")
	}

	if apiKey.Status != "active" {
		return nil, nil, fmt.Errorf("API key is not active")
	}

	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, nil, fmt.Errorf("API key has expired")
	}

	user, err := s.userStorage.GetUser(ctx, apiKey.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found")
	}

	if user.Status != UserStatusActive {
		return nil, nil, fmt.Errorf("user account is not active")
	}

	// Update last used
	s.apiKeyStorage.UpdateLastUsed(ctx, apiKey.ID)

	// Don't return password hash
	user.PasswordHash = ""
	return user, apiKey, nil
}
