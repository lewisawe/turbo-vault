package auth

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// Mock implementations for testing

type mockUserManager struct {
	users map[string]*User
}

func newMockUserManager() *mockUserManager {
	return &mockUserManager{
		users: make(map[string]*User),
	}
}

func (m *mockUserManager) CreateUser(ctx context.Context, request *CreateUserRequest) (*User, error) {
	user := &User{
		ID:          "user-" + request.Username,
		Username:    request.Username,
		Email:       request.Email,
		DisplayName: request.DisplayName,
		Status:      UserStatusActive,
		Roles:       request.Roles,
		Groups:      request.Groups,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	m.users[user.ID] = user
	return user, nil
}

func (m *mockUserManager) GetUser(ctx context.Context, userID string) (*User, error) {
	if user, exists := m.users[userID]; exists {
		return user, nil
	}
	return nil, fmt.Errorf("user not found")
}

func (m *mockUserManager) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	for _, user := range m.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (m *mockUserManager) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (m *mockUserManager) UpdateUser(ctx context.Context, userID string, request *UpdateUserRequest) (*User, error) {
	user, exists := m.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	
	if request.Email != nil {
		user.Email = *request.Email
	}
	if request.DisplayName != nil {
		user.DisplayName = *request.DisplayName
	}
	if request.Status != nil {
		user.Status = *request.Status
	}
	
	user.UpdatedAt = time.Now()
	return user, nil
}

func (m *mockUserManager) DeleteUser(ctx context.Context, userID string) error {
	delete(m.users, userID)
	return nil
}

func (m *mockUserManager) ListUsers(ctx context.Context, filter *UserFilter) ([]*User, error) {
	var users []*User
	for _, user := range m.users {
		users = append(users, user)
	}
	return users, nil
}

func (m *mockUserManager) SetPassword(ctx context.Context, userID, password string) error {
	return nil
}

func (m *mockUserManager) ValidatePassword(ctx context.Context, userID, password string) (bool, error) {
	// Simple mock - accept "password123" for any user
	return password == "password123", nil
}

func (m *mockUserManager) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	return nil
}

func (m *mockUserManager) ResetPassword(ctx context.Context, userID string) (string, error) {
	return "newpassword123", nil
}

func (m *mockUserManager) EnableUser(ctx context.Context, userID string) error {
	if user, exists := m.users[userID]; exists {
		user.Status = UserStatusActive
	}
	return nil
}

func (m *mockUserManager) DisableUser(ctx context.Context, userID string) error {
	if user, exists := m.users[userID]; exists {
		user.Status = UserStatusInactive
	}
	return nil
}

func (m *mockUserManager) LockUser(ctx context.Context, userID string, reason string) error {
	if user, exists := m.users[userID]; exists {
		user.Status = UserStatusLocked
		lockUntil := time.Now().Add(15 * time.Minute)
		user.LockedUntil = &lockUntil
	}
	return nil
}

func (m *mockUserManager) UnlockUser(ctx context.Context, userID string) error {
	if user, exists := m.users[userID]; exists {
		user.Status = UserStatusActive
		user.LockedUntil = nil
	}
	return nil
}

type mockSessionManager struct {
	sessions map[string]*Session
}

func newMockSessionManager() *mockSessionManager {
	return &mockSessionManager{
		sessions: make(map[string]*Session),
	}
}

func (m *mockSessionManager) CreateSession(ctx context.Context, user *User, metadata *SessionMetadata) (*Session, error) {
	session := &Session{
		ID:           "session-" + user.ID,
		UserID:       user.ID,
		Username:     user.Username,
		Status:       SessionStatusActive,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    time.Now().Add(30 * time.Minute),
	}
	
	if metadata != nil {
		session.IPAddress = metadata.IPAddress
		session.UserAgent = metadata.UserAgent
	}
	
	m.sessions[session.ID] = session
	return session, nil
}

func (m *mockSessionManager) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	if session, exists := m.sessions[sessionID]; exists {
		return session, nil
	}
	return nil, fmt.Errorf("session not found")
}

func (m *mockSessionManager) UpdateSession(ctx context.Context, sessionID string, metadata *SessionMetadata) (*Session, error) {
	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}
	
	session.LastActivity = time.Now()
	return session, nil
}

func (m *mockSessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	delete(m.sessions, sessionID)
	return nil
}

func (m *mockSessionManager) ValidateSession(ctx context.Context, sessionID string) (*Session, error) {
	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}
	
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}
	
	session.LastActivity = time.Now()
	return session, nil
}

func (m *mockSessionManager) RefreshSession(ctx context.Context, sessionID string) (*Session, error) {
	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}
	
	session.ExpiresAt = time.Now().Add(30 * time.Minute)
	session.LastActivity = time.Now()
	return session, nil
}

func (m *mockSessionManager) GetUserSessions(ctx context.Context, userID string) ([]*Session, error) {
	var sessions []*Session
	for _, session := range m.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

func (m *mockSessionManager) RevokeUserSessions(ctx context.Context, userID string) error {
	for sessionID, session := range m.sessions {
		if session.UserID == userID {
			delete(m.sessions, sessionID)
		}
	}
	return nil
}

func (m *mockSessionManager) CleanupExpiredSessions(ctx context.Context) error {
	now := time.Now()
	for sessionID, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, sessionID)
		}
	}
	return nil
}

func (m *mockSessionManager) CheckConcurrentSessions(ctx context.Context, userID string) (bool, error) {
	count := 0
	for _, session := range m.sessions {
		if session.UserID == userID && session.Status == SessionStatusActive {
			count++
		}
	}
	return count < 5, nil // Max 5 concurrent sessions
}

func (m *mockSessionManager) GetActiveSessions(ctx context.Context, userID string) ([]*Session, error) {
	var sessions []*Session
	for _, session := range m.sessions {
		if session.UserID == userID && session.Status == SessionStatusActive {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

type mockTokenValidator struct{}

func (m *mockTokenValidator) ValidateAPIKey(ctx context.Context, apiKey string) (*APIKeyInfo, error) {
	if apiKey == "valid-api-key" {
		return &APIKeyInfo{
			KeyID:     "key-123",
			UserID:    "user-testuser",
			Username:  "testuser",
			ExpiresAt: time.Now().Add(24 * time.Hour),
			IsActive:  true,
		}, nil
	}
	return nil, fmt.Errorf("invalid API key")
}

func (m *mockTokenValidator) ValidateJWT(ctx context.Context, token string) (*JWTClaims, error) {
	if token == "valid-jwt-token" {
		return &JWTClaims{
			UserID:    "user-testuser",
			Username:  "testuser",
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}
	return nil, fmt.Errorf("invalid JWT token")
}

func (m *mockTokenValidator) ValidateCertificate(ctx context.Context, cert *x509.Certificate) (*CertificateInfo, error) {
	return &CertificateInfo{
		Subject:   cert.Subject.String(),
		IsValid:   true,
		UserID:    "user-testuser",
		Username:  "testuser",
	}, nil
}

type mockPasswordManager struct{}

func (m *mockPasswordManager) HashPassword(password string) (string, error) {
	return "hashed-" + password, nil
}

func (m *mockPasswordManager) ValidatePassword(hashedPassword, password string) (bool, error) {
	return hashedPassword == "hashed-"+password, nil
}

func (m *mockPasswordManager) GenerateRandomPassword(length int) (string, error) {
	return "randompassword123", nil
}

func (m *mockPasswordManager) ValidatePasswordStrength(password string) (*PasswordStrengthResult, error) {
	return &PasswordStrengthResult{
		Score:    80,
		IsStrong: len(password) >= 8,
	}, nil
}

type mockAuditLogger struct{}

func (m *mockAuditLogger) LogAuthentication(ctx context.Context, event *AuthenticationEvent) error {
	return nil
}

func (m *mockAuditLogger) LogAuthorization(ctx context.Context, event *AuthorizationEvent) error {
	return nil
}

func (m *mockAuditLogger) LogSessionEvent(ctx context.Context, event *SessionEvent) error {
	return nil
}

func (m *mockAuditLogger) LogUserEvent(ctx context.Context, event *UserEvent) error {
	return nil
}

func (m *mockAuditLogger) LogRoleEvent(ctx context.Context, event *RoleEvent) error {
	return nil
}

type mockJWTManager struct{}

func (m *mockJWTManager) GenerateToken(ctx context.Context, user *User) (*JWTToken, error) {
	return &JWTToken{
		AccessToken:  "generated-jwt-token",
		RefreshToken: "generated-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(time.Hour),
	}, nil
}

func (m *mockJWTManager) ValidateToken(ctx context.Context, token string) (*JWTClaims, error) {
	if token == "valid-jwt-token" || token == "generated-jwt-token" {
		return &JWTClaims{
			UserID:    "user-testuser",
			Username:  "testuser",
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}
	return nil, fmt.Errorf("invalid token")
}

func (m *mockJWTManager) RefreshToken(ctx context.Context, refreshToken string) (*JWTToken, error) {
	return &JWTToken{
		AccessToken:  "refreshed-jwt-token",
		RefreshToken: "new-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(time.Hour),
	}, nil
}

func (m *mockJWTManager) RevokeToken(ctx context.Context, jti string) error {
	return nil
}

// Test helper functions

func createTestAuthManager() *DefaultAuthenticationManager {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	userManager := newMockUserManager()
	sessionManager := newMockSessionManager()
	tokenValidator := &mockTokenValidator{}
	passwordManager := &mockPasswordManager{}
	auditLogger := &mockAuditLogger{}
	jwtManager := &mockJWTManager{}

	config := DefaultAuthConfig()

	return NewDefaultAuthenticationManager(
		userManager,
		sessionManager,
		tokenValidator,
		passwordManager,
		auditLogger,
		jwtManager,
		config,
		logger,
	)
}

func createTestUser(userManager *mockUserManager) *User {
	user, _ := userManager.CreateUser(context.Background(), &CreateUserRequest{
		Username:    "testuser",
		Email:       "test@example.com",
		DisplayName: "Test User",
		Roles:       []string{"user"},
	})
	return user
}

// Integration Tests

func TestAuthenticationManager_AuthenticateCredentials(t *testing.T) {
	authManager := createTestAuthManager()
	userManager := authManager.userManager.(*mockUserManager)
	
	// Create test user
	createTestUser(userManager)
	
	ctx := context.Background()

	// Test successful authentication
	authenticatedUser, err := authManager.AuthenticateCredentials(ctx, "testuser", "password123")
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	if authenticatedUser.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", authenticatedUser.Username)
	}

	// Test failed authentication
	_, err = authManager.AuthenticateCredentials(ctx, "testuser", "wrongpassword")
	if err == nil {
		t.Error("Expected authentication to fail with wrong password")
	}

	// Test non-existent user
	_, err = authManager.AuthenticateCredentials(ctx, "nonexistent", "password123")
	if err == nil {
		t.Error("Expected authentication to fail for non-existent user")
	}
}

func TestAuthenticationManager_AuthenticateAPIKey(t *testing.T) {
	authManager := createTestAuthManager()
	userManager := authManager.userManager.(*mockUserManager)
	
	// Create test user
	createTestUser(userManager)
	
	ctx := context.Background()

	// Test successful API key authentication
	user, err := authManager.AuthenticateAPIKey(ctx, "valid-api-key")
	if err != nil {
		t.Fatalf("API key authentication failed: %v", err)
	}

	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", user.Username)
	}

	// Test invalid API key
	_, err = authManager.AuthenticateAPIKey(ctx, "invalid-api-key")
	if err == nil {
		t.Error("Expected API key authentication to fail with invalid key")
	}
}

func TestAuthenticationManager_AuthenticateJWT(t *testing.T) {
	authManager := createTestAuthManager()
	userManager := authManager.userManager.(*mockUserManager)
	
	// Create test user
	createTestUser(userManager)
	
	ctx := context.Background()

	// Test successful JWT authentication
	user, err := authManager.AuthenticateJWT(ctx, "valid-jwt-token")
	if err != nil {
		t.Fatalf("JWT authentication failed: %v", err)
	}

	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", user.Username)
	}

	// Test invalid JWT
	_, err = authManager.AuthenticateJWT(ctx, "invalid-jwt-token")
	if err == nil {
		t.Error("Expected JWT authentication to fail with invalid token")
	}
}

func TestAuthenticationManager_SessionManagement(t *testing.T) {
	authManager := createTestAuthManager()
	userManager := authManager.userManager.(*mockUserManager)
	
	// Create test user
	user := createTestUser(userManager)
	
	ctx := context.Background()

	// Test session creation
	session, err := authManager.CreateSession(ctx, user)
	if err != nil {
		t.Fatalf("Session creation failed: %v", err)
	}

	if session.UserID != user.ID {
		t.Errorf("Expected session user ID '%s', got '%s'", user.ID, session.UserID)
	}

	// Test session validation
	validatedSession, err := authManager.ValidateSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("Session validation failed: %v", err)
	}

	if validatedSession.ID != session.ID {
		t.Errorf("Expected session ID '%s', got '%s'", session.ID, validatedSession.ID)
	}

	// Test session refresh
	refreshedSession, err := authManager.RefreshSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("Session refresh failed: %v", err)
	}

	if refreshedSession.ID != session.ID {
		t.Errorf("Expected session ID '%s', got '%s'", session.ID, refreshedSession.ID)
	}

	// Test session revocation
	err = authManager.RevokeSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("Session revocation failed: %v", err)
	}

	// Validate that session is revoked
	_, err = authManager.ValidateSession(ctx, session.ID)
	if err == nil {
		t.Error("Expected session validation to fail after revocation")
	}
}

func TestAuthenticationManager_JWTManagement(t *testing.T) {
	authManager := createTestAuthManager()
	userManager := authManager.userManager.(*mockUserManager)
	
	// Create test user
	user := createTestUser(userManager)
	
	ctx := context.Background()

	// Test JWT generation
	token, err := authManager.GenerateJWT(ctx, user)
	if err != nil {
		t.Fatalf("JWT generation failed: %v", err)
	}

	if token.AccessToken == "" {
		t.Error("Expected access token to be generated")
	}

	if token.RefreshToken == "" {
		t.Error("Expected refresh token to be generated")
	}

	// Test JWT validation
	claims, err := authManager.ValidateJWT(ctx, token.AccessToken)
	if err != nil {
		t.Fatalf("JWT validation failed: %v", err)
	}

	if claims.UserID != user.ID {
		t.Errorf("Expected user ID '%s', got '%s'", user.ID, claims.UserID)
	}

	// Test JWT refresh
	newToken, err := authManager.RefreshJWT(ctx, token.RefreshToken)
	if err != nil {
		t.Fatalf("JWT refresh failed: %v", err)
	}

	if newToken.AccessToken == "" {
		t.Error("Expected new access token to be generated")
	}
}

func TestMiddleware_HTTPAuthentication(t *testing.T) {
	authManager := createTestAuthManager()
	userManager := authManager.userManager.(*mockUserManager)
	
	// Create test user
	createTestUser(userManager)

	// Create middleware
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	middleware := NewDefaultMiddleware(authManager, nil, nil, logger)

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, exists := middleware.GetUserFromContext(r.Context())
		if !exists {
			// For skip auth paths, user might not be in context
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello anonymous"))
			return
		}
		
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello " + user.Username))
	})

	// Wrap with authentication middleware
	authenticatedHandler := middleware.AuthenticateHTTP(testHandler)

	// Test API key authentication
	t.Run("API Key Authentication", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", "valid-api-key")
		
		rr := httptest.NewRecorder()
		authenticatedHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}

		if !strings.Contains(rr.Body.String(), "testuser") {
			t.Errorf("Expected response to contain 'testuser', got '%s'", rr.Body.String())
		}
	})

	// Test JWT authentication
	t.Run("JWT Authentication", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer valid-jwt-token")
		
		rr := httptest.NewRecorder()
		authenticatedHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}
	})

	// Test unauthenticated request
	t.Run("Unauthenticated Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		
		rr := httptest.NewRecorder()
		authenticatedHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})

	// Test skip auth paths
	t.Run("Skip Auth Paths", func(t *testing.T) {
		config := DefaultMiddlewareConfig()
		config.SkipAuthPaths = []string{"/health"}
		
		skipAuthMiddleware := NewDefaultMiddleware(authManager, nil, config, logger)
		skipAuthHandler := skipAuthMiddleware.AuthenticateHTTP(testHandler)

		req := httptest.NewRequest("GET", "/health", nil)
		
		rr := httptest.NewRecorder()
		skipAuthHandler.ServeHTTP(rr, req)

		// Should pass through without authentication
		if rr.Code == http.StatusUnauthorized {
			t.Error("Expected request to skip authentication for /health path")
		}
	})
}

func TestMiddleware_RequirePermission(t *testing.T) {
	authManager := createTestAuthManager()
	userManager := authManager.userManager.(*mockUserManager)
	
	// Create test user
	user := createTestUser(userManager)

	// Create mock authorization manager
	authzManager := &mockAuthzManager{
		permissions: map[string]bool{
			"testuser:secrets:read": true,
			"testuser:secrets:write": false,
		},
	}

	// Create middleware
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	middleware := NewDefaultMiddleware(authManager, authzManager, nil, logger)

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Access granted"))
	})

	// Test with permission
	t.Run("With Permission", func(t *testing.T) {
		// First authenticate
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", "valid-api-key")
		
		// Add user to context manually for this test
		ctx := middleware.SetUserInContext(req.Context(), user)
		req = req.WithContext(ctx)

		// Apply permission middleware
		permissionHandler := middleware.RequirePermission("secrets", "read")(testHandler)
		
		rr := httptest.NewRecorder()
		permissionHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}
	})

	// Test without permission
	t.Run("Without Permission", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", nil)
		req.Header.Set("X-API-Key", "valid-api-key")
		
		// Add user to context manually for this test
		ctx := middleware.SetUserInContext(req.Context(), user)
		req = req.WithContext(ctx)

		// Apply permission middleware for write (which user doesn't have)
		permissionHandler := middleware.RequirePermission("secrets", "write")(testHandler)
		
		rr := httptest.NewRecorder()
		permissionHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected status 403, got %d", rr.Code)
		}
	})
}

// Mock authorization manager for testing
type mockAuthzManager struct {
	permissions map[string]bool
}

func (m *mockAuthzManager) HasPermission(ctx context.Context, user *User, resource, action string) (bool, error) {
	key := user.Username + ":" + resource + ":" + action
	return m.permissions[key], nil
}

func (m *mockAuthzManager) CheckAccess(ctx context.Context, user *User, request *AccessRequest) (*AccessDecision, error) {
	allowed, _ := m.HasPermission(ctx, user, request.Resource, request.Action)
	return &AccessDecision{
		Allowed: allowed,
		Reason:  "Mock decision",
	}, nil
}

func (m *mockAuthzManager) AssignRole(ctx context.Context, userID, roleID string) error {
	return nil
}

func (m *mockAuthzManager) RevokeRole(ctx context.Context, userID, roleID string) error {
	return nil
}

func (m *mockAuthzManager) GetUserRoles(ctx context.Context, userID string) ([]*Role, error) {
	return []*Role{}, nil
}

func (m *mockAuthzManager) GrantPermission(ctx context.Context, roleID string, permission *Permission) error {
	return nil
}

func (m *mockAuthzManager) RevokePermission(ctx context.Context, roleID string, permissionID string) error {
	return nil
}

func (m *mockAuthzManager) GetRolePermissions(ctx context.Context, roleID string) ([]*Permission, error) {
	return []*Permission{}, nil
}

