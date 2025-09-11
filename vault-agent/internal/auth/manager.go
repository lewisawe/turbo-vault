package auth

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// DefaultAuthenticationManager implements the AuthenticationManager interface
type DefaultAuthenticationManager struct {
	userManager     UserManager
	sessionManager  SessionManager
	tokenValidator  TokenValidator
	passwordManager PasswordManager
	auditLogger     AuditLogger
	jwtManager      JWTManager
	config          *AuthConfig
	logger          *logrus.Logger
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	// JWT configuration
	JWTSecret           string        `json:"jwt_secret"`
	JWTExpiry           time.Duration `json:"jwt_expiry"`
	JWTRefreshExpiry    time.Duration `json:"jwt_refresh_expiry"`
	JWTIssuer           string        `json:"jwt_issuer"`
	
	// Session configuration
	SessionTimeout      time.Duration `json:"session_timeout"`
	SessionMaxConcurrent int          `json:"session_max_concurrent"`
	SessionSecureCookies bool         `json:"session_secure_cookies"`
	
	// API Key configuration
	APIKeyExpiry        time.Duration `json:"api_key_expiry"`
	APIKeyMaxPerUser    int           `json:"api_key_max_per_user"`
	
	// Password configuration
	PasswordMinLength   int           `json:"password_min_length"`
	PasswordRequireUpper bool         `json:"password_require_upper"`
	PasswordRequireLower bool         `json:"password_require_lower"`
	PasswordRequireDigit bool         `json:"password_require_digit"`
	PasswordRequireSpecial bool       `json:"password_require_special"`
	PasswordMaxAge      time.Duration `json:"password_max_age"`
	
	// Security configuration
	MaxFailedAttempts   int           `json:"max_failed_attempts"`
	LockoutDuration     time.Duration `json:"lockout_duration"`
	RequireMFA          bool          `json:"require_mfa"`
	
	// Certificate configuration
	CertificateValidation bool         `json:"certificate_validation"`
	TrustedCAs           []string      `json:"trusted_cas"`
}

// JWTManager defines the interface for JWT operations
type JWTManager interface {
	GenerateToken(ctx context.Context, user *User) (*JWTToken, error)
	ValidateToken(ctx context.Context, token string) (*JWTClaims, error)
	RefreshToken(ctx context.Context, refreshToken string) (*JWTToken, error)
	RevokeToken(ctx context.Context, jti string) error
}

// NewDefaultAuthenticationManager creates a new authentication manager
func NewDefaultAuthenticationManager(
	userManager UserManager,
	sessionManager SessionManager,
	tokenValidator TokenValidator,
	passwordManager PasswordManager,
	auditLogger AuditLogger,
	jwtManager JWTManager,
	config *AuthConfig,
	logger *logrus.Logger,
) *DefaultAuthenticationManager {
	if config == nil {
		config = DefaultAuthConfig()
	}

	return &DefaultAuthenticationManager{
		userManager:     userManager,
		sessionManager:  sessionManager,
		tokenValidator:  tokenValidator,
		passwordManager: passwordManager,
		auditLogger:     auditLogger,
		jwtManager:      jwtManager,
		config:          config,
		logger:          logger,
	}
}

// DefaultAuthConfig returns default authentication configuration
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		JWTExpiry:           24 * time.Hour,
		JWTRefreshExpiry:    7 * 24 * time.Hour,
		JWTIssuer:           "vault-agent",
		SessionTimeout:      30 * time.Minute,
		SessionMaxConcurrent: 5,
		SessionSecureCookies: true,
		APIKeyExpiry:        365 * 24 * time.Hour,
		APIKeyMaxPerUser:    10,
		PasswordMinLength:   8,
		PasswordRequireUpper: true,
		PasswordRequireLower: true,
		PasswordRequireDigit: true,
		PasswordRequireSpecial: false,
		PasswordMaxAge:      90 * 24 * time.Hour,
		MaxFailedAttempts:   5,
		LockoutDuration:     15 * time.Minute,
		RequireMFA:          false,
		CertificateValidation: true,
	}
}

// Authentication Methods

func (am *DefaultAuthenticationManager) AuthenticateAPIKey(ctx context.Context, apiKey string) (*User, error) {
	startTime := time.Now()
	
	// Validate API key format and extract info
	keyInfo, err := am.tokenValidator.ValidateAPIKey(ctx, apiKey)
	if err != nil {
		am.logAuthEvent(ctx, AuthEventLoginFailed, "", AuthMethodAPIKey, false, err.Error(), nil)
		return nil, fmt.Errorf("invalid API key: %w", err)
	}

	// Get user
	user, err := am.userManager.GetUser(ctx, keyInfo.UserID)
	if err != nil {
		am.logAuthEvent(ctx, AuthEventLoginFailed, keyInfo.UserID, AuthMethodAPIKey, false, "user not found", nil)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check user status
	if user.Status != UserStatusActive {
		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodAPIKey, false, "user not active", nil)
		return nil, fmt.Errorf("user account is not active: %s", user.Status)
	}

	// Check if user is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodAPIKey, false, "account locked", nil)
		return nil, fmt.Errorf("user account is locked until %v", user.LockedUntil)
	}

	// Check API key expiry
	if !keyInfo.ExpiresAt.IsZero() && time.Now().After(keyInfo.ExpiresAt) {
		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodAPIKey, false, "API key expired", nil)
		return nil, fmt.Errorf("API key has expired")
	}

	// Update last login
	now := time.Now()
	user.LastLogin = &now
	user.FailedLoginAttempts = 0
	if _, err := am.userManager.UpdateUser(ctx, user.ID, &UpdateUserRequest{
		// Only update last login and reset failed attempts
	}); err != nil {
		am.logger.WithError(err).Warn("Failed to update user last login")
	}

	am.logAuthEvent(ctx, AuthEventLogin, user.ID, AuthMethodAPIKey, true, "", map[string]interface{}{
		"duration_ms": time.Since(startTime).Milliseconds(),
		"api_key_id": keyInfo.KeyID,
	})

	return user, nil
}

func (am *DefaultAuthenticationManager) AuthenticateJWT(ctx context.Context, token string) (*User, error) {
	startTime := time.Now()
	
	// Validate JWT token
	claims, err := am.jwtManager.ValidateToken(ctx, token)
	if err != nil {
		am.logAuthEvent(ctx, AuthEventLoginFailed, "", AuthMethodJWT, false, err.Error(), nil)
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}

	// Get user
	user, err := am.userManager.GetUser(ctx, claims.UserID)
	if err != nil {
		am.logAuthEvent(ctx, AuthEventLoginFailed, claims.UserID, AuthMethodJWT, false, "user not found", nil)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check user status
	if user.Status != UserStatusActive {
		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodJWT, false, "user not active", nil)
		return nil, fmt.Errorf("user account is not active: %s", user.Status)
	}

	// Check if user is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodJWT, false, "account locked", nil)
		return nil, fmt.Errorf("user account is locked until %v", user.LockedUntil)
	}

	am.logAuthEvent(ctx, AuthEventLogin, user.ID, AuthMethodJWT, true, "", map[string]interface{}{
		"duration_ms": time.Since(startTime).Milliseconds(),
		"session_id": claims.SessionID,
	})

	return user, nil
}

func (am *DefaultAuthenticationManager) AuthenticateCertificate(ctx context.Context, cert *x509.Certificate) (*User, error) {
	startTime := time.Now()
	
	if !am.config.CertificateValidation {
		return nil, fmt.Errorf("certificate authentication is disabled")
	}

	// Validate certificate
	certInfo, err := am.tokenValidator.ValidateCertificate(ctx, cert)
	if err != nil {
		am.logAuthEvent(ctx, AuthEventLoginFailed, "", AuthMethodCertificate, false, err.Error(), nil)
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}

	if !certInfo.IsValid {
		am.logAuthEvent(ctx, AuthEventLoginFailed, "", AuthMethodCertificate, false, "certificate not valid", nil)
		return nil, fmt.Errorf("certificate is not valid")
	}

	// Get user by certificate info
	var user *User
	if certInfo.UserID != "" {
		user, err = am.userManager.GetUser(ctx, certInfo.UserID)
	} else if certInfo.Username != "" {
		user, err = am.userManager.GetUserByUsername(ctx, certInfo.Username)
	} else {
		// Try to find user by certificate subject
		user, err = am.userManager.GetUserByEmail(ctx, cert.Subject.CommonName)
	}

	if err != nil {
		am.logAuthEvent(ctx, AuthEventLoginFailed, "", AuthMethodCertificate, false, "user not found", nil)
		return nil, fmt.Errorf("user not found for certificate: %w", err)
	}

	// Check user status
	if user.Status != UserStatusActive {
		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodCertificate, false, "user not active", nil)
		return nil, fmt.Errorf("user account is not active: %s", user.Status)
	}

	// Check if user is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodCertificate, false, "account locked", nil)
		return nil, fmt.Errorf("user account is locked until %v", user.LockedUntil)
	}

	// Update last login
	now := time.Now()
	user.LastLogin = &now
	user.FailedLoginAttempts = 0
	if _, err := am.userManager.UpdateUser(ctx, user.ID, &UpdateUserRequest{}); err != nil {
		am.logger.WithError(err).Warn("Failed to update user last login")
	}

	am.logAuthEvent(ctx, AuthEventLogin, user.ID, AuthMethodCertificate, true, "", map[string]interface{}{
		"duration_ms": time.Since(startTime).Milliseconds(),
		"certificate_fingerprint": certInfo.Fingerprint,
	})

	return user, nil
}

func (am *DefaultAuthenticationManager) AuthenticateCredentials(ctx context.Context, username, password string) (*User, error) {
	startTime := time.Now()
	
	// Get user by username or email
	user, err := am.userManager.GetUserByUsername(ctx, username)
	if err != nil {
		// Try by email
		user, err = am.userManager.GetUserByEmail(ctx, username)
		if err != nil {
			am.logAuthEvent(ctx, AuthEventLoginFailed, "", AuthMethodPassword, false, "user not found", nil)
			return nil, fmt.Errorf("invalid credentials")
		}
	}

	// Check if user is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodPassword, false, "account locked", nil)
		return nil, fmt.Errorf("user account is locked until %v", user.LockedUntil)
	}

	// Check user status
	if user.Status != UserStatusActive {
		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodPassword, false, "user not active", nil)
		return nil, fmt.Errorf("user account is not active: %s", user.Status)
	}

	// Validate password
	valid, err := am.userManager.ValidatePassword(ctx, user.ID, password)
	if err != nil {
		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodPassword, false, "password validation error", nil)
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if !valid {
		// Increment failed login attempts
		user.FailedLoginAttempts++
		
		// Check if we should lock the account
		if user.FailedLoginAttempts >= am.config.MaxFailedAttempts {
			lockUntil := time.Now().Add(am.config.LockoutDuration)
			user.LockedUntil = &lockUntil
			
			if err := am.userManager.LockUser(ctx, user.ID, "too many failed login attempts"); err != nil {
				am.logger.WithError(err).Error("Failed to lock user account")
			}
			
			am.logAuthEvent(ctx, AuthEventAccountLocked, user.ID, AuthMethodPassword, false, "too many failed attempts", nil)
		} else {
			// Just update failed attempts
			if _, err := am.userManager.UpdateUser(ctx, user.ID, &UpdateUserRequest{}); err != nil {
				am.logger.WithError(err).Warn("Failed to update failed login attempts")
			}
		}

		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodPassword, false, "invalid password", map[string]interface{}{
			"failed_attempts": user.FailedLoginAttempts,
		})
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if MFA is required
	if am.config.RequireMFA && !user.MFAEnabled {
		am.logAuthEvent(ctx, AuthEventLoginFailed, user.ID, AuthMethodPassword, false, "MFA required", nil)
		return nil, fmt.Errorf("multi-factor authentication is required")
	}

	// Successful authentication - reset failed attempts and update last login
	now := time.Now()
	user.LastLogin = &now
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	
	if _, err := am.userManager.UpdateUser(ctx, user.ID, &UpdateUserRequest{}); err != nil {
		am.logger.WithError(err).Warn("Failed to update user after successful login")
	}

	am.logAuthEvent(ctx, AuthEventLogin, user.ID, AuthMethodPassword, true, "", map[string]interface{}{
		"duration_ms": time.Since(startTime).Milliseconds(),
	})

	return user, nil
}

// Session Management

func (am *DefaultAuthenticationManager) CreateSession(ctx context.Context, user *User) (*Session, error) {
	// Check concurrent session limits
	canCreate, err := am.sessionManager.CheckConcurrentSessions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check concurrent sessions: %w", err)
	}

	if !canCreate {
		return nil, fmt.Errorf("maximum concurrent sessions exceeded")
	}

	// Create session metadata from context
	metadata := &SessionMetadata{}
	if ipAddr := getIPFromContext(ctx); ipAddr != "" {
		metadata.IPAddress = ipAddr
	}
	if userAgent := getUserAgentFromContext(ctx); userAgent != "" {
		metadata.UserAgent = userAgent
	}

	// Create session
	session, err := am.sessionManager.CreateSession(ctx, user, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Log session creation
	if am.auditLogger != nil {
		am.auditLogger.LogSessionEvent(ctx, &SessionEvent{
			EventID:   uuid.New().String(),
			EventType: SessionEventCreated,
			SessionID: session.ID,
			UserID:    user.ID,
			Username:  user.Username,
			IPAddress: session.IPAddress,
			UserAgent: session.UserAgent,
			Timestamp: time.Now(),
		})
	}

	return session, nil
}

func (am *DefaultAuthenticationManager) ValidateSession(ctx context.Context, sessionID string) (*Session, error) {
	session, err := am.sessionManager.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session: %w", err)
	}

	// Log session activity
	if am.auditLogger != nil {
		am.auditLogger.LogSessionEvent(ctx, &SessionEvent{
			EventID:   uuid.New().String(),
			EventType: SessionEventActivity,
			SessionID: session.ID,
			UserID:    session.UserID,
			Username:  session.Username,
			IPAddress: session.IPAddress,
			UserAgent: session.UserAgent,
			Timestamp: time.Now(),
		})
	}

	return session, nil
}

func (am *DefaultAuthenticationManager) RefreshSession(ctx context.Context, sessionID string) (*Session, error) {
	session, err := am.sessionManager.RefreshSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh session: %w", err)
	}

	// Log session refresh
	if am.auditLogger != nil {
		am.auditLogger.LogSessionEvent(ctx, &SessionEvent{
			EventID:   uuid.New().String(),
			EventType: SessionEventRefreshed,
			SessionID: session.ID,
			UserID:    session.UserID,
			Username:  session.Username,
			IPAddress: session.IPAddress,
			UserAgent: session.UserAgent,
			Timestamp: time.Now(),
		})
	}

	return session, nil
}

func (am *DefaultAuthenticationManager) RevokeSession(ctx context.Context, sessionID string) error {
	session, err := am.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}

	if err := am.sessionManager.DeleteSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	// Log session revocation
	if am.auditLogger != nil {
		am.auditLogger.LogSessionEvent(ctx, &SessionEvent{
			EventID:   uuid.New().String(),
			EventType: SessionEventRevoked,
			SessionID: session.ID,
			UserID:    session.UserID,
			Username:  session.Username,
			IPAddress: session.IPAddress,
			UserAgent: session.UserAgent,
			Timestamp: time.Now(),
		})
	}

	return nil
}

func (am *DefaultAuthenticationManager) RevokeAllUserSessions(ctx context.Context, userID string) error {
	sessions, err := am.sessionManager.GetUserSessions(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	if err := am.sessionManager.RevokeUserSessions(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke user sessions: %w", err)
	}

	// Log session revocations
	if am.auditLogger != nil {
		for _, session := range sessions {
			am.auditLogger.LogSessionEvent(ctx, &SessionEvent{
				EventID:   uuid.New().String(),
				EventType: SessionEventRevoked,
				SessionID: session.ID,
				UserID:    session.UserID,
				Username:  session.Username,
				IPAddress: session.IPAddress,
				UserAgent: session.UserAgent,
				Timestamp: time.Now(),
				Metadata: map[string]interface{}{
					"revoke_all": true,
				},
			})
		}
	}

	return nil
}

// API Key Management

func (am *DefaultAuthenticationManager) CreateAPIKey(ctx context.Context, userID string, request *CreateAPIKeyRequest) (*APIKey, error) {
	// Check if user exists
	_, err := am.userManager.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check API key limits
	existingKeys, err := am.ListAPIKeys(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing API keys: %w", err)
	}

	if len(existingKeys) >= am.config.APIKeyMaxPerUser {
		return nil, fmt.Errorf("maximum API keys per user exceeded")
	}

	// Generate API key
	apiKey := &APIKey{
		ID:          uuid.New().String(),
		UserID:      userID,
		Name:        request.Name,
		Description: request.Description,
		Permissions: request.Permissions,
		Scopes:      request.Scopes,
		Status:      APIKeyStatusActive,
		CreatedAt:   time.Now(),
		RateLimit:   request.RateLimit,
		Metadata:    request.Metadata,
	}

	// Set expiry
	if request.ExpiresAt != nil {
		apiKey.ExpiresAt = request.ExpiresAt
	} else {
		expiry := time.Now().Add(am.config.APIKeyExpiry)
		apiKey.ExpiresAt = &expiry
	}

	// This would be implemented by the API key storage
	// The actual key generation and hashing would happen there
	// For now, we'll just return the API key structure

	am.logger.WithFields(logrus.Fields{
		"user_id":    userID,
		"api_key_id": apiKey.ID,
		"name":       apiKey.Name,
	}).Info("API key created")

	return apiKey, nil
}

func (am *DefaultAuthenticationManager) RevokeAPIKey(ctx context.Context, keyID string) error {
	// This would be implemented by the API key storage
	am.logger.WithField("api_key_id", keyID).Info("API key revoked")
	return nil
}

func (am *DefaultAuthenticationManager) ListAPIKeys(ctx context.Context, userID string) ([]*APIKey, error) {
	// This would be implemented by the API key storage
	return []*APIKey{}, nil
}

// JWT Management

func (am *DefaultAuthenticationManager) GenerateJWT(ctx context.Context, user *User) (*JWTToken, error) {
	return am.jwtManager.GenerateToken(ctx, user)
}

func (am *DefaultAuthenticationManager) ValidateJWT(ctx context.Context, token string) (*JWTClaims, error) {
	return am.jwtManager.ValidateToken(ctx, token)
}

func (am *DefaultAuthenticationManager) RefreshJWT(ctx context.Context, refreshToken string) (*JWTToken, error) {
	return am.jwtManager.RefreshToken(ctx, refreshToken)
}

// Helper methods

func (am *DefaultAuthenticationManager) logAuthEvent(ctx context.Context, eventType AuthEventType, userID string, method AuthMethod, success bool, reason string, metadata map[string]interface{}) {
	if am.auditLogger == nil {
		return
	}

	event := &AuthenticationEvent{
		EventID:       uuid.New().String(),
		EventType:     eventType,
		UserID:        userID,
		Method:        method,
		Success:       success,
		FailureReason: reason,
		IPAddress:     getIPFromContext(ctx),
		UserAgent:     getUserAgentFromContext(ctx),
		Timestamp:     time.Now(),
		Metadata:      metadata,
	}

	if err := am.auditLogger.LogAuthentication(ctx, event); err != nil {
		am.logger.WithError(err).Error("Failed to log authentication event")
	}
}

// Context helper functions (these would be implemented based on your HTTP framework)
func getIPFromContext(ctx context.Context) string {
	// Implementation depends on your HTTP framework
	// This is a placeholder
	return ""
}

func getUserAgentFromContext(ctx context.Context) string {
	// Implementation depends on your HTTP framework
	// This is a placeholder
	return ""
}