package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// DefaultMiddleware implements the Middleware interface
type DefaultMiddleware struct {
	authManager  AuthenticationManager
	authzManager AuthorizationManager
	config       *MiddlewareConfig
	logger       *logrus.Logger
}

// MiddlewareConfig contains middleware configuration
type MiddlewareConfig struct {
	// Authentication
	RequireAuth         bool     `json:"require_auth"`
	AuthMethods         []string `json:"auth_methods"`
	SkipAuthPaths       []string `json:"skip_auth_paths"`
	
	// Headers
	AuthHeaderName      string   `json:"auth_header_name"`
	APIKeyHeaderName    string   `json:"api_key_header_name"`
	SessionCookieName   string   `json:"session_cookie_name"`
	
	// Security
	RequireHTTPS        bool     `json:"require_https"`
	AllowedOrigins      []string `json:"allowed_origins"`
	
	// Context keys
	UserContextKey      string   `json:"user_context_key"`
	SessionContextKey   string   `json:"session_context_key"`
}

// Context keys for storing user and session information
type contextKey string

const (
	UserContextKey    contextKey = "user"
	SessionContextKey contextKey = "session"
)

// NewDefaultMiddleware creates a new authentication middleware
func NewDefaultMiddleware(
	authManager AuthenticationManager,
	authzManager AuthorizationManager,
	config *MiddlewareConfig,
	logger *logrus.Logger,
) *DefaultMiddleware {
	if config == nil {
		config = DefaultMiddlewareConfig()
	}

	return &DefaultMiddleware{
		authManager:  authManager,
		authzManager: authzManager,
		config:       config,
		logger:       logger,
	}
}

// DefaultMiddlewareConfig returns default middleware configuration
func DefaultMiddlewareConfig() *MiddlewareConfig {
	return &MiddlewareConfig{
		RequireAuth:       true,
		AuthMethods:       []string{"api_key", "jwt", "session"},
		SkipAuthPaths:     []string{"/health", "/metrics", "/login"},
		AuthHeaderName:    "Authorization",
		APIKeyHeaderName:  "X-API-Key",
		SessionCookieName: "session_id",
		RequireHTTPS:      false, // Set to true in production
		AllowedOrigins:    []string{"*"},
		UserContextKey:    "user",
		SessionContextKey: "session",
	}
}

// HTTP Middleware

func (m *DefaultMiddleware) AuthenticateHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path should skip authentication
		if m.shouldSkipAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Check HTTPS requirement
		if m.config.RequireHTTPS && r.TLS == nil {
			http.Error(w, "HTTPS required", http.StatusUpgradeRequired)
			return
		}

		// Try to authenticate the request
		user, session, err := m.authenticateHTTPRequest(r)
		if err != nil {
			m.logger.WithError(err).WithField("path", r.URL.Path).Debug("Authentication failed")
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// Add user and session to context
		ctx := r.Context()
		if user != nil {
			ctx = m.SetUserInContext(ctx, user)
		}
		if session != nil {
			ctx = m.SetSessionInContext(ctx, session)
		}

		// Continue with authenticated request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *DefaultMiddleware) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, exists := m.GetUserFromContext(r.Context())
		if !exists || user == nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *DefaultMiddleware) RequirePermission(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, exists := m.GetUserFromContext(r.Context())
			if !exists || user == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Check permission
			hasPermission, err := m.authzManager.HasPermission(r.Context(), user, resource, action)
			if err != nil {
				m.logger.WithError(err).Error("Permission check failed")
				http.Error(w, "Authorization check failed", http.StatusInternalServerError)
				return
			}

			if !hasPermission {
				http.Error(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *DefaultMiddleware) RequireRole(roleNames ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, exists := m.GetUserFromContext(r.Context())
			if !exists || user == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Check if user has any of the required roles
			hasRole := false
			for _, requiredRole := range roleNames {
				for _, userRole := range user.Roles {
					// This is simplified - in practice, you'd resolve role IDs to names
					if userRole == requiredRole {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}

			if !hasRole {
				http.Error(w, fmt.Sprintf("Required role not found: %v", roleNames), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// gRPC Middleware

func (m *DefaultMiddleware) AuthenticateGRPC(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Check if method should skip authentication
	if m.shouldSkipAuth(info.FullMethod) {
		return handler(ctx, req)
	}

	// Try to authenticate the request
	user, session, err := m.authenticateGRPCRequest(ctx)
	if err != nil {
		m.logger.WithError(err).WithField("method", info.FullMethod).Debug("gRPC authentication failed")
		return nil, status.Errorf(codes.Unauthenticated, "authentication required")
	}

	// Add user and session to context
	if user != nil {
		ctx = m.SetUserInContext(ctx, user)
	}
	if session != nil {
		ctx = m.SetSessionInContext(ctx, session)
	}

	// Continue with authenticated request
	return handler(ctx, req)
}

// Context Helpers

func (m *DefaultMiddleware) GetUserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(UserContextKey).(*User)
	return user, ok
}

func (m *DefaultMiddleware) GetSessionFromContext(ctx context.Context) (*Session, bool) {
	session, ok := ctx.Value(SessionContextKey).(*Session)
	return session, ok
}

func (m *DefaultMiddleware) SetUserInContext(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, UserContextKey, user)
}

func (m *DefaultMiddleware) SetSessionInContext(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, SessionContextKey, session)
}

// Authentication Methods

func (m *DefaultMiddleware) authenticateHTTPRequest(r *http.Request) (*User, *Session, error) {
	ctx := r.Context()

	// Try API Key authentication
	if apiKey := m.extractAPIKey(r); apiKey != "" {
		user, err := m.authManager.AuthenticateAPIKey(ctx, apiKey)
		if err == nil {
			return user, nil, nil
		}
		m.logger.WithError(err).Debug("API key authentication failed")
	}

	// Try JWT authentication
	if token := m.extractJWTToken(r); token != "" {
		user, err := m.authManager.AuthenticateJWT(ctx, token)
		if err == nil {
			return user, nil, nil
		}
		m.logger.WithError(err).Debug("JWT authentication failed")
	}

	// Try session authentication
	if sessionID := m.extractSessionID(r); sessionID != "" {
		session, err := m.authManager.ValidateSession(ctx, sessionID)
		if err == nil {
			// Get user from session
			user := &User{
				ID:       session.UserID,
				Username: session.Username,
				Status:   UserStatusActive, // Simplified
			}
			return user, session, nil
		}
		m.logger.WithError(err).Debug("Session authentication failed")
	}

	// Try client certificate authentication
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		user, err := m.authManager.AuthenticateCertificate(ctx, cert)
		if err == nil {
			return user, nil, nil
		}
		m.logger.WithError(err).Debug("Certificate authentication failed")
	}

	return nil, nil, fmt.Errorf("no valid authentication method found")
}

func (m *DefaultMiddleware) authenticateGRPCRequest(ctx context.Context) (*User, *Session, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nil, fmt.Errorf("no metadata found")
	}

	// Try API Key authentication
	if apiKeys := md.Get(strings.ToLower(m.config.APIKeyHeaderName)); len(apiKeys) > 0 {
		user, err := m.authManager.AuthenticateAPIKey(ctx, apiKeys[0])
		if err == nil {
			return user, nil, nil
		}
		m.logger.WithError(err).Debug("gRPC API key authentication failed")
	}

	// Try JWT authentication
	if authHeaders := md.Get("authorization"); len(authHeaders) > 0 {
		token := m.extractBearerToken(authHeaders[0])
		if token != "" {
			user, err := m.authManager.AuthenticateJWT(ctx, token)
			if err == nil {
				return user, nil, nil
			}
			m.logger.WithError(err).Debug("gRPC JWT authentication failed")
		}
	}

	return nil, nil, fmt.Errorf("no valid authentication method found")
}

// Token Extraction Methods

func (m *DefaultMiddleware) extractAPIKey(r *http.Request) string {
	// Check header
	if apiKey := r.Header.Get(m.config.APIKeyHeaderName); apiKey != "" {
		return apiKey
	}

	// Check query parameter
	if apiKey := r.URL.Query().Get("api_key"); apiKey != "" {
		return apiKey
	}

	return ""
}

func (m *DefaultMiddleware) extractJWTToken(r *http.Request) string {
	// Check Authorization header
	authHeader := r.Header.Get(m.config.AuthHeaderName)
	if authHeader != "" {
		return m.extractBearerToken(authHeader)
	}

	// Check query parameter
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}

	return ""
}

func (m *DefaultMiddleware) extractBearerToken(authHeader string) string {
	const bearerPrefix = "Bearer "
	if strings.HasPrefix(authHeader, bearerPrefix) {
		return strings.TrimPrefix(authHeader, bearerPrefix)
	}
	return ""
}

func (m *DefaultMiddleware) extractSessionID(r *http.Request) string {
	// Check cookie
	if cookie, err := r.Cookie(m.config.SessionCookieName); err == nil {
		return cookie.Value
	}

	// Check header
	if sessionID := r.Header.Get("X-Session-ID"); sessionID != "" {
		return sessionID
	}

	return ""
}

// Helper Methods

func (m *DefaultMiddleware) shouldSkipAuth(path string) bool {
	for _, skipPath := range m.config.SkipAuthPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// CORS Middleware (bonus)

func (m *DefaultMiddleware) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		
		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range m.config.AllowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Session-ID")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Security Headers Middleware

func (m *DefaultMiddleware) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		if m.config.RequireHTTPS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// Request ID Middleware

func (m *DefaultMiddleware) RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		w.Header().Set("X-Request-ID", requestID)
		
		// Add request ID to context
		ctx := context.WithValue(r.Context(), "request_id", requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logging Middleware

func (m *DefaultMiddleware) Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		// Get user info if available
		var userID, username string
		if user, exists := m.GetUserFromContext(r.Context()); exists && user != nil {
			userID = user.ID
			username = user.Username
		}

		m.logger.WithFields(logrus.Fields{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      wrapped.statusCode,
			"duration_ms": duration.Milliseconds(),
			"user_id":     userID,
			"username":    username,
			"ip":          getClientIP(r),
			"user_agent":  r.UserAgent(),
		}).Info("HTTP request")
	})
}

// Helper types and functions

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func generateRequestID() string {
	// Simple request ID generation
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}