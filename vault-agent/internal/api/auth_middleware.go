package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Simple demo users for authentication
var demoUsers = map[string]DemoUser{
	"admin": {
		Username: "admin",
		Password: "admin123", // In production, this would be hashed
		Role:     "administrator",
		Token:    "demo-admin-token-2025",
	},
	"developer": {
		Username: "developer", 
		Password: "dev123",
		Role:     "developer",
		Token:    "demo-dev-token-2025",
	},
	"viewer": {
		Username: "viewer",
		Password: "view123", 
		Role:     "viewer",
		Token:    "demo-viewer-token-2025",
	},
}

type DemoUser struct {
	Username string `json:"username"`
	Password string `json:"-"` // Never return password
	Role     string `json:"role"`
	Token    string `json:"token"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success bool     `json:"success"`
	Token   string   `json:"token,omitempty"`
	User    DemoUser `json:"user,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// AuthMiddleware checks for valid authentication
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for health check and login endpoints
		path := c.Request.URL.Path
		if path == "/health" || path == "/api/v1/auth/login" || strings.HasPrefix(path, "/api/v1/auth/") {
			c.Next()
			return
		}

		// Check for demo mode bypass (for existing functionality)
		if c.GetHeader("X-Demo-Mode") == "bypass" {
			c.Set("user", demoUsers["admin"]) // Default to admin for demo
			c.Next()
			return
		}

		// Check Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, APIResponse{
				Success: false,
				Error: &APIError{
					Code:    "MISSING_AUTH",
					Message: "Authorization header required",
				},
				RequestID: GetRequestID(c),
				Timestamp: GetCurrentTime(),
			})
			c.Abort()
			return
		}

		// Extract token (Bearer token or simple token)
		var token string
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			token = authHeader
		}

		// Validate token
		user := validateToken(token)
		if user == nil {
			c.JSON(http.StatusUnauthorized, APIResponse{
				Success: false,
				Error: &APIError{
					Code:    "INVALID_TOKEN",
					Message: "Invalid or expired token",
				},
				RequestID: GetRequestID(c),
				Timestamp: GetCurrentTime(),
			})
			c.Abort()
			return
		}

		// Set user in context
		c.Set("user", *user)
		c.Next()
	}
}

// validateToken checks if token is valid and returns user
func validateToken(token string) *DemoUser {
	for _, user := range demoUsers {
		if user.Token == token {
			return &user
		}
	}
	return nil
}

// LoginHandler handles user authentication
func LoginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, LoginResponse{
			Success: false,
			Error:   "Invalid request format",
		})
		return
	}

	// Check credentials
	user, exists := demoUsers[req.Username]
	if !exists || user.Password != req.Password {
		c.JSON(http.StatusUnauthorized, LoginResponse{
			Success: false,
			Error:   "Invalid username or password",
		})
		return
	}

	// Update last login (in production, this would be in database)
	user.Password = "" // Don't return password

	c.JSON(http.StatusOK, LoginResponse{
		Success: true,
		Token:   user.Token,
		User:    user,
	})
}

// GetCurrentUser returns the authenticated user from context
func GetCurrentUser(c *gin.Context) *DemoUser {
	if user, exists := c.Get("user"); exists {
		if demoUser, ok := user.(DemoUser); ok {
			return &demoUser
		}
	}
	return nil
}

// RequireRole middleware checks if user has required role
func RequireRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, APIResponse{
				Success: false,
				Error: &APIError{
					Code:    "NO_USER",
					Message: "No authenticated user found",
				},
				RequestID: GetRequestID(c),
				Timestamp: GetCurrentTime(),
			})
			c.Abort()
			return
		}

		// Check role hierarchy (admin can do everything)
		if user.Role == "administrator" {
			c.Next()
			return
		}

		if user.Role != requiredRole {
			c.JSON(http.StatusForbidden, APIResponse{
				Success: false,
				Error: &APIError{
					Code:    "INSUFFICIENT_PERMISSIONS",
					Message: "Insufficient permissions for this operation",
				},
				RequestID: GetRequestID(c),
				Timestamp: GetCurrentTime(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
