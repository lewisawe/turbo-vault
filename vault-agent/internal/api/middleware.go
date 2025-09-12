package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// CORSMiddleware handles Cross-Origin Resource Sharing
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-Request-ID")
		c.Header("Access-Control-Expose-Headers", "X-Request-ID")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// SecurityHeadersMiddleware adds security headers
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Next()
	}
}

// APIVersionMiddleware adds API version information to responses
func APIVersionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-API-Version", APIVersion)
		c.Next()
	}
}

// ResponseTimeMiddleware adds response time tracking
func ResponseTimeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)
		c.Header("X-Response-Time", duration.String())
	}
}

// ErrorHandlingMiddleware provides centralized error handling
func ErrorHandlingMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		apiError := &APIError{
			Type:      ErrorTypeInternal,
			Code:      "INTERNAL_SERVER_ERROR",
			Message:   "An internal server error occurred",
			RequestID: GetRequestID(c),
			Timestamp: GetCurrentTime(),
		}

		c.JSON(500, APIResponse{
			Success:   false,
			Error:     apiError,
			RequestID: GetRequestID(c),
			Timestamp: GetCurrentTime(),
		})
	})
}

// GetRequestID extracts the request ID from the context
func GetRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("request_id"); exists {
		return requestID.(string)
	}
	return ""
}

// GetCurrentTime returns the current time in UTC
func GetCurrentTime() time.Time {
	return time.Now().UTC()
}