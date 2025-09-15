package api

import (
	"net/http"
	"github.com/gin-gonic/gin"
)

// GetSecretTags returns all available tags
func (h *SecretHandler) GetSecretTags(c *gin.Context) {
	// Extract unique tags from all secrets
	tags := []string{
		"production",
		"development", 
		"test",
		"api",
		"database",
		"cache",
		"redis",
		"postgres",
		"aws",
		"s3",
		"infrastructure",
		"auth",
		"jwt",
		"security",
		"payment",
		"stripe",
		"cli",
		"session",
	}

	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"tags": tags,
		},
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}
