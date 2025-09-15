package api

import (
	"net/http"
	"github.com/gin-gonic/gin"
)

// PoliciesHandler handles policy-related API requests
type PoliciesHandler struct{}

// NewPoliciesHandler creates a new policies handler
func NewPoliciesHandler() *PoliciesHandler {
	return &PoliciesHandler{}
}

// ListPolicies returns all policies
func (h *PoliciesHandler) ListPolicies(c *gin.Context) {
	policies := []map[string]interface{}{
		{
			"id": "pol-001",
			"name": "admin-policy",
			"description": "Full administrative access",
			"priority": "high",
			"status": "active",
			"created_at": "2025-09-15T10:00:00Z",
			"rules": []string{"secrets:*", "users:*", "policies:*"},
		},
		{
			"id": "pol-002", 
			"name": "read-only-policy",
			"description": "Read-only access to secrets",
			"priority": "medium",
			"status": "active",
			"created_at": "2025-09-15T10:30:00Z",
			"rules": []string{"secrets:read"},
		},
		{
			"id": "pol-003",
			"name": "developer-policy", 
			"description": "Developer access to development secrets",
			"priority": "medium",
			"status": "active",
			"created_at": "2025-09-15T11:00:00Z",
			"rules": []string{"secrets:read", "secrets:create"},
		},
	}

	response := APIResponse{
		Success: true,
		Data: policies,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}
