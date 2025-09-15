package api

import (
	"net/http"
	"time"
	"github.com/gin-gonic/gin"
)

// UsersHandler handles user-related API requests
type UsersHandler struct{}

// NewUsersHandler creates a new users handler
func NewUsersHandler() *UsersHandler {
	return &UsersHandler{}
}

// ListUsers returns all users
func (h *UsersHandler) ListUsers(c *gin.Context) {
	users := []map[string]interface{}{
		{
			"id": "user-001",
			"username": "admin",
			"email": "admin@keyvault.local",
			"role": "administrator",
			"status": "active",
			"last_login": "2025-09-15T13:30:00Z",
			"created_at": "2025-09-15T10:00:00Z",
			"policies": []string{"admin-policy"},
		},
		{
			"id": "user-002",
			"username": "developer",
			"email": "dev@keyvault.local", 
			"role": "developer",
			"status": "active",
			"last_login": "2025-09-15T12:45:00Z",
			"created_at": "2025-09-15T10:15:00Z",
			"policies": []string{"developer-policy"},
		},
		{
			"id": "user-003",
			"username": "readonly",
			"email": "readonly@keyvault.local",
			"role": "viewer",
			"status": "inactive",
			"last_login": "2025-09-14T16:20:00Z",
			"created_at": "2025-09-15T10:30:00Z",
			"policies": []string{"read-only-policy"},
		},
	}

	response := APIResponse{
		Success: true,
		Data: users,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}

// CreateUser creates a new user
func (h *UsersHandler) CreateUser(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   &APIError{
				Code:    "INVALID_REQUEST",
				Message: "Invalid request data",
			},
			RequestID: GetRequestID(c),
			Timestamp: GetCurrentTime(),
		})
		return
	}

	user := map[string]interface{}{
		"id": "user-" + req.Username,
		"username": req.Username,
		"email": req.Email,
		"role": req.Role,
		"status": "active",
		"created_at": time.Now(),
		"last_login": nil,
	}

	response := APIResponse{
		Success: true,
		Data: user,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusCreated, response)
}

// UpdateUser updates an existing user
func (h *UsersHandler) UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
		Status   string `json:"status"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   &APIError{
				Code:    "INVALID_REQUEST",
				Message: "Invalid request data",
			},
			RequestID: GetRequestID(c),
			Timestamp: GetCurrentTime(),
		})
		return
	}

	user := map[string]interface{}{
		"id": userID,
		"username": req.Username,
		"email": req.Email,
		"role": req.Role,
		"status": req.Status,
		"updated_at": time.Now(),
	}

	response := APIResponse{
		Success: true,
		Data: user,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}

// DeleteUser deletes a user
func (h *UsersHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")

	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"id": userID,
			"deleted": true,
		},
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}

// ResetUserPassword resets a user's password
func (h *UsersHandler) ResetUserPassword(c *gin.Context) {
	userID := c.Param("id")
	
	var req struct {
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   &APIError{
				Code:    "INVALID_REQUEST",
				Message: "Invalid request data",
			},
			RequestID: GetRequestID(c),
			Timestamp: GetCurrentTime(),
		})
		return
	}

	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"id": userID,
			"password_reset": true,
		},
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}
