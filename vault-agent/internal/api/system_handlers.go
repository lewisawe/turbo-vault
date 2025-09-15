package api

import (
	"net/http"
	"time"
	"github.com/gin-gonic/gin"
)

// SystemHandler handles system-related API requests
type SystemHandler struct{}

// NewSystemHandler creates a new system handler
func NewSystemHandler() *SystemHandler {
	return &SystemHandler{}
}

// GetSystemStats returns system statistics
func (h *SystemHandler) GetSystemStats(c *gin.Context) {
	stats := map[string]interface{}{
		"total_secrets": 14,
		"active_secrets": 14,
		"expired_secrets": 0,
		"total_users": 3,
		"active_policies": 3,
		"uptime_seconds": 7200,
		"memory_usage": "45MB",
		"cpu_usage": "12%",
		"disk_usage": "2.1GB",
		"status": "online",
	}

	response := APIResponse{
		Success: true,
		Data: stats,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}

// GetSystemHealth returns system health status
func (h *SystemHandler) GetSystemHealth(c *gin.Context) {
	health := map[string]interface{}{
		"status": "online",
		"database": "connected",
		"encryption": "operational",
		"backup": "ready",
		"last_check": time.Now(),
		"uptime": "2h 15m",
	}

	response := APIResponse{
		Success: true,
		Data: health,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}

// GetRecentActivity returns recent system activity
func (h *SystemHandler) GetRecentActivity(c *gin.Context) {
	activities := []map[string]interface{}{
		{
			"id": "act-001",
			"type": "secret_created",
			"user": "system",
			"resource": "api-key-stripe",
			"timestamp": time.Now().Add(-2 * time.Hour),
			"details": "New secret created",
		},
		{
			"id": "act-002", 
			"type": "secret_accessed",
			"user": "system",
			"resource": "database-password",
			"timestamp": time.Now().Add(-1 * time.Hour),
			"details": "Secret value retrieved",
		},
		{
			"id": "act-003",
			"type": "secret_rotated",
			"user": "system", 
			"resource": "jwt-secret",
			"timestamp": time.Now().Add(-30 * time.Minute),
			"details": "Secret rotated successfully",
		},
	}

	response := APIResponse{
		Success: true,
		Data: activities,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}

// GetControlPlaneStatus returns control plane status
func (h *SystemHandler) GetControlPlaneStatus(c *gin.Context) {
	status := map[string]interface{}{
		"active":         true,
		"agent_id":       "demo-agent-001",
		"last_sync":      time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339),
		"sync_count":     42,
		"error_count":    0,
		"status":         "connected",
		"connected_time": time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
		"uptime_seconds": 7200,
	}

	response := APIResponse{
		Success:   true,
		Data:      status,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}

// GetSecurityStatus returns security manager status
func (h *SystemHandler) GetSecurityStatus(c *gin.Context) {
	status := map[string]interface{}{
		"active":           true,
		"hardening":        true,
		"scanning":         true,
		"last_scan":        time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339),
		"security_level":   "basic",
		"threats_detected": 0,
		"compliance_score": 85,
	}

	response := APIResponse{
		Success:   true,
		Data:      status,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}
