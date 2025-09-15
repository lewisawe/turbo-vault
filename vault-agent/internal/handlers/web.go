package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// WebHandler handles web interface requests
type WebHandler struct {
	upgrader websocket.Upgrader
	clients  map[*websocket.Conn]bool
	broadcast chan []byte
}

// NewWebHandler creates a new web handler
func NewWebHandler() *WebHandler {
	return &WebHandler{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for local development
			},
		},
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan []byte),
	}
}

// SetupWebRoutes sets up web interface routes
func (h *WebHandler) SetupWebRoutes(router *gin.Engine) {
	// Serve static files
	router.Static("/static", "./web")
	
	// Serve dashboard as default
	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/static/dashboard.html")
	})
	
	// WebSocket endpoint
	router.GET("/ws", h.handleWebSocket)
	
	// API endpoints for web interface
	web := router.Group("/web/api")
	{
		// System endpoints
		web.GET("/system/stats", h.getSystemStats)
		web.GET("/system/health", h.getSystemHealth)
		web.GET("/system/activity", h.getSystemActivity)
		web.GET("/system/settings", h.getSystemSettings)
		web.PUT("/system/settings/:category", h.updateSystemSettings)
		web.POST("/system/backup", h.createBackup)
		web.GET("/system/config/export", h.exportConfiguration)
		web.POST("/system/config/import", h.importConfiguration)
		web.POST("/system/notifications/test", h.testNotification)
		
		// Analytics endpoints
		web.GET("/analytics/access-patterns", h.getAccessPatterns)
		web.GET("/analytics/request-volume", h.getRequestVolume)
		web.GET("/analytics/response-times", h.getResponseTimes)
		web.GET("/analytics/error-rates", h.getErrorRates)
		
		// Performance metrics
		web.GET("/metrics/performance", h.getPerformanceMetrics)
		
		// Secrets endpoints
		web.GET("/secrets", h.getSecrets)
		web.POST("/secrets", h.createSecret)
		web.GET("/secrets/:id", h.getSecret)
		web.PUT("/secrets/:id", h.updateSecret)
		web.DELETE("/secrets/:id", h.deleteSecret)
		web.POST("/secrets/:id/rotate", h.rotateSecret)
		web.GET("/secrets/:id/versions", h.getSecretVersions)
		web.GET("/secrets/tags", h.getSecretTags)
		
		// Policies endpoints
		web.GET("/policies", h.getPolicies)
		web.POST("/policies", h.createPolicy)
		web.GET("/policies/:id", h.getPolicy)
		web.PUT("/policies/:id", h.updatePolicy)
		web.DELETE("/policies/:id", h.deletePolicy)
		web.POST("/policies/validate", h.validatePolicy)
		
		// Users endpoints
		web.GET("/users", h.getUsers)
		web.POST("/users", h.createUser)
		web.GET("/users/:id", h.getUser)
		web.PUT("/users/:id", h.updateUser)
		web.DELETE("/users/:id", h.deleteUser)
		web.POST("/users/:id/reset-password", h.resetUserPassword)
		
		// Audit endpoints
		web.GET("/audit/logs", h.getAuditLogs)
		web.GET("/audit/logs/export", h.exportAuditLogs)
	}
	
	// Start WebSocket message broadcaster
	go h.handleMessages()
}

// WebSocket handler
func (h *WebHandler) handleWebSocket(c *gin.Context) {
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to upgrade connection"})
		return
	}
	defer conn.Close()

	h.clients[conn] = true

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			delete(h.clients, conn)
			break
		}
	}
}

// Handle WebSocket messages
func (h *WebHandler) handleMessages() {
	for {
		msg := <-h.broadcast
		for client := range h.clients {
			err := client.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				client.Close()
				delete(h.clients, client)
			}
		}
	}
}

// Broadcast message to all WebSocket clients
func (h *WebHandler) BroadcastMessage(messageType string, payload interface{}) {
	message := map[string]interface{}{
		"type":      messageType,
		"payload":   payload,
		"timestamp": time.Now(),
	}
	
	data, err := json.Marshal(message)
	if err != nil {
		return
	}
	
	select {
	case h.broadcast <- data:
	default:
		// Channel is full, skip this message
	}
}

// System stats endpoint
func (h *WebHandler) getSystemStats(c *gin.Context) {
	stats := map[string]interface{}{
		"secrets":  150,  // Mock data
		"policies": 12,
		"users":    8,
		"uptime":   86400, // 24 hours in seconds
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"stats": stats,
	})
}

// System health endpoint
func (h *WebHandler) getSystemHealth(c *gin.Context) {
	health := map[string]interface{}{
		"cpu_usage":     25.5,
		"memory_usage":  45.2,
		"storage_usage": 12.8,
		"status":        "healthy",
	}
	
	c.JSON(http.StatusOK, health)
}

// System activity endpoint
func (h *WebHandler) getSystemActivity(c *gin.Context) {
	events := []map[string]interface{}{
		{
			"type":        "secret_access",
			"description": "Secret 'api-key-prod' accessed by user 'admin'",
			"timestamp":   time.Now().Add(-5 * time.Minute),
		},
		{
			"type":        "secret_create",
			"description": "New secret 'db-password' created by user 'developer'",
			"timestamp":   time.Now().Add(-15 * time.Minute),
		},
		{
			"type":        "policy_change",
			"description": "Policy 'read-only' updated by user 'admin'",
			"timestamp":   time.Now().Add(-30 * time.Minute),
		},
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"events": events,
	})
}

// System settings endpoint
func (h *WebHandler) getSystemSettings(c *gin.Context) {
	settings := map[string]interface{}{
		"agent_name":         "vault-agent-01",
		"log_level":          "info",
		"enable_metrics":     true,
		"session_timeout":    30,
		"max_login_attempts": 5,
		"require_mfa":        false,
		"backup_schedule":    "daily",
		"backup_retention":   30,
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"settings": settings,
	})
}

// Update system settings endpoint
func (h *WebHandler) updateSystemSettings(c *gin.Context) {
	category := c.Param("category")
	
	var settings map[string]interface{}
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid settings data"})
		return
	}
	
	// Mock update - in real implementation, this would update the actual settings
	c.JSON(http.StatusOK, gin.H{
		"message":  fmt.Sprintf("%s settings updated successfully", strings.Title(category)),
		"category": category,
		"settings": settings,
	})
}

// Create backup endpoint
func (h *WebHandler) createBackup(c *gin.Context) {
	// Mock backup creation
	backup := map[string]interface{}{
		"id":         fmt.Sprintf("backup-%d", time.Now().Unix()),
		"created_at": time.Now(),
		"size":       "2.5 MB",
		"status":     "completed",
	}
	
	c.JSON(http.StatusOK, backup)
}

// Analytics endpoints
func (h *WebHandler) getAccessPatterns(c *gin.Context) {
	// Mock data for access patterns
	labels := []string{}
	values := []int{}
	
	for i := 0; i < 24; i++ {
		labels = append(labels, fmt.Sprintf("%02d:00", i))
		values = append(values, 10+i*2) // Mock increasing pattern
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"labels": labels,
		"values": values,
	})
}

func (h *WebHandler) getRequestVolume(c *gin.Context) {
	labels := []string{"00:00", "04:00", "08:00", "12:00", "16:00", "20:00"}
	values := []int{45, 23, 78, 156, 134, 89}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"labels": labels,
		"values": values,
	})
}

func (h *WebHandler) getResponseTimes(c *gin.Context) {
	labels := []string{"00:00", "04:00", "08:00", "12:00", "16:00", "20:00"}
	values := []float64{45.2, 38.7, 52.1, 67.3, 43.8, 39.5}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"labels": labels,
		"values": values,
	})
}

func (h *WebHandler) getErrorRates(c *gin.Context) {
	labels := []string{"00:00", "04:00", "08:00", "12:00", "16:00", "20:00"}
	values := []float64{0.1, 0.05, 0.2, 0.15, 0.08, 0.03}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"labels": labels,
		"values": values,
	})
}

func (h *WebHandler) getPerformanceMetrics(c *gin.Context) {
	labels := []string{}
	responseTimes := []float64{}
	requestRates := []float64{}
	
	for i := 0; i < 12; i++ {
		labels = append(labels, fmt.Sprintf("%02d:00", i*2))
		responseTimes = append(responseTimes, 40.0+float64(i)*2.5)
		requestRates = append(requestRates, 50.0+float64(i)*5.0)
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"labels":         labels,
		"response_times": responseTimes,
		"request_rates":  requestRates,
	})
}

func (h *WebHandler) getSecretTags(c *gin.Context) {
	tags := []string{"production", "staging", "development", "api-key", "database", "service"}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"tags": tags,
	})
}

// Secrets handlers
func (h *WebHandler) getSecrets(c *gin.Context) {
	secrets := []map[string]interface{}{
		{
			"id":           "secret-001",
			"name":         "api-key-prod",
			"status":       "active",
			"tags":         []string{"production", "api"},
			"created_at":   time.Now().Add(-24 * time.Hour),
			"last_accessed": time.Now().Add(-1 * time.Hour),
		},
		{
			"id":           "secret-002",
			"name":         "db-password",
			"status":       "active",
			"tags":         []string{"database", "production"},
			"created_at":   time.Now().Add(-48 * time.Hour),
			"last_accessed": time.Now().Add(-30 * time.Minute),
		},
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"secrets": secrets,
		"total":   len(secrets),
	})
}

func (h *WebHandler) createSecret(c *gin.Context) {
	var secretData map[string]interface{}
	if err := c.ShouldBindJSON(&secretData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid secret data"})
		return
	}
	
	secret := map[string]interface{}{
		"id":         fmt.Sprintf("secret-%d", time.Now().Unix()),
		"name":       secretData["name"],
		"status":     "active",
		"created_at": time.Now(),
	}
	
	c.JSON(http.StatusCreated, secret)
}

func (h *WebHandler) getSecret(c *gin.Context) {
	secretId := c.Param("id")
	includeValue := c.Query("include_value") == "true"
	
	secret := map[string]interface{}{
		"id":         secretId,
		"name":       "api-key-prod",
		"status":     "active",
		"tags":       []string{"production", "api"},
		"created_at": time.Now().Add(-24 * time.Hour),
		"metadata":   map[string]string{"description": "Production API key"},
	}
	
	if includeValue {
		secret["value"] = "sk-1234567890abcdef"
	}
	
	c.JSON(http.StatusOK, secret)
}

func (h *WebHandler) updateSecret(c *gin.Context) {
	secretId := c.Param("id")
	
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid update data"})
		return
	}
	
	secret := map[string]interface{}{
		"id":         secretId,
		"updated_at": time.Now(),
	}
	
	c.JSON(http.StatusOK, secret)
}

func (h *WebHandler) deleteSecret(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Secret deleted successfully"})
}

func (h *WebHandler) rotateSecret(c *gin.Context) {
	secretId := c.Param("id")
	
	rotation := map[string]interface{}{
		"id":         fmt.Sprintf("rotation-%d", time.Now().Unix()),
		"secret_id":  secretId,
		"status":     "completed",
		"started_at": time.Now(),
	}
	
	c.JSON(http.StatusOK, rotation)
}

func (h *WebHandler) getSecretVersions(c *gin.Context) {
	versions := []map[string]interface{}{
		{
			"version":    2,
			"created_at": time.Now().Add(-1 * time.Hour),
			"created_by": "admin",
		},
		{
			"version":    1,
			"created_at": time.Now().Add(-24 * time.Hour),
			"created_by": "developer",
		},
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"versions": versions,
	})
}

// Policies handlers
func (h *WebHandler) getPolicies(c *gin.Context) {
	policies := []map[string]interface{}{
		{
			"id":          "policy-001",
			"name":        "admin-policy",
			"description": "Full administrative access",
			"priority":    100,
			"enabled":     true,
			"created_at":  time.Now().Add(-48 * time.Hour),
		},
		{
			"id":          "policy-002",
			"name":        "read-only",
			"description": "Read-only access to secrets",
			"priority":    200,
			"enabled":     true,
			"created_at":  time.Now().Add(-24 * time.Hour),
		},
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"policies": policies,
		"total":    len(policies),
	})
}

func (h *WebHandler) createPolicy(c *gin.Context) {
	var policyData map[string]interface{}
	if err := c.ShouldBindJSON(&policyData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy data"})
		return
	}
	
	policy := map[string]interface{}{
		"id":         fmt.Sprintf("policy-%d", time.Now().Unix()),
		"name":       policyData["name"],
		"enabled":    true,
		"created_at": time.Now(),
	}
	
	c.JSON(http.StatusCreated, policy)
}

func (h *WebHandler) getPolicy(c *gin.Context) {
	policyId := c.Param("id")
	
	policy := map[string]interface{}{
		"id":          policyId,
		"name":        "admin-policy",
		"description": "Full administrative access",
		"priority":    100,
		"enabled":     true,
		"rules": []map[string]interface{}{
			{
				"effect":    "allow",
				"actions":   []string{"*"},
				"resources": []string{"*"},
			},
		},
		"conditions": []map[string]interface{}{},
		"created_at": time.Now().Add(-48 * time.Hour),
	}
	
	c.JSON(http.StatusOK, policy)
}

func (h *WebHandler) updatePolicy(c *gin.Context) {
	policyId := c.Param("id")
	
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid update data"})
		return
	}
	
	policy := map[string]interface{}{
		"id":         policyId,
		"updated_at": time.Now(),
	}
	
	c.JSON(http.StatusOK, policy)
}

func (h *WebHandler) deletePolicy(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted successfully"})
}

func (h *WebHandler) validatePolicy(c *gin.Context) {
	var policyData map[string]interface{}
	if err := c.ShouldBindJSON(&policyData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy data"})
		return
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"valid":  true,
		"errors": []string{},
	})
}

// Users handlers
func (h *WebHandler) getUsers(c *gin.Context) {
	users := []map[string]interface{}{
		{
			"id":         "user-001",
			"username":   "admin",
			"email":      "admin@example.com",
			"roles":      []string{"admin"},
			"status":     "active",
			"created_at": time.Now().Add(-72 * time.Hour),
			"last_login": time.Now().Add(-1 * time.Hour),
		},
		{
			"id":         "user-002",
			"username":   "developer",
			"email":      "dev@example.com",
			"roles":      []string{"developer"},
			"status":     "active",
			"created_at": time.Now().Add(-48 * time.Hour),
			"last_login": time.Now().Add(-30 * time.Minute),
		},
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"users": users,
		"total": len(users),
	})
}

func (h *WebHandler) createUser(c *gin.Context) {
	var userData map[string]interface{}
	if err := c.ShouldBindJSON(&userData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user data"})
		return
	}
	
	user := map[string]interface{}{
		"id":         fmt.Sprintf("user-%d", time.Now().Unix()),
		"username":   userData["username"],
		"email":      userData["email"],
		"status":     "active",
		"created_at": time.Now(),
	}
	
	c.JSON(http.StatusCreated, user)
}

func (h *WebHandler) getUser(c *gin.Context) {
	userId := c.Param("id")
	
	user := map[string]interface{}{
		"id":         userId,
		"username":   "admin",
		"email":      "admin@example.com",
		"roles":      []string{"admin"},
		"status":     "active",
		"created_at": time.Now().Add(-72 * time.Hour),
		"last_login": time.Now().Add(-1 * time.Hour),
		"api_keys": []map[string]interface{}{
			{
				"name":       "CLI Key",
				"created_at": time.Now().Add(-24 * time.Hour),
			},
		},
	}
	
	c.JSON(http.StatusOK, user)
}

func (h *WebHandler) updateUser(c *gin.Context) {
	userId := c.Param("id")
	
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid update data"})
		return
	}
	
	user := map[string]interface{}{
		"id":         userId,
		"updated_at": time.Now(),
	}
	
	c.JSON(http.StatusOK, user)
}

func (h *WebHandler) deleteUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func (h *WebHandler) resetUserPassword(c *gin.Context) {
	password := fmt.Sprintf("temp-%d", time.Now().Unix())
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"temporary_password": password,
		"expires_at":        time.Now().Add(24 * time.Hour),
	})
}

// Configuration handlers
func (h *WebHandler) exportConfiguration(c *gin.Context) {
	config := map[string]interface{}{
		"version": "1.0",
		"settings": map[string]interface{}{
			"agent_name":    "vault-agent-01",
			"log_level":     "info",
			"enable_metrics": true,
		},
		"exported_at": time.Now(),
	}
	
	c.Header("Content-Disposition", "attachment; filename=vault-config.json")
	c.JSON(http.StatusOK, config)
}

func (h *WebHandler) importConfiguration(c *gin.Context) {
	file, err := c.FormFile("config")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No configuration file provided"})
		return
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"message":     "Configuration imported successfully",
		"filename":    file.Filename,
		"imported_at": time.Now(),
	})
}

func (h *WebHandler) testNotification(c *gin.Context) {
	var testData map[string]interface{}
	if err := c.ShouldBindJSON(&testData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid test data"})
		return
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Test notification sent to %s channel", testData["channel"]),
		"sent_at": time.Now(),
	})
}

func (h *WebHandler) getAuditLogs(c *gin.Context) {
	logs := []map[string]interface{}{
		{
			"id":         "audit-001",
			"timestamp":  time.Now().Add(-1 * time.Hour),
			"event_type": "secret_access",
			"actor":      map[string]string{"username": "admin", "id": "user-001"},
			"resource":   map[string]string{"type": "secret", "id": "secret-001"},
			"action":     "read",
			"result":     "success",
			"ip_address": "192.168.1.100",
			"context":    map[string]interface{}{"method": "GET"},
		},
		{
			"id":         "audit-002",
			"timestamp":  time.Now().Add(-2 * time.Hour),
			"event_type": "secret_create",
			"actor":      map[string]string{"username": "developer", "id": "user-002"},
			"resource":   map[string]string{"type": "secret", "id": "secret-002"},
			"action":     "create",
			"result":     "success",
			"ip_address": "192.168.1.101",
			"context":    map[string]interface{}{"method": "POST"},
		},
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"logs": logs,
	})
}

func (h *WebHandler) exportAuditLogs(c *gin.Context) {
	format := c.Query("format")
	
	if format == "csv" {
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", "attachment; filename=audit-logs.csv")
		c.String(http.StatusOK, "timestamp,event_type,actor,resource,action,result,ip_address\n")
		c.String(http.StatusOK, "%s,secret_access,admin,secret:secret-001,read,success,192.168.1.100\n", time.Now().Format(time.RFC3339))
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported format"})
	}
}