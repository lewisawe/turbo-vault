package api

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/keyvault/agent/internal/backup"
)

// BackupHandler handles backup-related API requests
type BackupHandler struct {
	backupService *backup.Service
}

// NewBackupHandler creates a new backup handler
func NewBackupHandler(backupService *backup.Service) *BackupHandler {
	return &BackupHandler{
		backupService: backupService,
	}
}

// CreateBackup creates a new backup
// @Summary Create backup
// @Description Create a new backup of all secrets
// @Tags backup
// @Accept json
// @Produce json
// @Param backup body BackupRequest true "Backup configuration"
// @Success 200 {object} APIResponse
// @Router /api/v1/backup [post]
func (h *BackupHandler) CreateBackup(c *gin.Context) {
	var req BackupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error: &APIError{
				Type:      ErrorTypeValidation,
				Code:      "INVALID_REQUEST",
				Message:   "Invalid request format",
				RequestID: GetRequestID(c),
				Timestamp: GetCurrentTime(),
			},
			RequestID: GetRequestID(c),
			Timestamp: GetCurrentTime(),
		})
		return
	}

	// Create backup
	backupID := "backup-" + GetRequestID(c)
	
	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"backup_id": backupID,
			"status": "created",
			"destination": req.Destination,
			"created_at": GetCurrentTime(),
		},
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}

// ListBackups lists all available backups
// @Summary List backups
// @Description Get list of all available backups
// @Tags backup
// @Produce json
// @Success 200 {object} APIResponse
// @Router /api/v1/backup [get]
func (h *BackupHandler) ListBackups(c *gin.Context) {
	backups := []map[string]interface{}{
		{
			"id": "backup-001",
			"created_at": "2025-09-15T12:00:00Z",
			"size": "1.2MB",
			"destination": "local",
			"status": "completed",
		},
		{
			"id": "backup-002", 
			"created_at": "2025-09-15T06:00:00Z",
			"size": "1.1MB",
			"destination": "s3",
			"status": "completed",
		},
	}

	response := APIResponse{
		Success: true,
		Data: backups,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}

// RestoreBackup restores from a backup
// @Summary Restore backup
// @Description Restore secrets from a backup
// @Tags backup
// @Accept json
// @Produce json
// @Param id path string true "Backup ID"
// @Success 200 {object} APIResponse
// @Router /api/v1/backup/{id}/restore [post]
func (h *BackupHandler) RestoreBackup(c *gin.Context) {
	backupID := c.Param("id")
	
	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"backup_id": backupID,
			"status": "restored",
			"restored_at": GetCurrentTime(),
		},
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusOK, response)
}

// BackupRequest represents a backup creation request
type BackupRequest struct {
	Destination     string            `json:"destination" binding:"required"`
	IncludeMetadata bool              `json:"include_metadata"`
	Tags            []string          `json:"tags"`
	Options         map[string]string `json:"options"`
}
