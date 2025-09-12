package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/keyvault/control-plane/internal/monitoring"
)

// MonitoringHandlers provides HTTP handlers for monitoring operations
type MonitoringHandlers struct {
	monitoring monitoring.MonitoringService
}

// NewMonitoringHandlers creates new monitoring handlers
func NewMonitoringHandlers(monitoring monitoring.MonitoringService) *MonitoringHandlers {
	return &MonitoringHandlers{monitoring: monitoring}
}

// GetMonitoringStats handles monitoring statistics requests
func (h *MonitoringHandlers) GetMonitoringStats(c *gin.Context) {
	stats, err := h.monitoring.GetMonitoringStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetEvents handles monitoring events requests
func (h *MonitoringHandlers) GetEvents(c *gin.Context) {
	var filter monitoring.EventFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	events, err := h.monitoring.GetEvents(c.Request.Context(), &filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, events)
}

// CheckVaultHealth handles vault health check requests
func (h *MonitoringHandlers) CheckVaultHealth(c *gin.Context) {
	vaultID := c.Param("id")
	
	health, err := h.monitoring.CheckVaultHealth(c.Request.Context(), vaultID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, health)
}

// CreateAlertRule handles alert rule creation
func (h *MonitoringHandlers) CreateAlertRule(c *gin.Context) {
	var rule monitoring.AlertRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.monitoring.CreateAlertRule(c.Request.Context(), &rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, rule)
}

// GetAlertRules handles alert rules listing
func (h *MonitoringHandlers) GetAlertRules(c *gin.Context) {
	rules, err := h.monitoring.GetAlertRules(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, rules)
}