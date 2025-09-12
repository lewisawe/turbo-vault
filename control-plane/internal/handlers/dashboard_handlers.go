package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/keyvault/control-plane/internal/dashboard"
)

// DashboardHandlers provides HTTP handlers for dashboard operations
type DashboardHandlers struct {
	dashboard dashboard.DashboardService
}

// NewDashboardHandlers creates new dashboard handlers
func NewDashboardHandlers(dashboard dashboard.DashboardService) *DashboardHandlers {
	return &DashboardHandlers{dashboard: dashboard}
}

// GetOverview handles system overview requests
func (h *DashboardHandlers) GetOverview(c *gin.Context) {
	orgID := c.Param("orgId")
	
	overview, err := h.dashboard.GetOverview(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, overview)
}

// GetVaultSummary handles vault summary requests
func (h *DashboardHandlers) GetVaultSummary(c *gin.Context) {
	orgID := c.Param("orgId")
	
	summary, err := h.dashboard.GetVaultSummary(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// GetPerformanceMetrics handles performance metrics requests
func (h *DashboardHandlers) GetPerformanceMetrics(c *gin.Context) {
	orgID := c.Param("orgId")
	timeRange := c.DefaultQuery("timeRange", "24h")
	
	metrics, err := h.dashboard.GetPerformanceMetrics(c.Request.Context(), orgID, timeRange)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, metrics)
}

// GetSecurityDashboard handles security dashboard requests
func (h *DashboardHandlers) GetSecurityDashboard(c *gin.Context) {
	orgID := c.Param("orgId")
	
	security, err := h.dashboard.GetSecurityDashboard(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, security)
}

// GetAlerts handles alerts dashboard requests
func (h *DashboardHandlers) GetAlerts(c *gin.Context) {
	orgID := c.Param("orgId")
	
	alerts, err := h.dashboard.GetAlerts(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, alerts)
}

// GetUsageAnalytics handles usage analytics requests
func (h *DashboardHandlers) GetUsageAnalytics(c *gin.Context) {
	orgID := c.Param("orgId")
	period := c.DefaultQuery("period", "daily")
	
	analytics, err := h.dashboard.GetUsageAnalytics(c.Request.Context(), orgID, period)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, analytics)
}

// GetCapacityPlanning handles capacity planning requests
func (h *DashboardHandlers) GetCapacityPlanning(c *gin.Context) {
	orgID := c.Param("orgId")
	
	capacity, err := h.dashboard.GetCapacityPlanning(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, capacity)
}

// GetComplianceStatus handles compliance status requests
func (h *DashboardHandlers) GetComplianceStatus(c *gin.Context) {
	orgID := c.Param("orgId")
	
	compliance, err := h.dashboard.GetComplianceStatus(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, compliance)
}