package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/keyvault/control-plane/internal/registry"
)

// VaultHandlers provides HTTP handlers for vault registry operations
type VaultHandlers struct {
	registry registry.VaultRegistry
}

// NewVaultHandlers creates new vault handlers
func NewVaultHandlers(registry registry.VaultRegistry) *VaultHandlers {
	return &VaultHandlers{registry: registry}
}

// RegisterVault handles vault registration requests
func (h *VaultHandlers) RegisterVault(c *gin.Context) {
	var req registry.RegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	vault, err := h.registry.RegisterVault(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, vault)
}

// UpdateHeartbeat handles vault heartbeat updates
func (h *VaultHandlers) UpdateHeartbeat(c *gin.Context) {
	var req registry.HeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.registry.UpdateHeartbeat(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ListVaults handles vault listing requests
func (h *VaultHandlers) ListVaults(c *gin.Context) {
	var filter registry.VaultFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.registry.ListVaults(c.Request.Context(), &filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetVault handles individual vault retrieval
func (h *VaultHandlers) GetVault(c *gin.Context) {
	vaultID := c.Param("id")
	
	vault, err := h.registry.GetVault(c.Request.Context(), vaultID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Vault not found"})
		return
	}

	c.JSON(http.StatusOK, vault)
}

// DeregisterVault handles vault deregistration
func (h *VaultHandlers) DeregisterVault(c *gin.Context) {
	vaultID := c.Param("id")
	
	if err := h.registry.DeregisterVault(c.Request.Context(), vaultID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deregistered"})
}