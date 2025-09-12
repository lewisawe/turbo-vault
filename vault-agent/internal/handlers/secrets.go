package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/keyvault/agent/internal/storage"
)

func CreateSecret(store *storage.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name        string            `json:"name" binding:"required"`
			Value       string            `json:"value" binding:"required"`
			Metadata    map[string]string `json:"metadata"`
			ExpiresAt   *time.Time        `json:"expires_at"`
			RotationDue *time.Time        `json:"rotation_due"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		secret := &storage.Secret{
			ID:          uuid.New().String(),
			Name:        req.Name,
			Value:       req.Value,
			Metadata:    req.Metadata,
			ExpiresAt:   req.ExpiresAt,
			RotationDue: req.RotationDue,
		}

		if err := store.CreateSecret(c.Request.Context(), secret); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create secret"})
			return
		}

		// Don't return the actual value in response
		secret.Value = ""
		c.JSON(http.StatusCreated, secret)
	}
}

func GetSecret(store *storage.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		
		secret, err := store.GetSecret(c.Request.Context(), id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
			return
		}

		c.JSON(http.StatusOK, secret)
	}
}

func UpdateSecret(store *storage.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		
		var req struct {
			Name        string            `json:"name"`
			Value       string            `json:"value"`
			Metadata    map[string]string `json:"metadata"`
			ExpiresAt   *time.Time        `json:"expires_at"`
			RotationDue *time.Time        `json:"rotation_due"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		secret := &storage.Secret{
			ID:          id,
			Name:        req.Name,
			Value:       req.Value,
			Metadata:    req.Metadata,
			ExpiresAt:   req.ExpiresAt,
			RotationDue: req.RotationDue,
		}

		if err := store.UpdateSecret(c.Request.Context(), id, secret); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update secret"})
			return
		}

		secret.Value = ""
		c.JSON(http.StatusOK, secret)
	}
}

func DeleteSecret(store *storage.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		
		if err := store.DeleteSecret(c.Request.Context(), id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete secret"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Secret deleted successfully"})
	}
}

func ListSecrets(store *storage.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {
		secrets, err := store.ListSecrets(c.Request.Context(), &storage.SecretFilter{})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list secrets"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"secrets": secrets})
	}
}

func RotateSecret(store *storage.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		
		var req struct {
			NewValue string `json:"new_value" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Get existing secret
		secret, err := store.GetSecret(id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
			return
		}

		// Update with new value and reset rotation due date
		secret.Value = req.NewValue
		if secret.RotationDue != nil {
			// Set next rotation to 30 days from now (configurable)
			nextRotation := time.Now().AddDate(0, 0, 30)
			secret.RotationDue = &nextRotation
		}

		if err := store.UpdateSecret(id, secret); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rotate secret"})
			return
		}

		secret.Value = ""
		c.JSON(http.StatusOK, gin.H{
			"message": "Secret rotated successfully",
			"secret":  secret,
		})
	}
}