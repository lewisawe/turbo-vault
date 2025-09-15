package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/keyvault/agent/internal/storage"
)

// SecretHandler handles secret-related API operations
type SecretHandler struct {
	storage storage.StorageBackend
}

// NewSecretHandler creates a new SecretHandler
func NewSecretHandler(storage storage.StorageBackend) *SecretHandler {
	return &SecretHandler{
		storage: storage,
	}
}

// CreateSecret creates a new secret
// @Summary Create a new secret
// @Description Create a new secret with encrypted storage
// @Tags secrets
// @Accept json
// @Produce json
// @Param secret body CreateSecretRequest true "Secret to create"
// @Success 201 {object} APIResponse{data=SecretResponse}
// @Failure 400 {object} APIResponse{error=APIError}
// @Failure 409 {object} APIResponse{error=APIError}
// @Failure 500 {object} APIResponse{error=APIError}
// @Router /api/v1/secrets [post]
func (h *SecretHandler) CreateSecret(c *gin.Context) {
	var req CreateSecretRequest
	if !ValidateRequest(c, &req) {
		return
	}

	// Convert request to storage secret
	secret := req.ToStorageSecret()
	secret.ID = uuid.New().String()
	secret.CreatedBy = h.getCurrentUser(c)

	// Create the secret
	if err := h.storage.CreateSecret(context.Background(), secret); err != nil {
		h.respondWithError(c, http.StatusInternalServerError, ErrorTypeInternal, "CREATE_FAILED",
			"Failed to create secret", map[string]interface{}{"error": err.Error()})
		return
	}

	// Return the created secret (without value)
	response := FromStorageSecret(secret)
	h.respondWithSuccess(c, http.StatusCreated, response, nil)
}

// GetSecret retrieves a secret by ID (metadata only)
// @Summary Get secret metadata
// @Description Get secret metadata without the actual value
// @Tags secrets
// @Produce json
// @Param id path string true "Secret ID"
// @Success 200 {object} APIResponse{data=SecretResponse}
// @Failure 404 {object} APIResponse{error=APIError}
// @Failure 500 {object} APIResponse{error=APIError}
// @Router /api/v1/secrets/{id} [get]
func (h *SecretHandler) GetSecret(c *gin.Context) {
	id := c.Param("id")
	if !h.validateUUID(c, id) {
		return
	}

	secret, err := h.storage.GetSecret(context.Background(), id)
	if err != nil {
		h.handleStorageError(c, err, "Secret not found")
		return
	}

	response := FromStorageSecret(secret)
	h.respondWithSuccess(c, http.StatusOK, response, nil)
}

// GetSecretValue retrieves a secret's decrypted value
// @Summary Get secret value
// @Description Get the decrypted value of a secret
// @Tags secrets
// @Produce json
// @Param id path string true "Secret ID"
// @Success 200 {object} APIResponse{data=SecretValueResponse}
// @Failure 404 {object} APIResponse{error=APIError}
// @Failure 500 {object} APIResponse{error=APIError}
// @Router /api/v1/secrets/{id}/value [get]
func (h *SecretHandler) GetSecretValue(c *gin.Context) {
	id := c.Param("id")
	if !h.validateUUID(c, id) {
		return
	}

	secret, err := h.storage.GetSecret(context.Background(), id)
	if err != nil {
		h.handleStorageError(c, err, "Secret not found")
		return
	}

	response := FromStorageSecretWithValue(secret)
	h.respondWithSuccess(c, http.StatusOK, response, nil)
}

// UpdateSecret updates an existing secret
// @Summary Update a secret
// @Description Update an existing secret's metadata and/or value
// @Tags secrets
// @Accept json
// @Produce json
// @Param id path string true "Secret ID"
// @Param secret body UpdateSecretRequest true "Secret updates"
// @Success 200 {object} APIResponse{data=SecretResponse}
// @Failure 400 {object} APIResponse{error=APIError}
// @Failure 404 {object} APIResponse{error=APIError}
// @Failure 500 {object} APIResponse{error=APIError}
// @Router /api/v1/secrets/{id} [put]
func (h *SecretHandler) UpdateSecret(c *gin.Context) {
	id := c.Param("id")
	if !h.validateUUID(c, id) {
		return
	}

	var req UpdateSecretRequest
	if !ValidateRequest(c, &req) {
		return
	}

	// Get existing secret
	existing, err := h.storage.GetSecret(context.Background(), id)
	if err != nil {
		h.handleStorageError(c, err, "Secret not found")
		return
	}

	// Apply updates
	h.applySecretUpdates(existing, &req)

	// Update the secret
	if err := h.storage.UpdateSecret(context.Background(), id, existing); err != nil {
		h.respondWithError(c, http.StatusInternalServerError, ErrorTypeInternal, "UPDATE_FAILED",
			"Failed to update secret", map[string]interface{}{"error": err.Error()})
		return
	}

	response := FromStorageSecret(existing)
	h.respondWithSuccess(c, http.StatusOK, response, nil)
}

// DeleteSecret deletes a secret
// @Summary Delete a secret
// @Description Permanently delete a secret
// @Tags secrets
// @Produce json
// @Param id path string true "Secret ID"
// @Success 200 {object} APIResponse{data=map[string]string}
// @Failure 404 {object} APIResponse{error=APIError}
// @Failure 500 {object} APIResponse{error=APIError}
// @Router /api/v1/secrets/{id} [delete]
func (h *SecretHandler) DeleteSecret(c *gin.Context) {
	id := c.Param("id")
	if !h.validateUUID(c, id) {
		return
	}

	// Check if secret exists
	_, err := h.storage.GetSecret(context.Background(), id)
	if err != nil {
		h.handleStorageError(c, err, "Secret not found")
		return
	}

	// Delete the secret
	if err := h.storage.DeleteSecret(context.Background(), id); err != nil {
		h.respondWithError(c, http.StatusInternalServerError, ErrorTypeInternal, "DELETE_FAILED",
			"Failed to delete secret", map[string]interface{}{"error": err.Error()})
		return
	}

	h.respondWithSuccess(c, http.StatusOK, map[string]string{
		"message": "Secret deleted successfully",
		"id":      id,
	}, nil)
}

// ListSecrets lists secrets with filtering and pagination
// @Summary List secrets
// @Description List secrets with optional filtering and pagination (metadata only)
// @Tags secrets
// @Produce json
// @Param name_pattern query string false "Name pattern filter"
// @Param tags query []string false "Tags filter"
// @Param status query string false "Status filter" Enums(active, deprecated, deleted, expired)
// @Param created_after query string false "Created after filter (RFC3339)"
// @Param created_by query string false "Created by filter"
// @Param page query int false "Page number" minimum(1)
// @Param per_page query int false "Items per page" minimum(1) maximum(100)
// @Success 200 {object} APIResponse{data=[]SecretResponse,metadata=Metadata}
// @Failure 400 {object} APIResponse{error=APIError}
// @Failure 500 {object} APIResponse{error=APIError}
// @Router /api/v1/secrets [get]
func (h *SecretHandler) ListSecrets(c *gin.Context) {
	var req ListSecretsRequest
	if !ValidateQueryParams(c, &req) {
		return
	}

	// Validate pagination parameters
	if req.Page < 0 {
		h.respondWithError(c, http.StatusBadRequest, ErrorTypeValidation, "VALIDATION_FAILED",
			"Page must be greater than 0", map[string]interface{}{"page": req.Page})
		return
	}
	if req.PerPage < 0 || req.PerPage > 100 {
		h.respondWithError(c, http.StatusBadRequest, ErrorTypeValidation, "VALIDATION_FAILED",
			"Per page must be between 1 and 100", map[string]interface{}{"per_page": req.PerPage})
		return
	}

	// Set defaults
	if req.Page == 0 {
		req.Page = 1
	}
	if req.PerPage == 0 {
		req.PerPage = 20
	}

	filter := req.ToStorageFilter()
	secrets, err := h.storage.ListSecrets(context.Background(), filter)
	if err != nil {
		h.respondWithError(c, http.StatusInternalServerError, ErrorTypeInternal, "LIST_FAILED",
			"Failed to list secrets", map[string]interface{}{"error": err.Error()})
		return
	}

	// Convert to response format
	var responses []*SecretResponse
	for _, secret := range secrets {
		responses = append(responses, FromStorageSecret(secret))
	}

	// Calculate metadata
	total := len(responses) // In a real implementation, you'd get this from a count query
	metadata := &Metadata{
		Page:       req.Page,
		PerPage:    req.PerPage,
		Total:      total,
		TotalPages: (total + req.PerPage - 1) / req.PerPage,
	}

	h.respondWithSuccess(c, http.StatusOK, responses, metadata)
}

// RotateSecret rotates a secret's value
// @Summary Rotate a secret
// @Description Rotate a secret by updating its value and resetting rotation schedule
// @Tags secrets
// @Accept json
// @Produce json
// @Param id path string true "Secret ID"
// @Param rotation body RotateSecretRequest true "Rotation request"
// @Success 200 {object} APIResponse{data=SecretResponse}
// @Failure 400 {object} APIResponse{error=APIError}
// @Failure 404 {object} APIResponse{error=APIError}
// @Failure 500 {object} APIResponse{error=APIError}
// @Router /api/v1/secrets/{id}/rotate [post]
func (h *SecretHandler) RotateSecret(c *gin.Context) {
	id := c.Param("id")
	if !h.validateUUID(c, id) {
		return
	}

	var req RotateSecretRequest
	if !ValidateRequest(c, &req) {
		return
	}

	// Get existing secret
	secret, err := h.storage.GetSecret(context.Background(), id)
	if err != nil {
		h.handleStorageError(c, err, "Secret not found")
		return
	}

	// Update with new value and reset rotation schedule
	secret.Value = req.NewValue
	if secret.RotationDue != nil {
		// Set next rotation to 30 days from now (configurable)
		nextRotation := time.Now().AddDate(0, 0, 30)
		secret.RotationDue = &nextRotation
	}

	// Update the secret
	if err := h.storage.UpdateSecret(context.Background(), id, secret); err != nil {
		h.respondWithError(c, http.StatusInternalServerError, ErrorTypeInternal, "ROTATION_FAILED",
			"Failed to rotate secret", map[string]interface{}{"error": err.Error()})
		return
	}

	response := FromStorageSecret(secret)
	h.respondWithSuccess(c, http.StatusOK, response, nil)
}

// Helper methods

func (h *SecretHandler) validateUUID(c *gin.Context, id string) bool {
	if _, err := uuid.Parse(id); err != nil {
		h.respondWithError(c, http.StatusBadRequest, ErrorTypeValidation, "INVALID_UUID",
			"Invalid UUID format", map[string]interface{}{"id": id})
		return false
	}
	return true
}

func (h *SecretHandler) getCurrentUser(c *gin.Context) string {
	// Use the GetCurrentUser helper from auth middleware
	if user := GetCurrentUser(c); user != nil {
		return user.Username
	}
	return "system"
}

func (h *SecretHandler) applySecretUpdates(secret *storage.Secret, req *UpdateSecretRequest) {
	if req.Name != nil {
		secret.Name = *req.Name
	}
	if req.Value != nil {
		secret.Value = *req.Value
	}
	if req.Metadata != nil {
		secret.Metadata = *req.Metadata
	}
	if req.Tags != nil {
		secret.Tags = *req.Tags
	}
	if req.ExpiresAt != nil {
		secret.ExpiresAt = req.ExpiresAt
	}
	if req.RotationDue != nil {
		secret.RotationDue = req.RotationDue
	}
}

func (h *SecretHandler) handleStorageError(c *gin.Context, err error, defaultMessage string) {
	// In a real implementation, you'd check specific error types
	h.respondWithError(c, http.StatusNotFound, ErrorTypeNotFound, "NOT_FOUND",
		defaultMessage, map[string]interface{}{"error": err.Error()})
}

func (h *SecretHandler) respondWithSuccess(c *gin.Context, status int, data interface{}, metadata *Metadata) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		Metadata:  metadata,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}
	c.JSON(status, response)
}

func (h *SecretHandler) respondWithError(c *gin.Context, status int, errorType ErrorType, code, message string, details map[string]interface{}) {
	apiError := &APIError{
		Type:      errorType,
		Code:      code,
		Message:   message,
		Details:   details,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(status, response)
}

// HealthHandler handles health check operations
type HealthHandler struct {
	storage storage.StorageBackend
	version string
}

// NewHealthHandler creates a new HealthHandler
func NewHealthHandler(storage storage.StorageBackend, version string) *HealthHandler {
	return &HealthHandler{
		storage: storage,
		version: version,
	}
}

// GetHealth returns the health status of the service
// @Summary Health check
// @Description Get the health status of the vault agent
// @Tags health
// @Produce json
// @Success 200 {object} APIResponse{data=HealthResponse}
// @Failure 503 {object} APIResponse{error=APIError}
// @Router /health [get]
func (h *HealthHandler) GetHealth(c *gin.Context) {
	checks := make(map[string]string)
	
	// Check database connectivity
	if err := h.storage.HealthCheck(context.Background()); err != nil {
		checks["database"] = "unhealthy: " + err.Error()
		h.respondWithError(c, http.StatusServiceUnavailable, ErrorTypeUnavailable, "SERVICE_UNHEALTHY",
			"Service is unhealthy", map[string]interface{}{"checks": checks})
		return
	}
	checks["database"] = "healthy"
	
	// Add more health checks as needed
	checks["encryption"] = "healthy"

	response := &HealthResponse{
		Status:    "healthy",
		Version:   h.version,
		Timestamp: GetCurrentTime(),
		Checks:    checks,
	}

	h.respondWithSuccess(c, http.StatusOK, response, nil)
}

func (h *HealthHandler) respondWithSuccess(c *gin.Context, status int, data interface{}, metadata *Metadata) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		Metadata:  metadata,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}
	c.JSON(status, response)
}

func (h *HealthHandler) respondWithError(c *gin.Context, status int, errorType ErrorType, code, message string, details map[string]interface{}) {
	apiError := &APIError{
		Type:      errorType,
		Code:      code,
		Message:   message,
		Details:   details,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(status, response)
}