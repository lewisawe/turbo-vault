package api

import (
	"time"

	"github.com/keyvault/agent/internal/storage"
)

// APIVersion represents the API version
const APIVersion = "v1"

// APIResponse represents a standard API response wrapper
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	Metadata  *Metadata   `json:"metadata,omitempty"`
	RequestID string      `json:"request_id"`
	Timestamp time.Time   `json:"timestamp"`
}

// APIError represents a structured error response
type APIError struct {
	Type      ErrorType              `json:"type"`
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	RequestID string                 `json:"request_id"`
	Timestamp time.Time              `json:"timestamp"`
}

// ErrorType represents different categories of errors
type ErrorType string

const (
	ErrorTypeValidation    ErrorType = "validation"
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeAuthorization  ErrorType = "authorization"
	ErrorTypeNotFound      ErrorType = "not_found"
	ErrorTypeConflict      ErrorType = "conflict"
	ErrorTypeRateLimit     ErrorType = "rate_limit"
	ErrorTypeInternal      ErrorType = "internal"
	ErrorTypeUnavailable   ErrorType = "unavailable"
)

// Metadata contains pagination and additional response metadata
type Metadata struct {
	Page       int `json:"page,omitempty"`
	PerPage    int `json:"per_page,omitempty"`
	Total      int `json:"total,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

// CreateSecretRequest represents the request to create a new secret
type CreateSecretRequest struct {
	Name        string            `json:"name" binding:"required,min=1,max=255" example:"database-password"`
	Value       string            `json:"value" binding:"required,min=1" example:"super-secret-password"`
	Description string            `json:"description,omitempty" binding:"max=1000" example:"Database connection password"`
	Metadata    map[string]string `json:"metadata,omitempty" example:"environment:production,service:api"`
	Tags        []string          `json:"tags,omitempty" example:"database,production,critical"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty" example:"2025-12-31T23:59:59Z"`
	RotationDue *time.Time        `json:"rotation_due,omitempty" example:"2025-10-01T00:00:00Z"`
}

// UpdateSecretRequest represents the request to update an existing secret
type UpdateSecretRequest struct {
	Name        *string            `json:"name,omitempty" binding:"omitempty,min=1,max=255" example:"database-password-updated"`
	Value       *string            `json:"value,omitempty" binding:"omitempty,min=1" example:"new-super-secret-password"`
	Description *string            `json:"description,omitempty" binding:"omitempty,max=1000" example:"Updated database connection password"`
	Metadata    *map[string]string `json:"metadata,omitempty" example:"environment:production,service:api,updated:true"`
	Tags        *[]string          `json:"tags,omitempty" example:"database,production,critical,updated"`
	ExpiresAt   *time.Time         `json:"expires_at,omitempty" example:"2026-12-31T23:59:59Z"`
	RotationDue *time.Time         `json:"rotation_due,omitempty" example:"2025-11-01T00:00:00Z"`
}

// SecretResponse represents a secret in API responses (without value by default)
type SecretResponse struct {
	ID           string            `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Name         string            `json:"name" example:"database-password"`
	Description  string            `json:"description,omitempty" example:"Database connection password"`
	Metadata     map[string]string `json:"metadata,omitempty" example:"environment:production,service:api"`
	Tags         []string          `json:"tags,omitempty" example:"database,production,critical"`
	CreatedAt    time.Time         `json:"created_at" example:"2025-09-11T10:00:00Z"`
	UpdatedAt    time.Time         `json:"updated_at" example:"2025-09-11T10:00:00Z"`
	ExpiresAt    *time.Time        `json:"expires_at,omitempty" example:"2025-12-31T23:59:59Z"`
	RotationDue  *time.Time        `json:"rotation_due,omitempty" example:"2025-10-01T00:00:00Z"`
	Version      int               `json:"version" example:"1"`
	CreatedBy    string            `json:"created_by" example:"user@example.com"`
	AccessCount  int64             `json:"access_count" example:"42"`
	LastAccessed *time.Time        `json:"last_accessed,omitempty" example:"2025-09-11T09:30:00Z"`
	Status       storage.SecretStatus `json:"status" example:"active"`
}

// SecretValueResponse represents a secret with its decrypted value
type SecretValueResponse struct {
	SecretResponse
	Value string `json:"value" example:"super-secret-password"`
}

// ListSecretsRequest represents query parameters for listing secrets
type ListSecretsRequest struct {
	NamePattern  string               `form:"name_pattern" binding:"omitempty,max=255" example:"database*"`
	Tags         []string             `form:"tags" binding:"omitempty" example:"production,database"`
	Status       storage.SecretStatus `form:"status" binding:"omitempty,oneof=active deprecated deleted expired" example:"active"`
	CreatedAfter *time.Time           `form:"created_after" binding:"omitempty" example:"2025-01-01T00:00:00Z"`
	CreatedBy    string               `form:"created_by" binding:"omitempty,max=255" example:"user@example.com"`
	Page         int                  `form:"page" binding:"omitempty,min=1" example:"1"`
	PerPage      int                  `form:"per_page" binding:"omitempty,min=1,max=100" example:"20"`
}

// RotateSecretRequest represents the request to rotate a secret
type RotateSecretRequest struct {
	NewValue string `json:"new_value" binding:"required,min=1" example:"new-rotated-password"`
	Reason   string `json:"reason,omitempty" binding:"max=500" example:"Scheduled rotation"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string            `json:"status" example:"healthy"`
	Version   string            `json:"version" example:"1.0.0"`
	Timestamp time.Time         `json:"timestamp" example:"2025-09-11T10:00:00Z"`
	Checks    map[string]string `json:"checks" example:"database:healthy,encryption:healthy"`
}

// MetricsResponse represents basic metrics response
type MetricsResponse struct {
	TotalSecrets    int64     `json:"total_secrets" example:"150"`
	ActiveSecrets   int64     `json:"active_secrets" example:"140"`
	ExpiredSecrets  int64     `json:"expired_secrets" example:"5"`
	RequestsPerSec  float64   `json:"requests_per_sec" example:"45.2"`
	AvgResponseTime float64   `json:"avg_response_time_ms" example:"12.5"`
	Uptime          string    `json:"uptime" example:"72h30m15s"`
	LastUpdated     time.Time `json:"last_updated" example:"2025-09-11T10:00:00Z"`
}

// ValidationError represents a field validation error
type ValidationError struct {
	Field   string `json:"field" example:"name"`
	Message string `json:"message" example:"Name is required"`
	Value   string `json:"value,omitempty" example:""`
}

// ToStorageSecret converts CreateSecretRequest to storage.Secret
func (r *CreateSecretRequest) ToStorageSecret() *storage.Secret {
	return &storage.Secret{
		Name:        r.Name,
		Value:       r.Value,
		Metadata:    r.Metadata,
		Tags:        r.Tags,
		ExpiresAt:   r.ExpiresAt,
		RotationDue: r.RotationDue,
	}
}

// ToStorageFilter converts ListSecretsRequest to storage.SecretFilter
func (r *ListSecretsRequest) ToStorageFilter() *storage.SecretFilter {
	filter := &storage.SecretFilter{
		NamePattern:  r.NamePattern,
		Tags:         r.Tags,
		Status:       r.Status,
		CreatedAfter: r.CreatedAfter,
		CreatedBy:    r.CreatedBy,
	}

	// Set pagination
	if r.Page > 0 && r.PerPage > 0 {
		filter.Limit = r.PerPage
		filter.Offset = (r.Page - 1) * r.PerPage
	}

	return filter
}

// FromStorageSecret converts storage.Secret to SecretResponse
func FromStorageSecret(secret *storage.Secret) *SecretResponse {
	return &SecretResponse{
		ID:           secret.ID,
		Name:         secret.Name,
		Metadata:     secret.Metadata,
		Tags:         secret.Tags,
		CreatedAt:    secret.CreatedAt,
		UpdatedAt:    secret.UpdatedAt,
		ExpiresAt:    secret.ExpiresAt,
		RotationDue:  secret.RotationDue,
		Version:      secret.Version,
		CreatedBy:    secret.CreatedBy,
		AccessCount:  secret.AccessCount,
		LastAccessed: secret.LastAccessed,
		Status:       secret.Status,
	}
}

// FromStorageSecretWithValue converts storage.Secret to SecretValueResponse
func FromStorageSecretWithValue(secret *storage.Secret) *SecretValueResponse {
	return &SecretValueResponse{
		SecretResponse: *FromStorageSecret(secret),
		Value:          secret.Value,
	}
}