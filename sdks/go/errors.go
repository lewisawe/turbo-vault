package vaultagent

import (
	"fmt"
	"net/http"
)

// VaultAgentError represents a general Vault Agent error
type VaultAgentError struct {
	Message   string                 `json:"message"`
	Code      string                 `json:"code,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
}

func (e *VaultAgentError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("[%s] %s", e.Code, e.Message)
	}
	return e.Message
}

// AuthenticationError represents authentication failures
type AuthenticationError struct {
	*VaultAgentError
}

func NewAuthenticationError(message string) *AuthenticationError {
	return &AuthenticationError{
		VaultAgentError: &VaultAgentError{
			Message: message,
			Code:    "AUTHENTICATION_ERROR",
		},
	}
}

// AuthorizationError represents authorization failures
type AuthorizationError struct {
	*VaultAgentError
}

func NewAuthorizationError(message string) *AuthorizationError {
	return &AuthorizationError{
		VaultAgentError: &VaultAgentError{
			Message: message,
			Code:    "AUTHORIZATION_ERROR",
		},
	}
}

// NotFoundError represents resource not found errors
type NotFoundError struct {
	*VaultAgentError
}

func NewNotFoundError(message string) *NotFoundError {
	return &NotFoundError{
		VaultAgentError: &VaultAgentError{
			Message: message,
			Code:    "NOT_FOUND",
		},
	}
}

// ValidationError represents validation failures
type ValidationError struct {
	*VaultAgentError
}

func NewValidationError(message string) *ValidationError {
	return &ValidationError{
		VaultAgentError: &VaultAgentError{
			Message: message,
			Code:    "VALIDATION_ERROR",
		},
	}
}

// RateLimitError represents rate limiting errors
type RateLimitError struct {
	*VaultAgentError
	RetryAfter int `json:"retry_after,omitempty"`
}

func NewRateLimitError(message string, retryAfter int) *RateLimitError {
	return &RateLimitError{
		VaultAgentError: &VaultAgentError{
			Message: message,
			Code:    "RATE_LIMIT_ERROR",
		},
		RetryAfter: retryAfter,
	}
}

// ConnectionError represents connection failures
type ConnectionError struct {
	*VaultAgentError
}

func NewConnectionError(message string) *ConnectionError {
	return &ConnectionError{
		VaultAgentError: &VaultAgentError{
			Message: message,
			Code:    "CONNECTION_ERROR",
		},
	}
}

// ConfigurationError represents configuration errors
type ConfigurationError struct {
	*VaultAgentError
}

func NewConfigurationError(message string) *ConfigurationError {
	return &ConfigurationError{
		VaultAgentError: &VaultAgentError{
			Message: message,
			Code:    "CONFIGURATION_ERROR",
		},
	}
}

// CryptographyError represents cryptography errors
type CryptographyError struct {
	*VaultAgentError
}

func NewCryptographyError(message string) *CryptographyError {
	return &CryptographyError{
		VaultAgentError: &VaultAgentError{
			Message: message,
			Code:    "CRYPTOGRAPHY_ERROR",
		},
	}
}

// PolicyError represents policy errors
type PolicyError struct {
	*VaultAgentError
}

func NewPolicyError(message string) *PolicyError {
	return &PolicyError{
		VaultAgentError: &VaultAgentError{
			Message: message,
			Code:    "POLICY_ERROR",
		},
	}
}

// RotationError represents rotation errors
type RotationError struct {
	*VaultAgentError
}

func NewRotationError(message string) *RotationError {
	return &RotationError{
		VaultAgentError: &VaultAgentError{
			Message: message,
			Code:    "ROTATION_ERROR",
		},
	}
}

// BackupError represents backup errors
type BackupError struct {
	*VaultAgentError
}

func NewBackupError(message string) *BackupError {
	return &BackupError{
		VaultAgentError: &VaultAgentError{
			Message: message,
			Code:    "BACKUP_ERROR",
		},
	}
}

// parseErrorResponse parses HTTP error responses and returns appropriate error types
func parseErrorResponse(statusCode int, body map[string]interface{}, requestID string) error {
	message := "Unknown error"
	if msg, ok := body["message"].(string); ok {
		message = msg
	} else if err, ok := body["error"].(string); ok {
		message = err
	}

	code := ""
	if c, ok := body["code"].(string); ok {
		code = c
	}

	details := make(map[string]interface{})
	if d, ok := body["details"].(map[string]interface{}); ok {
		details = d
	}

	baseError := &VaultAgentError{
		Message:   message,
		Code:      code,
		Details:   details,
		RequestID: requestID,
	}

	switch statusCode {
	case http.StatusUnauthorized:
		return &AuthenticationError{VaultAgentError: baseError}
	case http.StatusForbidden:
		return &AuthorizationError{VaultAgentError: baseError}
	case http.StatusNotFound:
		return &NotFoundError{VaultAgentError: baseError}
	case http.StatusBadRequest:
		return &ValidationError{VaultAgentError: baseError}
	case http.StatusTooManyRequests:
		retryAfter := 0
		if ra, ok := body["retry_after"].(float64); ok {
			retryAfter = int(ra)
		}
		return &RateLimitError{
			VaultAgentError: baseError,
			RetryAfter:      retryAfter,
		}
	default:
		baseError.Message = fmt.Sprintf("HTTP %d: %s", statusCode, message)
		return baseError
	}
}