package api

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

// ValidationMiddleware provides request validation with detailed error messages
func ValidationMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Next()
	})
}

// ValidateRequest validates a request struct and returns detailed validation errors
func ValidateRequest(c *gin.Context, req interface{}) bool {
	if err := c.ShouldBindJSON(req); err != nil {
		handleValidationError(c, err)
		return false
	}
	return true
}

// ValidateQueryParams validates query parameters and returns detailed validation errors
func ValidateQueryParams(c *gin.Context, req interface{}) bool {
	if err := c.ShouldBindQuery(req); err != nil {
		handleValidationError(c, err)
		return false
	}
	return true
}

// handleValidationError processes validation errors and returns structured error response
func handleValidationError(c *gin.Context, err error) {
	var validationErrors []ValidationError

	if validatorErrors, ok := err.(validator.ValidationErrors); ok {
		for _, fieldError := range validatorErrors {
			validationErrors = append(validationErrors, ValidationError{
				Field:   getJSONFieldName(fieldError),
				Message: getValidationMessage(fieldError),
				Value:   fmt.Sprintf("%v", fieldError.Value()),
			})
		}
	} else {
		// Handle other binding errors (JSON syntax, type conversion, etc.)
		validationErrors = append(validationErrors, ValidationError{
			Field:   "request",
			Message: err.Error(),
		})
	}

	apiError := &APIError{
		Type:      ErrorTypeValidation,
		Code:      "VALIDATION_FAILED",
		Message:   "Request validation failed",
		Details: map[string]interface{}{
			"validation_errors": validationErrors,
		},
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	}

	c.JSON(http.StatusBadRequest, APIResponse{
		Success:   false,
		Error:     apiError,
		RequestID: GetRequestID(c),
		Timestamp: GetCurrentTime(),
	})
}

// getJSONFieldName extracts the JSON field name from validation error
func getJSONFieldName(fieldError validator.FieldError) string {
	field := fieldError.Field()
	
	// Try to get the JSON tag name
	if fieldError.StructNamespace() != "" {
		// This is a simplified approach - in production you might want to use reflection
		// to get the actual JSON tag name
		return strings.ToLower(field[:1]) + field[1:]
	}
	
	return field
}

// getValidationMessage returns a human-readable validation message
func getValidationMessage(fieldError validator.FieldError) string {
	field := fieldError.Field()
	tag := fieldError.Tag()
	param := fieldError.Param()

	switch tag {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "min":
		if fieldError.Kind() == reflect.String {
			return fmt.Sprintf("%s must be at least %s characters long", field, param)
		}
		return fmt.Sprintf("%s must be at least %s", field, param)
	case "max":
		if fieldError.Kind() == reflect.String {
			return fmt.Sprintf("%s must be at most %s characters long", field, param)
		}
		return fmt.Sprintf("%s must be at most %s", field, param)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "url":
		return fmt.Sprintf("%s must be a valid URL", field)
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, param)
	case "uuid":
		return fmt.Sprintf("%s must be a valid UUID", field)
	case "datetime":
		return fmt.Sprintf("%s must be a valid datetime", field)
	default:
		return fmt.Sprintf("%s is invalid", field)
	}
}

// Custom validation functions
func init() {
	// Register custom validators if needed
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		// Example: register custom secret name validator
		v.RegisterValidation("secret_name", validateSecretName)
	}
}

// validateSecretName validates secret names according to our rules
func validateSecretName(fl validator.FieldLevel) bool {
	name := fl.Field().String()
	
	// Secret names must:
	// - Be 1-255 characters
	// - Contain only alphanumeric, hyphens, underscores, and dots
	// - Not start or end with special characters
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	
	// Check first and last characters
	if !isAlphaNumeric(name[0]) || !isAlphaNumeric(name[len(name)-1]) {
		return false
	}
	
	// Check all characters
	for _, char := range name {
		if !isAlphaNumeric(byte(char)) && char != '-' && char != '_' && char != '.' {
			return false
		}
	}
	
	return true
}

// isAlphaNumeric checks if a byte is alphanumeric
func isAlphaNumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}