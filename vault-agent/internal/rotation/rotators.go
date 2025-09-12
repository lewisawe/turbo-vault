package rotation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// RandomRotator generates random values for secret rotation
type RandomRotator struct{}

// NewRandomRotator creates a new random rotator
func NewRandomRotator() *RandomRotator {
	return &RandomRotator{}
}

// Rotate generates a new random value
func (r *RandomRotator) Rotate(ctx context.Context, secret *Secret, config map[string]interface{}) (*RotationResult, error) {
	length := 32 // Default length
	if l, ok := config["length"].(int); ok {
		length = l
	}

	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if c, ok := config["charset"].(string); ok {
		charset = c
	}

	encoding := "base64"
	if e, ok := config["encoding"].(string); ok {
		encoding = e
	}

	var newValue string
	var err error

	switch encoding {
	case "base64":
		newValue, err = r.generateBase64(length)
	case "hex":
		newValue, err = r.generateHex(length)
	case "charset":
		newValue, err = r.generateFromCharset(length, charset)
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}

	if err != nil {
		return &RotationResult{
			Success:   false,
			Error:     err,
			ErrorCode: "generation_failed",
		}, err
	}

	return &RotationResult{
		Success:  true,
		NewValue: newValue,
		Metadata: map[string]string{
			"rotator_type": "random",
			"encoding":     encoding,
			"length":       fmt.Sprintf("%d", length),
		},
	}, nil
}

// generateBase64 generates a base64-encoded random string
func (r *RandomRotator) generateBase64(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// generateHex generates a hex-encoded random string
func (r *RandomRotator) generateHex(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}

// generateFromCharset generates a random string from a character set
func (r *RandomRotator) generateFromCharset(length int, charset string) (string, error) {
	if len(charset) == 0 {
		return "", fmt.Errorf("charset cannot be empty")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	result := make([]byte, length)
	for i, b := range bytes {
		result[i] = charset[int(b)%len(charset)]
	}

	return string(result), nil
}

// Validate validates the random rotator configuration
func (r *RandomRotator) Validate(config map[string]interface{}) error {
	if length, ok := config["length"]; ok {
		if l, ok := length.(int); !ok || l <= 0 {
			return fmt.Errorf("length must be a positive integer")
		}
	}

	if encoding, ok := config["encoding"]; ok {
		if e, ok := encoding.(string); ok {
			validEncodings := []string{"base64", "hex", "charset"}
			valid := false
			for _, ve := range validEncodings {
				if e == ve {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("invalid encoding: %s", e)
			}
		}
	}

	return nil
}

// GetType returns the rotator type
func (r *RandomRotator) GetType() string {
	return "random"
}

// GetConfigSchema returns the configuration schema
func (r *RandomRotator) GetConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"length":   "int (default: 32) - Length of generated value",
		"encoding": "string (default: base64) - Encoding type: base64, hex, charset",
		"charset":  "string (default: alphanumeric) - Character set for charset encoding",
	}
}

// SupportsRollback indicates if this rotator supports rollback
func (r *RandomRotator) SupportsRollback() bool {
	return false // Random values cannot be rolled back
}

// Rollback is not supported for random rotator
func (r *RandomRotator) Rollback(ctx context.Context, secret *Secret, targetVersion int) error {
	return fmt.Errorf("rollback not supported for random rotator")
}

// ScriptRotator executes external scripts for secret rotation
type ScriptRotator struct {
	logger *logrus.Logger
}

// NewScriptRotator creates a new script rotator
func NewScriptRotator(logger *logrus.Logger) *ScriptRotator {
	return &ScriptRotator{
		logger: logger,
	}
}

// Rotate executes a script to rotate the secret
func (s *ScriptRotator) Rotate(ctx context.Context, secret *Secret, config map[string]interface{}) (*RotationResult, error) {
	scriptPath, ok := config["script_path"].(string)
	if !ok {
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("script_path is required"),
			ErrorCode: "missing_script_path",
		}, fmt.Errorf("script_path is required")
	}

	timeout := 30 * time.Second
	if t, ok := config["timeout"].(string); ok {
		if duration, err := time.ParseDuration(t); err == nil {
			timeout = duration
		}
	}

	// Prepare script arguments
	args := []string{}
	if a, ok := config["args"].([]interface{}); ok {
		for _, arg := range a {
			if argStr, ok := arg.(string); ok {
				args = append(args, argStr)
			}
		}
	}

	// Create context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Execute script
	cmd := exec.CommandContext(ctxWithTimeout, scriptPath, args...)
	
	// Set environment variables
	cmd.Env = []string{
		fmt.Sprintf("SECRET_ID=%s", secret.ID),
		fmt.Sprintf("SECRET_NAME=%s", secret.Name),
		fmt.Sprintf("CURRENT_VALUE=%s", secret.Value),
		fmt.Sprintf("CURRENT_VERSION=%d", secret.Version),
	}

	// Add custom environment variables
	if env, ok := config["env"].(map[string]interface{}); ok {
		for key, value := range env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%v", key, value))
		}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		s.logger.Errorf("Script execution failed: %v, stderr: %s", err, stderr.String())
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("script execution failed: %v", err),
			ErrorCode: "script_execution_failed",
		}, err
	}

	// Parse script output
	output := strings.TrimSpace(stdout.String())
	if output == "" {
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("script produced no output"),
			ErrorCode: "no_output",
		}, fmt.Errorf("script produced no output")
	}

	// Try to parse as JSON for structured output
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err == nil {
		// Structured output
		newValue, ok := result["value"].(string)
		if !ok {
			return &RotationResult{
				Success:   false,
				Error:     fmt.Errorf("script output missing 'value' field"),
				ErrorCode: "invalid_output",
			}, fmt.Errorf("script output missing 'value' field")
		}

		metadata := make(map[string]string)
		if meta, ok := result["metadata"].(map[string]interface{}); ok {
			for k, v := range meta {
				metadata[k] = fmt.Sprintf("%v", v)
			}
		}

		return &RotationResult{
			Success:      true,
			NewValue:     newValue,
			Metadata:     metadata,
			ExternalData: result,
		}, nil
	} else {
		// Simple string output
		return &RotationResult{
			Success:  true,
			NewValue: output,
			Metadata: map[string]string{
				"rotator_type": "script",
				"script_path":  scriptPath,
			},
		}, nil
	}
}

// Validate validates the script rotator configuration
func (s *ScriptRotator) Validate(config map[string]interface{}) error {
	scriptPath, ok := config["script_path"].(string)
	if !ok || scriptPath == "" {
		return fmt.Errorf("script_path is required")
	}

	// Check if script exists and is executable
	if _, err := exec.LookPath(scriptPath); err != nil {
		return fmt.Errorf("script not found or not executable: %w", err)
	}

	return nil
}

// GetType returns the rotator type
func (s *ScriptRotator) GetType() string {
	return "script"
}

// GetConfigSchema returns the configuration schema
func (s *ScriptRotator) GetConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"script_path": "string (required) - Path to the rotation script",
		"args":        "[]string (optional) - Arguments to pass to the script",
		"timeout":     "string (default: 30s) - Script execution timeout",
		"env":         "map[string]string (optional) - Environment variables",
	}
}

// SupportsRollback indicates if this rotator supports rollback
func (s *ScriptRotator) SupportsRollback() bool {
	return true // Scripts can implement rollback logic
}

// Rollback executes rollback script
func (s *ScriptRotator) Rollback(ctx context.Context, secret *Secret, targetVersion int) error {
	// This would execute a rollback script if configured
	return fmt.Errorf("rollback script not implemented")
}

// APIRotator calls external APIs for secret rotation
type APIRotator struct {
	logger *logrus.Logger
	client *http.Client
}

// NewAPIRotator creates a new API rotator
func NewAPIRotator(logger *logrus.Logger) *APIRotator {
	return &APIRotator{
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Rotate calls an external API to rotate the secret
func (a *APIRotator) Rotate(ctx context.Context, secret *Secret, config map[string]interface{}) (*RotationResult, error) {
	url, ok := config["url"].(string)
	if !ok {
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("url is required"),
			ErrorCode: "missing_url",
		}, fmt.Errorf("url is required")
	}

	method := "POST"
	if m, ok := config["method"].(string); ok {
		method = strings.ToUpper(m)
	}

	// Prepare request payload
	payload := map[string]interface{}{
		"secret_id":       secret.ID,
		"secret_name":     secret.Name,
		"current_version": secret.Version,
	}

	// Add custom payload fields
	if customPayload, ok := config["payload"].(map[string]interface{}); ok {
		for k, v := range customPayload {
			payload[k] = v
		}
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("failed to marshal payload: %w", err),
			ErrorCode: "payload_marshal_failed",
		}, err
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("failed to create request: %w", err),
			ErrorCode: "request_creation_failed",
		}, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vault-agent-rotator/1.0")

	if headers, ok := config["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			req.Header.Set(key, fmt.Sprintf("%v", value))
		}
	}

	// Execute request
	resp, err := a.client.Do(req)
	if err != nil {
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("API request failed: %w", err),
			ErrorCode: "api_request_failed",
		}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("API returned status %d", resp.StatusCode),
			ErrorCode: "api_error",
		}, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	// Parse response
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("failed to parse API response: %w", err),
			ErrorCode: "response_parse_failed",
		}, err
	}

	// Extract new value
	newValue, ok := response["value"].(string)
	if !ok {
		return &RotationResult{
			Success:   false,
			Error:     fmt.Errorf("API response missing 'value' field"),
			ErrorCode: "invalid_response",
		}, fmt.Errorf("API response missing 'value' field")
	}

	// Extract metadata
	metadata := make(map[string]string)
	if meta, ok := response["metadata"].(map[string]interface{}); ok {
		for k, v := range meta {
			metadata[k] = fmt.Sprintf("%v", v)
		}
	}

	return &RotationResult{
		Success:      true,
		NewValue:     newValue,
		Metadata:     metadata,
		ExternalData: response,
	}, nil
}

// Validate validates the API rotator configuration
func (a *APIRotator) Validate(config map[string]interface{}) error {
	url, ok := config["url"].(string)
	if !ok || url == "" {
		return fmt.Errorf("url is required")
	}

	if method, ok := config["method"]; ok {
		if m, ok := method.(string); ok {
			validMethods := []string{"GET", "POST", "PUT", "PATCH"}
			valid := false
			for _, vm := range validMethods {
				if strings.ToUpper(m) == vm {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("invalid HTTP method: %s", m)
			}
		}
	}

	return nil
}

// GetType returns the rotator type
func (a *APIRotator) GetType() string {
	return "api"
}

// GetConfigSchema returns the configuration schema
func (a *APIRotator) GetConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"url":     "string (required) - API endpoint URL",
		"method":  "string (default: POST) - HTTP method",
		"headers": "map[string]string (optional) - HTTP headers",
		"payload": "map[string]interface{} (optional) - Additional payload fields",
	}
}

// SupportsRollback indicates if this rotator supports rollback
func (a *APIRotator) SupportsRollback() bool {
	return true // APIs can implement rollback endpoints
}

// Rollback calls rollback API endpoint
func (a *APIRotator) Rollback(ctx context.Context, secret *Secret, targetVersion int) error {
	// This would call a rollback API endpoint if configured
	return fmt.Errorf("rollback API not implemented")
}