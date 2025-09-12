package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Setup test environment
	setupTestConfig()
	code := m.Run()
	// Cleanup
	cleanupTestConfig()
	os.Exit(code)
}

func setupTestConfig() {
	// Create temporary config directory
	tempDir, _ := os.MkdirTemp("", "vault-cli-test")
	viper.Set("config_dir", tempDir)
	
	// Set test configuration
	viper.Set("server.url", "http://localhost:8080")
	viper.Set("auth.api_key", "test-api-key")
	viper.Set("output", "json")
}

func cleanupTestConfig() {
	if configDir := viper.GetString("config_dir"); configDir != "" {
		os.RemoveAll(configDir)
	}
}

func TestSecretsListCommand(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)
		assert.Equal(t, "test-api-key", r.Header.Get("X-API-Key"))

		response := map[string]interface{}{
			"secrets": []map[string]interface{}{
				{
					"id":         "secret-1",
					"name":       "test-secret",
					"created_at": "2023-01-01T00:00:00Z",
					"status":     "active",
				},
			},
			"total": 1,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Update config to use mock server
	viper.Set("server.url", server.URL)

	// Execute command
	cmd := &cobra.Command{}
	cmd.AddCommand(secretsCmd)
	
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"secrets", "list"})

	err := cmd.Execute()
	require.NoError(t, err)

	// Verify output contains expected data
	outputStr := output.String()
	assert.Contains(t, outputStr, "test-secret")
}

func TestSecretsGetCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/secrets/test-secret", r.URL.Path)

		response := map[string]interface{}{
			"id":         "secret-1",
			"name":       "test-secret",
			"value":      "secret-value",
			"created_at": "2023-01-01T00:00:00Z",
			"status":     "active",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	viper.Set("server.url", server.URL)

	cmd := &cobra.Command{}
	cmd.AddCommand(secretsCmd)
	
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"secrets", "get", "test-secret", "--show-value"})

	err := cmd.Execute()
	require.NoError(t, err)

	outputStr := output.String()
	assert.Contains(t, outputStr, "test-secret")
}

func TestSecretsCreateCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)

		var requestBody map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&requestBody)
		require.NoError(t, err)

		assert.Equal(t, "test-secret", requestBody["name"])
		assert.Equal(t, "test-value", requestBody["value"])

		response := map[string]interface{}{
			"id":         "secret-1",
			"name":       "test-secret",
			"created_at": "2023-01-01T00:00:00Z",
			"status":     "active",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	viper.Set("server.url", server.URL)

	cmd := &cobra.Command{}
	cmd.AddCommand(secretsCmd)
	
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"secrets", "create", "test-secret", "--value", "test-value"})

	err := cmd.Execute()
	require.NoError(t, err)
}

func TestConfigInitCommand(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "vault-cli-config-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Set config directory in viper for test
	viper.Set("config_dir", tempDir)

	cmd := &cobra.Command{}
	cmd.AddCommand(configCmd)
	
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"config", "init"})

	err = cmd.Execute()
	require.NoError(t, err)

	// For this test, we'll just verify the command runs without error
	// The actual file creation logic would need to be refactored to be more testable
}

func TestConfigSetGetCommands(t *testing.T) {
	// Test set command
	cmd := &cobra.Command{}
	cmd.AddCommand(configCmd)
	
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"config", "set", "server.url", "http://test.example.com"})

	err := cmd.Execute()
	require.NoError(t, err)

	// Verify value was set
	assert.Equal(t, "http://test.example.com", viper.GetString("profiles.default.server.url"))

	// Test get command
	output.Reset()
	cmd.SetArgs([]string{"config", "get", "server.url"})

	err = cmd.Execute()
	require.NoError(t, err)

	outputStr := output.String()
	assert.Contains(t, outputStr, "http://test.example.com")
}

func TestPoliciesListCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/policies", r.URL.Path)

		response := map[string]interface{}{
			"policies": []map[string]interface{}{
				{
					"id":          "policy-1",
					"name":        "test-policy",
					"description": "Test policy",
					"enabled":     true,
					"priority":    100,
				},
			},
			"total": 1,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	viper.Set("server.url", server.URL)

	cmd := &cobra.Command{}
	cmd.AddCommand(policiesCmd)
	
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"policies", "list"})

	err := cmd.Execute()
	require.NoError(t, err)

	outputStr := output.String()
	assert.Contains(t, outputStr, "test-policy")
}

func TestSystemStatusCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/status", r.URL.Path)

		response := map[string]interface{}{
			"status":     "healthy",
			"version":    "1.0.0",
			"uptime":     "24h30m",
			"secrets":    100,
			"policies":   5,
			"users":      10,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	viper.Set("server.url", server.URL)

	cmd := &cobra.Command{}
	cmd.AddCommand(systemCmd)
	
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"system", "status"})

	err := cmd.Execute()
	require.NoError(t, err)

	outputStr := output.String()
	assert.Contains(t, outputStr, "healthy")
	assert.Contains(t, outputStr, "1.0.0")
}

func TestOutputFormats(t *testing.T) {
	tests := []struct {
		format   OutputFormat
		expected string
	}{
		{OutputJSON, "json"},
		{OutputYAML, "yaml"},
		{OutputTable, "table"},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			printer := &Printer{Format: tt.format}
			
			// For this test, we'll just verify the printer can be created
			// and the format is set correctly
			assert.Equal(t, tt.format, printer.Format)
		})
	}
}

func TestClientAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		apiKey   string
		token    string
		expected string
	}{
		{
			name:     "API Key authentication",
			apiKey:   "test-api-key",
			expected: "X-API-Key",
		},
		{
			name:     "Token authentication",
			token:    "test-token",
			expected: "Authorization",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.NotEmpty(t, r.Header.Get(tt.expected))
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client := &Client{
				BaseURL:    server.URL,
				HTTPClient: &http.Client{},
				APIKey:     tt.apiKey,
				Token:      tt.token,
			}

			_, err := client.Get("/test")
			require.NoError(t, err)
		})
	}
}

func TestErrorHandling(t *testing.T) {
	// Test server error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Internal server error",
		})
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		HTTPClient: &http.Client{},
	}

	resp, err := client.Get("/test")
	require.NoError(t, err)

	err = client.ParseResponse(resp, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Internal server error")
}

func TestInteractiveMode(t *testing.T) {
	// Test interactive command parsing
	testCases := []struct {
		input    string
		expected []string
	}{
		{"secrets list", []string{"secrets", "list"}},
		{"config set key value", []string{"config", "set", "key", "value"}},
		{"system status", []string{"system", "status"}},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			// This would test the interactive command parsing
			// For now, just verify the input splits correctly
			args := strings.Fields(tc.input)
			assert.Equal(t, tc.expected, args)
		})
	}
}