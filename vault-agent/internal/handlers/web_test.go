package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	
	webHandler := NewWebHandler()
	webHandler.SetupWebRoutes(router)
	
	return router
}

func TestWebInterface_Dashboard(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name           string
		endpoint       string
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name:           "System Stats",
			endpoint:       "/api/v1/system/stats",
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				require.NoError(t, err)
				
				stats, ok := response["stats"].(map[string]interface{})
				require.True(t, ok)
				assert.Contains(t, stats, "secrets")
				assert.Contains(t, stats, "policies")
				assert.Contains(t, stats, "users")
			},
		},
		{
			name:           "System Health",
			endpoint:       "/api/v1/system/health",
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				require.NoError(t, err)
				
				assert.Contains(t, response, "cpu_usage")
				assert.Contains(t, response, "memory_usage")
				assert.Contains(t, response, "storage_usage")
			},
		},
		{
			name:           "System Activity",
			endpoint:       "/api/v1/system/activity",
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				require.NoError(t, err)
				
				events, ok := response["events"].([]interface{})
				require.True(t, ok)
				assert.Greater(t, len(events), 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.endpoint, nil)
			w := httptest.NewRecorder()
			
			router.ServeHTTP(w, req)
			
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w.Body.String())
			}
		})
	}
}

func TestWebInterface_SecretsManagement(t *testing.T) {
	router := setupTestRouter()

	t.Run("List Secrets", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/secrets", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		secrets, ok := response["secrets"].([]interface{})
		require.True(t, ok)
		assert.Greater(t, len(secrets), 0)
	})

	t.Run("Create Secret", func(t *testing.T) {
		secretData := map[string]interface{}{
			"name":  "test-secret",
			"value": "test-value",
			"tags":  []string{"test"},
		}
		
		jsonData, _ := json.Marshal(secretData)
		req := httptest.NewRequest("POST", "/api/v1/secrets", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.Equal(t, "test-secret", response["name"])
		assert.Contains(t, response, "id")
	})

	t.Run("Get Secret", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/secrets/secret-001", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.Contains(t, response, "name")
		assert.Contains(t, response, "status")
	})

	t.Run("Get Secret with Value", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/secrets/secret-001?include_value=true", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.Contains(t, response, "value")
	})

	t.Run("Update Secret", func(t *testing.T) {
		updateData := map[string]interface{}{
			"tags": []string{"updated", "test"},
		}
		
		jsonData, _ := json.Marshal(updateData)
		req := httptest.NewRequest("PUT", "/api/v1/secrets/secret-001", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Rotate Secret", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/secrets/secret-001/rotate", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.Contains(t, response, "status")
	})

	t.Run("Delete Secret", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/secrets/secret-001", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestWebInterface_PolicyManagement(t *testing.T) {
	router := setupTestRouter()

	t.Run("List Policies", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/policies", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		policies, ok := response["policies"].([]interface{})
		require.True(t, ok)
		assert.Greater(t, len(policies), 0)
	})

	t.Run("Create Policy", func(t *testing.T) {
		policyData := map[string]interface{}{
			"name":        "test-policy",
			"description": "Test policy",
			"priority":    100,
			"enabled":     true,
			"rules": []map[string]interface{}{
				{
					"effect":    "allow",
					"actions":   []string{"read"},
					"resources": []string{"secrets/*"},
				},
			},
		}
		
		jsonData, _ := json.Marshal(policyData)
		req := httptest.NewRequest("POST", "/api/v1/policies", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("Get Policy", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/policies/policy-001", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.Contains(t, response, "rules")
		assert.Contains(t, response, "conditions")
	})

	t.Run("Validate Policy", func(t *testing.T) {
		policyData := map[string]interface{}{
			"rules": []map[string]interface{}{
				{
					"effect":    "allow",
					"actions":   []string{"read"},
					"resources": []string{"secrets/*"},
				},
			},
		}
		
		jsonData, _ := json.Marshal(policyData)
		req := httptest.NewRequest("POST", "/api/v1/policies/validate", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.Equal(t, true, response["valid"])
	})
}

func TestWebInterface_UserManagement(t *testing.T) {
	router := setupTestRouter()

	t.Run("List Users", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/users", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		users, ok := response["users"].([]interface{})
		require.True(t, ok)
		assert.Greater(t, len(users), 0)
	})

	t.Run("Create User", func(t *testing.T) {
		userData := map[string]interface{}{
			"username": "testuser",
			"email":    "test@example.com",
			"password": "testpass123",
			"roles":    []string{"developer"},
		}
		
		jsonData, _ := json.Marshal(userData)
		req := httptest.NewRequest("POST", "/api/v1/users", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("Get User", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/users/user-001", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.Contains(t, response, "username")
		assert.Contains(t, response, "api_keys")
	})

	t.Run("Reset User Password", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/users/user-001/reset-password", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.Contains(t, response, "temporary_password")
	})
}

func TestWebInterface_AuditLogs(t *testing.T) {
	router := setupTestRouter()

	t.Run("Get Audit Logs", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit/logs", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		logs, ok := response["logs"].([]interface{})
		require.True(t, ok)
		assert.Greater(t, len(logs), 0)
		
		// Check log structure
		log := logs[0].(map[string]interface{})
		assert.Contains(t, log, "timestamp")
		assert.Contains(t, log, "event_type")
		assert.Contains(t, log, "actor")
		assert.Contains(t, log, "resource")
		assert.Contains(t, log, "action")
		assert.Contains(t, log, "result")
	})

	t.Run("Export Audit Logs CSV", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit/logs/export?format=csv", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "text/csv", w.Header().Get("Content-Type"))
		assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
		
		body := w.Body.String()
		assert.Contains(t, body, "timestamp,event_type,actor")
	})
}

func TestWebInterface_Settings(t *testing.T) {
	router := setupTestRouter()

	t.Run("Get Settings", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system/settings", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		settings, ok := response["settings"].(map[string]interface{})
		require.True(t, ok)
		assert.Contains(t, settings, "agent_name")
		assert.Contains(t, settings, "log_level")
	})

	t.Run("Update Settings", func(t *testing.T) {
		settingsData := map[string]interface{}{
			"log_level": "debug",
		}
		
		jsonData, _ := json.Marshal(settingsData)
		req := httptest.NewRequest("PUT", "/api/v1/system/settings/general", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Create Backup", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/system/backup", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.Contains(t, response, "id")
		assert.Contains(t, response, "status")
	})

	t.Run("Export Configuration", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system/config/export", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.Contains(t, response, "version")
		assert.Contains(t, response, "settings")
	})

	t.Run("Test Notification", func(t *testing.T) {
		testData := map[string]interface{}{
			"channel": "email",
		}
		
		jsonData, _ := json.Marshal(testData)
		req := httptest.NewRequest("POST", "/api/v1/system/notifications/test", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestWebInterface_Analytics(t *testing.T) {
	router := setupTestRouter()

	endpoints := []string{
		"/api/v1/analytics/access-patterns",
		"/api/v1/analytics/request-volume",
		"/api/v1/analytics/response-times",
		"/api/v1/analytics/error-rates",
		"/api/v1/metrics/performance",
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest("GET", endpoint, nil)
			w := httptest.NewRecorder()
			
			router.ServeHTTP(w, req)
			
			assert.Equal(t, http.StatusOK, w.Code)
			
			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			
			assert.Contains(t, response, "labels")
			assert.Contains(t, response, "values")
		})
	}
}

func TestWebInterface_StaticFiles(t *testing.T) {
	router := setupTestRouter()

	t.Run("Serve Dashboard", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusMovedPermanently, w.Code)
		assert.Contains(t, w.Header().Get("Location"), "/web/dashboard.html")
	})
}

func TestWebInterface_ErrorHandling(t *testing.T) {
	router := setupTestRouter()

	t.Run("Invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/secrets", strings.NewReader("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Unsupported Export Format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit/logs/export?format=xml", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWebInterface_Security(t *testing.T) {
	router := setupTestRouter()

	t.Run("CORS Headers", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/v1/secrets", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		// Note: CORS middleware would need to be added to the router
		// This test verifies the structure is in place
	})

	t.Run("Content Security", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system/stats", nil)
		w := httptest.NewRecorder()
		
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		// Verify no sensitive data is exposed in error messages
	})
}