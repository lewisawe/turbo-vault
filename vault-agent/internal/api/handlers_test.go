package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/keyvault/agent/internal/storage"
)

// MockStorageBackend is a mock implementation of storage.StorageBackend for testing
type MockStorageBackend struct {
	mock.Mock
}

func (m *MockStorageBackend) CreateSecret(ctx context.Context, secret *storage.Secret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}

func (m *MockStorageBackend) GetSecret(ctx context.Context, id string) (*storage.Secret, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Secret), args.Error(1)
}

func (m *MockStorageBackend) GetSecretByName(ctx context.Context, name string) (*storage.Secret, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Secret), args.Error(1)
}

func (m *MockStorageBackend) UpdateSecret(ctx context.Context, id string, secret *storage.Secret) error {
	args := m.Called(ctx, id, secret)
	return args.Error(0)
}

func (m *MockStorageBackend) DeleteSecret(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorageBackend) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*storage.Secret, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*storage.Secret), args.Error(1)
}

func (m *MockStorageBackend) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockStorageBackend) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockStorageBackend) Backup(ctx context.Context, destination string) error {
	args := m.Called(ctx, destination)
	return args.Error(0)
}

func (m *MockStorageBackend) Restore(ctx context.Context, source string) error {
	args := m.Called(ctx, source)
	return args.Error(0)
}

// Test setup helpers
func setupTestRouter(storage storage.StorageBackend) *gin.Engine {
	gin.SetMode(gin.TestMode)
	config := &RouterConfig{
		Storage:       storage,
		Version:       "test",
		EnableSwagger: false,
		EnableCORS:    false,
	}
	return NewRouter(config)
}

func createTestSecret() *storage.Secret {
	now := time.Now().UTC()
	return &storage.Secret{
		ID:          uuid.New().String(),
		Name:        "test-secret",
		Value:       "test-value",
		Metadata:    map[string]string{"env": "test"},
		Tags:        []string{"test"},
		CreatedAt:   now,
		UpdatedAt:   now,
		Version:     1,
		CreatedBy:   "test-user",
		AccessCount: 0,
		Status:      storage.SecretStatusActive,
	}
}

// Test cases for CreateSecret endpoint
func TestCreateSecret(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    CreateSecretRequest
		mockSetup      func(*MockStorageBackend)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "successful creation",
			requestBody: CreateSecretRequest{
				Name:  "test-secret",
				Value: "test-value",
			},
			mockSetup: func(m *MockStorageBackend) {
				m.On("GetSecretByName", mock.Anything, "test-secret").Return(nil, fmt.Errorf("not found"))
				m.On("CreateSecret", mock.Anything, mock.AnythingOfType("*storage.Secret")).Return(nil)
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "validation error - missing name",
			requestBody: CreateSecretRequest{
				Value: "test-value",
			},
			mockSetup:      func(m *MockStorageBackend) {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_FAILED",
		},
		{
			name: "validation error - missing value",
			requestBody: CreateSecretRequest{
				Name: "test-secret",
			},
			mockSetup:      func(m *MockStorageBackend) {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_FAILED",
		},
		{
			name: "conflict - secret already exists",
			requestBody: CreateSecretRequest{
				Name:  "existing-secret",
				Value: "test-value",
			},
			mockSetup: func(m *MockStorageBackend) {
				existingSecret := createTestSecret()
				existingSecret.Name = "existing-secret"
				m.On("GetSecretByName", mock.Anything, "existing-secret").Return(existingSecret, nil)
			},
			expectedStatus: http.StatusConflict,
			expectedError:  "SECRET_EXISTS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := new(MockStorageBackend)
			tt.mockSetup(mockStorage)

			router := setupTestRouter(mockStorage)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response APIResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			if tt.expectedError != "" {
				assert.False(t, response.Success)
				assert.NotNil(t, response.Error)
				assert.Equal(t, tt.expectedError, response.Error.Code)
			} else {
				assert.True(t, response.Success)
				assert.Nil(t, response.Error)
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

// Test cases for GetSecret endpoint
func TestGetSecret(t *testing.T) {
	tests := []struct {
		name           string
		secretID       string
		mockSetup      func(*MockStorageBackend)
		expectedStatus int
		expectedError  string
	}{
		{
			name:     "successful retrieval",
			secretID: uuid.New().String(),
			mockSetup: func(m *MockStorageBackend) {
				secret := createTestSecret()
				m.On("GetSecret", mock.Anything, mock.AnythingOfType("string")).Return(secret, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid UUID",
			secretID:       "invalid-uuid",
			mockSetup:      func(m *MockStorageBackend) {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "INVALID_UUID",
		},
		{
			name:     "secret not found",
			secretID: uuid.New().String(),
			mockSetup: func(m *MockStorageBackend) {
				m.On("GetSecret", mock.Anything, mock.AnythingOfType("string")).Return(nil, fmt.Errorf("not found"))
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "NOT_FOUND",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := new(MockStorageBackend)
			tt.mockSetup(mockStorage)

			router := setupTestRouter(mockStorage)

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%s", tt.secretID), nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response APIResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			if tt.expectedError != "" {
				assert.False(t, response.Success)
				assert.NotNil(t, response.Error)
				assert.Equal(t, tt.expectedError, response.Error.Code)
			} else {
				assert.True(t, response.Success)
				assert.Nil(t, response.Error)
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

// Test cases for ListSecrets endpoint
func TestListSecrets(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		mockSetup      func(*MockStorageBackend)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "successful listing",
			mockSetup: func(m *MockStorageBackend) {
				secrets := []*storage.Secret{createTestSecret(), createTestSecret()}
				m.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).Return(secrets, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "with pagination",
			queryParams: "?page=2&per_page=10",
			mockSetup: func(m *MockStorageBackend) {
				secrets := []*storage.Secret{createTestSecret()}
				m.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).Return(secrets, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "with filters",
			queryParams: "?name_pattern=test*&status=active&tags=production",
			mockSetup: func(m *MockStorageBackend) {
				secrets := []*storage.Secret{createTestSecret()}
				m.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).Return(secrets, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid page parameter",
			queryParams:    "?page=-1",
			mockSetup:      func(m *MockStorageBackend) {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_FAILED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := new(MockStorageBackend)
			tt.mockSetup(mockStorage)

			router := setupTestRouter(mockStorage)

			url := "/api/v1/secrets" + tt.queryParams
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response APIResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			if tt.expectedError != "" {
				assert.False(t, response.Success)
				assert.NotNil(t, response.Error)
				assert.Equal(t, tt.expectedError, response.Error.Code)
			} else {
				assert.True(t, response.Success)
				assert.Nil(t, response.Error)
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

// Test cases for UpdateSecret endpoint
func TestUpdateSecret(t *testing.T) {
	secretID := uuid.New().String()

	tests := []struct {
		name           string
		requestBody    UpdateSecretRequest
		mockSetup      func(*MockStorageBackend)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "successful update",
			requestBody: UpdateSecretRequest{
				Name:  stringPtr("updated-secret"),
				Value: stringPtr("updated-value"),
			},
			mockSetup: func(m *MockStorageBackend) {
				secret := createTestSecret()
				m.On("GetSecret", mock.Anything, secretID).Return(secret, nil)
				m.On("UpdateSecret", mock.Anything, secretID, mock.AnythingOfType("*storage.Secret")).Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "secret not found",
			requestBody: UpdateSecretRequest{
				Name: stringPtr("updated-secret"),
			},
			mockSetup: func(m *MockStorageBackend) {
				m.On("GetSecret", mock.Anything, secretID).Return(nil, fmt.Errorf("not found"))
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "NOT_FOUND",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := new(MockStorageBackend)
			tt.mockSetup(mockStorage)

			router := setupTestRouter(mockStorage)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%s", secretID), bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response APIResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			if tt.expectedError != "" {
				assert.False(t, response.Success)
				assert.NotNil(t, response.Error)
				assert.Equal(t, tt.expectedError, response.Error.Code)
			} else {
				assert.True(t, response.Success)
				assert.Nil(t, response.Error)
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

// Test cases for DeleteSecret endpoint
func TestDeleteSecret(t *testing.T) {
	secretID := uuid.New().String()

	tests := []struct {
		name           string
		mockSetup      func(*MockStorageBackend)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "successful deletion",
			mockSetup: func(m *MockStorageBackend) {
				secret := createTestSecret()
				m.On("GetSecret", mock.Anything, secretID).Return(secret, nil)
				m.On("DeleteSecret", mock.Anything, secretID).Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "secret not found",
			mockSetup: func(m *MockStorageBackend) {
				m.On("GetSecret", mock.Anything, secretID).Return(nil, fmt.Errorf("not found"))
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "NOT_FOUND",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := new(MockStorageBackend)
			tt.mockSetup(mockStorage)

			router := setupTestRouter(mockStorage)

			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%s", secretID), nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response APIResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			if tt.expectedError != "" {
				assert.False(t, response.Success)
				assert.NotNil(t, response.Error)
				assert.Equal(t, tt.expectedError, response.Error.Code)
			} else {
				assert.True(t, response.Success)
				assert.Nil(t, response.Error)
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

// Test cases for RotateSecret endpoint
func TestRotateSecret(t *testing.T) {
	secretID := uuid.New().String()

	tests := []struct {
		name           string
		requestBody    RotateSecretRequest
		mockSetup      func(*MockStorageBackend)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "successful rotation",
			requestBody: RotateSecretRequest{
				NewValue: "new-rotated-value",
				Reason:   "Scheduled rotation",
			},
			mockSetup: func(m *MockStorageBackend) {
				secret := createTestSecret()
				rotationDue := time.Now().AddDate(0, 0, 30)
				secret.RotationDue = &rotationDue
				m.On("GetSecret", mock.Anything, secretID).Return(secret, nil)
				m.On("UpdateSecret", mock.Anything, secretID, mock.AnythingOfType("*storage.Secret")).Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "validation error - missing new value",
			requestBody: RotateSecretRequest{
				Reason: "Test rotation",
			},
			mockSetup:      func(m *MockStorageBackend) {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_FAILED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := new(MockStorageBackend)
			tt.mockSetup(mockStorage)

			router := setupTestRouter(mockStorage)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%s/rotate", secretID), bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response APIResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			if tt.expectedError != "" {
				assert.False(t, response.Success)
				assert.NotNil(t, response.Error)
				assert.Equal(t, tt.expectedError, response.Error.Code)
			} else {
				assert.True(t, response.Success)
				assert.Nil(t, response.Error)
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

// Test cases for Health endpoint
func TestHealthCheck(t *testing.T) {
	tests := []struct {
		name           string
		mockSetup      func(*MockStorageBackend)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "healthy service",
			mockSetup: func(m *MockStorageBackend) {
				m.On("HealthCheck", mock.Anything).Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "unhealthy service",
			mockSetup: func(m *MockStorageBackend) {
				m.On("HealthCheck", mock.Anything).Return(fmt.Errorf("database connection failed"))
			},
			expectedStatus: http.StatusServiceUnavailable,
			expectedError:  "SERVICE_UNHEALTHY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := new(MockStorageBackend)
			tt.mockSetup(mockStorage)

			router := setupTestRouter(mockStorage)

			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response APIResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			if tt.expectedError != "" {
				assert.False(t, response.Success)
				assert.NotNil(t, response.Error)
				assert.Equal(t, tt.expectedError, response.Error.Code)
			} else {
				assert.True(t, response.Success)
				assert.Nil(t, response.Error)
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

// Benchmark tests for performance validation
func BenchmarkCreateSecret(b *testing.B) {
	mockStorage := new(MockStorageBackend)
	mockStorage.On("GetSecretByName", mock.Anything, mock.AnythingOfType("string")).Return(nil, fmt.Errorf("not found"))
	mockStorage.On("CreateSecret", mock.Anything, mock.AnythingOfType("*storage.Secret")).Return(nil)

	router := setupTestRouter(mockStorage)

	requestBody := CreateSecretRequest{
		Name:  "benchmark-secret",
		Value: "benchmark-value",
	}
	body, _ := json.Marshal(requestBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkGetSecret(b *testing.B) {
	mockStorage := new(MockStorageBackend)
	secret := createTestSecret()
	mockStorage.On("GetSecret", mock.Anything, mock.AnythingOfType("string")).Return(secret, nil)

	router := setupTestRouter(mockStorage)
	secretID := uuid.New().String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%s", secretID), nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}