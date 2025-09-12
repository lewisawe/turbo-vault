package vaultagent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientSecretLifecycle(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/secrets":
			secret := Secret{
				SecretMetadata: SecretMetadata{
					ID:        "test-secret-id",
					Name:      "test-secret",
					Version:   1,
					CreatedBy: "test-user",
					Status:    SecretStatusActive,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
				Value: "test-value",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(secret)

		case r.Method == "GET" && r.URL.Path == "/api/v1/secrets/test-secret-id":
			secret := Secret{
				SecretMetadata: SecretMetadata{
					ID:        "test-secret-id",
					Name:      "test-secret",
					Version:   1,
					CreatedBy: "test-user",
					Status:    SecretStatusActive,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
				Value: "test-value",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(secret)

		case r.Method == "PUT" && r.URL.Path == "/api/v1/secrets/test-secret-id":
			secret := Secret{
				SecretMetadata: SecretMetadata{
					ID:        "test-secret-id",
					Name:      "test-secret",
					Version:   2,
					CreatedBy: "test-user",
					Status:    SecretStatusActive,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
				Value: "updated-value",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(secret)

		case r.Method == "GET" && r.URL.Path == "/api/v1/secrets":
			response := SecretsResponse{
				Secrets: []SecretMetadata{
					{
						ID:        "test-secret-id",
						Name:      "test-secret",
						Version:   1,
						CreatedBy: "test-user",
						Status:    SecretStatusActive,
						Tags:      []string{"integration-test"},
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)

		case r.Method == "DELETE" && r.URL.Path == "/api/v1/secrets/test-secret-id":
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client
	auth := NewAPIKeyAuth("test-api-key")
	client, err := NewClient(
		server.URL,
		auth,
		WithTimeout(10*time.Second),
		WithVerifySSL(false),
		WithLogLevel("error"),
	)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Test create secret
	secret, err := client.CreateSecret(ctx, CreateSecretRequest{
		Name:  "test-secret",
		Value: "test-value",
		Tags:  []string{"integration-test"},
	})
	require.NoError(t, err)
	assert.Equal(t, "test-secret", secret.Name)
	assert.Equal(t, "test-value", secret.Value)

	// Test get secret
	retrieved, err := client.GetSecret(ctx, secret.ID)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, retrieved.ID)
	assert.Equal(t, "test-value", retrieved.Value)

	// Test update secret
	newValue := "updated-value"
	updated, err := client.UpdateSecret(ctx, secret.ID, UpdateSecretRequest{
		Value: &newValue,
	})
	require.NoError(t, err)
	assert.Equal(t, "updated-value", updated.Value)
	assert.Equal(t, 2, updated.Version)

	// Test list secrets
	secrets, err := client.ListSecrets(ctx, ListSecretsOptions{
		Tags: []string{"integration-test"},
	})
	require.NoError(t, err)
	assert.Len(t, secrets, 1)
	assert.Equal(t, secret.ID, secrets[0].ID)

	// Test delete secret
	err = client.DeleteSecret(ctx, secret.ID)
	require.NoError(t, err)
}

func TestClientAuthentication(t *testing.T) {
	// Create test server that returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Invalid API key",
		})
	}))
	defer server.Close()

	// Create client with invalid auth
	auth := NewAPIKeyAuth("invalid-key")
	client, err := NewClient(
		server.URL,
		auth,
		WithTimeout(10*time.Second),
		WithVerifySSL(false),
		WithLogLevel("error"),
	)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Test authentication error
	_, err = client.ListSecrets(ctx, ListSecretsOptions{})
	require.Error(t, err)
	assert.IsType(t, &AuthenticationError{}, err)
}

func TestClientHealthCheck(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			status := VaultStatus{
				Status:        "healthy",
				Version:       "1.0.0",
				Uptime:        3600,
				SecretsCount:  10,
				PoliciesCount: 5,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(status)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client
	auth := NewAPIKeyAuth("test-api-key")
	client, err := NewClient(
		server.URL,
		auth,
		WithTimeout(10*time.Second),
		WithVerifySSL(false),
		WithLogLevel("error"),
	)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Test health check
	health, err := client.HealthCheck(ctx)
	require.NoError(t, err)
	assert.Equal(t, "healthy", health.Status)
	assert.Equal(t, "1.0.0", health.Version)
	assert.Equal(t, int64(3600), health.Uptime)
}

func TestClientCaching(t *testing.T) {
	callCount := 0
	
	// Create test server that counts calls
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/secrets/cached-secret" {
			callCount++
			secret := Secret{
				SecretMetadata: SecretMetadata{
					ID:        "cached-secret",
					Name:      "cached-secret",
					Version:   1,
					CreatedBy: "test-user",
					Status:    SecretStatusActive,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
				Value: "cached-value",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(secret)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client with caching enabled
	auth := NewAPIKeyAuth("test-api-key")
	client, err := NewClient(
		server.URL,
		auth,
		WithTimeout(10*time.Second),
		WithVerifySSL(false),
		WithCache(true, 1*time.Minute, 100),
		WithLogLevel("error"),
	)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Make two identical requests
	secret1, err := client.GetSecret(ctx, "cached-secret")
	require.NoError(t, err)

	secret2, err := client.GetSecret(ctx, "cached-secret")
	require.NoError(t, err)

	// Verify both requests returned the same data
	assert.Equal(t, secret1.ID, secret2.ID)
	assert.Equal(t, secret1.Value, secret2.Value)

	// Verify server was only called once due to caching
	assert.Equal(t, 1, callCount)
}