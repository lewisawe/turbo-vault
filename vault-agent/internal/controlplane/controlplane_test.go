package controlplane

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/keyvault/agent/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Register(t *testing.T) {
	// Create mock server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/agents/register", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with test server
	cfg := &config.ControlPlaneConfig{
		Enabled: true,
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	// Create client with insecure TLS for testing
	client := &Client{
		config:  cfg,
		agentID: "test-agent",
		baseURL: server.URL,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	// Test registration
	req := &RegistrationRequest{
		Version:      "1.0.0",
		Hostname:     "test-host",
		Capabilities: []string{"secrets"},
		Metadata:     map[string]string{"test": "value"},
	}

	err := client.Register(context.Background(), req)
	assert.NoError(t, err)
}

func TestClient_Heartbeat(t *testing.T) {
	// Create mock server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/agents/heartbeat", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client
	client := &Client{
		config: &config.ControlPlaneConfig{
			Enabled: true,
			URL:     server.URL,
			Timeout: 5 * time.Second,
		},
		agentID: "test-agent",
		baseURL: server.URL,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	// Test heartbeat
	req := &HeartbeatRequest{
		Status:  "healthy",
		Metrics: map[string]interface{}{"test": 123},
	}

	err := client.Heartbeat(context.Background(), req)
	assert.NoError(t, err)
}

func TestClient_SyncMetadata(t *testing.T) {
	// Create mock server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/agents/sync", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client
	client := &Client{
		config: &config.ControlPlaneConfig{
			Enabled: true,
			URL:     server.URL,
			Timeout: 5 * time.Second,
		},
		agentID: "test-agent",
		baseURL: server.URL,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	// Test metadata sync
	metadata := []MetadataSync{
		{
			SecretID:  "secret-1",
			Name:      "test-secret",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Metadata:  map[string]string{"env": "test"},
			Tags:      []string{"test"},
		},
	}

	err := client.SyncMetadata(context.Background(), metadata)
	assert.NoError(t, err)
}

func TestService_RetryLogic(t *testing.T) {
	// Create failing server that succeeds on 3rd attempt
	attempts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create service with retry configuration
	cfg := &config.ControlPlaneConfig{
		Enabled:       true,
		URL:           server.URL,
		Timeout:       1 * time.Second,
		MaxRetries:    3,
		RetryInterval: 100 * time.Millisecond,
	}

	client := &Client{
		config:  cfg,
		agentID: "test-agent",
		baseURL: server.URL,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	service := &Service{
		client:     client,
		config:     cfg,
		maxRetries: cfg.MaxRetries,
		stopCh:     make(chan struct{}),
	}

	// Test retry logic
	err := service.executeWithRetry(context.Background(), func() error {
		return client.Heartbeat(context.Background(), &HeartbeatRequest{
			Status: "healthy",
		})
	})

	assert.NoError(t, err)
	assert.Equal(t, 3, attempts)
}

func TestService_CircuitBreaker(t *testing.T) {
	// Create always failing server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := &config.ControlPlaneConfig{
		Enabled:       true,
		URL:           server.URL,
		Timeout:       1 * time.Second,
		MaxRetries:    2,
		RetryInterval: 10 * time.Millisecond,
	}

	client := &Client{
		config:  cfg,
		agentID: "test-agent",
		baseURL: server.URL,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	service := &Service{
		client:     client,
		config:     cfg,
		maxRetries: cfg.MaxRetries,
		stopCh:     make(chan struct{}),
	}

	// Trigger multiple failures to open circuit breaker
	for i := 0; i < 6; i++ {
		service.executeWithRetry(context.Background(), func() error {
			return client.Heartbeat(context.Background(), &HeartbeatRequest{
				Status: "healthy",
			})
		})
	}

	// Circuit should be open now
	assert.True(t, service.circuitOpen)
}

func TestCertManager_EnsureCertificates(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir := t.TempDir()
	
	certFile := tempDir + "/client.crt"
	keyFile := tempDir + "/client.key"
	caFile := tempDir + "/ca.crt"

	// Create a dummy CA file for testing
	caContent := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRl
c3QgQ0EgQ0EwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlUZXN0IENBIENBMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANLJhPHhITqQ
bPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wok/4xIA+ui35/MmNartNuC+Bd
Z1tMuVCPFZcCAwEAATANBgkqhkiG9w0BAQsFAANBAEOFurOxKg+B4WEpSriYH4+4
UhIPJXUTymjhrxMVodjkanVVdSeCa1J2T3dpd1/MSdh2d4z2iZHwmN0CjZDrx/o=
-----END CERTIFICATE-----`

	require.NoError(t, os.WriteFile(caFile, []byte(caContent), 0644))

	// Create certificate manager
	certManager := NewCertManager(certFile, keyFile, caFile, "test-agent")

	// Test certificate generation (will fail due to dummy CA, but should not panic)
	err := certManager.EnsureCertificates()
	// We expect this to fail with our dummy CA, but it should not panic
	assert.Error(t, err)
}

func TestOfflineMode(t *testing.T) {
	// Test that service works when control plane is disabled
	cfg := &config.ControlPlaneConfig{
		Enabled: false,
	}

	service, err := NewService(cfg, nil, "test-agent")
	require.NoError(t, err)

	// Should start successfully even with no control plane
	err = service.Start(context.Background())
	assert.NoError(t, err)

	// Should report offline
	assert.False(t, service.IsOnline())

	// Should stop cleanly
	err = service.Stop()
	assert.NoError(t, err)
}
