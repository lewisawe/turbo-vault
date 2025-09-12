package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/keyvault/agent/internal/config"
)

// Client handles communication with the control plane
type Client struct {
	config     *config.ControlPlaneConfig
	httpClient *http.Client
	agentID    string
	baseURL    string
}

// RegistrationRequest represents vault agent registration data
type RegistrationRequest struct {
	AgentID     string            `json:"agent_id"`
	Version     string            `json:"version"`
	Hostname    string            `json:"hostname"`
	Capabilities []string         `json:"capabilities"`
	Metadata    map[string]string `json:"metadata"`
}

// HeartbeatRequest represents heartbeat data
type HeartbeatRequest struct {
	AgentID   string            `json:"agent_id"`
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Metrics   map[string]interface{} `json:"metrics"`
}

// MetadataSync represents secret metadata for synchronization
type MetadataSync struct {
	SecretID    string            `json:"secret_id"`
	Name        string            `json:"name"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	RotationDue *time.Time        `json:"rotation_due,omitempty"`
	Metadata    map[string]string `json:"metadata"`
	Tags        []string          `json:"tags"`
}

// NewClient creates a new control plane client
func NewClient(cfg *config.ControlPlaneConfig, agentID string) (*Client, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("control plane is disabled")
	}

	// Load TLS certificates
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificates: %w", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13,
	}

	// Create HTTP client with mTLS
	httpClient := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &Client{
		config:     cfg,
		httpClient: httpClient,
		agentID:    agentID,
		baseURL:    cfg.URL,
	}, nil
}

// Register registers the vault agent with the control plane
func (c *Client) Register(ctx context.Context, req *RegistrationRequest) error {
	req.AgentID = c.agentID
	
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	resp, err := c.makeRequest(ctx, "POST", "/api/v1/agents/register", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Heartbeat sends heartbeat to control plane
func (c *Client) Heartbeat(ctx context.Context, req *HeartbeatRequest) error {
	req.AgentID = c.agentID
	req.Timestamp = time.Now()

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat request: %w", err)
	}

	resp, err := c.makeRequest(ctx, "POST", "/api/v1/agents/heartbeat", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// SyncMetadata synchronizes secret metadata with control plane
func (c *Client) SyncMetadata(ctx context.Context, metadata []MetadataSync) error {
	data, err := json.Marshal(map[string]interface{}{
		"agent_id": c.agentID,
		"secrets":  metadata,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	resp, err := c.makeRequest(ctx, "POST", "/api/v1/agents/sync", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// makeRequest makes an HTTP request with retry logic
func (c *Client) makeRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	url := c.baseURL + path
	
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "KeyVault-Agent/1.0")

	return c.httpClient.Do(req)
}

// Close closes the client
func (c *Client) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}
