package offline

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/keyvault/agent/internal/config"
)

// Mode represents the current operational mode
type Mode string

const (
	ModeOnline  Mode = "online"
	ModeOffline Mode = "offline"
)

// Status represents the connection status
type Status struct {
	Mode           Mode      `json:"mode"`
	LastOnline     time.Time `json:"last_online"`
	LastCheck      time.Time `json:"last_check"`
	ConsecutiveFails int     `json:"consecutive_fails"`
	Error          string    `json:"error,omitempty"`
}

// Detector monitors control plane connectivity and manages offline mode
type Detector struct {
	config       *config.ControlPlaneConfig
	client       *http.Client
	status       Status
	statusMutex  sync.RWMutex
	subscribers  []chan Status
	subMutex     sync.RWMutex
	stopCh       chan struct{}
	ticker       *time.Ticker
}

// NewDetector creates a new offline mode detector
func NewDetector(cfg *config.ControlPlaneConfig) *Detector {
	// Create HTTP client with appropriate timeouts and TLS config
	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Should be configurable
			},
		},
	}

	// Load client certificates if provided
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err == nil {
			client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{cert}
		}
	}

	detector := &Detector{
		config: cfg,
		client: client,
		status: Status{
			Mode:       ModeOffline,
			LastCheck:  time.Now(),
		},
		stopCh: make(chan struct{}),
	}

	// Start with offline mode if configured
	if cfg.OfflineMode {
		detector.status.Mode = ModeOffline
	}

	return detector
}

// Start begins monitoring control plane connectivity
func (d *Detector) Start(ctx context.Context) error {
	if !d.config.Enabled {
		// Control plane is disabled, stay in offline mode
		d.setStatus(Status{
			Mode:      ModeOffline,
			LastCheck: time.Now(),
		})
		return nil
	}

	// Perform initial connectivity check
	d.checkConnectivity()

	// Start periodic checks
	d.ticker = time.NewTicker(d.config.HeartbeatInterval)
	go d.monitorLoop()

	return nil
}

// Stop stops the offline mode detector
func (d *Detector) Stop() error {
	close(d.stopCh)
	if d.ticker != nil {
		d.ticker.Stop()
	}
	return nil
}

// GetStatus returns the current status
func (d *Detector) GetStatus() Status {
	d.statusMutex.RLock()
	defer d.statusMutex.RUnlock()
	return d.status
}

// IsOnline returns true if currently online
func (d *Detector) IsOnline() bool {
	return d.GetStatus().Mode == ModeOnline
}

// IsOffline returns true if currently offline
func (d *Detector) IsOffline() bool {
	return d.GetStatus().Mode == ModeOffline
}

// Subscribe subscribes to status change notifications
func (d *Detector) Subscribe() <-chan Status {
	d.subMutex.Lock()
	defer d.subMutex.Unlock()

	ch := make(chan Status, 10) // Buffered channel
	d.subscribers = append(d.subscribers, ch)
	
	// Send current status immediately
	go func() {
		ch <- d.GetStatus()
	}()

	return ch
}

// Unsubscribe removes a subscription
func (d *Detector) Unsubscribe(ch <-chan Status) {
	d.subMutex.Lock()
	defer d.subMutex.Unlock()

	for i, sub := range d.subscribers {
		if sub == ch {
			close(sub)
			d.subscribers = append(d.subscribers[:i], d.subscribers[i+1:]...)
			break
		}
	}
}

// ForceOffline forces the detector into offline mode
func (d *Detector) ForceOffline() {
	d.setStatus(Status{
		Mode:      ModeOffline,
		LastCheck: time.Now(),
		Error:     "forced offline",
	})
}

// ForceOnline forces the detector into online mode (for testing)
func (d *Detector) ForceOnline() {
	d.setStatus(Status{
		Mode:       ModeOnline,
		LastOnline: time.Now(),
		LastCheck:  time.Now(),
		ConsecutiveFails: 0,
	})
}

// monitorLoop runs the periodic connectivity monitoring
func (d *Detector) monitorLoop() {
	for {
		select {
		case <-d.ticker.C:
			d.checkConnectivity()
		case <-d.stopCh:
			return
		}
	}
}

// checkConnectivity performs a connectivity check to the control plane
func (d *Detector) checkConnectivity() {
	if d.config.URL == "" {
		d.setOffline("no control plane URL configured")
		return
	}

	// Create health check request
	ctx, cancel := context.WithTimeout(context.Background(), d.config.Timeout)
	defer cancel()

	healthURL := d.config.URL + "/health"
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		d.setOffline(fmt.Sprintf("failed to create request: %v", err))
		return
	}

	// Add headers
	req.Header.Set("User-Agent", "vault-agent/1.0")
	req.Header.Set("Accept", "application/json")

	// Perform request
	resp, err := d.client.Do(req)
	if err != nil {
		d.setOffline(fmt.Sprintf("connection failed: %v", err))
		return
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		d.setOnline()
	} else {
		d.setOffline(fmt.Sprintf("health check failed: HTTP %d", resp.StatusCode))
	}
}

// setOnline sets the status to online
func (d *Detector) setOnline() {
	now := time.Now()
	newStatus := Status{
		Mode:             ModeOnline,
		LastOnline:       now,
		LastCheck:        now,
		ConsecutiveFails: 0,
	}
	d.setStatus(newStatus)
}

// setOffline sets the status to offline with an error message
func (d *Detector) setOffline(errorMsg string) {
	d.statusMutex.Lock()
	currentStatus := d.status
	d.statusMutex.Unlock()

	newStatus := Status{
		Mode:             ModeOffline,
		LastOnline:       currentStatus.LastOnline,
		LastCheck:        time.Now(),
		ConsecutiveFails: currentStatus.ConsecutiveFails + 1,
		Error:            errorMsg,
	}
	d.setStatus(newStatus)
}

// setStatus updates the status and notifies subscribers
func (d *Detector) setStatus(newStatus Status) {
	d.statusMutex.Lock()
	oldMode := d.status.Mode
	d.status = newStatus
	d.statusMutex.Unlock()

	// Notify subscribers if mode changed
	if oldMode != newStatus.Mode {
		d.notifySubscribers(newStatus)
	}
}

// notifySubscribers sends status updates to all subscribers
func (d *Detector) notifySubscribers(status Status) {
	d.subMutex.RLock()
	defer d.subMutex.RUnlock()

	for _, ch := range d.subscribers {
		select {
		case ch <- status:
		default:
			// Channel is full, skip this subscriber
		}
	}
}

// Manager handles offline mode operations and graceful degradation
type Manager struct {
	detector     *Detector
	capabilities map[string]bool
	mutex        sync.RWMutex
}

// NewManager creates a new offline mode manager
func NewManager(detector *Detector) *Manager {
	return &Manager{
		detector: detector,
		capabilities: map[string]bool{
			"secret_operations":    true,  // Always available
			"key_management":       true,  // Always available
			"audit_logging":        true,  // Always available
			"policy_enforcement":   true,  // Always available
			"user_management":      false, // Requires control plane
			"policy_distribution":  false, // Requires control plane
			"metrics_reporting":    false, // Requires control plane
			"backup_coordination":  false, // Requires control plane
		},
	}
}

// IsCapabilityAvailable checks if a capability is available in current mode
func (m *Manager) IsCapabilityAvailable(capability string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	available, exists := m.capabilities[capability]
	if !exists {
		return false
	}

	// If offline, only return capabilities that work offline
	if m.detector.IsOffline() {
		offlineCapabilities := map[string]bool{
			"secret_operations":   true,
			"key_management":      true,
			"audit_logging":       true,
			"policy_enforcement":  true,
		}
		return offlineCapabilities[capability] && available
	}

	return available
}

// GetAvailableCapabilities returns all currently available capabilities
func (m *Manager) GetAvailableCapabilities() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var available []string
	for capability := range m.capabilities {
		if m.IsCapabilityAvailable(capability) {
			available = append(available, capability)
		}
	}

	return available
}

// GetDegradedCapabilities returns capabilities that are degraded in offline mode
func (m *Manager) GetDegradedCapabilities() []string {
	if m.detector.IsOnline() {
		return []string{}
	}

	degraded := []string{
		"user_management",
		"policy_distribution",
		"metrics_reporting",
		"backup_coordination",
	}

	return degraded
}

// HandleOfflineTransition handles the transition to offline mode
func (m *Manager) HandleOfflineTransition() error {
	// Log the transition
	// Disable online-only features
	// Cache necessary data
	// Set up offline operation mode
	
	return nil
}

// HandleOnlineTransition handles the transition to online mode
func (m *Manager) HandleOnlineTransition() error {
	// Log the transition
	// Re-enable online features
	// Sync cached data with control plane
	// Resume normal operation
	
	return nil
}

// GetOperationalStatus returns the current operational status
func (m *Manager) GetOperationalStatus() map[string]interface{} {
	status := m.detector.GetStatus()
	
	return map[string]interface{}{
		"mode":                status.Mode,
		"last_online":         status.LastOnline,
		"last_check":          status.LastCheck,
		"consecutive_fails":   status.ConsecutiveFails,
		"error":              status.Error,
		"available_capabilities": m.GetAvailableCapabilities(),
		"degraded_capabilities":  m.GetDegradedCapabilities(),
	}
}